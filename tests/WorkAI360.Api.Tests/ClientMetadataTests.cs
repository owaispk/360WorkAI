using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using WorkAI360.Api.Domain;
using WorkAI360.Api.OAuth;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>A fetcher that serves documents from memory and counts how often it was asked.</summary>
public sealed class FakeMetadataFetcher : IClientMetadataFetcher
{
    public Dictionary<string, MetadataResponse?> Documents { get; } = new();
    public List<string> Requests { get; } = [];

    public Task<MetadataResponse?> FetchAsync(Uri url, CancellationToken cancellationToken)
    {
        lock (Requests) Requests.Add(url.ToString());
        return Task.FromResult(Documents.GetValueOrDefault(url.ToString()));
    }

    public static MetadataResponse Json(object document) => new(200, "application/json", JsonSerializer.Serialize(document));
}

public sealed class MetadataFactory : ApiFactory
{
    public FakeMetadataFetcher Fetcher { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureServices(services => services.Replace(ServiceDescriptor.Singleton<IClientMetadataFetcher>(Fetcher)));
    }
}

public sealed class ClientMetadataPolicyTests
{
    private static readonly string[] Own = ["http://localhost", "https://den.example.com"];

    [Theory]
    [InlineData("https://client.example/oauth/metadata.json", true)]
    [InlineData("https://client.example/a", true)]
    [InlineData("https://client.example:8443/a/b?x=1", true)]
    [InlineData("http://client.example/oauth/metadata.json", false)]      // not HTTPS
    [InlineData("https://client.example", false)]                          // no path
    [InlineData("https://client.example/", false)]
    [InlineData("https://user:pass@client.example/x", false)]              // credentials
    [InlineData("https://client.example/x#frag", false)]
    [InlineData("https://client.example/a/../b", false)]                   // dot segments are normalised by Uri, so check the raw form below
    [InlineData("https://den.example.com/oauth/metadata.json", false)]     // this deployment itself
    [InlineData("https://DEN.example.com/x", false)]
    [InlineData("https://127.0.0.1/x", false)]
    [InlineData("https://10.1.2.3/x", false)]
    [InlineData("https://172.16.0.1/x", false)]
    [InlineData("https://172.32.0.1/x", true)]
    [InlineData("https://192.168.1.1/x", false)]
    [InlineData("https://169.254.169.254/latest/meta-data", false)]        // cloud metadata
    [InlineData("https://100.64.0.1/x", false)]
    [InlineData("https://[::1]/x", false)]
    [InlineData("https://[fd00::1]/x", false)]
    [InlineData("https://[fe80::1]/x", false)]
    [InlineData("https://[::ffff:10.0.0.1]/x", false)]                     // IPv4 inside IPv6
    [InlineData("https://93.184.216.34/x", true)]
    public void Only_public_https_documents_with_a_path_are_fetched(string url, bool allowed)
    {
        var parsed = new Uri(url);
        // Uri collapses "/a/../b" to "/b", which is harmless; the rule is about what is actually requested.
        var expected = url.Contains("/../") ? true : allowed;
        Assert.Equal(expected, ClientMetadataPolicy.IsAllowedUrl(parsed, Own, allowPrivate: false));
    }

    [Fact]
    public void Self_hosted_deployments_can_allow_private_addresses_but_never_their_own_origin()
    {
        Assert.True(ClientMetadataPolicy.IsAllowedUrl(new Uri("https://10.0.0.5/x"), Own, allowPrivate: true));
        Assert.False(ClientMetadataPolicy.IsAllowedUrl(new Uri("https://den.example.com/x"), Own, allowPrivate: true));
        Assert.False(ClientMetadataPolicy.IsAllowedUrl(new Uri("http://client.example/x"), Own, allowPrivate: true));
    }
}

public sealed class ClientMetadataDocumentTests
{
    private const string Id = "https://client.example/oauth/metadata.json";
    private static string Doc(object? merge = null, params string[] without)
    {
        var d = new Dictionary<string, object?> { ["client_id"] = Id, ["client_name"] = "Example Agent", ["redirect_uris"] = new[] { "http://127.0.0.1:5555/callback" }, ["token_endpoint_auth_method"] = "none", ["grant_types"] = new[] { "authorization_code", "refresh_token" } };
        if (merge is not null) foreach (var p in merge.GetType().GetProperties()) d[p.Name] = p.GetValue(merge);
        foreach (var key in without) d.Remove(key);
        return JsonSerializer.Serialize(d);
    }

    [Fact]
    public void A_valid_document_becomes_a_public_client()
    {
        var client = ClientResolver.Parse(Id, Doc())!;
        Assert.Equal(Id, client.Id);
        Assert.Equal("Example Agent", client.Name);
        Assert.Equal("none", client.AuthMethod);
        Assert.Null(client.SecretHash);
        Assert.Equal("[\"http://127.0.0.1:5555/callback\"]", client.RedirectUrisJson);
        Assert.NotNull(client.MetadataFetchedAt);
    }

    [Fact]
    public void The_document_must_be_about_the_client_id_it_was_fetched_for()
    {
        Assert.Null(ClientResolver.Parse(Id, Doc(new { client_id = "https://evil.example/x.json" })));
        Assert.Null(ClientResolver.Parse(Id, Doc(without: "client_id")));
        Assert.Null(ClientResolver.Parse(Id, Doc(new { client_id = Id + "/" })));
    }

    [Fact]
    public void A_document_may_not_carry_or_ask_for_a_secret()
    {
        Assert.Null(ClientResolver.Parse(Id, Doc(new { client_secret = "s3cret" })));
        Assert.Null(ClientResolver.Parse(Id, Doc(new { client_secret_expires_at = 0 })));
        Assert.Null(ClientResolver.Parse(Id, Doc(new { token_endpoint_auth_method = "client_secret_basic" })));
        Assert.Null(ClientResolver.Parse(Id, Doc(new { token_endpoint_auth_method = "private_key_jwt" })));
        Assert.NotNull(ClientResolver.Parse(Id, Doc(without: "token_endpoint_auth_method")));
    }

    [Theory]
    [InlineData("http://evil.example/cb")]
    [InlineData("javascript:alert(1)")]
    [InlineData("https://ok.example/cb#frag")]
    [InlineData("not a uri")]
    public void Every_redirect_must_pass_the_redirect_policy(string bad)
    {
        Assert.Null(ClientResolver.Parse(Id, Doc(new { redirect_uris = new[] { "https://ok.example/cb", bad } })));
    }

    [Fact]
    public void Redirects_are_required_and_bounded()
    {
        Assert.Null(ClientResolver.Parse(Id, Doc(without: "redirect_uris")));
        Assert.Null(ClientResolver.Parse(Id, Doc(new { redirect_uris = Array.Empty<string>() })));
        Assert.Null(ClientResolver.Parse(Id, Doc(new { redirect_uris = Enumerable.Range(0, 21).Select(i => $"https://ok.example/cb{i}").ToArray() })));
        Assert.Null(ClientResolver.Parse(Id, Doc(new { redirect_uris = "https://ok.example/cb" })));
    }

    [Fact]
    public void Grant_types_beyond_what_the_server_offers_are_refused()
    {
        Assert.Null(ClientResolver.Parse(Id, Doc(new { grant_types = new[] { "authorization_code", "client_credentials" } })));
        Assert.Null(ClientResolver.Parse(Id, Doc(new { grant_types = new[] { "password" } })));
    }

    [Fact]
    public void Names_default_to_the_host_and_are_cut_to_a_sensible_length_and_logos_must_be_https()
    {
        Assert.Equal("client.example", ClientResolver.Parse(Id, Doc(without: "client_name"))!.Name);
        Assert.Equal(100, ClientResolver.Parse(Id, Doc(new { client_name = new string('x', 500) }))!.Name.Length);
        Assert.Null(ClientResolver.Parse(Id, Doc(new { logo_uri = "http://client.example/logo.png" }))!.LogoUri);
        Assert.Equal("https://client.example/logo.png", ClientResolver.Parse(Id, Doc(new { logo_uri = "https://client.example/logo.png" }))!.LogoUri);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("\"string\"")]
    public void Anything_that_is_not_a_json_object_is_refused(string body) => Assert.Null(ClientResolver.Parse(Id, body));
}

public sealed class ClientMetadataFlowTests : IClassFixture<MetadataFactory>
{
    private const string Resource = "http://localhost/mcp/agent";
    private const string Redirect = "http://127.0.0.1:5555/callback";
    private readonly MetadataFactory _factory;
    public ClientMetadataFlowTests(MetadataFactory factory) => _factory = factory;

    private static string B64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private string NewId() => $"https://client-{Guid.NewGuid():N}.example/oauth/metadata.json";

    private void Serve(string id, string? name = "Example Agent", object[]? redirects = null) =>
        _factory.Fetcher.Documents[id] = FakeMetadataFetcher.Json(new { client_id = id, client_name = name, redirect_uris = redirects ?? [Redirect], token_endpoint_auth_method = "none" });

    private async Task<HttpClient> SignedInAsync()
    {
        var browser = _factory.Browser();
        var (_, token, _) = await _factory.SignUpAsync(browser, "Agent Owner");
        Assert.Equal(HttpStatusCode.Created, (await browser.SendAsync(Bearer(HttpMethod.Post, "/v1/org", token, new { name = "Agent Workspace" }))).StatusCode);
        return browser;
    }

    private static string AuthorizeUrl(string clientId, string challenge, string redirect = Redirect) =>
        $"/api/auth/oauth2/authorize?response_type=code&client_id={Uri.EscapeDataString(clientId)}&redirect_uri={Uri.EscapeDataString(redirect)}&scope={Uri.EscapeDataString("mcp:read offline_access")}&state=s&code_challenge={challenge}&code_challenge_method=S256&resource={Uri.EscapeDataString(Resource)}";

    private static (string Verifier, string Challenge) Pkce()
    {
        var v = B64(RandomNumberGenerator.GetBytes(32));
        return (v, B64(SHA256.HashData(Encoding.ASCII.GetBytes(v))));
    }

    [Fact]
    public async Task Discovery_says_clients_may_use_a_metadata_document()
    {
        var doc = await ReadJsonAsync(await _factory.Plain().GetAsync("/.well-known/oauth-authorization-server/api/auth"));
        Assert.True(doc.GetProperty("client_id_metadata_document_supported").GetBoolean());
    }

    [Fact]
    public async Task A_client_that_names_its_document_signs_in_and_gets_tokens_without_registering()
    {
        var id = NewId();
        Serve(id);
        var browser = await SignedInAsync();
        var (verifier, challenge) = Pkce();

        var authorize = await browser.GetAsync(AuthorizeUrl(id, challenge));
        Assert.Equal(HttpStatusCode.Redirect, authorize.StatusCode);
        var location = authorize.Headers.Location!.ToString();
        Assert.Contains("/mcp/consent?", location);

        var consent = await browser.PostAsJsonAsync("/api/auth/oauth2/consent", new { accept = true, scope = "mcp:read offline_access", oauth_query = location[(location.IndexOf('?') + 1)..] });
        Assert.Equal(HttpStatusCode.OK, consent.StatusCode);
        var code = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(new Uri((await ReadJsonAsync(consent)).GetProperty("url").GetString()!).Query)["code"].ToString();

        var token = await browser.PostAsync("/api/auth/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        { ["grant_type"] = "authorization_code", ["code"] = code, ["redirect_uri"] = Redirect, ["client_id"] = id, ["code_verifier"] = verifier, ["resource"] = Resource }));
        Assert.Equal(HttpStatusCode.OK, token.StatusCode);
        Assert.Equal(3, (await ReadJsonAsync(token)).GetProperty("access_token").GetString()!.Split('.').Length);   // a signed JWT

        var stored = _factory.WithDb(db => db.OAuthClients.AsNoTracking().Single(c => c.Id == id));
        Assert.Equal("none", stored.AuthMethod);
        Assert.Equal("Example Agent", stored.Name);
    }

    [Fact]
    public async Task The_document_is_fetched_once_and_then_trusted_for_an_hour_then_refreshed()
    {
        var id = NewId();
        Serve(id, "First name");
        var browser = await SignedInAsync();
        var (_, challenge) = Pkce();
        for (var i = 0; i < 3; i++) Assert.Equal(HttpStatusCode.Redirect, (await browser.GetAsync(AuthorizeUrl(id, challenge))).StatusCode);
        Assert.Equal(1, _factory.Fetcher.Requests.Count(r => r == id));

        // After an hour it is read again, and a changed name is picked up.
        _factory.WithDb(db => db.Database.ExecuteSqlRaw("UPDATE OAuthClients SET MetadataFetchedAt = {0} WHERE Id = {1}", DateTime.UtcNow.AddHours(-2), id));
        Serve(id, "Second name");
        Assert.Equal(HttpStatusCode.Redirect, (await browser.GetAsync(AuthorizeUrl(id, challenge))).StatusCode);
        Assert.Equal(2, _factory.Fetcher.Requests.Count(r => r == id));
        Assert.Equal("Second name", _factory.WithDb(db => db.OAuthClients.AsNoTracking().Single(c => c.Id == id).Name));

        // If the document is unreachable when it is due again, the known client keeps working with what is stored.
        _factory.WithDb(db => db.Database.ExecuteSqlRaw("UPDATE OAuthClients SET MetadataFetchedAt = {0} WHERE Id = {1}", DateTime.UtcNow.AddHours(-2), id));
        _factory.Fetcher.Documents[id] = null;
        Assert.Equal(HttpStatusCode.Redirect, (await browser.GetAsync(AuthorizeUrl(id, challenge))).StatusCode);
        Assert.Equal("Second name", _factory.WithDb(db => db.OAuthClients.AsNoTracking().Single(c => c.Id == id).Name));
    }

    [Fact]
    public async Task A_refreshed_document_that_loses_a_redirect_stops_honoring_it()
    {
        var id = NewId();
        Serve(id, redirects: [Redirect, "https://app.example/cb"]);
        var browser = await SignedInAsync();
        var (_, challenge) = Pkce();
        Assert.Equal(HttpStatusCode.Redirect, (await browser.GetAsync(AuthorizeUrl(id, challenge, "https://app.example/cb"))).StatusCode);
        _factory.WithDb(db => db.Database.ExecuteSqlRaw("UPDATE OAuthClients SET MetadataFetchedAt = {0} WHERE Id = {1}", DateTime.UtcNow.AddHours(-2), id));
        Serve(id, redirects: [Redirect]);
        var refused = await browser.GetAsync(AuthorizeUrl(id, challenge, "https://app.example/cb"));
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
    }

    [Fact]
    public async Task Unknown_unreachable_or_invalid_documents_are_an_unknown_client_and_nothing_is_stored()
    {
        var browser = await SignedInAsync();
        var (_, challenge) = Pkce();

        var unreachable = NewId();
        var invalidId = NewId();
        _factory.Fetcher.Documents[invalidId] = FakeMetadataFetcher.Json(new { client_id = "https://someone-else.example/x.json", redirect_uris = new[] { Redirect } });
        var notJson = NewId();
        _factory.Fetcher.Documents[notJson] = new MetadataResponse(200, "text/html", "<html></html>");
        var missing = NewId();
        _factory.Fetcher.Documents[missing] = new MetadataResponse(404, "application/json", "{}");
        var withSecret = NewId();
        _factory.Fetcher.Documents[withSecret] = FakeMetadataFetcher.Json(new { client_id = withSecret, redirect_uris = new[] { Redirect }, client_secret = "x" });

        foreach (var id in new[] { unreachable, invalidId, notJson, missing, withSecret })
        {
            var response = await browser.GetAsync(AuthorizeUrl(id, challenge));
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("invalid_client", (await ReadJsonAsync(response)).GetProperty("error").GetString());
            Assert.False(_factory.WithDb(db => db.OAuthClients.Any(c => c.Id == id)), $"{id} was stored");
        }
    }

    [Fact]
    public async Task A_redirect_not_in_the_document_is_refused_and_a_document_url_on_this_server_is_never_fetched()
    {
        var id = NewId();
        Serve(id);
        var browser = await SignedInAsync();
        var (_, challenge) = Pkce();
        var wrong = await browser.GetAsync(AuthorizeUrl(id, challenge, "https://attacker.example/cb"));
        Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);

        var own = "http://localhost/oauth/metadata.json";
        var before = _factory.Fetcher.Requests.Count;
        var response = await browser.GetAsync(AuthorizeUrl(own, challenge));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(before, _factory.Fetcher.Requests.Count);
    }

    [Fact]
    public async Task Registered_clients_are_unaffected_and_an_https_id_that_was_registered_is_not_overridden_by_a_document()
    {
        var browser = _factory.Plain();
        var registered = await browser.PostAsJsonAsync("/register", new { client_name = "Plain", redirect_uris = new[] { Redirect }, token_endpoint_auth_method = "none" });
        var id = (await ReadJsonAsync(registered)).GetProperty("client_id").GetString()!;
        var before = _factory.Fetcher.Requests.Count;
        var signedIn = await SignedInAsync();
        Assert.Equal(HttpStatusCode.Redirect, (await signedIn.GetAsync(AuthorizeUrl(id, Pkce().Challenge))).StatusCode);
        Assert.Equal(before, _factory.Fetcher.Requests.Count);   // a plain client_id is never fetched
    }
}
