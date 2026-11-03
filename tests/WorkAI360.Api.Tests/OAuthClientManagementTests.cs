using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using WorkAI360.Api.Domain.OAuthExtras;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>Client management for the person who registered a client: /api/auth/oauth2/create-client, get-client(s), public-client, update-client, client/rotate-secret, delete-client.</summary>
public sealed class OAuthClientManagementTests(OAuthExtrasFactory factory) : OAuthExtrasBase(factory), IClassFixture<OAuthExtrasFactory>
{
    private static async Task<(HttpStatusCode Status, JsonElement Body)> SendAsync(HttpClient http, HttpMethod method, string url, object? body = null)
    {
        var request = new HttpRequestMessage(method, url);
        if (body is not null) request.Content = JsonContent.Create(body);
        var response = await http.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();
        return (response.StatusCode, string.IsNullOrEmpty(text) ? default : JsonDocument.Parse(text).RootElement.Clone());
    }

    private static Task<(HttpStatusCode Status, JsonElement Body)> CreateAsync(HttpClient http, object body) => SendAsync(http, HttpMethod.Post, "/api/auth/oauth2/create-client", body);

    [Fact]
    public async Task A_signed_in_person_creates_reads_lists_updates_and_deletes_their_client()
    {
        var (browser, _, userId, _) = await SignedInAsync();
        var (status, created) = await CreateAsync(browser, new
        {
            client_name = "Build Bot", redirect_uris = new[] { Redirect }, token_endpoint_auth_method = "client_secret_basic",
            client_uri = "https://bot.example.com", contacts = new[] { "ops@example.com" }, tos_uri = "https://bot.example.com/tos",
        });
        Assert.Equal(HttpStatusCode.Created, status);
        var clientId = created.GetProperty("client_id").GetString()!;
        Assert.StartsWith("ow_mcp_cs_", created.GetProperty("client_secret").GetString());
        Assert.Equal(userId, created.GetProperty("user_id").GetString());
        Assert.Equal("https://bot.example.com", created.GetProperty("client_uri").GetString());

        // Read: no secret, the owner and the metadata.
        var (getStatus, got) = await SendAsync(browser, HttpMethod.Get, $"/api/auth/oauth2/get-client?client_id={clientId}");
        Assert.Equal(HttpStatusCode.OK, getStatus);
        Assert.False(got.TryGetProperty("client_secret", out _));
        Assert.Equal(0, got.GetProperty("client_secret_expires_at").GetInt32());
        Assert.Equal("Build Bot", got.GetProperty("client_name").GetString());
        Assert.Equal("ops@example.com", got.GetProperty("contacts")[0].GetString());

        // The list holds this client (and anything else they registered while signed in, e.g. via /register).
        var (_, viaRegister) = await RegisterAsync(browser, new { client_name = "Dyn", redirect_uris = new[] { Redirect } });
        Assert.Equal(userId, viaRegister.GetProperty("user_id").GetString());
        var (_, list) = await SendAsync(browser, HttpMethod.Get, "/api/auth/oauth2/get-clients");
        var ids = list.EnumerateArray().Select(c => c.GetProperty("client_id").GetString()).ToList();
        Assert.Contains(clientId, ids);
        Assert.Contains(viaRegister.GetProperty("client_id").GetString(), ids);
        Assert.All(list.EnumerateArray(), c => Assert.False(c.TryGetProperty("client_secret", out _)));

        // Update: name, scope, redirect, descriptive fields merge.
        var (updStatus, updated) = await SendAsync(browser, HttpMethod.Post, "/api/auth/oauth2/update-client", new
        {
            client_id = clientId, update = new { client_name = "Build Bot 2", scope = "mcp:read", redirect_uris = new[] { "https://bot.example.com/cb" }, policy_uri = "https://bot.example.com/privacy" },
        });
        Assert.Equal(HttpStatusCode.OK, updStatus);
        Assert.Equal("Build Bot 2", updated.GetProperty("client_name").GetString());
        Assert.Equal("mcp:read", updated.GetProperty("scope").GetString());
        Assert.Equal("https://bot.example.com/cb", updated.GetProperty("redirect_uris")[0].GetString());
        Assert.Equal("https://bot.example.com/tos", updated.GetProperty("tos_uri").GetString());
        Assert.Equal("https://bot.example.com/privacy", updated.GetProperty("policy_uri").GetString());

        // Delete: gone, and its consents and tokens with it.
        var (delStatus, _) = await SendAsync(browser, HttpMethod.Post, "/api/auth/oauth2/delete-client", new { client_id = clientId });
        Assert.Equal(HttpStatusCode.OK, delStatus);
        Assert.Equal(HttpStatusCode.NotFound, (await SendAsync(browser, HttpMethod.Get, $"/api/auth/oauth2/get-client?client_id={clientId}")).Status);
        Assert.Equal(0, Factory.WithDb(db => db.OAuthClients.Count(c => c.Id == clientId) + db.Set<OAuthClientExtras>().Count(x => x.ClientId == clientId)));
    }

    [Fact]
    public async Task Rotating_a_secret_replaces_it_and_the_old_one_stops_working()
    {
        var (browser, _, _, _) = await SignedInAsync();
        var (id, oldSecret) = await ClientCredentialsClientAsync(browser);
        await GrantAsync(id, "mcp:read");
        var form = new Dictionary<string, string> { ["grant_type"] = "client_credentials", ["scope"] = "mcp:read" };
        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(Factory.Plain(), form, Basic(id, oldSecret!))).Status);

        var (status, rotated) = await SendAsync(browser, HttpMethod.Post, "/api/auth/oauth2/client/rotate-secret", new { client_id = id });
        Assert.Equal(HttpStatusCode.OK, status);
        var newSecret = rotated.GetProperty("client_secret").GetString()!;
        Assert.NotEqual(oldSecret, newSecret);
        Assert.Equal(HttpStatusCode.Unauthorized, (await TokenAsync(Factory.Plain(), form, Basic(id, oldSecret!))).Status);
        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(Factory.Plain(), form, Basic(id, newSecret))).Status);

        // Public clients have no secret to rotate.
        var publicClient = await PublicClientAsync(browser);
        var (badStatus, bad) = await SendAsync(browser, HttpMethod.Post, "/api/auth/oauth2/client/rotate-secret", new { client_id = publicClient });
        Assert.Equal(HttpStatusCode.BadRequest, badStatus);
        Assert.Equal("secret rotation is only available for clients using client_secret authentication", Desc(bad));
    }

    [Fact]
    public async Task Only_the_owner_manages_a_client_and_anonymous_clients_belong_to_nobody()
    {
        var (owner, _, _, _) = await SignedInAsync();
        var (other, _, _, _) = await SignedInAsync();
        var (_, created) = await CreateAsync(owner, new { client_name = "Mine", redirect_uris = new[] { Redirect }, token_endpoint_auth_method = "client_secret_post" });
        var id = created.GetProperty("client_id").GetString()!;

        foreach (var (method, url, body) in new (HttpMethod, string, object?)[]
        {
            (HttpMethod.Get, $"/api/auth/oauth2/get-client?client_id={id}", null),
            (HttpMethod.Post, "/api/auth/oauth2/update-client", new { client_id = id, update = new { client_name = "Hijacked" } }),
            (HttpMethod.Post, "/api/auth/oauth2/client/rotate-secret", new { client_id = id }),
            (HttpMethod.Post, "/api/auth/oauth2/delete-client", new { client_id = id }),
        })
        {
            var (status, answer) = await SendAsync(other, method, url, body);
            Assert.Equal(HttpStatusCode.Unauthorized, status);
            Assert.Equal("UNAUTHORIZED", answer.GetProperty("code").GetString());
            Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(Factory.Plain(), method, url, body)).Status);
        }
        Assert.Empty((await SendAsync(other, HttpMethod.Get, "/api/auth/oauth2/get-clients")).Body.EnumerateArray());
        Assert.Equal("Mine", (await SendAsync(owner, HttpMethod.Get, $"/api/auth/oauth2/get-client?client_id={id}")).Body.GetProperty("client_name").GetString());

        // A client registered without signing in has no owner: nobody can manage it, and its registration names no user.
        var (_, anonymous) = await RegisterAsync(Factory.Plain(), new { client_name = "Anon", redirect_uris = new[] { Redirect } });
        Assert.False(anonymous.TryGetProperty("user_id", out _));
        var anonId = anonymous.GetProperty("client_id").GetString()!;
        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(owner, HttpMethod.Post, "/api/auth/oauth2/delete-client", new { client_id = anonId })).Status);

        // Unknown ids are 404; creating needs a session.
        Assert.Equal(HttpStatusCode.NotFound, (await SendAsync(owner, HttpMethod.Get, "/api/auth/oauth2/get-client?client_id=nope")).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await CreateAsync(Factory.Plain(), new { client_name = "X", redirect_uris = new[] { Redirect } })).Status);
    }

    [Fact]
    public async Task Updates_follow_the_registration_rules()
    {
        var (browser, _, _, _) = await SignedInAsync();
        var (_, created) = await CreateAsync(browser, new { client_name = "Rules", redirect_uris = new[] { Redirect } });
        var id = created.GetProperty("client_id").GetString()!;
        async Task<string> Refused(object update)
        {
            var (status, body) = await SendAsync(browser, HttpMethod.Post, "/api/auth/oauth2/update-client", new { client_id = id, update });
            Assert.Equal(HttpStatusCode.BadRequest, status);
            return body.GetProperty("error").GetString()!;
        }
        Assert.Equal("invalid_redirect_uri", await Refused(new { redirect_uris = new[] { "http://evil.example.com/cb" } }));
        Assert.Equal("invalid_redirect_uri", await Refused(new { redirect_uris = Array.Empty<string>() }));
        Assert.Equal("invalid_client_metadata", await Refused(new { scope = "admin:everything" }));
        Assert.Equal("invalid_client_metadata", await Refused(new { grant_types = new[] { "password" } }));
        Assert.Equal("invalid_client_metadata", await Refused(new { client_uri = "javascript:alert(1)" }));
        Assert.Equal("invalid_client_metadata", await Refused(new { application_type = "desktop" }));
        // Nothing changed.
        var (_, got) = await SendAsync(browser, HttpMethod.Get, $"/api/auth/oauth2/get-client?client_id={id}");
        Assert.Equal(Redirect, got.GetProperty("redirect_uris")[0].GetString());

        // Dropping client_credentials clears the scopes a platform admin granted for it.
        var (_, machine) = await RegisterAsync(browser, new { client_name = "Both", token_endpoint_auth_method = "client_secret_basic", grant_types = new[] { "client_credentials", "authorization_code" }, redirect_uris = new[] { Redirect } });
        var machineId = machine.GetProperty("client_id").GetString()!;
        await GrantAsync(machineId, "mcp:read");
        Assert.NotNull(Factory.WithDb(db => db.Set<OAuthClientExtras>().Single(x => x.ClientId == machineId).ClientCredentialsScope));
        var (okStatus, _) = await SendAsync(browser, HttpMethod.Post, "/api/auth/oauth2/update-client", new { client_id = machineId, update = new { grant_types = new[] { "authorization_code" } } });
        Assert.Equal(HttpStatusCode.OK, okStatus);
        Assert.Null(Factory.WithDb(db => db.Set<OAuthClientExtras>().Single(x => x.ClientId == machineId).ClientCredentialsScope));
    }

    [Fact]
    public async Task Public_client_shows_only_public_fields_to_signed_in_people()
    {
        var (owner, _, _, _) = await SignedInAsync();
        var (viewer, _, _, _) = await SignedInAsync();
        var (_, created) = await CreateAsync(owner, new { client_name = "Shown", redirect_uris = new[] { Redirect }, token_endpoint_auth_method = "client_secret_basic", client_uri = "https://shown.example.com" });
        var id = created.GetProperty("client_id").GetString()!;
        var (status, body) = await SendAsync(viewer, HttpMethod.Get, $"/api/auth/oauth2/public-client?client_id={id}");
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal("Shown", body.GetProperty("client_name").GetString());
        Assert.Equal("https://shown.example.com", body.GetProperty("client_uri").GetString());
        foreach (var hidden in new[] { "client_secret", "user_id", "scope", "token_endpoint_auth_method", "grant_types" }) Assert.False(body.TryGetProperty(hidden, out _), hidden);
        Assert.Empty(body.GetProperty("redirect_uris").EnumerateArray());
        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(Factory.Plain(), HttpMethod.Get, $"/api/auth/oauth2/public-client?client_id={id}")).Status);
    }
}
