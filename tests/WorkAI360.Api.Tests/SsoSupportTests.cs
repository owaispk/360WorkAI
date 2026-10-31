using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using WorkAI360.Api.Features.Sso;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

public sealed class SsoOutboundTests(StrictSsoFactory factory) : IClassFixture<StrictSsoFactory>
{
    [Theory]
    [InlineData("127.0.0.1", false)]
    [InlineData("10.1.2.3", false)]
    [InlineData("172.16.0.1", false)]
    [InlineData("192.168.1.1", false)]
    [InlineData("169.254.169.254", false)]
    [InlineData("100.64.0.1", false)]
    [InlineData("0.0.0.0", false)]
    [InlineData("::1", false)]
    [InlineData("fe80::1", false)]
    [InlineData("fd00::1", false)]
    [InlineData("::ffff:127.0.0.1", false)]
    [InlineData("8.8.8.8", true)]
    [InlineData("2606:4700:4700::1111", true)]
    public void Only_public_addresses_are_reachable(string address, bool expected) =>
        Assert.Equal(expected, OutboundPolicy.IsPublicAddress(IPAddress.Parse(address)));

    [Fact]
    public void Plain_http_and_embedded_credentials_are_refused_outside_development()
    {
        Assert.False(OutboundPolicy.IsAcceptableUrl("http://idp.example.com/", false));
        Assert.True(OutboundPolicy.IsAcceptableUrl("https://idp.example.com/", false));
        Assert.False(OutboundPolicy.IsAcceptableUrl("https://user:pw@idp.example.com/", false));
        Assert.False(OutboundPolicy.IsAcceptableUrl("file:///etc/passwd", true));
        Assert.True(OutboundPolicy.IsAcceptableUrl("http://127.0.0.1:1/", true));
    }

    [Fact]
    public async Task An_administrator_cannot_point_the_server_at_internal_addresses()
    {
        await using var idp = await FakeIdp.StartAsync();
        var w = await SsoWorld.CreateAsync(factory, idp, factory.Dns);
        // The provider is on loopback and plain http: refused before anything is fetched.
        var plain = await w.RegisterAsync();
        Assert.Equal(HttpStatusCode.BadRequest, plain.Status);
        Assert.Equal(0, idp.TokenCalls);
        // Over https the address itself is refused when the server connects (discovery would otherwise reach loopback).
        var viaDiscovery = await w.Owner(HttpMethod.Post, "/v1/sso/oidc", new { issuer = "https://127.0.0.1:1", domain = w.Domain, clientId = "c", clientSecret = "s" });
        Assert.Equal(HttpStatusCode.BadRequest, viaDiscovery.Status);
        Assert.Contains("public https URL", viaDiscovery.Body.GetProperty("details")[0].GetProperty("message").GetString());
        // Manually entered endpoints are checked too.
        var manual = await w.Owner(HttpMethod.Post, "/v1/sso/oidc", new { issuer = "https://idp.example.com", domain = w.Domain, clientId = "c", clientSecret = "s", skipDiscovery = true,
            authorizationEndpoint = "https://idp.example.com/a", tokenEndpoint = "http://169.254.169.254/token", jwksEndpoint = "https://idp.example.com/j" });
        Assert.Equal(HttpStatusCode.BadRequest, manual.Status);
        Assert.Contains("token endpoint must be a public https URL", manual.Body.GetProperty("details")[0].GetProperty("message").GetString());
        var literal = await w.Owner(HttpMethod.Post, "/v1/sso/oidc", new { issuer = "https://idp.example.com", domain = w.Domain, clientId = "c", clientSecret = "s", skipDiscovery = true,
            authorizationEndpoint = "https://idp.example.com/a", tokenEndpoint = "https://127.0.0.1:1/token", jwksEndpoint = "https://idp.example.com/j" });
        Assert.Equal(HttpStatusCode.BadRequest, literal.Status);
    }

    [Fact]
    public async Task A_name_that_resolves_to_a_private_address_is_refused_at_connect_time()
    {
        await using var idp = await FakeIdp.StartAsync();
        using var strict = new HttpClient(IdpHttp.CreateHandler(allowPrivate: false));
        // "localhost" passes any name check; only the address it resolves to gives it away.
        await Assert.ThrowsAsync<HttpRequestException>(() => strict.GetAsync(idp.Url.Replace("127.0.0.1", "localhost") + "/jwks"));
        using var relaxed = new HttpClient(IdpHttp.CreateHandler(allowPrivate: true));
        Assert.Equal(HttpStatusCode.OK, (await relaxed.GetAsync(idp.Url.Replace("127.0.0.1", "localhost") + "/jwks")).StatusCode);
    }
}

/// <summary>Development convenience: a loopback issuer counts as verified, like the reference's dev mode. Nothing else does.</summary>
public sealed class SsoLoopbackTests(LoopbackSsoFactory factory) : IClassFixture<LoopbackSsoFactory>
{
    [Fact]
    public async Task A_loopback_issuer_is_verified_without_DNS_in_development_only()
    {
        await using var idp = await FakeIdp.StartAsync();
        var w = await SsoWorld.CreateAsync(factory, idp, null);
        var r = await w.RegisterAsync();
        Assert.True(r.Body.GetProperty("connection").GetProperty("domainVerified").GetBoolean());
        Assert.Equal(JsonValueKind.Null, r.Body.GetProperty("domainVerificationToken").ValueKind);
        await w.RunTestAsync();
        Assert.Equal(HttpStatusCode.NoContent, (await w.Owner(HttpMethod.Post, "/v1/sso/enable", new { })).Status);

        // A public issuer name is not trusted by this convenience.
        var other = await SsoWorld.CreateAsync(factory, idp, null);
        var named = await other.Owner(HttpMethod.Post, "/v1/sso/oidc", new { issuer = "https://idp.example.com", domain = other.Domain, clientId = "c", clientSecret = "s", skipDiscovery = true,
            authorizationEndpoint = "https://idp.example.com/a", tokenEndpoint = "https://idp.example.com/t", jwksEndpoint = "https://idp.example.com/j" });
        Assert.False(named.Body.GetProperty("connection").GetProperty("domainVerified").GetBoolean());
    }
}

public sealed class DnsTxtParsingTests
{
    [Fact]
    public void A_TXT_answer_is_read_even_when_names_are_compressed_and_strings_are_split()
    {
        var query = SystemDnsTxtResolver.BuildQuery("_t.example.com", 0x1234);
        var answer = new List<byte>(query);
        answer[2] = 0x81; answer[3] = 0x80; answer[7] = 1;                 // response, one answer
        answer.AddRange([0xC0, 0x0C, 0, 16, 0, 1, 0, 0, 0, 60]);            // name pointer, TXT, IN, ttl
        var rdata = new List<byte>(); foreach (var piece in new[] { "abc", "def" }) { rdata.Add((byte)piece.Length); rdata.AddRange(System.Text.Encoding.ASCII.GetBytes(piece)); }
        answer.AddRange([0, (byte)rdata.Count]); answer.AddRange(rdata);
        Assert.Equal(["abcdef"], SystemDnsTxtResolver.ParseTxt([.. answer], 0x1234));
        Assert.Throws<InvalidDataException>(() => SystemDnsTxtResolver.ParseTxt([.. answer], 0x9999));   // someone else's answer
        answer[3] = 0x83;                                                    // NXDOMAIN
        Assert.Empty(SystemDnsTxtResolver.ParseTxt([.. answer], 0x1234));
    }
}
