using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WorkAI360.Api.Features.Sso;

namespace WorkAI360.Api.Tests;

/// <summary>An in-process OpenID Connect provider on loopback (authorization code + PKCE, RS256 ID tokens, JWKS) that can misbehave on purpose.</summary>
public sealed class FakeIdp : IAsyncDisposable
{
    public const string ClientId = "fake-client";
    public const string ClientSecret = "fake-secret";

    private readonly WebApplication _app;
    private readonly RSA _key = RSA.Create(2048);
    private readonly RSA _otherKey = RSA.Create(2048);
    private readonly string _kid = "k-" + Guid.NewGuid().ToString("N")[..6];

    public string Url { get; private set; } = "";
    public string Issuer => Url;
    /// <summary>Who the provider signs in next.</summary>
    public (string Sub, string Email, string Name) Identity { get; set; } = ("sub-1", "person@example.test", "Person One");
    /// <summary>nonce | no-nonce | aud | iss | exp | sig | alg-none | alg-hs256 | no-sub | no-email | state | error | kid-unknown | azp | nbf | rs-small</summary>
    public string Fault { get; set; } = "";
    public ConcurrentBag<Dictionary<string, string>> AuthRequests { get; } = [];
    public ConcurrentBag<Dictionary<string, string>> TokenRequests { get; } = [];
    public int TokenCalls => TokenRequests.Count;
    private readonly ConcurrentDictionary<string, (Dictionary<string, string> Query, (string Sub, string Email, string Name) Identity, string Fault, bool Used)> _codes = new();

    private FakeIdp(WebApplication app) => _app = app;

    public static async Task<FakeIdp> StartAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var app = builder.Build();
        var idp = new FakeIdp(app);
        idp.Map(app);
        await app.StartAsync();
        idp.Url = app.Urls.First();
        return idp;
    }

    private static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private string Jwt(Dictionary<string, object?> claims, string fault)
    {
        var header = new Dictionary<string, object> { ["alg"] = "RS256", ["typ"] = "JWT", ["kid"] = fault == "kid-unknown" ? "nope" : _kid };
        var key = fault == "sig" ? _otherKey : _key;
        var body = B64(JsonSerializer.SerializeToUtf8Bytes(claims));
        if (fault == "alg-none") return $"{B64(JsonSerializer.SerializeToUtf8Bytes(new { alg = "none", typ = "JWT" }))}.{body}.";
        if (fault == "alg-hs256")
        {
            var h = B64(JsonSerializer.SerializeToUtf8Bytes(new { alg = "HS256", typ = "JWT", kid = _kid }));
            var secret = _key.ExportSubjectPublicKeyInfoPem();
            return $"{h}.{body}.{B64(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.ASCII.GetBytes($"{h}.{body}")))}";
        }
        var head = B64(JsonSerializer.SerializeToUtf8Bytes(header));
        return $"{head}.{body}.{B64(key.SignData(Encoding.ASCII.GetBytes($"{head}.{body}"), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))}";
    }

    /// <summary>Signs arbitrary claims with the provider's real key (for tests that need an exact token).</summary>
    public string Sign(Dictionary<string, object?> claims) => Jwt(claims, "");

    private void Map(WebApplication app)
    {
        app.MapGet("/.well-known/openid-configuration", () => Results.Json(new Dictionary<string, object>
        {
            ["issuer"] = Issuer, ["authorization_endpoint"] = Url + "/authorize", ["token_endpoint"] = Url + "/token", ["jwks_uri"] = Url + "/jwks",
        }));
        app.MapGet("/jwks", () =>
        {
            var p = _key.ExportParameters(false);
            return Results.Json(new { keys = new[] { new { kty = "RSA", use = "sig", alg = "RS256", kid = _kid, n = B64(p.Modulus!), e = B64(p.Exponent!) } } });
        });
        app.MapGet("/authorize", (HttpContext ctx) =>
        {
            var q = ctx.Request.Query.ToDictionary(k => k.Key, k => k.Value.ToString());
            AuthRequests.Add(q);
            if (q.GetValueOrDefault("client_id") != ClientId || q.GetValueOrDefault("response_type") != "code" || !q.ContainsKey("redirect_uri")) return Results.BadRequest("bad authorization request");
            var back = q["redirect_uri"];
            if (Fault == "error") return Results.Redirect($"{back}{(back.Contains('?') ? '&' : '?')}error=access_denied&error_description=No&state={Uri.EscapeDataString(q.GetValueOrDefault("state") ?? "")}");
            var code = Convert.ToHexString(RandomNumberGenerator.GetBytes(12));
            _codes[code] = (q, Identity, Fault, false);
            var state = Fault == "state" ? "forged-state" : q.GetValueOrDefault("state") ?? "";
            return Results.Redirect($"{back}{(back.Contains('?') ? '&' : '?')}code={code}&state={Uri.EscapeDataString(state)}");
        });
        app.MapPost("/token", async (HttpContext ctx) =>
        {
            var f = (await ctx.Request.ReadFormAsync()).ToDictionary(k => k.Key, k => k.Value.ToString());
            string? id, secret;
            if (ctx.Request.Headers.Authorization.ToString() is { } auth && auth.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                var pair = Encoding.UTF8.GetString(Convert.FromBase64String(auth[6..])).Split(':', 2);
                id = Uri.UnescapeDataString(pair[0]); secret = Uri.UnescapeDataString(pair[1]);
                f["_auth"] = "basic";
            }
            else { id = f.GetValueOrDefault("client_id"); secret = f.GetValueOrDefault("client_secret"); f["_auth"] = "post"; }
            TokenRequests.Add(f);
            if (id != ClientId || secret != ClientSecret) return Results.Json(new { error = "invalid_client" }, statusCode: 401);
            if (!f.TryGetValue("code", out var code) || !_codes.TryGetValue(code, out var rec) || rec.Used) return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
            _codes[code] = rec with { Used = true };
            if (f.GetValueOrDefault("redirect_uri") != rec.Query["redirect_uri"]) return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
            if (rec.Query.TryGetValue("code_challenge", out var challenge))
            {
                var want = B64(SHA256.HashData(Encoding.ASCII.GetBytes(f.GetValueOrDefault("code_verifier") ?? "")));
                if (rec.Query.GetValueOrDefault("code_challenge_method") != "S256" || want != challenge) return Results.Json(new { error = "invalid_grant", error_description = "pkce" }, statusCode: 400);
            }
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var fault = rec.Fault;
            var claims = new Dictionary<string, object?>
            {
                ["iss"] = fault == "iss" ? "https://evil.example" : Issuer, ["aud"] = fault == "aud" ? "someone-else" : ClientId, ["sub"] = rec.Identity.Sub, ["iat"] = now,
                ["exp"] = fault == "exp" ? now - 3600 : now + 300, ["email"] = rec.Identity.Email, ["email_verified"] = true, ["name"] = rec.Identity.Name,
            };
            if (fault != "no-nonce") claims["nonce"] = fault == "nonce" ? "not-the-nonce" : rec.Query.GetValueOrDefault("nonce");
            if (fault == "no-sub") claims.Remove("sub");
            if (fault == "no-email") { claims.Remove("email"); claims.Remove("email_verified"); }
            if (fault == "azp") { claims["aud"] = new[] { ClientId, "other-client" }; claims["azp"] = "other-client"; }
            if (fault == "nbf") claims["nbf"] = now + 3600;
            return Results.Json(new { access_token = "at-" + Guid.NewGuid().ToString("N")[..8], token_type = "Bearer", expires_in = 300, id_token = Jwt(claims, fault) });
        });
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
        _key.Dispose();
        _otherKey.Dispose();
    }
}

/// <summary>A DNS answer sheet: tests publish the TXT record the workspace is asked to create.</summary>
public sealed class FakeDns : IDnsTxtResolver
{
    private readonly ConcurrentDictionary<string, string[]> _records = new(StringComparer.OrdinalIgnoreCase);
    public ConcurrentBag<string> Lookups { get; } = [];
    public void Publish(string name, params string[] values) => _records[name] = values;
    public Task<IReadOnlyList<string>> ResolveTxtAsync(string name, CancellationToken cancellationToken)
    {
        Lookups.Add(name);
        return Task.FromResult<IReadOnlyList<string>>(_records.TryGetValue(name, out var v) ? v : []);
    }
}
