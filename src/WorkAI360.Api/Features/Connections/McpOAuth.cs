using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace WorkAI360.Api.Features.Connections;

/// <summary>Why an OAuth step with a remote server failed. <see cref="Code"/> says what to do about it.</summary>
public sealed class OAuthException(string code, string message, int? httpStatus = null) : Exception(message)
{
    /// <summary>discovery_failed, configuration_required, registration_failed, token_rejected, token_failed, issuer_mismatch.</summary>
    public string Code { get; } = code;
    public int? HttpStatus { get; } = httpStatus;
}

public sealed record AuthServer(string Issuer, string AuthorizationEndpoint, string TokenEndpoint, string? RegistrationEndpoint, string Resource, string[] ScopesSupported, string[] AdvertisedIssuers, bool SupportsClientMetadata);

public sealed record TokenSet(string AccessToken, string? RefreshToken, string TokenType, string? Scope, DateTime? ExpiresAt);

/// <summary>
/// OAuth for a remote MCP server: finds its authorization server (RFC 9728 protected-resource metadata, then RFC 8414 / OpenID metadata),
/// registers this app dynamically (RFC 7591) when the admin gave no client, builds a PKCE (S256) authorization request that names the
/// resource (RFC 8707), and exchanges and refreshes tokens. Every request goes through <see cref="GuardedHttp"/>.
/// </summary>
public sealed partial class McpOAuth(GuardedHttp http)
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

    [GeneratedRegex("resource_metadata=\"([^\"]+)\"")]
    private static partial Regex ResourceMetadataRegex();

    private async Task<(HttpStatusCode Status, JsonObject? Json, GuardedHttp.Reply Reply)> GetJsonAsync(string url, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        var reply = await Send(request, ct);
        JsonObject? json = null;
        try { json = JsonNode.Parse(reply.Body) as JsonObject; } catch (JsonException) { }
        return (reply.Status, json, reply);
    }

    private async Task<GuardedHttp.Reply> Send(HttpRequestMessage request, CancellationToken ct)
    {
        try { return await http.SendAsync(request, Timeout, ct); }
        catch (UrlRefusedException e) { throw new OAuthException("discovery_failed", e.Message); }
        catch (ResponseTooLargeException e) { throw new OAuthException("discovery_failed", e.Message); }
        catch (HttpRequestException e) when (e.InnerException is UrlRefusedException refused) { throw new OAuthException("discovery_failed", refused.Message); }
        catch (HttpRequestException) { throw new OAuthException("discovery_failed", "The sign-in service could not be reached."); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new OAuthException("discovery_failed", "The sign-in service took too long to answer."); }
    }

    private static string[] Strings(JsonNode? node) => node is JsonArray a ? a.Where(n => n?.GetValueKind() == JsonValueKind.String).Select(n => n!.GetValue<string>()).ToArray() : [];
    private static string? Str(JsonObject o, string key) => o[key]?.GetValueKind() == JsonValueKind.String ? o[key]!.GetValue<string>() : null;

    /// <summary>The MCP server's protected-resource metadata (RFC 9728): from its own 401 challenge when it names one, else the well-known addresses.</summary>
    private async Task<JsonObject> ResourceMetadataAsync(string serverUrl, CancellationToken ct)
    {
        var server = new Uri(serverUrl);
        var origin = server.GetLeftPart(UriPartial.Authority);
        var path = server.AbsolutePath.TrimEnd('/');

        // The server's own challenge names its metadata when it sends one.
        string? metadataUrl = null;
        try
        {
            using var probe = new HttpRequestMessage(HttpMethod.Post, serverUrl) { Content = new StringContent("""{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"openwork-den","version":"0.1.0"}}}""", Encoding.UTF8, "application/json") };
            probe.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            probe.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
            var reply = await Send(probe, ct);
            if (reply.Status == HttpStatusCode.Unauthorized && reply.Headers.WwwAuthenticate.Count > 0)
            {
                var match = ResourceMetadataRegex().Match(string.Join(", ", reply.Headers.WwwAuthenticate.Select(h => h.ToString())));
                if (match.Success) metadataUrl = match.Groups[1].Value;
            }
        }
        catch (OAuthException) { throw; }

        JsonObject? resourceMetadata = null;
        foreach (var candidate in new[] { metadataUrl, $"{origin}/.well-known/oauth-protected-resource{path}", $"{origin}/.well-known/oauth-protected-resource" }.Where(c => c is not null).Distinct())
        {
            var (status, json, _) = await GetJsonAsync(candidate!, ct);
            if (status == HttpStatusCode.OK && json is not null) { resourceMetadata = json; break; }
        }

        // No guessing at the server's own origin when it publishes no protected-resource metadata (as the reference does).
        return resourceMetadata ?? throw new OAuthException("discovery_failed", "The MCP server does not publish OAuth protected-resource metadata.");
    }

    /// <summary>The issuers the MCP server advertises right now (each once, in its order), for the issuer review. Nothing is registered or stored.</summary>
    public async Task<string[]> AdvertisedIssuersAsync(string serverUrl, CancellationToken ct = default)
    {
        var resourceMetadata = await ResourceMetadataAsync(serverUrl, ct);
        var resource = Str(resourceMetadata, "resource") is { Length: > 0 } declared ? declared : serverUrl;
        if (!ResourceMatches(serverUrl, resource)) throw new OAuthException("discovery_failed", "The MCP server's metadata describes a different resource than the address given.");
        return Strings(resourceMetadata["authorization_servers"]).Distinct(StringComparer.Ordinal).ToArray();
    }

    /// <summary>Finds the sign-in service for an MCP server. <paramref name="pinnedIssuer"/> picks one when several are advertised.</summary>
    public async Task<AuthServer> DiscoverAsync(string serverUrl, string? pinnedIssuer, CancellationToken ct = default)
    {
        var resourceMetadata = await ResourceMetadataAsync(serverUrl, ct);
        var advertised = Strings(resourceMetadata["authorization_servers"]);
        if (advertised.Length == 0) throw new OAuthException("discovery_failed", "The MCP server does not advertise a sign-in service.");
        var issuer = pinnedIssuer is not null ? advertised.FirstOrDefault(a => a.TrimEnd('/') == pinnedIssuer.TrimEnd('/')) ?? throw new OAuthException("issuer_mismatch", "The selected sign-in service is no longer advertised by this MCP server.") : advertised[0];
        var resource = Str(resourceMetadata, "resource") is { Length: > 0 } declared ? declared : serverUrl;
        if (!ResourceMatches(serverUrl, resource)) throw new OAuthException("discovery_failed", "The MCP server's metadata describes a different resource than the address given.");

        var issuerUri = new Uri(issuer);
        var issuerPath = issuerUri.AbsolutePath.TrimEnd('/');
        var issuerOrigin = issuerUri.GetLeftPart(UriPartial.Authority);
        var metadataCandidates = new List<string> { $"{issuerOrigin}/.well-known/oauth-authorization-server{issuerPath}", $"{issuerOrigin}/.well-known/openid-configuration{issuerPath}", $"{issuer.TrimEnd('/')}/.well-known/openid-configuration" };
        JsonObject? meta = null;
        foreach (var candidate in metadataCandidates.Distinct())
        {
            var (status, json, _) = await GetJsonAsync(candidate, ct);
            if (status == HttpStatusCode.OK && json is not null) { meta = json; break; }
        }
        if (meta is null) throw new OAuthException("discovery_failed", "The sign-in service's metadata could not be read.");
        if (Str(meta, "issuer")?.TrimEnd('/') != issuer.TrimEnd('/')) throw new OAuthException("issuer_mismatch", "The sign-in service names a different issuer than the one the MCP server advertised.");
        var authorize = Str(meta, "authorization_endpoint") ?? throw new OAuthException("discovery_failed", "The sign-in service has no authorization endpoint.");
        var token = Str(meta, "token_endpoint") ?? throw new OAuthException("discovery_failed", "The sign-in service has no token endpoint.");
        var methods = Strings(meta["code_challenge_methods_supported"]);
        if (methods.Length > 0 && !methods.Contains("S256")) throw new OAuthException("discovery_failed", "The sign-in service does not support PKCE (S256).");
        var registration = Str(meta, "registration_endpoint");
        foreach (var endpoint in new[] { authorize, token, registration }.Where(e => e is not null))
        {
            try { await http.AssertPublicAsync(endpoint!, ct); }
            catch (UrlRefusedException e) { throw new OAuthException("discovery_failed", e.Message); }
        }
        var scopes = Strings(resourceMetadata["scopes_supported"]);
        return new AuthServer(issuer, authorize, token, registration, resource, scopes, advertised, meta["client_id_metadata_document_supported"]?.GetValueKind() == JsonValueKind.True);
    }

    private static bool ResourceMatches(string serverUrl, string resource)
    {
        static string Norm(string u) => u.TrimEnd('/').ToLowerInvariant();
        return Norm(serverUrl) == Norm(resource) || Norm(serverUrl).StartsWith(Norm(resource) + "/", StringComparison.Ordinal);
    }

    /// <summary>Registers this app with the authorization server (RFC 7591). Public client, PKCE, authorization code and refresh.</summary>
    public async Task<(string ClientId, string? Secret, string Method)> RegisterAsync(AuthServer server, string redirectUri, CancellationToken ct = default)
    {
        if (server.RegistrationEndpoint is null) throw new OAuthException("configuration_required", "This authorization server requires a pre-registered OAuth client before OpenWork can connect.");
        var body = new JsonObject
        {
            ["client_name"] = "OpenWork",
            ["application_type"] = "web",
            ["redirect_uris"] = new JsonArray(redirectUri),
            ["grant_types"] = new JsonArray("authorization_code", "refresh_token"),
            ["response_types"] = new JsonArray("code"),
            ["token_endpoint_auth_method"] = "none",
        };
        using var request = new HttpRequestMessage(HttpMethod.Post, server.RegistrationEndpoint) { Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json") };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        var reply = await Send(request, ct);
        JsonObject? json = null;
        try { json = JsonNode.Parse(reply.Body) as JsonObject; } catch (JsonException) { }
        if ((int)reply.Status is < 200 or >= 300 || json is null || Str(json, "client_id") is not { Length: > 0 } clientId)
            throw new OAuthException("registration_failed", "The authorization server did not accept the app registration.", (int)reply.Status);
        return (clientId, Str(json, "client_secret"), Str(json, "token_endpoint_auth_method") ?? "none");
    }

    public static (string Verifier, string Challenge) NewPkce()
    {
        var verifier = Base64Url(RandomNumberGenerator.GetBytes(48));
        return (verifier, Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))));
    }

    public static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static string AuthorizeUrl(AuthServer server, string clientId, string redirectUri, string state, string challenge, string? scope)
    {
        var query = new List<string>
        {
            "response_type=code",
            $"client_id={Uri.EscapeDataString(clientId)}",
            $"code_challenge={challenge}",
            "code_challenge_method=S256",
            $"redirect_uri={Uri.EscapeDataString(redirectUri)}",
            $"state={Uri.EscapeDataString(state)}",
        };
        if (!string.IsNullOrWhiteSpace(scope)) query.Add($"scope={Uri.EscapeDataString(scope)}");
        query.Add($"resource={Uri.EscapeDataString(server.Resource)}");
        var separator = server.AuthorizationEndpoint.Contains('?') ? "&" : "?";
        return server.AuthorizationEndpoint + separator + string.Join("&", query);
    }

    public Task<TokenSet> ExchangeCodeAsync(string tokenEndpoint, string clientId, string? secret, string? method, string code, string redirectUri, string verifier, string resource, CancellationToken ct = default) =>
        TokenAsync(tokenEndpoint, clientId, secret, method, new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code", ["code"] = code, ["redirect_uri"] = redirectUri, ["code_verifier"] = verifier, ["resource"] = resource,
        }, ct);

    public Task<TokenSet> RefreshAsync(string tokenEndpoint, string clientId, string? secret, string? method, string refreshToken, string resource, CancellationToken ct = default) =>
        TokenAsync(tokenEndpoint, clientId, secret, method, new Dictionary<string, string> { ["grant_type"] = "refresh_token", ["refresh_token"] = refreshToken, ["resource"] = resource }, ct);

    private async Task<TokenSet> TokenAsync(string tokenEndpoint, string clientId, string? secret, string? method, Dictionary<string, string> form, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (secret is not null && method != "client_secret_post")
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Uri.EscapeDataString(clientId)}:{Uri.EscapeDataString(secret)}")));
        else
        {
            form["client_id"] = clientId;
            if (secret is not null) form["client_secret"] = secret;
        }
        request.Content = new FormUrlEncodedContent(form);
        var reply = await Send(request, ct);
        JsonObject? json = null;
        try { json = JsonNode.Parse(reply.Body) as JsonObject; } catch (JsonException) { }
        if ((int)reply.Status is < 200 or >= 300 || json is null || Str(json, "access_token") is not { Length: > 0 } access)
        {
            var error = json is null ? null : Str(json, "error");
            throw new OAuthException(error is "invalid_grant" or "invalid_client" or "unauthorized_client" ? "token_rejected" : "token_failed",
                "The sign-in service did not issue a token.", (int)reply.Status);
        }
        DateTime? expires = json["expires_in"]?.GetValueKind() == JsonValueKind.Number ? DateTime.UtcNow.AddSeconds(json["expires_in"]!.GetValue<double>()) : null;
        return new TokenSet(access, Str(json, "refresh_token"), Str(json, "token_type") ?? "Bearer", Str(json, "scope"), expires);
    }
}
