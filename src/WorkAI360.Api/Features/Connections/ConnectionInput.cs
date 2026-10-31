using System.Text.Json;
using System.Text.RegularExpressions;
using WorkAI360.Api.Features.Library;

namespace WorkAI360.Api.Features.Connections;

public sealed record OAuthClientInput(string ClientId, string? ClientSecret, string? Method);

/// <summary>A create or edit request, read the way the reference's schemas read it (same messages, first problem reported with the count of the rest).</summary>
public sealed class ConnectionInput
{
    public string Name = "";
    public string? ExternalKey;
    public string Url = "";
    public string AuthType = "none";
    public string CredentialMode = "shared";
    public bool? ExposeDirectly;
    public string? ApiKey;
    public string? ApiKeyAuthScheme;
    public bool HasRequestHeaders;
    /// <summary>For an edit, a header with no value keeps the stored value of the header with the same name.</summary>
    public List<(string Name, string? Value)> RequestHeaders = [];
    public OAuthClientInput? OAuthClient;
    public bool ManualEndpointsPresent;
    public (string Authorization, string Token)? ManualEndpoints;
    public bool IssuerPresent;
    public string? Issuer;
    public List<string>? RequestedScopes;
    public AccessInput Access = new(true, [], []);
    public bool AccessPresent;
    public DateTime? ExpectedUpdatedAt;

    private static readonly Regex Key = new("^[a-z0-9][a-z0-9._-]{0,127}$", RegexOptions.Compiled);
    private static readonly HashSet<string> SensitiveParameters = ["access_token", "api_key", "client_secret", "token", "refresh_token", "id_token", "code_verifier"];

    public static List<(string[] Path, string Code, string Message)> UrlIssues(string value, bool allowPrivate, string field = "url")
    {
        var issues = new List<(string[], string, string)>();
        var path = field.Split('.');
        if (value.Length > 2048) issues.Add((path, "too_big", "Too big: expected string to have <=2048 characters"));
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || !value.Contains("://")) { issues.Add((path, "invalid_format", "Invalid URL")); return issues; }
        if (uri.Scheme is not ("http" or "https")) issues.Add((path, "custom", "MCP URLs must use HTTP or HTTPS."));
        if (uri.Scheme == "http" && !allowPrivate) issues.Add((path, "custom", "Hosted MCP connections must use HTTPS."));
        if (!string.IsNullOrEmpty(uri.Fragment)) issues.Add((path, "custom", "MCP URLs must not contain a fragment."));
        if (!string.IsNullOrEmpty(uri.UserInfo)) issues.Add((path, "custom", "MCP URLs must not contain embedded credentials."));
        foreach (var pair in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var name = Uri.UnescapeDataString(pair.Split('=')[0]);
            if (SensitiveParameters.Contains(name.ToLowerInvariant())) issues.Add((path, "custom", $"MCP URL query parameter \"{name}\" must not contain credentials."));
        }
        return issues;
    }

    public static ConnectionInput Parse(JsonElement body, bool editing, bool allowPrivate)
    {
        var input = new ConnectionInput();
        input.Name = Zod.Str(body, "name", max: 255)!;
        if (!editing && Zod.Has(body, "externalKey"))
        {
            input.ExternalKey = Zod.Str(body, "externalKey", trim: false, min: 0);
            if (input.ExternalKey is null || !Key.IsMatch(input.ExternalKey)) throw new Invalid("externalKey", "Invalid string: must match pattern /^[a-z0-9][a-z0-9._-]{0,127}$/", "invalid_format");
        }
        var rawUrl = Zod.Str(body, "url")!;
        var issues = UrlIssues(rawUrl, allowPrivate);
        if (issues.Count > 0) throw new Invalid(issues);
        input.Url = rawUrl;
        input.AuthType = Zod.Enum(body, "authType", ["oauth", "apikey", "none"]);
        if (editing) input.CredentialMode = Zod.Enum(body, "credentialMode", ["shared", "per_member"]);
        else if (Zod.Has(body, "credentialMode")) input.CredentialMode = Zod.Enum(body, "credentialMode", ["shared", "per_member"]);
        input.ExposeDirectly = Zod.Bool(body, "exposeDirectly");
        if (Zod.Has(body, "apiKey")) input.ApiKey = Zod.Str(body, "apiKey", max: 4096);
        if (Zod.Has(body, "apiKeyAuthScheme")) input.ApiKeyAuthScheme = Zod.Enum(body, "apiKeyAuthScheme", ["bearer", "token"]);

        var headers = Zod.Array(body, "requestHeaders", 4);
        if (headers is not null)
        {
            input.HasRequestHeaders = true;
            for (var i = 0; i < headers.Count; i++)
            {
                var h = headers[i];
                if (h.ValueKind != JsonValueKind.Object) throw new Invalid($"requestHeaders.{i}", $"Invalid input: expected object, received {Zod.Kind(h)}");
                var name = Zod.Str(h, "name", max: 256, path: $"requestHeaders.{i}.name")!;
                string? value = null;
                if (Zod.Has(h, "value") && (editing || true))
                {
                    value = Zod.Str(h, "value", trim: false, max: 8192, path: $"requestHeaders.{i}.value");
                }
                else if (!editing) throw new Invalid($"requestHeaders.{i}.value", "Invalid input: expected string, received undefined");
                input.RequestHeaders.Add((name, value));
            }
        }
        if (Zod.Has(body, "oauthClient"))
        {
            var o = Zod.Object(body, "oauthClient");
            input.OAuthClient = new OAuthClientInput(Zod.Str(o, "clientId", max: 512, path: "oauthClient.clientId")!,
                Zod.Has(o, "clientSecret") ? Zod.Str(o, "clientSecret", max: 4096, path: "oauthClient.clientSecret") : null,
                Zod.Has(o, "tokenEndpointAuthMethod") ? Zod.Enum(o, "tokenEndpointAuthMethod", ["client_secret_basic", "client_secret_post"], "oauthClient.tokenEndpointAuthMethod") : null);
        }
        if (Zod.Has(body, "manualOAuthEndpoints"))
        {
            input.ManualEndpointsPresent = true;
            if (body.GetProperty("manualOAuthEndpoints").ValueKind != JsonValueKind.Null)
            {
                var m = Zod.Object(body, "manualOAuthEndpoints");
                var a = Zod.Str(m, "authorizationEndpoint", path: "manualOAuthEndpoints.authorizationEndpoint")!;
                var t = Zod.Str(m, "tokenEndpoint", path: "manualOAuthEndpoints.tokenEndpoint")!;
                foreach (var (field, value) in new[] { ("authorizationEndpoint", a), ("tokenEndpoint", t) })
                    if (!Uri.TryCreate(value, UriKind.Absolute, out var u) || u.Scheme is not ("http" or "https")) throw new Invalid($"manualOAuthEndpoints.{field}", "Invalid URL", "invalid_format");
                input.ManualEndpoints = (a, t);
            }
        }
        if (Zod.Has(body, "authorizationServerIssuer"))
        {
            input.IssuerPresent = true;
            if (body.GetProperty("authorizationServerIssuer").ValueKind != JsonValueKind.Null)
            {
                input.Issuer = Zod.Str(body, "authorizationServerIssuer", max: 2048);
                if (!Uri.TryCreate(input.Issuer, UriKind.Absolute, out _)) throw new Invalid("authorizationServerIssuer", "Invalid URL", "invalid_format");
            }
        }
        var scopes = Zod.Array(body, "requestedScopes", 100);
        if (scopes is not null)
        {
            input.RequestedScopes = [];
            for (var i = 0; i < scopes.Count; i++)
            {
                if (scopes[i].ValueKind != JsonValueKind.String) throw new Invalid($"requestedScopes.{i}", $"Invalid input: expected string, received {Zod.Kind(scopes[i])}");
                var s = scopes[i].GetString()!.Trim();
                if (s.Length is < 1 or > 255) throw new Invalid($"requestedScopes.{i}", s.Length < 1 ? "Too small: expected string to have >=1 characters" : "Too big: expected string to have <=255 characters", s.Length < 1 ? "too_small" : "too_big");
                input.RequestedScopes.Add(s);
            }
        }
        if (Zod.Has(body, "access"))
        {
            input.AccessPresent = true;
            input.Access = ParseAccess(Zod.Object(body, "access"));
        }
        else if (editing) throw new Invalid("access", "Invalid input: expected object, received undefined");
        if (editing)
        {
            var expected = Zod.Str(body, "expectedUpdatedAt")!;
            if (!DateTimeOffset.TryParse(expected, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out var at) || !Regex.IsMatch(expected, @"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$"))
                throw new Invalid("expectedUpdatedAt", "Invalid ISO datetime", "invalid_format");
            input.ExpectedUpdatedAt = at.UtcDateTime;
        }
        return input;
    }

    public static AccessInput ParseAccess(JsonElement access)
    {
        List<string> Ids(string name, string prefix)
        {
            var raw = Zod.Array(access, name, 200);
            var list = new List<string>();
            for (var i = 0; raw is not null && i < raw.Count; i++)
            {
                if (raw[i].ValueKind != JsonValueKind.String) throw new Invalid($"access.{name}.{i}", $"Invalid input: expected string, received {Zod.Kind(raw[i])}");
                var s = raw[i].GetString()!.Trim();
                if (s.Length < 1) throw new Invalid($"access.{name}.{i}", "Too small: expected string to have >=1 characters", "too_small");
                list.Add(Zod.TypeId(s, prefix, $"access.{name}.{i}"));
            }
            return list;
        }
        var orgWide = false;
        if (Zod.Has(access, "orgWide"))
        {
            var v = access.GetProperty("orgWide");
            if (v.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw new Invalid("access.orgWide", $"Invalid input: expected boolean, received {Zod.Kind(v)}");
            orgWide = v.GetBoolean();
        }
        return new AccessInput(orgWide, Ids("memberIds", "om"), Ids("teamIds", "tem"));
    }
}
