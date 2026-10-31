using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using WorkAI360.Api.Features.Library;

namespace WorkAI360.Api.Features.Connections;

/// <summary>What an MCP server needs before OpenWork can connect, found without saving anything or registering an app.</summary>
public sealed class McpDiscovery(GuardedHttp http, McpOAuth oauth, McpClient mcp)
{
    public sealed record Check(string Id, string Status, int? HttpStatus = null, string? Code = null)
    {
        public JsonObject ToJson()
        {
            var o = new JsonObject { ["id"] = Id, ["status"] = Status };
            if (HttpStatus is { } h) o["httpStatus"] = h;
            if (Code is not null) o["code"] = Code;
            return o;
        }
    }

    private static readonly (string Code, string Label, string Reason, bool Required)[] AlwaysManual =
    [
        ("provider_access", "Provider access", "Provider roles, licenses, tenant access, and administrator consent are not described by MCP OAuth metadata.", false),
        ("network_trust", "Network trust", "Private routing, proxy, firewall, and private CA requirements must be confirmed in the Den deployment environment.", false),
    ];

    public async Task<JsonObject> DiscoverAsync(string url, IReadOnlyList<(string Name, string Value)> headers, Action<Check>? onCheck, CancellationToken ct, TimeSpan? timeout = null)
    {
        onCheck ??= _ => { };
        await http.AssertPublicAsync(url, ct);   // a refused address is an error for the caller, not a "failed" server
        onCheck(new Check("server", "running"));
        var warnings = new JsonArray();
        var manual = new JsonArray();
        void Manual((string Code, string Label, string Reason, bool Required) m) => manual.Add(new JsonObject { ["code"] = m.Code, ["label"] = m.Label, ["reason"] = m.Reason, ["required"] = m.Required });

        // First ask the server without any sign-in; the answer says whether it needs one.
        string initialize; string? protocol = null; int? status = null;
        try { protocol = await mcp.InitializeAsync(new McpTarget(url, headers), ct); initialize = "succeeded"; status = 200; }
        catch (McpException e) when (e.Kind == McpFailure.Unauthorized) { initialize = "authentication_required"; status = e.HttpStatus; }
        catch (McpException e) when (e.Kind == McpFailure.Refused) { throw new UrlRefusedException(e.Message); }
        catch (McpException e) { initialize = "failed"; status = e.HttpStatus; if (e.Kind is McpFailure.Protocol or McpFailure.Tool) initialize = "unsupported"; }

        var server = new JsonObject { ["url"] = url, ["initialize"] = initialize == "unsupported" ? "failed" : initialize };
        if (protocol is not null) server["protocolVersion"] = protocol;
        onCheck(new Check("server", initialize is "succeeded" or "authentication_required" ? "passed" : "failed", status, initialize == "authentication_required" ? "authentication_required" : initialize == "failed" ? "unavailable" : initialize == "unsupported" ? "unsupported" : null));

        var auth = new JsonObject { ["kind"] = "none", ["authorizationServers"] = new JsonArray(), ["requiredScopes"] = new JsonArray(), ["recommendedScopes"] = new JsonArray(), ["refreshSupport"] = "unknown", ["availableRegistrationMethods"] = new JsonArray("pre_registered"), ["recommendedRegistrationMethod"] = "pre_registered" };
        var tools = new JsonObject { ["visibility"] = "unavailable" };
        string result;
        if (initialize == "succeeded")
        {
            onCheck(new Check("resource", "skipped", Code: "not_required"));
            onCheck(new Check("provider", "skipped", Code: "not_required"));
            try
            {
                var list = await mcp.ListToolsAsync(new McpTarget(url, headers), ct);
                tools = new JsonObject { ["visibility"] = "available_without_auth", ["count"] = list.Count, ["items"] = new JsonArray(list.Take(50).Select(t =>
                {
                    var o = new JsonObject { ["name"] = t.Name };
                    foreach (var key in new[] { "readOnlyHint", "destructiveHint", "openWorldHint" }) if (t.Annotations?[key] is JsonValue v) o[key] = v.DeepClone();
                    return (JsonNode)o;
                }).ToArray()) };
            }
            catch (McpException) { tools = new JsonObject { ["visibility"] = "unavailable" }; }
            result = "ready";
        }
        else if (initialize == "authentication_required")
        {
            onCheck(new Check("resource", "running"));
            AuthServer? found = null;
            try { found = await oauth.DiscoverAsync(url, null, ct); }
            catch (OAuthException e) { warnings.Add(new JsonObject { ["code"] = "oauth_resource_metadata_unavailable", ["message"] = e.Code == "issuer_mismatch" ? e.Message : "Resource server does not implement OAuth 2.0 Protected Resource Metadata." }); }
            tools = new JsonObject { ["visibility"] = "requires_auth" };
            if (found is null)
            {
                auth["kind"] = "manual_bearer";
                onCheck(new Check("resource", "failed", Code: "unavailable"));
                onCheck(new Check("provider", "skipped"));
                Manual(("oauth_client_registration", "Register an OAuth client", "The authorization server does not advertise client metadata documents or dynamic registration.", true));
                result = "manual_action_required";
            }
            else
            {
                onCheck(new Check("resource", "passed", 200));
                onCheck(new Check("provider", "passed", 200));
                var methods = new JsonArray("pre_registered");
                if (found.RegistrationEndpoint is not null) methods.Add("dynamic");
                auth["kind"] = "oauth"; auth["resource"] = found.Resource;
                auth["authorizationServers"] = new JsonArray(new JsonObject
                {
                    ["issuer"] = found.Issuer, ["authorizationEndpoint"] = found.AuthorizationEndpoint, ["tokenEndpoint"] = found.TokenEndpoint, ["registrationEndpoint"] = found.RegistrationEndpoint,
                    ["clientIdMetadataDocumentSupported"] = found.SupportsClientMetadata, ["scopesSupported"] = new JsonArray(found.ScopesSupported.Select(s => (JsonNode)s).ToArray()),
                });
                auth["resourceScopesSupported"] = new JsonArray(found.ScopesSupported.Select(s => (JsonNode)s).ToArray());
                auth["recommendedScopes"] = new JsonArray(found.ScopesSupported.Select(s => (JsonNode)s).ToArray());
                auth["refreshSupport"] = "unknown";
                auth["availableRegistrationMethods"] = methods;
                auth["recommendedRegistrationMethod"] = found.RegistrationEndpoint is not null ? "dynamic" : "pre_registered";
                if (found.RegistrationEndpoint is null) { Manual(("oauth_client_registration", "Register an OAuth client", "The authorization server does not advertise client metadata documents or dynamic registration.", true)); result = "manual_action_required"; }
                else result = "ready";
            }
        }
        else
        {
            onCheck(new Check("resource", "skipped"));
            onCheck(new Check("provider", "skipped"));
            result = initialize == "unsupported" ? "unsupported" : "unreachable";
        }
        foreach (var m in AlwaysManual) Manual(m);
        return new JsonObject { ["status"] = result, ["server"] = server, ["authentication"] = auth, ["tools"] = tools, ["manualRequirements"] = manual, ["warnings"] = warnings };
    }

    /// <summary>Turns "vercel", "mcp.example.com" or a full address into addresses worth probing, in order.</summary>
    public static (string Kind, List<string> Candidates, string? Reason) Candidates(string query, McpPreset? preset)
    {
        if (preset is not null) return ("preset", [preset.Url], null);
        var q = query.Trim();
        if (q.Length == 0) return ("invalid", [], "Enter a server address or a product name.");
        if (q.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || q.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return Uri.TryCreate(q, UriKind.Absolute, out var u) ? ("url", [u.ToString()], null) : ("invalid", [], "That does not look like a web address.");
        if (q.Contains(' ') || q.Contains('/') && !q.Contains('.')) return ("invalid", [], "Use a web address, a host name or a product name.");
        if (q.Contains('.')) return ("host", [$"https://{q.TrimEnd('/')}/mcp", $"https://{q.TrimEnd('/')}"], null);
        var name = q.ToLowerInvariant();
        return ("name", [$"https://mcp.{name}.com/mcp", $"https://mcp.{name}.com", $"https://{name}.com/mcp"], null);
    }

    public static string SuggestName(string url)
    {
        var host = new Uri(url).Host;
        var parts = host.Split('.').Where(p => p is not ("mcp" or "www" or "api")).ToArray();
        var label = parts.Length > 1 ? parts[^2] : parts.FirstOrDefault() ?? host;
        return label.Length == 0 ? host : char.ToUpperInvariant(label[0]) + label[1..];
    }
}

public sealed partial class ConnectionsFeature
{
    private static async Task<IResult> DiscoverAsync(HttpContext ctx, Caller caller, bool stream)
    {
        var body = await Zod.BodyAsync(ctx);
        var raw = Zod.Str(body, "url")!;
        var issues = ConnectionInput.UrlIssues(raw, ctx.RequestServices.GetRequiredService<GuardedHttp>().AllowPrivate);
        if (issues.Count > 0) throw new Invalid(issues);
        var headers = new List<(string Name, string Value)>();
        var rawHeaders = Zod.Array(body, "requestHeaders", 4);
        for (var i = 0; rawHeaders is not null && i < rawHeaders.Count; i++)
            headers.Add((Zod.Str(rawHeaders[i], "name", max: 256, path: $"requestHeaders.{i}.name")!, Zod.Str(rawHeaders[i], "value", trim: false, max: 8192, path: $"requestHeaders.{i}.value")!));
        if (ConnectionService.ValidateHeaders(headers, "discover") is { } problem) return Bad(problem);
        var discovery = ctx.RequestServices.GetRequiredService<McpDiscovery>();
        var canViewSettings = caller.Has("connections.view");

        JsonObject ForCaller(JsonObject result)
        {
            if (!canViewSettings) result.Remove("publishedSignInAddresses");
            return result;
        }

        if (!stream)
        {
            try { return Ok(ForCaller(await discovery.DiscoverAsync(raw, headers, null, ctx.RequestAborted))); }
            catch (UrlRefusedException e) { return Ok(new { error = "requirements_discovery_failed", message = e.Message }, 502); }
        }
        return Results.Stream(async output =>
        {
            ctx.Response.Headers.CacheControl = "no-store";
            async Task Send(string name, JsonNode data)
            {
                await output.WriteAsync(Encoding.UTF8.GetBytes($"event: {name}\ndata: {data.ToJsonString()}\n\n"));
                await output.FlushAsync();
            }
            var pending = new List<McpDiscovery.Check>();
            try
            {
                var result = await discovery.DiscoverAsync(raw, headers, pending.Add, ctx.RequestAborted);
                foreach (var check in pending) await Send("check", check.ToJson());
                await Send("result", ForCaller(result));
            }
            catch (Exception e) when (e is UrlRefusedException or McpException or OAuthException or HttpRequestException)
            {
                foreach (var check in pending) await Send("check", check.ToJson());
                await Send("error", new JsonObject { ["message"] = "The server check could not finish. Try again." });
            }
        }, "text/event-stream");
    }

    private static void MapDiscovery(WebApplication app)
    {
        app.MapPost("/v1/mcp-connections/discover", (HttpContext ctx, ConnectionService _) => Run(ctx, (caller, _) => DiscoverAsync(ctx, caller, false)));
        app.MapPost("/v1/mcp-connections/discover/stream", (HttpContext ctx, ConnectionService _) => Run(ctx, (caller, _) => DiscoverAsync(ctx, caller, true)));

        app.MapPost("/v1/mcp-connections/resolve", (HttpContext ctx, IConfiguration config) => Run(ctx, async (caller, service) =>
        {
            if (Need(ctx, caller, "connections.manage") is { } denied) return denied;
            var body = await Zod.BodyAsync(ctx);
            var query = Zod.Str(body, "query", trim: false, min: 1, max: 2048)!;
            var presets = McpPresets.ForCatalog(config.GetValue<bool>("Connections:ExpandedPresets")).ToList();
            var q = query.Trim().ToLowerInvariant();
            var preset = presets.FirstOrDefault(p => p.PresetId == q || p.DisplayName.ToLowerInvariant() == q || (Uri.TryCreate(q.Contains("://") ? q : "https://" + q, UriKind.Absolute, out var u) && Uri.TryCreate(p.Url, UriKind.Absolute, out var pu) && u.Host == pu.Host));
            var (kind, candidates, reason) = McpDiscovery.Candidates(query, preset);
            if (kind == "invalid") return Ok(new { resolution = "not_found", attempted = Array.Empty<string>(), reason });
            var discovery = ctx.RequestServices.GetRequiredService<McpDiscovery>();
            var canViewSettings = caller.Has("connections.view");
            (string Url, JsonObject Result)? match = null;
            foreach (var candidate in candidates)
            {
                try
                {
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ctx.RequestAborted);
                    cts.CancelAfter(TimeSpan.FromSeconds(8));
                    var result = await discovery.DiscoverAsync(candidate, [], null, cts.Token);
                    var initialize = result["server"]?["initialize"]?.GetValue<string>();
                    var qualifies = initialize == "succeeded" || (initialize == "authentication_required" && result["authentication"]?["kind"]?.GetValue<string>() == "oauth");
                    if (qualifies) { match = (candidate, result); break; }
                }
                catch (Exception e) when (e is UrlRefusedException or McpException or OAuthException or OperationCanceledException or HttpRequestException) { /* this candidate loses */ }
            }
            JsonObject Discovery(JsonObject r) { if (!canViewSettings) r.Remove("publishedSignInAddresses"); return r; }
            if (preset is not null)
                return Ok(new Dictionary<string, object?>
                {
                    ["resolution"] = "preset", ["attempted"] = candidates, ["preset"] = McpPresets.ToJson(preset, service.CallbackUrl),
                    ["match"] = match is { } m1 ? new { url = m1.Url, suggestedName = preset.DisplayName, discovery = Discovery(m1.Result) } : null,
                }.Where(kv => kv.Value is not null).ToDictionary(kv => kv.Key, kv => kv.Value));
            if (match is not { } m2) return Ok(new { resolution = "not_found", attempted = candidates });
            return Ok(new { resolution = "discovered", attempted = candidates, match = new { url = m2.Url, suggestedName = McpDiscovery.SuggestName(m2.Url), discovery = Discovery(m2.Result) } });
        }));
    }
}
