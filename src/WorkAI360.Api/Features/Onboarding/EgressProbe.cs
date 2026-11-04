using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using WorkAI360.Api.Features.Connections;

namespace WorkAI360.Api.Features.Onboarding;

/// <summary>
/// The controlled egress diagnostic (the reference's <c>egress-diagnostics.ts</c>): fixed HTTP, redirect, OAuth-shaped and MCP probes from this server to the
/// operator-configured public Diagnostics origin, layer by layer, stopping at the first failure and saying who should act. Every request is signed for its
/// run and step with the diagnostic token; every answer must carry the Diagnostics application's own reference, so a proxy that answers instead is caught.
/// Requests go through the outbound guard (public addresses only, redirects never followed, bounded). Only synthetic values are ever sent.
/// </summary>
public sealed class EgressProbe(GuardedHttp http)
{
    public const string RunHeader = "x-openwork-diagnostic-run-id";
    public const string StepHeader = "x-openwork-diagnostic-step";
    public const string SignatureHeader = "x-openwork-diagnostic-signature";
    public const string IdHeader = "x-openwork-diagnostic-id";
    public static readonly string[] StepIds = ["reachability", "http-methods", "redirect", "oauth-discovery", "oauth-token", "mcp-handshake"];
    private const int MaxJsonBytes = 64 * 1024;
    private static readonly Regex DiagnosticId = new("^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly Dictionary<string, (string Category, string Label, string Message)> Definitions = new()
    {
        ["reachability"] = ("connectivity", "Public reachability", "Den reached the public Diagnostics service over HTTP."),
        ["http-methods"] = ("http", "HTTP methods and headers", "HEAD, OPTIONS, authenticated JSON POST, and response headers passed."),
        ["redirect"] = ("http", "Same-origin redirect", "Den accepted and completed a controlled same-origin redirect."),
        ["oauth-discovery"] = ("oauth", "OAuth metadata discovery", "Protected-resource and authorization-server metadata were discovered and validated."),
        ["oauth-token"] = ("oauth", "OAuth-shaped token POST", "Den completed a client-secret Basic token request and received a short-lived synthetic token."),
        ["mcp-handshake"] = ("mcp", "MCP handshake and tool call", "Initialize, ready notification, tool discovery, and a content-free synthetic tool call passed."),
    };

    private sealed class Failure(string category, string code, string message, string owner, string action) : Exception(message)
    {
        public string Category { get; } = category;
        public string Code { get; } = code;
        public string Owner { get; } = owner;
        public string Action { get; } = action;
    }

    private sealed class Evidence
    {
        public List<int> Statuses { get; } = [];
        public List<string> Ids { get; } = [];
    }

    private static Failure Protocol(string category, string code, string message) =>
        new(category, code, message, "openwork-support", "Give OpenWork support the run ID and diagnostic reference so the response contract can be compared with the remote trace.");

    /// <summary>A network error in the reference's words; never the exception text (it can name internal hosts).</summary>
    private static Failure Network(Exception error)
    {
        if (error is UrlRefusedException)
            return new("connectivity", "egress_target_refused", "The Diagnostics origin points to a private or internal address, which the outbound guard refuses.", "den-operator",
                "Point Onboarding:DiagnosticsOrigin at the public Diagnostics service (private addresses are refused unless Connections:AllowPrivateUrls is on).");
        var socket = (error as HttpRequestException)?.InnerException as SocketException ?? error.InnerException as SocketException;
        if (socket?.SocketErrorCode is SocketError.HostNotFound or SocketError.TryAgain or SocketError.NoData)
            return new("connectivity", socket.SocketErrorCode == SocketError.TryAgain ? "EAI_AGAIN" : "ENOTFOUND", "The Den container could not resolve the Diagnostics hostname.", "network-administrator",
                "Ask the network administrator to verify cluster DNS, DNS policy, and the diagnostic hostname.");
        if (error.InnerException is AuthenticationException || error is AuthenticationException)
            return new("connectivity", "tls_validation_failed", "TLS validation failed before Diagnostics received an HTTP request.", "network-administrator",
                "Ask the network administrator to verify TLS inspection, the trusted CA bundle, hostname policy, and certificate expiry inside the Den container.");
        if (error is OperationCanceledException || socket?.SocketErrorCode == SocketError.TimedOut)
            return new("connectivity", "ETIMEDOUT", "The outbound request timed out before a valid Diagnostics response arrived.", "network-administrator",
                "Ask the network administrator to inspect egress firewall, proxy routing, NetworkPolicy, service-mesh, and timeout configuration.");
        var code = socket?.SocketErrorCode switch
        {
            SocketError.ConnectionRefused => "ECONNREFUSED", SocketError.ConnectionReset => "ECONNRESET", SocketError.NetworkUnreachable => "ENETUNREACH", _ => "fetch_failed",
        };
        return new("connectivity", code, "The Den container could not complete the outbound connection.", "network-administrator",
            "Ask the Den operator and network administrator to inspect container egress, proxy configuration, service-mesh policy, and connection resets.");
    }

    private static Failure Http(int status, string category) => status switch
    {
        401 or 403 => new(category, $"http_{status}", $"Diagnostics rejected the synthetic authorization with HTTP {status}.", "den-operator",
            "Verify that Den and the Diagnostics deployment use the same synthetic diagnostic token and that the proxy forwards Authorization headers."),
        407 => new("connectivity", "http_407", "The corporate proxy requires authentication.", "network-administrator",
            "Configure the customer proxy credentials for the Den runtime and confirm Node outbound requests use the approved proxy path."),
        >= 500 => new(category, $"http_{status}", $"The Diagnostics service returned HTTP {status}.", "openwork-support",
            "Give OpenWork support the run ID and diagnostic reference so the Diagnostics deployment can be inspected."),
        _ => new(category, $"http_{status}", $"The diagnostic request returned unexpected HTTP {status}.", "openwork-support",
            "Give OpenWork support the run ID and response status, then compare the matching remote trace."),
    };

    public static string Signature(string secret, string runId, string step) =>
        Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes($"openwork-diagnostics-v1\n{runId}\n{step}")));

    public async Task<JsonObject> RunAsync(string origin, string bearerToken, TimeSpan? requestTimeout = null, CancellationToken ct = default)
    {
        origin = origin.TrimEnd('/');
        var timeout = requestTimeout ?? TimeSpan.FromSeconds(5);
        var runId = Guid.NewGuid().ToString();
        var runStarted = DateTime.UtcNow;
        var accessToken = "";

        async Task<GuardedHttp.Reply> Send(string category, Evidence evidence, int[] expected, HttpMethod method, string url, string step, string? body = null, string? contentType = null, Dictionary<string, string>? headers = null)
        {
            using var request = new HttpRequestMessage(method, url);
            request.Headers.TryAddWithoutValidation(RunHeader, runId);
            request.Headers.TryAddWithoutValidation(StepHeader, step);
            request.Headers.TryAddWithoutValidation(SignatureHeader, Signature(bearerToken, runId, step));
            request.Headers.TryAddWithoutValidation("user-agent", "openwork-den-egress-diagnostics/1.0");
            foreach (var (k, v) in headers ?? []) request.Headers.TryAddWithoutValidation(k, v);
            if (body is not null) request.Content = new StringContent(body, Encoding.UTF8, contentType ?? "application/json");
            GuardedHttp.Reply reply;
            try { reply = await http.SendAsync(request, timeout, ct); }
            catch (Exception e) when (e is HttpRequestException or OperationCanceledException or UrlRefusedException or IOException or AuthenticationException) { throw Network(e); }
            catch (ResponseTooLargeException) { throw Protocol("http", "response_too_large", "Diagnostics returned more than 64 KiB of response data."); }
            var status = (int)reply.Status;
            evidence.Statuses.Add(status);
            var id = reply.Headers.TryGetValues(IdHeader, out var ids) ? ids.FirstOrDefault() ?? "" : "";
            if (DiagnosticId.IsMatch(id)) evidence.Ids.Add(id);
            if (!expected.Contains(status)) throw Http(status, category);
            if (!DiagnosticId.IsMatch(id))
                throw new Failure(category, "diagnostic_reference_missing", "A response arrived, but it did not contain proof that it came from the Diagnostics application.", "network-administrator",
                    "Ask the network administrator to inspect whether a proxy, gateway, or service mesh replaced the response or removed x-openwork-diagnostic-id.");
            return reply;
        }

        static JsonObject Json(GuardedHttp.Reply reply)
        {
            if (reply.Body.Length == 0) throw new Failure("http", "empty_response_body", "Diagnostics returned an empty response where JSON was required.", "openwork-support", "Give OpenWork support the run ID and diagnostic reference.");
            if (reply.Body.Length > MaxJsonBytes) throw new Failure("http", "response_too_large", "Diagnostics returned more than 64 KiB of response data.", "openwork-support", "Give OpenWork support the run ID; the diagnostic response exceeded its declared safety bound.");
            try { if (JsonNode.Parse(reply.Body) is JsonObject o) return o; }
            catch (JsonException) { /* reported below */ }
            throw new Failure("http", "invalid_json_response", "Diagnostics returned a malformed JSON response.", "openwork-support", "Give OpenWork support the run ID and diagnostic reference.");
        }

        static bool IsTrue(JsonNode? n) => n is JsonValue v && v.TryGetValue<bool>(out var b) && b;
        static string? Str(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

        var tasks = new Dictionary<string, Func<Evidence, Task>>
        {
            ["reachability"] = async e =>
            {
                var body = Json(await Send("connectivity", e, [200], HttpMethod.Get, $"{origin}/diagnostics/egress", "reachability-get"));
                if (!IsTrue(body["ok"])) throw new Failure("connectivity", "invalid_reachability_response", "The reachability endpoint returned an unexpected response.", "openwork-support", "Give OpenWork support the run ID and diagnostic reference.");
            },
            ["http-methods"] = async e =>
            {
                await Send("http", e, [204], HttpMethod.Head, $"{origin}/diagnostics/egress", "http-head");
                var options = await Send("http", e, [204], HttpMethod.Options, $"{origin}/diagnostics/egress", "http-options");
                var allow = string.Join(",", options.Headers.TryGetValues("allow", out var a) ? a : options.ContentHeaders?.Allow ?? []);
                if (!allow.Contains("POST", StringComparison.Ordinal))
                    throw new Failure("http", "options_header_missing", "The OPTIONS response did not preserve its Allow header.", "network-administrator", "Ask the network administrator to inspect proxy handling of OPTIONS and response headers.");
                var posted = Json(await Send("http", e, [200], HttpMethod.Post, $"{origin}/diagnostics/egress", "http-post", "{\"probe\":\"openwork-egress-diagnostic\"}",
                    headers: new() { ["authorization"] = $"Bearer {bearerToken}" }));
                if (!IsTrue(posted["ok"]) || Str(posted["method"]) != "POST") throw Protocol("http", "invalid_post_response", "The JSON POST endpoint returned an unexpected response.");
            },
            ["redirect"] = async e =>
            {
                var first = await Send("http", e, [302], HttpMethod.Get, $"{origin}/diagnostics/redirect", "redirect-start");
                var location = first.Headers.Location?.ToString() ?? "";
                var target = new Uri(new Uri(origin + "/"), location);
                if (target.GetLeftPart(UriPartial.Authority) != new Uri(origin).GetLeftPart(UriPartial.Authority) || target.AbsolutePath != "/diagnostics/egress")
                    throw new Failure("http", "unsafe_redirect_target", "The controlled redirect did not remain on the Diagnostics origin.", "openwork-support", "Give OpenWork support the run ID and diagnostic reference.");
                var second = Json(await Send("http", e, [200], HttpMethod.Get, target.ToString(), "redirect-complete"));
                if (!IsTrue(second["ok"])) throw Protocol("http", "invalid_redirect_response", "The redirect destination returned an unexpected response.");
            },
            ["oauth-discovery"] = async e =>
            {
                var pr = Json(await Send("oauth", e, [200], HttpMethod.Get, $"{origin}/.well-known/oauth-protected-resource/mcp", "oauth-protected-resource"));
                var servers = pr["authorization_servers"] as JsonArray;
                if (Str(pr["resource"]) != $"{origin}/mcp" || servers is null || !servers.Any(s => Str(s) == origin))
                    throw new Failure("oauth", "protected_resource_metadata_mismatch", "OAuth protected-resource metadata did not describe the expected MCP resource.", "openwork-support", "Give OpenWork support the run ID and diagnostic reference.");
                var asm = Json(await Send("oauth", e, [200], HttpMethod.Get, $"{origin}/.well-known/oauth-authorization-server", "oauth-authorization-server"));
                if (Str(asm["issuer"]) != origin || Str(asm["token_endpoint"]) != $"{origin}/oauth/token")
                    throw new Failure("oauth", "authorization_server_metadata_mismatch", "OAuth authorization-server metadata did not describe the expected token endpoint.", "openwork-support", "Give OpenWork support the run ID and diagnostic reference.");
            },
            ["oauth-token"] = async e =>
            {
                var form = $"grant_type=client_credentials&resource={Uri.EscapeDataString(origin + "/mcp")}&scope={Uri.EscapeDataString("diagnostics:connectivity")}";
                var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes($"openwork-diagnostics:{bearerToken}"));
                var token = Json(await Send("oauth", e, [200], HttpMethod.Post, $"{origin}/oauth/token", "oauth-token", form, "application/x-www-form-urlencoded", new() { ["authorization"] = $"Basic {basic}" }));
                if (Str(token["token_type"]) != "Bearer" || Str(token["access_token"]) is not { Length: > 20 } issued)
                    throw new Failure("oauth", "invalid_token_response", "The OAuth-shaped token response did not contain a usable synthetic Bearer token.", "openwork-support", "Give OpenWork support the run ID and diagnostic reference.");
                accessToken = issued;
            },
            ["mcp-handshake"] = async e =>
            {
                var auth = new Dictionary<string, string> { ["accept"] = "application/json, text/event-stream", ["authorization"] = $"Bearer {accessToken}" };
                var init = await Send("mcp", e, [200], HttpMethod.Post, $"{origin}/mcp", "mcp-initialize",
                    "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"params\":{\"capabilities\":{},\"clientInfo\":{\"name\":\"openwork-den-egress-diagnostics\",\"version\":\"1.0\"},\"protocolVersion\":\"2025-11-25\"}}", headers: auth);
                var result = Json(init)["result"] as JsonObject;
                var session = init.Headers.TryGetValues("mcp-session-id", out var sv) ? sv.FirstOrDefault() ?? "" : "";
                var version = init.Headers.TryGetValues("mcp-protocol-version", out var vv) ? vv.FirstOrDefault() ?? "" : "";
                if (result is null || Str(result["protocolVersion"]) != "2025-11-25" || session.Length <= 20 || version != "2025-11-25")
                    throw new Failure("mcp", "mcp_initialize_contract_mismatch", "MCP initialization did not return the expected protocol version and session.", "openwork-support", "Give OpenWork support the run ID and initialize diagnostic reference.");
                var sessionHeaders = new Dictionary<string, string>(auth) { ["mcp-protocol-version"] = version, ["mcp-session-id"] = session };
                await Send("mcp", e, [202], HttpMethod.Post, $"{origin}/mcp", "mcp-initialized", "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}", headers: sessionHeaders);
                var catalog = Json(await Send("mcp", e, [200], HttpMethod.Post, $"{origin}/mcp", "mcp-tools-list", "{\"id\":2,\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"params\":{}}", headers: sessionHeaders))["result"] as JsonObject;
                if (catalog?["tools"] is not JsonArray { Count: 1 } tools)
                    throw new Failure("mcp", "mcp_catalog_contract_mismatch", "MCP tool discovery did not return the single synthetic diagnostic tool.", "openwork-support", "Give OpenWork support the run ID and catalog diagnostic reference.");
                if (tools[0] is not JsonObject tool || Str(tool["name"]) is not { Length: > 0 } name)
                    throw new Failure("mcp", "mcp_tool_name_missing", "MCP tool discovery returned a tool without a usable name.", "openwork-support", "Give OpenWork support the run ID and catalog diagnostic reference.");
                var call = new JsonObject { ["id"] = 3, ["jsonrpc"] = "2.0", ["method"] = "tools/call", ["params"] = new JsonObject { ["arguments"] = new JsonObject { ["query"] = "private-cloud-egress" }, ["name"] = name } };
                var called = Json(await Send("mcp", e, [200], HttpMethod.Post, $"{origin}/mcp", "mcp-tools-call", call.ToJsonString(), headers: sessionHeaders))["result"] as JsonObject;
                if (called?["isError"] is not JsonValue isError || !isError.TryGetValue<bool>(out var flag) || flag)
                    throw new Failure("mcp", "mcp_tool_contract_mismatch", "The synthetic MCP tool call was not reported as successful.", "openwork-support", "Give OpenWork support the run ID and tool-call diagnostic reference.");
            },
        };

        var steps = new JsonArray();
        string? highest = null, failedStep = null;
        foreach (var id in StepIds)
        {
            var (category, label, message) = Definitions[id];
            var started = DateTime.UtcNow;
            var evidence = new Evidence();
            JsonObject Step(string status, string category, string? code, string message, string owner, string action)
            {
                var completed = DateTime.UtcNow;
                return new JsonObject
                {
                    ["id"] = id, ["label"] = label, ["category"] = category, ["status"] = status, ["startedAt"] = Iso(started), ["completedAt"] = Iso(completed),
                    ["durationMs"] = (long)Math.Max(0, (completed - started).TotalMilliseconds),
                    ["httpStatuses"] = new JsonArray(evidence.Statuses.Select(s => (JsonNode)s).ToArray()), ["diagnosticIds"] = new JsonArray(evidence.Ids.Select(s => (JsonNode)s).ToArray()),
                    ["code"] = code, ["message"] = message, ["owner"] = owner, ["action"] = action,
                };
            }
            if (failedStep is not null)
            {
                steps.Add(Step("skipped", category, "blocked_by_previous_failure", "This step was not attempted because an earlier layer failed.", "den-operator", "Resolve the first failed step, then run the diagnostic again."));
                continue;
            }
            try
            {
                await tasks[id](evidence);
                highest = id;
                steps.Add(Step("passed", category, null, message, "openwork-support", "No action required."));
            }
            catch (Failure f)
            {
                failedStep = id;
                steps.Add(Step("failed", f.Category, f.Code, f.Message, f.Owner, f.Action));
            }
        }
        return new JsonObject
        {
            ["runId"] = runId, ["targetOrigin"] = origin, ["supportUrl"] = $"{origin}/?runId={Uri.EscapeDataString(runId)}", ["startedAt"] = Iso(runStarted), ["completedAt"] = Iso(DateTime.UtcNow),
            ["overallStatus"] = failedStep is null ? "passed" : "failed", ["highestPassingStep"] = highest, ["failedStep"] = failedStep, ["steps"] = steps,
        };
    }

    private static string Iso(DateTime t) => t.ToString("yyyy-MM-ddTHH:mm:ss.fff'Z'", System.Globalization.CultureInfo.InvariantCulture);
}
