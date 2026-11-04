using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using WorkAI360.Api.Features.Onboarding;

namespace WorkAI360.Api.Tests;

/// <summary>A stand-in for the public Diagnostics service: the reference's contract, with switchable faults. It checks every request's run/step signature.</summary>
public sealed class FakeDiagnostics : IAsyncDisposable
{
    public const string Token = "synthetic-diagnostic-token-0123456789";
    private readonly WebApplication _app;
    public string Origin { get; private set; } = "";
    /// <summary>none, strip-id (a proxy answering), reject-token, offsite-redirect, tool-error, slow-mcp.</summary>
    public volatile string Fault = "none";
    public ConcurrentQueue<(string Step, bool SignatureOk)> Seen { get; } = new();

    private FakeDiagnostics(WebApplication app) { _app = app; }

    public static async Task<FakeDiagnostics> StartAsync()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var app = builder.Build();
        var fake = new FakeDiagnostics(app);
        app.Run(fake.HandleAsync);
        await app.StartAsync();
        fake.Origin = app.Urls.First().Replace("localhost", "127.0.0.1");
        return fake;
    }

    private async Task HandleAsync(HttpContext ctx)
    {
        var run = ctx.Request.Headers[EgressProbe.RunHeader].ToString();
        var step = ctx.Request.Headers[EgressProbe.StepHeader].ToString();
        Seen.Enqueue((step, ctx.Request.Headers[EgressProbe.SignatureHeader].ToString() == EgressProbe.Signature(Token, run, step)));
        if (Fault != "strip-id") ctx.Response.Headers[EgressProbe.IdHeader] = Guid.NewGuid().ToString();
        var path = ctx.Request.Path.Value;
        var method = ctx.Request.Method;
        async Task Json(int status, JsonNode body, Dictionary<string, string>? headers = null)
        {
            ctx.Response.StatusCode = status;
            ctx.Response.ContentType = "application/json";
            foreach (var (k, v) in headers ?? []) ctx.Response.Headers[k] = v;
            await ctx.Response.WriteAsync(body.ToJsonString());
        }
        switch (path)
        {
            case "/diagnostics/egress" when method == "GET": await Json(200, new JsonObject { ["ok"] = true }); return;
            case "/diagnostics/egress" when method == "HEAD": ctx.Response.StatusCode = 204; return;
            case "/diagnostics/egress" when method == "OPTIONS": ctx.Response.StatusCode = 204; ctx.Response.Headers.Allow = "GET, HEAD, OPTIONS, POST"; return;
            case "/diagnostics/egress" when method == "POST":
                if (Fault == "reject-token" || ctx.Request.Headers.Authorization.ToString() != $"Bearer {Token}") { await Json(401, new JsonObject { ["error"] = "unauthorized" }); return; }
                await Json(200, new JsonObject { ["ok"] = true, ["method"] = "POST" }); return;
            case "/diagnostics/redirect":
                ctx.Response.StatusCode = 302;
                ctx.Response.Headers.Location = Fault == "offsite-redirect" ? "https://elsewhere.example/diagnostics/egress" : "/diagnostics/egress";
                return;
            case "/.well-known/oauth-protected-resource/mcp": await Json(200, new JsonObject { ["resource"] = $"{Origin}/mcp", ["authorization_servers"] = new JsonArray(Origin) }); return;
            case "/.well-known/oauth-authorization-server": await Json(200, new JsonObject { ["issuer"] = Origin, ["token_endpoint"] = $"{Origin}/oauth/token" }); return;
            case "/oauth/token":
                var expected = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"openwork-diagnostics:{Token}"));
                if (ctx.Request.Headers.Authorization.ToString() != expected) { await Json(401, new JsonObject { ["error"] = "invalid_client" }); return; }
                await Json(200, new JsonObject { ["token_type"] = "Bearer", ["access_token"] = "synthetic-access-" + Guid.NewGuid().ToString("N"), ["expires_in"] = 60 }); return;
            case "/mcp":
                if (Fault == "slow-mcp") await Task.Delay(8000);
                var body = JsonNode.Parse(await new StreamReader(ctx.Request.Body).ReadToEndAsync())!;
                var rpc = body["method"]!.GetValue<string>();
                var session = new Dictionary<string, string> { ["mcp-session-id"] = "session-" + new string('x', 30), ["mcp-protocol-version"] = "2025-11-25" };
                if (rpc == "initialize") { await Json(200, new JsonObject { ["jsonrpc"] = "2.0", ["id"] = 1, ["result"] = new JsonObject { ["protocolVersion"] = "2025-11-25" } }, session); return; }
                if (rpc == "notifications/initialized") { ctx.Response.StatusCode = 202; return; }
                if (rpc == "tools/list") { await Json(200, new JsonObject { ["jsonrpc"] = "2.0", ["id"] = 2, ["result"] = new JsonObject { ["tools"] = new JsonArray(new JsonObject { ["name"] = "diagnostic_echo" }) } }); return; }
                await Json(200, new JsonObject { ["jsonrpc"] = "2.0", ["id"] = 3, ["result"] = new JsonObject { ["isError"] = Fault == "tool-error", ["content"] = new JsonArray() } }); return;
        }
        ctx.Response.StatusCode = 404;
    }

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();
}

/// <summary>A deployment configured to probe the fake Diagnostics service (on loopback, so private addresses are allowed).</summary>
public sealed class EgressFactory : ApiFactory
{
    private static readonly Lazy<FakeDiagnostics> Shared = new(() => FakeDiagnostics.StartAsync().GetAwaiter().GetResult());
    public FakeDiagnostics Fake => Shared.Value;
    protected override IEnumerable<KeyValuePair<string, string>> Settings =>
    [
        new("Onboarding:DiagnosticsOrigin", Shared.Value.Origin), new("Onboarding:DiagnosticsBearerToken", FakeDiagnostics.Token), new("Connections:AllowPrivateUrls", "true"),
    ];
}

/// <summary>Probe-only checks against a private target with private addresses refused, without a Diagnostics service.</summary>
public sealed class EgressGuardedFactory : ApiFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Settings =>
        [new("Onboarding:DiagnosticsOrigin", "http://127.0.0.1:9"), new("Onboarding:DiagnosticsBearerToken", FakeDiagnostics.Token)];
}

/// <summary>POST /v1/diagnostics/egress: the reference's six fixed probes against the operator's Diagnostics origin.</summary>
public sealed class EgressDiagnosticTests(EgressFactory factory) : IClassFixture<EgressFactory>
{
    private static readonly SemaphoreSlim Serial = new(1, 1);

    private async Task<JsonElement> RunAsync(string fault)
    {
        await Serial.WaitAsync();
        try
        {
            factory.Fake.Fault = fault;
            factory.Fake.Seen.Clear();
            var w = await Workspace.CreateAsync(factory);
            var r = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/diagnostics/egress");
            Assert.True(r.Status == HttpStatusCode.OK, $"{r.Status} {r.Body}");
            return r.Body;
        }
        finally { factory.Fake.Fault = "none"; Serial.Release(); }
    }

    private static List<(string Id, string Status, string? Code)> Steps(JsonElement run) =>
        run.GetProperty("steps").EnumerateArray().Select(s => (s.GetProperty("id").GetString()!, s.GetProperty("status").GetString()!, s.GetProperty("code").ValueKind == JsonValueKind.String ? s.GetProperty("code").GetString() : null)).ToList();

    [Fact]
    public async Task Every_layer_passes_against_a_healthy_Diagnostics_service_with_signed_requests()
    {
        var run = await RunAsync("none");
        Assert.Equal("passed", run.GetProperty("overallStatus").GetString());
        Assert.Equal("mcp-handshake", run.GetProperty("highestPassingStep").GetString());
        Assert.Equal(JsonValueKind.Null, run.GetProperty("failedStep").ValueKind);
        Assert.Equal(EgressProbe.StepIds, Steps(run).Select(s => s.Id).ToArray());
        Assert.All(Steps(run), s => Assert.Equal("passed", s.Status));
        var http = run.GetProperty("steps").EnumerateArray().Single(s => s.GetProperty("id").GetString() == "http-methods");
        Assert.Equal([204, 204, 200], http.GetProperty("httpStatuses").EnumerateArray().Select(x => x.GetInt32()).ToArray());
        Assert.Equal(3, http.GetProperty("diagnosticIds").GetArrayLength());
        Assert.Equal(factory.Fake.Origin, run.GetProperty("targetOrigin").GetString());
        Assert.Contains(run.GetProperty("runId").GetString()!, run.GetProperty("supportUrl").GetString());
        // Every request carried a signature for its own run and step, and the token never appears in the result.
        Assert.Equal(13, factory.Fake.Seen.Count); // 1 + 3 + 2 + 2 + 1 + 4 requests
        Assert.All(factory.Fake.Seen, s => Assert.True(s.SignatureOk, s.Step));
        Assert.DoesNotContain(FakeDiagnostics.Token, run.GetRawText());
    }

    [Theory]
    [InlineData("strip-id", "reachability", "diagnostic_reference_missing", "network-administrator")]
    [InlineData("reject-token", "http-methods", "http_401", "den-operator")]
    [InlineData("offsite-redirect", "redirect", "unsafe_redirect_target", "openwork-support")]
    [InlineData("tool-error", "mcp-handshake", "mcp_tool_contract_mismatch", "openwork-support")]
    public async Task The_first_failing_layer_is_named_with_its_owner_and_later_layers_are_skipped(string fault, string failedStep, string code, string owner)
    {
        var run = await RunAsync(fault);
        Assert.Equal("failed", run.GetProperty("overallStatus").GetString());
        Assert.Equal(failedStep, run.GetProperty("failedStep").GetString());
        var steps = Steps(run);
        var index = Array.IndexOf(EgressProbe.StepIds, failedStep);
        Assert.All(steps.Take(index), s => Assert.Equal("passed", s.Status));
        Assert.Equal(("failed", code), (steps[index].Status, steps[index].Code));
        Assert.Equal(owner, run.GetProperty("steps")[index].GetProperty("owner").GetString());
        Assert.All(steps.Skip(index + 1), s => Assert.Equal(("skipped", "blocked_by_previous_failure"), (s.Status, s.Code)));
        Assert.Equal(index == 0 ? JsonValueKind.Null : JsonValueKind.String, run.GetProperty("highestPassingStep").ValueKind);
    }

    [Fact]
    public async Task Only_people_who_may_run_network_checks_can_run_it()
    {
        var w = await Workspace.CreateAsync(factory);
        var member = await w.AddAsync();
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(member, HttpMethod.Post, "/v1/diagnostics/egress")).Status);
    }
}

public sealed class EgressGuardTests(EgressGuardedFactory factory) : IClassFixture<EgressGuardedFactory>
{
    [Fact]
    public async Task A_private_target_is_refused_by_the_outbound_guard_and_reported_for_the_operator()
    {
        var w = await Workspace.CreateAsync(factory);
        var r = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/diagnostics/egress");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal("reachability", r.Body.GetProperty("failedStep").GetString());
        var first = r.Body.GetProperty("steps")[0];
        Assert.Equal("egress_target_refused", first.GetProperty("code").GetString());
        Assert.Equal("den-operator", first.GetProperty("owner").GetString());
        Assert.Empty(first.GetProperty("httpStatuses").EnumerateArray());
    }
}
