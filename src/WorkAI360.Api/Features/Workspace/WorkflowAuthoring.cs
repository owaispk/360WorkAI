using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Data;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Workspace;

/// <summary>
/// The <c>execute_capability_script</c> tool on <c>/mcp/agent</c>: an agent writes a small script, runs it once as the person, and (when it works)
/// saves it as a Workflow with <c>POST /v1/workflows</c> using the receipt. The script gets <c>input</c> and the person's <c>tools</c>. A successful run
/// leaves a receipt and its exact source is kept for 15 minutes so a save can prove it is the same code. A live run (read-only tools, server-supplied
/// <c>input.runtime</c>) is for scripts that will back a live app.
/// </summary>
public sealed class WorkflowAuthoringTools(AuthoringSources sources) : IMcpToolProvider
{
    public const string ToolName = "execute_capability_script";

    private static readonly JsonNode Schema = JsonNode.Parse(
        """
        {"type":"object","properties":{
          "code":{"type":"string","description":"The script source."},
          "input":{"description":"Value the script reads as `input`. Not allowed in live mode."},
          "inputSchema":{"type":"object","description":"JSON Schema the input must satisfy."},
          "outputSchema":{"type":"object","description":"JSON Schema the result must satisfy."},
          "mode":{"type":"string","enum":["adhoc","live"],"description":"live runs read-only tools with a generated input.runtime."},
          "timeZone":{"type":"string","description":"IANA time zone for live mode (default UTC)."}},
        "required":["code"],"additionalProperties":false}
        """)!;

    public IReadOnlyList<McpToolDefinition> Tools { get; } =
    [
        new(ToolName, "Run a short script once as the signed-in person. The script is JavaScript with top-level await and return; it receives `input` and calls the person's connected actions as tools.<service>.<action>(args). "
            + "Returns the value, its Markdown, and a receiptId. A successful run can be saved as a Workflow (POST /v1/workflows with that receiptId) within 15 minutes. Literal credentials in the source are refused.",
            Schema),
    ];

    private static JsonObject Error(string code, string message) => McpEndpoints.ToolError(code, message);

    public async Task<JsonObject> CallAsync(string name, JsonObject arguments, McpPrincipal principal, IServiceProvider services)
    {
        var live = arguments["mode"]?.GetValue<string>() == "live";
        var needed = live ? OAuthConstants.ReadScope : OAuthConstants.WriteScope;
        if (!principal.Scopes.Contains(needed)) return Error("insufficient_scope", $"This tool needs the {needed} scope{(live ? "" : " (a script may call actions that change things)")}.");
        if (arguments["code"] is not JsonValue cv || !cv.TryGetValue<string>(out var code) || code.Length is < 1 or > 200_000) return Error("invalid_request", "code must be a string of 1 to 200000 characters.");
        if (arguments["mode"] is { } mode && mode.GetValue<string>() is not ("adhoc" or "live")) return Error("invalid_request", "mode must be adhoc or live.");
        if (live && arguments.ContainsKey("input")) return Error("invalid_request", "Live runs generate input.runtime; omit input.");
        string? zone = arguments["timeZone"]?.GetValue<string>();
        if (zone is not null && (!live || !ArtifactRuntime.ValidZone(zone))) return Error("invalid_request", live ? "timeZone must be an IANA time zone." : "timeZone is only supported in live mode.");
        if (arguments["inputSchema"] is not null and not JsonObject || arguments["outputSchema"] is not null and not JsonObject) return Error("invalid_request", "inputSchema and outputSchema must be JSON Schema objects.");
        try { SourceSafety.AssertSafe(code); }
        catch (WorkflowException) { return Error("workflow_source_contains_secret", "Source cannot be run or saved because it may contain a literal credential. Remove credentials and retry."); }

        var db = services.GetRequiredService<DenDbContext>();
        var member = await db.Members.AsNoTracking().FirstOrDefaultAsync(m => m.OrganizationId == principal.OrganizationId && m.UserId == principal.UserId);
        if (member is null) return Error("forbidden", "You are not a member of this organization.");
        var svc = services.GetRequiredService<WorkflowService>();
        var tools = services.GetRequiredService<WorkflowTools>();

        var inputSchema = arguments["inputSchema"] as JsonObject;
        var outputSchema = arguments["outputSchema"] as JsonObject;
        JsonNode? input = live ? new JsonObject { ["runtime"] = ArtifactRuntime.Build(zone) } : arguments["input"]?.DeepClone();
        var inputDigest = WorkflowArtifacts.Digest(input);
        var source = live ? "authoring:live" : "adhoc";
        var started = WorkflowService.Now();
        if (inputSchema is not null && CodemodePayload.Check(inputSchema, input) is var (problem, issues) && problem is not null)
            return Error(problem == "invalid_schema" ? "invalid_request" : "invalid_capability_arguments", problem == "invalid_schema" ? issues[0] : "The arguments do not match inputSchema.");

        var built = await tools.BuildAsync(principal.UserId, principal.OrganizationId, live, CancellationToken.None);
        var run = await CodeModeRunner.RunAsync(code, input, live, built.Tools, new CodeModeLimits(120_000, 1024, 65_536), CancellationToken.None);
        var finished = WorkflowService.Now();
        string status = run.Ok ? "succeeded" : "failed";
        string? errorKind = run.Ok ? null : run.Error!.Kind, errorMessage = run.Ok ? null : run.Error!.Message;
        JsonNode? value = null;
        if (run.Ok)
        {
            value = JsonNode.Parse(WorkflowArtifacts.Canonical(run.Value));
            if (outputSchema is not null && CodemodePayload.Check(outputSchema, value).Problem is not null) { status = "failed"; errorKind = "InvalidResult"; errorMessage = "The result does not match outputSchema."; }
        }
        var receiptId = await svc.RecordAsync(new RunRecord(principal.OrganizationId, member.Id, null, null, null, source, code, status, errorKind, errorMessage, run.ToolCalls, run.DurationMs, started, finished,
            inputDigest, WorkflowArtifacts.OptionalDigest(inputSchema), WorkflowArtifacts.OptionalDigest(outputSchema)));
        if (status != "succeeded") return Error(errorKind == "InvalidResult" ? "invalid_result" : "script_failed", errorMessage!);
        var retained = receiptId is not null && sources.Retain(new AuthoringSource(receiptId, principal.OrganizationId, member.Id, code, live ? "live" : "adhoc", inputDigest,
            WorkflowArtifacts.OptionalDigest(inputSchema), WorkflowArtifacts.OptionalDigest(outputSchema), WorkflowArtifacts.CodeDigest(code), source, live ? (JsonObject?)((JsonObject)input!)["runtime"]!.DeepClone() : null));
        return McpEndpoints.ToolResult(new JsonObject
        {
            ["ok"] = true, ["receiptId"] = receiptId, ["value"] = value?.DeepClone(), ["markdown"] = WorkflowArtifacts.RenderMarkdown(value),
            ["toolCalls"] = new JsonArray(run.ToolCalls.Select(c => (JsonNode)new JsonObject { ["name"] = c }).ToArray()),
            ["logs"] = new JsonArray(run.Logs.Select(l => (JsonNode)l).ToArray()), ["durationMs"] = run.DurationMs,
            ["savable"] = retained, ["retentionMinutes"] = (int)AuthoringSources.Ttl.TotalMinutes,
        });
    }
}
