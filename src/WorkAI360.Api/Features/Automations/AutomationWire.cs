using System.Text.Json;
using WorkAI360.Api.Domain.Automations;

namespace WorkAI360.Api.Features.Automations;

/// <summary>An Automation with the revision that is current and its latest run: what the list and detail routes return.</summary>
public sealed record Item(Automation Automation, AutomationRevision Revision, AutomationRun? LatestRun);

/// <summary>The reference's JSON for Automations, revisions and runs.</summary>
public static class AutomationWire
{
    public static JsonElement? Parse(string? json) => json is null ? null : JsonSerializer.Deserialize<JsonElement>(json);

    public static Dictionary<string, object?> Of(Automation a) => new()
    {
        ["id"] = a.Id, ["organizationId"] = a.OrganizationId, ["ownerMemberId"] = a.OwnerMemberId, ["name"] = a.Name, ["state"] = a.State,
        ["currentRevisionId"] = a.CurrentRevisionId, ["nextDueAt"] = a.NextDueAt, ["latestRunAt"] = a.LatestRunAt,
        ["latestSuccessfulRunId"] = a.LatestSuccessfulRunId, ["latestSuccessfulResult"] = Parse(a.LatestSuccessfulResultJson),
        ["needsAttentionReason"] = Parse(a.NeedsAttentionJson), ["createdAt"] = a.CreatedAt, ["updatedAt"] = a.UpdatedAt, ["archivedAt"] = a.ArchivedAt,
    };

    public static Dictionary<string, object?> Of(AutomationRevision r) => new()
    {
        ["id"] = r.Id, ["automationId"] = r.AutomationId, ["version"] = r.Version, ["instructions"] = r.Instructions, ["schedule"] = Parse(r.ScheduleJson),
        ["model"] = new Dictionary<string, object?> { ["providerId"] = r.ProviderId, ["modelId"] = r.ModelId, ["variant"] = r.ModelVariant },
        ["action"] = Parse(r.ActionJson), ["executionTarget"] = r.ExecutionTarget, ["workspaceId"] = r.WorkspaceId,
        ["maximumRuntimeMs"] = r.MaximumRuntimeMs, ["digest"] = r.Digest, ["createdAt"] = r.CreatedAt,
    };

    public static Dictionary<string, object?> Of(AutomationRun r)
    {
        var receipt = Parse(r.EngineReceiptJson);
        string? Text(string name) => receipt is { ValueKind: JsonValueKind.Object } o && o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        object? thread = null;
        if (r.EngineKind is not null)
        {
            var t = new Dictionary<string, object?>
            {
                ["id"] = r.ThreadId, ["threadKind"] = "automation", ["executionLocation"] = r.ExecutionTarget, ["automationId"] = r.AutomationId,
                ["automationRunId"] = r.Id, ["engineKind"] = r.EngineKind,
            };
            if (Text("nativeThreadId") is { } native) t["nativeThreadId"] = native;
            if (Text("workspaceId") is { } workspace) t["workspaceId"] = workspace;
            thread = t;
        }
        var wire = new Dictionary<string, object?>
        {
            ["id"] = r.Id, ["automationId"] = r.AutomationId, ["revisionId"] = r.RevisionId, ["trigger"] = r.Trigger, ["scheduledFor"] = r.ScheduledFor,
            ["idempotencyKey"] = r.IdempotencyKey, ["status"] = r.Status, ["leaseOwner"] = r.LeaseOwner, ["leaseExpiresAt"] = r.LeaseExpiresAt,
            ["heartbeatAt"] = r.HeartbeatAt, ["attemptCount"] = r.AttemptCount, ["executionTarget"] = r.ExecutionTarget, ["executionThread"] = thread,
            ["providerId"] = r.ProviderId, ["modelId"] = r.ModelId, ["modelVariant"] = r.ModelVariant, ["startedAt"] = r.StartedAt, ["finishedAt"] = r.FinishedAt,
            ["error"] = Parse(r.ErrorJson), ["resultSummary"] = r.ResultSummary, ["codemodeReceiptId"] = null, ["validatedResult"] = null,
            ["usage"] = Parse(r.UsageJson), ["createdAt"] = r.CreatedAt, ["updatedAt"] = r.UpdatedAt,
        };
        if (r.TriggerContextJson is not null) wire["triggerContext"] = Parse(r.TriggerContextJson);
        return wire;
    }

    public static Dictionary<string, object?> Of(AutomationRunEvent e) => new()
    {
        ["id"] = e.Id, ["runId"] = e.RunId, ["attempt"] = e.Attempt, ["sequence"] = e.Sequence, ["type"] = e.EventType,
        ["payload"] = Parse(e.PayloadJson), ["createdAt"] = e.CreatedAt,
    };

    public static Dictionary<string, object?> Of(Item item) => new()
    {
        ["automation"] = Of(item.Automation), ["revision"] = Of(item.Revision), ["latestRun"] = item.LatestRun is null ? null : Of(item.LatestRun),
    };

    public static string EmptyUsage => "{\"inputTokens\":null,\"outputTokens\":null,\"costMicros\":null}";
}
