using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WorkAI360.Api.Features.Library;

namespace WorkAI360.Api.Features.Automations;

public sealed record ModelChoice(string ProviderId, string ModelId, string? Variant, bool VariantGiven)
{
    /// <summary>The wire shape of a model inside an action: the variant only when the request had one.</summary>
    public Dictionary<string, object?> ToActionWire()
    {
        var wire = new Dictionary<string, object?> { ["providerId"] = ProviderId, ["modelId"] = ModelId };
        if (VariantGiven) wire["variant"] = Variant;
        return wire;
    }

    public bool Same(ModelChoice other) => ProviderId == other.ProviderId && ModelId == other.ModelId && Variant == other.Variant;
}

/// <summary>What an Automation does: ask an agent (instructions and a model), or run a saved Workflow script.</summary>
public sealed record ActionSpec(string Kind, string? Instructions, ModelChoice? Model, string? ScriptJson, string? InputJson)
{
    public Dictionary<string, object?> ToWire()
    {
        if (Kind == "agent") return new() { ["kind"] = "agent", ["instructions"] = Instructions, ["model"] = Model!.ToActionWire() };
        var wire = new Dictionary<string, object?> { ["kind"] = "saved_script", ["script"] = JsonSerializer.Deserialize<JsonElement>(ScriptJson!) };
        if (InputJson is not null) wire["input"] = JsonSerializer.Deserialize<JsonElement>(InputJson);
        return wire;
    }

    public string ToJson() => JsonSerializer.Serialize(ToWire());

    public static ActionSpec Parse(JsonElement e, string[] path)
    {
        if (e.ValueKind != JsonValueKind.Object) throw new Invalid(string.Join('.', path), $"Invalid input: expected object, received {Reader.Kind(e)}");
        var kind = e.TryGetProperty("kind", out var k) && k.ValueKind == JsonValueKind.String ? k.GetString() : null;
        if (kind is not ("agent" or "saved_script")) throw new Invalid([([.. path, "kind"], "invalid_union", "Invalid input")]);
        var allowed = kind == "agent" ? new[] { "kind", "instructions", "model" } : ["kind", "script", "input"];
        var extra = e.EnumerateObject().Select(p => p.Name).Where(n => !allowed.Contains(n)).ToList();
        if (extra.Count > 0) throw new Invalid([(path, "unrecognized_keys", extra.Count == 1 ? $"Unrecognized key: \"{extra[0]}\"" : $"Unrecognized keys: {string.Join(", ", extra.Select(n => $"\"{n}\""))}")]);
        if (kind == "agent")
        {
            var instructions = Reader.Str(e, "instructions", path, 1, 100_000);
            if (!e.TryGetProperty("model", out var m)) throw new Invalid(string.Join('.', [.. path, "model"]), "Invalid input: expected object, received undefined");
            return new ActionSpec(kind, instructions, ParseModel(m, [.. path, "model"]), null, null);
        }
        if (!e.TryGetProperty("script", out var script)) throw new Invalid(string.Join('.', [.. path, "script"]), "Invalid input: expected object, received undefined");
        var sp = (string[])[.. path, "script"];
        if (script.ValueKind != JsonValueKind.Object) throw new Invalid(string.Join('.', sp), $"Invalid input: expected object, received {Reader.Kind(script)}");
        var names = new[] { "pluginId", "configObjectId", "configObjectVersionId" };
        var bad = script.EnumerateObject().Select(p => p.Name).Where(n => !names.Contains(n)).ToList();
        if (bad.Count > 0) throw new Invalid([(sp, "unrecognized_keys", bad.Count == 1 ? $"Unrecognized key: \"{bad[0]}\"" : $"Unrecognized keys: {string.Join(", ", bad.Select(n => $"\"{n}\""))}")]);
        foreach (var n in names) Reader.Str(script, n, sp, 1, 160);
        return new ActionSpec(kind, null, null, script.GetRawText(), e.TryGetProperty("input", out var input) ? input.GetRawText() : null);
    }

    public static ModelChoice ParseModel(JsonElement m, string[] path)
    {
        if (m.ValueKind != JsonValueKind.Object) throw new Invalid(string.Join('.', path), $"Invalid input: expected object, received {Reader.Kind(m)}");
        var provider = Reader.Str(m, "providerId", path, 1, 160);
        var model = Reader.Str(m, "modelId", path, 1, 160);
        string? variant = null;
        var given = false;
        if (m.TryGetProperty("variant", out var v) && v.ValueKind != JsonValueKind.Undefined)
        {
            given = true;
            if (v.ValueKind != JsonValueKind.Null) variant = Reader.Str(m, "variant", path, 1, 60);
        }
        return new ModelChoice(provider, model, variant, given);
    }
}

/// <summary>A request to create an Automation, after validation: the desktop (legacy) shape or the action shape that runs in the cloud.</summary>
public sealed record CreateDefinition(string Name, AutomationSchedule Schedule, ActionSpec Action, string ExecutionTarget, string? WorkspaceId, bool FromActionShape);

public sealed record UpdateDefinition(string? Name, string? Instructions, AutomationSchedule? Schedule, ModelChoice? Model, ActionSpec? Action, string? ExecutionTarget, bool WorkspaceGiven, string? WorkspaceId);

public static class AutomationInput
{
    /// <summary><c>POST /v1/automations</c>: either the action shape (name, schedule, action, executionTarget) or the shape released desktops send (name, instructions, schedule, model, workspaceId).</summary>
    public static CreateDefinition ParseCreate(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object) throw new Invalid("", $"Invalid input: expected object, received {Reader.Kind(root)}");
        var actionShape = root.TryGetProperty("action", out _) || root.TryGetProperty("executionTarget", out _);
        var legacyShape = root.TryGetProperty("instructions", out _) || root.TryGetProperty("model", out _);
        // Neither shape: the reference's union reports that nothing matched.
        if (!actionShape && !legacyShape) throw new Invalid([([], "invalid_union", "Invalid input")]);
        var name = Reader.Str(root, "name", [], 1, 120);
        if (actionShape)
        {
            var schedule = ScheduleOf(root);
            if (!root.TryGetProperty("action", out var action)) throw new Invalid("action", "Invalid input: expected object, received undefined");
            var spec = ActionSpec.Parse(action, ["action"]);
            var target = Reader.Str(root, "executionTarget", [], 1, 16, trim: false);
            if (target is not ("desktop" or "cloud")) throw new Invalid("executionTarget", "Invalid option: expected one of \"desktop\"|\"cloud\"", "invalid_value");
            if (target != "cloud") throw new Invalid("executionTarget", "Action-based Automations are created by Web and run in OpenWork Cloud.", "custom");
            return new CreateDefinition(name, schedule, spec, "cloud", null, true);
        }
        var instructions = Reader.Str(root, "instructions", [], 1, 100_000);
        var legacySchedule = ScheduleOf(root);
        if (!root.TryGetProperty("model", out var model)) throw new Invalid("model", "Invalid input: expected object, received undefined");
        var choice = ActionSpec.ParseModel(model, ["model"]);
        string? workspace = null;
        if (root.TryGetProperty("workspaceId", out var w) && w.ValueKind != JsonValueKind.Null) workspace = Reader.Str(root, "workspaceId", [], 1, 240);
        return new CreateDefinition(name, legacySchedule, new ActionSpec("agent", instructions, choice, null, null), "desktop", workspace, false);
    }

    /// <summary><c>POST /v1/cloud-automations</c>: strictly name, schedule and action; always the cloud.</summary>
    public static CreateDefinition ParseCreateCloud(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object) throw new Invalid("", $"Invalid input: expected object, received {Reader.Kind(root)}");
        var name = Reader.Str(root, "name", [], 1, 120);
        var schedule = ScheduleOf(root);
        if (!root.TryGetProperty("action", out var action)) throw new Invalid("action", "Invalid input: expected object, received undefined");
        var spec = ActionSpec.Parse(action, ["action"]);
        Strict(root, "name", "schedule", "action");
        return new CreateDefinition(name, schedule, spec, "cloud", null, true);
    }

    public static UpdateDefinition ParseUpdate(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object) throw new Invalid("", $"Invalid input: expected object, received {Reader.Kind(root)}");
        string? name = null, instructions = null, target = null, workspace = null;
        AutomationSchedule? schedule = null;
        ModelChoice? model = null;
        ActionSpec? action = null;
        var workspaceGiven = false;
        if (root.TryGetProperty("name", out _)) name = Reader.Str(root, "name", [], 1, 120);
        if (root.TryGetProperty("instructions", out _)) instructions = Reader.Str(root, "instructions", [], 1, 100_000);
        if (root.TryGetProperty("schedule", out var s)) schedule = AutomationSchedule.Parse(s, ["schedule"]);
        if (root.TryGetProperty("model", out var m)) model = ActionSpec.ParseModel(m, ["model"]);
        if (root.TryGetProperty("action", out var a)) action = ActionSpec.Parse(a, ["action"]);
        if (root.TryGetProperty("executionTarget", out _))
        {
            target = Reader.Str(root, "executionTarget", [], 1, 16, trim: false);
            if (target is not ("desktop" or "cloud")) throw new Invalid("executionTarget", "Invalid option: expected one of \"desktop\"|\"cloud\"", "invalid_value");
        }
        if (root.TryGetProperty("workspaceId", out var w))
        {
            workspaceGiven = true;
            if (w.ValueKind != JsonValueKind.Null) workspace = Reader.Str(root, "workspaceId", [], 1, 240);
        }
        Strict(root, "name", "instructions", "schedule", "model", "action", "executionTarget", "workspaceId");
        if (!root.EnumerateObject().Any()) throw new Invalid([([], "custom", "At least one behavior-changing field is required")]);
        return new UpdateDefinition(name, instructions, schedule, model, action, target, workspaceGiven, workspace);
    }

    private static AutomationSchedule ScheduleOf(JsonElement root)
    {
        if (!root.TryGetProperty("schedule", out var s)) throw new Invalid("schedule", "Invalid input: expected object, received undefined");
        return AutomationSchedule.Parse(s, ["schedule"]);
    }

    private static void Strict(JsonElement root, params string[] allowed)
    {
        var extra = root.EnumerateObject().Select(p => p.Name).Where(n => !allowed.Contains(n)).ToList();
        if (extra.Count > 0) throw new Invalid([([], "unrecognized_keys", extra.Count == 1 ? $"Unrecognized key: \"{extra[0]}\"" : $"Unrecognized keys: {string.Join(", ", extra.Select(n => $"\"{n}\""))}")]);
    }

    /// <summary>A stable fingerprint of what an Automation does. Two saves with the same fingerprint are not a new revision.</summary>
    public static string Digest(string instructions, AutomationSchedule schedule, ModelChoice model, ActionSpec action, string target, int maximumRuntimeMs, string? workspaceId)
    {
        var text = string.Join('\n', instructions, schedule.ToJson(), $"{model.ProviderId}|{model.ModelId}|{model.Variant}", action.ToJson(), target, maximumRuntimeMs, workspaceId ?? "");
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)))[..16];
    }
}
