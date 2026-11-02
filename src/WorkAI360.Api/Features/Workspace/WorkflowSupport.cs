using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Acornima;
using Acornima.Ast;

namespace WorkAI360.Api.Features.Workspace;

/// <summary>
/// A failure named the way the reference names it: a short code (<c>workflow_not_found</c>) that the routes turn into a status and a message.
/// It mirrors the <c>Error(message)</c> values the reference throws, so the same codes reach the same answers.
/// </summary>
public sealed class WorkflowException(string code) : Exception(code);

/// <summary>Reading and checking TypeIDs the way the reference's id library does, with the same messages.</summary>
public static class TypeIds
{
    private const string Alphabet = "0123456789abcdefghjkmnpqrstvwxyz";

    /// <summary>The id, or a <see cref="WorkflowException"/> carrying the library's message when it is not a TypeID of the expected prefix.</summary>
    public static string Normalize(string value, string prefix, params string[] alsoAccepted)
    {
        var underscore = value.LastIndexOf('_');
        string p, s;
        if (underscore == -1) { p = ""; s = value; }
        else
        {
            p = value[..underscore];
            s = value[(underscore + 1)..];
            if (p.Length == 0) throw new WorkflowException($"Invalid TypeId. Prefix cannot be empty when there's a separator: {value}");
        }
        if (s.Length == 0) throw new WorkflowException("Invalid length. Suffix should have 26 characters, got 0");
        if (p.Length > 0 && !(p.Length <= 63 && p.All(c => c is >= 'a' and <= 'z' or '_') && p[0] != '_' && p[^1] != '_'))
            throw new WorkflowException($"Invalid prefix \"{p}\". Must be at most 63 ASCII letters [a-z_]");
        if (s.Length != 26) throw new WorkflowException($"Invalid length. Suffix should have 26 characters, got {s.Length}");
        if (s[0] > '7') throw new WorkflowException($"Invalid suffix. First character \"{s[0]}\" must be in the range [0-7]");
        if (s.Any(c => !Alphabet.Contains(c))) throw new WorkflowException("Invalid base32 character");
        if (p != prefix && !alsoAccepted.Contains(p)) throw new WorkflowException($"TypeID prefix mismatch: expected '{prefix}' but got '{p}'");
        return value;
    }

    public static string ConfigObject(string value) => Normalize(value, "cob");
    public static string ConfigObjectVersion(string value) => Normalize(value, "cov");
    public static string Plugin(string value) => Normalize(value, "plg");
    /// <summary>Receipts are <c>wfr_…</c>; ids written before the rename (<c>cmr_…</c>) still read.</summary>
    public static string Receipt(string value) => Normalize(value, "wfr", "cmr");
    public static string ArtifactView(string value) => Normalize(value, "arv");
    public static string ArtifactViewRevision(string value) => Normalize(value, "avr");
}

public sealed record RequiredCapability(string CapabilityName, string ScriptPath);

/// <summary>The checked form of a Workflow version's <c>normalizedPayloadJson</c> (language, schemas, example input, required capabilities, limits).</summary>
public sealed class CodemodePayload
{
    public JsonObject? InputSchema { get; init; }
    public JsonObject? OutputSchema { get; init; }
    public JsonNode? ExampleInput { get; init; }
    public bool HasExampleInput { get; init; }
    public List<RequiredCapability> Required { get; init; } = [];
    public int? TimeoutMs { get; init; }
    public int? MaxToolCalls { get; init; }
    public int? MaxOutputBytes { get; init; }

    private static readonly string[] Keys = ["language", "inputSchema", "outputSchema", "exampleInput", "requiredCapabilities", "limits"];

    private static bool IsInt(JsonNode? n, long minimum, out long value)
    {
        value = 0;
        if (n is not JsonValue v || WorkflowArtifacts.El(v).ValueKind != JsonValueKind.Number) return false;
        var d = WorkflowArtifacts.El(v).GetDouble();
        if (d != Math.Floor(d) || Math.Abs(d) > 9007199254740991 || d < minimum) return false;
        value = (long)d;
        return true;
    }

    /// <summary>The reference's <c>parseCodemodeScriptPayload</c>: the payload, or the message saying what is wrong with it.</summary>
    public static (CodemodePayload? Payload, string? Message) Parse(JsonNode? node)
    {
        if (node is not JsonObject o || o.Any(p => !Keys.Contains(p.Key)))
            return (null, "The Workflow payload must contain only language, inputSchema, outputSchema, exampleInput, requiredCapabilities, and limits.");
        if (o["language"] is not JsonValue lv || !lv.TryGetValue<string>(out var language) || language != "codemode-js") return (null, "The Workflow language must be codemode-js.");
        if (o.ContainsKey("inputSchema") && o["inputSchema"] is not JsonObject) return (null, "The Workflow inputSchema must be a JSON Schema object.");
        if (o.ContainsKey("outputSchema") && o["outputSchema"] is not JsonObject) return (null, "The Workflow outputSchema must be a JSON Schema object.");
        if (JsonSchemaCheck.HasAsync(o["inputSchema"]) || JsonSchemaCheck.HasAsync(o["outputSchema"])) return (null, "Asynchronous Workflow schemas are not supported.");
        if (o["requiredCapabilities"] is not JsonArray required) return (null, "The Workflow requiredCapabilities must be an array.");
        var list = new List<RequiredCapability>();
        foreach (var r in required)
        {
            if (r is not JsonObject ro || ro.Any(p => p.Key is not ("capabilityName" or "scriptPath"))
                || ro["capabilityName"] is not JsonValue cv || !cv.TryGetValue<string>(out var cap) || string.IsNullOrWhiteSpace(cap)
                || ro["scriptPath"] is not JsonValue sv || !sv.TryGetValue<string>(out var path) || string.IsNullOrWhiteSpace(path))
                return (null, "Each Workflow required capability must contain only non-empty capabilityName and scriptPath strings.");
            list.Add(new RequiredCapability(cap, path));
        }
        int? timeout = null, calls = null, bytes = null;
        if (o.ContainsKey("limits"))
        {
            if (o["limits"] is not JsonObject lo || lo.Any(p => p.Key is not ("timeoutMs" or "maxToolCalls" or "maxOutputBytes")))
                return (null, "The Workflow limits must contain only timeoutMs, maxToolCalls, and maxOutputBytes.");
            if (lo.ContainsKey("timeoutMs")) { if (!IsInt(lo["timeoutMs"], 1, out var t)) return (null, "The Workflow timeoutMs limit must be a positive safe integer."); timeout = (int)Math.Min(t, int.MaxValue); }
            if (lo.ContainsKey("maxToolCalls")) { if (!IsInt(lo["maxToolCalls"], 0, out var c)) return (null, "The Workflow maxToolCalls limit must be a non-negative safe integer."); calls = (int)Math.Min(c, int.MaxValue); }
            if (lo.ContainsKey("maxOutputBytes")) { if (!IsInt(lo["maxOutputBytes"], 0, out var b)) return (null, "The Workflow maxOutputBytes limit must be a non-negative safe integer."); bytes = (int)Math.Min(b, int.MaxValue); }
        }
        return (new CodemodePayload
        {
            InputSchema = o["inputSchema"] as JsonObject, OutputSchema = o["outputSchema"] as JsonObject,
            ExampleInput = o.ContainsKey("exampleInput") ? o["exampleInput"] : null, HasExampleInput = o.ContainsKey("exampleInput"),
            Required = list, TimeoutMs = timeout, MaxToolCalls = calls, MaxOutputBytes = bytes,
        }, null);
    }

    /// <summary>What a value must satisfy: null when it does; "invalid_schema" when the schema itself cannot be used; otherwise the issues.</summary>
    public static (string? Problem, List<string> Issues) Check(JsonObject schema, JsonNode? value)
    {
        if (JsonSchemaCheck.HasAsync(schema)) return ("invalid_schema", ["Asynchronous Workflow schemas are not supported."]);
        var result = JsonSchemaCheck.Validate(schema, value);
        if (!result.SchemaValid) return ("invalid_schema", ["The Workflow input schema could not be compiled."]);
        if (result.Ok) return (null, []);
        var text = string.Join(", ", result.Errors);
        return ("invalid_arguments", [text.Length > 1000 ? text[..1000] + "..." : text]);
    }
}

/// <summary>Refuses Workflow source that appears to hold a literal credential (so one can never be saved or retained), as the reference does.</summary>
public static partial class SourceSafety
{
    private static readonly Regex[] SecretPatterns =
    [
        new(@"\bBearer\s+[A-Za-z0-9._~+/-]+=*", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b(?:gh[pousr]_|github_pat_|xox[baprs]-|sk-|rk-)[A-Za-z0-9_-]{8,}\b", RegexOptions.Compiled),
        new(@"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", RegexOptions.Compiled),
        new(@"\bAIza[A-Za-z0-9_-]{30,}\b", RegexOptions.Compiled),
        new(@"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", RegexOptions.Compiled),
        new(@"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----", RegexOptions.Compiled),
        new("\\b(?:[A-Za-z0-9_]*(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|private[_-]?key|credentials?|secret|token|passphrase)|authorization)[\"'`]?\\s*\\]?\\s*[:=]\\s*[\"'`][^\"'`\\r\\n]+[\"'`]", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"[?&](?:api[_-]?key|token|access_token|secret|password)=[^\s""'`&#]+", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\b[a-z][a-z0-9+.-]*://[^\s/:""'`]+:[^\s/@""'`]+@", RegexOptions.IgnoreCase | RegexOptions.Compiled),
    ];

    [GeneratedRegex(@"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|private[_-]?key|credentials?|secret|token|passphrase|authorization)$", RegexOptions.IgnoreCase)]
    private static partial Regex CredentialName();

    [GeneratedRegex(@"\\(?:u\{([0-9a-f]{1,6})\}|u([0-9a-f]{4})|x([0-9a-f]{2}))", RegexOptions.IgnoreCase)]
    private static partial Regex Escapes();

    private static string Decode(string code) => Escapes().Replace(code, m =>
    {
        var hex = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Success ? m.Groups[2].Value : m.Groups[3].Value;
        var value = Convert.ToInt32(hex, 16);
        return value <= 0x10ffff && !(value is >= 0xD800 and <= 0xDFFF) ? char.ConvertFromUtf32(value) : m.Value;
    });

    private static bool CredentialTarget(Node? node) => node switch
    {
        Identifier i => CredentialName().IsMatch(i.Name),
        Literal { Value: string s } => CredentialName().IsMatch(s),
        MemberExpression m => m.Computed ? CredentialTarget(m.Property) : CredentialTarget(m.Property),
        ParenthesizedExpression p => CredentialTarget(p.Expression),
        _ => false,
    };

    private static string? CredentialLiteral(Node? node) => node switch
    {
        ParenthesizedExpression p => CredentialLiteral(p.Expression),
        Literal { Value: string s } => s,
        TemplateLiteral { Expressions.Count: 0 } t => string.Concat(t.Quasis.Select(q => q.Value.Cooked)),
        BinaryExpression { Operator: Operator.Addition } b when CredentialLiteral(b.Left) is { } l && CredentialLiteral(b.Right) is { } r => l + r,
        _ => null,
    };

    private static bool HasCredentialAssignment(Node node)
    {
        switch (node)
        {
            case VariableDeclarator { Init: not null } v when CredentialTarget(v.Id) && CredentialLiteral(v.Init) is not null: return true;
            case Property { Computed: false } p when CredentialTarget(p.Key) && CredentialLiteral(p.Value) is not null: return true;
            case Property { Computed: true } pc when CredentialTarget(pc.Key) && CredentialLiteral(pc.Value) is not null: return true;
            case AssignmentExpression { Operator: Operator.Assignment } a when CredentialTarget(a.Left) && CredentialLiteral(a.Right) is not null: return true;
            case AssignmentPattern ap when CredentialTarget(ap.Left) && CredentialLiteral(ap.Right) is not null: return true;
        }
        return node.ChildNodes.Any(c => c is not null && HasCredentialAssignment(c));
    }

    public static void AssertSafe(string code)
    {
        var decoded = Decode(code);
        if (SecretPatterns.Any(p => p.IsMatch(code) || p.IsMatch(decoded))) throw new WorkflowException("workflow_source_contains_secret");
        try
        {
            var program = new Parser(new ParserOptions { AllowReturnOutsideFunction = true }).ParseScript("(async function () {" + code + "\n})");
            if (HasCredentialAssignment(program)) throw new WorkflowException("workflow_source_contains_secret");
        }
        catch (ParseErrorException) { /* unparseable source is refused when it runs, not here */ }
    }
}

/// <summary>What a run kept so a Workflow can be saved from it: the exact source, who ran it, and the digests of what it was run with.</summary>
public sealed record AuthoringSource(string ReceiptId, string OrganizationId, string MemberId, string Code, string Mode, string InputDigest, string? InputSchemaDigest, string? OutputSchemaDigest, string CodeDigest, string Source, JsonObject? Runtime);

/// <summary>
/// Source kept for 15 minutes after a successful authoring run, so saving it can prove it is the same code. Held in memory in this process (the
/// reference does the same when no shared store is configured): after a restart, or on another instance, the person runs the script again.
/// At most 200 entries and 16 MB are kept; the oldest go first.
/// </summary>
public sealed class AuthoringSources
{
    public static readonly TimeSpan Ttl = TimeSpan.FromMinutes(15);
    private const int MaxEntries = 200;
    private const int MaxBytes = 16 * 1024 * 1024;
    private const int MaxEntryBytes = 1024 * 1024;

    private readonly object _gate = new();
    private readonly LinkedList<(string Key, AuthoringSource Source, DateTime ExpiresAt, int Bytes)> _entries = [];
    private int _bytes;

    private static string Key(string orgId, string memberId, string receiptId) => $"{orgId}|{memberId}|{receiptId}";

    private void Expire(DateTime now)
    {
        for (var node = _entries.First; node is not null;)
        {
            var next = node.Next;
            if (node.Value.ExpiresAt <= now) { _bytes -= node.Value.Bytes; _entries.Remove(node); }
            node = next;
        }
    }

    /// <summary>Keeps the source; false when it is unsafe (holds a credential), too large, empty, or already kept.</summary>
    public bool Retain(AuthoringSource source, DateTime? at = null)
    {
        if (string.IsNullOrEmpty(source.Code) || source.Code.Length > 200_000) return false;
        try { SourceSafety.AssertSafe(source.Code); } catch (WorkflowException) { return false; }
        var bytes = source.Code.Length * 2 + 512;
        if (bytes > MaxEntryBytes) return false;
        var now = at ?? DateTime.UtcNow;
        lock (_gate)
        {
            Expire(now);
            var key = Key(source.OrganizationId, source.MemberId, source.ReceiptId);
            if (_entries.Any(e => e.Key == key)) return false;
            while (_entries.Count >= MaxEntries || _bytes + bytes > MaxBytes)
            {
                if (_entries.First is null) return false;
                _bytes -= _entries.First.Value.Bytes;
                _entries.RemoveFirst();
            }
            _entries.AddLast((key, source, now + Ttl, bytes));
            _bytes += bytes;
            return true;
        }
    }

    public AuthoringSource? Get(string orgId, string memberId, string receiptId, DateTime? at = null)
    {
        lock (_gate)
        {
            Expire(at ?? DateTime.UtcNow);
            var key = Key(orgId, memberId, receiptId);
            foreach (var e in _entries) if (e.Key == key) return e.Source;
            return null;
        }
    }
}

/// <summary>How a failure becomes an HTTP answer (the reference's <c>routeFailure</c>).</summary>
public static class WorkflowFailures
{
    public static (int Status, object Body) Map(Exception error)
    {
        switch (error)
        {
            case Library.LibraryForbidden f: return (403, new { error = "forbidden", message = f.Message });
            case Library.LibraryFailure lf: return (lf.Status, new { error = lf.Error, message = lf.Message });
        }
        var message = error is WorkflowException ? error.Message : "Workflow request failed.";
        if (message == "app_changed_since_preview") return (409, new { error = message, message = "This app was saved elsewhere. Reopen it before saving your changes." });
        if (message == "legacy_view_read_only") return (409, new { error = message, message = "This is an older app that can no longer be edited or saved. It still opens and refreshes. To change it, ask OpenWork to build a new App." });
        if (message.Contains("not_found")) return (404, new { error = "workflow_not_found", message });
        switch (message)
        {
            case "workflow_matching_test_receipt_required":
                return (400, new { error = message, message = "Test the draft first, then immediately create the version using that successful test's receiptId and the exact unchanged name, description, code, exampleInput, inputSchema, outputSchema, and requiredCapabilities. Do not reuse an older receipt or alter any draft field between the two calls." });
            case "workflow_source_contains_secret":
                return (400, new { error = message, message = "Source cannot be retained or saved because it may contain a literal credential. Remove credentials and retest." });
            case "workflow_authoring_receipt_required":
                return (400, new { error = message, message = "A matching successful authoring receipt and its retained source are required. Source retention lasts at most 15 minutes and is shared across replicas when Redis is configured, otherwise process-local. Configured storage failures do not fall back locally. Retest and use the new receiptId with unchanged source, input, and schemas, or omit receiptId and supply the exact tested source." });
            case "workflow_live_current_input_forbidden":
                return (400, new { error = message, message = "Omit currentInput for a live authoring receipt. Validation uses the retained server-generated runtime, which is not saved as example input." });
            case "workflow_recent_receipt_required":
                return (400, new { error = message, message = "Run the exact procedure successfully with execute_capability_script, then retry saving the Workflow without changing the code. The successful run must be less than 15 minutes old. The match is byte-exact on the code string, so re-send the identical source (same whitespace) that succeeded." });
        }
        const string unavailable = "workflow_capability_unavailable:";
        if (message.StartsWith(unavailable, StringComparison.Ordinal))
        {
            var capability = message[unavailable.Length..];
            var isSearch = capability is "$codemode.search" or "tools.$codemode.search";
            return (400, new
            {
                error = "workflow_capability_unavailable", capability,
                message = isSearch
                    ? "Workflows cannot include tools.$codemode.search. Use search_capabilities (or tools.$codemode.search in an ad-hoc run) to find the exact tool paths, then write the Workflow with direct tool calls only and run it again before saving."
                    : $"The Workflow calls {capability}, which is not available to this member as a saved capability. Remove it or connect the required service, then run the exact code again before saving.",
            });
        }
        return (400, new { error = "workflow_rejected", message });
    }

    /// <summary>The apps routes word a few failures for the person using the app.</summary>
    public static (int Status, object Body) MapApp(Exception error)
    {
        var (status, body) = Map(error);
        var code = error is WorkflowException ? error.Message : "";
        if (code == "teammate_not_found") return (status, new { error = code, message = "No teammate with that email belongs to this organization. Ask an admin to invite them first." });
        var message = code.Contains("not_found") ? "This app is unavailable or you no longer have access."
            : code == "artifact_view_schema_incompatible" ? "The workflow’s results have changed. Ask OpenWork to update this app before saving."
            : code == "artifact_view_revision_not_ready" ? "This app is still being prepared. Wait for its preview before saving."
            : null;
        if (message is null) return (status, body);
        var node = JsonSerializer.SerializeToNode(body)!.AsObject();
        node["message"] = message;
        return (status, node);
    }
}
