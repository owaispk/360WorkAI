using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.OrgAdmin;
using WorkAI360.Api.Endpoints;

namespace WorkAI360.Api.Features.OrgAdmin;

/// <summary>The audit routes: browse retained operations and their events, export them, read usage, and switch capture on or off.</summary>
public static partial class AuditEndpoints
{
    private static readonly string[] Origins = ["api", "cloud_ui", "mcp", "scheduler", "webhook", "platform_admin"];
    private static readonly string[] OperationOutcomes = ["running", "succeeded", "failed", "partial", "unknown"];
    private static readonly TimeSpan CursorLifetime = TimeSpan.FromHours(24);

    [GeneratedRegex("^usr_[0-7][0-9a-hjkmnp-tv-z]{25}$")] private static partial Regex UserId();
    [GeneratedRegex("^aop_[0-7][0-9a-hjkmnp-tv-z]{25}$")] private static partial Regex OperationId();
    [GeneratedRegex("^[a-z][a-z0-9_.-]*$")] private static partial Regex Slug();
    [GeneratedRegex("^[^\\u0000-\\u001f\\u007f-\\u009f]+$")] private static partial Regex NoControls();
    [GeneratedRegex("^(?:[1-9][0-9]?|100)$")] private static partial Regex Limit();

    private sealed class QueryError(string code, int status = 400) : Exception(code)
    {
        public string Code { get; } = code;
        public int Status { get; } = status;
    }

    private sealed record Filters(DateTime? From, DateTime? To, string? ActorId, string? Action, string? Outcome, string? Origin, string? SearchId, string? ResourceId, string? ResourceType);

    private sealed record Cursor(string Org, string Mode, string FilterHash, string? Operation, long VisibleBefore, long IssuedAt, long ExpiresAt, string A, string B);

    public static void MapAuditEndpoints(this WebApplication app)
    {
        app.MapGet("/v1/audit/event-types", (HttpContext ctx, OrgAccess access, AuditPolicies policies, IAuditLog audit) =>
            Serve(ctx, access, "audit.view", policies, audit, "event_types", null, async context =>
            {
                Query(ctx, [], []);
                await Task.CompletedTask;
                return Results.Json(new { eventTypes = AuditActions.EventTypes });
            }));

        app.MapGet("/v1/audit/operations", (HttpContext ctx, OrgAccess access, DenDbContext db, AuditPolicies policies, IAuditLog audit, IOptions<AuthOptions> auth) =>
            Serve(ctx, access, "audit.view", policies, audit, "operations", null, async context =>
            {
                var query = Query(ctx, FilterNames.Concat(PageNames).ToArray(), []);
                var filters = ReadFilters(query);
                var (limit, token) = ReadPage(query);
                var binding = new Binding(context.Organization.Id, "operations", FilterHash(filters), null);
                var state = Snapshot(binding, token, auth.Value.Secret, 0);
                var visibleBefore = FromMillis(state.VisibleBefore);
                var scoped = OperationsQuery(db, context.Organization.Id, filters, visibleBefore);
                if (state.Position is { } position)
                {
                    var startedAt = ParseIso(position.A);
                    scoped = scoped.Where(o => o.FirstRecordedAt < startedAt || (o.FirstRecordedAt == startedAt && string.Compare(o.Id, position.B) < 0));
                }
                var rows = await scoped.OrderByDescending(o => o.FirstRecordedAt).ThenByDescending(o => o.Id).Take(limit + 1).AsNoTracking().ToListAsync();
                var page = rows.Take(limit).ToList();
                var ids = page.Select(o => o.Id).ToList();
                var events = await db.Set<AuditEvent>().AsNoTracking().Where(e => ids.Contains(e.OperationId) && e.RecordedAt <= visibleBefore).Select(e => new { e.Id, e.OperationId, e.Action, e.RecordedAt }).ToListAsync();
                var first = events.GroupBy(e => e.OperationId).ToDictionary(g => g.Key, g => g.OrderBy(e => e.RecordedAt).ThenBy(e => e.Id).First());
                var firstIds = first.Values.Select(e => e.Id).ToList();
                var resources = (await db.Set<AuditEventResource>().AsNoTracking().Where(r => firstIds.Contains(r.EventId)).ToListAsync()).GroupBy(r => r.EventId).ToDictionary(g => g.Key, g => g.OrderBy(r => r.Position).ToList());
                var operations = page.Select(o =>
                {
                    var firstEvent = first[o.Id];
                    return new
                    {
                        id = o.Id, kind = o.Kind, scope = o.Scope, action = firstEvent.Action, initiatingActor = JsonNode.Parse(o.InitiatingActorJson), origin = o.Origin, originTrust = o.OriginTrust,
                        startedAt = Responses.IsoUtc(o.FirstRecordedAt), outcome = o.Outcome, eventCount = o.EventCount, logicalBytes = o.LogicalBytes,
                        resources = (resources.GetValueOrDefault(firstEvent.Id) ?? []).Select(r => r.Label is null ? (object)new { type = r.ResourceType, id = r.ResourceId, relationship = r.Relationship } : new { type = r.ResourceType, id = r.ResourceId, relationship = r.Relationship, label = r.Label }).ToList(),
                    };
                }).ToList();
                string? next = null;
                if (rows.Count > limit && page.Count > 0) next = Sign(binding, state, Responses.IsoUtc(page[^1].FirstRecordedAt), page[^1].Id, auth.Value.Secret);
                ctx.Response.Headers["X-Audit-Resource-Scope"] = "first_event";
                return Results.Json(new { operations, nextCursor = next, snapshotAt = Responses.IsoUtc(visibleBefore) });
            }));

        app.MapGet("/v1/audit/operations/{operationId}/events", (string operationId, HttpContext ctx, OrgAccess access, DenDbContext db, AuditPolicies policies, IAuditLog audit, IOptions<AuthOptions> auth) =>
            Serve(ctx, access, "audit.view", policies, audit, "events", operationId, async context =>
            {
                var query = Query(ctx, PageNames, []);
                if (!OperationId().IsMatch(operationId)) throw new QueryError("audit_invalid_query");
                var (limit, token) = ReadPage(query);
                var binding = new Binding(context.Organization.Id, "events", FilterHash(new Filters(null, null, null, null, null, null, null, null, null)), operationId);
                var state = Snapshot(binding, token, auth.Value.Secret, 0);
                var visibleBefore = FromMillis(state.VisibleBefore);
                if (!await db.Set<AuditOperation>().AnyAsync(o => o.OrganizationId == context.Organization.Id && o.Id == operationId)) throw new QueryError("audit_operation_not_found", 404);
                var scoped = db.Set<AuditEvent>().AsNoTracking().Where(e => e.OrganizationId == context.Organization.Id && e.OperationId == operationId && e.RecordedAt <= visibleBefore);
                var (events, next) = await EventPage(scoped, state, binding, limit, auth.Value.Secret);
                return Results.Json(new { events, nextCursor = next, snapshotAt = Responses.IsoUtc(visibleBefore) });
            }));

        app.MapGet("/v1/audit/usage", (HttpContext ctx, OrgAccess access, DenDbContext db, AuditPolicies policies, IAuditLog audit) =>
            Serve(ctx, access, "audit.view", policies, audit, "usage", null, async context =>
            {
                Query(ctx, [], []);
                await policies.EnsureAsync(db, context.Organization.Id, entry => audit.RecordAsync(context.Organization.Id, AuditActor.System, entry));
                return Results.Json(await UsageAsync(db, policies, context.Organization.Id));
            }));

        app.MapGet("/v1/audit/export", (HttpContext ctx, OrgAccess access, DenDbContext db, AuditPolicies policies, IAuditLog audit, IOptions<AuthOptions> auth, IOptions<OrgAdminOptions> options) =>
            Serve(ctx, access, "audit.view", policies, audit, "export", null, async context =>
            {
                var query = Query(ctx, FilterNames.Concat(PageNames).Append("format").ToArray(), []);
                var filters = ReadFilters(query);
                var (limit, token) = ReadPage(query);
                var format = query.GetValueOrDefault("format") ?? "ndjson";
                if (format is not ("csv" or "ndjson")) throw new QueryError("audit_invalid_query");
                var binding = new Binding(context.Organization.Id, format == "csv" ? "export-csv" : "export-ndjson", FilterHash(filters), null);
                var state = Snapshot(binding, token, auth.Value.Secret, options.Value.Audit.ExportSettleSeconds);
                var visibleBefore = FromMillis(state.VisibleBefore);
                var operationIds = OperationsQuery(db, context.Organization.Id, filters, visibleBefore).Select(o => o.Id);
                var scoped = db.Set<AuditEvent>().AsNoTracking().Where(e => e.OrganizationId == context.Organization.Id && e.RecordedAt <= visibleBefore && operationIds.Contains(e.OperationId));
                var (events, next) = await EventPage(scoped, state, binding, limit, auth.Value.Secret);
                var body = format == "csv" ? Csv(events) : string.Concat(events.Select(e => e!.ToJsonString() + "\n"));
                var headers = ctx.Response.Headers;
                headers["Content-Disposition"] = $"attachment; filename=\"audit-{new DateTimeOffset(visibleBefore).ToUnixTimeMilliseconds()}.{format}\"";
                headers["X-Content-Type-Options"] = "nosniff";
                headers["X-Audit-Snapshot-At"] = Responses.IsoUtc(visibleBefore);
                if (next is not null) headers["X-Audit-Next-Cursor"] = next;
                return Results.Text(body, format == "csv" ? "text/csv; charset=utf-8" : "application/x-ndjson; charset=utf-8");
            }));

        app.MapPatch("/v1/audit/settings", async (HttpContext ctx, OrgAccess access, DenDbContext db, AuditPolicies policies, IAuditLog audit) =>
        {
            ctx.Response.Headers.CacheControl = "no-store";
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "audit.manage") is { } denied) return denied;
            if (!policies.Visible) return Results.Json(new { error = "audit_visibility_disabled" }, statusCode: 403);

            var (root, invalid) = await Zod.ReadObjectAsync(ctx, "captureOn");
            if (invalid is not null) return invalid;
            var issues = new List<ZodIssue>();
            bool captureOn = false;
            long expected = 0;
            if (!root.TryGetProperty("captureOn", out var on)) issues.Add(new("invalid_type", ["captureOn"], "Invalid input: expected boolean, received undefined"));
            else if (on.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) issues.Add(new("invalid_type", ["captureOn"], $"Invalid input: expected boolean, received {Zod.Kind(on)}"));
            else captureOn = on.GetBoolean();
            if (!root.TryGetProperty("expectedRevision", out var rev)) issues.Add(new("invalid_type", ["expectedRevision"], "Invalid input: expected number, received undefined"));
            else if (rev.ValueKind != JsonValueKind.Number) issues.Add(new("invalid_type", ["expectedRevision"], $"Invalid input: expected number, received {Zod.Kind(rev)}"));
            else if (!rev.TryGetInt64(out expected) || expected > 9007199254740991) issues.Add(new("invalid_type", ["expectedRevision"], "Invalid input: expected int, received number"));
            else if (expected < 0) issues.Add(new("too_small", ["expectedRevision"], "Too small: expected number to be >=0"));
            if (Zod.Unrecognized(root, "captureOn", "expectedRevision") is { } extra) issues.Add(extra);
            if (issues.Count > 0) return Zod.Respond(issues);

            if (captureOn && !policies.Entitled)
                return Results.Json(new { error = "enterprise_plan_required", feature = "auditLogs", message = "Audit logs requires an Enterprise plan or explicit self-hosted installation entitlement." }, statusCode: 402);
            if (captureOn && !policies.CaptureAvailable) return Results.Json(new { error = "audit_capture_unavailable" }, statusCode: 409);

            // Initialization (when the policy is new) and the change commit together, so an explicit OFF never publishes an intermediate ON.
            AuditPolicy? before;
            AuditPolicy? after;
            bool initialized;
            await using (var tx = await db.Database.BeginTransactionAsync())
            {
                (before, initialized) = await policies.EnsureAsync(db, context!.Organization.Id);
                if (expected == 0 && before is not null && !initialized) return Conflict("audit_policy_changed");
                if (initialized && expected != 0) return Conflict("audit_policy_changed");
                var expectedRevision = initialized && expected == 0 ? 1 : expected;
                if (before is null) return Conflict("audit_policy_not_configured");
                if (before.Revision != expectedRevision) return Conflict("audit_policy_changed");
                after = before;
                if (before.Enabled != captureOn)
                {
                    var now = AuditClock.Next();
                    var changed = await db.Set<AuditPolicy>().Where(p => p.OrganizationId == before.OrganizationId && p.Revision == expectedRevision)
                        .ExecuteUpdateAsync(s => s.SetProperty(p => p.Enabled, captureOn).SetProperty(p => p.Revision, expectedRevision + 1).SetProperty(p => p.EffectiveAt, now)
                            .SetProperty(p => p.CaptureStartedAt, p => captureOn && p.CaptureStartedAt == null ? now : p.CaptureStartedAt));
                    if (changed == 0) return Conflict("audit_policy_changed");
                    after = await db.Set<AuditPolicy>().AsNoTracking().FirstAsync(p => p.OrganizationId == before.OrganizationId);
                }
                await tx.CommitAsync();
            }
            if (initialized && before is not null)
                await audit.RecordAsync(context.Organization.Id, AuditActor.System, new AuditEntry(AuditActions.PolicyInitialized, [new("audit_policy", context.Organization.Id), new("organization", context.Organization.Id, "parent")], "lifecycle", After: AuditPolicies.PolicyJson(before), Force: true));
            if (before is not null && after is not null && after.Revision != before.Revision)
                await audit.RecordAsync(context, new AuditEntry(captureOn ? AuditActions.CaptureEnabled : AuditActions.CaptureDisabled,
                    [new("audit_policy", context.Organization.Id), new("organization", context.Organization.Id, "parent")], "lifecycle",
                    Before: new JsonObject { ["enabled"] = before.Enabled, ["revision"] = before.Revision }, After: new JsonObject { ["enabled"] = after.Enabled, ["revision"] = after.Revision }, Force: true));
            return Results.Json(await UsageAsync(db, policies, context.Organization.Id));
        });
    }

    private static IResult Conflict(string code) => Results.Json(new { error = code }, statusCode: 409);

    // ----- shared plumbing -------------------------------------------------------------------------------------------------------------

    /// <summary>Permission, visibility, the read itself, then (when the policy records access) a requested/served pair describing the read.</summary>
    private static async Task<IResult> Serve(HttpContext ctx, OrgAccess access, string permission, AuditPolicies policies, IAuditLog audit, string read, string? operationId,
        Func<OrgContext, Task<IResult>> action)
    {
        ctx.Response.Headers.CacheControl = "no-store";
        var (context, failure) = await access.ResolveAsync(ctx);
        if (failure is not null) return failure;
        if (access.Require(context!, permission) is { } denied) return denied;
        if (!policies.Visible) return Results.Json(new { error = "audit_visibility_disabled" }, statusCode: 403);
        IResult result;
        try { result = await action(context!); }
        catch (QueryError e) { return Results.Json(new { error = e.Code }, statusCode: e.Status); }
        // Only a read that succeeded is recorded as served.
        var resource = operationId is null ? new AuditResource("audit_collection", $"audit.{read}") : new AuditResource("audit_operation", operationId);
        await audit.RecordAsync(context!,
            new AuditEntry(AuditActions.Requested(read), [resource], "access", "unknown"),
            new AuditEntry(AuditActions.Served(read), [resource], "access"));
        return result;
    }

    private static readonly string[] FilterNames = ["from", "to", "actorId", "action", "outcome", "origin", "searchId", "resourceId", "resourceType"];
    private static readonly string[] PageNames = ["limit", "cursor"];

    /// <summary>Query string as a map. A repeated or unknown parameter is refused (the reference's queries are strict).</summary>
    private static Dictionary<string, string> Query(HttpContext ctx, string[] allowed, string[] _)
    {
        var map = new Dictionary<string, string>();
        foreach (var (name, values) in ctx.Request.Query)
        {
            if (values.Count != 1 || !allowed.Contains(name)) throw new QueryError("audit_invalid_query");
            map[name] = values[0]!;
        }
        return map;
    }

    private static (int Limit, string? Cursor) ReadPage(Dictionary<string, string> query)
    {
        var limit = 50;
        if (query.TryGetValue("limit", out var l)) { if (!Limit().IsMatch(l)) throw new QueryError("audit_invalid_query"); limit = int.Parse(l, CultureInfo.InvariantCulture); }
        if (query.TryGetValue("cursor", out var cursor) && (cursor.Length is < 1 or > 4096)) throw new QueryError("audit_invalid_query");
        return (limit, query.GetValueOrDefault("cursor"));
    }

    private static Filters ReadFilters(Dictionary<string, string> q)
    {
        DateTime? Date(string name)
        {
            if (!q.TryGetValue(name, out var v)) return null;
            if (v.Length > 40) throw new QueryError("audit_invalid_query");
            if (DateTimeOffset.TryParseExact(v, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var day)) return day.UtcDateTime;
            // Offset date-times only: "2026-01-01T00:00:00Z" or "+02:00"; a bare local time is refused like the reference's datetime({offset: true}).
            if (Regex.IsMatch(v, @"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})$") && DateTimeOffset.TryParse(v, CultureInfo.InvariantCulture, DateTimeStyles.None, out var at)) return at.UtcDateTime;
            throw new QueryError("audit_invalid_query");
        }
        string? Text(string name, int max, Regex? pattern = null)
        {
            if (!q.TryGetValue(name, out var v)) return null;
            if (v.Length < 1 || v.Length > max || (pattern is not null && !pattern.IsMatch(v))) throw new QueryError("audit_invalid_query");
            return v;
        }
        var from = Date("from");
        var to = Date("to");
        var actor = Text("actorId", 255, UserId());
        var outcome = Text("outcome", 32);
        var origin = Text("origin", 32);
        if (outcome is not null && !OperationOutcomes.Contains(outcome)) throw new QueryError("audit_invalid_query");
        if (origin is not null && !Origins.Contains(origin)) throw new QueryError("audit_invalid_query");
        var resourceId = Text("resourceId", 255, NoControls());
        var resourceType = Text("resourceType", 64, Slug());
        if (from is not null && to is not null && from > to) throw new QueryError("audit_invalid_query");
        if (resourceType is not null && resourceId is null) throw new QueryError("audit_invalid_query");
        return new Filters(from, to, actor, Text("action", 128, Slug()), outcome, origin, Text("searchId", 255, NoControls()), resourceId, resourceType);
    }

    private static IQueryable<AuditOperation> OperationsQuery(DenDbContext db, string organizationId, Filters f, DateTime visibleBefore)
    {
        var events = db.Set<AuditEvent>().Where(e => e.OrganizationId == organizationId && e.RecordedAt <= visibleBefore);
        var query = db.Set<AuditOperation>().Where(o => o.OrganizationId == organizationId && events.Any(e => e.OperationId == o.Id));
        if (f.From is { } from) query = query.Where(o => o.FirstRecordedAt >= from);
        if (f.To is { } to) query = query.Where(o => o.FirstRecordedAt <= to);
        if (f.ActorId is { } actor) query = query.Where(o => o.InitiatingActorType == "user" && o.InitiatingActorId == actor);
        if (f.Outcome is { } outcome) query = query.Where(o => o.Outcome == outcome);
        if (f.Origin is { } origin) query = query.Where(o => o.Origin == origin);
        if (f.Action is { } action) query = query.Where(o => events.Any(e => e.OperationId == o.Id && e.Action == action));
        var resources = db.Set<AuditEventResource>().Where(r => r.OrganizationId == organizationId);
        if (f.SearchId is { } id)
            query = query.Where(o => o.Id == id || events.Any(e => e.OperationId == o.Id && (e.Id == id || e.RequestId == id)) || resources.Any(r => r.OperationId == o.Id && r.ResourceId == id));
        if (f.ResourceId is { } resourceId)
        {
            var type = f.ResourceType;
            query = query.Where(o => resources.Any(r => r.OperationId == o.Id && r.ResourceId == resourceId && (type == null || r.ResourceType == type)));
        }
        return query;
    }

    private static async Task<(List<JsonNode?> Events, string? Next)> EventPage(IQueryable<AuditEvent> scoped, State state, Binding binding, int limit, string secret)
    {
        if (state.Position is { } position)
        {
            var at = ParseIso(position.A);
            scoped = scoped.Where(e => e.RecordedAt > at || (e.RecordedAt == at && string.Compare(e.Id, position.B) > 0));
        }
        var rows = await scoped.OrderBy(e => e.RecordedAt).ThenBy(e => e.Id).Take(limit + 1).ToListAsync();
        var page = rows.Take(limit).ToList();
        var events = page.Select(e => JsonNode.Parse(e.EnvelopeJson)).ToList();
        string? next = rows.Count > limit && page.Count > 0 ? Sign(binding, state, Responses.IsoUtc(page[^1].RecordedAt), page[^1].Id, secret) : null;
        return (events, next);
    }

    private static async Task<object> UsageAsync(DenDbContext db, AuditPolicies policies, string organizationId)
    {
        var policy = await db.Set<AuditPolicy>().AsNoTracking().FirstOrDefaultAsync(p => p.OrganizationId == organizationId);
        var retained = await db.Set<AuditOperation>().CountAsync(o => o.OrganizationId == organizationId);
        var events = await db.Set<AuditEvent>().CountAsync(e => e.OrganizationId == organizationId);
        var bytes = retained == 0 ? 0 : await db.Set<AuditOperation>().Where(o => o.OrganizationId == organizationId).SumAsync(o => o.LogicalBytes);
        var oldest = retained == 0 ? (DateTime?)null : await db.Set<AuditOperation>().Where(o => o.OrganizationId == organizationId).MinAsync(o => o.FirstRecordedAt);
        return new
        {
            entitlement = policies.Entitlement,
            captureOn = policy?.Enabled ?? false,
            captureAvailable = policies.CaptureAvailable,
            policy = policy is null ? null : PolicyWire(policy),
            captureEnabled = policies.Entitled && policies.CaptureAvailable && policy?.Enabled == true,
            retainedOperations = retained,
            eventCount = events,
            logicalBytes = bytes,
            oldestAvailableAt = oldest is { } o ? Responses.IsoUtc(o) : null,
            // The reference recomputes totals on a schedule and reports when; these are live, so "measured" is now.
            measuredAt = retained == 0 ? null : Responses.IsoUtc(DateTime.UtcNow),
            billing = "disabled",
            cleanup = "dry_run",
            drains = "not_configured",
        };
    }

    private static object PolicyWire(AuditPolicy p) => new
    {
        organizationId = p.OrganizationId, revision = p.Revision, source = p.Source, enabled = p.Enabled, categories = JsonNode.Parse(p.CategoriesJson), allowance = p.Allowance,
        excessMode = p.ExcessMode, effectiveAt = Responses.IsoUtc(p.EffectiveAt), captureStartedAt = p.CaptureStartedAt is { } c ? Responses.IsoUtc(c) : null, attachmentWindowSeconds = p.AttachmentWindowSeconds,
    };

    // ----- cursors: signed, bound to the organization, the kind of read and the filters, valid for 24 hours -------------------------------

    private sealed record Binding(string Org, string Mode, string FilterHash, string? Operation);
    private sealed record State(long VisibleBefore, long IssuedAt, long ExpiresAt, (string A, string B)? Position);

    private static string FilterHash(Filters f) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(f))));

    private static State Snapshot(Binding binding, string? token, string secret, int settleSeconds)
    {
        if (token is null)
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            return new State(now - settleSeconds * 1000L, now, now + (long)CursorLifetime.TotalMilliseconds, null);
        }
        var cursor = Read(token, secret) ?? throw new QueryError("audit_invalid_cursor");
        if (cursor.Org != binding.Org || cursor.Mode != binding.Mode || cursor.FilterHash != binding.FilterHash || cursor.Operation != binding.Operation) throw new QueryError("audit_invalid_cursor");
        if (cursor.ExpiresAt <= DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()) throw new QueryError("audit_cursor_expired", 410);
        return new State(cursor.VisibleBefore, cursor.IssuedAt, cursor.ExpiresAt, (cursor.A, cursor.B));
    }

    private static string Sign(Binding binding, State state, string a, string b, string secret)
    {
        var payload = Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new Cursor(binding.Org, binding.Mode, binding.FilterHash, binding.Operation, state.VisibleBefore, state.IssuedAt, state.ExpiresAt, a, b))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var signature = Convert.ToBase64String(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(payload))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return $"{payload}.{signature}";
    }

    private static Cursor? Read(string token, string secret)
    {
        var dot = token.IndexOf('.');
        if (dot <= 0) return null;
        var payload = token[..dot];
        var expected = Convert.ToBase64String(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(payload))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(token[(dot + 1)..]))) return null;
        try
        {
            var padded = payload.Replace('-', '+').Replace('_', '/');
            padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
            return JsonSerializer.Deserialize<Cursor>(Convert.FromBase64String(padded));
        }
        catch (Exception e) when (e is FormatException or JsonException) { return null; }
    }

    private static DateTime FromMillis(long ms) => new(ms * TimeSpan.TicksPerMillisecond + DateTime.UnixEpoch.Ticks, DateTimeKind.Utc);
    private static DateTime ParseIso(string value) => DateTime.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal);

    // ----- CSV: every cell quoted; formula-leading cells prefixed; backslashes doubled; control characters written as \uXXXX ------------

    public static string CsvCell(string? value)
    {
        var text = value ?? "";
        var unsafeStart = Regex.IsMatch(text, @"^[\s\p{Cc}\p{Cf}]*[=+@-]") || Regex.IsMatch(text, @"^[\s\p{Cc}\p{Cf}]*[\t\r\n]");
        var encoded = text.Replace("\\", "\\\\");
        encoded = Regex.Replace(encoded, @"[\u0000-\u001f\u007f-\u009f  ]", m => $"\\u{(int)m.Value[0]:x4}");
        return $"\"{(unsafeStart ? "'" : "")}{encoded.Replace("\"", "\"\"")}\"";
    }

    private static string Csv(List<JsonNode?> events)
    {
        string[] header = ["schema_version", "event_id", "operation_id", "organization_id", "operation_kind", "operation_scope", "operation_started_at", "initiating_actor_type", "initiating_actor_id", "origin", "origin_trust", "actor_type", "actor_id", "member_id", "credential_id", "action", "category", "event_outcome", "occurred_at", "recorded_at", "request_id", "resources_json", "changed_fields_json", "logical_bytes"];
        var sb = new StringBuilder();
        sb.Append(string.Join(',', header.Select(CsvCell))).Append("\r\n");
        foreach (var e in events)
        {
            string? S(JsonNode? n) => n is JsonValue v ? v.ToString() : null;
            var op = e!["operation"]!;
            string?[] row =
            [
                S(e["schemaVersion"]), S(e["id"]), S(e["operationId"]), S(e["organizationId"]), S(op["kind"]), S(op["scope"]), S(op["startedAt"]), S(op["initiatingActor"]!["type"]), S(op["initiatingActor"]!["id"]),
                S(op["origin"]), S(op["originTrust"]), S(e["actor"]!["type"]), S(e["actor"]!["id"]), S(e["actor"]!["memberId"]), S(e["actor"]!["credentialId"]), S(e["action"]), S(e["category"]), S(e["outcome"]),
                S(e["occurredAt"]), S(e["recordedAt"]), S(e["requestId"]), e["resources"]!.ToJsonString(), (e["changes"]?["changedFields"] ?? new JsonArray()).ToJsonString(), S(e["logicalBytes"]),
            ];
            sb.Append(string.Join(',', row.Select(CsvCell))).Append("\r\n");
        }
        return sb.ToString();
    }
}
