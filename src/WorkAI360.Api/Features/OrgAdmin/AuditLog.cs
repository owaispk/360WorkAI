using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.OrgAdmin;

namespace WorkAI360.Api.Features.OrgAdmin;

public sealed record AuditActor(string Type, string? Id, string? MemberId = null, string? CredentialId = null)
{
    public static AuditActor System { get; } = new("system", "den-api.audit-defaults");
    public static AuditActor Unknown { get; } = new("unknown", null);
    public static AuditActor User(string userId, string? memberId = null, string? credentialId = null) => new("user", userId, memberId, credentialId);
}

public sealed record AuditResource(string Type, string Id, string Relationship = "target", string? Label = null);

/// <summary>What happened: the stable action name, its category, the outcome, what it touched and (for changes) before and after.</summary>
public sealed record AuditEntry(
    string Action,
    IReadOnlyList<AuditResource> Resources,
    string Category = "change",
    string Outcome = "succeeded",
    JsonObject? Before = null,
    JsonObject? After = null,
    string? ReasonCode = null,
    string Origin = "api",
    bool Force = false);

/// <summary>Records audit events. Every area that changes something an administrator would want to look back on calls this.</summary>
public interface IAuditLog
{
    /// <summary>One operation with one event per entry, by the person (or API key) behind the request.</summary>
    Task RecordAsync(OrgContext context, params AuditEntry[] entries);

    /// <summary>The same, for an actor that is not a request's caller (the system, an unknown caller, a person acting in a workspace they just joined).</summary>
    Task RecordAsync(string organizationId, AuditActor actor, params AuditEntry[] entries);

    /// <summary>An event about a person (sign-in, sign-out): recorded in every workspace they belong to.</summary>
    Task RecordForUserAsync(string userId, AuditEntry entry);
}

/// <summary>The audit capture policy of a workspace and its lazy first-use creation.</summary>
public sealed class AuditPolicies(IOptions<OrgAdminOptions> options)
{
    public static readonly string[] DefaultCategories = ["change", "security", "execution", "access", "request", "lifecycle"];
    public const long ProvisionalAllowance = 6_000_000;
    public const int ProvisionalWindowSeconds = 300;

    public bool Visible => options.Value.Audit.Visible;
    public bool CaptureAvailable => options.Value.Audit.CaptureAvailable;
    public bool Entitled => options.Value.Audit.SelfHosted;
    public object Entitlement => new { enabled = Entitled, source = Entitled ? "self_hosted" : "none" };

    /// <summary>The policy, created ON the first time it is needed when the workspace may use audit logs. Null when it cannot exist yet.</summary>
    public async Task<(AuditPolicy? Policy, bool Initialized)> EnsureAsync(DenDbContext db, string organizationId, Func<AuditEntry, Task>? lifecycle = null)
    {
        if (!CaptureAvailable || !Entitled) return (await db.Set<AuditPolicy>().AsNoTracking().FirstOrDefaultAsync(p => p.OrganizationId == organizationId), false);
        var existing = await db.Set<AuditPolicy>().AsNoTracking().FirstOrDefaultAsync(p => p.OrganizationId == organizationId);
        if (existing is not null) return (existing, false);
        var now = AuditClock.Next();
        var policy = new AuditPolicy
        {
            OrganizationId = organizationId, Revision = 1, Source = "operator", Enabled = true,
            CategoriesJson = JsonSerializer.Serialize(DefaultCategories), Allowance = ProvisionalAllowance, ExcessMode = "keep_all",
            EffectiveAt = now, CaptureStartedAt = now, AttachmentWindowSeconds = ProvisionalWindowSeconds,
        };
        db.Set<AuditPolicy>().Add(policy);
        try { await db.SaveChangesAsync(); }
        catch (DbUpdateException)
        {
            // A concurrent request created it first: use theirs and record nothing.
            db.Entry(policy).State = EntityState.Detached;
            return (await db.Set<AuditPolicy>().AsNoTracking().FirstOrDefaultAsync(p => p.OrganizationId == organizationId), false);
        }
        if (lifecycle is not null)
            await lifecycle(new AuditEntry(AuditActions.PolicyInitialized, [new("audit_policy", organizationId), new("organization", organizationId, "parent")],
                "lifecycle", After: PolicyJson(policy), ReasonCode: null));
        return (policy, true);
    }

    public static JsonObject PolicyJson(AuditPolicy p) => new()
    {
        ["organizationId"] = p.OrganizationId, ["revision"] = p.Revision, ["source"] = p.Source, ["enabled"] = p.Enabled,
        ["categories"] = JsonNode.Parse(p.CategoriesJson), ["allowance"] = p.Allowance, ["excessMode"] = p.ExcessMode,
        ["effectiveAt"] = Iso(p.EffectiveAt), ["attachmentWindowSeconds"] = p.AttachmentWindowSeconds,
    };

    public static string Iso(DateTime value) => Responses.IsoUtc(value);
}

/// <summary>Strictly increasing timestamps, so events recorded in one request keep their order when read back.</summary>
public static class AuditClock
{
    private static long _last;

    public static DateTime Next()
    {
        while (true)
        {
            var seen = Interlocked.Read(ref _last);
            // Millisecond steps: the wire format has millisecond precision, so two events never share a time.
            var candidate = Math.Max(DateTime.UtcNow.Ticks / TimeSpan.TicksPerMillisecond, seen + 1);
            if (Interlocked.CompareExchange(ref _last, candidate, seen) == seen) return new DateTime(candidate * TimeSpan.TicksPerMillisecond, DateTimeKind.Utc);
        }
    }
}

public sealed class AuditLog(DbContextOptions<DenDbContext> dbOptions, AuditPolicies policies, IHttpContextAccessor accessor, ILogger<AuditLog> logger) : IAuditLog
{
    public Task RecordAsync(OrgContext context, params AuditEntry[] entries) =>
        RecordAsync(context.Organization.Id, AuditActor.User(context.Auth.User.Id, context.Member.Id, context.ApiKeyId), entries);

    public async Task RecordAsync(string organizationId, AuditActor actor, params AuditEntry[] entries)
    {
        try { await WriteAsync(organizationId, actor, entries); }
        catch (Exception e) when (e is DbUpdateException or InvalidOperationException or Microsoft.Data.Sqlite.SqliteException)
        {
            // Writing history must not undo the change it describes; the failure is logged loudly.
            logger.LogError(e, "audit event not recorded: {Action} in {Organization}", entries.FirstOrDefault()?.Action, organizationId);
        }
    }

    public async Task RecordForUserAsync(string userId, AuditEntry entry)
    {
        try
        {
            await using var db = new DenDbContext(dbOptions);
            var organizationIds = await db.Members.AsNoTracking().Where(m => m.UserId == userId).Select(m => m.OrganizationId).ToListAsync();
            foreach (var organizationId in organizationIds) await WriteAsync(organizationId, AuditActor.User(userId), [entry]);
        }
        catch (Exception e) when (e is DbUpdateException or InvalidOperationException or Microsoft.Data.Sqlite.SqliteException)
        {
            logger.LogError(e, "audit event not recorded: {Action} for user {User}", entry.Action, userId);
        }
    }

    private async Task WriteAsync(string organizationId, AuditActor actor, AuditEntry[] entries)
    {
        if (entries.Length == 0 || !policies.CaptureAvailable || !policies.Entitled) return;
        await using var db = new DenDbContext(dbOptions);
        var (policy, _) = await policies.EnsureAsync(db, organizationId, entry => WriteCoreAsync(db, organizationId, AuditActor.System, [entry], null, null));
        if (policy is null) return;
        var categories = JsonSerializer.Deserialize<string[]>(policy.CategoriesJson) ?? [];
        // A policy that is off records nothing, except the lifecycle events that say it was switched (forced).
        var captured = entries.Where(e => e.Force || (policy.Enabled && categories.Contains(e.Category))).ToArray();
        if (captured.Length == 0) return;
        var http = accessor.HttpContext;
        // The request wrote its own change events: request capture does not record it again.
        if (http is not null) http.Items[AuditRoutes.RecordedItem] = true;
        var requestId = http is null ? null : RequestId(http);
        var route = http?.GetEndpoint() is RouteEndpoint endpoint ? endpoint.RoutePattern.RawText : null;
        await WriteCoreAsync(db, organizationId, actor, captured, requestId, http is null || route is null ? null : (http.Request.Method, route));
    }

    private static string RequestId(HttpContext http)
    {
        if (http.Items.TryGetValue("audit.requestId", out var existing) && existing is string text) return text;
        var id = Ids.New("req");
        http.Items["audit.requestId"] = id;
        return id;
    }

    private static async Task WriteCoreAsync(DenDbContext db, string organizationId, AuditActor actor, AuditEntry[] entries, string? requestId, (string Method, string Route)? http)
    {
        var operationId = Ids.New("aop");
        var started = AuditClock.Next();
        var origin = entries[0].Origin;
        var actorJson = ActorJson(actor);
        var bytes = 0L;
        var outcome = entries[^1].Outcome switch { "succeeded" => "succeeded", "failed" or "denied" => "failed", _ => "unknown" };
        foreach (var entry in entries)
        {
            var recorded = AuditClock.Next();
            var eventId = Ids.New("aev");
            var envelope = new JsonObject
            {
                ["schemaVersion"] = 2, ["id"] = eventId, ["organizationId"] = organizationId, ["operationId"] = operationId,
                ["operation"] = new JsonObject
                {
                    ["kind"] = entries[0].Category == "access" ? "audit.access" : "api.request", ["scope"] = entries[0].Action, ["origin"] = origin,
                    ["originTrust"] = "authenticated", ["initiatingActor"] = actorJson.DeepClone(), ["startedAt"] = AuditPolicies.Iso(started),
                },
                ["actor"] = actorJson.DeepClone(), ["action"] = entry.Action, ["category"] = entry.Category, ["outcome"] = entry.Outcome,
                ["occurredAt"] = AuditPolicies.Iso(recorded), ["recordedAt"] = AuditPolicies.Iso(recorded),
                ["requestId"] = requestId,
                ["resources"] = new JsonArray(entry.Resources.Select(r => (JsonNode)ResourceJson(r)).ToArray()),
            };
            if (entry.Before is not null || entry.After is not null)
            {
                var fields = entry.Before is null || entry.After is null
                    ? (entry.After ?? entry.Before)!.Select(p => p.Key)
                    : entry.Before.Select(p => p.Key).Concat(entry.After.Select(p => p.Key)).Distinct().Where(k => entry.Before[k]?.ToJsonString() != entry.After[k]?.ToJsonString());
                envelope["changes"] = new JsonObject
                {
                    ["before"] = entry.Before?.DeepClone(), ["after"] = entry.After?.DeepClone(),
                    ["changedFields"] = new JsonArray(fields.Order(StringComparer.Ordinal).Select(f => (JsonNode)JsonValue.Create(f)!).ToArray()),
                };
            }
            if (entry.ReasonCode is not null) envelope["reasonCode"] = entry.ReasonCode;
            if (http is { } h) envelope["http"] = new JsonObject { ["method"] = h.Method, ["route"] = h.Route };
            envelope["logicalBytes"] = 0;
            var size = System.Text.Encoding.UTF8.GetByteCount(envelope.ToJsonString());
            envelope["logicalBytes"] = size;
            bytes += size;
            db.Set<AuditEvent>().Add(new AuditEvent { Id = eventId, OrganizationId = organizationId, OperationId = operationId, Action = entry.Action, RequestId = requestId, RecordedAt = recorded, EnvelopeJson = envelope.ToJsonString() });
            for (var i = 0; i < entry.Resources.Count; i++)
            {
                var resource = entry.Resources[i];
                db.Set<AuditEventResource>().Add(new AuditEventResource { Id = Ids.New("aer"), OrganizationId = organizationId, OperationId = operationId, EventId = eventId, ResourceType = resource.Type, ResourceId = resource.Id, Relationship = resource.Relationship, Label = resource.Label, Position = i });
            }
        }
        db.Set<AuditOperation>().Add(new AuditOperation
        {
            Id = operationId, OrganizationId = organizationId, Kind = entries[0].Category == "access" ? "audit.access" : "api.request", Scope = entries[0].Action, Origin = origin, OriginTrust = "authenticated",
            InitiatingActorJson = actorJson.ToJsonString(), InitiatingActorType = actor.Type, InitiatingActorId = actor.Id, FirstRecordedAt = started, Outcome = outcome, EventCount = entries.Length, LogicalBytes = bytes,
        });
        await db.SaveChangesAsync();
    }

    public static JsonObject ActorJson(AuditActor actor)
    {
        var json = new JsonObject { ["type"] = actor.Type, ["id"] = actor.Id };
        if (actor.MemberId is not null) json["memberId"] = actor.MemberId;
        if (actor.CredentialId is not null) json["credentialId"] = actor.CredentialId;
        return json;
    }

    private static JsonObject ResourceJson(AuditResource r)
    {
        var json = new JsonObject { ["type"] = r.Type, ["id"] = r.Id, ["relationship"] = r.Relationship };
        if (r.Label is not null) json["label"] = r.Label;
        return json;
    }
}
