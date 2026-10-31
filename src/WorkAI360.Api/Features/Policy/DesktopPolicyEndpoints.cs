using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Policy;
using WorkAI360.Api.Features.Library;
using static WorkAI360.Api.Features.Policy.PolicyStore;

namespace WorkAI360.Api.Features.Policy;

/// <summary>The wire shapes of desktop policies and the document reading around them.</summary>
public static class DesktopPolicyService
{
    public const string DefaultName = "Default desktop policy";

    public static object Definitions() => DesktopPolicyRules.Definitions.Select(d => new Dictionary<string, object?>
    {
        ["id"] = d.Id, ["teamLabel"] = d.TeamLabel, ["group"] = d.Group, ["name"] = d.Name, ["description"] = d.Description,
        ["userNotice"] = d.UserNotice, ["defaultValue"] = d.DefaultValue, ["restrictedValue"] = d.RestrictedValue,
    }).ToList();

    /// <summary>The document as clients read it: a default policy shows every key; execution shows its defaults.</summary>
    public static JsonObject DocumentJson(string json, bool isDefault)
    {
        var doc = DesktopPolicyRules.Read(json);
        var o = new JsonObject();
        var values = isDefault ? DesktopPolicyRules.WithDefaults(doc.Values) : doc.Values;
        foreach (var key in DesktopPolicyRules.Keys) if (values.TryGetValue(key, out var v)) o[key] = v;
        if (doc.Access is not null)
        {
            var caps = new JsonObject();
            foreach (var key in DesktopPolicyRules.Keys) if (doc.Access.Capabilities.TryGetValue(key, out var v)) caps[key] = v;
            o["access"] = new JsonObject { ["mode"] = doc.Access.Mode, ["capabilities"] = caps };
        }
        if (doc.Execution is not null) o["execution"] = DesktopPolicyRules.ExecutionNode(doc.Execution);
        if (doc.Onboarding is not null)
        {
            o["onboardingPrompts"] = new JsonArray(doc.Onboarding.Prompts.Select(p => (JsonNode)p).ToArray());
            if (doc.Onboarding.Descriptions is not null) o["onboardingPromptDescriptions"] = new JsonArray(doc.Onboarding.Descriptions.Select(p => (JsonNode)p).ToArray());
        }
        return o;
    }

    public static async Task<List<object>> ListAsync(DenDbContext db, string orgId)
    {
        var policies = await db.Set<DesktopPolicy>().AsNoTracking().Where(p => p.OrganizationId == orgId && p.DeletedAt == null).ToListAsync();
        var ids = policies.Select(p => p.Id).ToList();
        var assignments = ids.Count == 0 ? [] : await db.Set<DesktopPolicyAssignment>().AsNoTracking().Where(a => ids.Contains(a.PolicyId)).ToListAsync();
        return policies
            .OrderByDescending(p => p.IsDefault).ThenBy(p => p.PolicyName, StringComparer.OrdinalIgnoreCase).ThenBy(p => p.PolicyName, StringComparer.Ordinal).ThenBy(p => p.Id, StringComparer.Ordinal)
            .Select(p => View(p, assignments.Where(a => a.PolicyId == p.Id).ToList())).ToList();
    }

    private static int Rank(DesktopPolicyAssignment a) => a.MemberId is not null ? 0 : a.TeamId is not null ? 1 : 2;

    public static object View(DesktopPolicy p, List<DesktopPolicyAssignment> assignments)
    {
        var ordered = assignments.OrderBy(Rank).ThenBy(a => a.Id, StringComparer.Ordinal).ToList();
        return new Dictionary<string, object?>
        {
            ["id"] = p.Id, ["externalKey"] = p.ExternalKey, ["organizationId"] = p.OrganizationId, ["policyName"] = p.PolicyName,
            ["isDefault"] = p.IsDefault, ["isEnabled"] = p.IsEnabled, ["priority"] = p.Priority,
            ["policy"] = DocumentJson(p.PolicyJson, p.IsDefault),
            ["createdByOrgMemberId"] = p.CreatedByMemberId, ["createdAt"] = Iso(p.CreatedAt), ["updatedAt"] = Iso(p.UpdatedAt),
            ["deletedAt"] = p.DeletedAt is null ? null : Iso(p.DeletedAt.Value),
            ["roles"] = ordered.Where(a => a.Role is not null).Select(a => a.Role!).Distinct().ToList(),
            ["assignments"] = ordered.Select(a => new Dictionary<string, object?>
            {
                ["id"] = a.Id, ["orgMemberId"] = a.MemberId, ["teamId"] = a.TeamId, ["role"] = a.Role, ["createdAt"] = Iso(a.CreatedAt),
            }).ToList(),
        };
    }

    public static async Task<object?> ViewByIdAsync(DenDbContext db, string orgId, string id)
    {
        var p = await db.Set<DesktopPolicy>().AsNoTracking().FirstOrDefaultAsync(x => x.Id == id && x.OrganizationId == orgId && x.DeletedAt == null);
        if (p is null) return null;
        return View(p, await db.Set<DesktopPolicyAssignment>().AsNoTracking().Where(a => a.PolicyId == id).ToListAsync());
    }
}

/// <summary>A create or update request for a desktop policy, validated.</summary>
public sealed record DesktopPolicyInput(string PolicyName, PolicyDocumentWrite Policy, int? Priority, bool? IsEnabled, List<string> MemberIds, List<string> TeamIds, List<string> Roles)
{
    public static DesktopPolicyInput Parse(JsonElement body)
    {
        var name = Zod.Str(body, "policyName", max: 255)!;
        var policy = DesktopPolicyWrites.Parse(Zod.Object(body, "policy"));
        int? priority = null;
        if (body.TryGetProperty("priority", out var p))
        {
            if (p.ValueKind != JsonValueKind.Number) throw new Invalid("priority", $"Invalid input: expected number, received {Zod.Kind(p)}");
            if (!p.TryGetDouble(out var d) || d != Math.Floor(d)) throw new Invalid("priority", "Invalid input: expected int, received number");
            if (d < 0) throw new Invalid("priority", "Too small: expected number to be >=0", "too_small");
            if (d > 1_000_000) throw new Invalid("priority", "Too big: expected number to be <=1000000", "too_big");
            priority = (int)d;
        }
        var enabled = Zod.Bool(body, "isEnabled");
        var members = Zod.Array(body, "memberIds", 500)?.Select((e, i) => IdAt(e, "memberIds", i, "om")).ToList() ?? [];
        var teams = Zod.Array(body, "teamIds", 500)?.Select((e, i) => IdAt(e, "teamIds", i, "tem")).ToList() ?? [];
        var roles = Zod.Array(body, "roles", 10)?.Select((e, i) =>
        {
            if (e.ValueKind != JsonValueKind.String) throw new Invalid($"roles.{i}", $"Invalid input: expected string, received {Zod.Kind(e)}");
            var r = e.GetString()!;
            if (!DesktopPolicyRules.AssignmentRoles.Contains(r)) throw new Invalid($"roles.{i}", "Invalid option: expected one of \"owner\"|\"admin\"|\"member\"", "invalid_value");
            return r;
        }).ToList() ?? [];
        return new DesktopPolicyInput(name, policy, priority, enabled, members, teams, roles);
    }

    private static string IdAt(JsonElement e, string field, int index, string prefix)
    {
        if (e.ValueKind != JsonValueKind.String) throw new Invalid($"{field}.{index}", $"Invalid input: expected string, received {Zod.Kind(e)}");
        return Zod.TypeId(e.GetString()!, prefix, $"{field}.{index}");
    }
}

public static class DesktopPolicyEndpoints
{
    private static readonly Regex ExternalKey = new("^[a-z0-9][a-z0-9._-]{0,127}$", RegexOptions.Compiled);
    private const string PatternText = "/^[a-z0-9][a-z0-9._-]{0,127}$/";

    private static string Key(string value)
    {
        if (!ExternalKey.IsMatch(value)) throw new Invalid("externalKey", $"Invalid string: must match pattern {PatternText}", "invalid_format");
        return value;
    }

    public static void Map(WebApplication app)
    {
        app.MapGet("/v1/desktop-policies", (HttpContext ctx, PolicyRunner run, PolicyStore store, DenDbContext db) =>
            run.RunAsync(ctx, "desktop_policies.view", async c =>
            {
                await store.EnsureDefaultPolicyAsync(c.Organization.Id, c.Member.Id);
                return Json(new { definitions = DesktopPolicyService.Definitions(), desktopPolicies = await DesktopPolicyService.ListAsync(db, c.Organization.Id) });
            }));

        app.MapGet("/v1/desktop-policies/by-key/{externalKey}", (string externalKey, HttpContext ctx, PolicyRunner run, DenDbContext db) =>
            run.RunAsync(ctx, "desktop_policies.view", async c =>
            {
                Key(externalKey);
                var row = await db.Set<DesktopPolicy>().AsNoTracking().FirstOrDefaultAsync(p => p.OrganizationId == c.Organization.Id && p.ExternalKey == externalKey && p.DeletedAt == null);
                var view = row is null ? null : await DesktopPolicyService.ViewByIdAsync(db, c.Organization.Id, row.Id);
                return view is null ? NotFound("desktop_policy_not_found") : Json(new { desktopPolicy = view });
            }));

        app.MapGet("/v1/desktop-policies/{desktopPolicyId}", (string desktopPolicyId, HttpContext ctx, PolicyRunner run, PolicyStore store, DenDbContext db) =>
            run.RunAsync(ctx, "desktop_policies.view", async c =>
            {
                Zod.TypeId(desktopPolicyId, "dpo", "desktopPolicyId");
                await store.EnsureDefaultPolicyAsync(c.Organization.Id, c.Member.Id);
                var view = await DesktopPolicyService.ViewByIdAsync(db, c.Organization.Id, desktopPolicyId);
                return view is null ? NotFound("desktop_policy_not_found") : Json(new { desktopPolicy = view });
            }));

        app.MapPost("/v1/desktop-policies", (HttpContext ctx, PolicyRunner run, PolicyStore store, DenDbContext db) =>
            run.RunAsync(ctx, "desktop_policies.manage", async c =>
            {
                var input = DesktopPolicyInput.Parse(await Zod.BodyAsync(ctx));
                await store.EnsureDefaultPolicyAsync(c.Organization.Id, c.Member.Id);
                return await CreateAsync(db, c, input, null);
            }));

        app.MapPatch("/v1/desktop-policies/{desktopPolicyId}", (string desktopPolicyId, HttpContext ctx, PolicyRunner run, PolicyStore store, DenDbContext db) =>
            run.RunAsync(ctx, "desktop_policies.manage", async c =>
            {
                Zod.TypeId(desktopPolicyId, "dpo", "desktopPolicyId");
                var input = DesktopPolicyInput.Parse(await Zod.BodyAsync(ctx));
                await store.EnsureDefaultPolicyAsync(c.Organization.Id, c.Member.Id);
                var result = await UpdateAsync(db, c, desktopPolicyId, input, replace: false);
                if (result is ConflictResult) result = await UpdateAsync(db, c, desktopPolicyId, input, replace: false);   // a writer replacing the same assignments: last write wins
                return result is ConflictResult ? Json(new { error = "resource_conflict", message = "The desktop policy is being changed by someone else. Try again." }, 409) : result;
            }));

        app.MapDelete("/v1/desktop-policies/{desktopPolicyId}", (string desktopPolicyId, HttpContext ctx, PolicyRunner run, PolicyStore store, DenDbContext db) =>
            run.RunAsync(ctx, "desktop_policies.manage", async c =>
            {
                Zod.TypeId(desktopPolicyId, "dpo", "desktopPolicyId");
                await store.EnsureDefaultPolicyAsync(c.Organization.Id, c.Member.Id);
                return await DeleteAsync(db, c, desktopPolicyId) is { } failure ? failure : Results.NoContent();
            }));

        app.MapPut("/v1/desktop-policies/by-key/{externalKey}", (string externalKey, HttpContext ctx, PolicyRunner run, PolicyStore store, DenDbContext db) =>
            run.RunAsync(ctx, "desktop_policies.manage", async c =>
            {
                Key(externalKey);
                var input = DesktopPolicyInput.Parse(await Zod.BodyAsync(ctx));
                if (ctx.Request.Headers.ContainsKey("If-Match") || ctx.Request.Headers.ContainsKey("If-None-Match"))
                    return Json(new { error = "unsupported_precondition", message = "This endpoint uses last-write-wins. Serialize configuration writers." }, 400);
                await store.EnsureDefaultPolicyAsync(c.Organization.Id, c.Member.Id);
                for (var attempt = 0; ; attempt++)
                {
                    var existing = await db.Set<DesktopPolicy>().AsNoTracking().FirstOrDefaultAsync(p => p.OrganizationId == c.Organization.Id && p.ExternalKey == externalKey && p.DeletedAt == null);
                    var result = existing is not null ? await UpdateAsync(db, c, existing.Id, input, replace: true) : await CreateAsync(db, c, input, externalKey);
                    if (result is not ConflictResult) return result;
                    // A concurrent creator took the key between the lookup and the insert: apply to what it made.
                    db.ChangeTracker.Clear();
                    if (attempt == 1) return Json(new { error = "resource_conflict", message = "The resource name is already in use by another identity." }, 409);
                }
            }));

        app.MapDelete("/v1/desktop-policies/by-key/{externalKey}", (string externalKey, HttpContext ctx, PolicyRunner run, DenDbContext db) =>
            run.RunAsync(ctx, "desktop_policies.manage", async c =>
            {
                Key(externalKey);
                var existing = await db.Set<DesktopPolicy>().AsNoTracking().FirstOrDefaultAsync(p => p.OrganizationId == c.Organization.Id && p.ExternalKey == externalKey && p.DeletedAt == null);
                if (existing is null) return Json(new { ok = true, deleted = false });
                return await DeleteAsync(db, c, existing.Id) ?? Json(new { ok = true, deleted = true });
            }));
    }

    /// <summary>Marks a lost race so the by-key route can look again.</summary>
    private sealed class ConflictResult : IResult { public Task ExecuteAsync(HttpContext httpContext) => Task.CompletedTask; }

    private static async Task<(List<string>? Members, List<string>? Teams, IResult? Failure)> ResolveTargetsAsync(DenDbContext db, string orgId, DesktopPolicyInput input)
    {
        var members = input.MemberIds.Distinct().ToList();
        if (members.Count > 0 && await db.Members.CountAsync(m => m.OrganizationId == orgId && members.Contains(m.Id)) != members.Count) return (null, null, NotFound("member_not_found"));
        var teams = input.TeamIds.Distinct().ToList();
        if (teams.Count > 0 && await db.Teams.CountAsync(t => t.OrganizationId == orgId && teams.Contains(t.Id)) != teams.Count) return (null, null, NotFound("team_not_found"));
        return (members, teams, null);
    }

    private static List<DesktopPolicyAssignment> NewAssignments(string orgId, string policyId, List<string> members, List<string> teams, IEnumerable<string> roles, DateTime now) =>
    [
        .. members.Select(m => new DesktopPolicyAssignment { Id = Ids.New("dpm"), OrganizationId = orgId, PolicyId = policyId, MemberId = m, SubjectKey = "m:" + m, CreatedAt = now }),
        .. teams.Select(t => new DesktopPolicyAssignment { Id = Ids.New("dpm"), OrganizationId = orgId, PolicyId = policyId, TeamId = t, SubjectKey = "t:" + t, CreatedAt = now }),
        .. roles.Distinct().Select(r => new DesktopPolicyAssignment { Id = Ids.New("dpm"), OrganizationId = orgId, PolicyId = policyId, Role = r, SubjectKey = "r:" + r, CreatedAt = now }),
    ];

    private static async Task<IResult> CreateAsync(DenDbContext db, OrgContext c, DesktopPolicyInput input, string? externalKey)
    {
        var (members, teams, failure) = await ResolveTargetsAsync(db, c.Organization.Id, input);
        if (failure is not null) return failure;
        var now = DateTime.UtcNow;
        var policy = new DesktopPolicy
        {
            Id = Ids.New("dpo"), OrganizationId = c.Organization.Id, ExternalKey = externalKey, PolicyName = input.PolicyName, IsDefault = false,
            IsEnabled = input.IsEnabled ?? true, Priority = input.Priority ?? 0,
            PolicyJson = DesktopPolicyRules.Serialize(DesktopPolicyWrites.Merge(input.Policy, null, isDefault: false, replace: false), isDefault: false),
            CreatedByMemberId = c.Member.Id, CreatedAt = now, UpdatedAt = now,
        };
        db.Set<DesktopPolicy>().Add(policy);
        db.Set<DesktopPolicyAssignment>().AddRange(NewAssignments(c.Organization.Id, policy.Id, members!, teams!, input.Roles, now));
        try { await db.SaveChangesAsync(); }
        catch (DbUpdateException)
        {
            if (externalKey is not null) return new ConflictResult();
            // A team or person removed at this moment: say which.
            db.ChangeTracker.Clear();
            return (await ResolveTargetsAsync(db, c.Organization.Id, input)).Failure ?? throw new InvalidOperationException("Could not save the desktop policy.");
        }
        return Json(new { desktopPolicy = await DesktopPolicyService.ViewByIdAsync(db, c.Organization.Id, policy.Id) }, 201);
    }

    private static async Task<IResult> UpdateAsync(DenDbContext db, OrgContext c, string id, DesktopPolicyInput input, bool replace)
    {
        var existing = await db.Set<DesktopPolicy>().FirstOrDefaultAsync(p => p.Id == id && p.OrganizationId == c.Organization.Id && p.DeletedAt == null);
        if (existing is null) return NotFound("desktop_policy_not_found");
        if (existing.IsDefault && input.IsEnabled == false)
            return Json(new { error = "default_policy_required", message = "The default desktop policy cannot be disabled." }, 400);
        var (members, teams, failure) = await ResolveTargetsAsync(db, c.Organization.Id, input);
        if (failure is not null) return failure;

        var now = DateTime.UtcNow;
        existing.PolicyName = existing.IsDefault ? existing.PolicyName : input.PolicyName;
        existing.IsEnabled = existing.IsDefault || (input.IsEnabled ?? existing.IsEnabled);
        existing.Priority = existing.IsDefault ? 0 : input.Priority ?? existing.Priority;
        existing.PolicyJson = DesktopPolicyRules.Serialize(DesktopPolicyWrites.Merge(input.Policy, existing.PolicyJson, existing.IsDefault, replace), existing.IsDefault);
        existing.UpdatedAt = now;
        try
        {
            await using var tx = await db.Database.BeginTransactionAsync();
            if (!existing.IsDefault)
            {
                await db.Set<DesktopPolicyAssignment>().Where(a => a.PolicyId == existing.Id).ExecuteDeleteAsync();
                db.Set<DesktopPolicyAssignment>().AddRange(NewAssignments(c.Organization.Id, existing.Id, members!, teams!, input.Roles, now));
            }
            await db.SaveChangesAsync();
            await tx.CommitAsync();
        }
        catch (DbUpdateException)
        {
            db.ChangeTracker.Clear();
            // Two writers replacing the assignments at once, or a team or person removed at this moment.
            var gone = (await ResolveTargetsAsync(db, c.Organization.Id, input)).Failure;
            return gone ?? new ConflictResult();
        }
        return Json(new { desktopPolicy = await DesktopPolicyService.ViewByIdAsync(db, c.Organization.Id, existing.Id) });
    }

    /// <summary>Null when deleted, else the answer to give.</summary>
    private static async Task<IResult?> DeleteAsync(DenDbContext db, OrgContext c, string id)
    {
        var existing = await db.Set<DesktopPolicy>().FirstOrDefaultAsync(p => p.Id == id && p.OrganizationId == c.Organization.Id && p.DeletedAt == null);
        if (existing is null) return NotFound("desktop_policy_not_found");
        if (existing.IsDefault) return Json(new { error = "default_policy_required", message = "The default desktop policy cannot be deleted." }, 400);
        existing.DeletedAt = DateTime.UtcNow;
        existing.IsEnabled = false;
        existing.ExternalKey = null;
        await db.SaveChangesAsync();
        return null;
    }
}
