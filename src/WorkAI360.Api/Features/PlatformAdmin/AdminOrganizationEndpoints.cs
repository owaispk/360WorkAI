using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.PlatformAdmin;
using WorkAI360.Api.Features.OrgAdmin;

namespace WorkAI360.Api.Features.PlatformAdmin;

/// <summary>
/// Workspaces as the operator sees them: list and search, one workspace with a page of its people, the plan fields (stored, never billed), extra free
/// seats, the data-processing-agreement decision, complimentary web access and the per-workspace feature overrides ("capabilities").
/// </summary>
public static class AdminOrganizationEndpoints
{
    public static void MapAdminOrganizationEndpoints(this WebApplication app)
    {
        app.MapGet("/v1/admin/organizations", async (HttpContext ctx, PlatformAdminGuard guard, DenDbContext db, OrganizationPlans plans, FeatureResolver resolver) =>
        {
            var (_, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            var watch = Stopwatch.StartNew();
            var (limit, offset, search) = AdminSupport.Page(ctx.Request.Query);
            var includeFeatures = ctx.Request.Query["includeFeatures"].ToString() != "0";
            var query = db.Organizations.AsNoTracking().AsQueryable();
            if (search.Length > 0)
            {
                var pattern = AdminSupport.LikePattern(search);
                query = query.Where(o => EF.Functions.Like(o.Name.ToLower(), pattern, "|") || EF.Functions.Like(o.Slug.ToLower(), pattern, "|") || EF.Functions.Like(o.Id.ToLower(), pattern, "|"));
            }
            var total = await query.CountAsync();
            var rows = await query.OrderByDescending(o => o.CreatedAt).ThenByDescending(o => o.Id).Skip(offset).Take(limit).ToListAsync();
            var ids = rows.Select(o => o.Id).ToList();
            var states = await plans.GetManyAsync(ids);
            var counts = (await db.Members.AsNoTracking().Where(m => ids.Contains(m.OrganizationId)).GroupBy(m => m.OrganizationId).Select(g => new { Id = g.Key, Count = g.Count() }).ToListAsync()).ToDictionary(g => g.Id, g => g.Count);
            var rollouts = includeFeatures ? await resolver.RolloutsAsync() : null;
            var overrides = includeFeatures
                ? (await db.Set<PlatformOrganizationFeature>().AsNoTracking().Where(f => ids.Contains(f.OrganizationId)).ToListAsync()).GroupBy(f => f.OrganizationId).ToDictionary(g => g.Key, g => g.ToDictionary(f => f.FeatureKey, f => f.Enabled))
                : null;
            var organizations = rows.Select(o =>
            {
                var state = states.GetValueOrDefault(o.Id) ?? PlanState.From(null);
                var item = new Dictionary<string, object?>
                {
                    ["id"] = o.Id, ["name"] = o.Name, ["slug"] = o.Slug, ["createdAt"] = AdminSupport.Iso(o.CreatedAt), ["updatedAt"] = AdminSupport.Iso(state.UpdatedAt ?? o.CreatedAt),
                    ["memberCount"] = counts.GetValueOrDefault(o.Id), ["plan"] = new { tier = state.Tier, source = state.Source }, ["seatLimit"] = state.SeatLimit,
                    ["freeSeatCount"] = state.FreeSeatCount, ["seatsFreeAdditional"] = state.SeatsFreeAdditional, ["billableSeatCount"] = counts.GetValueOrDefault(o.Id),
                    ["userLimit"] = null, ["endsAt"] = state.EndsAt, ["ended"] = state.Ended, ["paidBy"] = "none",
                };
                if (rollouts is not null)
                {
                    var described = FeatureCatalog.All.Select(f => resolver.Resolve(f, rollouts, overrides!.GetValueOrDefault(o.Id) ?? [])).ToList();
                    item["capabilities"] = Capabilities(described);
                    item["featureStates"] = FeatureStates(described, null);
                }
                item["openworkWebAccess"] = WebAccess(state);
                return item;
            }).ToList();
            return Results.Json(new { organizations, page = AdminSupport.PageInfo(limit, offset, search, total, organizations.Count, watch.ElapsedMilliseconds), generatedAt = AdminSupport.Iso(DateTime.UtcNow) });
        });

        app.MapGet("/v1/admin/organizations/{organizationId}", async (string organizationId, HttpContext ctx, PlatformAdminGuard guard, DenDbContext db, OrganizationPlans plans) =>
        {
            var (_, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            ctx.Response.Headers.CacheControl = "no-store";
            if (!AdminSupport.IsTypeId("org", organizationId)) return AdminSupport.Invalid("Invalid organization id.");
            var watch = Stopwatch.StartNew();
            var (limit, offset, search) = AdminSupport.Page(ctx.Request.Query);
            var org = await db.Organizations.AsNoTracking().FirstOrDefaultAsync(o => o.Id == organizationId);
            if (org is null) return AdminSupport.NotFound("Organization not found.");
            var people = from m in db.Members.AsNoTracking() join u in db.Users.AsNoTracking() on m.UserId equals u.Id where m.OrganizationId == organizationId select new { m, u };
            var total = await people.CountAsync();
            var matching = people;
            if (search.Length > 0)
            {
                var pattern = AdminSupport.LikePattern(search);
                matching = people.Where(p => EF.Functions.Like(p.u.Name.ToLower(), pattern, "|") || EF.Functions.Like(p.u.Email.ToLower(), pattern, "|") || EF.Functions.Like(p.m.Role.ToLower(), pattern, "|"));
            }
            var matchingTotal = search.Length > 0 ? await matching.CountAsync() : total;
            var members = await matching.OrderBy(p => p.u.Name).ThenBy(p => p.m.Id).Skip(offset).Take(limit).ToListAsync();
            var now = DateTime.UtcNow;
            var invited = await db.Invitations.AsNoTracking().CountAsync(i => i.OrganizationId == organizationId && i.Status == InvitationStatus.Pending && i.ExpiresAt > now);
            var state = await plans.GetAsync(organizationId);
            return Results.Json(new
            {
                organization = new
                {
                    id = org.Id, name = org.Name, slug = org.Slug, createdAt = AdminSupport.Iso(org.CreatedAt), planTier = state.Tier, seatLimit = state.SeatLimit, memberCount = total,
                    plan = state.Resolved(total + invited), people = new { joined = total, invited }, subscriptions = new { team = (object?)null },
                    openworkWeb = new { complimentaryAccess = state.ComplimentaryWebAccess, hasAccess = state.ComplimentaryWebAccess, hasOngoingSubscription = false, subscriptionStatus = (string?)null },
                },
                members = members.Select(p => new { id = p.m.Id, userId = p.u.Id, name = p.u.Name, email = p.u.Email, role = p.m.Role, joinedAt = AdminSupport.Iso(p.m.JoinedAt ?? p.m.CreatedAt) }),
                page = AdminSupport.PageInfo(limit, offset, search, matchingTotal, members.Count, watch.ElapsedMilliseconds),
                generatedAt = AdminSupport.Iso(DateTime.UtcNow),
            });
        });

        app.MapPatch("/v1/admin/organizations/{organizationId}/plan", async (string organizationId, HttpContext ctx, PlatformAdminGuard guard, DenDbContext db, OrganizationPlans plans, IAuditLog audit) =>
        {
            var (admin, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            var body = await AdminBody.ReadAsync(ctx);
            if (AdminBody.NotObject(body) is { } notObject) return AdminSupport.Invalid(notObject);
            var root = body!.Value;
            var tier = AdminBody.Get(root, "tier");
            if (tier is not { ValueKind: JsonValueKind.String } t || t.GetString() is not ("free" or "team" or "enterprise")) return AdminSupport.Invalid("Invalid option: expected one of \"free\"|\"team\"|\"enterprise\"");
            var seatLimit = AdminBody.Get(root, "seatLimit");
            if (AdminBody.IntProblem(seatLimit, 1, PlanState.MaxUsers) is { } seatProblem) return AdminSupport.Invalid(seatProblem);
            var endsAt = AdminBody.Get(root, "endsAt");
            string? endDate = null;
            if (endsAt is { ValueKind: not JsonValueKind.Null } end)
            {
                if (end.ValueKind != JsonValueKind.String) return AdminSupport.Invalid($"Invalid input: expected string, received {AdminBody.Kind(end)}");
                if (t.GetString() == "free") return AdminSupport.Invalid("A Free plan has no end date.");
                endDate = PlanState.NormalizeEndDate(end.GetString()!);
                if (endDate is null) return AdminSupport.Invalid("Use a date such as 2026-11-22.");
            }
            if (!AdminSupport.LooksLikeOrganizationId(organizationId)) return AdminSupport.Invalid("Invalid organization id.");
            if (!await db.Organizations.AnyAsync(o => o.Id == organizationId)) return AdminSupport.NotFound("Organization not found.");

            var before = await plans.GetAsync(organizationId);
            var (state, limit) = await plans.SetPlanAsync(organizationId, t.GetString()!, seatLimit!.Value.GetInt32(), endDate);
            await RecordAsync(audit, admin!, organizationId, AuditActions.OrganizationPlanUpdated,
                new() { ["tier"] = before.Tier, ["seats"] = before.Seats, ["endsAt"] = before.EndsAt }, new() { ["tier"] = state.Tier, ["seats"] = state.Seats, ["endsAt"] = state.EndsAt });
            var users = await db.Members.CountAsync(m => m.OrganizationId == organizationId);
            return Results.Json(new { ok = true, organization = new { id = organizationId, plan = state.Resolved(users), seatLimit = limit } });
        });

        app.MapPatch("/v1/admin/organizations/{organizationId}/free-seats", async (string organizationId, HttpContext ctx, PlatformAdminGuard guard, DenDbContext db, OrganizationPlans plans, IAuditLog audit) =>
        {
            var (admin, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            var body = await AdminBody.ReadAsync(ctx);
            if (AdminBody.NotObject(body) is { } notObject) return AdminSupport.Invalid(notObject);
            if (AdminBody.IntProblem(AdminBody.Get(body!.Value, "totalFreeSeats"), PlanState.FreeSeats, PlanState.MaxUsers) is { } problem) return AdminSupport.Invalid(problem);
            if (!AdminSupport.LooksLikeOrganizationId(organizationId)) return AdminSupport.Invalid("Invalid organization id.");
            if (!await db.Organizations.AnyAsync(o => o.Id == organizationId)) return AdminSupport.NotFound("Organization not found.");

            var total = AdminBody.Get(body.Value, "totalFreeSeats")!.Value.GetInt32();
            var row = await plans.RowForUpdateAsync(organizationId);
            var previous = row.SeatsFreeAdditional;
            row.SeatsFreeAdditional = total - PlanState.FreeSeats;
            row.UpdatedAt = DateTime.UtcNow;
            await db.SaveChangesAsync();
            await RecordAsync(audit, admin!, organizationId, AuditActions.OrganizationFreeSeatsUpdated, new() { ["seatsFreeAdditional"] = previous }, new() { ["seatsFreeAdditional"] = row.SeatsFreeAdditional });
            var members = await db.Members.CountAsync(m => m.OrganizationId == organizationId);
            return Results.Json(new { ok = true, organization = new { id = organizationId, memberCount = members, freeSeatCount = total, seatsFreeAdditional = row.SeatsFreeAdditional, billableSeatCount = members } });
        });

        app.MapPatch("/v1/admin/organizations/{organizationId}/dpa", async (string organizationId, HttpContext ctx, PlatformAdminGuard guard, DenDbContext db, OrganizationPlans plans, IAuditLog audit) =>
        {
            var (admin, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            var body = await AdminBody.ReadAsync(ctx);
            if (AdminBody.NotObject(body) is { } notObject) return AdminSupport.Invalid(notObject);
            var root = body!.Value;
            var issues = new List<ZodIssue>();
            var dpa = AdminBody.Get(root, "dpaSigned");
            if (AdminBody.BoolProblem(dpa) is { } dpaProblem) issues.Add(new("invalid_type", ["dpaSigned"], dpaProblem));
            var reason = AdminBody.Get(root, "reason");
            if (AdminBody.ReasonProblem(reason, out var reasonText) is { } reasonProblem) issues.Add(new(reason is { ValueKind: JsonValueKind.String } ? "too_small" : "invalid_type", ["reason"], reasonProblem));
            if (Zod.Unrecognized(root, "dpaSigned", "reason") is { } extra) issues.Add(extra);
            if (issues.Count > 0) return Zod.Respond(issues);
            if (!AdminSupport.LooksLikeOrganizationId(organizationId)) return AdminSupport.Invalid("Invalid organization id.");
            if (!await db.Organizations.AnyAsync(o => o.Id == organizationId)) return AdminSupport.NotFound("Organization not found.");

            var signed = dpa!.Value.GetBoolean();
            var row = await plans.RowForUpdateAsync(organizationId);
            var previous = row.DpaSigned;
            row.DpaSigned = signed;
            row.UpdatedAt = DateTime.UtcNow;
            await db.SaveChangesAsync();
            // The reason is recorded as "given", never its text, as the reference does.
            await RecordAsync(audit, admin!, organizationId, AuditActions.DpaSignedUpdated, new() { ["dpaSigned"] = previous }, new() { ["dpaSigned"] = signed }, reasonProvided: reasonText.Length > 0);
            return Results.Json(new { ok = true, organization = new { id = organizationId, dpaSigned = signed } });
        });

        app.MapPut("/v1/admin/organizations/{organizationId}/openwork-web-access", async (string organizationId, HttpContext ctx, PlatformAdminGuard guard, DenDbContext db, OrganizationPlans plans, IAuditLog audit) =>
        {
            var (admin, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            var body = await AdminBody.ReadAsync(ctx);
            if (AdminBody.NotObject(body) is { } notObject) return AdminSupport.Invalid(notObject);
            var enabled = AdminBody.Get(body!.Value, "enabled");
            if (AdminBody.BoolProblem(enabled) is { } enabledProblem) return AdminSupport.Invalid(enabledProblem);
            if (AdminBody.ReasonProblem(AdminBody.Get(body.Value, "reason"), out var reason) is { } reasonProblem) return AdminSupport.Invalid(reasonProblem);
            if (!AdminSupport.LooksLikeOrganizationId(organizationId)) return AdminSupport.Invalid("Invalid organization id.");
            if (!await db.Organizations.AnyAsync(o => o.Id == organizationId)) return AdminSupport.NotFound("Organization not found.");

            var grant = enabled!.Value.GetBoolean();
            var row = await plans.RowForUpdateAsync(organizationId);
            var previous = row.ComplimentaryWebAccess;
            row.ComplimentaryWebAccess = grant;
            row.UpdatedAt = DateTime.UtcNow;
            await db.SaveChangesAsync();
            await RecordAsync(audit, admin!, organizationId, grant ? AuditActions.ComplimentaryAccessGranted : AuditActions.ComplimentaryAccessRevoked,
                new() { ["openworkWebComplimentaryAccess"] = previous }, new() { ["openworkWebComplimentaryAccess"] = grant }, reasonProvided: reason.Length > 0);
            return Results.Json(new { ok = true, organization = new { id = organizationId, openworkWebAccess = WebAccess(PlanState.From(row)) } });
        });

        app.MapGet("/v1/admin/organizations/{organizationId}/capabilities", async (string organizationId, HttpContext ctx, PlatformAdminGuard guard, DenDbContext db, FeatureResolver resolver, FeatureChanges changes) =>
        {
            var (_, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            if (!AdminSupport.LooksLikeOrganizationId(organizationId)) return AdminSupport.Invalid("Invalid organization id.");
            if (!await db.Organizations.AnyAsync(o => o.Id == organizationId)) return AdminSupport.NotFound("Organization not found.");
            var described = await resolver.DescribeAsync(organizationId);
            return Results.Json(new { capabilities = Capabilities(described), featureStates = FeatureStates(described, await changes.LatestAsync(organizationId)) });
        });

        app.MapPut("/v1/admin/organizations/{organizationId}/capabilities", async (string organizationId, HttpContext ctx, PlatformAdminGuard guard, DenDbContext db, FeatureResolver resolver, FeatureChanges changes, IAuditLog audit) =>
        {
            var (admin, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            var body = await AdminBody.ReadAsync(ctx);
            if (AdminBody.NotObject(body) is { } notObject) return AdminSupport.Invalid(notObject);
            var capabilities = AdminBody.Get(body!.Value, "capabilities");
            if (capabilities is not { ValueKind: JsonValueKind.Object } caps) return AdminSupport.Invalid($"Invalid input: expected object, received {AdminBody.Kind(capabilities)}");
            // Every registry key takes true, false or null (clear); the deprecated gatewayDashboard is checked and ignored; unknown keys are ignored.
            foreach (var property in caps.EnumerateObject())
                if ((FeatureCatalog.Find(property.Name) is not null || property.Name == "gatewayDashboard") && property.Value.ValueKind is not (JsonValueKind.True or JsonValueKind.False or JsonValueKind.Null))
                    return AdminSupport.Invalid($"Invalid input: expected boolean, received {AdminBody.Kind(property.Value)}");
            if (!AdminSupport.LooksLikeOrganizationId(organizationId)) return AdminSupport.Invalid("Invalid organization id.");
            if (!await db.Organizations.AnyAsync(o => o.Id == organizationId)) return AdminSupport.NotFound("Organization not found.");

            var requested = new List<(FeatureInfo Feature, bool? Value)>();
            foreach (var feature in FeatureCatalog.All)
            {
                if (!caps.TryGetProperty(feature.Key, out var value)) continue;
                if (!feature.Available) return AdminSupport.Invalid($"{feature.Key} is not part of this deployment.");
                requested.Add((feature, value.ValueKind == JsonValueKind.Null ? null : value.GetBoolean()));
            }
            await changes.SetOverridesAsync(organizationId, requested, admin!.User.Id);
            if (requested.Count > 0)
                await RecordAsync(audit, admin, organizationId, AuditActions.OrganizationCapabilitiesUpdated, null,
                    new JsonObject(requested.Select(r => new KeyValuePair<string, JsonNode?>(r.Feature.Key, r.Value is { } v ? JsonValue.Create(v) : null))));
            var described = await resolver.DescribeAsync(organizationId);
            return Results.Json(new { ok = true, organization = new { id = organizationId }, capabilities = Capabilities(described), featureStates = FeatureStates(described, await changes.LatestAsync(organizationId)) });
        });
    }

    /// <summary>The organization's effective feature map as /admin lists it (plus the deprecated, always-true gatewayDashboard).</summary>
    public static Dictionary<string, object?> Capabilities(IReadOnlyList<ResolvedFeature> described)
    {
        var map = new Dictionary<string, object?>();
        foreach (var f in described) map[f.Key] = f.Enabled;
        map["gatewayDashboard"] = true;
        return map;
    }

    public static Dictionary<string, object?> FeatureStates(IReadOnlyList<ResolvedFeature> described, IReadOnlyDictionary<string, object?>? lastChanges)
    {
        var map = new Dictionary<string, object?>();
        foreach (var f in described)
        {
            var state = new Dictionary<string, object?>
            {
                ["enabled"] = f.Enabled, ["source"] = f.Source, ["everyone"] = f.Everyone, ["killed"] = f.Killed, ["lock"] = f.Lock, ["override"] = f.Override, ["overrideApplies"] = f.OverrideApplies,
            };
            if (lastChanges is not null) state["lastChange"] = lastChanges.GetValueOrDefault(f.Key);
            map[f.Key] = state;
        }
        return map;
    }

    public static object WebAccess(PlanState state) => new
    {
        hasAccess = state.ComplimentaryWebAccess, accessSource = state.ComplimentaryWebAccess ? "complimentary" : null, complimentaryAccess = state.ComplimentaryWebAccess,
        hasEligibleSubscription = false, hasOngoingSubscription = false, subscriptionStatus = (string?)null,
    };

    /// <summary>The audit event for a platform change: the admin is the actor and the origin is platform_admin, so the workspace's own history shows who did it.</summary>
    public static Task RecordAsync(IAuditLog audit, AdminContext admin, string organizationId, string action, JsonObject? before, JsonObject? after, bool? reasonProvided = null) =>
        audit.RecordAsync(organizationId, AuditActor.User(admin.User.Id),
            new AuditEntry(action, [new("organization", organizationId, "target")], Before: before, After: after, ReasonCode: reasonProvided is true ? "reason_provided" : null, Origin: "platform_admin"));
}
