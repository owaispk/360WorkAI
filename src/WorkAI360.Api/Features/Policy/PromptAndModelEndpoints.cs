using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Policy;
using WorkAI360.Api.Features.Library;
using static WorkAI360.Api.Features.Policy.PolicyStore;

namespace WorkAI360.Api.Features.Policy;

public static class PromptEndpoints
{
    private static object Prompt(OrgPrompt p) => new Dictionary<string, object?>
    {
        ["id"] = p.Id, ["name"] = p.Name, ["content"] = p.Content,
        ["assignment"] = new { everyone = p.TeamId is null, teamIds = p.TeamId is null ? [] : new[] { p.TeamId }, memberIds = Array.Empty<string>() },
        ["updatedAt"] = Iso(p.UpdatedAt),
    };

    public static async Task<object> ViewAsync(DenDbContext db, PolicyStore store, OrgContext c)
    {
        var orgId = c.Organization.Id;
        var rows = await db.Set<OrgPrompt>().AsNoTracking().Where(p => p.OrganizationId == orgId).ToListAsync();
        var everyone = rows.FirstOrDefault(r => r.TeamId is null);
        return new
        {
            everyone = everyone is null ? null : Prompt(everyone),
            teams = (await store.TeamsAsync(orgId)).Select(t => new { teamId = t.Id, name = t.Name, prompt = rows.FirstOrDefault(r => r.TeamId == t.Id) is { } r ? Prompt(r) : null }).ToList(),
            canEdit = c.Permissions.Has("prompts.manage"),
        };
    }

    private static string Content(JsonElement body)
    {
        foreach (var p in body.EnumerateObject()) if (p.Name != "content") throw new Invalid("", $"Unrecognized key: \"{p.Name}\"", "unrecognized_keys");
        if (!body.TryGetProperty("content", out var v) || v.ValueKind == JsonValueKind.Undefined) throw new Invalid("content", "Invalid input: expected string, received undefined");
        if (v.ValueKind != JsonValueKind.String) throw new Invalid("content", $"Invalid input: expected string, received {Zod.Kind(v)}");
        var s = v.GetString()!;
        if (s.Length > PromptRules.MaxLength) throw new Invalid("content", $"Too big: expected string to have <={PromptRules.MaxLength} characters", "too_big");
        if (s.Trim().Length == 0) throw new Invalid("content", "Write a prompt before saving.", "custom");
        return s;
    }

    public static void Map(WebApplication app)
    {
        app.MapGet("/v1/org/prompts", (HttpContext ctx, PolicyRunner run, PolicyStore store, DenDbContext db) =>
            run.RunAsync(ctx, "prompts.view", async c => NoStore(ctx, Json(await ViewAsync(db, store, c)))));

        app.MapPut("/v1/org/prompts/everyone", (HttpContext ctx, PolicyRunner run, PolicyStore store, DenDbContext db) =>
            run.RunAsync(ctx, "prompts.manage", async c => await SaveAsync(ctx, db, store, c, null, Content(await Zod.BodyAsync(ctx)))));

        app.MapDelete("/v1/org/prompts/everyone", (HttpContext ctx, PolicyRunner run, PolicyStore store, DenDbContext db) =>
            run.RunAsync(ctx, "prompts.manage", async c => await RemoveAsync(ctx, db, store, c, null)));

        app.MapPut("/v1/org/prompts/teams/{teamId}", (string teamId, HttpContext ctx, PolicyRunner run, PolicyStore store, DenDbContext db) =>
            run.RunAsync(ctx, "prompts.manage", async c =>
            {
                Zod.TypeId(teamId, "tem", "teamId");
                var content = Content(await Zod.BodyAsync(ctx));
                return await SaveAsync(ctx, db, store, c, await store.FindTeamAsync(c.Organization.Id, teamId), content, teamGiven: true);
            }));

        app.MapDelete("/v1/org/prompts/teams/{teamId}", (string teamId, HttpContext ctx, PolicyRunner run, PolicyStore store, DenDbContext db) =>
            run.RunAsync(ctx, "prompts.manage", async c =>
            {
                Zod.TypeId(teamId, "tem", "teamId");
                return await RemoveAsync(ctx, db, store, c, await store.FindTeamAsync(c.Organization.Id, teamId), teamGiven: true);
            }));
    }

    private static IResult NoStore(HttpContext ctx, IResult result)
    {
        ctx.Response.Headers.CacheControl = "no-store";
        return result;
    }

    private static async Task<IResult> SaveAsync(HttpContext ctx, DenDbContext db, PolicyStore store, OrgContext c, TeamInfo? team, string content, bool teamGiven = false)
    {
        if (teamGiven && team is null) return NotFound("team_not_found");
        var scope = team?.Id ?? "everyone";
        var name = team?.Name ?? AgentPermissionRules.Everyone;
        for (var attempt = 0; ; attempt++)
        {
            db.ChangeTracker.Clear();
            var row = await db.Set<OrgPrompt>().FirstOrDefaultAsync(p => p.OrganizationId == c.Organization.Id && p.ScopeKey == scope);
            var now = DateTime.UtcNow;
            if (row is null) db.Add(row = new OrgPrompt { Id = Ids.New("osp"), OrganizationId = c.Organization.Id, ScopeKey = scope, TeamId = team?.Id, Name = name, Content = content, CreatedAt = now, UpdatedAt = now });
            row.Content = content; row.Name = name; row.UpdatedByMemberId = c.Member.Id; row.UpdatedAt = now;
            try { await db.SaveChangesAsync(); break; }
            catch (DbUpdateException) when (attempt == 0) { }   // a concurrent first save of this scope won: update its prompt
            catch (DbUpdateException) { return NotFound("team_not_found"); }
        }
        return NoStore(ctx, Json(await ViewAsync(db, store, c)));
    }

    private static async Task<IResult> RemoveAsync(HttpContext ctx, DenDbContext db, PolicyStore store, OrgContext c, TeamInfo? team, bool teamGiven = false)
    {
        if (teamGiven && team is null) return NotFound("team_not_found");
        await db.Set<OrgPrompt>().Where(p => p.OrganizationId == c.Organization.Id && p.ScopeKey == (team == null ? "everyone" : team.Id)).ExecuteDeleteAsync();
        return NoStore(ctx, Json(await ViewAsync(db, store, c)));
    }
}

public sealed record DefaultModelOption(string ProviderId, string ModelId, string ProviderName, string ModelName, string LogoProviderId, string Source);

public sealed record DefaultModelOptions(IReadOnlyList<DefaultModelOption> Options, IReadOnlyList<string> UnavailableSources);

/// <summary>
/// Which models a workspace can pick as a default and how a person reaches one. The models come from the AI Gateway, OpenWork Models and the
/// workspace's own providers, none of which exist in this rewrite yet, so the built-in catalog is empty (as the reference's is for a workspace
/// with nothing set up); register another implementation when they do.
/// </summary>
public interface IDefaultModelCatalog
{
    Task<DefaultModelOptions> OptionsAsync(string organizationId);

    /// <summary>The model reference this person's desktop uses for the choice, or null when they cannot use it.</summary>
    Task<(string ProviderId, string ModelId)?> ReferenceForMemberAsync(string organizationId, string memberId, IReadOnlyList<string> teamIds, ModelChoice choice);
}

public sealed class EmptyDefaultModelCatalog : IDefaultModelCatalog
{
    public Task<DefaultModelOptions> OptionsAsync(string organizationId) => Task.FromResult(new DefaultModelOptions([], []));

    public Task<(string ProviderId, string ModelId)?> ReferenceForMemberAsync(string organizationId, string memberId, IReadOnlyList<string> teamIds, ModelChoice choice) =>
        Task.FromResult<(string, string)?>(null);
}

public static class DefaultModelEndpoints
{
    private const string Unknown = "That model isn't one your organization has. Choose one from the list.";

    private static ModelChoice? Choice(OrgDefaultModel? row) => row is null ? null : new ModelChoice(row.ProviderId, row.ModelId);

    private static object? Wire(ModelChoice? m) => m is null ? null : new { providerId = m.ProviderId, modelId = m.ModelId };

    private static async Task<object> ViewAsync(DenDbContext db, PolicyStore store, OrgContext c)
    {
        var orgId = c.Organization.Id;
        var rows = await db.Set<OrgDefaultModel>().AsNoTracking().Where(r => r.OrganizationId == orgId).ToListAsync();
        var teams = await store.TeamsAsync(orgId);
        var ids = teams.Select(t => t.Id).ToList();
        var memberships = (await db.TeamMembers.AsNoTracking().Where(tm => ids.Contains(tm.TeamId)).Select(tm => new { tm.TeamId, tm.MemberId }).ToListAsync()).Select(x => (x.TeamId, x.MemberId)).ToList();
        var models = teams.Select(t => (TeamId: t.Id, Model: Choice(rows.FirstOrDefault(r => r.TeamId == t.Id)))).ToList();
        var conflicts = DefaultModelRules.CountConflicts(models, memberships);
        return new
        {
            everyone = Wire(Choice(rows.FirstOrDefault(r => r.TeamId is null))),
            teams = teams.Select(t => new
            {
                teamId = t.Id, name = t.Name, memberCount = memberships.Count(m => m.TeamId == t.Id),
                model = Wire(models.First(m => m.TeamId == t.Id).Model), conflictingMemberCount = conflicts.GetValueOrDefault(t.Id),
            }).ToList(),
            canEdit = c.Permissions.Has("inference.manage"),
        };
    }

    private static ModelChoice? ParseWrite(JsonElement body)
    {
        foreach (var p in body.EnumerateObject()) if (p.Name != "model") throw new Invalid("", $"Unrecognized key: \"{p.Name}\"", "unrecognized_keys");
        if (!body.TryGetProperty("model", out var m)) throw new Invalid("model", "Invalid input: expected object, received undefined");
        if (m.ValueKind == JsonValueKind.Null) return null;
        if (m.ValueKind != JsonValueKind.Object) throw new Invalid("model", $"Invalid input: expected object, received {Zod.Kind(m)}");
        foreach (var p in m.EnumerateObject()) if (p.Name is not ("providerId" or "modelId")) throw new Invalid("model", $"Unrecognized key: \"{p.Name}\"", "unrecognized_keys");
        return new ModelChoice(Zod.Str(m, "providerId", max: 128, path: "model.providerId")!, Zod.Str(m, "modelId", max: 255, path: "model.modelId")!);
    }

    public static void Map(WebApplication app)
    {
        app.MapGet("/v1/org/default-model", (HttpContext ctx, PolicyRunner run, PolicyStore store, DenDbContext db) =>
            run.RunAsync(ctx, "inference.view", async c => { ctx.Response.Headers.CacheControl = "no-store"; return Json(await ViewAsync(db, store, c)); }));

        app.MapGet("/v1/org/default-model/options", (HttpContext ctx, PolicyRunner run, IDefaultModelCatalog catalog) =>
            run.RunAsync(ctx, "inference.view", async c =>
            {
                ctx.Response.Headers.CacheControl = "no-store";
                var o = await catalog.OptionsAsync(c.Organization.Id);
                return Json(new
                {
                    options = o.Options.Select(x => new { providerId = x.ProviderId, modelId = x.ModelId, providerName = x.ProviderName, modelName = x.ModelName, logoProviderId = x.LogoProviderId, source = x.Source }).ToList(),
                    unavailableSources = o.UnavailableSources,
                });
            }));

        app.MapPut("/v1/org/default-model/everyone", (HttpContext ctx, PolicyRunner run, PolicyStore store, DenDbContext db, IDefaultModelCatalog catalog) =>
            run.RunAsync(ctx, "inference.manage", async c => await SaveAsync(ctx, db, store, catalog, c, null, ParseWrite(await Zod.BodyAsync(ctx)))));

        app.MapPut("/v1/org/default-model/teams/{teamId}", (string teamId, HttpContext ctx, PolicyRunner run, PolicyStore store, DenDbContext db, IDefaultModelCatalog catalog) =>
            run.RunAsync(ctx, "inference.manage", async c =>
            {
                Zod.TypeId(teamId, "tem", "teamId");
                var model = ParseWrite(await Zod.BodyAsync(ctx));
                var team = await store.FindTeamAsync(c.Organization.Id, teamId);
                return team is null ? NotFound("team_not_found") : await SaveAsync(ctx, db, store, catalog, c, team, model);
            }));
    }

    private static async Task<IResult> SaveAsync(HttpContext ctx, DenDbContext db, PolicyStore store, IDefaultModelCatalog catalog, OrgContext c, TeamInfo? team, ModelChoice? model)
    {
        var orgId = c.Organization.Id;
        if (model is not null)
        {
            var options = await catalog.OptionsAsync(orgId);
            if (!options.Options.Any(o => o.ProviderId == model.ProviderId && o.ModelId == model.ModelId))
            {
                var source = options.UnavailableSources.Count > 0;
                return source
                    ? Json(new { error = "model_source_unavailable", message = "That model's provider can't be checked right now. Try again in a minute." }, 503)
                    : Json(new { error = "unknown_model", message = Unknown }, 400);
            }
        }
        var scope = team?.Id ?? DefaultModelRules.EveryoneScope;
        for (var attempt = 0; ; attempt++)
        {
            db.ChangeTracker.Clear();
            var row = await db.Set<OrgDefaultModel>().FirstOrDefaultAsync(r => r.OrganizationId == orgId && r.ScopeKey == scope);
            try
            {
                if (model is null) { if (row is not null) { db.Remove(row); await db.SaveChangesAsync(); } }
                else
                {
                    var now = DateTime.UtcNow;
                    if (row is null) db.Add(row = new OrgDefaultModel { Id = Ids.New("odm"), OrganizationId = orgId, ScopeKey = scope, TeamId = team?.Id, ProviderId = model.ProviderId, ModelId = model.ModelId, CreatedAt = now, UpdatedAt = now });
                    row.ProviderId = model.ProviderId; row.ModelId = model.ModelId; row.UpdatedByMemberId = c.Member.Id; row.UpdatedAt = now;
                    await db.SaveChangesAsync();
                }
                break;
            }
            catch (DbUpdateException) when (attempt == 0) { }
            catch (DbUpdateException) { return NotFound("team_not_found"); }
        }
        ctx.Response.Headers.CacheControl = "no-store";
        return Json(await ViewAsync(db, store, c));
    }

    /// <summary>What <c>/v1/me/desktop-config</c> sends as <c>defaultModel</c>: the person's teams' override, else the workspace default, if they can use it.</summary>
    public static async Task<object?> ForMemberAsync(DenDbContext db, PolicyStore store, IDefaultModelCatalog catalog, string orgId, string memberId)
    {
        try
        {
            var rows = await db.Set<OrgDefaultModel>().AsNoTracking().Where(r => r.OrganizationId == orgId).ToListAsync();
            if (rows.Count == 0) return null;
            var teams = await store.MemberTeamsAsync(orgId, memberId);
            var resolved = DefaultModelRules.Resolve(Choice(rows.FirstOrDefault(r => r.TeamId is null)), teams.Select(t => (t.Name, Choice(rows.FirstOrDefault(r => r.TeamId == t.Id)))));
            if (resolved is null) return null;
            var reference = await catalog.ReferenceForMemberAsync(orgId, memberId, teams.Select(t => t.Id).ToList(), resolved.Model);
            if (reference is null) return null;
            var d = new Dictionary<string, object?> { ["providerID"] = reference.Value.ProviderId, ["modelID"] = reference.Value.ModelId, ["source"] = resolved.FromKind };
            if (resolved.FromKind == "team") d["teamName"] = resolved.TeamName;
            return d;
        }
        catch (Exception)
        {
            return null;   // a lookup that fails leaves the desktop on its own default
        }
    }
}
