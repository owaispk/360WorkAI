using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.Policy;
using WorkAI360.Api.Features.Library;

namespace WorkAI360.Api.Features.Policy;

public sealed class PolicyOptions
{
    public const string Section = "Policy";
    /// <summary>The deployment runs Automations at all (the reference's DEN_AUTOMATIONS_ENABLED).</summary>
    public bool AutomationsEnabled { get; set; } = true;
    /// <summary>The deployment has a headless runner, which Cloud Automations need. Nothing here provides one, so it is off unless configured.</summary>
    public bool HeadlessRunnerConfigured { get; set; }
}

/// <summary>
/// Policy an admin sets for people and teams: desktop policies, agent permissions, system prompts, the default model, Automations and Workbot
/// settings, and what the signed-in person's desktop receives (<c>/v1/me/desktop-config</c>, <c>/v1/me/prompts</c>). See docs/features/policy.md.
/// </summary>
public sealed class PolicyFeature : IFeature
{
    public void AddServices(IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<PolicyOptions>(configuration.GetSection(PolicyOptions.Section));
        services.AddScoped<PolicyRunner>();
        services.AddScoped<PolicyStore>();
        services.AddScoped<DesktopConfigService>();
        services.AddScoped<IDefaultModelCatalog, EmptyDefaultModelCatalog>();
    }

    public void MapEndpoints(WebApplication app)
    {
        DesktopPolicyEndpoints.Map(app);
        AgentPermissionEndpoints.Map(app);
        PromptEndpoints.Map(app);
        DefaultModelEndpoints.Map(app);
        SettingsEndpoints.Map(app);
        MeEndpoints.Map(app);
    }
}

/// <summary>Resolves the workspace, checks one permission (the reference's order: sign-in, membership, permission, then the request), and answers invalid requests in the reference's shape.</summary>
public sealed class PolicyRunner(OrgAccess access)
{
    public async Task<IResult> RunAsync(HttpContext ctx, string? permission, Func<OrgContext, Task<IResult>> handler)
    {
        var (context, failure) = await access.ResolveAsync(ctx);
        if (failure is not null) return failure;
        if (permission is not null && access.Require(context!, permission) is { } denied) return denied;
        try { return await handler(context!); }
        catch (Invalid invalid) { return invalid.ToResult(); }
    }
}

public sealed record TeamInfo(string Id, string Name);

/// <summary>Reads that several policy routes share.</summary>
public sealed class PolicyStore(DenDbContext db)
{
    public static string Iso(DateTime value) => Responses.IsoUtc(value);

    public static IResult Json(object body, int status = 200) => Results.Json(body, statusCode: status);

    public static IResult NotFound(string error) => Results.Json(new { error }, statusCode: 404);

    /// <summary>The workspace's teams by name (ignoring case).</summary>
    public async Task<List<TeamInfo>> TeamsAsync(string orgId) =>
        (await db.Teams.AsNoTracking().Where(t => t.OrganizationId == orgId).Select(t => new TeamInfo(t.Id, t.Name)).ToListAsync())
        .OrderBy(t => t.Name, StringComparer.OrdinalIgnoreCase).ThenBy(t => t.Name, StringComparer.Ordinal).ThenBy(t => t.Id, StringComparer.Ordinal).ToList();

    public Task<TeamInfo?> FindTeamAsync(string orgId, string teamId) =>
        db.Teams.AsNoTracking().Where(t => t.OrganizationId == orgId && t.Id == teamId).Select(t => new TeamInfo(t.Id, t.Name)).FirstOrDefaultAsync();

    /// <summary>The teams a person is in.</summary>
    public async Task<List<TeamInfo>> MemberTeamsAsync(string orgId, string memberId) =>
        await (from tm in db.TeamMembers.AsNoTracking()
               join t in db.Teams.AsNoTracking() on tm.TeamId equals t.Id
               where t.OrganizationId == orgId && tm.MemberId == memberId
               select new TeamInfo(t.Id, t.Name)).ToListAsync();

    public async Task<Dictionary<string, int>> MemberCountsAsync(IEnumerable<string> teamIds)
    {
        var ids = teamIds.ToList();
        if (ids.Count == 0) return [];
        return await db.TeamMembers.AsNoTracking().Where(tm => ids.Contains(tm.TeamId)).GroupBy(tm => tm.TeamId).Select(g => new { g.Key, N = g.Count() }).ToDictionaryAsync(x => x.Key, x => x.N);
    }

    /// <summary>
    /// Every workspace has one default desktop policy. It is made the first time anything needs it (the reference makes it with the workspace),
    /// and two requests doing so at once end with one.
    /// </summary>
    public async Task EnsureDefaultPolicyAsync(string orgId, string createdByMemberId)
    {
        if (await db.Set<DesktopPolicy>().AnyAsync(p => p.OrganizationId == orgId && p.IsDefault && p.DeletedAt == null)) return;
        var now = DateTime.UtcNow;
        db.Set<DesktopPolicy>().Add(new DesktopPolicy
        {
            Id = Ids.New("dpo"), OrganizationId = orgId, PolicyName = DesktopPolicyService.DefaultName, IsDefault = true, IsEnabled = true, Priority = 0,
            PolicyJson = DesktopPolicyRules.Serialize(new DesktopPolicyDocument(DesktopPolicyRules.All(true), null, null, null), isDefault: true),
            CreatedByMemberId = createdByMemberId, CreatedAt = now, UpdatedAt = now,
        });
        try { await db.SaveChangesAsync(); }
        catch (DbUpdateException) { db.ChangeTracker.Clear(); }   // someone else made it at the same moment
    }

    public async Task<OrgPolicySettings> SettingsAsync(string orgId) =>
        await db.Set<OrgPolicySettings>().AsNoTracking().FirstOrDefaultAsync(s => s.Id == orgId)
        ?? new OrgPolicySettings { Id = orgId, UpdatedAt = DateTime.UnixEpoch };

    /// <summary>Changes the workspace's settings row, creating it first; a racing first write retries once against the row the winner made.</summary>
    public async Task UpdateSettingsAsync(string orgId, Action<OrgPolicySettings> change)
    {
        for (var attempt = 0; ; attempt++)
        {
            var row = await db.Set<OrgPolicySettings>().FirstOrDefaultAsync(s => s.Id == orgId);
            if (row is null) { row = new OrgPolicySettings { Id = orgId }; db.Set<OrgPolicySettings>().Add(row); }
            change(row);
            row.UpdatedAt = DateTime.UtcNow;
            try { await db.SaveChangesAsync(); return; }
            catch (DbUpdateException) when (attempt == 0) { db.ChangeTracker.Clear(); }
        }
    }
}
