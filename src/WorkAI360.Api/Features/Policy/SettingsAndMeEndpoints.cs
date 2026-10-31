using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Policy;
using WorkAI360.Api.Features.Library;
using static WorkAI360.Api.Features.Policy.PolicyStore;

namespace WorkAI360.Api.Features.Policy;

/// <summary>What a signed-in person's desktop receives: the effective desktop policy, agent permission rules and default model.</summary>
public sealed class DesktopConfigService(DenDbContext db, PolicyStore store, IDefaultModelCatalog catalog, IOptions<PolicyOptions> options)
{
    public async Task<Dictionary<string, object?>> BuildAsync(OrgContext c)
    {
        var orgId = c.Organization.Id;
        await store.EnsureDefaultPolicyAsync(orgId, c.Member.Id);
        var config = new Dictionary<string, object?>();
        var policies = await db.Set<DesktopPolicy>().AsNoTracking().Where(p => p.OrganizationId == orgId && p.DeletedAt == null).OrderBy(p => p.CreatedAt).ToListAsync();
        var teams = await store.MemberTeamsAsync(orgId, c.Member.Id);

        if (policies.Count == 0)
        {
            foreach (var (k, v) in DesktopPolicyRules.All(true)) config[k] = v;
        }
        else
        {
            var defaultPolicy = policies.FirstOrDefault(p => p.IsDefault && p.IsEnabled);
            var roles = DesktopPolicyRules.MatchingAssignmentRoles(c.Member.Role, c.Permissions.AdminTeams.Count > 0);
            var teamIds = teams.Select(t => t.Id).ToList();
            var enabledIds = policies.Where(p => p.IsEnabled).Select(p => p.Id).ToList();
            var assignedIds = (await db.Set<DesktopPolicyAssignment>().AsNoTracking()
                .Where(a => enabledIds.Contains(a.PolicyId) && ((a.MemberId != null && a.MemberId == c.Member.Id) || (a.TeamId != null && teamIds.Contains(a.TeamId)) || (a.Role != null && roles.Contains(a.Role))))
                .Select(a => a.PolicyId).ToListAsync()).ToHashSet();
            var assigned = policies.Where(p => p.IsEnabled && assignedIds.Contains(p.Id)).Select(p => new AssignedPolicy(p.Id, p.Priority, p.CreatedAt, DesktopPolicyRules.Read(p.PolicyJson))).ToList();
            var defaultDoc = defaultPolicy is null ? null : DesktopPolicyRules.Read(defaultPolicy.PolicyJson);

            var effective = DesktopPolicyRules.CalculateEffective(policies.Count, defaultDoc, assigned.Select(a => a.Document).ToList());
            foreach (var key in DesktopPolicyRules.Keys) config[key] = effective[key];
            config["execution"] = DesktopPolicyRules.ExecutionNode(DesktopPolicyRules.ResolveExecution(new[] { defaultDoc }.Concat(assigned.Select(a => a.Document))));
            if (DesktopPolicyRules.SelectOnboarding(defaultDoc, assigned) is { } onboarding)
            {
                config["onboardingPrompts"] = onboarding.Prompts;
                if (onboarding.Descriptions is not null) config["onboardingPromptDescriptions"] = onboarding.Descriptions;
            }
        }

        var settings = await store.SettingsAsync(orgId);
        var desktopOn = options.Value.AutomationsEnabled && settings.DesktopAutomations;
        var cloudOn = options.Value.AutomationsEnabled && options.Value.HeadlessRunnerConfigured && settings.CloudAutomations;
        config["automationsEnabled"] = options.Value.AutomationsEnabled && (desktopOn || cloudOn);
        config["desktopAutomationsEnabled"] = desktopOn;
        config["cloudAutomationsEnabled"] = cloudOn;
        config["dashboardEnabled"] = false;
        // Compatibility fields for published desktops.
        config["connectEnabled"] = true;
        config["liveProviderSync"] = true;
        config["nativeAffordanceCodeMode"] = true;
        config["localProviderMirror"] = true;
        config["removeOpencodeZen"] = true;
        config["agentPermissions"] = new { rules = (await AgentRulesAsync(orgId, teams)).Select(r => new { action = r.Action, resource = r.Resource, effect = r.Effect, source = r.Source }).ToList() };
        if (await DefaultModelEndpoints.ForMemberAsync(db, store, catalog, orgId, c.Member.Id) is { } model) config["defaultModel"] = model;
        return config;
    }

    /// <summary>The rules a person's apps enforce: everyone's settings, then the person's teams', by team name.</summary>
    public async Task<List<AgentRule>> AgentRulesAsync(string orgId, IReadOnlyList<TeamInfo> teams)
    {
        var teamIds = teams.Select(t => t.Id).ToList();
        var rows = await db.Set<AgentPermissionPolicy>().AsNoTracking().Where(p => p.OrganizationId == orgId && (p.ScopeKey == "everyone" || (p.TeamId != null && teamIds.Contains(p.TeamId)))).ToListAsync();
        if (rows.Count == 0) return [];
        var everyone = rows.FirstOrDefault(r => r.ScopeKey == "everyone");
        var ordered = teams.OrderBy(t => t.Name, StringComparer.OrdinalIgnoreCase).ThenBy(t => t.Name, StringComparer.Ordinal).ThenBy(t => t.Id, StringComparer.Ordinal);
        return AgentPermissionRules.ResolveRules(
            everyone is null ? null : new AgentPolicySettings(AgentPermissionRules.Everyone, AgentSettingsJson.Read(everyone.SettingsJson)),
            ordered.Select(t => new AgentPolicySettings(t.Name, AgentSettingsJson.Read(rows.FirstOrDefault(r => r.TeamId == t.Id)?.SettingsJson))).ToList());
    }
}

public static class MeEndpoints
{
    public static void Map(WebApplication app)
    {
        app.MapGet("/v1/me/desktop-config", (HttpContext ctx, PolicyRunner run, DesktopConfigService service) =>
            run.RunAsync(ctx, null, async c => Json(await service.BuildAsync(c))));

        app.MapGet("/v1/me/prompts", (HttpContext ctx, PolicyRunner run, PolicyStore store, DenDbContext db) =>
            run.RunAsync(ctx, null, async c =>
            {
                ctx.Response.Headers.CacheControl = "no-store";
                var orgId = c.Organization.Id;
                var rows = await db.Set<OrgPrompt>().AsNoTracking().Where(p => p.OrganizationId == orgId).ToListAsync();
                var teams = await store.MemberTeamsAsync(orgId, c.Member.Id);
                var resolved = PromptRules.ResolveForMember(
                    rows.Select(r => new ResolvablePrompt(r.Id, r.Content, r.CreatedAt, new PromptAssignment(r.TeamId is null, r.TeamId is null ? [] : [r.TeamId], []))),
                    c.Member.Id, teams.Select(t => (t.Id, t.Name)));
                return Json(new
                {
                    prompts = resolved.Select(p => p.TeamName is null
                        ? (object)new { id = p.Id, source = p.Source, content = p.Content }
                        : new { id = p.Id, source = p.Source, teamName = p.TeamName, content = p.Content }).ToList(),
                });
            }));
    }
}

public static class SettingsEndpoints
{
    private static object AutomationView(OrgPolicySettings s, PolicyOptions o) => new
    {
        settings = new { desktop = s.DesktopAutomations, cloud = s.CloudAutomations },
        available = new { desktop = o.AutomationsEnabled && s.DesktopAutomations, cloud = o.AutomationsEnabled && o.HeadlessRunnerConfigured && s.CloudAutomations },
        deploymentEnabled = o.AutomationsEnabled,
        headlessRunnerConfigured = o.HeadlessRunnerConfigured,
    };


    private static IResult FeatureOff(string feature) => Results.Json(new { error = "feature_disabled", feature }, statusCode: 404);

    private static object WorkbotSettings(string? chosen) => new { model = chosen, gatewayModels = true, defaultModel = "openai/gpt-6-luna", defaultReadiness = "unverified", models = Array.Empty<object>(), modelAvailable = true, runnerReachable = false };

    public static void Map(WebApplication app)
    {
        app.MapGet("/v1/org/automation-settings", (HttpContext ctx, PolicyRunner run, PolicyStore store, IOptions<PolicyOptions> options) =>
            run.RunAsync(ctx, null, async c => { ctx.Response.Headers.CacheControl = "no-store"; return Json(AutomationView(await store.SettingsAsync(c.Organization.Id), options.Value)); }));

        app.MapPut("/v1/org/automation-settings", (HttpContext ctx, PolicyRunner run, PolicyStore store, IOptions<PolicyOptions> options) =>
            run.RunAsync(ctx, "organization.update", async c =>
            {
                ctx.Response.Headers.CacheControl = "no-store";
                var body = await Zod.BodyAsync(ctx);
                foreach (var p in body.EnumerateObject()) if (p.Name is not ("desktop" or "cloud")) throw new Invalid("", $"Unrecognized key: \"{p.Name}\"", "unrecognized_keys");
                var desktop = Zod.Bool(body, "desktop");
                var cloud = Zod.Bool(body, "cloud");
                if (desktop is null && cloud is null) throw new Invalid("", "Provide desktop, cloud or both.", "custom");
                if (cloud == true && !options.Value.HeadlessRunnerConfigured)
                    return Json(new { error = "headless_runner_required", message = "Cloud Automations need OpenWork's headless runner on this deployment. Ask your OpenWork operator to set it up." }, 409);
                await store.UpdateSettingsAsync(c.Organization.Id, s => { if (desktop is { } d) s.DesktopAutomations = d; if (cloud is { } k) s.CloudAutomations = k; });
                return Json(AutomationView(await store.SettingsAsync(c.Organization.Id), options.Value));
            }));

        app.MapGet("/v1/org/workbot-readiness", (HttpContext ctx, PolicyRunner run) =>
            run.RunAsync(ctx, null, c =>
            {
                ctx.Response.Headers.CacheControl = "no-store";
                // Workbot's default needs the AI Gateway, and there are no Gateway providers in this rewrite yet.
                return Task.FromResult(Json(new { gatewayRequired = true, hasGatewayProvider = false }));
            }));

        app.MapGet("/v1/org/workbot-settings", (HttpContext ctx, PolicyRunner run, PolicyStore store, OrgAccess access) =>
            run.RunAsync(ctx, null, async c =>
            {
                if (!c.Permissions.Has("inference.manage") && access.Require(c, "inference.view") is { } denied) return denied;
                ctx.Response.Headers.CacheControl = "no-store";
                return Json(WorkbotSettings((await store.SettingsAsync(c.Organization.Id)).WorkbotModel));
            }));

        app.MapPut("/v1/org/workbot-settings", (HttpContext ctx, PolicyRunner run, PolicyStore store) =>
            run.RunAsync(ctx, "inference.manage", async c =>
            {
                ctx.Response.Headers.CacheControl = "no-store";
                var body = await Zod.BodyAsync(ctx);
                foreach (var p in body.EnumerateObject()) if (p.Name != "model") throw new Invalid("", $"Unrecognized key: \"{p.Name}\"", "unrecognized_keys");
                if (!body.TryGetProperty("model", out var m)) throw new Invalid("model", "Invalid input: expected string, received undefined");
                string? model = null;
                if (m.ValueKind != JsonValueKind.Null) model = Zod.Str(body, "model", max: 255);
                // A model can be saved only when Workbot's runner serves it right now, and there is no runner here: only "the default" can be chosen.
                if (model is not null) return Json(new { error = "workbot_runner_unavailable", message = "Workbot's models can't be checked right now. Try again in a minute." }, 503);
                await store.UpdateSettingsAsync(c.Organization.Id, s => s.WorkbotModel = null);
                return Json(WorkbotSettings(null));
            }));

        // The Auto Router and Workbot's proactive agents sit behind features that are off, and answer as the reference does with them off.
        foreach (var (method, path, feature) in new[]
        {
            ("GET", "/v1/org/auto-router", "autoRouter"), ("GET", "/v1/org/auto-router/options", "autoRouter"), ("PUT", "/v1/org/auto-router", "autoRouter"), ("GET", "/v1/org/auto-router/connect", "autoRouter"),
            ("GET", "/v1/org/workbot-settings/proactive", "workbotProactive"), ("PUT", "/v1/org/workbot-settings/proactive", "workbotProactive"), ("GET", "/v1/org/workbot-settings/proactive/health", "workbotProactive"),
        })
        {
            app.MapMethods(path, [method], (HttpContext ctx, PolicyRunner run) => run.RunAsync(ctx, null, _ => Task.FromResult(FeatureOff(feature))));
        }
    }
}
