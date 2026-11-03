using System.Text.Json.Nodes;

namespace WorkAI360.Api.Features.OrgAdmin;

/// <summary>
/// The parts of GET /v1/org that describe the deployment rather than the workspace: feature flags, capabilities, entitlements, plan and sign-in methods.
/// Capabilities are advertised honestly: only what this build serves is on (the reference also reports connections, workflows and more).
/// </summary>
public sealed class OrgEnvelope(WorkAI360.Api.Features.PlatformAdmin.FeatureResolver features, WorkAI360.Api.Features.PlatformAdmin.OrganizationPlans plans, AuditPolicies audit, Microsoft.Extensions.Options.IOptions<WorkAI360.Api.Features.Gateway.GatewayOptions> gateway)
{
    public async Task AddToAsync(JsonObject payload, string organizationId, string? userId = null)
    {
        // Feature flags: this build's defaults, then what platform admins set (everyone, this workspace, then the caller's own membership), then configuration locks.
        var effective = await features.EffectiveAsync(organizationId, userId);
        var map = new Dictionary<string, bool>();
        foreach (var key in FeatureDefaults.Organization.Keys.Order(StringComparer.Ordinal)) map[key] = effective.GetValueOrDefault(key);
        map["engineV2ForceUpgrade"] = true;
        payload["features"] = JsonSerializer(map);
        var state = await plans.GetAsync(organizationId);
        payload["plan"] = new JsonObject { ["tier"] = state.Tier, ["source"] = state.Source };
        // This build has no plan gating: everything is entitled, except audit logs, which follow the audit entitlement setting.
        payload["entitlements"] = new JsonObject { ["sso"] = true, ["desktopPolicies"] = true, ["orgControls"] = true, ["analytics"] = true, ["auditLogs"] = audit.Entitled, ["scim"] = true };
        payload["capabilities"] = new JsonObject
        {
            ["auditLogs"] = audit.Visible, ["gatewayDashboard"] = gateway.Value.Enabled, ["orgManagedDashboards"] = false, ["mcpConnections"] = false,
            ["appMcpServers"] = false, ["workflows"] = false, ["installLinks"] = false, ["openworkWeb"] = state.ComplimentaryWebAccess, ["workbot"] = false,
        };
        payload["authMethods"] = new JsonObject { ["sso"] = false, ["scim"] = false };
    }

    private static JsonObject JsonSerializer(Dictionary<string, bool> map)
    {
        var json = new JsonObject();
        foreach (var (key, value) in map) json[key] = value;
        return json;
    }
}
