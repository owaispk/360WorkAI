using System.Text.Json.Nodes;

namespace WorkAI360.Api.Features.OrgAdmin;

/// <summary>
/// The parts of GET /v1/org that describe the deployment rather than the workspace: feature flags, capabilities, entitlements, plan and sign-in methods.
/// Capabilities are advertised honestly: only what this build serves is on (the reference also reports connections, workflows and more).
/// </summary>
public sealed class OrgEnvelope(IConfiguration configuration, AuditPolicies audit)
{
    public void AddTo(JsonObject payload)
    {
        payload["features"] = JsonSerializer(FeatureState.All(configuration));
        payload["plan"] = new JsonObject { ["tier"] = "free", ["source"] = "default" };
        // This build has no plan gating: everything is entitled, except audit logs, which follow the audit entitlement setting.
        payload["entitlements"] = new JsonObject { ["sso"] = true, ["desktopPolicies"] = true, ["orgControls"] = true, ["analytics"] = true, ["auditLogs"] = audit.Entitled, ["scim"] = true };
        payload["capabilities"] = new JsonObject
        {
            ["auditLogs"] = audit.Visible, ["gatewayDashboard"] = false, ["orgManagedDashboards"] = false, ["mcpConnections"] = false,
            ["appMcpServers"] = false, ["workflows"] = false, ["installLinks"] = false, ["openworkWeb"] = false, ["workbot"] = false,
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
