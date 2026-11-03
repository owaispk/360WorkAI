namespace WorkAI360.Web.Components;

/// <summary>Dashboard button for the AI Gateway, for people who may see Gateway providers.</summary>
public sealed class GatewayDashboardLinks : IDashboardLinkSource
{
    public IEnumerable<DashboardLink> Links => [new("AI Gateway", "/dashboard/ai-gateway", "ai-gateway-link", 86, "gateway_providers.view")];
}
