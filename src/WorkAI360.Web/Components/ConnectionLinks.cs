namespace WorkAI360.Web.Components;

/// <summary>The dashboard buttons for the connections area.</summary>
public sealed class ConnectionDashboardLinks : IDashboardLinkSource
{
    public IEnumerable<DashboardLink> Links =>
    [
        new("Connections", "/dashboard/mcp-connections", "connections-link", 60, "connections.view"),
        new("Your connections", "/dashboard/your-connections", "your-connections-link", 65),
    ];
}
