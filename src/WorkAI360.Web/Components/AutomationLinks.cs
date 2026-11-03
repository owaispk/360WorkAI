namespace WorkAI360.Web.Components;

/// <summary>Dashboard buttons for Automations and usage analytics (see docs/features/automations.md).</summary>
public sealed class AutomationLinks : IDashboardLinkSource
{
    public IEnumerable<DashboardLink> Links =>
    [
        new("Automations", "/dashboard/automations", "automations-link", 50),
        new("Usage analytics", "/dashboard/analytics", "analytics-link", 51, "usage_analytics.view"),
    ];
}
