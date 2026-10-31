namespace WorkAI360.Web.Components;

/// <summary>Dashboard buttons for what admins set for people and teams (see docs/features/policy.md).</summary>
public sealed class PolicyDashboardLinks : IDashboardLinkSource
{
    public IEnumerable<DashboardLink> Links =>
    [
        new("Agents, prompts and models", "/dashboard/policy", "policy-link", 40, "prompts.view"),
        new("Desktop app policies", "/dashboard/desktop-policies", "desktop-policies-link", 41, "desktop_policies.view"),
    ];
}
