namespace WorkAI360.Web.Components;

/// <summary>The single sign-on and SCIM buttons on the dashboard (shown to people allowed to see them).</summary>
public sealed class SsoDashboardLinks : IDashboardLinkSource
{
    public IEnumerable<DashboardLink> Links =>
    [
        new("Single sign-on", "/dashboard/sso", "sso-link", 50, "sso.view"),
        new("SCIM provisioning", "/dashboard/scim", "scim-link", 51, "scim.view"),
    ];
}
