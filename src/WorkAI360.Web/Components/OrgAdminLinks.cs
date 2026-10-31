namespace WorkAI360.Web.Components;

/// <summary>Dashboard buttons for the organization admin pages (API keys, audit log, settings, branding).</summary>
public sealed class OrgAdminDashboardLinks : IDashboardLinkSource
{
    public IEnumerable<DashboardLink> Links =>
    [
        new("Organization settings", "/dashboard/org-settings", "org-settings-link", 40, "organization.update"),
        new("Brand and appearance", "/dashboard/brand-appearance", "brand-link", 50, "branding.update"),
        new("API keys", "/dashboard/api-keys", "api-keys-link", 60, "api_keys.view"),
        new("Audit logs", "/dashboard/audit-logs", "audit-link", 70, "audit.view"),
    ];
}
