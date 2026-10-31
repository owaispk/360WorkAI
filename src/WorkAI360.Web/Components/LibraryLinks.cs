namespace WorkAI360.Web.Components;

/// <summary>The library's buttons on the dashboard.</summary>
public sealed class LibraryDashboardLinks : IDashboardLinkSource
{
    public IEnumerable<DashboardLink> Links =>
    [
        new("My library", "/dashboard/library", "library-link", 40),
        new("Plugins", "/dashboard/plugins", "plugins-link", 41),
        new("Skills", "/dashboard/skills", "skills-link", 42),
        new("Marketplaces", "/dashboard/marketplaces", "marketplaces-link", 43),
    ];
}
