namespace WorkAI360.Web.Components;

/// <summary>One button on the dashboard, shown in <see cref="Order"/> order. <see cref="Permission"/> (optional) hides it from people who lack that permission.</summary>
public sealed record DashboardLink(string Label, string Href, string TestId, int Order, string? Permission = null);

/// <summary>
/// A source of dashboard buttons. Any public class implementing this with a parameterless constructor is found at startup, so a new area
/// adds its own links by adding a file (see docs/AREA_GUIDE.md), not by editing the dashboard page.
/// </summary>
public interface IDashboardLinkSource
{
    IEnumerable<DashboardLink> Links { get; }
}

public static class DashboardLinks
{
    private static readonly Lazy<IReadOnlyList<DashboardLink>> All = new(() =>
        typeof(IDashboardLinkSource).Assembly.GetTypes()
            .Where(t => t is { IsClass: true, IsAbstract: false } && typeof(IDashboardLinkSource).IsAssignableFrom(t) && t.GetConstructor(Type.EmptyTypes) is not null)
            .SelectMany(t => ((IDashboardLinkSource)Activator.CreateInstance(t)!).Links)
            .OrderBy(l => l.Order).ThenBy(l => l.Label, StringComparer.Ordinal)
            .ToList());

    public static IReadOnlyList<DashboardLink> For(IReadOnlySet<string> permissions) => All.Value.Where(l => l.Permission is null || permissions.Contains(l.Permission)).ToList();
}

/// <summary>The links that were on the dashboard before areas could add their own.</summary>
public sealed class CoreDashboardLinks : IDashboardLinkSource
{
    public IEnumerable<DashboardLink> Links =>
    [
        new("Manage members", "/dashboard/members", "members-link", 10),
        new("Teams", "/dashboard/teams", "teams-link", 20),
        new("Permissions", "/dashboard/permissions", "permissions-link", 30),
    ];
}
