namespace WorkAI360.Api.Auth;

/// <summary>The three built-in roles and the rules about naming and ranking them (same as the reference).</summary>
public static class Roles
{
    public const string Owner = "owner";
    public const string Admin = "admin";
    public const string Member = "member";

    /// <summary>"Super-admin" was merged into admin; a stray value is read as admin rather than rejected.</summary>
    public static string Normalize(string value)
    {
        var name = string.Join('-', value.Trim().ToLowerInvariant().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return name == "super-admin" ? Admin : name;
    }

    public static bool IsAssignable(string role) => role is Admin or Member;

    public static bool IsPrivileged(string role) => role is Owner or Admin;

    private static int Level(string role) => role switch { Owner => 2, Admin => 1, Member => 0, _ => -1 };

    /// <summary>True when a change from one role to another takes access away (or cannot be shown to add any), so credentials must be revoked.</summary>
    public static bool RevokesCredentials(string previous, string next) =>
        previous != next && (Level(previous) < 0 || Level(next) < 0 || Level(next) <= Level(previous));

    /// <summary>
    /// The role an invitation carries. "admin" wins when named; "owner" is refused (it moves only by ownership transfer);
    /// anything else is invalid. Comma lists (a legacy of multi-role support) collapse to the single role.
    /// </summary>
    public static (string? Role, bool OwnerRequested, bool Invalid) ForInvitation(string value)
    {
        var names = value.Split(',').Select(Normalize).Where(n => n.Length > 0).Distinct().ToList();
        if (names.Contains(Owner)) return (null, true, false);
        if (names.Count == 0 || names.Any(n => !IsAssignable(n))) return (null, false, true);
        return (names.Contains(Admin) ? Admin : Member, false, false);
    }
}

/// <summary>Which permission keys each role holds. The catalog is generated from the reference (scripts/gen-permissions.py).</summary>
public static class Permissions
{
    private static readonly Dictionary<string, PermissionDefinition> ByKey = PermissionCatalog.All.ToDictionary(p => p.Key);
    private static readonly string[] OwnerKeys = PermissionCatalog.All.Select(p => p.Key).Order(StringComparer.Ordinal).ToArray();
    private static readonly string[] AdminKeys = PermissionCatalog.All.Where(p => p.AdminDefault).Select(p => p.Key).Order(StringComparer.Ordinal).ToArray();
    private static readonly string[] MemberKeys = PermissionCatalog.All.Where(p => p.MemberDefault).Select(p => p.Key).Order(StringComparer.Ordinal).ToArray();

    /// <summary>The owner holds every key; admins and members hold their default sets. Sorted, as the reference returns them.</summary>
    public static IReadOnlyList<string> For(string role) => role switch { Roles.Owner => OwnerKeys, Roles.Admin => AdminKeys, _ => MemberKeys };

    public static bool Has(string role, string key) => role == Roles.Owner || For(role).Contains(key);

    public static PermissionDefinition Definition(string key) => ByKey.TryGetValue(key, out var d) ? d : throw new ArgumentException($"Unknown permission {key}", nameof(key));
}
