using WorkAI360.Api.Auth;

namespace WorkAI360.Api.Auth;

/// <summary>
/// The safety rules around who may put people in teams and make Admin teams (ported from the reference): you cannot hand out
/// what you do not hold, and only owners and admins may change who is an admin. The owner is exempt from all of it.
/// </summary>
public sealed class TeamRules(PermissionService permissions, OrgAccess access)
{
    public const string AdminGrantRequiresAdmin = "Only the owner or an admin can make someone an admin.";
    public const string AdminTeamRequiresAdmin = "Only the owner or an admin can make a team an Admin team or add people to one.";
    public const string AdminTeamRemovalRequiresAdmin = "Only the owner or an admin can delete an Admin team, turn it off, or remove people from it.";
    public const string TeamGrantsForbidden = "You can't add people to this team because it grants permissions you don't have.";
    public const string AdminTeamGrantsForbidden = "You can't make this an Admin team because Admin permissions include permissions you don't have.";

    public const string OwnRoleChange = "You can't change your own role. Ask the owner or another admin.";
    public const string AdminRoleGrantForbidden = "You can't make someone an admin because admins have permissions you don't have.";
    public const string AdminRoleChangeRequiresAdmin = "Only the owner or an admin can change an admin's role.";

    public enum AdminTeamChange { None, Makes, AddsMembers, Unmakes, RemovesMembers, Deletes }

    /// <summary>Changes to who is admin through an Admin team need an owner or admin, in either direction.</summary>
    public IResult? AdminTeamDenial(OrgContext context, AdminTeamChange change)
    {
        if (context.IsOwner || context.IsAdmin) return null;
        return change switch
        {
            AdminTeamChange.Makes or AdminTeamChange.AddsMembers => access.Forbidden(AdminTeamRequiresAdmin),
            AdminTeamChange.Unmakes or AdminTeamChange.RemovesMembers or AdminTeamChange.Deletes => access.Forbidden(AdminTeamRemovalRequiresAdmin),
            _ => null,
        };
    }

    /// <summary>
    /// Null when the caller may give people what joining this team (or making it an Admin team) grants: every key its role allows, plus
    /// the Admin set's keys if it is an Admin team. <paramref name="teamId"/> is null for a team being created (it has no role yet).
    /// </summary>
    public async Task<IResult?> GrantDenialAsync(OrgContext context, string? teamId, bool grantsAdmin, bool adminDefaultsOnly, string message)
    {
        var actor = context.Permissions;
        if (actor.IsOwner) return null;
        var teamKeys = teamId is not null && !adminDefaultsOnly ? await permissions.TeamRoleKeysAsync(teamId) : [];
        if (grantsAdmin)
        {
            if (!actor.IsAdmin) return access.Forbidden(AdminGrantRequiresAdmin);
            var missingAdminKey = FirstMissing(actor, await permissions.AdminDefaultKeysAsync(context.Organization.Id));
            if (missingAdminKey is not null) return access.Forbidden(message, missingAdminKey);
        }
        var missing = FirstMissing(actor, teamKeys);
        return missing is null ? null : access.Forbidden(message, missing);
    }

    /// <summary>Making someone an admin (by role or invitation) hands them the whole Admin set, so the caller must be an admin who holds all of it.</summary>
    public async Task<IResult?> AdminRoleGrantDenialAsync(OrgContext context)
    {
        if (context.IsOwner) return null;
        if (!context.IsAdmin) return access.Forbidden(AdminGrantRequiresAdmin);
        var missing = FirstMissing(context.Permissions, await permissions.AdminDefaultKeysAsync(context.Organization.Id));
        return missing is null ? null : access.Forbidden(AdminRoleGrantForbidden, missing);
    }

    /// <summary>The first key (in sorted order) the person lacks, or null when they hold every one.</summary>
    public static string? FirstMissing(MemberPermissions held, IEnumerable<string> keys) =>
        held.IsOwner ? null : keys.Distinct().Order(StringComparer.Ordinal).FirstOrDefault(k => !held.Has(k));
}
