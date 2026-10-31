using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Features.OrgAdmin;

namespace WorkAI360.Api.Endpoints;

/// <summary>The body of GET /v1/org: the workspace, the caller's standing in it, its members (pending invitations included as placeholders) and invitations.</summary>
public static class OrgPayload
{
    public static async Task<object> BuildAsync(DenDbContext db, OrgContext context)
    {
        var org = context.Organization;
        var now = DateTime.UtcNow;
        var rows = await (from m in db.Members.AsNoTracking()
                          join u in db.Users.AsNoTracking() on m.UserId equals u.Id
                          where m.OrganizationId == org.Id
                          orderby m.CreatedAt, m.Id
                          select new { Member = m, User = u }).ToListAsync();
        var invitations = await db.Invitations.AsNoTracking().Where(i => i.OrganizationId == org.Id).OrderBy(i => i.CreatedAt).ThenBy(i => i.Id).ToListAsync();
        var settings = await OrgSettings.GetAsync(db, org.Id);
        var owner = rows.FirstOrDefault(r => r.Member.Role == Roles.Owner);
        var teams = await db.Teams.AsNoTracking().Where(t => t.OrganizationId == org.Id).OrderBy(t => t.CreatedAt).ThenBy(t => t.Id).ToListAsync();
        var teamIds = teams.Select(t => t.Id).ToList();
        var links = await db.TeamMembers.AsNoTracking().Where(tm => teamIds.Contains(tm.TeamId)).OrderBy(tm => tm.CreatedAt).ThenBy(tm => tm.Id).ToListAsync();
        var adminTeamsOf = (string memberId) => teams.Where(t => t.GrantsOrganizationAdmin && links.Any(l => l.TeamId == t.Id && l.MemberId == memberId))
            .Select(t => (object)new { id = t.Id, name = t.Name }).ToList();

        var members = rows.Select(r => (object)new Dictionary<string, object?>
        {
            ["id"] = r.Member.Id,
            ["userId"] = r.Member.UserId,
            ["inviteId"] = r.Member.InviteId,
            ["role"] = r.Member.Role,
            ["createdAt"] = Responses.IsoUtc(r.Member.CreatedAt),
            ["joinedAt"] = r.Member.JoinedAt is { } j ? Responses.IsoUtc(j) : Responses.IsoUtc(r.Member.CreatedAt),
            ["isOwner"] = r.Member.Role == Roles.Owner,
            ["user"] = new { id = r.User.Id, email = r.User.Email, name = r.User.Name, image = r.User.Image },
            ["adminTeams"] = adminTeamsOf(r.Member.Id),
            ["effectiveRole"] = EffectiveRole(r.Member.Role, adminTeamsOf(r.Member.Id).Count > 0),
        }).ToList();

        // A pending invitation is listed as a placeholder member so it can be seen, and removed, like one.
        foreach (var invitation in invitations.Where(i => i.EffectiveStatus(now) == InvitationStatus.Pending))
        {
            members.Add(new Dictionary<string, object?>
            {
                ["id"] = invitation.PlaceholderMemberId,
                ["userId"] = null,
                ["inviteId"] = invitation.Id,
                ["role"] = invitation.Role,
                ["createdAt"] = Responses.IsoUtc(invitation.CreatedAt),
                ["joinedAt"] = null,
                ["isOwner"] = false,
                ["user"] = new { id = invitation.PlaceholderMemberId, email = invitation.Email, name = invitation.Email.Split('@')[0], image = (string?)null },
                ["adminTeams"] = Array.Empty<object>(),
                ["effectiveRole"] = invitation.Role,
            });
        }

        return new
        {
            organization = new
            {
                id = org.Id,
                name = org.Name,
                slug = org.Slug,
                logo = (string?)null,
                allowedEmailDomains = OrgSettings.Domains(settings),
                metadata = OrgSettings.Metadata(settings).ToJsonString(),
                createdAt = Responses.IsoUtc(org.CreatedAt),
                updatedAt = Responses.IsoUtc(settings?.UpdatedAt ?? org.CreatedAt),
                owner = owner is null ? null : new { memberId = owner.Member.Id, userId = owner.User.Id, name = owner.User.Name, email = owner.User.Email, image = owner.User.Image },
            },
            currentMember = new
            {
                id = context.Member.Id,
                userId = context.Member.UserId,
                role = EffectiveRole(context.Member.Role, context.Permissions.AdminTeams.Count > 0),
                directRole = context.Member.Role,
                adminTeams = context.Permissions.AdminTeams.Select(t => new { id = t.Id, name = t.Name }).ToList(),
                createdAt = Responses.IsoUtc(context.Member.CreatedAt),
                joinedAt = Responses.IsoUtc(context.Member.JoinedAt ?? context.Member.CreatedAt),
                isOwner = context.IsOwner,
                permissions = context.Permissions.Keys.Order(StringComparer.Ordinal).ToList(),
            },
            members,
            invitations = invitations.Select(i => new { id = i.Id, email = i.Email, role = i.Role, status = i.EffectiveStatus(now) == InvitationStatus.Expired ? InvitationStatus.Pending : i.Status, expiresAt = Responses.IsoUtc(i.ExpiresAt), createdAt = Responses.IsoUtc(i.CreatedAt) })
                .Where(i => i.status == InvitationStatus.Pending).ToList(),
            teams = teams.Select(t => TeamBody.Summary(t, links.Where(l => l.TeamId == t.Id).Select(l => l.MemberId).ToList())).ToList(),
            currentMemberTeams = teams.Where(t => links.Any(l => l.TeamId == t.Id && l.MemberId == context.Member.Id))
                .Select(t => new { id = t.Id, name = t.Name, organizationId = t.OrganizationId, createdAt = Responses.IsoUtc(t.CreatedAt), updatedAt = Responses.IsoUtc(t.UpdatedAt) }).ToList(),
            plan = "free",
        };
    }

    /// <summary>"member,admin" for someone who is an admin only through an Admin team, so clients can tell it apart from the admin role.</summary>
    public static string EffectiveRole(string directRole, bool adminViaTeam) =>
        adminViaTeam && directRole is not (Roles.Owner or Roles.Admin) ? $"{directRole},{Roles.Admin}" : directRole;
}
