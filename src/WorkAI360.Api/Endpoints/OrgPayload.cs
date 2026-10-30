using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;

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
        var owner = rows.FirstOrDefault(r => r.Member.Role == Roles.Owner);

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
            ["adminTeams"] = Array.Empty<object>(),
            ["effectiveRole"] = r.Member.Role,
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
                allowedEmailDomains = (string[]?)null,
                metadata = "{}",
                createdAt = Responses.IsoUtc(org.CreatedAt),
                updatedAt = Responses.IsoUtc(org.CreatedAt),
                owner = owner is null ? null : new { memberId = owner.Member.Id, userId = owner.User.Id, name = owner.User.Name, email = owner.User.Email, image = owner.User.Image },
            },
            currentMember = new
            {
                id = context.Member.Id,
                userId = context.Member.UserId,
                role = context.Member.Role,
                directRole = context.Member.Role,
                adminTeams = Array.Empty<object>(),
                createdAt = Responses.IsoUtc(context.Member.CreatedAt),
                joinedAt = Responses.IsoUtc(context.Member.JoinedAt ?? context.Member.CreatedAt),
                isOwner = context.IsOwner,
                permissions = Permissions.For(context.Member.Role),
            },
            members,
            invitations = invitations.Select(i => new { id = i.Id, email = i.Email, role = i.Role, status = i.EffectiveStatus(now) == InvitationStatus.Expired ? InvitationStatus.Pending : i.Status, expiresAt = Responses.IsoUtc(i.ExpiresAt), createdAt = Responses.IsoUtc(i.CreatedAt) })
                .Where(i => i.status == InvitationStatus.Pending).ToList(),
            teams = Array.Empty<object>(),
            plan = "free",
        };
    }
}
