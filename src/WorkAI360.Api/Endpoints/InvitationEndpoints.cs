using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Email;
using WorkAI360.Api.Features.OrgAdmin;
using WorkAI360.Api.Features.Scim;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Endpoints;

/// <summary>Inviting people into a workspace: create or resend, cancel, copy the link, preview and accept.</summary>
public static class InvitationEndpoints
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromDays(7);

    private static IResult InvalidTeam() => Results.Json(new { error = "invalid_request", message = "Choose a team in this organization that is not managed by your identity provider." }, statusCode: 400);

    public static string LinkFor(OAuthUrls urls, Invitation invitation) => $"{urls.Web}/join-org?invite={invitation.InviteToken}";

    public static void MapInvitationEndpoints(this WebApplication app)
    {
        app.MapPost("/v1/invitations", async (HttpContext ctx, OrgAccess access, DenDbContext db, IEmailSender sender, OAuthUrls urls, ILoggerFactory logs, TeamRules rules, IAuditLog audit) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "invitations.manage") is { } denied) return denied;

            string? email = null, roleValue = null, teamValue = null;
            var teamPresent = false;
            try
            {
                using var doc = await JsonDocument.ParseAsync(ctx.Request.Body);
                if (doc.RootElement.ValueKind == JsonValueKind.Object)
                {
                    if (doc.RootElement.TryGetProperty("email", out var e) && e.ValueKind == JsonValueKind.String) email = e.GetString();
                    if (doc.RootElement.TryGetProperty("role", out var r) && r.ValueKind == JsonValueKind.String) roleValue = r.GetString();
                    if (doc.RootElement.TryGetProperty("teamId", out var t) && t.ValueKind is JsonValueKind.String or JsonValueKind.Null) { teamPresent = true; teamValue = t.ValueKind == JsonValueKind.String ? t.GetString() : null; }
                    else if (doc.RootElement.TryGetProperty("teamId", out var bad)) return MemberEndpoints.InvalidRequest("teamId", $"Invalid input: expected string, received {Features.Library.Zod.Kind(bad)}");
                }
            }
            catch (JsonException) { }
            if (email is null) return MemberEndpoints.InvalidRequest("email", "Invalid input: expected string, received undefined");
            if (!AuthEndpoints.IsValidEmail(email)) return MemberEndpoints.InvalidRequest("email", "Invalid email address", "invalid_format");
            if (roleValue is null) return MemberEndpoints.InvalidRequest("role", "Invalid input: expected string, received undefined");
            if (teamValue is not null && MemberEndpoints.ValidateTypeId(teamValue, "tem", "teamId") is { } malformed) return malformed;

            var (role, ownerRequested, invalid) = Roles.ForInvitation(roleValue);
            if (ownerRequested) return Results.Json(new { error = "forbidden", message = "Owner can only be assigned by the Den ownership transfer API." }, statusCode: 403);
            if (invalid) return Results.Json(new { error = "invalid_role", message = "Choose Member or Admin." }, statusCode: 400);
            // Making someone an admin is a role change, so it needs the permission to change roles.
            if (role == Roles.Admin && access.Require(context!, "members.update") is { } adminDenied) return adminDenied;
            if (role == Roles.Admin && await rules.AdminRoleGrantDenialAsync(context!) is { } cannotGrant) return cannotGrant;

            var normalized = AuthEndpoints.NormalizeEmail(email);
            var org = context!.Organization;
            var alreadyMember = await (from m in db.Members join u in db.Users on m.UserId equals u.Id where m.OrganizationId == org.Id && u.Email == normalized select m.Id).AnyAsync();
            if (alreadyMember) return Results.Json(new { error = "member_exists", message = "That email address is already a member of this organization." }, statusCode: 409);
            // A workspace limited to some email domains only invites those.
            if (OrgSettings.Domains(await OrgSettings.GetAsync(db, org.Id)) is { Length: > 0 } allowed && !OrgSettings.IsAllowed(allowed, normalized))
                return Results.Json(OrgSettings.Restriction("invite_email_domain_not_allowed", allowed, normalized), statusCode: 409);

            var now = DateTime.UtcNow;
            var invitation = await db.Invitations.FirstOrDefaultAsync(i => i.OrganizationId == org.Id && i.Email == normalized && i.Status == InvitationStatus.Pending && i.ExpiresAt > now);
            var refreshed = invitation is not null;

            // The team the person joins: omitted keeps a pending invitation's team, null clears it. Choosing one needs "Manage teams" and every
            // permission the team grants; a team that is not this workspace's (or is run by the identity provider) reads as not allowed.
            if (invitation?.TeamId is { } currentTeam && await db.Teams.AsNoTracking().AnyAsync(t => t.Id == currentTeam && t.GrantsOrganizationAdmin)
                && access.Require(context!, "teams.manage_admin") is { } adminTeamDenied) return adminTeamDenied;
            var teamId = teamPresent ? teamValue : invitation?.TeamId;
            if (teamPresent && invitation?.TeamId is { } oldTeam && oldTeam != teamId && await ScimTeams.IsManagedAsync(db, org.Id, oldTeam)) return InvalidTeam();
            if (teamId is not null || (invitation?.TeamId is not null && teamPresent))
            {
                if (access.Require(context!, "teams.manage") is { } teamsDenied) return teamsDenied;
                if (teamId is not null)
                {
                    var team = await db.Teams.AsNoTracking().FirstOrDefaultAsync(t => t.Id == teamId && t.OrganizationId == org.Id);
                    if (team is null || await ScimTeams.IsManagedAsync(db, org.Id, team.Id)) return InvalidTeam();
                    if (team.GrantsOrganizationAdmin && access.Require(context!, "teams.manage_admin") is { } manageAdmin) return manageAdmin;
                    if (await rules.GrantDenialAsync(context!, team.Id, team.GrantsOrganizationAdmin, false, TeamRules.TeamGrantsForbidden) is { } teamGrantDenied) return teamGrantDenied;
                }
            }
            var previousTeam = invitation?.TeamId;
            if (invitation is null)
            {
                invitation = new Invitation
                {
                    Id = Ids.New("inv"),
                    OrganizationId = org.Id,
                    Email = normalized,
                    Role = role!,
                    Status = InvitationStatus.Pending,
                    InviteToken = Ids.RandomAlnum(21),
                    InvitedByUserId = context.Auth.User.Id,
                    PlaceholderMemberId = Ids.New("om"),
                    TeamId = teamId,
                    CreatedAt = now,
                    ExpiresAt = now + Lifetime,
                };
                db.Invitations.Add(invitation);
            }
            else
            {
                // Inviting again resends: same link, a fresh week, and the latest role.
                invitation.Role = role!;
                invitation.ExpiresAt = now + Lifetime;
                invitation.TeamId = teamId;
            }
            // The pending person shows in the team at once (as the reference does); accepting keeps the same member.
            if (previousTeam is not null && previousTeam != teamId)
                await db.TeamMembers.Where(tm => tm.TeamId == previousTeam && tm.MemberId == invitation.PlaceholderMemberId).ExecuteDeleteAsync();
            if (teamId is not null && !await db.TeamMembers.AnyAsync(tm => tm.TeamId == teamId && tm.MemberId == invitation.PlaceholderMemberId))
                db.TeamMembers.Add(new TeamMember { Id = Ids.New("tmm"), TeamId = teamId, MemberId = invitation.PlaceholderMemberId, CreatedAt = now });
            await db.SaveChangesAsync();
            await audit.RecordAsync(context, new AuditEntry(refreshed ? AuditActions.InvitationRefreshed : AuditActions.InvitationCreated,
                [new("invitation", invitation.Id, "target", invitation.Email), new("organization", org.Id, "parent")],
                After: new() { ["email"] = invitation.Email, ["role"] = invitation.Role, ["status"] = invitation.Status }));

            try
            {
                await sender.SendAsync(InvitationEmail.Create(normalized, LinkFor(urls, invitation), context.Auth.User.Name, context.Auth.User.Email, org.Name, invitation.Role));
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                logs.CreateLogger("Invitations").LogError(e, "Could not send an invitation email");
                // The invitation is saved: the admin can copy the link or retry.
                return Results.Json(new { error = "invitation_email_failed", reason = "nodemailer_rejected", message = "The invitation email could not be sent. The invitation is saved; retry to send again, or copy its link.", invitationId = invitation.Id }, statusCode: 502);
            }

            return Results.Json(new { invitationId = invitation.Id, email = invitation.Email, role = invitation.Role, expiresAt = Responses.IsoUtc(invitation.ExpiresAt), inviteToken = invitation.InviteToken },
                statusCode: refreshed ? 200 : 201);
        });

        app.MapGet("/v1/invitations/{invitationId}/link", async (string invitationId, HttpContext ctx, OrgAccess access, DenDbContext db, OAuthUrls urls) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "invitations.manage") is { } denied) return denied;
            if (MemberEndpoints.ValidateTypeId(invitationId, "inv", "invitationId") is not null) return Results.Json(new { error = "invitation_not_found" }, statusCode: 404);

            var invitation = await db.Invitations.AsNoTracking().FirstOrDefaultAsync(i => i.Id == invitationId && i.OrganizationId == context!.Organization.Id);
            if (invitation is null) return Results.Json(new { error = "invitation_not_found" }, statusCode: 404);
            if (invitation.Role == Roles.Admin && access.Require(context!, "members.update") is { } adminDenied) return adminDenied;

            var status = invitation.EffectiveStatus(DateTime.UtcNow);
            if (status != InvitationStatus.Pending)
                return Results.Json(new { error = "invitation_not_pending", message = "This invitation can no longer be used. Resend it to create a new link.", status }, statusCode: 409);
            return Results.Json(new { invitationId = invitation.Id, inviteLink = LinkFor(urls, invitation), expiresAt = Responses.IsoUtc(invitation.ExpiresAt) });
        });

        app.MapPost("/v1/invitations/{invitationId}/cancel", async (string invitationId, HttpContext ctx, OrgAccess access, DenDbContext db, IAuditLog audit) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "invitations.manage") is { } denied) return denied;
            if (MemberEndpoints.ValidateTypeId(invitationId, "inv", "invitationId") is not null) return Results.Json(new { error = "invitation_not_found" }, statusCode: 404);

            var invitation = await db.Invitations.FirstOrDefaultAsync(i => i.Id == invitationId && i.OrganizationId == context!.Organization.Id);
            if (invitation is null) return Results.Json(new { error = "invitation_not_found" }, statusCode: 404);
            // An expired invitation can still be cleaned up; one that was used or already canceled cannot.
            if (invitation.Status != InvitationStatus.Pending)
                return Results.Json(new { error = "invitation_not_pending", message = "Only pending invitations can be canceled.", status = invitation.Status }, statusCode: 409);
            invitation.Status = InvitationStatus.Canceled;
            await db.TeamMembers.Where(tm => tm.MemberId == invitation.PlaceholderMemberId).ExecuteDeleteAsync();
            await db.SaveChangesAsync();
            await audit.RecordAsync(context!, new AuditEntry(AuditActions.InvitationCanceled, [new("invitation", invitation.Id, "target", invitation.Email), new("organization", context!.Organization.Id, "parent")],
                Before: new() { ["status"] = InvitationStatus.Pending }, After: new() { ["status"] = InvitationStatus.Canceled }));
            return Results.Json(new { success = true });
        });

        // Public: the join page shows what the person is being invited to before they sign in. The id or the emailed token both find it.
        app.MapGet("/v1/orgs/invitations/preview", async (string? id, DenDbContext db) =>
        {
            if (string.IsNullOrEmpty(id)) return MemberEndpoints.InvalidRequest("id", "Invalid input: expected string, received undefined");
            var invitation = await db.Invitations.AsNoTracking().FirstOrDefaultAsync(i => i.Id == id || i.InviteToken == id);
            if (invitation is null) return Results.Json(new { error = "invitation_not_found" }, statusCode: 404);
            var org = await db.Organizations.AsNoTracking().FirstAsync(o => o.Id == invitation.OrganizationId);
            var settings = await OrgSettings.GetAsync(db, org.Id);
            var brand = OrgSettings.Metadata(settings);
            return Results.Json(new
            {
                invitation = new { id = invitation.Id, email = invitation.Email, role = invitation.Role, status = invitation.EffectiveStatus(DateTime.UtcNow), expiresAt = Responses.IsoUtc(invitation.ExpiresAt), createdAt = Responses.IsoUtc(invitation.CreatedAt) },
                organization = new { id = org.Id, name = org.Name, slug = org.Slug, allowedEmailDomains = OrgSettings.Domains(settings), branding = new { appName = (string?)brand["brandAppName"]?.GetValue<string>() ?? "OpenWork", logoUrl = (string?)brand["brandLogoUrl"]?.GetValue<string>(), iconUrl = (string?)brand["brandIconUrl"]?.GetValue<string>() } },
            });
        });

        app.MapPost("/v1/orgs/invitations/accept", async (HttpContext ctx, SessionService sessions, DenDbContext db, IAuditLog audit) =>
        {
            var current = await sessions.ResolveAsync(ctx);
            if (current is null) return Responses.Unauthorized();

            string? id = null;
            try
            {
                using var doc = await JsonDocument.ParseAsync(ctx.Request.Body);
                if (doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty("id", out var v) && v.ValueKind == JsonValueKind.String) id = v.GetString();
            }
            catch (JsonException) { }
            if (string.IsNullOrEmpty(id)) return MemberEndpoints.InvalidRequest("id", "Invalid input: expected string, received undefined");

            var now = DateTime.UtcNow;
            var invitation = await db.Invitations.FirstOrDefaultAsync(i => i.Id == id || i.InviteToken == id);
            // Only the invited address can accept; for everyone else the invitation does not exist.
            if (invitation is null || !string.Equals(invitation.Email, current.User.Email, StringComparison.OrdinalIgnoreCase)) return Results.Json(new { error = "invitation_not_found" }, statusCode: 404);
            var org = await db.Organizations.FirstAsync(o => o.Id == invitation.OrganizationId);

            var alreadyMember = await db.Members.AnyAsync(m => m.OrganizationId == org.Id && m.UserId == current.User.Id);
            // The domain limit is checked again here: it may have been set after the invitation was sent.
            if (!alreadyMember && OrgSettings.Domains(await OrgSettings.GetAsync(db, org.Id)) is { Length: > 0 } allowed && !OrgSettings.IsAllowed(allowed, current.User.Email))
                return Results.Json(OrgSettings.Restriction("account_email_domain_not_allowed", allowed, current.User.Email), statusCode: 409);
            string? joinedMemberId = null;
            // Accepting twice is harmless; accepting something canceled, expired or used by someone else is not possible.
            if (invitation.Status == InvitationStatus.Accepted) { if (!alreadyMember) return Results.Json(new { error = "invitation_not_found" }, statusCode: 404); }
            else if (invitation.EffectiveStatus(now) != InvitationStatus.Pending) return Results.Json(new { error = "invitation_not_found" }, statusCode: 404);
            else
            {
                await using var tx = await db.Database.BeginTransactionAsync();
                // Exactly one caller can flip the status from pending.
                var claimed = await db.Invitations.Where(i => i.Id == invitation.Id && i.Status == InvitationStatus.Pending && i.ExpiresAt > now)
                    .ExecuteUpdateAsync(s => s.SetProperty(i => i.Status, InvitationStatus.Accepted).SetProperty(i => i.AcceptedAt, now).SetProperty(i => i.AcceptedByUserId, current.User.Id));
                if (claimed == 0)
                {
                    // Someone else got there first. If that was this same person (a double click, a retry), the outcome is the same: they are in.
                    var winner = await db.Invitations.AsNoTracking().FirstAsync(i => i.Id == invitation.Id);
                    var theyAreIn = winner.Status == InvitationStatus.Accepted && winner.AcceptedByUserId == current.User.Id;
                    if (!theyAreIn) return Results.Json(new { error = "invitation_not_found" }, statusCode: 404);
                }
                else
                {
                    if (!alreadyMember)
                        db.Members.Add(new Member { Id = joinedMemberId = invitation.PlaceholderMemberId, OrganizationId = org.Id, UserId = current.User.Id, Role = invitation.Role, CreatedAt = now, JoinedAt = now, InviteId = invitation.Id });
                    await db.SaveChangesAsync();
                    await tx.CommitAsync();
                }
            }

            if (joinedMemberId is not null)
                await audit.RecordAsync(org.Id, AuditActor.User(current.User.Id, joinedMemberId), new AuditEntry(AuditActions.InvitationAccepted,
                    [new("invitation", invitation.Id, "target", invitation.Email), new("member", joinedMemberId, "related"), new("organization", org.Id, "parent")],
                    After: new() { ["status"] = InvitationStatus.Accepted, ["role"] = invitation.Role }));
            if (current.Session.ActiveOrganizationId is null) await OrgEndpoints.SetActiveAsync(db, current.Session, org.Id);
            return Results.Json(new { accepted = true, organizationId = org.Id, organizationSlug = org.Slug, invitationId = invitation.Id });
        });
    }
}
