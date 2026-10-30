using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;

namespace WorkAI360.Api.Endpoints;

/// <summary>
/// Changing roles, transferring ownership and removing people. Only the owner can change roles or hand over ownership; admins can invite
/// and remove members. The owner can never be removed or demoted. Losing access ends the person's sessions and their agents' access.
/// </summary>
public static partial class MemberEndpoints
{
    private const string NotFoundMessage = "The organization member could not be found.";

    [GeneratedRegex("^om_[0-7][0-9a-hjkmnp-tv-z]{25}$")]
    private static partial Regex MemberIdPattern();

    /// <summary>Malformed ids are a validation error (400), the way the reference answers; well-formed unknown ids are 404.</summary>
    private const string Base32 = "0123456789abcdefghjkmnpqrstvwxyz";

    /// <summary>
    /// A TypeID path parameter. Malformed ids are a validation error that lists every problem, as the reference's validator does
    /// (size, prefix, base32 alphabet, overall structure); a well-formed id that names nothing is a 404 further on.
    /// </summary>
    public static IResult? ValidateTypeId(string value, string prefix, string field)
    {
        var size = prefix.Length + 27;
        var issues = new List<(string Code, string Message)>();
        if (value.Length < size) issues.Add(("too_small", $"TypeID must be {size} characters ({prefix}_<26 char suffix>)"));
        else if (value.Length > size) issues.Add(("too_big", $"TypeID must be {size} characters ({prefix}_<26 char suffix>)"));
        if (!value.StartsWith(prefix + "_")) issues.Add(("custom", $"TypeID must start with '{prefix}_'"));
        var suffix = value[(value.LastIndexOf('_') + 1)..];
        if (suffix.Any(c => !Base32.Contains(c))) issues.Add(("custom", "TypeID suffix contains invalid base32 characters"));
        if (!Regex.IsMatch(value, @"^([a-z]([a-z_]*[a-z])?_)?[0-7][0-9a-hjkmnp-tv-z]{25}$")) issues.Add(("custom", "TypeID is structurally invalid"));
        if (issues.Count == 0) return null;
        var message = $"{field}: {issues[0].Message}{(issues.Count > 1 ? $" (and {issues.Count - 1} more)" : "")}";
        return Results.Json(new { error = "invalid_request", message, details = issues.Select(i => new { i.Code, path = new[] { field }, message = i.Message }) }, statusCode: 400);
    }

    public static IResult InvalidRequest(string field, string message, string code = "invalid_type") =>
        Results.Json(new { error = "invalid_request", message = $"{field}: {message}", details = new[] { new { code, path = new[] { field }, message } } }, statusCode: 400);

    public static void MapMemberEndpoints(this WebApplication app)
    {
        app.MapPost("/v1/members/{memberId}/role", async (string memberId, HttpContext ctx, OrgAccess access, DenDbContext db, CredentialRevocation revocation, TeamRules rules) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "members.update") is { } denied) return denied;
            if (ValidateTypeId(memberId, "om", "memberId") is { } malformed) return malformed;

            string? role = null;
            try
            {
                using var doc = await JsonDocument.ParseAsync(ctx.Request.Body);
                if (doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty("role", out var r) && r.ValueKind == JsonValueKind.String) role = r.GetString();
            }
            catch (JsonException) { }
            if (role is null) return InvalidRequest("role", "Invalid input: expected string, received undefined");
            if (role.Trim().Length is 0 or > 64) return InvalidRequest("role", "Invalid string: must contain between 1 and 64 character(s)", "too_small");

            var next = Roles.Normalize(role);
            if (!Roles.IsAssignable(next)) return Results.Json(new { error = "invalid_role", message = "Choose one of the existing organization roles." }, statusCode: 400);

            await using var tx = await db.Database.BeginTransactionAsync();
            var members = await db.Members.Where(m => m.OrganizationId == context!.Organization.Id).ToListAsync();
            var target = members.FirstOrDefault(m => m.Id == memberId);
            if (target is null) return Results.Json(new { error = "member_not_found", message = NotFoundMessage }, statusCode: 404);

            // The rules that protect the owner and the workspace's ability to be administered.
            if (target.Role == Roles.Owner) return Results.Json(new { error = "owner_role_locked", message = "The organization owner role cannot be changed." }, statusCode: 400);
            if (Roles.IsPrivileged(target.Role) && !Roles.IsPrivileged(next) && !members.Any(m => m.Id != target.Id && Roles.IsPrivileged(m.Role)))
                return Results.Json(new { error = "last_privileged_member", message = "Add another workspace owner or admin before changing this member's role." }, statusCode: 400);

            // Nobody changes their own role. Making an admin needs an admin who holds everything admins hold, and so does demoting one.
            if (target.Id == context!.Member.Id && !context.IsOwner) return access.Forbidden(TeamRules.OwnRoleChange);
            if (next == Roles.Admin && target.Role != Roles.Admin && await rules.AdminRoleGrantDenialAsync(context) is { } cannotGrant) return cannotGrant;
            if (next != Roles.Admin && target.Role == Roles.Admin && !context.IsOwner && !context.IsAdmin) return access.Forbidden(TeamRules.AdminRoleChangeRequiresAdmin);

            if (target.Role == next) return Results.Json(new { success = true });
            var previous = target.Role;
            target.Role = next;
            await db.SaveChangesAsync();
            await tx.CommitAsync();

            // Losing access must not leave a live session or agent token behind. A promotion takes nothing away.
            if (Roles.RevokesCredentials(previous, next)) await revocation.RevokeAsync(target.UserId, context.Organization.Id);
            return Results.Json(new { success = true });
        });

        app.MapPost("/v1/members/{memberId}/transfer-ownership", async (string memberId, HttpContext ctx, OrgAccess access, DenDbContext db, CredentialRevocation revocation) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.RequireOwner(context!) is { } denied) return denied;
            if (ValidateTypeId(memberId, "om", "memberId") is { } malformed) return malformed;

            if (memberId == context!.Member.Id)
                return Results.Json(new { error = "owner_transfer_invalid", message = "Choose a different active member to become workspace owner." }, statusCode: 400);

            await using var tx = await db.Database.BeginTransactionAsync();
            var target = await db.Members.FirstOrDefaultAsync(m => m.Id == memberId && m.OrganizationId == context.Organization.Id);
            if (target is null) return Results.Json(new { error = "target_member_not_found", message = "Choose an active member to become workspace owner." }, statusCode: 404);
            if (target.Role == Roles.Owner) return Results.Json(new { error = "owner_transfer_invalid", message = "This member is already a workspace owner." }, statusCode: 400);
            // Ownership goes to someone already trusted with administration, never straight to a plain member.
            if (target.Role != Roles.Admin) return Results.Json(new { error = "owner_transfer_invalid", message = "Choose an active workspace admin to become owner." }, statusCode: 400);

            // Two conditional updates, so the decision is made on the rows as they are at commit, not as they were read: a second transfer
            // racing this one finds the caller no longer owner (or the target no longer admin) and changes nothing.
            var demoted = await db.Members.Where(m => m.Id == context.Member.Id && m.Role == Roles.Owner).ExecuteUpdateAsync(s => s.SetProperty(m => m.Role, Roles.Admin));
            if (demoted == 0) return Results.Json(new { error = "forbidden", code = "requires_admin", message = "Only the workspace owner can do this.", retryable = false }, statusCode: 403);
            var promoted = await db.Members.Where(m => m.Id == target.Id && m.Role == Roles.Admin).ExecuteUpdateAsync(s => s.SetProperty(m => m.Role, Roles.Owner));
            if (promoted == 0) return Results.Json(new { error = "owner_transfer_invalid", message = "Choose an active workspace admin to become owner." }, statusCode: 400); // the transaction rolls back
            await tx.CommitAsync();

            var previousOwner = context.Member;
            // Both people's standing just changed, so both sign in again (the reference ends the new owner's sessions too).
            await revocation.RevokeAsync(previousOwner.UserId, context.Organization.Id);
            await revocation.RevokeAsync(target.UserId, context.Organization.Id);
            return Results.Json(new { success = true });
        });

        app.MapDelete("/v1/members/{memberId}", async (string memberId, HttpContext ctx, OrgAccess access, DenDbContext db, CredentialRevocation revocation) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "members.delete") is { } denied) return denied;
            if (ValidateTypeId(memberId, "om", "memberId") is { } malformed) return malformed;

            // A pending person is a placeholder for an invitation: removing it withdraws the invitation.
            var invitation = await db.Invitations.FirstOrDefaultAsync(i => i.PlaceholderMemberId == memberId && i.OrganizationId == context!.Organization.Id && i.Status == InvitationStatus.Pending);
            if (invitation is not null)
            {
                invitation.Status = InvitationStatus.Canceled;
                await db.SaveChangesAsync();
                return Results.NoContent();
            }

            await using var tx = await db.Database.BeginTransactionAsync();
            var target = await db.Members.FirstOrDefaultAsync(m => m.Id == memberId && m.OrganizationId == context!.Organization.Id);
            if (target is null) return Results.Json(new { error = "member_not_found", message = NotFoundMessage }, statusCode: 404);
            if (target.Role == Roles.Owner) return Results.Json(new { error = "owner_role_locked", message = "The organization owner cannot be removed." }, statusCode: 400);
            // Admins (by role, or through an Admin team) can only be removed by the owner or another admin, even by someone holding members.delete.
            var adminViaTeam = await (from tm in db.TeamMembers join t in db.Teams on tm.TeamId equals t.Id where tm.MemberId == target.Id && t.GrantsOrganizationAdmin select tm.Id).AnyAsync();
            if ((target.Role == Roles.Admin || adminViaTeam) && !context!.IsOwner && !context.IsAdmin)
                return Results.Json(new { error = "forbidden", message = "Only the owner or an admin can remove an admin from the organization." }, statusCode: 403);

            db.TeamMembers.RemoveRange(await db.TeamMembers.Where(tm => tm.MemberId == target.Id).ToListAsync());
            db.Members.Remove(target);
            await db.SaveChangesAsync();
            await tx.CommitAsync();

            await revocation.RevokeAsync(target.UserId, context!.Organization.Id);
            return Results.NoContent();
        });
    }
}
