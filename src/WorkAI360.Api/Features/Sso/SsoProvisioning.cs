using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.Sso;

namespace WorkAI360.Api.Features.Sso;

public sealed record SsoIdentity(string Subject, string Email, string? Name);

public sealed record Resolution(User? User, string? ErrorCode, string? ErrorMessage)
{
    public static Resolution Found(User user) => new(user, null, null);
    public static Resolution Refused(string code, string message) => new(null, code, message);
}

/// <summary>
/// Who a successful single sign-on is, and what they may do afterwards. The rules (from the reference):
/// the provider only vouches for emails on its own verified domain; a person is recognised by the provider's stable subject, not the email;
/// a first sign-in joins an existing account by email (and if that account never proved its email, every earlier way in is removed);
/// someone SCIM deprovisioned stays out; invited people join through their invitation, everyone else joins as a plain member.
/// </summary>
public sealed class SsoProvisioning(DenDbContext db)
{
    public const string OutsideDomainMessage = "Your sign-in provider returned an email outside this organization's verified domain.";
    public const string DeprovisionedMessage = "This user was deprovisioned by SCIM. Reactivate them in the identity provider before signing in.";
    public const string UnusablePassword = "sso-only";

    /// <param name="readOnly">An administrator's connection test: recognise the person (by link or email) but change nothing, create nobody.</param>
    public async Task<Resolution> ResolveUserAsync(SsoConnection c, SsoIdentity identity, bool readOnly, CancellationToken ct)
    {
        var email = identity.Email.Trim().ToLowerInvariant();
        var domain = SsoService.EmailDomain(email);
        // Only a verified domain gives the provider the right to speak for an address.
        if (!c.DomainVerified || domain is null || !SsoService.EmailDomainMatches(domain, c.Domain))
            return Resolution.Refused("email_outside_sso_domain", OutsideDomainMessage);

        if (await IsDeprovisionedEmailAsync(c.OrganizationId, email, ct)) return Resolution.Refused("access_denied", DeprovisionedMessage);

        var link = await db.Set<ExternalAccount>().FirstOrDefaultAsync(a => a.ProviderId == c.ProviderId && a.AccountId == identity.Subject, ct);
        if (link is not null)
        {
            var linked = await db.Users.FirstOrDefaultAsync(u => u.Id == link.UserId, ct);
            if (linked is not null) return Resolution.Found(linked);
            db.Remove(link);
            await db.SaveChangesAsync(ct);
        }

        var now = DateTime.UtcNow;
        var user = await db.Users.FirstOrDefaultAsync(u => u.Email == email, ct);
        if (readOnly) return user is null ? Resolution.Refused("access_denied", "This sign-in does not belong to an existing account.") : Resolution.Found(user);
        if (user is not null)
        {
            if (!user.EmailVerified)
            {
                // Whoever registered this address first never proved it was theirs. The verified-domain identity takes it over alone.
                user.PasswordHash = UnusablePassword;
                user.EmailVerified = true;
                user.UpdatedAt = now;
                // (SCIM links are not sign-in methods: they say who the identity provider provisioned, so they stay.)
                await db.Set<ExternalAccount>().Where(a => a.UserId == user.Id && a.ProviderId != c.ProviderId && !a.ProviderId.StartsWith("openwork-scim-")).ExecuteDeleteAsync(ct);
                await db.Sessions.Where(s => s.UserId == user.Id).ExecuteDeleteAsync(ct);
            }
        }
        else
        {
            user = new User
            {
                Id = Ids.New("usr"), Email = email, Name = string.IsNullOrWhiteSpace(identity.Name) ? email.Split('@')[0] : identity.Name.Trim(),
                EmailVerified = true, PasswordHash = UnusablePassword, CreatedAt = now, UpdatedAt = now,
            };
            db.Users.Add(user);
        }
        db.Add(new ExternalAccount { Id = Ids.New("acc"), UserId = user.Id, ProviderId = c.ProviderId, AccountId = identity.Subject, CreatedAt = now });
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException)
        {
            // A parallel sign-in created the same person or link first: take what exists.
            db.ChangeTracker.Clear();
            var again = await db.Set<ExternalAccount>().FirstOrDefaultAsync(a => a.ProviderId == c.ProviderId && a.AccountId == identity.Subject, ct);
            var existing = again is null ? await db.Users.FirstOrDefaultAsync(u => u.Email == email, ct) : await db.Users.FirstOrDefaultAsync(u => u.Id == again.UserId, ct);
            if (existing is null) throw;
            if (again is null) db.Add(new ExternalAccount { Id = Ids.New("acc"), UserId = existing.Id, ProviderId = c.ProviderId, AccountId = identity.Subject, CreatedAt = now });
            try { await db.SaveChangesAsync(ct); } catch (DbUpdateException) { db.ChangeTracker.Clear(); }
            return Resolution.Found(existing);
        }
        return Resolution.Found(user);
    }

    public async Task<bool> IsDeprovisionedEmailAsync(string organizationId, string email, CancellationToken ct) =>
        await db.Set<ScimUserTombstone>().AnyAsync(t => t.OrganizationId == organizationId && t.Email == email, ct);

    /// <summary>Records the sign-in and makes sure the person belongs to the workspace. Returns an error message when they may not.</summary>
    public async Task<string?> ProvisionAsync(SsoConnection c, User user, SsoIdentity identity, string? displayName, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var email = identity.Email.Trim().ToLowerInvariant();
        var tombstoned = await db.Set<ScimUserTombstone>().AnyAsync(t => t.OrganizationId == c.OrganizationId && (t.DeprovisionedUserId == user.Id || t.Email == email), ct);
        var inactive = await db.Set<ExternalIdentity>().AnyAsync(i => i.OrganizationId == c.OrganizationId && i.UserId == user.Id && !i.Active && i.ScimProviderId != null, ct);
        if (tombstoned || inactive) return DeprovisionedMessage;

        var identityRow = await db.Set<ExternalIdentity>().FirstOrDefaultAsync(i => i.OrganizationId == c.OrganizationId && i.UserId == user.Id, ct);
        if (identityRow is null)
        {
            db.Add(new ExternalIdentity
            {
                Id = Ids.New("exi"), OrganizationId = c.OrganizationId, UserId = user.Id, Source = "sso", SsoProviderId = c.ProviderId, RemoteId = identity.Subject,
                UserName = email, Email = email, DisplayName = displayName ?? identity.Name, Active = true, LastSsoLoginAt = now,
            });
        }
        else
        {
            identityRow.Source = identityRow.ScimProviderId is null ? "sso" : "scim+sso";
            identityRow.SsoProviderId = c.ProviderId;
            identityRow.RemoteId = identity.Subject;
            identityRow.Email = email;
            identityRow.DisplayName = displayName ?? identity.Name ?? identityRow.DisplayName;
            identityRow.Active = true;
            identityRow.LastSsoLoginAt = now;
        }

        if (!await db.Members.AnyAsync(m => m.OrganizationId == c.OrganizationId && m.UserId == user.Id, ct))
        {
            var invitation = await db.Invitations.FirstOrDefaultAsync(i => i.OrganizationId == c.OrganizationId && i.Email == email && i.Status == InvitationStatus.Pending && i.ExpiresAt > now, ct);
            if (invitation is not null)
            {
                invitation.Status = InvitationStatus.Accepted;
                invitation.AcceptedAt = now;
                invitation.AcceptedByUserId = user.Id;
            }
            db.Members.Add(new Member
            {
                Id = Ids.New("om"), OrganizationId = c.OrganizationId, UserId = user.Id, Role = invitation?.Role ?? Roles.Member, CreatedAt = now, JoinedAt = now, InviteId = invitation?.Id,
            });
        }
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException) { db.ChangeTracker.Clear(); }
        return null;
    }
}
