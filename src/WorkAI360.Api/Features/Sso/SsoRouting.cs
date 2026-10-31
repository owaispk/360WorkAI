using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Sso;

namespace WorkAI360.Api.Features.Sso;

public sealed record SsoRequirement(string OrganizationId, string OrganizationSlug, string SignInPath);

/// <summary>Decides who must sign in through their workspace's SSO. Only connections that are enabled AND have a verified domain count.</summary>
public sealed class SsoRouting(DenDbContext db)
{
    /// <summary>The workspace whose verified, enabled SSO claims the email's domain (what the sign-in form asks before showing a password).</summary>
    public async Task<SsoRequirement?> ForEmailDomainAsync(string email)
    {
        var domain = SsoService.EmailDomain(email);
        if (domain is null || !domain.Contains('.')) return null;
        var rows = await (from c in db.Set<SsoConnection>()
                          join o in db.Organizations on c.OrganizationId equals o.Id
                          where c.Status == "enabled" && c.DomainVerified
                          orderby c.CreatedAt
                          select new { c.Domain, c.SignInPath, OrgId = o.Id, o.Slug }).ToListAsync();
        var hit = rows.FirstOrDefault(r => SsoService.Domains(r.Domain).Contains(domain));
        return hit is null ? null : new SsoRequirement(hit.OrgId, hit.Slug, hit.SignInPath);
    }

    /// <summary>An existing account that belongs to a workspace with enforced SSO: its password and email sign-in are closed.</summary>
    public async Task<SsoRequirement?> ForExistingUserAsync(string email)
    {
        var normalized = email.Trim().ToLowerInvariant();
        var hit = await (from u in db.Users
                         where u.Email == normalized
                         join m in db.Members on u.Id equals m.UserId
                         join c in db.Set<SsoConnection>() on m.OrganizationId equals c.OrganizationId
                         join o in db.Organizations on c.OrganizationId equals o.Id
                         where c.Status == "enabled" && c.DomainVerified
                         orderby c.CreatedAt
                         select new { c.SignInPath, OrgId = o.Id, o.Slug }).FirstOrDefaultAsync();
        return hit is null ? null : new SsoRequirement(hit.OrgId, hit.Slug, hit.SignInPath);
    }
}
