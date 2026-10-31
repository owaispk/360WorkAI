using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Sso;

namespace WorkAI360.Api.Features.Scim;

/// <summary>Which teams belong to an identity provider.</summary>
public static class ScimTeams
{
    /// <summary>True when the team is the projection of a SCIM group and the workspace maps groups to teams.</summary>
    public static Task<bool> IsManagedAsync(DenDbContext db, string organizationId, string teamId) =>
        (from g in db.Set<ScimGroup>()
         join p in db.Set<ScimProvider>() on g.ProviderId equals p.ProviderId
         where g.OrganizationId == organizationId && g.TeamId == teamId && p.GroupMappingMode == ScimService.CreateTeams
         select g.Id).AnyAsync();
}
