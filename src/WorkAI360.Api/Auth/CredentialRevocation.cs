using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Data;

namespace WorkAI360.Api.Auth;

/// <summary>
/// Takes back everything a person could use after losing access to a workspace. Web sessions belong to the person, not to a
/// workspace, so all of them end (a live session could otherwise re-select the workspace and mint new tokens); the person
/// signs in again and sees only what they still belong to. Their agent access to this workspace ends too.
/// </summary>
public sealed class CredentialRevocation(DenDbContext db)
{
    public async Task RevokeAsync(string userId, string organizationId)
    {
        await db.Sessions.Where(s => s.UserId == userId).ExecuteDeleteAsync();
        await db.RefreshTokens.Where(t => t.UserId == userId && t.OrganizationId == organizationId).ExecuteDeleteAsync();
        await db.OAuthConsents.Where(c => c.UserId == userId && c.OrganizationId == organizationId).ExecuteDeleteAsync();
        await db.McpAccessTokens.Where(t => t.UserId == userId && t.OrganizationId == organizationId).ExecuteDeleteAsync();
        await db.AuthorizationCodes.Where(c => c.UserId == userId && c.OrganizationId == organizationId).ExecuteDeleteAsync();
        await db.DeviceCodes.Where(d => d.UserId == userId && d.OrganizationId == organizationId && d.Status == Domain.DeviceStatus.Approved).ExecuteDeleteAsync();
        await db.HandoffGrants.Where(g => g.UserId == userId && g.OrganizationId == organizationId && g.ConsumedAt == null).ExecuteDeleteAsync();
        // Access tokens already issued (JWTs) cannot be recalled, but every MCP call re-checks membership, so they stop working at once.
    }
}
