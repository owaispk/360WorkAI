using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Data;

namespace WorkAI360.Api.Auth;

/// <summary>
/// Takes back everything a person could use after losing access to a workspace. Web sessions belong to the person, not to a
/// workspace, so all of them end (a live session could otherwise re-select the workspace and mint new tokens); the person
/// signs in again and sees only what they still belong to. Their agent access to this workspace ends too.
/// </summary>
public sealed class CredentialRevocation(DenDbContext db, Features.OrgAdmin.IAuditLog audit)
{
    public async Task RevokeAsync(string userId, string organizationId, OrgContext? actor = null)
    {
        await db.Sessions.Where(s => s.UserId == userId).ExecuteDeleteAsync();
        // Organization API keys act as the member who made them: turn this person's keys for the workspace off (they stay listed, as disabled, like the reference).
        var now = DateTime.UtcNow;
        var keys = await db.Set<Domain.OrgAdmin.ApiKey>().AsNoTracking().Where(k => k.UserId == userId && k.OrganizationId == organizationId && k.Enabled).ToListAsync();
        await db.Set<Domain.OrgAdmin.ApiKey>().Where(k => k.UserId == userId && k.OrganizationId == organizationId && k.Enabled)
            .ExecuteUpdateAsync(s => s.SetProperty(k => k.Enabled, false).SetProperty(k => k.UpdatedAt, now));
        foreach (var key in keys)
        {
            var entry = new Features.OrgAdmin.AuditEntry(Features.OrgAdmin.AuditActions.ApiKeyRevoked,
                [new("api_key", key.Id, "target", key.Name), new("member", key.MemberId, "parent")],
                Before: new() { ["enabled"] = true }, After: new() { ["enabled"] = false }, ReasonCode: "member_access_changed");
            if (actor is not null) await audit.RecordAsync(actor, entry);
            else await audit.RecordAsync(organizationId, Features.OrgAdmin.AuditActor.System, entry);
        }
        await db.RefreshTokens.Where(t => t.UserId == userId && t.OrganizationId == organizationId).ExecuteDeleteAsync();
        await db.OAuthConsents.Where(c => c.UserId == userId && c.OrganizationId == organizationId).ExecuteDeleteAsync();
        await db.McpAccessTokens.Where(t => t.UserId == userId && t.OrganizationId == organizationId).ExecuteDeleteAsync();
        await db.AuthorizationCodes.Where(c => c.UserId == userId && c.OrganizationId == organizationId).ExecuteDeleteAsync();
        await db.DeviceCodes.Where(d => d.UserId == userId && d.OrganizationId == organizationId && d.Status == Domain.DeviceStatus.Approved).ExecuteDeleteAsync();
        await db.HandoffGrants.Where(g => g.UserId == userId && g.OrganizationId == organizationId && g.ConsumedAt == null).ExecuteDeleteAsync();
        // Access tokens already issued (JWTs) cannot be recalled, but every MCP call re-checks membership, so they stop working at once.
    }
}
