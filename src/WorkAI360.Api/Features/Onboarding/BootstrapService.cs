using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.Library;
using WorkAI360.Api.Domain.Onboarding;
using WorkAI360.Api.Endpoints;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Onboarding;

/// <summary>
/// "Provision now, claim later": an agent builds a workspace before any person has an account, then hands over a link or a short code. The person
/// who claims it becomes its owner, and the agent's temporary identity (a sign-in-less setup member) is removed in the same step.
/// </summary>
public sealed class BootstrapService(DenDbContext db, IOptions<AuthOptions> auth, IOptions<OnboardingOptions> options, OAuthUrls urls, PermissionService permissions)
{
    public const string AssertionType = "openwork-preclaim+jwt";
    public const string AgentEmailDomain = "agents.openwork.invalid";
    public const string StarterOutput = "OPENWORK_BOOTSTRAP_SKILL_TRIGGERED";
    private const string CodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    private byte[] AssertionKey() => HMACSHA256.HashData(Encoding.UTF8.GetBytes(auth.Value.Secret), Encoding.UTF8.GetBytes("workai360:preclaim-assertion:v1"));

    public static string NormalizeCode(string code) => code.Replace(" ", "").Replace("-", "").ToUpperInvariant();
    public static string HashCode(string code) => Ids.Sha256Hex(NormalizeCode(code));

    // ---- the assertion: a signed token that names one provisional workspace ----------------------------------------------------------

    private static string B64(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] B64Decode(string s) => Convert.FromBase64String(s.Replace('-', '+').Replace('_', '/').PadRight(s.Length + (4 - s.Length % 4) % 4, '='));

    public string SignAssertion(WorkspaceBootstrap b)
    {
        var header = B64(JsonSerializer.SerializeToUtf8Bytes(new { alg = "HS256", typ = AssertionType }));
        var payload = B64(JsonSerializer.SerializeToUtf8Bytes(new
        {
            iss = urls.Issuer, aud = urls.TokenEndpoint, sub = b.AgentUserId, jti = b.AssertionJti, bid = b.Id, org = b.OrganizationId,
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), exp = new DateTimeOffset(DateTime.SpecifyKind(b.ExpiresAt, DateTimeKind.Utc)).ToUnixTimeSeconds(),
        }));
        var signature = B64(HMACSHA256.HashData(AssertionKey(), Encoding.ASCII.GetBytes($"{header}.{payload}")));
        return $"{header}.{payload}.{signature}";
    }

    /// <summary>The workspace an assertion names, when its signature, audience, expiry and token id all check out. <c>Revoked</c> is true once it was claimed or expired.</summary>
    public async Task<(WorkspaceBootstrap? Bootstrap, bool Revoked)> VerifyAssertionAsync(string token)
    {
        var parts = token.Split('.');
        if (parts.Length != 3) return (null, false);
        try
        {
            var expected = HMACSHA256.HashData(AssertionKey(), Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"));
            if (!CryptographicOperations.FixedTimeEquals(expected, B64Decode(parts[2]))) return (null, false);
            using var header = JsonDocument.Parse(B64Decode(parts[0]));
            if (header.RootElement.GetProperty("alg").GetString() != "HS256" || header.RootElement.GetProperty("typ").GetString() != AssertionType) return (null, false);
            using var payload = JsonDocument.Parse(B64Decode(parts[1]));
            var p = payload.RootElement;
            if (p.GetProperty("iss").GetString() != urls.Issuer || p.GetProperty("aud").GetString() != urls.TokenEndpoint) return (null, false);
            if (p.GetProperty("exp").GetInt64() <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()) return (null, false);
            var id = p.GetProperty("bid").GetString()!;
            var jti = p.GetProperty("jti").GetString();
            var sub = p.GetProperty("sub").GetString();
            var row = await db.Set<WorkspaceBootstrap>().AsNoTracking().FirstOrDefaultAsync(b => b.Id == id);
            if (row is null || row.AssertionJti != jti || row.AgentUserId != sub) return (null, false);
            return (row, row.Status != "provisional" || row.CredentialsRevokedAt is not null || row.ExpiresAt <= DateTime.UtcNow);
        }
        catch (Exception e) when (e is FormatException or JsonException or KeyNotFoundException or InvalidOperationException) { return (null, false); }
    }

    // ---- creating a provisional workspace --------------------------------------------------------------------------------------------

    public sealed record Created(Organization Organization, WorkspaceBootstrap Bootstrap, ConfigObject Skill, List<(WorkspaceClaim Claim, string Token, string Url)> Links, string Assertion);

    public async Task<Created> CreateAsync(string workspaceName, string skillName, string? devicePublicKey, IReadOnlyList<string> roles, string? ownerEmail, IReadOnlyList<string>? teammates)
    {
        await RetireExpiredAsync();
        var now = LibraryNow();
        var expires = now.AddHours(Math.Max(1, options.Value.Bootstrap.ExpiresHours));
        var orgId = Ids.New("org");
        var bootstrapId = Ids.New("wbt");
        var agentId = Ids.New("usr");
        var memberId = Ids.New("om");
        var skillText = $"---\nname: {skillName}\ndescription: Starter skill created by OpenWork agent bootstrap.\nopenworkBootstrapTrigger: bootstrap.verify\nopenworkBootstrapOutput: {JsonSerializer.Serialize(StarterOutput)}\n---\n\n# {skillName}\n\nWhen triggered with `bootstrap.verify`, output exactly:\n\n`{StarterOutput}`\n";
        const string description = "Starter skill created by OpenWork agent bootstrap.";

        var org = new Organization { Id = orgId, Name = workspaceName, Slug = orgId, CreatedAt = now };
        db.Organizations.Add(org);
        db.Users.Add(new User { Id = agentId, Email = $"agent+{bootstrapId}@{AgentEmailDomain}", Name = "Setup agent", EmailVerified = false, PasswordHash = "!", CreatedAt = now, UpdatedAt = now });
        db.Members.Add(new Member { Id = memberId, OrganizationId = orgId, UserId = agentId, Role = "owner", CreatedAt = now, JoinedAt = now });
        var bootstrap = new WorkspaceBootstrap
        {
            Id = bootstrapId, OrganizationId = orgId, SetupMemberId = memberId, AgentUserId = agentId, Status = "provisional", AssertionJti = Ids.RandomAlnum(24),
            DeviceKeyFingerprint = devicePublicKey is null ? null : Ids.Sha256Hex(devicePublicKey)[..64], OwnerEmail = ownerEmail,
            TeammateEmailsJson = teammates is { Count: > 0 } ? JsonSerializer.Serialize(teammates.Distinct().ToList()) : null, ExpiresAt = expires, CreatedAt = now,
        };
        db.Set<WorkspaceBootstrap>().Add(bootstrap);

        // The starter content: one skill in one plugin on one marketplace, shared with everyone in the workspace.
        var plugin = new Plugin { Id = Ids.New("plg"), OrganizationId = orgId, Name = skillName, Description = description, Status = "active", CreatedByMemberId = memberId, CreatedAt = now, UpdatedAt = now };
        var skill = new ConfigObject
        {
            Id = Ids.New("cob"), OrganizationId = orgId, ObjectType = "skill", SourceMode = "cloud", Title = skillName, Description = description,
            SearchText = $"{skillName}\n{description}\n{skillText}", Status = "active", CreatedByMemberId = memberId, CreatedAt = now, UpdatedAt = now,
        };
        var marketplace = new Marketplace
        {
            Id = Ids.New("mkt"), OrganizationId = orgId, Name = "OpenWork Marketplace", Description = "Built-in OpenWork AI capabilities available in the desktop app after sign-in.",
            LogoUrl = "/openwork-mark.svg", Status = "active", CreatedByMemberId = memberId, CreatedAt = now, UpdatedAt = now,
        };
        db.Add(plugin);
        db.Add(skill);
        db.Add(marketplace);
        db.Add(new ConfigObjectVersion { Id = Ids.New("cov"), OrganizationId = orgId, ConfigObjectId = skill.Id, RawSourceText = skillText, CreatedVia = "cloud", CreatedByMemberId = memberId, CreatedAt = now });
        db.Add(new PluginConfigObject { Id = Ids.New("pco"), OrganizationId = orgId, PluginId = plugin.Id, ConfigObjectId = skill.Id, MembershipSource = "manual", CreatedByMemberId = memberId, CreatedAt = now });
        db.Add(new MarketplacePlugin { Id = Ids.New("mkp"), OrganizationId = orgId, MarketplaceId = marketplace.Id, PluginId = plugin.Id, MembershipSource = "manual", CreatedByMemberId = memberId, CreatedAt = now });
        Grant(GrantKinds.Plugin, plugin.Id, "pag"); Grant(GrantKinds.ConfigObject, skill.Id, "coa");
        db.Add(Share(GrantKinds.Marketplace, marketplace.Id, "mag"));

        var links = new List<(WorkspaceClaim, string, string)>();
        foreach (var role in roles.Distinct())
        {
            var token = B64(RandomNumberGenerator.GetBytes(32));
            var claim = new WorkspaceClaim { Id = Ids.New("wcl"), BootstrapId = bootstrapId, OrganizationId = orgId, TokenHash = Ids.Sha256Hex(token), Role = role, Status = "pending", ExpiresAt = expires, CreatedAt = now };
            db.Set<WorkspaceClaim>().Add(claim);
            links.Add((claim, token, ClaimUrl(token, role == "owner" ? ownerEmail : null, role == "owner" ? teammates : null)));
        }
        await db.SaveChangesAsync();
        await permissions.EnsureDefaultSetsAsync(orgId);
        return new Created(org, bootstrap, skill, links, SignAssertion(bootstrap));

        void Grant(string kind, string id, string prefix)
        {
            db.Add(new LibraryGrant { Id = Ids.New(prefix), OrganizationId = orgId, ResourceKind = kind, ResourceId = id, SubjectKey = "m:" + memberId, MemberId = memberId, Role = "manager", CreatedByMemberId = memberId, CreatedAt = now });
            db.Add(Share(kind, id, prefix));
        }
        LibraryGrant Share(string kind, string id, string prefix) => new() { Id = Ids.New(prefix), OrganizationId = orgId, ResourceKind = kind, ResourceId = id, SubjectKey = "org", OrgWide = true, Role = "viewer", CreatedByMemberId = memberId, CreatedAt = now };
    }

    private static DateTime LibraryNow() { var n = DateTime.UtcNow; return new DateTime(n.Ticks - n.Ticks % TimeSpan.TicksPerMillisecond, DateTimeKind.Utc); }

    public string ClaimUrl(string token, string? email, IReadOnlyList<string>? invite)
    {
        var url = $"{urls.Web}/workspace-claim?token={Uri.EscapeDataString(token)}";
        if (!string.IsNullOrEmpty(email)) url += $"&email={Uri.EscapeDataString(email)}";
        if (invite is { Count: > 0 }) url += $"&invite={Uri.EscapeDataString(string.Join(",", invite))}";
        return url;
    }

    // ---- claim codes ----------------------------------------------------------------------------------------------------------------------

    public async Task<object> IssueCodeAsync(WorkspaceBootstrap b, int minutes)
    {
        var code = new string(Enumerable.Range(0, 8).Select(_ => CodeAlphabet[RandomNumberGenerator.GetInt32(CodeAlphabet.Length)]).ToArray());
        var now = DateTime.UtcNow;
        // Each call cancels the code before it that nobody used.
        await db.Set<WorkspaceClaimCode>().Where(c => c.BootstrapId == b.Id && c.State == "pending").ExecuteUpdateAsync(u => u.SetProperty(c => c.State, "cancelled"));
        db.Set<WorkspaceClaimCode>().Add(new WorkspaceClaimCode { Id = Ids.New("wcc"), BootstrapId = b.Id, OrganizationId = b.OrganizationId, CodeHash = HashCode(code), State = "pending", ExpiresAt = now.AddMinutes(minutes), CreatedAt = now });
        await db.SaveChangesAsync();
        var display = $"{code[..4]}-{code[4..]}";
        return new { user_code = display, verification_uri = $"{urls.Web}/claim", verification_uri_complete = $"{urls.Web}/claim?user_code={Uri.EscapeDataString(display)}", expires_in = minutes * 60, interval = 5 };
    }

    public async Task<object> ClaimStateAsync(WorkspaceBootstrap b)
    {
        var latest = await db.Set<WorkspaceClaimCode>().AsNoTracking().Where(c => c.BootstrapId == b.Id && c.State != "cancelled").OrderByDescending(c => c.CreatedAt).ThenByDescending(c => c.Id).FirstOrDefaultAsync();
        // Re-read: the caller's copy may predate a claim.
        var current = await db.Set<WorkspaceBootstrap>().AsNoTracking().FirstAsync(x => x.Id == b.Id);
        if (current.Status == "claimed" && current.CredentialsRevokedAt is not null) return new { state = "reconciled", reconciled = true };
        if (latest is null) return new { state = "none", reconciled = false };
        if (latest.State == "pending" && latest.ExpiresAt <= DateTime.UtcNow) return new { state = "expired", reconciled = false };
        if (latest.State == "accepted") return new { state = "accepted", reconciled = false };
        if (latest.State == "reconciled") return new { state = "reconciled", reconciled = true };
        return new { state = "pending", reconciled = false };
    }

    public sealed record CodeLookup(WorkspaceClaimCode Code, WorkspaceBootstrap Bootstrap, Organization Organization);

    public async Task<CodeLookup?> LookupCodeAsync(string code)
    {
        var now = DateTime.UtcNow;
        var hash = HashCode(code);
        var row = await (from c in db.Set<WorkspaceClaimCode>().AsNoTracking()
                         join b in db.Set<WorkspaceBootstrap>().AsNoTracking() on c.BootstrapId equals b.Id
                         join o in db.Organizations.AsNoTracking() on c.OrganizationId equals o.Id
                         where c.CodeHash == hash && c.State == "pending" && c.ExpiresAt > now && b.Status == "provisional" && b.ExpiresAt > now
                         select new CodeLookup(c, b, o)).FirstOrDefaultAsync();
        return row;
    }

    // ---- handing the workspace to a person -----------------------------------------------------------------------------------------

    public sealed record Claimed(string OrganizationId, string OrganizationName, string Slug, string Role, string BootstrapId, string[] Teammates);

    /// <summary>
    /// Claims with a link token. One conditional update decides the winner, so two people opening the same link cannot both take the workspace; the
    /// rest happens in one transaction with the claimed state, so a failure leaves the link usable.
    /// </summary>
    public async Task<Claimed?> ClaimWithLinkAsync(string userId, string token)
    {
        var hash = Ids.Sha256Hex(token);
        var now = DateTime.UtcNow;
        var claim = await db.Set<WorkspaceClaim>().AsNoTracking().FirstOrDefaultAsync(c => c.TokenHash == hash && c.Status == "pending" && c.ExpiresAt > now);
        if (claim is null) return null;
        var b = await db.Set<WorkspaceBootstrap>().AsNoTracking().FirstOrDefaultAsync(x => x.Id == claim.BootstrapId && x.Status == "provisional");
        if (b is null) return null;
        await using var tx = await db.Database.BeginTransactionAsync();
        // Everything that can take this workspace queues on its row first, so a link and a code racing each other cannot deadlock on each other's rows.
        await db.LockOrganizationAsync(b.OrganizationId);
        var won = await db.Set<WorkspaceClaim>().Where(c => c.Id == claim.Id && c.Status == "pending").ExecuteUpdateAsync(u => u.SetProperty(c => c.Status, "claimed").SetProperty(c => c.ClaimedByUserId, userId).SetProperty(c => c.ClaimedAt, now));
        if (won == 0) { await tx.RollbackAsync(); return null; }
        var transferred = await TransferAsync(b, userId, claim.Role, now);
        if (transferred is null) { await tx.RollbackAsync(); return null; }
        // A link also ends any claim code the agent made.
        await db.Set<WorkspaceClaimCode>().Where(c => c.BootstrapId == b.Id && c.State == "pending").ExecuteUpdateAsync(u => u.SetProperty(c => c.State, "cancelled"));
        await tx.CommitAsync();
        return transferred;
    }

    public async Task<Claimed?> ClaimWithCodeAsync(string userId, WorkspaceClaimCode code, WorkspaceBootstrap b)
    {
        var now = DateTime.UtcNow;
        await using var tx = await db.Database.BeginTransactionAsync();
        await db.LockOrganizationAsync(b.OrganizationId);
        var won = await db.Set<WorkspaceClaimCode>().Where(c => c.Id == code.Id && c.State == "pending" && c.ExpiresAt > now).ExecuteUpdateAsync(u => u.SetProperty(c => c.State, "accepted").SetProperty(c => c.ClaimedByUserId, userId).SetProperty(c => c.AcceptedAt, now));
        if (won == 0) { await tx.RollbackAsync(); return null; }
        var transferred = await TransferAsync(b, userId, "owner", now);
        if (transferred is null) { await tx.RollbackAsync(); return null; }
        // Unused claim links stop working once the workspace has an owner; the agent's credentials ended in the transfer, which completes the claim.
        await db.Set<WorkspaceClaim>().Where(c => c.BootstrapId == b.Id && c.Status == "pending").ExecuteUpdateAsync(u => u.SetProperty(c => c.Status, "cancelled"));
        await db.Set<WorkspaceClaimCode>().Where(c => c.Id == code.Id).ExecuteUpdateAsync(u => u.SetProperty(c => c.State, "reconciled").SetProperty(c => c.ReconciledAt, now));
        await tx.CommitAsync();
        return transferred;
    }

    /// <summary>Makes the person a member, passes the starter content to them, and removes the setup agent (its member, its sessions, its user). Runs inside the caller's transaction.</summary>
    private async Task<Claimed?> TransferAsync(WorkspaceBootstrap b, string userId, string role, DateTime now)
    {
        // Won the conditional update on the bootstrap itself: only one of a link and a code can take the workspace.
        var moved = await db.Set<WorkspaceBootstrap>().Where(x => x.Id == b.Id && x.Status == "provisional").ExecuteUpdateAsync(u => u.SetProperty(x => x.Status, "claimed").SetProperty(x => x.ClaimedAt, now).SetProperty(x => x.CredentialsRevokedAt, now));
        if (moved == 0) return null;

        var existing = await db.Members.FirstOrDefaultAsync(m => m.OrganizationId == b.OrganizationId && m.UserId == userId);
        string memberId;
        if (existing is not null) { existing.Role = role; existing.JoinedAt = now; memberId = existing.Id; }
        else
        {
            memberId = Ids.New("om");
            db.Members.Add(new Member { Id = memberId, OrganizationId = b.OrganizationId, UserId = userId, Role = role, CreatedAt = now, JoinedAt = now });
        }
        await db.SaveChangesAsync();

        // What the agent made now belongs to the person who claimed it.
        var org = b.OrganizationId;
        await db.Set<Plugin>().Where(x => x.OrganizationId == org && x.CreatedByMemberId == b.SetupMemberId).ExecuteUpdateAsync(u => u.SetProperty(x => x.CreatedByMemberId, memberId));
        await db.Set<ConfigObject>().Where(x => x.OrganizationId == org && x.CreatedByMemberId == b.SetupMemberId).ExecuteUpdateAsync(u => u.SetProperty(x => x.CreatedByMemberId, memberId));
        await db.Set<Marketplace>().Where(x => x.OrganizationId == org && x.CreatedByMemberId == b.SetupMemberId).ExecuteUpdateAsync(u => u.SetProperty(x => x.CreatedByMemberId, memberId));
        await db.Set<LibraryGrant>().Where(x => x.OrganizationId == org && x.MemberId == b.SetupMemberId).ExecuteUpdateAsync(u => u.SetProperty(x => x.MemberId, memberId).SetProperty(x => x.SubjectKey, "m:" + memberId));
        await db.Set<LibraryGrant>().Where(x => x.OrganizationId == org && x.CreatedByMemberId == b.SetupMemberId).ExecuteUpdateAsync(u => u.SetProperty(x => x.CreatedByMemberId, memberId));
        await db.Set<PluginConfigObject>().Where(x => x.OrganizationId == org && x.CreatedByMemberId == b.SetupMemberId).ExecuteUpdateAsync(u => u.SetProperty(x => x.CreatedByMemberId, memberId));
        await db.Set<MarketplacePlugin>().Where(x => x.OrganizationId == org && x.CreatedByMemberId == b.SetupMemberId).ExecuteUpdateAsync(u => u.SetProperty(x => x.CreatedByMemberId, memberId));

        await RetireAgentAsync(b);

        var organization = await db.Organizations.AsNoTracking().FirstAsync(o => o.Id == org);
        var teammates = role == "owner" && b.TeammateEmailsJson is { } json ? JsonSerializer.Deserialize<string[]>(json)?.Where(e => e.Contains('@')).ToArray() ?? [] : [];
        return new Claimed(organization.Id, organization.Name, organization.Slug, role, b.Id, teammates);
    }

    /// <summary>Ends the agent's identity: its sessions and tokens, its member row, and its user. The bootstrap keeps the id so the old assertion can still read the final claim state.</summary>
    private async Task RetireAgentAsync(WorkspaceBootstrap b)
    {
        await db.Sessions.Where(s => s.UserId == b.AgentUserId).ExecuteDeleteAsync();
        await db.McpAccessTokens.Where(t => t.UserId == b.AgentUserId).ExecuteDeleteAsync();
        await db.RefreshTokens.Where(t => t.UserId == b.AgentUserId).ExecuteDeleteAsync();
        await db.Members.Where(m => m.Id == b.SetupMemberId).ExecuteDeleteAsync();
        await db.Users.Where(u => u.Id == b.AgentUserId).ExecuteDeleteAsync();
    }

    /// <summary>Workspaces nobody claimed in time lose their agent: expiry cleanup rides on new bootstraps, in small batches.</summary>
    public async Task RetireExpiredAsync(int limit = 25)
    {
        var now = DateTime.UtcNow;
        var expired = await db.Set<WorkspaceBootstrap>().AsNoTracking().Where(b => b.Status == "provisional" && b.ExpiresAt <= now).OrderBy(b => b.ExpiresAt).Take(limit).ToListAsync();
        foreach (var b in expired)
        {
            var moved = await db.Set<WorkspaceBootstrap>().Where(x => x.Id == b.Id && x.Status == "provisional").ExecuteUpdateAsync(u => u.SetProperty(x => x.Status, "expired").SetProperty(x => x.CredentialsRevokedAt, now));
            if (moved == 1) await RetireAgentAsync(b);
        }
    }
}
