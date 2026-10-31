using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.Sso;
using WorkAI360.Api.Features.Sso;

namespace WorkAI360.Api.Features.Scim;

public sealed record ScimFailure(int Status, string Detail, string? ScimType = null);

public sealed record ScimUserInput(string UserName, string? ExternalId, string? Formatted, string? GivenName, string? FamilyName, (string Value, bool Primary)[] Emails, bool? Active);

/// <summary>
/// SCIM provisioning for one workspace: the bearer token (shown once, kept only as a hash), people (create, update, deprovision), groups and
/// their projection onto teams, and the repair run. SCIM never grants a role: people arrive as plain members, and groups are metadata unless
/// the workspace chooses to map them to teams.
/// </summary>
public sealed class ScimService(DenDbContext db, CredentialRevocation revocation)
{
    public const string UserSchema = "urn:ietf:params:scim:schemas:core:2.0:User";
    public const string GroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group";
    public const string ListSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
    public const string PatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
    public const string ErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error";
    public const string MetadataOnly = "metadata_only";
    public const string CreateTeams = "create_teams";
    public const int MaxAttempts = 5;

    public static string ProviderIdFor(string organizationId) => $"openwork-scim-{organizationId}";

    // ---- The token ----

    public static string HashToken(string raw) => Ids.Sha256Hex(raw);

    /// <summary>Creates the connection if needed and replaces its token. The returned bearer token carries the provider and workspace ids so the right row is found before the secret is checked.</summary>
    public async Task<(ScimProvider Provider, string BearerToken)> RotateTokenAsync(string organizationId, string userId)
    {
        var raw = Ids.RandomAlnum(32);
        var now = DateTime.UtcNow;
        var providerId = ProviderIdFor(organizationId);
        var provider = await db.Set<ScimProvider>().FirstOrDefaultAsync(p => p.OrganizationId == organizationId);
        if (provider is null)
        {
            provider = new ScimProvider { Id = Ids.New("scp"), OrganizationId = organizationId, ProviderId = providerId, TokenHash = HashToken(raw), CreatedByUserId = userId, GroupMappingMode = MetadataOnly, CreatedAt = now, UpdatedAt = now };
            db.Add(provider);
        }
        else
        {
            provider.TokenHash = HashToken(raw);
            provider.UpdatedAt = now;
        }
        await db.SaveChangesAsync();
        return (provider, SsoService.Base64Url(Encoding.UTF8.GetBytes($"{raw}:{providerId}:{organizationId}")));
    }

    private static readonly string DummyHash = HashToken("no-such-token");

    /// <summary>The connection a bearer token belongs to, or null. The ids inside the token only select a row; the secret is compared in constant time.</summary>
    public async Task<ScimProvider?> AuthenticateAsync(string? bearer)
    {
        string? raw = null, providerId = null, organizationId = null;
        if (!string.IsNullOrEmpty(bearer))
        {
            try
            {
                var padded = bearer.Replace('-', '+').Replace('_', '/');
                padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
                var parts = Encoding.UTF8.GetString(Convert.FromBase64String(padded)).Split(':');
                if (parts.Length >= 3) { raw = parts[0]; providerId = parts[1]; organizationId = string.Join(':', parts[2..]); }
            }
            catch (FormatException) { }
        }
        var provider = raw is { Length: > 0 } && providerId is { Length: > 0 } && organizationId is { Length: > 0 }
            ? await db.Set<ScimProvider>().AsNoTracking().FirstOrDefaultAsync(p => p.ProviderId == providerId && p.OrganizationId == organizationId)
            : null;
        var matches = SsoService.FixedEquals(HashToken(raw ?? ""), provider?.TokenHash ?? DummyHash);
        return provider is not null && matches ? provider : null;
    }

    // ---- Users ----

    private static string Normalize(string value) => value.Trim().ToLowerInvariant();

    public static string AccountId(ScimUserInput input) => input.ExternalId ?? input.UserName;

    public static string PrimaryEmail(ScimUserInput input) => Normalize(input.Emails.FirstOrDefault(e => e.Primary).Value ?? input.Emails.FirstOrDefault().Value ?? input.UserName);

    public static string FullName(string email, string? formatted, string? given, string? family)
    {
        if (formatted?.Trim() is { Length: > 0 } f) return f;
        if (!string.IsNullOrEmpty(given) && !string.IsNullOrEmpty(family)) return $"{given} {family}";
        return given ?? (string.IsNullOrEmpty(family) ? email : family);
    }

    public async Task<(User? User, ExternalAccount? Account)> FindUserAsync(ScimProvider provider, string userId)
    {
        var account = await db.Set<ExternalAccount>().FirstOrDefaultAsync(a => a.UserId == userId && a.ProviderId == provider.ProviderId);
        if (account is null) return (null, null);
        if (!await db.Members.AnyAsync(m => m.OrganizationId == provider.OrganizationId && m.UserId == userId)) return (null, null);
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == userId);
        return user is null ? (null, null) : (user, account);
    }

    public async Task<(User? User, ExternalAccount? Account, ScimFailure? Failure)> CreateUserAsync(ScimProvider provider, ScimUserInput input)
    {
        var accountId = AccountId(input);
        if (await db.Set<ExternalAccount>().AnyAsync(a => a.ProviderId == provider.ProviderId && a.AccountId == accountId))
            return (null, null, new ScimFailure(409, "User already exists", "uniqueness"));
        if (input.Active == false) return (null, null, new ScimFailure(400, "Setting `active: false` requires the admin plugin, which provides the enforced disabled-user state"));

        var email = PrimaryEmail(input);
        var name = FullName(email, input.Formatted, input.GivenName, input.FamilyName);
        var now = DateTime.UtcNow;
        var user = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
        if (user is not null)
        {
            // An existing account is only adopted when it already belongs to this workspace: SCIM must not be able to take over anyone else's account.
            if (!await db.Members.AnyAsync(m => m.OrganizationId == provider.OrganizationId && m.UserId == user.Id)) return (null, null, new ScimFailure(409, "User already exists", "uniqueness"));
        }
        else
        {
            user = new User { Id = Ids.New("usr"), Email = email, Name = name, EmailVerified = false, PasswordHash = SsoProvisioning.UnusablePassword, CreatedAt = now, UpdatedAt = now };
            db.Users.Add(user);
        }
        var account = new ExternalAccount { Id = Ids.New("acc"), UserId = user.Id, ProviderId = provider.ProviderId, AccountId = accountId, CreatedAt = now };
        db.Add(account);
        if (!await db.Members.AnyAsync(m => m.OrganizationId == provider.OrganizationId && m.UserId == user.Id))
            db.Members.Add(new Member { Id = Ids.New("om"), OrganizationId = provider.OrganizationId, UserId = user.Id, Role = Roles.Member, CreatedAt = now, JoinedAt = now });
        // Coming back through SCIM is how someone who was deprovisioned is let in again.
        await db.Set<ScimUserTombstone>().Where(t => t.OrganizationId == provider.OrganizationId && (t.Email == email || (input.ExternalId != null && t.ExternalId == input.ExternalId))).ExecuteDeleteAsync();
        try { await db.SaveChangesAsync(); }
        catch (DbUpdateException) { db.ChangeTracker.Clear(); return (null, null, new ScimFailure(409, "User already exists", "uniqueness")); }
        await SyncIdentityAsync(provider, user, input.ExternalId, input.UserName, email, name, true);
        await ReconcileGroupsForUserAsync(provider, user.Id);
        return (user, account, null);
    }

    private async Task SyncIdentityAsync(ScimProvider provider, User user, string? externalId, string? userName, string email, string? displayName, bool active)
    {
        var now = DateTime.UtcNow;
        var row = await db.Set<ExternalIdentity>().FirstOrDefaultAsync(i => i.OrganizationId == provider.OrganizationId && i.UserId == user.Id);
        if (row is null)
        {
            row = new ExternalIdentity { Id = Ids.New("exi"), OrganizationId = provider.OrganizationId, UserId = user.Id, Source = "scim", Email = email };
            db.Add(row);
        }
        row.Source = row.SsoProviderId is null ? "scim" : "scim+sso";
        row.ScimProviderId = provider.ProviderId;
        row.ExternalId = externalId;
        row.UserName = userName;
        row.Email = email;
        row.DisplayName = displayName;
        row.Active = active;
        row.LastScimSyncAt = now;
        try { await db.SaveChangesAsync(); } catch (DbUpdateException) { db.ChangeTracker.Clear(); }
    }

    public async Task<ScimFailure?> ReplaceUserAsync(ScimProvider provider, User user, ExternalAccount account, ScimUserInput input)
    {
        var email = PrimaryEmail(input);
        var name = FullName(email, input.Formatted, input.GivenName, input.FamilyName);
        if (email != user.Email && await db.Users.AnyAsync(u => u.Email == email && u.Id != user.Id)) return new ScimFailure(409, "Email already in use", "uniqueness");
        var newAccountId = AccountId(input);
        if (newAccountId != account.AccountId && await db.Set<ExternalAccount>().AnyAsync(a => a.ProviderId == provider.ProviderId && a.AccountId == newAccountId && a.Id != account.Id))
            return new ScimFailure(409, "User already exists", "uniqueness");
        if (email != user.Email) user.EmailVerified = false;
        user.Email = email;
        user.Name = name;
        user.UpdatedAt = DateTime.UtcNow;
        account.AccountId = newAccountId;
        await db.SaveChangesAsync();
        await SyncIdentityAsync(provider, user, input.ExternalId, input.UserName, email, name, true);
        return null;
    }

    /// <summary>The fields a PATCH may change (the reference's mapping): active, name parts, externalId, userName. Returns null when nothing mappable was named.</summary>
    public sealed record UserPatch(bool Deactivate, bool TouchesActive, string? Email, string? Name, string? ExternalId, bool Any);

    public static UserPatch BuildPatch(User user, IEnumerable<(string Op, string? Path, System.Text.Json.JsonElement Value)> operations)
    {
        bool deactivate = false, touchesActive = false, any = false;
        string? email = null, name = null, externalId = null;
        var currentName = user.Name;
        void Apply(string path, System.Text.Json.JsonElement value)
        {
            var p = "/" + path.TrimStart('/').Replace('.', '/');
            switch (p.ToLowerInvariant())
            {
                case "/active":
                    any = touchesActive = true;
                    deactivate |= value.ValueKind == System.Text.Json.JsonValueKind.False || (value.ValueKind == System.Text.Json.JsonValueKind.String && value.GetString()!.ToLowerInvariant() == "false");
                    break;
                case "/name/formatted" when value.ValueKind == System.Text.Json.JsonValueKind.String: name = currentName = value.GetString()!; any = true; break;
                case "/name/givenname" when value.ValueKind == System.Text.Json.JsonValueKind.String:
                    name = currentName = FullName(user.Email, null, value.GetString(), string.Join(' ', currentName.Split(' ').Skip(1)).Trim()); any = true; break;
                case "/name/familyname" when value.ValueKind == System.Text.Json.JsonValueKind.String:
                    var given = (string.Join(' ', currentName.Split(' ').SkipLast(1)) is { Length: > 0 } g ? g : currentName).Trim();
                    name = currentName = FullName(user.Email, null, given, value.GetString()); any = true; break;
                case "/externalid" when value.ValueKind == System.Text.Json.JsonValueKind.String: externalId = value.GetString(); any = true; break;
                case "/username" when value.ValueKind == System.Text.Json.JsonValueKind.String: email = Normalize(value.GetString()!); any = true; break;
            }
        }
        void Walk(System.Text.Json.JsonElement value, string? path)
        {
            if (value.ValueKind == System.Text.Json.JsonValueKind.Object)
                foreach (var property in value.EnumerateObject()) Walk(property.Value, path is null ? property.Name : $"{path}.{property.Name}");
            else if (path is not null) Apply(path, value);
        }
        foreach (var (op, path, value) in operations)
            if (op is "add" or "replace") Walk(value, path);
        return new UserPatch(deactivate, touchesActive, email, name, externalId, any);
    }

    public async Task<ScimFailure?> ApplyPatchAsync(ScimProvider provider, User user, ExternalAccount account, UserPatch patch)
    {
        if (patch.Email is { } email && email != user.Email)
        {
            if (await db.Users.AnyAsync(u => u.Email == email && u.Id != user.Id)) return new ScimFailure(409, "Email already in use", "uniqueness");
            user.Email = email;
            user.EmailVerified = false;
        }
        if (patch.Name is { } name) user.Name = name;
        if (patch.ExternalId is { } externalId) account.AccountId = externalId;
        user.UpdatedAt = DateTime.UtcNow;
        await db.SaveChangesAsync();
        await SyncIdentityAsync(provider, user, patch.ExternalId ?? account.AccountId, user.Email, user.Email, user.Name, true);
        return null;
    }

    /// <summary>
    /// Takes the person out of the workspace: their membership and team places go, every session and agent credential they hold ends, SCIM and SSO
    /// links are dropped and a tombstone keeps single sign-on from quietly bringing them back. A person with no other workspace is deleted.
    /// </summary>
    public async Task<ScimFailure?> DeprovisionAsync(ScimProvider provider, string userId)
    {
        var org = provider.OrganizationId;
        var member = await db.Members.FirstOrDefaultAsync(m => m.OrganizationId == org && m.UserId == userId);
        if (member?.Role == Roles.Owner) return new ScimFailure(409, "The workspace owner cannot be deprovisioned. Transfer ownership first.");
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == userId);
        var identity = await db.Set<ExternalIdentity>().FirstOrDefaultAsync(i => i.OrganizationId == org && i.UserId == userId);
        var account = await db.Set<ExternalAccount>().FirstOrDefaultAsync(a => a.UserId == userId && a.ProviderId == provider.ProviderId);
        var email = (identity?.Email ?? user?.Email)?.Trim().ToLowerInvariant();
        var now = DateTime.UtcNow;

        await using var tx = await db.Database.BeginTransactionAsync();
        if (member is not null)
        {
            db.TeamMembers.RemoveRange(await db.TeamMembers.Where(t => t.MemberId == member.Id).ToListAsync());
            db.Members.Remove(member);
        }
        await db.Set<ScimGroupMember>().Where(g => g.ProviderId == provider.ProviderId && g.RemoteUserId == userId).ExecuteUpdateAsync(s => s.SetProperty(g => g.MemberId, (string?)null).SetProperty(g => g.TeamMemberId, (string?)null));
        var tombstone = await db.Set<ScimUserTombstone>().FirstOrDefaultAsync(t => t.OrganizationId == org && t.DeprovisionedUserId == userId);
        if (tombstone is null) db.Add(new ScimUserTombstone { Id = Ids.New("sut"), OrganizationId = org, ProviderId = provider.ProviderId, DeprovisionedUserId = userId, ExternalId = identity?.ExternalId ?? account?.AccountId, Email = email, DeprovisionedAt = now });
        else { tombstone.Email = email; tombstone.ExternalId = identity?.ExternalId ?? account?.AccountId; tombstone.DeprovisionedAt = now; }
        if (account is not null) db.Remove(account);
        if (identity is not null) { identity.Active = false; identity.ScimProviderId = provider.ProviderId; identity.LastScimSyncAt = now; }
        await db.SaveChangesAsync();
        await tx.CommitAsync();

        // Ends every session (web, desktop, CLI) and the agent access this person held here.
        await revocation.RevokeAsync(userId, org);
        if (user is not null && !await db.Members.AnyAsync(m => m.UserId == userId))
        {
            await db.Sessions.Where(s => s.UserId == userId).ExecuteDeleteAsync();
            await db.Set<ExternalAccount>().Where(a => a.UserId == userId).ExecuteDeleteAsync();
            await db.Users.Where(u => u.Id == userId).ExecuteDeleteAsync();
        }
        return null;
    }

    // ---- Groups and teams ----

    public static string TeamModeOf(ScimProvider p) => p.GroupMappingMode == CreateTeams ? CreateTeams : MetadataOnly;

    private async Task<string> ChooseTeamNameAsync(string organizationId, string displayName, string? currentTeamId)
    {
        var exact = await db.Teams.Where(t => t.OrganizationId == organizationId && t.Name == displayName).Select(t => t.Id).FirstOrDefaultAsync();
        if (exact is null || exact == currentTeamId) return displayName;
        var suffixed = $"{displayName} (SCIM)";
        if (!await db.Teams.AnyAsync(t => t.OrganizationId == organizationId && t.Name == suffixed)) return suffixed;
        return $"{displayName} (SCIM {Ids.New("tem")[^6..]})";
    }

    private async Task<ScimGroup> EnsureTeamAsync(ScimProvider provider, ScimGroup group)
    {
        if (TeamModeOf(provider) != CreateTeams || group.TeamId is not null) return group;
        var now = DateTime.UtcNow;
        var team = new Team { Id = Ids.New("tem"), OrganizationId = provider.OrganizationId, Name = await ChooseTeamNameAsync(provider.OrganizationId, group.DisplayName, null), CreatedAt = now, UpdatedAt = now };
        db.Teams.Add(team);
        group.TeamId = team.Id;
        await db.SaveChangesAsync();
        return group;
    }

    private async Task AttachAsync(ScimProvider provider, ScimGroup group, ScimGroupMember row)
    {
        var member = await db.Members.FirstOrDefaultAsync(m => m.OrganizationId == provider.OrganizationId && m.UserId == row.RemoteUserId);
        if (member is null) return;
        string? teamMemberId = null;
        if (TeamModeOf(provider) == CreateTeams && group.TeamId is not null)
        {
            var existing = await db.TeamMembers.FirstOrDefaultAsync(t => t.TeamId == group.TeamId && t.MemberId == member.Id);
            if (existing is null)
            {
                existing = new TeamMember { Id = Ids.New("tmm"), TeamId = group.TeamId, MemberId = member.Id, CreatedAt = DateTime.UtcNow };
                db.TeamMembers.Add(existing);
            }
            teamMemberId = existing.Id;
        }
        row.MemberId = member.Id;
        row.TeamMemberId = teamMemberId;
        await db.SaveChangesAsync();
    }

    private async Task ReplaceMembersAsync(ScimProvider provider, ScimGroup group, IReadOnlyList<string> values)
    {
        group = await EnsureTeamAsync(provider, group);
        var wanted = values.Select(v => v.Trim()).Where(v => v.Length > 0).Distinct().ToList();
        var existing = await db.Set<ScimGroupMember>().Where(m => m.GroupId == group.Id).ToListAsync();
        foreach (var row in existing.Where(m => !wanted.Contains(m.RemoteUserId)))
        {
            if (TeamModeOf(provider) == CreateTeams && row.TeamMemberId is not null) await db.TeamMembers.Where(t => t.Id == row.TeamMemberId).ExecuteDeleteAsync();
            db.Remove(row);
        }
        await db.SaveChangesAsync();
        foreach (var value in wanted)
        {
            var row = existing.FirstOrDefault(m => m.RemoteUserId == value);
            if (row is null)
            {
                row = new ScimGroupMember { Id = Ids.New("sgm"), GroupId = group.Id, OrganizationId = provider.OrganizationId, ProviderId = provider.ProviderId, RemoteUserId = value };
                db.Add(row);
                await db.SaveChangesAsync();
            }
            if (row.TeamMemberId is null) await AttachAsync(provider, group, row);
        }
    }

    public async Task ReconcileGroupsForUserAsync(ScimProvider provider, string userId)
    {
        var rows = await db.Set<ScimGroupMember>().Where(m => m.ProviderId == provider.ProviderId && m.OrganizationId == provider.OrganizationId && m.RemoteUserId == userId && m.TeamMemberId == null).ToListAsync();
        foreach (var row in rows)
        {
            var group = await db.Set<ScimGroup>().FirstOrDefaultAsync(g => g.Id == row.GroupId);
            if (group is not null) await AttachAsync(provider, group, row);
        }
    }

    public Task<ScimGroup?> FindGroupAsync(ScimProvider provider, string id) =>
        db.Set<ScimGroup>().FirstOrDefaultAsync(g => g.Id == id && g.ProviderId == provider.ProviderId && g.OrganizationId == provider.OrganizationId);

    public async Task<(ScimGroup? Group, ScimFailure? Failure)> CreateGroupAsync(ScimProvider provider, string displayName, string? externalId, IReadOnlyList<string> members)
    {
        displayName = displayName.Trim();
        if (displayName.Length == 0) return (null, new ScimFailure(400, "displayName is required"));
        if (externalId is not null && await db.Set<ScimGroup>().AnyAsync(g => g.ProviderId == provider.ProviderId && g.ExternalId == externalId))
            return (null, new ScimFailure(409, "A group with that externalId already exists"));
        var now = DateTime.UtcNow;
        var group = new ScimGroup { Id = Ids.New("scg"), OrganizationId = provider.OrganizationId, ProviderId = provider.ProviderId, ExternalId = externalId, DisplayName = displayName, CreatedAt = now, UpdatedAt = now };
        db.Add(group);
        await db.SaveChangesAsync();
        await ReplaceMembersAsync(provider, group, members);
        return (group, null);
    }

    public async Task<ScimFailure?> UpdateGroupAsync(ScimProvider provider, ScimGroup group, string displayName, string? externalId, IReadOnlyList<string> members)
    {
        displayName = displayName.Trim();
        if (displayName.Length == 0) return new ScimFailure(400, "displayName is required");
        if (externalId is not null && externalId != group.ExternalId && await db.Set<ScimGroup>().AnyAsync(g => g.ProviderId == provider.ProviderId && g.ExternalId == externalId))
            return new ScimFailure(409, "A group with that externalId already exists");
        group.ExternalId = externalId;
        group.DisplayName = displayName;
        group.UpdatedAt = DateTime.UtcNow;
        if (group.TeamId is not null && TeamModeOf(provider) == CreateTeams)
        {
            var team = await db.Teams.FirstOrDefaultAsync(t => t.Id == group.TeamId);
            if (team is not null) { team.Name = await ChooseTeamNameAsync(provider.OrganizationId, displayName, team.Id); team.UpdatedAt = DateTime.UtcNow; }
        }
        await db.SaveChangesAsync();
        await ReplaceMembersAsync(provider, group, members);
        return null;
    }

    public async Task DeleteGroupAsync(ScimProvider provider, ScimGroup group)
    {
        var rows = await db.Set<ScimGroupMember>().Where(m => m.GroupId == group.Id).ToListAsync();
        if (TeamModeOf(provider) == CreateTeams)
        {
            if (group.TeamId is not null) await db.Teams.Where(t => t.Id == group.TeamId && t.OrganizationId == provider.OrganizationId).ExecuteUpdateAsync(s => s.SetProperty(t => t.GrantsOrganizationAdmin, false));
            var ids = rows.Where(r => r.TeamMemberId is not null).Select(r => r.TeamMemberId!).ToList();
            await db.TeamMembers.Where(t => ids.Contains(t.Id)).ExecuteDeleteAsync();
        }
        db.RemoveRange(rows);
        db.Remove(group);
        await db.SaveChangesAsync();
    }

    public async Task<IReadOnlyList<string>> MemberValuesAsync(ScimGroup group) =>
        await db.Set<ScimGroupMember>().Where(m => m.GroupId == group.Id).OrderBy(m => m.RemoteUserId).Select(m => m.RemoteUserId).ToListAsync();

    /// <summary>Switching the mapping hands authority over team membership back and forth, so Admin designation is dropped and (when mapping turns on) manual edits are replaced by the identity provider's.</summary>
    public async Task SetMappingModeAsync(ScimProvider provider, string mode)
    {
        var groups = await db.Set<ScimGroup>().Where(g => g.ProviderId == provider.ProviderId && g.OrganizationId == provider.OrganizationId).ToListAsync();
        var teamIds = groups.Where(g => g.TeamId is not null).Select(g => g.TeamId!).ToList();
        if (provider.GroupMappingMode != mode)
        {
            await db.Teams.Where(t => t.OrganizationId == provider.OrganizationId && teamIds.Contains(t.Id)).ExecuteUpdateAsync(s => s.SetProperty(t => t.GrantsOrganizationAdmin, false));
            if (mode == CreateTeams) await db.TeamMembers.Where(t => teamIds.Contains(t.TeamId)).ExecuteDeleteAsync();
        }
        await db.Set<ScimGroupMember>().Where(m => m.ProviderId == provider.ProviderId && m.OrganizationId == provider.OrganizationId).ExecuteUpdateAsync(s => s.SetProperty(m => m.TeamMemberId, (string?)null));
        var tracked = await db.Set<ScimProvider>().FirstAsync(p => p.Id == provider.Id);
        tracked.GroupMappingMode = mode;
        tracked.UpdatedAt = DateTime.UtcNow;
        await db.SaveChangesAsync();
        if (mode == CreateTeams)
        {
            foreach (var group in groups)
            {
                var values = await MemberValuesAsync(group);
                await ReplaceMembersAsync(tracked, group, values);
            }
        }
    }

    public async Task DeleteConnectionAsync(ScimProvider provider)
    {
        var org = provider.OrganizationId;
        var groups = await db.Set<ScimGroup>().Where(g => g.ProviderId == provider.ProviderId).ToListAsync();
        var teamIds = groups.Where(g => g.TeamId is not null).Select(g => g.TeamId!).ToList();
        if (teamIds.Count > 0 && provider.GroupMappingMode == CreateTeams)
            // The teams stay as ordinary teams, but nothing the identity provider projected keeps authority.
            await db.Teams.Where(t => t.OrganizationId == org && teamIds.Contains(t.Id)).ExecuteUpdateAsync(s => s.SetProperty(t => t.GrantsOrganizationAdmin, false));
        var groupIds = groups.Select(g => g.Id).ToList();
        await db.Set<ScimGroupMember>().Where(m => groupIds.Contains(m.GroupId)).ExecuteDeleteAsync();
        await db.Set<ScimGroup>().Where(g => g.ProviderId == provider.ProviderId).ExecuteDeleteAsync();
        await db.Set<ScimUserTombstone>().Where(t => t.ProviderId == provider.ProviderId).ExecuteDeleteAsync();
        await db.Set<ExternalIdentity>().Where(i => i.OrganizationId == org && i.ScimProviderId == provider.ProviderId && i.SsoProviderId != null)
            .ExecuteUpdateAsync(s => s.SetProperty(i => i.Source, "sso").SetProperty(i => i.ScimProviderId, (string?)null).SetProperty(i => i.ExternalId, (string?)null).SetProperty(i => i.LastScimSyncAt, (DateTime?)null));
        await db.Set<ExternalIdentity>().Where(i => i.OrganizationId == org && i.ScimProviderId == provider.ProviderId && i.SsoProviderId == null)
            .ExecuteUpdateAsync(s => s.SetProperty(i => i.Active, false).SetProperty(i => i.ScimProviderId, (string?)null).SetProperty(i => i.ExternalId, (string?)null).SetProperty(i => i.LastScimSyncAt, (DateTime?)null));
        await db.Set<ExternalAccount>().Where(a => a.ProviderId == provider.ProviderId).ExecuteDeleteAsync();
        await db.Set<ScimProvider>().Where(p => p.Id == provider.Id).ExecuteDeleteAsync();
    }

    // ---- Health and repair ----

    public async Task RecordFailureAsync(ScimProvider provider, string action, string? userId, string error, bool retryable = true)
    {
        var now = DateTime.UtcNow;
        db.Add(new ScimSyncEvent
        {
            Id = Ids.New("sse"), OrganizationId = provider.OrganizationId, ProviderId = provider.ProviderId, UserId = userId, Action = action,
            Status = retryable ? "pending" : "failed", Attempts = retryable ? 0 : MaxAttempts, LastError = error.Length > 2000 ? error[..2000] : error,
            NextRetryAt = retryable ? now.AddMinutes(1) : null, CreatedAt = now,
        });
        await db.SaveChangesAsync();
    }

    public async Task<object> HealthAsync(string organizationId)
    {
        var unresolved = db.Set<ScimSyncEvent>().Where(e => e.OrganizationId == organizationId && e.ResolvedAt == null);
        var last = await unresolved.OrderByDescending(e => e.CreatedAt).FirstOrDefaultAsync();
        var lastSync = await db.Set<ExternalIdentity>().Where(i => i.OrganizationId == organizationId && i.LastScimSyncAt != null).OrderByDescending(i => i.LastScimSyncAt).Select(i => i.LastScimSyncAt).FirstOrDefaultAsync();
        return new
        {
            unresolvedFailureCount = await unresolved.CountAsync(),
            lastFailureAt = last is null ? null : Responses.IsoUtc(last.CreatedAt),
            lastFailureAction = last?.Action,
            lastFailureMessage = last?.LastError,
            nextRetryAt = last?.NextRetryAt is { } n ? Responses.IsoUtc(n) : null,
            lastSuccessfulSyncAt = lastSync is { } l ? Responses.IsoUtc(l) : null,
        };
    }

    /// <summary>
    /// Looks for drift between what SCIM says and what the workspace has: an active SCIM identity whose person is no longer a member is deactivated (repaired);
    /// one that is a member but has lost its SCIM account is reported for a person to look at (failure).
    /// </summary>
    public async Task<(int Checked, int Repaired, int Failures)> ReconcileAsync(string organizationId)
    {
        var provider = await db.Set<ScimProvider>().AsNoTracking().FirstOrDefaultAsync(p => p.OrganizationId == organizationId);
        if (provider is null) return (0, 0, 0);
        var identities = await db.Set<ExternalIdentity>().Where(i => i.OrganizationId == organizationId && i.ScimProviderId == provider.ProviderId && i.Active).ToListAsync();
        int repaired = 0, failures = 0;
        foreach (var identity in identities)
        {
            var isMember = await db.Members.AnyAsync(m => m.OrganizationId == organizationId && m.UserId == identity.UserId);
            var hasAccount = await db.Set<ExternalAccount>().AnyAsync(a => a.UserId == identity.UserId && a.ProviderId == provider.ProviderId);
            if (!isMember)
            {
                identity.Active = false;
                identity.LastScimSyncAt = DateTime.UtcNow;
                repaired++;
            }
            else if (!hasAccount)
            {
                failures++;
                var known = await db.Set<ScimSyncEvent>().AnyAsync(e => e.OrganizationId == organizationId && e.UserId == identity.UserId && e.Action == "reconcile_drift" && e.ResolvedAt == null);
                if (!known) await RecordFailureAsync(provider, "reconcile_drift", identity.UserId, "Active SCIM identity has workspace access but no SCIM account.", retryable: false);
            }
        }
        await db.SaveChangesAsync();
        return (identities.Count, repaired, failures);
    }
}
