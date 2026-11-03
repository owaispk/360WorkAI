using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.LlmProviders;
using WorkAI360.Api.Features.Connections;

namespace WorkAI360.Api.Features.LlmProviders;

/// <summary>A refusal with the reference's <c>{error, message?}</c> body.</summary>
public sealed class ProviderFailure(int status, string error, string? message = null) : Exception(message ?? error)
{
    public int Status { get; } = status;
    public string Error { get; } = error;
    public string? Detail { get; } = message;
    public IResult ToResult() => Detail is null ? Results.Json(new { error = Error }, statusCode: Status) : Results.Json(new { error = Error, message = Detail }, statusCode: Status);
}

/// <summary>A parsed provider write (the reference's <c>llmProviderWriteSchema</c>).</summary>
public sealed record ProviderWrite(
    string Name, string Source, string? ProviderId, List<string>? ModelIds, string? CustomConfigText, JsonNode? CustomConfig, bool HasCustomConfig,
    string CredentialMode, string? ApiKey, Dictionary<string, string>? ApiKeys, List<string> MemberIds, List<string> TeamIds, bool AllMembers);

public sealed record NormalizedProvider(string Source, string ProviderId, string Name, JsonObject ProviderConfig, List<CatalogModel> Models, string? ApiKey);

/// <summary>Providers, their models, who may use them and people's own keys (the reference's <c>llm-providers.ts</c> and <c>llm-provider-access.ts</c>).</summary>
public sealed class LlmProviderService(DenDbContext db, SecretBox box, ModelCatalog catalog)
{
    public const string MicrosoftFoundryProviderId = "microsoft-foundry";

    public async Task<List<string>> TeamIdsAsync(string memberId) =>
        await db.TeamMembers.AsNoTracking().Where(t => t.MemberId == memberId).Select(t => t.TeamId).ToListAsync();

    /// <summary>The access rows that let this person use a provider of the workspace: their own, one of their teams', or the workspace-wide one.</summary>
    public async Task<List<LlmProviderAccess>> AccessibleAsync(string orgId, string memberId, IReadOnlyCollection<string> teamIds) =>
        await (from a in db.Set<LlmProviderAccess>().AsNoTracking()
               join p in db.Set<LlmProvider>().AsNoTracking() on a.LlmProviderId equals p.Id
               where p.OrganizationId == orgId && (a.MemberId == memberId || (a.TeamId != null && teamIds.Contains(a.TeamId)) || (a.MemberId == null && a.TeamId == null))
               select a).ToListAsync();

    public async Task<bool> CanUseAsync(string orgId, string providerId, string memberId, IReadOnlyCollection<string> teamIds) =>
        (await AccessibleAsync(orgId, memberId, teamIds)).Any(a => a.LlmProviderId == providerId);

    /// <summary>Every current member who may use the provider (directly, through a team, or because everyone may).</summary>
    public async Task<List<string>> GrantedMemberIdsAsync(string orgId, string providerId)
    {
        var rows = await db.Set<LlmProviderAccess>().AsNoTracking().Where(a => a.LlmProviderId == providerId).ToListAsync();
        var members = db.Members.AsNoTracking().Where(m => m.OrganizationId == orgId);
        if (rows.Any(a => a.MemberId == null && a.TeamId == null)) return await members.Select(m => m.Id).ToListAsync();
        var direct = rows.Where(a => a.MemberId != null).Select(a => a.MemberId!).ToList();
        var teams = rows.Where(a => a.TeamId != null).Select(a => a.TeamId!).ToList();
        var viaTeams = await db.TeamMembers.AsNoTracking().Where(t => teams.Contains(t.TeamId)).Select(t => t.MemberId).ToListAsync();
        var wanted = direct.Concat(viaTeams).Distinct().ToList();
        return await members.Where(m => wanted.Contains(m.Id)).Select(m => m.Id).ToListAsync();
    }

    public Task<LlmProvider?> FindAsync(string orgId, string providerId) =>
        db.Set<LlmProvider>().FirstOrDefaultAsync(p => p.OrganizationId == orgId && p.Id == providerId);

    public static JsonObject Config(LlmProvider p) => JsonNode.Parse(p.ProviderConfigJson) as JsonObject ?? [];
    private static JsonObject Config(LlmProviderModel m) => JsonNode.Parse(m.ModelConfigJson) as JsonObject ?? [];
    public string? Secret(LlmProvider p) => box.Decrypt(p.ApiKeyEnc);

    // ---- reading ---------------------------------------------------------------------------------------------------------------------------

    /// <summary>
    /// Providers as the list and the single reads return them. Who may see the stored configuration: anyone who can edit the provider (Edit any
    /// provider, or its creator) or is granted it (they receive the full configuration from /connect anyway). Everyone else gets the view-only
    /// configuration and nothing derived from the stored configuration or credential. People's names and emails are only for those who can edit it.
    /// </summary>
    public async Task<List<Dictionary<string, object?>>> LoadAsync(string orgId, string memberId, IReadOnlyCollection<string> teamIds, bool viewAll, bool updateAll, string scope)
    {
        var accessible = await AccessibleAsync(orgId, memberId, teamIds);
        var accessibleIds = accessible.Select(a => a.LlmProviderId).Distinct().ToList();
        if (scope == "usable" && accessibleIds.Count == 0) return [];
        var query = db.Set<LlmProvider>().AsNoTracking().Where(p => p.OrganizationId == orgId);
        query = scope == "manageable"
            ? viewAll ? query : query.Where(p => p.CreatedByMemberId == memberId)
            : query.Where(p => accessibleIds.Contains(p.Id));
        var providers = (await query.ToListAsync()).OrderByDescending(p => p.UpdatedAt).ToList();
        if (providers.Count == 0) return [];
        var ids = providers.Select(p => p.Id).ToList();
        var models = await db.Set<LlmProviderModel>().AsNoTracking().Where(m => ids.Contains(m.LlmProviderId)).ToListAsync();
        var mine = scope == "usable"
            ? (await db.Set<LlmProviderMemberCredential>().AsNoTracking().Where(c => c.OrganizationId == orgId && c.MemberId == memberId && c.State == "active" && ids.Contains(c.LlmProviderId)).Select(c => c.LlmProviderId).ToListAsync()).ToHashSet()
            : [];
        var access = await db.Set<LlmProviderAccess>().AsNoTracking().Where(a => ids.Contains(a.LlmProviderId)).ToListAsync();
        var memberIds = access.Where(a => a.MemberId != null).Select(a => a.MemberId!).Distinct().ToList();
        var people = await (from m in db.Members.AsNoTracking()
                            join u in db.Users.AsNoTracking() on m.UserId equals u.Id
                            where memberIds.Contains(m.Id)
                            select new { m.Id, m.Role, UserId = u.Id, u.Name, u.Email, u.Image }).ToDictionaryAsync(x => x.Id);
        var teamRefIds = access.Where(a => a.TeamId != null).Select(a => a.TeamId!).Distinct().ToList();
        var teams = await db.Teams.AsNoTracking().Where(t => teamRefIds.Contains(t.Id)).ToDictionaryAsync(t => t.Id);
        var accessibleSet = accessibleIds.ToHashSet();

        var result = new List<Dictionary<string, object?>>();
        foreach (var p in providers)
        {
            var manage = updateAll || p.CreatedByMemberId == memberId;
            var stored = manage || accessibleSet.Contains(p.Id);
            var config = Config(p);
            var secret = stored ? Secret(p) : null;
            var item = Row(p, stored ? config : ViewOnlyProvider(config));
            item["configRedacted"] = !stored;
            if (scope == "usable") item["hasMyCredential"] = p.CredentialMode == "per_member" && mine.Contains(p.Id);
            item["hasApiKey"] = stored && !string.IsNullOrWhiteSpace(secret);
            item["configuredEnvKeys"] = stored ? ProviderCredentials.ConfiguredEnvKeys(secret, ProviderCredentials.EnvNames(config)) : new List<string>();
            item["runtimeEnvKeys"] = stored ? ProviderCredentials.RuntimeEnvNames(p.Id, p.Source, config) : new List<string>();
            item["models"] = models.Where(m => m.LlmProviderId == p.Id).OrderBy(m => m.Name, StringComparer.InvariantCulture)
                .Select(m => new { id = m.ModelId, name = m.Name, config = stored ? Config(m) : ViewOnlyModel(Config(m)), createdAt = Responses.IsoUtc(m.CreatedAt) }).ToList();
            var rows = access.Where(a => a.LlmProviderId == p.Id).ToList();
            item["access"] = new
            {
                allMembers = rows.Any(a => a.MemberId == null && a.TeamId == null),
                membersHidden = !manage,
                members = rows.Where(a => a.MemberId != null && people.ContainsKey(a.MemberId)).Select(a =>
                {
                    var person = people[a.MemberId!];
                    return manage
                        ? (object)new { id = a.Id, orgMembershipId = a.MemberId, role = person.Role, user = new { id = person.UserId, name = person.Name, email = person.Email, image = person.Image }, createdAt = Responses.IsoUtc(a.CreatedAt) }
                        : new { id = a.Id, orgMembershipId = a.MemberId, createdAt = Responses.IsoUtc(a.CreatedAt) };
                }).ToList(),
                teams = rows.Where(a => a.TeamId != null && teams.ContainsKey(a.TeamId)).Select(a => new
                {
                    id = a.Id, teamId = a.TeamId, name = teams[a.TeamId!].Name, createdAt = Responses.IsoUtc(teams[a.TeamId!].CreatedAt), updatedAt = Responses.IsoUtc(teams[a.TeamId!].UpdatedAt),
                }).ToList(),
            };
            var via = accessible.Where(a => a.LlmProviderId == p.Id).ToList();
            item["accessibleVia"] = new
            {
                orgMembershipIds = via.Where(a => a.MemberId != null).Select(a => a.MemberId!).Distinct().ToList(),
                teamIds = via.Where(a => a.TeamId != null).Select(a => a.TeamId!).Distinct().ToList(),
            };
            result.Add(item);
        }
        return result;
    }

    /// <summary>The row's own fields, as the reference spreads them (the credential is never among them).</summary>
    public static Dictionary<string, object?> Row(LlmProvider p, JsonObject config) => new()
    {
        ["externalKey"] = p.ExternalKey, ["id"] = p.Id, ["organizationId"] = p.OrganizationId, ["createdByOrgMembershipId"] = p.CreatedByMemberId,
        ["source"] = p.Source, ["providerId"] = p.ProviderId, ["name"] = p.Name, ["providerConfig"] = config, ["credentialMode"] = p.CredentialMode,
        ["createdAt"] = Responses.IsoUtc(p.CreatedAt), ["updatedAt"] = Responses.IsoUtc(p.UpdatedAt),
    };

    private static string? ShortText(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s) && s.Length <= 255 ? s : null;

    /// <summary>What a view-only caller sees of a provider: id, name and npm only (any other stored field could carry a credential).</summary>
    public static JsonObject ViewOnlyProvider(JsonObject c)
    {
        var o = new JsonObject();
        foreach (var k in new[] { "id", "name", "npm" }) if (ShortText(c[k]) is { } s) o[k] = s;
        return o;
    }

    /// <summary>What a view-only caller sees of a model: id, name and numeric limits only.</summary>
    public static JsonObject ViewOnlyModel(JsonObject c)
    {
        var o = new JsonObject();
        foreach (var k in new[] { "id", "name" }) if (ShortText(c[k]) is { } s) o[k] = s;
        if (c["limit"] is JsonObject limit)
        {
            var picked = new JsonObject();
            foreach (var k in new[] { "context", "input", "output" })
                if (limit[k] is JsonValue v && v.TryGetValue<double>(out var d) && double.IsFinite(d)) picked[k] = v.DeepClone();
            if (picked.Count > 0) o["limit"] = picked;
        }
        return o;
    }

    // ---- writing ---------------------------------------------------------------------------------------------------------------------------

    public async Task<NormalizedProvider> NormalizeAsync(ProviderWrite input, LlmProvider? existing)
    {
        JsonObject providerConfig;
        string providerId;
        List<CatalogModel> models;
        if (input.Source == "models_dev")
        {
            CatalogProvider? provider;
            try { provider = await catalog.FindAsync(input.ProviderId ?? ""); }
            catch (CatalogUnavailableException e) { throw new ProviderFailure(502, "provider_catalog_unavailable", e.Message); }
            if (provider is null) throw new ProviderFailure(404, "provider_not_found", "The selected provider was not found in models.dev.");
            if (provider.Npm == "@ai-sdk/amazon-bedrock/mantle" || provider.Id == MicrosoftFoundryProviderId)
                throw new ProviderFailure(400, "gateway_only_provider", $"{provider.Name} is available through AI Gateway, not Bring your own keys.");
            // Azure model lists are the resource's deployments, which can be named anything.
            var allowDeploymentIds = provider.Npm == "@ai-sdk/azure";
            models = [];
            foreach (var modelId in (input.ModelIds ?? []).Distinct())
            {
                var model = provider.Models.FirstOrDefault(m => m.Id == modelId);
                if (model is null)
                {
                    if (!allowDeploymentIds) throw new ProviderFailure(404, "model_not_found", $"Model {modelId} is not available for {provider.Name}.");
                    model = new CatalogModel(modelId, modelId, new JsonObject { ["id"] = modelId, ["name"] = modelId });
                }
                models.Add(model);
            }
            providerConfig = (JsonObject)provider.Config.DeepClone();
            providerId = provider.Id;
        }
        else
        {
            try
            {
                var custom = CustomProviderConfig.Normalize(input.CustomConfigText, input.HasCustomConfig ? input.CustomConfig : null);
                providerConfig = custom.ProviderConfig;
                providerId = custom.ProviderId;
                models = custom.Models;
            }
            catch (CustomProviderConfigException e) { throw new ProviderFailure(400, "invalid_custom_provider_config", e.Message); }
        }
        var apiKey = ResolveCredential(providerConfig, existing, input.ApiKey, input.ApiKeys);
        return new NormalizedProvider(input.Source, providerId, input.Name, providerConfig, models, apiKey);
    }

    public string? ResolveCredential(JsonObject providerConfig, LlmProvider? existing, string? apiKey, IReadOnlyDictionary<string, string>? apiKeys)
    {
        try
        {
            var value = ProviderCredentials.Resolve(ProviderCredentials.EnvNames(providerConfig), existing is null ? null : Secret(existing),
                existing is null ? [] : ProviderCredentials.EnvNames(Config(existing)), apiKey, apiKeys);
            // Only a credential change is checked, so unrelated edits still save.
            if ((apiKey is not null || apiKeys is not null) && ProviderCredentials.BedrockError(providerConfig, value) is { } error) throw new ProviderCredentialException(error);
            return value;
        }
        catch (ProviderCredentialException e) { throw new ProviderFailure(400, "invalid_api_keys", e.Message); }
    }

    public async Task<List<string>> ResolveMembersAsync(string orgId, IReadOnlyCollection<string> values)
    {
        var unique = values.Distinct().ToList();
        if (unique.Count == 0) return [];
        var found = await db.Members.AsNoTracking().CountAsync(m => m.OrganizationId == orgId && unique.Contains(m.Id));
        if (found != unique.Count) throw new ProviderFailure(404, "member_not_found");
        return unique;
    }

    public async Task<List<string>> ResolveTeamsAsync(string orgId, IReadOnlyCollection<string> values)
    {
        var unique = values.Distinct().ToList();
        if (unique.Count == 0) return [];
        var found = await db.Teams.AsNoTracking().CountAsync(t => t.OrganizationId == orgId && unique.Contains(t.Id));
        if (found != unique.Count) throw new ProviderFailure(404, "team_not_found");
        return unique;
    }

    private void AddModels(string providerId, List<CatalogModel> models, DateTime now)
    {
        foreach (var m in models)
            db.Set<LlmProviderModel>().Add(new LlmProviderModel { Id = Ids.New("lpm"), LlmProviderId = providerId, ModelId = m.Id, Name = m.Name, ModelConfigJson = m.Config.ToJsonString(), CreatedAt = now });
    }

    /// <summary>The access rows for a write: the workspace-wide row plus the creator's, or the creator, the people and the teams named.</summary>
    private void AddAccess(string providerId, string creatorMemberId, bool allMembers, List<string> memberIds, List<string> teamIds, DateTime now)
    {
        LlmProviderAccess Row(string? member, string? team) => new() { Id = Ids.New("lpa"), LlmProviderId = providerId, MemberId = member, TeamId = team, CreatedAt = now };
        if (allMembers)
        {
            db.Set<LlmProviderAccess>().Add(Row(null, null));
            db.Set<LlmProviderAccess>().Add(Row(creatorMemberId, null));
            return;
        }
        foreach (var member in new[] { creatorMemberId }.Concat(memberIds).Distinct()) db.Set<LlmProviderAccess>().Add(Row(member, null));
        foreach (var team in teamIds) db.Set<LlmProviderAccess>().Add(Row(null, team));
    }

    public async Task<LlmProvider> CreateAsync(OrgContext c, ProviderWrite input, string? externalKey)
    {
        var normalized = await NormalizeAsync(input, null);
        var orgId = c.Organization.Id;
        var members = await ResolveMembersAsync(orgId, input.MemberIds);
        var teams = await ResolveTeamsAsync(orgId, input.TeamIds);
        var now = DateTime.UtcNow;
        var provider = new LlmProvider
        {
            Id = Ids.New("lpr"), OrganizationId = orgId, ExternalKey = externalKey, CreatedByMemberId = c.Member.Id, Source = normalized.Source,
            ProviderId = normalized.ProviderId, Name = normalized.Name, ProviderConfigJson = normalized.ProviderConfig.ToJsonString(), CredentialMode = input.CredentialMode,
            ApiKeyEnc = normalized.ApiKey is null ? null : box.Encrypt(normalized.ApiKey), CreatedAt = now, UpdatedAt = now,
        };
        await using var tx = await db.Database.BeginTransactionAsync();
        db.Set<LlmProvider>().Add(provider);
        AddModels(provider.Id, normalized.Models, now);
        AddAccess(provider.Id, c.Member.Id, input.AllMembers, members, teams, now);
        await db.SaveChangesAsync();
        await tx.CommitAsync();
        return provider;
    }

    public async Task<LlmProvider> UpdateAsync(OrgContext c, LlmProvider provider, ProviderWrite input)
    {
        var normalized = await NormalizeAsync(input, provider);
        var orgId = c.Organization.Id;
        var members = await ResolveMembersAsync(orgId, input.MemberIds);
        var teams = await ResolveTeamsAsync(orgId, input.TeamIds);
        var now = DateTime.UtcNow;
        await using var tx = await db.Database.BeginTransactionAsync();
        if (provider.CredentialMode != input.CredentialMode)
            await db.Set<LlmProviderMemberCredential>().Where(x => x.LlmProviderId == provider.Id).ExecuteDeleteAsync();
        await db.Set<LlmProviderModel>().Where(x => x.LlmProviderId == provider.Id).ExecuteDeleteAsync();
        await db.Set<LlmProviderAccess>().Where(x => x.LlmProviderId == provider.Id).ExecuteDeleteAsync();
        provider.Source = normalized.Source; provider.ProviderId = normalized.ProviderId; provider.Name = normalized.Name;
        provider.ProviderConfigJson = normalized.ProviderConfig.ToJsonString(); provider.CredentialMode = input.CredentialMode;
        provider.ApiKeyEnc = normalized.ApiKey is null ? null : box.Encrypt(normalized.ApiKey);
        provider.UpdatedAt = now > provider.UpdatedAt ? now : provider.UpdatedAt.AddMilliseconds(1);
        AddModels(provider.Id, normalized.Models, now);
        AddAccess(provider.Id, provider.CreatedByMemberId, input.AllMembers, members, teams, now);
        await db.SaveChangesAsync();
        await tx.CommitAsync();
        return provider;
    }

    public async Task DeleteAsync(LlmProvider provider)
    {
        await using var tx = await db.Database.BeginTransactionAsync();
        await db.Set<LlmProviderMemberCredential>().Where(x => x.LlmProviderId == provider.Id).ExecuteDeleteAsync();
        await db.Set<LlmProviderAccess>().Where(x => x.LlmProviderId == provider.Id).ExecuteDeleteAsync();
        await db.Set<LlmProviderModel>().Where(x => x.LlmProviderId == provider.Id).ExecuteDeleteAsync();
        await db.Set<LlmProvider>().Where(x => x.Id == provider.Id).ExecuteDeleteAsync();
        await tx.CommitAsync();
    }

    /// <summary>The write response: the row with its derived credential facts (never the credential).</summary>
    public Dictionary<string, object?> WriteJson(LlmProvider p)
    {
        var config = Config(p);
        var secret = Secret(p);
        var item = Row(p, config);
        item["hasApiKey"] = !string.IsNullOrEmpty(secret);
        item["configuredEnvKeys"] = ProviderCredentials.ConfiguredEnvKeys(secret, ProviderCredentials.EnvNames(config));
        item["runtimeEnvKeys"] = ProviderCredentials.RuntimeEnvNames(p.Id, p.Source, config);
        return item;
    }

    /// <summary>What a granted person's desktop receives to call the provider: the configuration under runtime env names, the credential and the models.</summary>
    public async Task<Dictionary<string, object?>> ConnectJsonAsync(LlmProvider p, string memberId)
    {
        var credential = ProviderCredentials.Decode(Secret(p));
        string? memberState = null;
        if (p.CredentialMode == "per_member")
        {
            var binding = await db.Set<LlmProviderMemberCredential>().AsNoTracking().FirstOrDefaultAsync(x => x.OrganizationId == p.OrganizationId && x.LlmProviderId == p.Id && x.MemberId == memberId);
            memberState = binding?.State ?? "missing";
            credential = memberState == "active" && binding is not null ? ProviderCredentials.Decode(box.Decrypt(binding.SecretEnc)) : new DecodedCredential(null, null);
        }
        var (config, apiKeys) = ProviderCredentials.ToRuntime(p.Id, p.Source, Config(p), credential.ApiKeys);
        var item = Row(p, config);
        item["apiKeys"] = apiKeys;
        item["apiKey"] = credential.ApiKey;
        if (memberState is not null) item["memberCredential"] = new { state = memberState };
        item["models"] = (await db.Set<LlmProviderModel>().AsNoTracking().Where(m => m.LlmProviderId == p.Id).ToListAsync())
            .OrderBy(m => m.Name, StringComparer.InvariantCulture)
            .Select(m => new { id = m.ModelId, name = m.Name, config = Config(m), createdAt = Responses.IsoUtc(m.CreatedAt) }).ToList();
        return item;
    }

    // ---- people's own keys -----------------------------------------------------------------------------------------------------------------

    public enum WriteOutcome { Ok, VersionConflict, Blocked }

    public static object CredentialSummary(LlmProviderMemberCredential c) => new { state = c.State, version = c.Version, updatedAt = Responses.IsoUtc(c.UpdatedAt) };

    /// <summary>
    /// Stores one member's credential (version + 1). Writes for a workspace queue behind its row. A blocked credential is the administrator's: a member's
    /// own write leaves it alone (<see cref="WriteOutcome.Blocked"/>); the administrator's write is the way to unblock it.
    /// </summary>
    public async Task<(WriteOutcome Outcome, LlmProviderMemberCredential? Credential)> UpsertMemberCredentialAsync(
        string orgId, string providerId, string memberId, string secret, string createdBy, bool allowBlockedOverwrite,
        string? externalPrincipalId = null, string? externalCredentialId = null, int? expectedVersion = null)
    {
        await using var tx = await db.Database.BeginTransactionAsync();
        await db.LockOrganizationAsync(orgId);
        var existing = await db.Set<LlmProviderMemberCredential>().FirstOrDefaultAsync(x => x.OrganizationId == orgId && x.LlmProviderId == providerId && x.MemberId == memberId);
        if (existing?.State == "blocked" && !allowBlockedOverwrite) return (WriteOutcome.Blocked, null);
        if (expectedVersion is not null && existing?.Version != expectedVersion) return (WriteOutcome.VersionConflict, null);
        var now = DateTime.UtcNow;
        if (existing is null)
        {
            existing = new LlmProviderMemberCredential
            {
                Id = Ids.New("lpc"), OrganizationId = orgId, LlmProviderId = providerId, MemberId = memberId, SecretEnc = box.Encrypt(secret),
                ExternalPrincipalId = externalPrincipalId, ExternalCredentialId = externalCredentialId, State = "active", Version = 1, CreatedBy = createdBy, CreatedAt = now, UpdatedAt = now,
            };
            db.Set<LlmProviderMemberCredential>().Add(existing);
        }
        else
        {
            existing.SecretEnc = box.Encrypt(secret);
            existing.ExternalPrincipalId = externalPrincipalId ?? existing.ExternalPrincipalId;
            existing.ExternalCredentialId = externalCredentialId ?? existing.ExternalCredentialId;
            existing.State = "active";
            existing.Version += 1;
            existing.CreatedBy = createdBy;
            existing.UpdatedAt = now;
        }
        await db.SaveChangesAsync();
        await tx.CommitAsync();
        return (WriteOutcome.Ok, existing);
    }

    /// <summary>Removes the member's own credential. A blocked one stays (deleting it would let them make a new active one): returns false then.</summary>
    public async Task<bool> DeleteOwnCredentialAsync(string orgId, string providerId, string memberId)
    {
        await using var tx = await db.Database.BeginTransactionAsync();
        await db.LockOrganizationAsync(orgId);
        var existing = await db.Set<LlmProviderMemberCredential>().FirstOrDefaultAsync(x => x.OrganizationId == orgId && x.LlmProviderId == providerId && x.MemberId == memberId);
        if (existing is null) return true;
        if (existing.State == "blocked") return false;
        db.Remove(existing);
        await db.SaveChangesAsync();
        await tx.CommitAsync();
        return true;
    }

    public async Task<LlmProviderMemberCredential?> BlockAsync(string orgId, string providerId, string memberId)
    {
        await using var tx = await db.Database.BeginTransactionAsync();
        await db.LockOrganizationAsync(orgId);
        var existing = await db.Set<LlmProviderMemberCredential>().FirstOrDefaultAsync(x => x.OrganizationId == orgId && x.LlmProviderId == providerId && x.MemberId == memberId);
        if (existing is null) return null;
        existing.State = "blocked";
        existing.Version += 1;
        existing.UpdatedAt = DateTime.UtcNow;
        await db.SaveChangesAsync();
        await tx.CommitAsync();
        return existing;
    }

    public async Task<List<object>> MemberCredentialsAsync(string orgId, string providerId)
    {
        var memberIds = await GrantedMemberIdsAsync(orgId, providerId);
        var credentials = await db.Set<LlmProviderMemberCredential>().AsNoTracking()
            .Where(x => x.OrganizationId == orgId && x.LlmProviderId == providerId && memberIds.Contains(x.MemberId)).ToDictionaryAsync(x => x.MemberId);
        return memberIds.Order(StringComparer.Ordinal).Select(id =>
        {
            credentials.TryGetValue(id, out var c);
            return (object)new
            {
                orgMembershipId = id, state = c?.State ?? "missing", externalPrincipalId = c?.ExternalPrincipalId, externalCredentialId = c?.ExternalCredentialId,
                version = c?.Version, updatedAt = c is null ? null : Responses.IsoUtc(c.UpdatedAt),
            };
        }).ToList();
    }
}
