using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.Gateway;
using WorkAI360.Api.Features.Connections;

namespace WorkAI360.Api.Features.Gateway;

/// <summary>A refusal in the reference's gateway shape: <c>{error, message?}</c>.</summary>
public sealed class GatewayError(int status, string code, string? message = null) : Exception(message ?? code)
{
    public int Status { get; } = status;
    public string Code { get; } = code;
    public string? Text { get; } = message;
    public IResult ToResult() => Text is null ? Results.Json(new { error = Code }, statusCode: Status) : Results.Json(new { error = Code, message = Text }, statusCode: Status);

    /// <summary>The reference's mapping of a LiteLLM failure (liteLlmErrorResponse).</summary>
    public static GatewayError From(LiteLlmException e) => new(e.Code is "invalid_base_url" or "no_models" ? 400 : 409, "litellm_" + e.Code, e.Message);
}

public sealed record GatewayAudience(string Type, string? Id)
{
    public string Key => Type switch { "team" => $"team:{Id}", "member" => $"member:{Id}", _ => "organization" };
}

public sealed record SyncResult(int ModelCount, int GroupCount, int TeamCount, int People, int Keys, int Removed, List<string> Warnings)
{
    public object ToJson() => new
    {
        modelCount = ModelCount, groupCount = GroupCount, teamCount = TeamCount,
        members = new { matched = 0, rejected = 0, unavailable = 0, removed = 0 },
        warnings = Warnings,
        issued = new { people = People, keys = Keys, notInLiteLlm = 0, noKeyToMirror = 0, noModels = 0, errors = Warnings.Count, removed = Removed },
    };
}

/// <summary>
/// The AI Gateway over LiteLLM: providers, synced models, model groups, access grants, and the per-person LiteLLM keys Den issues. LiteLLM serves
/// the requests; Den decides who may call which model and keeps each person's key in step with that (see docs/features/gateway.md).
/// </summary>
public sealed class GatewayService(DenDbContext db, LiteLlmClients clients, SecretBox box, IOptions<GatewayOptions> options, ILogger<GatewayService> log)
{
    public const string LiteLlmProviderId = "litellm";
    public const string AllModelsGroupName = "All LiteLLM models";
    public const string EnvName = "LITELLM_API_KEY";

    public GatewayOptions Options => options.Value;

    public LiteLlmClient ClientFor(GatewayProvider p) =>
        p.UsesDeploymentProxy ? clients.Deployment() : clients.Workspace(p.AdminBaseUrl!, box.Decrypt(p.AdminKeyEnc) ?? throw new GatewayError(409, "litellm_not_configured", "The provider has no LiteLLM admin key."));

    public string InferenceBase(GatewayProvider p) => clients.InferenceBaseFor(p.UsesDeploymentProxy, p.AdminBaseUrl);

    public static async Task<T> CallAsync<T>(Func<Task<T>> run)
    {
        try { return await run(); }
        catch (LiteLlmException e) { throw GatewayError.From(e); }
    }

    public async Task<GatewayProvider> GetAsync(string orgId, string id) =>
        await db.Set<GatewayProvider>().FirstOrDefaultAsync(p => p.OrganizationId == orgId && p.Id == id) ?? throw new GatewayError(404, "inference_provider_not_found");

    public async Task<List<string>> TeamIdsAsync(string memberId) => await db.TeamMembers.AsNoTracking().Where(t => t.MemberId == memberId).Select(t => t.TeamId).ToListAsync();

    /// <summary>The model ids a member may call on a provider: active groups granted to the workspace, one of their teams, or them. Empty when disabled.</summary>
    public async Task<List<string>> EffectiveModelsAsync(GatewayProvider p, string memberId, IReadOnlyCollection<string>? teamIds = null)
    {
        if (p.Status != "active") return [];
        teamIds ??= await TeamIdsAsync(memberId);
        var keys = teamIds.Select(t => $"team:{t}").Append($"member:{memberId}").Append("organization").ToList();
        return await (from a in db.Set<GatewayAccessGrant>().AsNoTracking()
                      join g in db.Set<GatewayModelGroup>().AsNoTracking() on a.ModelGroupId equals g.Id
                      join l in db.Set<GatewayModelGroupModel>().AsNoTracking() on g.Id equals l.ModelGroupId
                      join m in db.Set<GatewayProviderModel>().AsNoTracking() on l.GatewayProviderModelId equals m.Id
                      where a.GatewayProviderId == p.Id && g.GatewayProviderId == p.Id && m.GatewayProviderId == p.Id && g.Status == "active" && keys.Contains(a.AudienceKey)
                      select m.ModelId).Distinct().OrderBy(x => x).ToListAsync();
    }

    /// <summary>Validates audiences against this workspace (ids from elsewhere are 404, as the reference).</summary>
    public async Task CheckAudiencesAsync(string orgId, IEnumerable<GatewayAudience> audiences)
    {
        foreach (var a in audiences)
        {
            if (a.Type == "member" && !await db.Members.AnyAsync(m => m.Id == a.Id && m.OrganizationId == orgId)) throw new GatewayError(404, "member_not_found");
            if (a.Type == "team" && !await db.Teams.AnyAsync(t => t.Id == a.Id && t.OrganizationId == orgId)) throw new GatewayError(404, "team_not_found");
        }
    }

    public GatewayAccessGrant NewGrant(string providerId, string groupId, GatewayAudience a) => new()
    {
        Id = Ids.New("ipa"), GatewayProviderId = providerId, ModelGroupId = groupId, AudienceKey = a.Key,
        MemberId = a.Type == "member" ? a.Id : null, TeamId = a.Type == "team" ? a.Id : null, CreatedAt = DateTime.UtcNow,
    };

    /// <summary>Creates a LiteLLM provider: proves the key manages the proxy, reads its models, makes its team, the all-models group and the grants.</summary>
    public async Task<(GatewayProvider Provider, SyncResult Sync)> CreateAsync(OrgContext c, string name, bool deployment, string? root, string? adminKey, List<GatewayAudience> audiences, CancellationToken ct)
    {
        await CheckAudiencesAsync(c.Organization.Id, audiences);
        var now = DateTime.UtcNow;
        var provider = new GatewayProvider
        {
            Id = Ids.New("ipr"), OrganizationId = c.Organization.Id, CreatedByMemberId = c.Member.Id, ProviderId = LiteLlmProviderId, Name = name, Status = "active",
            UsesDeploymentProxy = deployment, AdminBaseUrl = deployment ? null : root, AdminKeyEnc = deployment ? null : box.Encrypt(adminKey!), CreatedAt = now, UpdatedAt = now,
        };
        var client = ClientFor(provider);
        var models = await CallAsync(async () =>
        {
            await client.RequireAdminAsync(ct);
            var listed = await client.ListModelsAsync(ct);
            if (listed.Count == 0) throw new LiteLlmException("no_models", "The LiteLLM proxy serves no chat models for this key.");
            provider.LiteLlmTeamId = await client.EnsureTeamAsync(null, $"openwork-{provider.Id}", listed.Select(m => m.Id).ToList(), ct);
            return listed;
        });
        provider.LastSyncedAt = now;
        db.Set<GatewayProvider>().Add(provider);
        var group = new GatewayModelGroup { Id = Ids.New("gmg"), GatewayProviderId = provider.Id, Name = AllModelsGroupName, Description = "Every model the LiteLLM proxy serves. Kept in step at each sync.", Status = "active", CreatedAt = now, UpdatedAt = now };
        db.Set<GatewayModelGroup>().Add(group);
        foreach (var m in models)
        {
            var row = new GatewayProviderModel { Id = Ids.New("ipm"), GatewayProviderId = provider.Id, ModelId = m.Id, Name = m.Id, ConfigJson = m.Config.ToJsonString(), CreatedAt = now };
            db.Set<GatewayProviderModel>().Add(row);
            db.Set<GatewayModelGroupModel>().Add(new GatewayModelGroupModel { ModelGroupId = group.Id, GatewayProviderModelId = row.Id });
        }
        foreach (var a in audiences.DistinctBy(a => a.Key)) db.Set<GatewayAccessGrant>().Add(NewGrant(provider.Id, group.Id, a));
        await db.SaveChangesAsync(ct);
        return (provider, new SyncResult(models.Count, 1, 1, 0, 0, 0, []));
    }

    /// <summary>
    /// Re-reads the proxy's models: new ones join the all-models group, gone ones leave every group; the team's model list follows; every issued key
    /// is brought in line with what its holder may now call. A failed read keeps the last catalog and records the error.
    /// </summary>
    public async Task<SyncResult> SyncAsync(GatewayProvider p, CancellationToken ct)
    {
        var client = ClientFor(p);
        List<LiteLlmModel> models;
        try { models = await client.ListModelsAsync(ct); }
        catch (LiteLlmException e)
        {
            p.LastSyncError = e.Message.Length > 1000 ? e.Message[..1000] : e.Message;
            p.UpdatedAt = DateTime.UtcNow;
            await db.SaveChangesAsync(ct);
            throw GatewayError.From(e);
        }
        var now = DateTime.UtcNow;
        var existing = await db.Set<GatewayProviderModel>().Where(m => m.GatewayProviderId == p.Id).ToListAsync(ct);
        var wanted = models.ToDictionary(m => m.Id, StringComparer.Ordinal);
        var gone = existing.Where(m => !wanted.ContainsKey(m.ModelId)).ToList();
        var goneIds = gone.Select(m => m.Id).ToList();
        await db.Set<GatewayModelGroupModel>().Where(l => goneIds.Contains(l.GatewayProviderModelId)).ExecuteDeleteAsync(ct);
        db.Set<GatewayProviderModel>().RemoveRange(gone);
        var allGroup = await db.Set<GatewayModelGroup>().FirstOrDefaultAsync(g => g.GatewayProviderId == p.Id && g.Name == AllModelsGroupName, ct);
        foreach (var m in models)
        {
            var row = existing.FirstOrDefault(e => e.ModelId == m.Id);
            if (row is null)
            {
                row = new GatewayProviderModel { Id = Ids.New("ipm"), GatewayProviderId = p.Id, ModelId = m.Id, Name = m.Id, ConfigJson = m.Config.ToJsonString(), CreatedAt = now };
                db.Set<GatewayProviderModel>().Add(row);
                if (allGroup is not null) db.Set<GatewayModelGroupModel>().Add(new GatewayModelGroupModel { ModelGroupId = allGroup.Id, GatewayProviderModelId = row.Id });
            }
            else row.ConfigJson = m.Config.ToJsonString();
        }
        var warnings = new List<string>();
        try { p.LiteLlmTeamId = await client.EnsureTeamAsync(p.LiteLlmTeamId, $"openwork-{p.Id}", models.Select(m => m.Id).ToList(), ct); }
        catch (LiteLlmException e) { warnings.Add(e.Message); }
        p.LastSyncedAt = now;
        p.LastSyncError = null;
        p.UpdatedAt = now;
        await db.SaveChangesAsync(ct);
        var (people, keys, removed, errors) = await ReconcileAsync(p, ct);
        warnings.AddRange(errors);
        var groupCount = await db.Set<GatewayModelGroup>().CountAsync(g => g.GatewayProviderId == p.Id, ct);
        return new SyncResult(models.Count, groupCount, p.LiteLlmTeamId is null ? 0 : 1, people, keys, removed, warnings);
    }

    /// <summary>
    /// Brings every issued key of a provider in line with access: a holder who may call nothing (left, lost the grant, provider disabled) loses the key in
    /// LiteLLM and here; a holder whose models changed gets the new list on the same key. Returns (people, keys kept, removed, errors).
    /// </summary>
    public async Task<(int People, int Keys, int Removed, List<string> Errors)> ReconcileAsync(GatewayProvider p, CancellationToken ct)
    {
        var errors = new List<string>();
        var issued = await db.Set<GatewayIssuedKey>().Where(k => k.GatewayProviderId == p.Id).ToListAsync(ct);
        if (issued.Count == 0) return (0, 0, 0, errors);
        LiteLlmClient? client = null;
        int kept = 0, removed = 0;
        foreach (var key in issued)
        {
            var stillMember = await db.Members.AnyAsync(m => m.Id == key.MemberId && m.OrganizationId == p.OrganizationId && m.UserId == key.UserId, ct);
            var models = stillMember ? await EffectiveModelsAsync(p, key.MemberId) : [];
            var current = JsonSerializer.Deserialize<List<string>>(key.ModelsJson) ?? [];
            try
            {
                client ??= ClientFor(p);
                if (models.Count == 0)
                {
                    await client.DeleteKeysAsync([key.TokenHash], ct);
                    db.Set<GatewayIssuedKey>().Remove(key);
                    removed++;
                }
                else
                {
                    if (!models.SequenceEqual(current, StringComparer.Ordinal))
                    {
                        await client.UpdateKeyModelsAsync(key.TokenHash, models, ct);
                        key.ModelsJson = JsonSerializer.Serialize(models);
                        key.UpdatedAt = DateTime.UtcNow;
                    }
                    kept++;
                }
            }
            catch (Exception e) when (e is LiteLlmException or GatewayError)
            {
                errors.Add(e.Message);
                log.LogWarning("LiteLLM key reconcile failed for provider {Provider}: {Message}", p.Id, e.Message);
            }
        }
        await db.SaveChangesAsync(ct);
        return (issued.Select(k => k.MemberId).Distinct().Count(), kept, removed, errors);
    }

    /// <summary>
    /// The caller's own LiteLLM key for a provider, issued on first use and kept in step with their access. Two first calls at once end with one key:
    /// the loser's LiteLLM key is deleted.
    /// </summary>
    public async Task<(string Key, List<string> Models)> EnsureKeyAsync(GatewayProvider p, OrgContext c, IReadOnlyCollection<string> models, CancellationToken ct)
    {
        var client = ClientFor(p);
        var existing = await db.Set<GatewayIssuedKey>().FirstOrDefaultAsync(k => k.GatewayProviderId == p.Id && k.MemberId == c.Member.Id, ct);
        if (existing is not null && existing.UserId == c.Member.UserId && box.Decrypt(existing.KeyEnc) is { } value)
        {
            var current = JsonSerializer.Deserialize<List<string>>(existing.ModelsJson) ?? [];
            if (!models.SequenceEqual(current, StringComparer.Ordinal))
            {
                await CallAsync(async () => { await client.UpdateKeyModelsAsync(existing.TokenHash, models, ct); return true; });
                existing.ModelsJson = JsonSerializer.Serialize(models);
                existing.UpdatedAt = DateTime.UtcNow;
                await db.SaveChangesAsync(ct);
            }
            return (value, models.ToList());
        }
        if (existing is not null)
        {
            // A key for an earlier membership with the same id, or unreadable material: replace it.
            try { await client.DeleteKeysAsync([existing.TokenHash], ct); } catch (LiteLlmException) { }
            db.Set<GatewayIssuedKey>().Remove(existing);
            await db.SaveChangesAsync(ct);
        }
        var metadata = new JsonObject { ["source"] = "openwork", ["organizationId"] = p.OrganizationId, ["memberId"] = c.Member.Id, ["providerId"] = p.Id };
        var issued = await CallAsync(() => client.IssueKeyAsync(c.Member.Id, p.LiteLlmTeamId, $"openwork-{p.Id}-{c.Member.Id}", models, metadata, ct));
        var now = DateTime.UtcNow;
        db.Set<GatewayIssuedKey>().Add(new GatewayIssuedKey
        {
            GatewayProviderId = p.Id, MemberId = c.Member.Id, OrganizationId = p.OrganizationId, UserId = c.Member.UserId, KeyEnc = box.Encrypt(issued.Key),
            TokenHash = issued.TokenHash, KeyPrefix = issued.Key.Length > 8 ? issued.Key[..8] : issued.Key, ModelsJson = JsonSerializer.Serialize(models), CreatedAt = now, UpdatedAt = now,
        });
        try
        {
            await db.SaveChangesAsync(ct);
            return (issued.Key, models.ToList());
        }
        catch (DbUpdateException)
        {
            db.ChangeTracker.Clear();
            try { await client.DeleteKeysAsync([issued.TokenHash], ct); } catch (LiteLlmException) { }
            var winner = await db.Set<GatewayIssuedKey>().AsNoTracking().FirstAsync(k => k.GatewayProviderId == p.Id && k.MemberId == c.Member.Id, ct);
            return (box.Decrypt(winner.KeyEnc)!, models.ToList());
        }
    }

    /// <summary>Deletes every LiteLLM key of a person in a workspace (they left or lost access). Best effort per provider; failures are logged and retried at the next sync.</summary>
    public async Task RevokePersonAsync(string userId, string organizationId, CancellationToken ct = default)
    {
        var keys = await db.Set<GatewayIssuedKey>().Where(k => k.OrganizationId == organizationId && k.UserId == userId).ToListAsync(ct);
        foreach (var group in keys.GroupBy(k => k.GatewayProviderId))
        {
            var provider = await db.Set<GatewayProvider>().AsNoTracking().FirstOrDefaultAsync(p => p.Id == group.Key, ct);
            try
            {
                if (provider is not null) await ClientFor(provider).DeleteKeysAsync(group.Select(k => k.TokenHash).ToList(), ct);
                db.Set<GatewayIssuedKey>().RemoveRange(group);
            }
            catch (Exception e) when (e is LiteLlmException or GatewayError)
            {
                log.LogWarning("Could not delete LiteLLM keys for provider {Provider}; the next sync retries: {Message}", group.Key, e.Message);
            }
        }
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Removes a provider: its keys and team in LiteLLM first (refused when LiteLLM cannot confirm, so no key outlives it), then its rows.</summary>
    public async Task DeleteAsync(GatewayProvider p, CancellationToken ct)
    {
        var client = ClientFor(p);
        var hashes = await db.Set<GatewayIssuedKey>().Where(k => k.GatewayProviderId == p.Id).Select(k => k.TokenHash).ToListAsync(ct);
        await CallAsync(async () =>
        {
            await client.DeleteKeysAsync(hashes, ct);
            if (p.LiteLlmTeamId is not null) await client.DeleteTeamAsync(p.LiteLlmTeamId, ct);
            return true;
        });
        var groupIds = await db.Set<GatewayModelGroup>().Where(g => g.GatewayProviderId == p.Id).Select(g => g.Id).ToListAsync(ct);
        await db.Set<GatewayModelGroupModel>().Where(l => groupIds.Contains(l.ModelGroupId)).ExecuteDeleteAsync(ct);
        await db.Set<GatewayAccessGrant>().Where(a => a.GatewayProviderId == p.Id).ExecuteDeleteAsync(ct);
        await db.Set<GatewayModelGroup>().Where(g => g.GatewayProviderId == p.Id).ExecuteDeleteAsync(ct);
        await db.Set<GatewayProviderModel>().Where(m => m.GatewayProviderId == p.Id).ExecuteDeleteAsync(ct);
        await db.Set<GatewayIssuedKey>().Where(k => k.GatewayProviderId == p.Id).ExecuteDeleteAsync(ct);
        await db.Set<GatewayProvider>().Where(x => x.Id == p.Id).ExecuteDeleteAsync(ct);
    }

    // ---- shapes ----------------------------------------------------------------------------------------------------------------------------------

    public JsonObject ProviderConfig(GatewayProvider p) => new()
    {
        ["id"] = LiteLlmProviderId, ["name"] = p.Name, ["npm"] = "@ai-sdk/openai-compatible", ["api"] = InferenceBase(p), ["env"] = new JsonArray(EnvName),
    };

    /// <summary>
    /// A provider as a person sees it (the reference's GatewayProviderSummary): only the models they may call, never a key. <paramref name="usable"/> are
    /// the caller's model ids.
    /// </summary>
    public async Task<JsonObject> SummaryAsync(GatewayProvider p, IReadOnlyCollection<string> usable)
    {
        var models = await db.Set<GatewayProviderModel>().AsNoTracking().Where(m => m.GatewayProviderId == p.Id).OrderBy(m => m.ModelId).ToListAsync();
        var groups = await (from l in db.Set<GatewayModelGroupModel>().AsNoTracking()
                            join g in db.Set<GatewayModelGroup>().AsNoTracking() on l.ModelGroupId equals g.Id
                            where g.GatewayProviderId == p.Id
                            select new { l.GatewayProviderModelId, g.Id, g.Name }).ToListAsync();
        var list = new JsonArray();
        foreach (var m in models.Where(m => usable.Contains(m.ModelId)))
        {
            var group = groups.FirstOrDefault(g => g.GatewayProviderModelId == m.Id);
            list.Add(new JsonObject
            {
                ["id"] = m.ModelId, ["name"] = m.Name, ["config"] = JsonNode.Parse(m.ConfigJson), ["upstreamModelId"] = m.ModelId,
                ["modelGroupId"] = group?.Id, ["modelGroupName"] = group?.Name,
            });
        }
        return new JsonObject
        {
            ["id"] = p.Id, ["providerId"] = p.ProviderId, ["name"] = p.Name, ["source"] = "openwork_gateway", ["credentialMode"] = "member",
            ["credentialStatus"] = "ready", ["authUrl"] = null, ["status"] = p.Status, ["createdAt"] = Responses.IsoUtc(p.CreatedAt), ["updatedAt"] = Responses.IsoUtc(p.UpdatedAt),
            ["providerConfig"] = ProviderConfig(p), ["modelIds"] = new JsonArray(), ["pinnedModelIds"] = new JsonArray(), ["models"] = list,
            ["modelAssignmentsComplete"] = true, ["authorizationRequests"] = new JsonArray(),
        };
    }

    /// <summary>A provider for people who manage the gateway (GatewayProviderDetails): every model, groups, grants, LiteLLM status. Never a key.</summary>
    public async Task<JsonObject> DetailsAsync(GatewayProvider p, bool identities)
    {
        var summary = await SummaryAsync(p, await db.Set<GatewayProviderModel>().AsNoTracking().Where(m => m.GatewayProviderId == p.Id).Select(m => m.ModelId).ToListAsync());
        var groups = await db.Set<GatewayModelGroup>().AsNoTracking().Where(g => g.GatewayProviderId == p.Id).OrderBy(g => g.CreatedAt).ThenBy(g => g.Id).ToListAsync();
        var links = await (from l in db.Set<GatewayModelGroupModel>().AsNoTracking()
                           join m in db.Set<GatewayProviderModel>().AsNoTracking() on l.GatewayProviderModelId equals m.Id
                           where m.GatewayProviderId == p.Id
                           select new { l.ModelGroupId, m.ModelId }).ToListAsync();
        var grants = await db.Set<GatewayAccessGrant>().AsNoTracking().Where(a => a.GatewayProviderId == p.Id).OrderBy(a => a.CreatedAt).ThenBy(a => a.Id).ToListAsync();
        var keys = await db.Set<GatewayIssuedKey>().AsNoTracking().Where(k => k.GatewayProviderId == p.Id).ToListAsync();
        var people = identities
            ? await (from m in db.Members.AsNoTracking() join u in db.Users.AsNoTracking() on m.UserId equals u.Id where m.OrganizationId == p.OrganizationId select new { m.Id, u.Name, u.Email }).ToListAsync()
            : [];
        var teams = await db.Teams.AsNoTracking().Where(t => t.OrganizationId == p.OrganizationId).Select(t => new { t.Id, t.Name }).ToListAsync();
        summary["settings"] = new JsonObject { ["upstreamBaseUrl"] = InferenceBase(p), ["deploymentProxy"] = p.UsesDeploymentProxy };
        summary["modelGroups"] = new JsonArray(groups.Select(g => (JsonNode)new JsonObject
        {
            ["id"] = g.Id, ["name"] = g.Name, ["description"] = g.Description, ["status"] = g.Status,
            ["modelIds"] = new JsonArray(links.Where(l => l.ModelGroupId == g.Id).Select(l => l.ModelId).Order(StringComparer.Ordinal).Select(x => (JsonNode)x).ToArray()),
        }).ToArray());
        summary["credentialSets"] = new JsonArray();
        summary["accessGrants"] = new JsonArray(grants.Select(a =>
        {
            var audience = new JsonObject { ["type"] = a.MemberId is not null ? "member" : a.TeamId is not null ? "team" : "organization" };
            if (a.MemberId is not null)
            {
                audience["memberId"] = a.MemberId;
                var person = people.FirstOrDefault(x => x.Id == a.MemberId);
                if (identities) { audience["name"] = person?.Name; audience["email"] = person?.Email; }
            }
            if (a.TeamId is not null) { audience["teamId"] = a.TeamId; audience["name"] = teams.FirstOrDefault(t => t.Id == a.TeamId)?.Name; }
            return (JsonNode)new JsonObject { ["id"] = a.Id, ["modelGroupId"] = a.ModelGroupId, ["audience"] = audience };
        }).ToArray());
        summary["litellm"] = new JsonObject
        {
            ["mode"] = "member", ["keySource"] = "issued", ["issueStrategy"] = "per_team", ["mirrorFallback"] = null,
            ["issuedMemberCount"] = keys.Select(k => k.MemberId).Distinct().Count(), ["attentionCount"] = 0, ["attention"] = new JsonArray(),
            ["baseUrl"] = InferenceBase(p), ["spendTracking"] = true, ["hasSyncKey"] = p.UsesDeploymentProxy || p.AdminKeyEnc is not null,
            ["lastSyncedAt"] = p.LastSyncedAt is { } s ? Responses.IsoUtc(s) : null, ["lastSyncError"] = p.LastSyncError,
            ["modelCount"] = await db.Set<GatewayProviderModel>().CountAsync(m => m.GatewayProviderId == p.Id),
            ["teamCount"] = p.LiteLlmTeamId is null ? 0 : 1, ["connectedMemberCount"] = 0, ["deploymentProxy"] = p.UsesDeploymentProxy,
        };
        summary["credentialCounts"] = new JsonObject { ["total"] = keys.Count, ["active"] = keys.Count, ["revoked"] = 0, ["refreshFailed"] = 0 };
        return summary;
    }
}

/// <summary>Takes a person's LiteLLM keys back when they lose access to a workspace (called by <see cref="CredentialRevocation"/>).</summary>
public sealed class GatewayAccessEnded(GatewayService gateway) : IMemberAccessEnded
{
    public Task OnAccessEndedAsync(string userId, string organizationId) => gateway.RevokePersonAsync(userId, organizationId);
}
