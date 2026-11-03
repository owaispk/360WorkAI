using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Connections;
using WorkAI360.Api.Features.Library;
using WorkAI360.Api.Features.PluginConnections;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Connections;

/// <summary>Who is acting: a person in a workspace with their teams.</summary>
public sealed record Caller(OrgContext Context, HashSet<string> TeamIds)
{
    public string OrgId => Context.Organization.Id;
    public string MemberId => Context.Member.Id;
    public bool Has(string permission) => Context.Permissions.Has(permission);
}

public sealed record AccessInput(bool OrgWide, IReadOnlyList<string> MemberIds, IReadOnlyList<string> TeamIds);

/// <summary>A usable credential for one person on one connection, or the reason there is none.</summary>
public sealed record Credential(bool Ok, string? Message, string? ApiKey, string? AccessToken, ConnectedAccount? Account);

/// <summary>A failure explained for an administrator: stable code, a message written by us, and a reference to quote to support.</summary>
public sealed record Diagnostic(string ReferenceId, string Phase, string Category, string Code, bool Retryable, string ActionOwner, string OperatorAction, string Message, int? HttpStatus, int? JsonRpcCode, string? ProviderMessage)
{
    public object ToJson() => new Dictionary<string, object?>
    {
        ["referenceId"] = ReferenceId, ["highestPassed"] = "reachable", ["phase"] = Phase, ["category"] = Category, ["code"] = Code, ["retryable"] = Retryable,
        ["actionOwner"] = ActionOwner, ["operatorAction"] = OperatorAction, ["message"] = Message,
    }.Concat(HttpStatus is { } h ? [new KeyValuePair<string, object?>("httpStatus", h)] : [])
     .Concat(JsonRpcCode is { } j ? [new KeyValuePair<string, object?>("jsonRpcCode", j)] : [])
     .Concat(ProviderMessage is { } p ? [new KeyValuePair<string, object?>("providerErrorMessage", p)] : [])
     .ToDictionary(kv => kv.Key, kv => kv.Value);
}

/// <summary>
/// Connection rules shared by the routes, the capability provider and the pages: who may use what, which credential a call carries (with
/// refresh), what a connection looks like on the wire, readiness checks, and the sign-in with an OAuth-protected server.
/// </summary>
public sealed class ConnectionService(DenDbContext db, SecretBox box, McpClient mcp, McpOAuth oauth, GuardedHttp http, OAuthUrls urls, PluginBindingStore bindings)
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, SemaphoreSlim> RefreshLocks = new();
    public const string CallbackPath = "/v1/mcp-connections/oauth/callback";

    public static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never };

    // ---------- who ----------

    public async Task<Caller> CallerAsync(OrgContext context)
    {
        var teams = await db.TeamMembers.AsNoTracking().Where(t => t.MemberId == context.Member.Id).Select(t => t.TeamId).ToListAsync();
        return new Caller(context, teams.ToHashSet());
    }

    public async Task<ExternalMcpConnection?> FindAsync(string orgId, string id) =>
        await db.Set<ExternalMcpConnection>().FirstOrDefaultAsync(c => c.OrganizationId == orgId && c.Id == id);

    public async Task<ExternalMcpConnection?> FindByKeyAsync(string orgId, string key) =>
        await db.Set<ExternalMcpConnection>().FirstOrDefaultAsync(c => c.OrganizationId == orgId && c.ExternalKey == key);

    public async Task<List<ExternalMcpConnection>> ListAllAsync(string orgId) =>
        await db.Set<ExternalMcpConnection>().AsNoTracking().Where(c => c.OrganizationId == orgId).OrderBy(c => c.CreatedAt).ThenBy(c => c.Id).ToListAsync();

    /// <summary>
    /// Connections granted to this person: to everyone, to them, or to one of their teams, or (through a plugin that needs them) because the plugin is
    /// shared with them. Being an admin grants nothing by itself.
    /// </summary>
    public async Task<List<ExternalMcpConnection>> UsableAsync(string orgId, string memberId, IReadOnlyCollection<string> teamIds)
    {
        var ids = await db.Set<ConnectionAccessGrant>().AsNoTracking()
            .Where(g => g.OrganizationId == orgId && (g.OrgWide || g.MemberId == memberId || (g.TeamId != null && teamIds.Contains(g.TeamId))))
            .Select(g => g.ConnectionId).Distinct().ToListAsync();
        ids.AddRange(await bindings.UsableConnectionIdsAsync(orgId, memberId, teamIds));
        ids = ids.Distinct().ToList();
        if (ids.Count == 0) return [];
        var retired = (await bindings.RetiredAsync(orgId, ids)).ToList();
        return await db.Set<ExternalMcpConnection>().AsNoTracking().Where(c => c.OrganizationId == orgId && ids.Contains(c.Id) && !retired.Contains(c.Id)).OrderBy(c => c.CreatedAt).ThenBy(c => c.Id).ToListAsync();
    }

    /// <summary>Every connection of the workspace except those retired with an archived plugin (the "all connections" list).</summary>
    public async Task<List<ExternalMcpConnection>> ListVisibleAsync(string orgId)
    {
        var all = await ListAllAsync(orgId);
        var retired = await bindings.RetiredAsync(orgId, all.Select(c => c.Id).ToList());
        return all.Where(c => !retired.Contains(c.Id)).ToList();
    }

    public async Task<bool> CanUseAsync(ExternalMcpConnection connection, string memberId, IReadOnlyCollection<string> teamIds) =>
        await db.Set<ConnectionAccessGrant>().AnyAsync(g => g.ConnectionId == connection.Id && g.OrganizationId == connection.OrganizationId
            && (g.OrgWide || g.MemberId == memberId || (g.TeamId != null && teamIds.Contains(g.TeamId))))
        || await bindings.CanUseAsync(connection.OrganizationId, connection.Id, memberId, teamIds);

    /// <summary>What a person may know about the plugins that need a connection (see <see cref="PluginBindingStore"/>).</summary>
    public Task<Provenance> ProvenanceAsync(Caller caller, string connectionId, bool everything = false) =>
        bindings.ProvenanceAsync(new Audience(caller.OrgId, caller.MemberId, caller.TeamIds, caller.Has("sharing.manage_all")), connectionId, everything);

    public Task<bool> IsManagedByPluginAsync(string orgId, string connectionId) => bindings.IsManagedAsync(orgId, connectionId);

    // ---------- access grants ----------

    /// <summary>Replaces who may use a connection, atomically. Org-wide stands alone (it already covers everyone). Unknown people or teams are refused by the caller first.</summary>
    public async Task ReplaceAccessAsync(string orgId, string connectionId, AccessInput access, string byMemberId)
    {
        // Changes to one connection's grants run one at a time in this process; across processes the unique indexes refuse a duplicate and the loser retries.
        var gate = AccessLocks.GetOrAdd(connectionId, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync();
        try
        {
            for (var attempt = 1; ; attempt++)
            {
                try
                {
                    // Inside a caller's transaction (an edit) the grants join it; otherwise this is one transaction of its own.
                    await using var tx = db.Database.CurrentTransaction is null ? await db.Database.BeginTransactionAsync() : null;
                    await db.Set<ConnectionAccessGrant>().Where(g => g.ConnectionId == connectionId).ExecuteDeleteAsync();
                    AddGrants(orgId, connectionId, access, byMemberId);
                    await db.SaveChangesAsync();
                    if (tx is not null) await tx.CommitAsync();
                    return;
                }
                catch (DbUpdateException) when (attempt < 3 && db.Database.CurrentTransaction is null)
                {
                    db.ChangeTracker.Clear();
                }
            }
        }
        finally { gate.Release(); }
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, SemaphoreSlim> AccessLocks = new();

    public void AddGrants(string orgId, string connectionId, AccessInput access, string byMemberId)
    {
        var now = DateTime.UtcNow;
        ConnectionAccessGrant Row() => new() { Id = Ids.New("emcag"), OrganizationId = orgId, ConnectionId = connectionId, CreatedByMemberId = byMemberId, CreatedAt = now };
        if (access.OrgWide) { var r = Row(); r.OrgWide = true; db.Add(r); return; }
        foreach (var m in access.MemberIds.Distinct()) { var r = Row(); r.MemberId = m; db.Add(r); }
        foreach (var t in access.TeamIds.Distinct()) { var r = Row(); r.TeamId = t; db.Add(r); }
    }

    public async Task<(bool OrgWide, List<string> MemberIds, List<string> TeamIds)> AccessOfAsync(string connectionId)
    {
        var grants = await db.Set<ConnectionAccessGrant>().AsNoTracking().Where(g => g.ConnectionId == connectionId).OrderBy(g => g.CreatedAt).ThenBy(g => g.Id).ToListAsync();
        return (grants.Any(g => g.OrgWide), grants.Where(g => g.MemberId != null).Select(g => g.MemberId!).ToList(), grants.Where(g => g.TeamId != null).Select(g => g.TeamId!).ToList());
    }

    // ---------- stored settings ----------

    public List<(string Name, string Value)> RequestHeaders(ExternalMcpConnection c)
    {
        var plain = box.Decrypt(c.RequestHeadersEnc);
        if (plain is null) return [];
        try
        {
            return (JsonNode.Parse(plain) as JsonArray)?.OfType<JsonObject>()
                .Where(o => o["name"] is JsonValue && o["value"] is JsonValue)
                .Select(o => (o["name"]!.GetValue<string>(), o["value"]!.GetValue<string>())).ToList() ?? [];
        }
        catch (JsonException) { return []; }
    }

    public string? EncryptHeaders(IReadOnlyList<(string Name, string Value)> headers) =>
        headers.Count == 0 ? null : box.Encrypt(new JsonArray(headers.Select(h => (JsonNode)new JsonObject { ["name"] = h.Name, ["value"] = h.Value }).ToArray()).ToJsonString());

    public string? Encrypt(string? value) => value is null ? null : box.Encrypt(value);

    public JsonObject OAuthConfig(ExternalMcpConnection c) => (c.OAuthConfigJson is null ? null : JsonNode.Parse(c.OAuthConfigJson) as JsonObject) ?? new JsonObject();

    public (bool AllDisabled, List<string> Disabled, string? By, string? At) Policy(ExternalMcpConnection c)
    {
        if (c.ToolPolicyJson is null) return (false, [], null, null);
        var o = JsonNode.Parse(c.ToolPolicyJson) as JsonObject;
        if (o is null) return (false, [], null, null);
        return (o["allDisabled"]?.GetValue<bool>() ?? false, (o["disabledTools"] as JsonArray)?.Select(n => n!.GetValue<string>()).ToList() ?? [], o["updatedByName"]?.GetValue<string>(), o["updatedAt"]?.GetValue<string>());
    }

    /// <summary>The tool policy check applied to every execution: all tools off, or this tool off.</summary>
    public (bool Blocked, string? By, string? At) Evaluate(ExternalMcpConnection c, string tool)
    {
        var p = Policy(c);
        return (p.AllDisabled || p.Disabled.Contains(tool), p.By, p.At);
    }

    public object PolicyJson(ExternalMcpConnection c, bool attribution)
    {
        var p = Policy(c);
        return new { allDisabled = p.AllDisabled, disabledTools = p.Disabled, updatedBy = attribution ? p.By : null, updatedAt = p.At };
    }

    // ---------- credentials ----------

    private static bool Connected(ExternalMcpConnection c) => c.CredentialMode == "per_member" || c.AccessTokenEnc != null || c.ApiKeyEnc != null || (c.AuthType == "none" && c.ConnectedAt != null);

    public async Task<ConnectedAccount?> AccountAsync(string connectionId, string memberId) =>
        await db.Set<ConnectedAccount>().FirstOrDefaultAsync(a => a.ConnectionId == connectionId && a.MemberId == memberId);

    /// <summary>What a call by this person carries to the server. OAuth tokens are refreshed first when they are about to expire.</summary>
    public async Task<Credential> ResolveCredentialAsync(ExternalMcpConnection c, string memberId, CancellationToken ct = default)
    {
        if (c.CredentialMode == "per_member")
        {
            var account = await AccountAsync(c.Id, memberId);
            if (account?.AccessTokenEnc is null) return new Credential(false, "Connect your account before using this MCP's tools.", null, null, account);
            if (c.AuthType == "apikey") return account.TokenType == "api_key" && box.Decrypt(account.AccessTokenEnc) is { } key ? new Credential(true, null, key, null, account) : new Credential(false, "Connect your account before using this MCP's tools.", null, null, account);
            var fresh = await FreshTokenAsync(c, account, ct);
            return fresh is null ? new Credential(false, "Connect your account before using this MCP's tools.", null, null, account) : new Credential(true, null, null, fresh, account);
        }
        switch (c.AuthType)
        {
            case "none": return Connected(c) ? new Credential(true, null, null, null, null) : new Credential(false, "Connect this MCP before using its tools.", null, null, null);
            case "apikey":
                return box.Decrypt(c.ApiKeyEnc) is { } k ? new Credential(true, null, k, null, null) : new Credential(false, "Connect this MCP before using its tools.", null, null, null);
            default:
                if (c.AccessTokenEnc is null) return new Credential(false, "Connect this MCP before using its tools.", null, null, null);
                var token = await FreshTokenAsync(c, null, ct);
                return token is null ? new Credential(false, "Connect this MCP before using its tools.", null, null, null) : new Credential(true, null, null, token, null);
        }
    }

    public McpTarget Target(ExternalMcpConnection c, Credential credential)
    {
        var headers = RequestHeaders(c);
        if (credential.ApiKey is { } key) headers.Add(("Authorization", c.ApiKeyAuthScheme == "token" ? $"token {key}" : $"Bearer {key}"));
        else if (credential.AccessToken is { } access) headers.Add(("Authorization", $"Bearer {access}"));
        return new McpTarget(c.Url, headers);
    }

    /// <summary>The access token, refreshed when it expires within a minute. A refresh the server rejects clears the sign-in (the person must connect again).</summary>
    private async Task<string?> FreshTokenAsync(ExternalMcpConnection c, ConnectedAccount? account, CancellationToken ct)
    {
        string? Access() => box.Decrypt(account is null ? c.AccessTokenEnc : account.AccessTokenEnc);
        DateTime? Expires() => account is null ? c.ExpiresAt : account.ExpiresAt;
        if (Expires() is not { } expiry || expiry > DateTime.UtcNow.AddSeconds(60)) return Access();
        return await RefreshAsync(c, account, ct, usedToken: null);
    }

    /// <summary>Refreshes the OAuth token for a credential. Calls for one credential run one at a time, and a second caller reuses the first's result.</summary>
    public async Task<string?> RefreshAsync(ExternalMcpConnection c, ConnectedAccount? account, CancellationToken ct, string? usedToken)
    {
        var gate = RefreshLocks.GetOrAdd(account?.Id ?? c.Id, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(ct);
        try
        {
            // Another request may have refreshed while this one waited: read the stored values again.
            if (account is null) await db.Entry(c).ReloadAsync(ct); else await db.Entry(account).ReloadAsync(ct);
            var current = box.Decrypt(account is null ? c.AccessTokenEnc : account.AccessTokenEnc);
            var expires = account is null ? c.ExpiresAt : account.ExpiresAt;
            if (usedToken is null && current is not null && (expires is null || expires > DateTime.UtcNow.AddSeconds(60))) return current;
            // A caller whose token was rejected: if a newer token is stored, someone else already refreshed, so use theirs.
            if (usedToken is not null && current is not null && current != usedToken) return current;
            var refresh = box.Decrypt(account is null ? c.RefreshTokenEnc : account.RefreshTokenEnc);
            var client = await db.Set<ConnectionOAuthClient>().AsNoTracking().FirstOrDefaultAsync(x => x.ConnectionId == c.Id);
            var config = OAuthConfig(c);
            var tokenEndpoint = config["tokenEndpoint"]?.GetValue<string>();
            var resource = config["resource"]?.GetValue<string>() ?? c.Url;
            if (refresh is null || client is null || tokenEndpoint is null) { await ClearCredentialAsync(c, account, "credential_expired"); return null; }
            try
            {
                var tokens = await oauth.RefreshAsync(tokenEndpoint, client.ClientId, box.Decrypt(client.ClientSecretEnc), client.TokenEndpointAuthMethod, refresh, resource, ct);
                SaveTokens(c, account, tokens, keepRefresh: refresh);
                await db.SaveChangesAsync(ct);
                return tokens.AccessToken;
            }
            catch (OAuthException e) when (e.Code == "token_rejected")
            {
                await ClearCredentialAsync(c, account, "authorization_rejected");
                return null;
            }
            catch (OAuthException) { return current; }
        }
        finally { gate.Release(); }
    }

    private void SaveTokens(ExternalMcpConnection c, ConnectedAccount? account, TokenSet tokens, string? keepRefresh)
    {
        var now = DateTime.UtcNow;
        var refresh = tokens.RefreshToken ?? keepRefresh;
        if (account is null)
        {
            c.AccessTokenEnc = box.Encrypt(tokens.AccessToken);
            c.RefreshTokenEnc = refresh is null ? null : box.Encrypt(refresh);
            c.TokenType = tokens.TokenType; c.Scope = tokens.Scope ?? c.Scope; c.ExpiresAt = tokens.ExpiresAt;
        }
        else
        {
            account.AccessTokenEnc = box.Encrypt(tokens.AccessToken);
            account.RefreshTokenEnc = refresh is null ? null : box.Encrypt(refresh);
            account.TokenType = tokens.TokenType; account.Scopes = tokens.Scope ?? account.Scopes; account.ExpiresAt = tokens.ExpiresAt; account.UpdatedAt = now;
        }
    }

    private async Task ClearCredentialAsync(ExternalMcpConnection c, ConnectedAccount? account, string reason)
    {
        var health = new JsonObject { ["version"] = 1, ["status"] = "reconnect_required", ["reason"] = reason, ["checkedAt"] = Responses.IsoUtc(DateTime.UtcNow) }.ToJsonString();
        if (account is null)
        {
            c.AccessTokenEnc = null; c.RefreshTokenEnc = null; c.TokenType = null; c.Scope = null; c.ExpiresAt = null; c.ConnectedAt = null; c.CredentialHealthJson = health;
        }
        else
        {
            account.AccessTokenEnc = null; account.RefreshTokenEnc = null; account.TokenType = null; account.Scopes = null; account.ExpiresAt = null; account.CredentialHealthJson = health; account.ReadinessJson = null; account.UpdatedAt = DateTime.UtcNow;
        }
        await db.SaveChangesAsync();
    }

    // ---------- talking to the server ----------

    /// <summary>Runs a call against the server; on a 401 with an OAuth token, refreshes once and tries again.</summary>
    public async Task<T> WithCredentialAsync<T>(ExternalMcpConnection c, Credential credential, Func<McpTarget, Task<T>> action, CancellationToken ct)
    {
        try { return await action(Target(c, credential)); }
        catch (McpException e) when (e.Kind == McpFailure.Unauthorized && c.AuthType == "oauth" && credential.AccessToken is not null)
        {
            var token = await RefreshAsync(c, credential.Account, ct, usedToken: credential.AccessToken);
            if (token is null || token == credential.AccessToken) throw;
            return await action(Target(c, credential with { AccessToken = token }));
        }
    }

    public Task<IReadOnlyList<McpTool>> ListToolsAsync(ExternalMcpConnection c, Credential credential, CancellationToken ct = default) =>
        WithCredentialAsync(c, credential, t => mcp.ListToolsAsync(t, ct), ct);

    public Task<JsonObject> CallToolAsync(ExternalMcpConnection c, Credential credential, string tool, JsonObject args, CancellationToken ct = default) =>
        WithCredentialAsync(c, credential, t => mcp.CallToolAsync(t, tool, args, ct), ct);

    public Task ProbeAsync(ExternalMcpConnection c, Credential credential, CancellationToken ct = default) =>
        WithCredentialAsync(c, credential, async t => await mcp.InitializeAsync(t, ct), ct);

    public static Diagnostic Diagnose(McpException e, string phase)
    {
        var reference = Ids.New("req");
        return e.Kind switch
        {
            McpFailure.Unauthorized => new(reference, "AUTH_RESOURCE_VALIDATION", "oauth_resource_rejected", $"MCP_OAUTH_HTTP_{e.HttpStatus}", true, "organization_admin", "Update the credential for this MCP connection, then retry.", $"The MCP resource rejected the supplied authorization (HTTP {e.HttpStatus}).", e.HttpStatus, null, null),
            McpFailure.Timeout => new(reference, phase, "request_timeout", "MCP_REQUEST_TIMEOUT", true, "openwork", "Try again in a moment.", "The MCP server took too long to respond.", null, null, null),
            McpFailure.Network => new(reference, phase, "provider_unavailable", "MCP_PROVIDER_UNAVAILABLE", true, "provider_admin", "Check that the MCP server is running and reachable, then retry.", "The MCP server could not be reached.", null, null, null),
            McpFailure.Refused => new(reference, "CONFIGURATION", "url_refused", "MCP_URL_REFUSED", false, "organization_admin", "Use a public HTTPS address for the MCP server.", e.Message, null, null, null),
            McpFailure.TooLarge => new(reference, phase, "response_too_large", "MCP_RESPONSE_TOO_LARGE", false, "provider_admin", "The server's answer is too large for OpenWork to read.", e.Message, null, null, null),
            McpFailure.Http => new(reference, phase, "provider_http_error", "MCP_HTTP_ERROR", e.HttpStatus >= 500, "provider_admin", "Check the MCP server, then retry.", e.Message, e.HttpStatus, null, null),
            McpFailure.Tool when e.JsonRpcCode == -32602 => new(reference, phase, "mcp_tool_input_invalid", "MCP_INVALID_PARAMS", false, "openwork", "Correct the tool arguments using the latest advertised input schema; do not retry the same arguments unchanged.", $"The provider rejected the tool arguments. Provider-declared message (untrusted): \"{e.ProviderMessage}\".", e.HttpStatus, e.JsonRpcCode, e.ProviderMessage),
            McpFailure.Tool => new(reference, phase, "mcp_tool_error", "MCP_TOOL_ERROR", false, "provider_admin", "Check the tool and its arguments, then retry.", $"The MCP server returned an error. Provider-declared message (untrusted): \"{e.ProviderMessage}\".", e.HttpStatus, e.JsonRpcCode, e.ProviderMessage),
            _ => new(reference, phase, "protocol_error", "MCP_PROTOCOL_ERROR", false, "provider_admin", "Check that the address is an MCP server that speaks Streamable HTTP.", "The server did not answer like an MCP server.", e.HttpStatus, null, null),
        };
    }

    // ---------- readiness ----------

    private static readonly Dictionary<string, string> ReadinessReasons = new()
    {
        ["sign_in_required"] = "Sign in to check this connection.",
        ["setup_required"] = "Finish setting up this connection.",
        ["unavailable"] = "The service didn't respond. Try again later.",
        ["timed_out"] = "The check timed out. Try again.",
        ["sign_in_rejected"] = "The service rejected the sign-in. Sign in again.",
        ["tools_unreadable"] = "The service answered but its tools couldn't be read. Check the connection address and settings.",
    };

    public object? VisibleReadiness(string? json)
    {
        if (json is null) return null;
        var o = JsonNode.Parse(json) as JsonObject;
        if (o is null) return null;
        var d = new Dictionary<string, object?>
        {
            ["status"] = o["status"]?.GetValue<string>(), ["checkedAt"] = o["checkedAt"]?.GetValue<string>(), ["lastSuccessfulAt"] = o["lastSuccessfulAt"]?.GetValue<string>(),
            ["reason"] = o["reason"]?.GetValue<string>(), ["failure"] = o["failure"]?.GetValue<string>(),
        };
        if (o["referenceId"] is JsonValue r) d["referenceId"] = r.GetValue<string>();
        return d;
    }

    /// <summary>Checks initialize and tools/list with this person's credential (no tool is run) and records the outcome.</summary>
    public async Task<object> CheckAsync(ExternalMcpConnection c, string memberId, CancellationToken ct = default)
    {
        var account = c.CredentialMode == "per_member" ? await AccountAsync(c.Id, memberId) : null;
        var previous = (JsonNode.Parse((account?.ReadinessJson ?? c.ReadinessJson) ?? "null") as JsonObject)?["lastSuccessfulAt"]?.GetValue<string>();
        var now = Responses.IsoUtc(DateTime.UtcNow);
        string status = "could_not_verify"; string? failure = null; string? reason = null; string? reference = null;
        var credential = await ResolveCredentialAsync(c, memberId, ct);
        if (!credential.Ok)
        {
            failure = c.CredentialMode == "per_member" ? "sign_in_required" : "setup_required";
            reason = ReadinessReasons[failure];
        }
        else
        {
            try { await ListToolsAsync(c, credential, ct); status = "ready"; }
            catch (McpException e)
            {
                var diagnostic = Diagnose(e, "MCP_TOOL_DISCOVERY");
                reference = diagnostic.ReferenceId;
                failure = e.Kind switch { McpFailure.Unauthorized => "sign_in_rejected", McpFailure.Timeout => "timed_out", McpFailure.Network or McpFailure.Http or McpFailure.Refused => "unavailable", _ => "tools_unreadable" };
                reason = ReadinessReasons[failure];
            }
        }
        var check = new JsonObject { ["status"] = status, ["checkedAt"] = now, ["lastSuccessfulAt"] = status == "ready" ? now : previous, ["reason"] = reason, ["failure"] = failure };
        if (reference is not null) check["referenceId"] = reference;
        var text = check.ToJsonString();
        // Re-read: the settings may have changed while the server was being asked, and a check of old settings must not stand for the new ones.
        await db.Entry(c).ReloadAsync(ct);
        if (account is null) c.ReadinessJson = text;
        else
        {
            account.ReadinessJson = text;
            if (status == "ready") c.ReadinessJson = text;   // a person's working check stands for the connector too
        }
        await db.SaveChangesAsync(ct);
        return VisibleReadiness(text)!;
    }

    // ---------- wire shape ----------

    public string ApiOrigin => urls.Api;

    public string WebUrl => urls.Web;

    public string? DecryptKey(ExternalMcpConnection c) => box.Decrypt(c.ApiKeyEnc);

    /// <summary>The credential of a shared connection that is not saved yet (used to check a new or edited server before keeping it).</summary>
    public Task<Credential> ResolveCredentialForProbeAsync(ExternalMcpConnection c) =>
        Task.FromResult(c.AuthType == "apikey" ? new Credential(box.Decrypt(c.ApiKeyEnc) is not null, null, box.Decrypt(c.ApiKeyEnc), null, null) : new Credential(true, null, null, null, null));

    /// <summary>Signs out everyone: every stored account goes, the shared credential is cleared, the connection and its grants stay.</summary>
    public async Task DisconnectAllAsync(ExternalMcpConnection c)
    {
        await using var tx = await db.Database.BeginTransactionAsync();
        await db.Set<ConnectedAccount>().Where(a => a.ConnectionId == c.Id).ExecuteDeleteAsync();
        if (c.AuthType == "apikey") c.ApiKeyEnc = null;
        c.AccessTokenEnc = null; c.RefreshTokenEnc = null; c.TokenType = null; c.Scope = null; c.ExpiresAt = null; c.CredentialHealthJson = null; c.ConnectedAt = null;
        c.UpdatedAt = DateTime.UtcNow > c.UpdatedAt ? DateTime.UtcNow : c.UpdatedAt.AddMilliseconds(1);
        await db.SaveChangesAsync();
        await tx.CommitAsync();
    }

    public string CallbackUrl => urls.Api + CallbackPath;

    public async Task<Dictionary<string, object?>> ToJsonAsync(ExternalMcpConnection c, Caller caller, bool includeAccess, bool includeManualEndpoints, Dictionary<string, string>? names = null, bool allPluginNames = false)
    {
        var connected = Connected(c);
        var connectedAt = c.ConnectedAt;
        var connectedForMe = connected && c.CredentialMode == "shared";
        ConnectedAccount? account = null;
        var health = c.CredentialHealthJson;
        var readiness = c.ReadinessJson;
        var granted = c.Scope?.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList() ?? [];
        if (c.CredentialMode == "per_member")
        {
            account = await AccountAsync(c.Id, caller.MemberId);
            connectedForMe = account?.AccessTokenEnc != null && (c.AuthType != "apikey" || account.TokenType == "api_key");
            health = account?.CredentialHealthJson; readiness = account?.ReadinessJson;
            granted = account?.Scopes?.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList() ?? [];
            if (includeAccess)
            {
                var anyone = await db.Set<ConnectedAccount>().AsNoTracking().Where(a => a.ConnectionId == c.Id && a.AccessTokenEnc != null).OrderByDescending(a => a.ConnectedAt).FirstOrDefaultAsync();
                connected = anyone is not null; connectedAt = anyone?.ConnectedAt;
            }
            else { connected = connectedForMe; connectedAt = account?.AccessTokenEnc != null ? account.ConnectedAt : null; }
        }
        var healthObj = health is null ? null : JsonNode.Parse(health) as JsonObject;
        var needsReconnect = healthObj?["status"]?.GetValue<string>() == "reconnect_required";
        var config = OAuthConfig(c);
        var client = c.AuthType == "oauth" || includeAccess ? await db.Set<ConnectionOAuthClient>().AsNoTracking().FirstOrDefaultAsync(x => x.ConnectionId == c.Id) : null;

        var d = new Dictionary<string, object?>
        {
            ["id"] = c.Id, ["name"] = c.Name, ["externalKey"] = c.ExternalKey, ["url"] = c.Url, ["authType"] = c.AuthType, ["credentialMode"] = c.CredentialMode,
            ["apiKeyAuthScheme"] = c.ApiKeyAuthScheme, ["requestHeaderNames"] = RequestHeaders(c).Select(h => h.Name).ToList(), ["exposeDirectly"] = c.ExposeDirectly,
            ["nativeProviderKey"] = null, ["externalAccountId"] = null, ["connected"] = connected, ["connectedAt"] = connectedAt is { } at ? Responses.IsoUtc(at) : null,
        };
        if (includeAccess)
        {
            d["createdByName"] = names is not null && names.TryGetValue(c.CreatedByMemberId, out var n) ? n : null;
            d["createdByYou"] = c.CreatedByMemberId == caller.MemberId;
            d["canRemove"] = caller.Has("connections.delete") || c.CreatedByMemberId == caller.MemberId;
        }
        d["createdAt"] = Responses.IsoUtc(c.CreatedAt);
        d["updatedAt"] = Responses.IsoUtc(c.UpdatedAt);
        d["connectedForMe"] = connectedForMe;
        d["needsReconnect"] = needsReconnect;
        d["credentialHealth"] = healthObj?["status"]?.GetValue<string>() ?? "unknown";
        d["credentialHealthReason"] = healthObj?["reason"]?.GetValue<string>();
        d["credentialHealthCheckedAt"] = healthObj?["checkedAt"]?.GetValue<string>();
        d["readiness"] = VisibleReadiness(readiness);
        if (includeAccess) d["organizationReadiness"] = VisibleReadiness(c.ReadinessJson) ?? VisibleReadiness(readiness);
        d["issuerReviewRequired"] = false;
        d["reconnectActionOwner"] = needsReconnect ? (c.CredentialMode == "shared" ? "organization_admin" : "member") : null;
        var provenance = await ProvenanceAsync(caller, c.Id, allPluginNames);
        var requiredTypes = provenance.RequiredAuthTypes.ToList();
        if (requiredTypes.Count == 0 && McpAuthPolicy.Required(null, c.Url) is { } fromPreset) requiredTypes.Add(fromPreset);
        var authPolicyConfirmed = provenance.IdentityManagedBy.Count == 0 || requiredTypes.Count > 0 || McpAuthPolicy.PresetFor(c.Url) is not null;
        var authTypeMismatch = requiredTypes.Any(t => !McpAuthPolicy.ExistingCompatible(c.AuthType, t));
        var oauthClientRequired = c.AuthType == "oauth" && McpAuthPolicy.RequiresPreRegisteredClient(c.Url);
        d["requiredBy"] = provenance.RequiredBy.Select(x => new { pluginId = x.PluginId, name = x.Name }).ToList();
        d["identityManagedBy"] = provenance.IdentityManagedBy.Select(x => new { pluginId = x.PluginId, name = x.Name }).ToList();
        d["requiredAuthType"] = requiredTypes.Count == 1 ? requiredTypes[0] : null;
        d["authPolicyConfirmed"] = authPolicyConfirmed;
        d["authTypeMismatch"] = authTypeMismatch;
        d["oauthClientConfigured"] = client is not null;
        d["oauthClientRequired"] = oauthClientRequired;
        d["setupRequired"] = provenance.IdentityManagedBy.Count > 0 && (!authPolicyConfirmed || authTypeMismatch || (oauthClientRequired && client is null) || (!connected && c.AuthType is "apikey" or "none"));
        if (includeAccess)
        {
            var access = await AccessOfAsync(c.Id);
            d["access"] = new { orgWide = access.OrgWide, memberIds = access.MemberIds, teamIds = access.TeamIds };
            d["oauthClientId"] = client?.ClientId;
            d["oauthCallbackUrl"] = c.AuthType == "oauth" ? CallbackUrl : null;
            d["oauthSharedCallbackUrl"] = c.AuthType == "oauth" ? CallbackUrl : null;
            d["oauthClientMetadataUrl"] = c.AuthType == "oauth" ? urls.Api + "/oauth/client-metadata.json" : null;
            d["oauthCallbackMode"] = c.AuthType == "oauth" ? "shared-v1" : null;
            d["oauthRegistrationSource"] = client?.RegistrationSource;
            if (includeManualEndpoints)
            {
                d["manualOAuthEndpoints"] = config["manualOAuthEndpoints"]?.DeepClone();
                d["oauthClientHasSecret"] = client?.ClientSecretEnc != null;
            }
            d["authorizationServerIssuer"] = config["authorizationServerIssuer"]?.GetValue<string>();
            d["requestedScopes"] = (config["requestedScopes"] as JsonArray)?.Select(n => n!.GetValue<string>()).ToList() ?? [];
            d["grantedScopes"] = granted;
        }
        else d["access"] = null;
        return d;
    }

    public async Task<Dictionary<string, string>> MemberNamesAsync(string orgId)
    {
        var rows = await (from m in db.Members.AsNoTracking() join u in db.Users.AsNoTracking() on m.UserId equals u.Id where m.OrganizationId == orgId select new { m.Id, u.Name, u.Email }).ToListAsync();
        return rows.ToDictionary(r => r.Id, r => r.Name.Trim().Length > 0 ? r.Name.Trim() : r.Email);
    }

    public object Links(ExternalMcpConnection c, string orgId)
    {
        var web = urls.Web;
        return new
        {
            yourConnections = $"{web}/dashboard/your-connections?connectionId={c.Id}",
            signIn = $"{web}/connect/mcp?connectionId={c.Id}&org={orgId}&name={Uri.EscapeDataString(c.Name).Replace("%20", "+")}",
            oauthCallback = c.AuthType == "oauth" ? CallbackUrl : "http://127.0.0.1/unused-mcp-oauth-callback",
        };
    }

    // ---------- OAuth sign-in ----------

    public sealed record StartResult(string? AuthorizeUrl, string? ErrorCode, string? ErrorMessage, int Status);

    /// <summary>Begins the browser sign-in: finds the sign-in service, registers this app if needed, stores the PKCE secret and returns the address to open.</summary>
    public async Task<(string? Url, OAuthException? Failure)> StartOAuthAsync(ExternalMcpConnection c, Caller caller, CancellationToken ct = default)
    {
        try
        {
            var config = OAuthConfig(c);
            var manual = config["manualOAuthEndpoints"] as JsonObject;
            AuthServer server;
            if (manual is not null)
            {
                var authEndpoint = manual["authorizationEndpoint"]!.GetValue<string>(); var tokenEndpoint = manual["tokenEndpoint"]!.GetValue<string>();
                await http.AssertPublicAsync(authEndpoint, ct); await http.AssertPublicAsync(tokenEndpoint, ct);
                server = new AuthServer(new Uri(authEndpoint).GetLeftPart(UriPartial.Authority), authEndpoint, tokenEndpoint, null, c.Url, [], [], false);
            }
            else server = await oauth.DiscoverAsync(c.Url, config["authorizationServerIssuer"]?.GetValue<string>(), ct);

            var client = await db.Set<ConnectionOAuthClient>().FirstOrDefaultAsync(x => x.ConnectionId == c.Id, ct);
            // A client belongs to one authorization server: a registered one is reused only for the same issuer (an admin's own app always is).
            if (client is not null && client.RegistrationSource != "pre-registered" && client.Issuer != server.Issuer) { db.Remove(client); client = null; }
            if (client is null)
            {
                var (clientId, secret, method) = await oauth.RegisterAsync(server, CallbackUrl, ct);
                client = new ConnectionOAuthClient
                {
                    Id = Ids.New("emcoc"), OrganizationId = c.OrganizationId, ConnectionId = c.Id, ClientId = clientId, ClientSecretEnc = Encrypt(secret), RegistrationSource = "dynamic",
                    TokenEndpointAuthMethod = method, Issuer = server.Issuer, CreatedByMemberId = caller.MemberId, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow,
                };
                db.Add(client);
            }
            var (verifier, challenge) = McpOAuth.NewPkce();
            var state = McpOAuth.Base64Url(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
            var now = DateTime.UtcNow;
            db.Add(new ConnectionOAuthTransaction
            {
                Id = Ids.Sha256Hex(state), OrganizationId = c.OrganizationId, ConnectionId = c.Id, MemberId = caller.MemberId, CodeVerifierEnc = box.Encrypt(verifier), RedirectUri = CallbackUrl,
                TokenEndpoint = server.TokenEndpoint, Issuer = server.Issuer, Resource = server.Resource, CreatedAt = now, ExpiresAt = now.AddMinutes(10),
            });
            config["authorizationServerIssuer"] = server.Issuer; config["tokenEndpoint"] = server.TokenEndpoint; config["resource"] = server.Resource;
            c.OAuthConfigJson = config.ToJsonString();
            // Expired sign-ins are not kept.
            await db.Set<ConnectionOAuthTransaction>().Where(t => t.ExpiresAt < now).ExecuteDeleteAsync(ct);
            await db.SaveChangesAsync(ct);
            var requested = (config["requestedScopes"] as JsonArray)?.Select(n => n!.GetValue<string>()).ToArray() ?? [];
            var scope = requested.Length > 0 ? string.Join(' ', requested) : string.Join(' ', server.ScopesSupported);
            return (McpOAuth.AuthorizeUrl(server, client.ClientId, CallbackUrl, state, challenge, scope), null);
        }
        catch (OAuthException e) { return (null, e); }
        catch (UrlRefusedException e) { return (null, new OAuthException("discovery_failed", e.Message)); }
    }

    public sealed record CallbackResult(bool Ok, string Name, string? Message, string? ReferenceId, int Status, bool BadRequest = false);

    /// <summary>The provider came back: find the sign-in by its state (single use), check the issuer, exchange the code and store the tokens.</summary>
    public async Task<CallbackResult> CompleteOAuthAsync(string? state, string? code, string? error, string? issuer, string? scopedConnectionId, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(state)) return new(false, "", "Missing state.", null, 400, true);
        var id = Ids.Sha256Hex(state);
        var tx = await db.Set<ConnectionOAuthTransaction>().AsNoTracking().FirstOrDefaultAsync(t => t.Id == id, ct);
        if (tx is null || tx.ExpiresAt < DateTime.UtcNow || (scopedConnectionId is not null && scopedConnectionId != tx.ConnectionId)) return new(false, "", "Invalid or expired state.", null, 400, true);
        // Single use: whoever deletes the row owns the sign-in; a replay finds nothing.
        if (await db.Set<ConnectionOAuthTransaction>().Where(t => t.Id == id).ExecuteDeleteAsync(ct) != 1) return new(false, "", "Invalid or expired state.", null, 400, true);

        var c = await FindAsync(tx.OrganizationId, tx.ConnectionId);
        var memberStillIn = await db.Members.AnyAsync(m => m.Id == tx.MemberId && m.OrganizationId == tx.OrganizationId, ct);
        if (c is null || !memberStillIn) return new(false, "", "Unknown authorization transaction.", null, 400, true);
        var reference = Ids.New("req");
        if (!string.IsNullOrEmpty(error))
        {
            await RecordConnectFailureAsync(c, tx.MemberId, reference, "sign_in_rejected");
            return new(false, c.Name, "The provider did not allow the sign-in. Try connecting again.", reference, 400);
        }
        if (string.IsNullOrEmpty(code)) return new(false, c.Name, "Missing authorization code.", null, 400, true);
        if (issuer is not null && issuer.TrimEnd('/') != tx.Issuer.TrimEnd('/'))
        {
            await RecordConnectFailureAsync(c, tx.MemberId, reference, "setup_required");
            return new(false, c.Name, "The sign-in response came from a different service than the one that started it.", reference, 400);
        }
        var client = await db.Set<ConnectionOAuthClient>().AsNoTracking().FirstOrDefaultAsync(x => x.ConnectionId == c.Id, ct);
        if (client is null) return new(false, c.Name, "This connection has no OAuth client.", reference, 400);
        TokenSet tokens;
        try
        {
            tokens = await oauth.ExchangeCodeAsync(tx.TokenEndpoint, client.ClientId, box.Decrypt(client.ClientSecretEnc), client.TokenEndpointAuthMethod, code, tx.RedirectUri, box.Decrypt(tx.CodeVerifierEnc) ?? "", tx.Resource, ct);
        }
        catch (OAuthException)
        {
            await RecordConnectFailureAsync(c, tx.MemberId, reference, "setup_required");
            return new(false, c.Name, "The provider did not accept the sign-in. Try connecting again.", reference, 400);
        }
        var now = DateTime.UtcNow;
        if (c.CredentialMode == "per_member")
        {
            var account = await AccountAsync(c.Id, tx.MemberId);
            if (account is null) { account = new ConnectedAccount { Id = Ids.New("emcca"), OrganizationId = c.OrganizationId, MemberId = tx.MemberId, ConnectionId = c.Id, ConnectedAt = now, UpdatedAt = now }; db.Add(account); }
            SaveTokens(c, account, tokens, null);
            account.ConnectedAt = now; account.CredentialHealthJson = new JsonObject { ["version"] = 1, ["status"] = "ready", ["reason"] = null, ["checkedAt"] = Responses.IsoUtc(now) }.ToJsonString(); account.ReadinessJson = null;
        }
        else
        {
            SaveTokens(c, null, tokens, null);
            c.ConnectedAt = now; c.CredentialHealthJson = new JsonObject { ["version"] = 1, ["status"] = "ready", ["reason"] = null, ["checkedAt"] = Responses.IsoUtc(now) }.ToJsonString(); c.ReadinessJson = null;
        }
        c.UpdatedAt = now > c.UpdatedAt ? now : c.UpdatedAt.AddMilliseconds(1);
        await db.SaveChangesAsync(ct);
        await CheckAsync(c, tx.MemberId, ct);
        return new(true, c.Name, null, null, 200);
    }

    private async Task RecordConnectFailureAsync(ExternalMcpConnection c, string memberId, string reference, string failure)
    {
        var check = new JsonObject { ["status"] = "could_not_verify", ["checkedAt"] = Responses.IsoUtc(DateTime.UtcNow), ["lastSuccessfulAt"] = null, ["reason"] = ReadinessReasons[failure], ["failure"] = failure, ["referenceId"] = reference }.ToJsonString();
        if (c.CredentialMode == "per_member")
        {
            var account = await AccountAsync(c.Id, memberId);
            var now = DateTime.UtcNow;
            if (account is null) { account = new ConnectedAccount { Id = Ids.New("emcca"), OrganizationId = c.OrganizationId, MemberId = memberId, ConnectionId = c.Id, ConnectedAt = now, UpdatedAt = now }; db.Add(account); }
            account.ReadinessJson = check;
        }
        else c.ReadinessJson = check;
        await db.SaveChangesAsync();
    }

    // ---------- removing ----------

    public async Task DeleteAsync(ExternalMcpConnection c)
    {
        await using var tx = await db.Database.BeginTransactionAsync();
        await db.Set<ConnectionAccessGrant>().Where(g => g.ConnectionId == c.Id).ExecuteDeleteAsync();
        await db.Set<ConnectedAccount>().Where(a => a.ConnectionId == c.Id).ExecuteDeleteAsync();
        await db.Set<ConnectionOAuthClient>().Where(o => o.ConnectionId == c.Id).ExecuteDeleteAsync();
        await db.Set<ConnectionOAuthTransaction>().Where(t => t.ConnectionId == c.Id).ExecuteDeleteAsync();
        await bindings.RemoveForConnectionAsync(c.OrganizationId, c.Id);
        await db.Set<ExternalMcpConnection>().Where(x => x.Id == c.Id).ExecuteDeleteAsync();
        await tx.CommitAsync();
    }

    // ---------- header validation ----------

    private static readonly HashSet<string> ReservedHeaders = ["host", "content-length", "content-type", "accept", "connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "proxy-authorization", "proxy-connection", "cookie", "mcp-session-id", "mcp-protocol-version", "last-event-id"];
    private static readonly Regex HeaderName = new(@"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$", RegexOptions.Compiled);

    /// <summary>The reference's rules for administrator headers; null when fine, else a message that names the header and never echoes a value.</summary>
    public static string? ValidateHeaders(IReadOnlyList<(string Name, string Value)> headers, string authType)
    {
        if (headers.Count > 4) return "You can add up to 4 request headers.";
        var seen = new HashSet<string>();
        foreach (var (name, value) in headers)
        {
            if (name.Length == 0) return "Each request header needs a name.";
            if (name.Length > 64) return $"The request header name \"{name[..64]}…\" is too long. Use at most 64 characters.";
            if (!HeaderName.IsMatch(name)) return $"\"{name}\" is not a valid request header name. Use letters, numbers and dashes, with no spaces.";
            var lower = name.ToLowerInvariant();
            if (ReservedHeaders.Contains(lower) || lower.StartsWith("x-openwork-")) return $"The request header \"{name}\" is set by OpenWork and can't be added.";
            if (lower == "authorization" && authType is "oauth" or "apikey") return $"The request header \"{name}\" is set by OpenWork for this sign-in method and can't be added.";
            if (value.Length == 0) return $"Enter a value for the request header \"{name}\".";
            if (value.Length > 4096) return $"The value for the request header \"{name}\" is too long. Use at most 4096 characters.";
            if (value.Any(ch => ch is '\r' or '\n' or '\0')) return $"The value for the request header \"{name}\" can't contain line breaks.";
            if (!seen.Add(lower)) return $"The request header \"{name}\" is listed more than once.";
        }
        return null;
    }
}
