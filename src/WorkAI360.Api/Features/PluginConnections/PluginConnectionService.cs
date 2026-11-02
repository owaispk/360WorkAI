using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Connections;
using WorkAI360.Api.Domain.Library;
using WorkAI360.Api.Domain.PluginConnections;
using WorkAI360.Api.Features.Connections;
using WorkAI360.Api.Features.Library;

namespace WorkAI360.Api.Features.PluginConnections;

/// <summary>How a person wants a plugin's MCP server signed in (the reference's plugin MCP setup).</summary>
public sealed record McpSetup(string AuthType, string? CredentialMode, string? ApiKey, string? ClientId, string? ClientSecret)
{
    public string Mode => CredentialMode ?? (AuthType == "oauth" ? "per_member" : "shared");

    /// <summary>Reads <c>{authType, credentialMode, apiKey, oauthClient}</c> with the reference's zod messages; <paramref name="path"/> is the prefix of the field names.</summary>
    public static McpSetup Parse(JsonElement el, string path)
    {
        string P(string name) => path.Length == 0 ? name : $"{path}.{name}";
        var authType = Zod.Has(el, "authType") ? Zod.Enum(el, "authType", ["oauth", "apikey", "none"], P("authType")) : "oauth";
        var mode = Zod.Has(el, "credentialMode") ? Zod.Enum(el, "credentialMode", ["shared", "per_member"], P("credentialMode")) : null;
        var apiKey = Zod.Str(el, "apiKey", required: false, max: 4096, path: P("apiKey"));
        string? clientId = null, clientSecret = null;
        if (Zod.Has(el, "oauthClient"))
        {
            var oc = el.GetProperty("oauthClient");
            if (oc.ValueKind != JsonValueKind.Object) throw new Invalid(P("oauthClient"), $"Invalid input: expected object, received {Zod.Kind(oc)}");
            clientId = Zod.Str(oc, "clientId", max: 512, path: P("oauthClient.clientId"));
            clientSecret = Zod.Str(oc, "clientSecret", required: false, max: 4096, path: P("oauthClient.clientSecret"));
        }
        return new McpSetup(authType, mode, apiKey, clientId, clientSecret);
    }
}

/// <summary>A remote MCP server a plugin's config object declares.</summary>
public sealed record DeclaredServer(string Name, JsonObject Config, string Url);

/// <summary>
/// Binds the MCP servers a plugin declares to connections: sets a connection up (or reuses one with the same address and sign-in),
/// checks it, records which connection serves which server, and reports readiness. Who may use a connection through a plugin is decided in
/// <see cref="PluginBindingStore"/>; here we only keep the rule that nobody configures a plugin they cannot see.
/// </summary>
public sealed class PluginConnectionService(DenDbContext db, ConnectionService connections, PluginReadiness readinessReader, LibraryAccess lib, GuardedHttp http)
{
    private static DateTime Now() => LibraryStore.Now();

    // ---------- reading what a plugin declares ----------

    public static string Slug(string value)
    {
        var s = System.Text.RegularExpressions.Regex.Replace(value.Trim().ToLowerInvariant(), "[^a-z0-9]+", "-").Trim('-');
        if (s.Length > 80) s = s[..80];
        return s.Length == 0 ? "mcp" : s;
    }

    public static JsonObject? ParseObject(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        try { return JsonNode.Parse(text) as JsonObject; } catch (JsonException) { return null; }
    }

    public Task<Dictionary<string, JsonObject>> LatestSpecsAsync(IReadOnlyCollection<string> configObjectIds) => new PluginSpecs(db).LatestAsync(configObjectIds);

    /// <summary>The servers a config object declares: the <c>mcp</c> and <c>mcpServers</c> maps, or the object itself when it carries a url or command.</summary>
    public static List<(string Name, JsonObject Config)> Entries(JsonObject spec, string fallbackName)
    {
        var entries = new List<(string, JsonObject)>();
        foreach (var key in new[] { "mcp", "mcpServers" })
            if (spec[key] is JsonObject container) foreach (var (name, node) in container) if (node is JsonObject config) entries.Add((name, config));
        if (entries.Count == 0 && (Text(spec["url"]) is not null || Text(spec["command"]) is not null)) entries.Add((fallbackName, spec));
        return entries;
    }

    public static string? Text(JsonNode? node) => node is JsonValue v && v.TryGetValue<string>(out var s) && s.Trim().Length > 0 ? s.Trim() : null;

    private static bool IsReady(ExternalMcpConnection c) => c.CredentialMode == "per_member" || c.AccessTokenEnc != null || c.ApiKeyEnc != null || (c.AuthType == "none" && c.ConnectedAt != null);

    // ---------- the route: configure one declared server ----------

    private async Task<(Plugin Plugin, ConfigObject Object)> RequirementAsync(string orgId, string pluginId, string configObjectId)
    {
        var row = await (from m in db.Set<PluginConfigObject>().AsNoTracking()
                         join p in db.Set<Plugin>() on m.PluginId equals p.Id
                         join o in db.Set<ConfigObject>() on m.ConfigObjectId equals o.Id
                         where m.OrganizationId == orgId && m.PluginId == pluginId && m.ConfigObjectId == configObjectId && m.RemovedAt == null
                               && p.OrganizationId == orgId && p.Status == "active" && p.DeletedAt == null
                               && o.OrganizationId == orgId && o.ObjectType == "mcp" && o.Status == "active" && o.DeletedAt == null
                         select new { Plugin = p, Object = o }).FirstOrDefaultAsync();
        return row is null ? throw new LibraryFailure(404, "mcp_requirement_not_found", "Active plugin MCP requirement not found.") : (row.Plugin, row.Object);
    }

    public static void ValidateAuth(McpSetup s, string mode, bool awaitingKey)
    {
        var key = string.IsNullOrWhiteSpace(s.ApiKey) ? null : s.ApiKey!.Trim();
        if (s.ClientId is not null && s.AuthType != "oauth") throw new LibraryFailure(400, "invalid_mcp_auth", "oauthClient is only allowed when authType is oauth.");
        if (key is not null && s.AuthType != "apikey") throw new LibraryFailure(400, "invalid_mcp_auth", "apiKey is only allowed when authType is apikey.");
        if (s.AuthType == "apikey" && mode != "shared") throw new LibraryFailure(400, "invalid_mcp_auth", "authType apikey requires credentialMode shared.");
        if (s.AuthType == "apikey" && key is null && !awaitingKey) throw new LibraryFailure(400, "invalid_mcp_auth", "authType apikey requires apiKey.");
        if (mode == "per_member" && s.AuthType != "oauth") throw new LibraryFailure(400, "invalid_mcp_auth", "credentialMode per_member requires authType oauth.");
    }

    private static string ExpectedMode(McpSetup s) => s.AuthType is "apikey" or "none" ? "shared" : s.Mode;

    private async Task AssertRemoteUrlAsync(string url, CancellationToken ct)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) throw new LibraryFailure(400, "invalid_mcp_url", "MCP server URL is invalid.");
        if (uri.Scheme is not ("http" or "https")) throw new LibraryFailure(400, "invalid_mcp_url", "MCP URLs must use HTTP or HTTPS.");
        if (uri.Scheme == "http" && !http.AllowPrivate) throw new LibraryFailure(400, "invalid_mcp_url", "Hosted MCP connections must use HTTPS.");
        if (uri.Fragment.Length > 0) throw new LibraryFailure(400, "invalid_mcp_url", "MCP URLs must not contain a fragment.");
        if (uri.UserInfo.Length > 0) throw new LibraryFailure(400, "invalid_mcp_url", "MCP URLs must not contain embedded credentials.");
        var sensitive = new HashSet<string>(["access_token", "api_key", "client_secret", "token", "refresh_token", "id_token", "code_verifier"]);
        foreach (var pair in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var name = Uri.UnescapeDataString(pair.Split('=')[0].Replace('+', ' '));
            if (sensitive.Contains(name.ToLowerInvariant())) throw new LibraryFailure(400, "invalid_mcp_url", $"MCP URL query parameter \"{name}\" must not contain credentials.");
        }
        try { await http.AssertPublicAsync(url, ct); }
        catch (UrlRefusedException e) { throw new LibraryFailure(400, "invalid_mcp_url", e.Message); }
    }

    public sealed record Configured(PluginMcpBinding Binding, ExternalMcpConnection Connection, bool AwaitingKey);

    /// <summary>
    /// Configures one declared server of an MCP object in a plugin. The caller has already checked <c>connections.manage</c>. The person must be
    /// able to see the plugin (a plugin they cannot see is reported as the reference reports it for a viewer who is missing: 403).
    /// </summary>
    public async Task<Configured> ConfigureAsync(Actor a, string pluginId, string configObjectId, string serverName, McpSetup setup, bool awaitKey, CancellationToken ct = default)
    {
        var awaitingKey = awaitKey && setup.AuthType == "apikey" && string.IsNullOrWhiteSpace(setup.ApiKey);
        var mode = ExpectedMode(setup);
        ValidateAuth(setup, setup.Mode, awaitingKey);
        var (plugin, obj) = await RequirementAsync(a.OrgId, pluginId, configObjectId);
        if (await lib.PluginRoleAsync(a, plugin.Id) is null) throw new LibraryForbidden("Missing viewer access for plugin.");
        var spec = (await LatestSpecsAsync([obj.Id])).GetValueOrDefault(obj.Id) ?? throw new LibraryFailure(409, "mcp_requirement_not_synced", "MCP config object has no active version to configure.");
        var name = serverName.Trim();
        var entry = Entries(spec, obj.Title).FirstOrDefault(e => e.Name == name);
        if (entry.Config is null) throw new LibraryFailure(404, "mcp_server_not_found", "MCP server declaration not found on this config object.");
        var url = Text(entry.Config["url"]) ?? throw new LibraryFailure(400, "mcp_server_not_remote", "Only declared remote MCP servers with a URL can be configured.");
        var declared = McpAuthPolicy.Required(McpAuthPolicy.Declared(entry.Config), url);
        if (!McpAuthPolicy.Compatible(setup.AuthType, declared, url))
            throw new LibraryFailure(409, "mcp_auth_type_mismatch", declared is not null ? $"This MCP requirement must use {declared} authentication." : "This authentication type is not supported by the MCP server.");
        await AssertRemoteUrlAsync(url, ct);
        var apiKey = string.IsNullOrWhiteSpace(setup.ApiKey) ? null : setup.ApiKey!.Trim();
        var caller = await connections.CallerAsync(a.Context);

        // Two people setting up the same server at once end up with one connection, not two.
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await db.LockOrganizationAsync(a.OrgId);
        var previous = await db.Set<PluginMcpBinding>().FirstOrDefaultAsync(b => b.PluginId == plugin.Id && b.ConfigObjectId == obj.Id && b.ServerName == name, ct);

        ExternalMcpConnection? connection = null;
        var created = false;
        foreach (var candidate in await connections.ListAllAsync(a.OrgId))
        {
            if (McpAuthPolicy.ComparableUrl(candidate.Url) != McpAuthPolicy.ComparableUrl(url) || candidate.AuthType != setup.AuthType || candidate.CredentialMode != mode) continue;
            if (setup.AuthType == "apikey" && (apiKey is null || connections.DecryptKey(candidate) != apiKey)) continue;
            if (setup.AuthType == "oauth" && setup.ClientId is not null)
            {
                var client = await db.Set<ConnectionOAuthClient>().AsNoTracking().FirstOrDefaultAsync(o => o.ConnectionId == candidate.Id, ct);
                if (client?.ClientId != setup.ClientId) continue;
            }
            connection = await db.Set<ExternalMcpConnection>().FirstAsync(c => c.Id == candidate.Id, ct);
            break;
        }
        if (connection is null)
        {
            var now = Now();
            connection = new ExternalMcpConnection
            {
                Id = Ids.New("emc"), OrganizationId = a.OrgId, Name = ConnectionName(plugin.Name, name), Url = url, AuthType = setup.AuthType, CredentialMode = mode,
                ApiKeyEnc = setup.AuthType == "apikey" ? connections.Encrypt(apiKey) : null, OAuthConfigJson = setup.AuthType == "oauth" ? new JsonObject { ["version"] = 1, ["authorizationServerIssuer"] = null, ["requestedScopes"] = new JsonArray() }.ToJsonString() : null,
                CreatedByMemberId = a.MemberId, CreatedAt = now, UpdatedAt = now,
            };
            db.Add(connection);
            await db.SaveChangesAsync(ct);
            created = true;
        }

        try
        {
            if (!(awaitingKey && connection.ApiKeyEnc is null)) await ValidateAsync(connection, setup.AuthType, ct);
        }
        catch (LibraryFailure)
        {
            if (created) { await db.Entry(connection).ReloadAsync(ct); db.Remove(connection); await db.SaveChangesAsync(ct); await tx.CommitAsync(ct); }
            else await tx.CommitAsync(ct);
            throw;
        }

        if (setup.ClientId is not null && !await db.Set<ConnectionOAuthClient>().AnyAsync(o => o.ConnectionId == connection.Id, ct))
        {
            var now = Now();
            db.Add(new ConnectionOAuthClient
            {
                Id = Ids.New("emcoc"), OrganizationId = a.OrgId, ConnectionId = connection.Id, ClientId = setup.ClientId, ClientSecretEnc = connections.Encrypt(setup.ClientSecret),
                RegistrationSource = "pre-registered", CreatedByMemberId = a.MemberId, CreatedAt = now, UpdatedAt = now,
            });
        }

        var owned = created || (previous is not null && previous.ConnectionId == connection.Id && previous.ConnectionOwnedByPlugin);
        var binding = previous ?? new PluginMcpBinding { Id = Ids.New("pmr"), OrganizationId = a.OrgId, PluginId = plugin.Id, ConfigObjectId = obj.Id, ServerName = name, ConnectionId = connection.Id, CreatedByMemberId = a.MemberId, CreatedAt = Now(), UpdatedAt = Now() };
        var replacedId = previous is not null && previous.ConnectionId != connection.Id && previous.ConnectionOwnedByPlugin ? previous.ConnectionId : null;
        binding.ConnectionId = connection.Id;
        binding.RequiredAuthType = declared ?? setup.AuthType;
        binding.ConnectionOwnedByPlugin = owned;
        binding.UpdatedAt = Now();
        if (previous is null) db.Add(binding);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);

        // A connection this plugin made for the server it no longer uses goes away unless something else still points at it.
        if (replacedId is not null) await DeleteIfUnreferencedAsync(a.OrgId, replacedId);
        _ = caller;
        return new Configured(binding, connection, awaitingKey && connection.ApiKeyEnc is null);
    }

    public static string ConnectionName(string pluginName, string serverName)
    {
        var p = pluginName.Trim(); var s = serverName.Trim();
        if (p.Length == 0) return s.Length == 0 ? "Imported MCP" : s;
        return s.Length == 0 ? p : $"{p} / {s}";
    }

    private async Task ValidateAsync(ExternalMcpConnection connection, string authType, CancellationToken ct)
    {
        if (authType == "oauth") return;
        try { await connections.ProbeAsync(connection, await connections.ResolveCredentialForProbeAsync(connection), ct); }
        catch (McpException e)
        {
            var d = ConnectionService.Diagnose(e, "MCP_INITIALIZE");
            if (e.HttpStatus is 401 or 403 || e.Kind == McpFailure.Unauthorized) throw new LibraryFailure(400, "credential_rejected", $"{connection.Name} did not accept this key.");
            throw new LibraryFailure(502, "connection_validation_failed", $"Could not reach {connection.Name} to check it. Reference: {d.ReferenceId}.");
        }
        if (authType == "none") { connection.ConnectedAt = Now(); await db.SaveChangesAsync(ct); }
    }

    private async Task DeleteIfUnreferencedAsync(string orgId, string connectionId)
    {
        if (await db.Set<PluginMcpBinding>().AnyAsync(b => b.OrganizationId == orgId && b.ConnectionId == connectionId)) return;
        if (await db.Set<ConnectionAccessGrant>().AnyAsync(g => g.OrganizationId == orgId && g.ConnectionId == connectionId)) return;
        var c = await connections.FindAsync(orgId, connectionId);
        if (c is not null) await connections.DeleteAsync(c);
    }

    public object ConfiguredJson(Configured c, string orgId) => new
    {
        binding = new { configObjectId = c.Binding.ConfigObjectId, externalMcpConnectionId = c.Connection.Id, id = c.Binding.Id, pluginId = c.Binding.PluginId, serverName = c.Binding.ServerName },
        connection = new { authType = c.Connection.AuthType, connected = IsReady(c.Connection), connectedAt = c.Connection.ConnectedAt is { } at ? Responses.IsoUtc(at) : null, credentialMode = c.Connection.CredentialMode, id = c.Connection.Id, name = c.Connection.Name, url = c.Connection.Url },
        links = new { yourConnections = $"{connections.WebUrl}/dashboard/your-connections?connectionId={c.Connection.Id}" },
    };

    public object CredentialPromptFields(Configured c) => new
    {
        credentialPrompt = new
        {
            schemaVersion = "1", kind = "credential_prompt",
            target = new { type = "plugin_connection_key", pluginId = c.Binding.PluginId, configObjectId = c.Binding.ConfigObjectId, serverName = c.Binding.ServerName, connectionId = c.Connection.Id },
            name = c.Connection.Name, destination = c.Connection.Url,
        },
        nextStep = $"A private field for this API key is shown to the person in OpenWork. Never ask them to paste the key in chat or into a tool argument. End your turn; OpenWork continues the task once the key is saved. Other clients: ask the person to add it at {connections.WebUrl}/dashboard/mcp-connections/{c.Connection.Id}.",
    };

    // ---------- creating a plugin with connections ----------

    /// <summary>What <c>components[].connection</c> / <c>connectionId</c> asked for, checked before anything is created.</summary>
    public sealed record ComponentConnection(McpSetup? Setup, ExternalMcpConnection? Existing);

    /// <summary>Pre-flight for <c>connectionId</c>: the connection is this workspace's, and the person made it or manages connections. Returns the component input that points at it.</summary>
    public async Task<(ConfigInput Input, ExternalMcpConnection Connection)> ConnectionBackedInputAsync(Actor a, string connectionId)
    {
        var connection = await connections.FindAsync(a.OrgId, connectionId) ?? throw new LibraryFailure(404, "mcp_connection_not_found", "That connector was not found in this organization.");
        // Members bundle only connectors they added themselves.
        if (connection.CreatedByMemberId != a.MemberId && !a.Has("connections.manage"))
            throw new LibraryForbidden("Only organization owners and admins can bind plugin MCP servers to organization connections.");
        var serverName = Slug(connection.Name);
        var server = new JsonObject { ["type"] = "remote", ["url"] = connection.Url, ["openworkManaged"] = "den_external_mcp", ["externalMcpConnectionId"] = connection.Id, ["externalMcpConnectionOwnedByPlugin"] = false, ["requiredAuthType"] = connection.AuthType };
        if (connection.AuthType == "oauth") server["oauth"] = true;
        var payload = new JsonObject
        {
            ["mcpServers"] = new JsonObject { [serverName] = server },
            ["openworkManaged"] = "den_external_mcp", ["externalMcpConnectionId"] = connection.Id, ["externalMcpConnectionOwnedByPlugin"] = false, ["requiredAuthType"] = connection.AuthType,
        };
        var payloadText = payload.ToJsonString();
        using var payloadDoc = JsonDocument.Parse(payloadText);
        using var metaDoc = JsonDocument.Parse(new JsonObject { ["name"] = connection.Name }.ToJsonString());
        return (new ConfigInput(null, payloadText, null, metaDoc.RootElement.Clone(), payloadDoc.RootElement.Clone()), connection);
    }

    /// <summary>After the plugin exists: configures each declared server of the objects that carried <c>connection</c>, and binds the ones that named a connection. Undoes the plugin if any of it fails.</summary>
    public async Task ApplyAsync(Actor a, Plugin plugin, IReadOnlyList<string> objectIds, IReadOnlyList<(McpSetup? Setup, ExternalMcpConnection? Existing)> wanted, CancellationToken ct = default)
    {
        try
        {
            var specs = await LatestSpecsAsync(objectIds);
            for (var i = 0; i < wanted.Count; i++)
            {
                var (setup, existing) = wanted[i];
                if (setup is not null)
                {
                    var title = (await db.Set<ConfigObject>().AsNoTracking().FirstAsync(o => o.Id == objectIds[i], ct)).Title;
                    foreach (var entry in Entries(specs.GetValueOrDefault(objectIds[i]) ?? new JsonObject(), title))
                        await ConfigureAsync(a, plugin.Id, objectIds[i], entry.Name, setup, awaitKey: false, ct);
                }
                else if (existing is not null)
                {
                    var now = Now();
                    db.Add(new PluginMcpBinding
                    {
                        Id = Ids.New("pmr"), OrganizationId = a.OrgId, PluginId = plugin.Id, ConfigObjectId = objectIds[i], ServerName = Slug(existing.Name), ConnectionId = existing.Id,
                        RequiredAuthType = existing.AuthType, ConnectionOwnedByPlugin = false, CreatedByMemberId = a.MemberId, CreatedAt = now, UpdatedAt = now,
                    });
                    await db.SaveChangesAsync(ct);
                }
            }
        }
        catch
        {
            db.ChangeTracker.Clear();
            await RollbackAsync(a.OrgId, plugin.Id);
            throw;
        }
    }

    /// <summary>
    /// Undoes a failed setup the way the reference does: drops the bindings and the connections this attempt made, then archives the plugin
    /// (archiving, not deleting, keeps its history; the same name is free to use again because only active plugins are unique).
    /// </summary>
    public async Task RollbackAsync(string orgId, string pluginId)
    {
        var bindings = await db.Set<PluginMcpBinding>().AsNoTracking().Where(b => b.OrganizationId == orgId && b.PluginId == pluginId).ToListAsync();
        await db.Set<PluginMcpBinding>().Where(b => b.PluginId == pluginId).ExecuteDeleteAsync();
        foreach (var id in bindings.Where(b => b.ConnectionOwnedByPlugin).Select(b => b.ConnectionId).Distinct()) await DeleteIfUnreferencedAsync(orgId, id);
        var plugin = await db.Set<Plugin>().FirstOrDefaultAsync(p => p.Id == pluginId);
        if (plugin is not null) { plugin.Status = "archived"; plugin.UpdatedAt = Now(); await db.SaveChangesAsync(); }
    }

    // ---------- what a plugin needs, for the person asking ----------

    /// <summary>
    /// For each MCP server the plugin declares: the connections that could serve it that this person may know about. A bound connection the
    /// person may not use (and cannot list) is not named; the entry then reads as not set up.
    /// </summary>
    public async Task<List<Dictionary<string, object?>>> RequirementsAsync(Actor a, string pluginId)
    {
        await lib.PluginAsync(a, pluginId, LibRole.Viewer);
        var readiness = await readinessReader.ForPluginsAsync(a.Context, a.Aud, [pluginId]);
        return readiness.GetValueOrDefault(pluginId)?.Connections ?? [];
    }
}
