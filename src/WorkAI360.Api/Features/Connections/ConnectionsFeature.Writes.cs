using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Connections;
using WorkAI360.Api.Features.Library;

namespace WorkAI360.Api.Features.Connections;

public sealed partial class ConnectionsFeature
{
    private const string OrgWideDenied = "You can't make a connection available to everyone in the organization. Choose specific people or teams instead.";

    /// <summary>Everyone or a named list: people and teams must belong to this workspace (another workspace's ids read as not found).</summary>
    private static async Task<IResult?> AccessTargetsExistAsync(DenDbContext db, string orgId, AccessInput access)
    {
        if (access.OrgWide) return null;
        var members = access.MemberIds.Distinct().ToList();
        if (members.Count > 0 && await db.Members.CountAsync(m => m.OrganizationId == orgId && members.Contains(m.Id)) != members.Count) return Results.Json(new { error = "member_not_found" }, statusCode: 404);
        var teams = access.TeamIds.Distinct().ToList();
        if (teams.Count > 0 && await db.Teams.CountAsync(t => t.OrganizationId == orgId && teams.Contains(t.Id)) != teams.Count) return Results.Json(new { error = "team_not_found" }, statusCode: 404);
        return null;
    }

    /// <summary>Members add connectors for themselves: a server that signs each person in on their own, or needs no sign-in. Never a workspace secret.</summary>
    private static string? MemberCreateDenial(ConnectionInput input, bool canShareOrgWide)
    {
        if (input.ExternalKey is not null) return "Only workspace owners and admins can add connections with a stable key.";
        if (input.AuthType == "apikey" || input.ApiKey is not null) return "Only workspace owners and admins can add a connection that uses a key.";
        if (input.RequestHeaders.Count > 0) return "Only workspace owners and admins can add request headers.";
        if (input.OAuthClient is not null) return "Only workspace owners and admins can add OAuth app credentials.";
        if (input.AuthType == "oauth" && input.CredentialMode != "per_member") return "Connections you add sign each person in with their own account.";
        if (input.Access.OrgWide && !canShareOrgWide) return "Only workspace owners and admins can share a connection with everyone.";
        return null;
    }

    private static AccessInput MemberManaged(AccessInput access, string creatorId) =>
        new(false, new[] { creatorId }.Concat(access.MemberIds).Distinct().ToList(), access.TeamIds.Distinct().ToList());

    private async Task<IResult?> OrgWideShareDenialAsync(Caller caller, ConnectionService service, bool orgWide, string? existingConnectionId)
    {
        if (!orgWide || caller.Has("sharing.share_org_wide")) return null;
        // Keeping an already org-wide connection org-wide shares nothing new.
        if (existingConnectionId is not null && (await service.AccessOfAsync(existingConnectionId)).OrgWide) return null;
        return Results.Json(new
        {
            error = "forbidden", code = "requires_admin", message = OrgWideDenied, retryable = false,
            action_url = $"{service.WebUrl}/dashboard/members", requiredPermission = "sharing.share_org_wide",
        }, statusCode: 403);
    }

    private static object? CredentialPrompt(ExternalMcpConnection c, ConnectionService service) => new
    {
        credentialPrompt = new { schemaVersion = "1", kind = "credential_prompt", target = new { type = "mcp_connection_key", connectionId = c.Id }, name = c.Name, destination = c.Url },
        nextStep = $"A private field for this API key is shown to the person in OpenWork. Never ask them to paste the key in chat or into a tool argument. End your turn; OpenWork continues the task once the key is saved. Other clients: ask the person to add it at {service.WebUrl}/dashboard/mcp-connections/{c.Id}.",
    };

    private async Task<IResult> CreateAsync(HttpContext ctx, Caller caller, ConnectionService service, ConnectionInput input, int status)
    {
        var db = ctx.RequestServices.GetRequiredService<DenDbContext>();
        var http = ctx.RequestServices.GetRequiredService<GuardedHttp>();
        if (ConnectionService.ValidateHeaders(input.RequestHeaders.Select(h => (h.Name, h.Value ?? "")).ToList(), input.AuthType) is { } headerProblem) return Bad(headerProblem);
        var awaitingKey = input.AuthType == "apikey" && input.CredentialMode == "shared" && input.ApiKey is null;
        if (input.OAuthClient is not null && input.AuthType != "oauth") return Bad("oauthClient is only allowed when authType is oauth.");
        if (input.ApiKeyAuthScheme is not null && input.AuthType != "apikey") return Bad("apiKeyAuthScheme is only allowed for API-key connections.");
        if (input.ApiKeyAuthScheme is not null && !caller.Has("connections.manage")) return Forbidden("Only workspace owners and admins can configure API-key transport.");
        if (await OrgWideShareDenialAsync(caller, service, input.Access.OrgWide, null) is { } orgWide) return orgWide;
        if (input.AuthType != "oauth" && (input.IssuerPresent || (input.RequestedScopes?.Count ?? 0) > 0)) return Bad("OAuth issuer and scopes are only allowed when authType is oauth.");
        if (input.CredentialMode == "per_member" && (input.AuthType == "none" || input.ApiKey is not null)) return Bad("Individual accounts require OAuth or a personal API key enrolled by each member. Do not supply a shared key.");
        try { await http.AssertPublicAsync(input.Url, ctx.RequestAborted); }
        catch (UrlRefusedException e) { return Bad(e.Message); }
        if (input.ManualEndpoints is { } manual)
        {
            if (input.AuthType != "oauth" || input.OAuthClient?.ClientId is null) return Bad("Manual sign-in addresses require OAuth and a pre-registered client ID.");
            if (!caller.Has("connections.manage")) return Forbidden("Only workspace owners and admins can configure manual sign-in addresses.");
            try { await http.AssertPublicAsync(manual.Authorization, ctx.RequestAborted); await http.AssertPublicAsync(manual.Token, ctx.RequestAborted); }
            catch (UrlRefusedException e) { return Bad(e.Message); }
        }
        if (await AccessTargetsExistAsync(db, caller.OrgId, input.Access) is { } missing) return missing;

        var now = Now();
        var config = new JsonObject { ["version"] = 1, ["authorizationServerIssuer"] = input.Issuer, ["requestedScopes"] = new JsonArray((input.RequestedScopes ?? []).Select(s => (JsonNode)s).ToArray()) };
        if (input.ManualEndpoints is { } m) config["manualOAuthEndpoints"] = new JsonObject { ["authorizationEndpoint"] = m.Authorization, ["tokenEndpoint"] = m.Token };
        var c = new ExternalMcpConnection
        {
            Id = Ids.New("emc"), OrganizationId = caller.OrgId, Name = input.Name, ExternalKey = input.ExternalKey, Url = input.Url, AuthType = input.AuthType, CredentialMode = input.CredentialMode,
            ExposeDirectly = input.ExposeDirectly ?? false, ApiKeyAuthScheme = input.AuthType == "apikey" ? input.ApiKeyAuthScheme ?? "bearer" : "bearer",
            ApiKeyEnc = service.Encrypt(input.AuthType == "apikey" ? input.ApiKey : null), RequestHeadersEnc = service.EncryptHeaders(input.RequestHeaders.Select(h => (h.Name, h.Value!)).ToList()),
            OAuthConfigJson = input.AuthType == "oauth" ? config.ToJsonString() : null, CreatedByMemberId = caller.MemberId, CreatedAt = now, UpdatedAt = now,
        };

        // A server with no per-person sign-in is checked before it is saved: a wrong key or address never leaves a connection that looks ready.
        if (input.AuthType != "oauth" && input.CredentialMode == "shared" && !awaitingKey)
        {
            try { await service.ProbeAsync(c, await service.ResolveCredentialForProbeAsync(c), ctx.RequestAborted); }
            catch (McpException e)
            {
                var d = ConnectionService.Diagnose(e, "MCP_INITIALIZE");
                return Ok(new { error = "connection_validation_failed", message = $"Could not validate \"{c.Name}\": {d.Message} Reference: {d.ReferenceId}.", diagnostic = d.ToJson() }, 502);
            }
            if (input.AuthType == "none") c.ConnectedAt = now;
        }
        db.Add(c);
        if (input.OAuthClient is { } oc)
            db.Add(new ConnectionOAuthClient
            {
                Id = Ids.New("emcoc"), OrganizationId = caller.OrgId, ConnectionId = c.Id, ClientId = oc.ClientId, ClientSecretEnc = service.Encrypt(oc.ClientSecret), RegistrationSource = "pre-registered",
                TokenEndpointAuthMethod = oc.Method, CreatedByMemberId = caller.MemberId, CreatedAt = now, UpdatedAt = now,
            });
        service.AddGrants(caller.OrgId, c.Id, input.Access, caller.MemberId);
        try { await db.SaveChangesAsync(); }
        catch (DbUpdateException) { return Results.Json(new { error = "external_key_exists", message = $"A connection with externalKey \"{input.ExternalKey}\" already exists. Use PUT /v1/mcp-connections/by-key/{input.ExternalKey} to update it." }, statusCode: 409); }

        if (input.AuthType != "oauth" && input.CredentialMode == "shared" && !awaitingKey) await service.CheckAsync(c, caller.MemberId, ctx.RequestAborted);
        var body = await service.ToJsonAsync(c, caller, true, caller.Has("connections.view"), await service.MemberNamesAsync(caller.OrgId));
        body["links"] = service.Links(c, caller.OrgId);
        if (awaitingKey) foreach (var p in CredentialPrompt(c, service)!.GetType().GetProperties()) body[p.Name] = p.GetValue(CredentialPrompt(c, service));
        return Ok(body, status);
    }

    private static void MapWrites(WebApplication app)
    {
        var feature = new ConnectionsFeature();

        app.MapPost("/v1/mcp-connections", (HttpContext ctx, ConnectionService _) => Run(ctx, async (caller, service) =>
        {
            var body = await Zod.BodyAsync(ctx);
            if (Zod.Has(body, "kind") && body.GetProperty("kind").ValueKind == System.Text.Json.JsonValueKind.String && body.GetProperty("kind").GetString() == "native_provider")
                return Bad("Native provider connectors (Google Workspace, Microsoft 365) are not available yet.");
            if (Zod.Has(body, "kind")) Zod.Enum(body, "kind", ["external_mcp"]);
            var input = ConnectionInput.Parse(body, false, feature.AllowPrivate(ctx));
            if (!caller.Has("connections.manage"))
            {
                var denial = MemberCreateDenial(input, caller.Has("sharing.share_org_wide"));
                if (denial is not null) return Forbidden(denial);
                input.Access = MemberManaged(input.Access, caller.MemberId) with { OrgWide = input.Access.OrgWide };
            }
            if (input.ExternalKey is not null && await service.FindByKeyAsync(caller.OrgId, input.ExternalKey) is { } existing)
                return Results.Json(new { error = "external_key_exists", message = $"A connection with externalKey \"{input.ExternalKey}\" already exists ({existing.Id}). Use PUT /v1/mcp-connections/by-key/{input.ExternalKey} to update it." }, statusCode: 409);
            return await feature.CreateAsync(ctx, caller, service, input, 200);
        }));

        app.MapPut("/v1/mcp-connections/by-key/{externalKey}", (string externalKey, HttpContext ctx) => Run(ctx, async (caller, service) =>
        {
            if (Need(ctx, caller, "connections.manage") is { } denied) return denied;
            if (!System.Text.RegularExpressions.Regex.IsMatch(externalKey, "^[a-z0-9][a-z0-9._-]{0,127}$")) throw new Invalid("externalKey", "Invalid string: must match pattern /^[a-z0-9][a-z0-9._-]{0,127}$/", "invalid_format");
            var json = await Zod.BodyAsync(ctx);
            var existing = await service.FindByKeyAsync(caller.OrgId, externalKey);
            if (existing is null)
            {
                var input = ConnectionInput.Parse(json, false, feature.AllowPrivate(ctx));
                input.ExternalKey = externalKey;
                return await feature.CreateAsync(ctx, caller, service, input, 201);
            }
            // Replacing a connection someone else made also needs "Edit any connection".
            var canUpdateAny = caller.Has("connections.update");
            if (!canUpdateAny && existing.CreatedByMemberId != caller.MemberId) return Forbidden("Only the workspace owner, people allowed to edit any connection, or the connection creator can edit this MCP connection.");
            var replace = ConnectionInput.Parse(WithExpected(json, existing), true, feature.AllowPrivate(ctx));
            return await feature.ReplaceAsync(ctx, caller, service, existing, replace);
        }));

        app.MapDelete("/v1/mcp-connections/by-key/{externalKey}", (string externalKey, HttpContext ctx) => Run(ctx, async (caller, service) =>
        {
            if (!Fresh(ctx, caller)) return Reauth();
            var c = await service.FindByKeyAsync(caller.OrgId, externalKey);
            if (c is null) return Ok(new { ok = true, deleted = false });
            if (!caller.Has("connections.delete") && c.CreatedByMemberId != caller.MemberId) return Forbidden("Only the workspace owner, people allowed to remove any connection, or the connection creator can remove this MCP connection.");
            await service.DeleteAsync(c);
            return Ok(new { ok = true, deleted = true });
        }));

        app.MapPut("/v1/mcp-connections/{connectionId}", (string connectionId, HttpContext ctx) => Run(ctx, async (caller, service) =>
        {
            if (!Fresh(ctx, caller)) return Reauth();
            Zod.TypeId(connectionId, "emc", "connectionId");
            var body = await Zod.BodyAsync(ctx);
            var c = await service.FindAsync(caller.OrgId, connectionId);
            // Parse before the existence check, as the reference's validators run first.
            var input = ConnectionInput.Parse(body, true, feature.AllowPrivate(ctx));
            if (c is null) return NotFound();
            if (!caller.Has("connections.update") && c.CreatedByMemberId != caller.MemberId) return Forbidden("Only the workspace owner, people allowed to edit any connection, or the connection creator can edit this MCP connection.");
            return await feature.ReplaceAsync(ctx, caller, service, c, input);
        }));

        app.MapPut("/v1/mcp-connections/{connectionId}/access", (string connectionId, HttpContext ctx) => Run(ctx, async (caller, service) =>
        {
            Zod.TypeId(connectionId, "emc", "connectionId");
            var body = await Zod.BodyAsync(ctx);
            var requested = ConnectionInput.ParseAccess(Zod.Object(body, "access"));
            var c = await service.FindAsync(caller.OrgId, connectionId);
            var canManage = caller.Has("connections.manage");
            if (!canManage && c?.CreatedByMemberId != caller.MemberId) return Forbidden("Only workspace owners, admins, or the person who added this connection can change who can use it.");
            if (c is null) return NotFound();
            if (!caller.Has("sharing.share_org_wide") && requested.OrgWide) return Forbidden("Only workspace owners and admins can share a connection with everyone.");
            var access = canManage ? requested : MemberManaged(requested, caller.MemberId) with { OrgWide = requested.OrgWide };
            if (await AccessTargetsExistAsync(ctx.RequestServices.GetRequiredService<DenDbContext>(), caller.OrgId, access) is { } missing) return missing;
            await service.ReplaceAccessAsync(caller.OrgId, c.Id, access, caller.MemberId);
            return Ok(await service.ToJsonAsync(c, caller, true, caller.Has("connections.view"), await service.MemberNamesAsync(caller.OrgId)));
        }));

        app.MapDelete("/v1/mcp-connections/{connectionId}", (string connectionId, HttpContext ctx) => Run(ctx, async (caller, service) =>
        {
            if (!Fresh(ctx, caller)) return Reauth();
            Zod.TypeId(connectionId, "emc", "connectionId");
            var c = await service.FindAsync(caller.OrgId, connectionId);
            if (c is null) return NotFound();
            if (!caller.Has("connections.delete") && c.CreatedByMemberId != caller.MemberId) return Forbidden("Only the workspace owner, people allowed to remove any connection, or the connection creator can remove this MCP connection.");
            await service.DeleteAsync(c);
            return Ok(new { ok = true });
        }));

        app.MapPost("/v1/mcp-connections/{connectionId}/removal-request", (string connectionId, HttpContext ctx) => Run(ctx, async (caller, service) =>
        {
            Zod.TypeId(connectionId, "emc", "connectionId");
            var body = await Zod.BodyAsync(ctx);
            var expected = Zod.Str(body, "expectedName", max: 255)!;
            var c = await service.FindAsync(caller.OrgId, connectionId);
            if (c is null) return Results.Json(new { error = "connection_not_found", message = "There is no connection with this ID in the organization. List connections with getMcpConnections and use an ID from there." }, statusCode: 404);
            if (!caller.Has("connections.delete") && c.CreatedByMemberId != caller.MemberId)
                return Forbidden($"You can't remove {c.Name}. Only the person who added it, or someone with the Remove any connection permission, can. Ask an organization owner or admin to remove it.");
            if (c.Name.Trim() != expected)
                return Results.Json(new { error = "connection_name_mismatch", message = $"This connection is named \"{c.Name}\", not \"{expected}\". Nothing was prepared. Check with the user which connection they mean.", connection = new { id = c.Id, name = c.Name } }, statusCode: 409);
            return Ok(new
            {
                status = "confirmation_required", connection = new { id = c.Id, name = c.Name, url = c.Url }, requiredBy = (await service.ProvenanceAsync(caller, c.Id)).RequiredBy.Select(x => new { pluginId = x.PluginId, name = x.Name }).ToList(),
                handoff = new { action = "open_link", url = $"{service.WebUrl}/dashboard/mcp-connections/{c.Id}?remove=1", instructions = $"Open the link signed in to {caller.Context.Organization.Name} and choose Remove to remove {c.Name}. Nothing is removed until you do." },
            });
        }));

        app.MapPost("/v1/mcp-connections/{connectionId}/disconnect", (string connectionId, HttpContext ctx) => Run(ctx, async (caller, service) =>
        {
            if (Need(ctx, caller, "connections.disconnect") is { } denied) return denied;
            Zod.TypeId(connectionId, "emc", "connectionId");
            var c = await service.FindAsync(caller.OrgId, connectionId);
            if (c is null) return NotFound();
            await service.DisconnectAllAsync(c);
            return Ok(new { ok = true });
        }));

        app.MapPost("/v1/mcp-connections/{connectionId}/disconnect-my-account", (string connectionId, HttpContext ctx) => Run(ctx, async (caller, service) =>
        {
            Zod.TypeId(connectionId, "emc", "connectionId");
            var c = await service.FindAsync(caller.OrgId, connectionId);
            if (c is null) return NotFound();
            if (c.CredentialMode != "per_member") return Bad("Only per-member MCP connections can be disconnected from Your Connections.");
            var account = await service.AccountAsync(c.Id, caller.MemberId);
            if (account is null) return Results.Json(new { error = "connection_not_found", message = "Nothing was connected." }, statusCode: 404);
            var db = ctx.RequestServices.GetRequiredService<DenDbContext>();
            db.Remove(account);
            await db.SaveChangesAsync();
            return Ok(new { ok = true });
        }));
    }

    private static System.Text.Json.JsonElement WithExpected(System.Text.Json.JsonElement body, ExternalMcpConnection existing)
    {
        var node = JsonNode.Parse(body.GetRawText())!.AsObject();
        node["expectedUpdatedAt"] = Responses.IsoUtc(existing.UpdatedAt);
        // The same body as a create: the credential mode defaults to shared and access to everyone.
        node["credentialMode"] ??= "shared";
        node["access"] ??= new JsonObject { ["orgWide"] = true, ["memberIds"] = new JsonArray(), ["teamIds"] = new JsonArray() };
        return System.Text.Json.JsonSerializer.SerializeToElement(node);
    }

    /// <summary>Applies an edit. Changing where a connection points, how it signs in or whether people use their own accounts ends the old sign-ins; renaming and resharing keep them.</summary>
    private async Task<IResult> ReplaceAsync(HttpContext ctx, Caller caller, ConnectionService service, ExternalMcpConnection c, ConnectionInput input)
    {
        var db = ctx.RequestServices.GetRequiredService<DenDbContext>();
        var http = ctx.RequestServices.GetRequiredService<GuardedHttp>();
        // A plugin that needs this connection owns its address and sign-in: renaming and resharing stay open, the rest is refused.
        var declaredScheme = input.AuthType == "apikey" ? input.ApiKeyAuthScheme ?? c.ApiKeyAuthScheme : "bearer";
        var ownedFieldsChanged = c.Url != input.Url || c.AuthType != input.AuthType || c.CredentialMode != input.CredentialMode || input.ApiKey is not null
            || c.ApiKeyAuthScheme != declaredScheme || input.IssuerPresent || input.RequestedScopes is not null || input.ManualEndpointsPresent;
        if (ownedFieldsChanged && await service.IsManagedByPluginAsync(c.OrganizationId, c.Id))
        {
            var owners = (await service.ProvenanceAsync(caller, c.Id)).IdentityManagedBy.Select(x => x.Name).Distinct().ToList();
            if (owners.Count == 0) owners = (await service.ProvenanceAsync(caller, c.Id)).RequiredBy.Select(x => x.Name).Distinct().ToList();
            return Ok(new { error = "marketplace_managed", message = $"{(owners.Count == 0 ? "A marketplace plugin" : string.Join(", ", owners))} owns this connection's server and authentication settings. Edit those values in the marketplace definition." }, 409);
        }
        if (!SameMillisecond(c.UpdatedAt, input.ExpectedUpdatedAt!.Value)) return Conflict("This connection changed after you opened it. Close the dialog, review the latest settings, and try again.");

        static string Norm(string u) => u.TrimEnd('/').ToLowerInvariant();
        var scheme = input.AuthType == "apikey" ? input.ApiKeyAuthScheme ?? c.ApiKeyAuthScheme : "bearer";
        var identityChanged = Norm(c.Url) != Norm(input.Url) || c.AuthType != input.AuthType || c.CredentialMode != input.CredentialMode || c.ApiKeyAuthScheme != scheme;
        var config = service.OAuthConfig(c);
        var hadManual = config["manualOAuthEndpoints"] is JsonObject;

        if (input.ManualEndpointsPresent)
        {
            if (input.AuthType != "oauth") return Bad("Manual sign-in addresses are only allowed for OAuth.");
            if (!caller.Has("connections.manage")) return Forbidden("Only workspace owners and admins can configure manual sign-in addresses.");
        }
        var savedClient = await db.Set<ConnectionOAuthClient>().FirstOrDefaultAsync(o => o.ConnectionId == c.Id);
        (string, string)? manual = input.ManualEndpointsPresent ? input.ManualEndpoints : (!identityChanged && hadManual ? (config["manualOAuthEndpoints"]!["authorizationEndpoint"]!.GetValue<string>(), config["manualOAuthEndpoints"]!["tokenEndpoint"]!.GetValue<string>()) : null);
        if (manual is { } mp)
        {
            var client = input.OAuthClient is not null ? input.OAuthClient.ClientId : (!identityChanged ? savedClient?.ClientId : null);
            if (savedClient is { RegistrationSource: "dynamic" } && input.OAuthClient is null) return Bad("Manual sign-in addresses require an administrator-supplied OAuth client, not an automatically registered app.");
            if (client is null) return Bad("Manual sign-in addresses require a pre-registered client ID.");
            try { await http.AssertPublicAsync(mp.Item1, ctx.RequestAborted); await http.AssertPublicAsync(mp.Item2, ctx.RequestAborted); }
            catch (UrlRefusedException e) { return Bad(e.Message); }
        }
        if (input.ApiKey is not null && input.AuthType != "apikey") return Bad("apiKey is only allowed when authType is apikey.");
        var storedHeaders = service.RequestHeaders(c);
        var merged = new List<(string Name, string Value)>();
        var headersChanged = false;
        if (!input.HasRequestHeaders) merged = storedHeaders;
        else
        {
            foreach (var (name, value) in input.RequestHeaders)
            {
                if (value is not null) { merged.Add((name, value)); continue; }
                var kept = storedHeaders.FirstOrDefault(h => string.Equals(h.Name, name, StringComparison.OrdinalIgnoreCase));
                if (kept.Name is null) return Bad($"Enter a value for the request header \"{name}\". No value is saved for it yet.");
                merged.Add((name, kept.Value));
            }
            headersChanged = !merged.SequenceEqual(storedHeaders);
        }
        if (ConnectionService.ValidateHeaders(merged, input.AuthType) is { } headerProblem) return Bad(headerProblem);
        if (headersChanged && !caller.Has("connections.manage")) return Forbidden("Only workspace owners and admins can change request headers.");
        if (input.ApiKeyAuthScheme is not null && input.AuthType != "apikey") return Bad("apiKeyAuthScheme is only allowed for API-key connections.");
        if (input.ApiKeyAuthScheme is not null && !caller.Has("connections.manage")) return Forbidden("Only workspace owners and admins can configure API-key transport.");
        if (await OrgWideShareDenialAsync(caller, service, input.Access.OrgWide, c.Id) is { } orgWide) return orgWide;
        if (input.OAuthClient is not null && input.AuthType != "oauth") return Bad("oauthClient is only allowed when authType is oauth.");
        if (input.AuthType != "oauth" && (input.IssuerPresent || input.RequestedScopes is not null)) return Bad("OAuth issuer and scopes are only allowed when authType is oauth.");
        if (input.CredentialMode == "per_member" && (input.AuthType == "none" || input.ApiKey is not null)) return Bad("Individual accounts require OAuth or a personal API key enrolled by each member. Do not supply a shared key.");

        var newKey = input.AuthType == "apikey" ? input.ApiKey ?? (!identityChanged && c.AuthType == "apikey" ? service.DecryptKey(c) : null) : null;
        var awaiting = input.AuthType == "apikey" && input.CredentialMode == "shared" && newKey is null && c.AuthType == "apikey" && c.CredentialMode == "shared" && c.ApiKeyEnc is null;
        if (input.AuthType == "apikey" && input.CredentialMode == "shared" && newKey is null && !awaiting)
            return Bad(c.AuthType == "apikey" && c.CredentialMode == "per_member"
                ? "Nothing was changed. Switching to one shared key needs a person to enter it: call postMcpConnectionsCredentialPrompt with this connectionId and scope shared."
                : identityChanged ? "A replacement apiKey is required when changing an API-key connection's identity." : "This API-key connection has no saved key; provide a replacement apiKey.");
        try { await http.AssertPublicAsync(input.Url, ctx.RequestAborted); }
        catch (UrlRefusedException e) { return Bad(e.Message); }
        if (await AccessTargetsExistAsync(db, caller.OrgId, input.Access) is { } missing) return missing;

        var shouldValidate = input.AuthType != "oauth" && input.CredentialMode == "shared" && !awaiting && (identityChanged || c.Url != input.Url || input.ApiKey is not null || headersChanged);
        if (shouldValidate)
        {
            var proposed = new ExternalMcpConnection { Id = c.Id, OrganizationId = c.OrganizationId, Name = input.Name, Url = input.Url, AuthType = input.AuthType, CredentialMode = input.CredentialMode, CreatedByMemberId = c.CreatedByMemberId,
                ApiKeyAuthScheme = scheme, ApiKeyEnc = service.Encrypt(newKey), RequestHeadersEnc = service.EncryptHeaders(merged), ConnectedAt = Now() };
            try { await service.ProbeAsync(proposed, await service.ResolveCredentialForProbeAsync(proposed), ctx.RequestAborted); }
            catch (McpException e)
            {
                var d = ConnectionService.Diagnose(e, "MCP_INITIALIZE");
                return Ok(new { error = "connection_validation_failed", message = $"Could not validate \"{input.Name}\": {d.Message} Reference: {d.ReferenceId}.", diagnostic = d.ToJson() }, 502);
            }
        }

        var hadCredential = c.AccessTokenEnc is not null || c.ApiKeyEnc is not null || await db.Set<ConnectedAccount>().AnyAsync(a => a.ConnectionId == c.Id);
        await using var tx = await db.Database.BeginTransactionAsync();
        var newConfig = new JsonObject
        {
            ["version"] = 1,
            ["authorizationServerIssuer"] = input.IssuerPresent ? input.Issuer : (!identityChanged ? config["authorizationServerIssuer"]?.DeepClone() : null),
            ["requestedScopes"] = new JsonArray((input.RequestedScopes ?? (!identityChanged ? (config["requestedScopes"] as JsonArray)?.Select(n => n!.GetValue<string>()).ToList() : null) ?? []).Select(s => (JsonNode)s).ToArray()),
        };
        if (manual is { } mm) newConfig["manualOAuthEndpoints"] = new JsonObject { ["authorizationEndpoint"] = mm.Item1, ["tokenEndpoint"] = mm.Item2 };
        var issuerChanged = input.IssuerPresent && input.Issuer != config["authorizationServerIssuer"]?.GetValue<string>();
        var manualChanged = input.ManualEndpointsPresent;
        var reconnect = identityChanged || issuerChanged || manualChanged;
        c.Name = input.Name; c.Url = input.Url; c.AuthType = input.AuthType; c.CredentialMode = input.CredentialMode; c.ApiKeyAuthScheme = scheme;
        if (input.ExposeDirectly is { } ed) c.ExposeDirectly = ed;
        c.ApiKeyEnc = service.Encrypt(newKey); c.RequestHeadersEnc = service.EncryptHeaders(merged);
        c.OAuthConfigJson = input.AuthType == "oauth" ? newConfig.ToJsonString() : null;
        if (reconnect || input.ApiKey is not null)
        {
            // The old sign-ins belong to the old settings.
            c.AccessTokenEnc = null; c.RefreshTokenEnc = null; c.TokenType = null; c.Scope = null; c.ExpiresAt = null; c.CredentialHealthJson = null; c.ReadinessJson = null;
            c.ConnectedAt = input.AuthType == "none" || (input.AuthType == "apikey" && newKey is not null) ? Now() : null;
            await db.Set<ConnectedAccount>().Where(a => a.ConnectionId == c.Id).ExecuteDeleteAsync();
            if (reconnect && !(input.OAuthClient is null && !identityChanged && !manualChanged) && savedClient is { RegistrationSource: "dynamic" }) db.Remove(savedClient);
        }
        if (input.OAuthClient is { } oc)
        {
            var existing = await db.Set<ConnectionOAuthClient>().FirstOrDefaultAsync(o => o.ConnectionId == c.Id);
            var secret = oc.ClientSecret is not null ? service.Encrypt(oc.ClientSecret) : (existing is { } e && e.ClientId == oc.ClientId ? e.ClientSecretEnc : null);
            var method = oc.Method ?? (existing is { } e2 && e2.ClientId == oc.ClientId ? e2.TokenEndpointAuthMethod : null);
            if (existing is not null) db.Remove(existing);
            await db.SaveChangesAsync();
            db.Add(new ConnectionOAuthClient { Id = Ids.New("emcoc"), OrganizationId = caller.OrgId, ConnectionId = c.Id, ClientId = oc.ClientId, ClientSecretEnc = secret, RegistrationSource = "pre-registered", TokenEndpointAuthMethod = method, CreatedByMemberId = caller.MemberId, CreatedAt = Now(), UpdatedAt = Now() });
        }
        c.UpdatedAt = Now() > c.UpdatedAt ? Now() : c.UpdatedAt.AddMilliseconds(1);
        try { await db.SaveChangesAsync(); }
        catch (DbUpdateConcurrencyException) { return Conflict("This connection changed after you opened it. Close the dialog, review the latest settings, and try again."); }
        await service.ReplaceAccessAsync(caller.OrgId, c.Id, input.Access, caller.MemberId);
        await tx.CommitAsync();

        if (shouldValidate) await service.CheckAsync(c, caller.MemberId, ctx.RequestAborted);
        var body = await service.ToJsonAsync(c, caller, true, caller.Has("connections.view"), await service.MemberNamesAsync(caller.OrgId));
        body["identityChanged"] = identityChanged;
        body["reconnectionRequired"] = reconnect && hadCredential;
        if (awaiting) foreach (var p in CredentialPrompt(c, service)!.GetType().GetProperties()) body[p.Name] = p.GetValue(CredentialPrompt(c, service));
        return Ok(body);
    }
}
