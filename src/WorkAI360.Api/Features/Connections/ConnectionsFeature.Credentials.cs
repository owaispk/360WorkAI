using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Connections;
using WorkAI360.Api.Features.Library;

namespace WorkAI360.Api.Features.Connections;

public sealed partial class ConnectionsFeature
{
    /// <summary>A pasted key: one token, no spaces or control characters.</summary>
    private static bool ValidKey(string? key) => key is { Length: > 0 and <= 4096 } && key.All(ch => !char.IsWhiteSpace(ch) && !char.IsControl(ch));

    private static async Task<(string? ApiKey, DateTime? Expected, IResult? Failure)> ReadKeyBodyAsync(HttpContext ctx, bool allowExpected)
    {
        var (text, tooLarge) = await ReadLimitedAsync(ctx.Request.Body, 16_384);
        var message = "Enter only your API key, without a prefix, spaces or control characters.";
        // Validation never repeats what was typed: it can be a secret.
        IResult Refuse() => Bad(message);
        if (tooLarge) return (null, null, Bad("Enter only the API key."));
        JsonElement body;
        try { using var doc = JsonDocument.Parse(text); body = doc.RootElement.Clone(); }
        catch (JsonException) { return (null, null, Refuse()); }
        if (body.ValueKind != JsonValueKind.Object) return (null, null, Refuse());
        string? key = null; DateTime? expected = null;
        foreach (var property in body.EnumerateObject())
        {
            if (property.Name == "apiKey" && property.Value.ValueKind == JsonValueKind.String) key = property.Value.GetString();
            else if (allowExpected && property.Name == "expectedUpdatedAt" && property.Value.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(property.Value.GetString(), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AdjustToUniversal, out var at)) expected = at.UtcDateTime;
            else return (null, null, Refuse());
        }
        return ValidKey(key) ? (key, expected, null) : (null, null, Refuse());
    }

    private static void MapCredentials(WebApplication app)
    {
        // A person's own key for a connection where each person uses their own. Write-only: nothing ever returns it.
        app.MapPut("/v1/mcp-connections/{connectionId}/my-credential", (string connectionId, HttpContext ctx) => Run(ctx, async (caller, service) =>
        {
            Zod.TypeId(connectionId, "emc", "connectionId");
            var (key, _, failure) = await ReadKeyBodyAsync(ctx, false);
            if (failure is not null) return failure;
            var c = await service.FindAsync(caller.OrgId, connectionId);
            if (c is null) return NotFound();
            if (c.AuthType != "apikey" || c.CredentialMode != "per_member") return Bad("This connection does not accept personal API keys.");
            if (!await service.CanUseAsync(c, caller.MemberId, caller.TeamIds)) return Forbidden("Personal API keys require a direct organization, team or member grant on this connection.");
            var db = ctx.RequestServices.GetRequiredService<DenDbContext>();
            var now = DateTime.UtcNow;
            var account = await service.AccountAsync(c.Id, caller.MemberId);
            if (account is null) { account = new ConnectedAccount { Id = Ids.New("emcca"), OrganizationId = caller.OrgId, MemberId = caller.MemberId, ConnectionId = c.Id, ConnectedAt = now, UpdatedAt = now }; db.Add(account); }
            account.AccessTokenEnc = service.Encrypt(key); account.RefreshTokenEnc = null; account.TokenType = "api_key"; account.ExpiresAt = null; account.Scopes = null;
            account.CredentialHealthJson = null; account.ReadinessJson = null; account.ConnectedAt = now; account.UpdatedAt = now;
            await db.SaveChangesAsync();
            await service.CheckAsync(c, caller.MemberId, ctx.RequestAborted);
            return Ok(new { ok = true });
        }));

        // The organization's one key. A key the server rejects is not kept.
        app.MapPut("/v1/mcp-connections/{connectionId}/shared-credential", (string connectionId, HttpContext ctx) => Run(ctx, async (caller, service) =>
        {
            ctx.Response.Headers.CacheControl = "no-store";
            if (Need(ctx, caller, "connections.manage") is { } denied) return denied;
            Zod.TypeId(connectionId, "emc", "connectionId");
            var (key, expected, failure) = await ReadKeyBodyAsync(ctx, true);
            if (failure is not null) return failure;
            var c = await service.FindAsync(caller.OrgId, connectionId);
            if (c is null) return NotFound();
            var db = ctx.RequestServices.GetRequiredService<DenDbContext>();
            var switching = expected is not null;
            if (switching)
            {
                if (!Fresh(ctx, caller)) return Reauth();
                if (c.AuthType != "apikey" || c.CredentialMode != "per_member") return Bad("This connection does not use personal API keys.");
                if (!SameMillisecond(c.UpdatedAt, expected!.Value)) return Conflict("This connection changed after you opened it. Close the dialog, review the latest settings, and try again.");
            }
            else if (c.AuthType != "apikey" || c.CredentialMode != "shared") return Bad("This connection does not use a shared API key.");
            var previousKey = service.DecryptKey(c);
            var previousMode = c.CredentialMode;
            var proposed = new ExternalMcpConnection { Id = c.Id, OrganizationId = c.OrganizationId, Name = c.Name, Url = c.Url, AuthType = c.AuthType, CredentialMode = "shared", CreatedByMemberId = c.CreatedByMemberId, ApiKeyAuthScheme = c.ApiKeyAuthScheme, ApiKeyEnc = service.Encrypt(key), RequestHeadersEnc = c.RequestHeadersEnc };
            try { await service.ProbeAsync(proposed, await service.ResolveCredentialForProbeAsync(proposed), ctx.RequestAborted); }
            catch (McpException e)
            {
                var rejected = e.Kind == McpFailure.Unauthorized;
                return Ok(new { error = rejected ? "credential_rejected" : "connection_validation_failed", message = rejected ? $"{c.Name} did not accept this key." : $"Could not reach {c.Name} to check this key." }, rejected ? 400 : 502);
            }
            _ = previousKey; _ = previousMode;
            c.ApiKeyEnc = service.Encrypt(key); c.CredentialMode = "shared"; c.ReadinessJson = null; c.CredentialHealthJson = null; c.ConnectedAt = DateTime.UtcNow;
            if (switching) await db.Set<ConnectedAccount>().Where(a => a.ConnectionId == c.Id).ExecuteDeleteAsync();
            c.UpdatedAt = DateTime.UtcNow > c.UpdatedAt ? DateTime.UtcNow : c.UpdatedAt.AddMilliseconds(1);
            try { await db.SaveChangesAsync(); }
            catch (DbUpdateConcurrencyException) { return Conflict("This connection changed after you opened it. Close the dialog, review the latest settings, and try again."); }
            var readiness = await service.CheckAsync(c, caller.MemberId, ctx.RequestAborted);
            var status = ((IDictionary<string, object?>)readiness);
            return Ok(new { ok = true, connectionId = c.Id, readiness = new { status = status["status"], checkedAt = status["checkedAt"] } });
        }));

        // Asks the person (not the agent) for a key. It changes nothing by itself.
        app.MapPost("/v1/mcp-connections/{connectionId}/credential-prompt", (string connectionId, HttpContext ctx) => Run(ctx, async (caller, service) =>
        {
            Zod.TypeId(connectionId, "emc", "connectionId");
            var body = await Zod.BodyAsync(ctx);
            string? scope = Zod.Has(body, "scope") ? Zod.Enum(body, "scope", ["shared", "personal"]) : null;
            var c = await service.FindAsync(caller.OrgId, connectionId);
            if (c is null) return NotFound();
            if (c.AuthType != "apikey") return Bad($"{c.Name} does not use an API key. Use its connect action instead.");
            var personalKeys = c.CredentialMode == "per_member";
            scope ??= personalKeys ? "personal" : "shared";
            object Respond(string type) => new
            {
                connectionId = c.Id, scope,
                credentialPrompt = new { schemaVersion = "1", kind = "credential_prompt", target = new { type, connectionId = c.Id }, name = c.Name, destination = c.Url },
                nextStep = "A private field for this API key is shown to the person in OpenWork. Never ask them to paste the key in chat or into a tool argument. End your turn; OpenWork continues the task once the key is saved.",
            };
            if (scope == "personal")
            {
                if (!personalKeys) return Bad($"{c.Name} uses one shared organization key, so people can't add their own. An owner or admin can replace the shared key with scope shared.");
                if (!await service.CanUseAsync(c, caller.MemberId, caller.TeamIds)) return Forbidden("You have not been granted access to this connection.");
                return Ok(Respond("mcp_connection_member_key"));
            }
            if (!caller.Has("connections.manage")) return Forbidden($"Only workspace owners and admins can enter the shared key for {c.Name}.");
            return Ok(Respond("mcp_connection_key"));
        }));
    }
}
