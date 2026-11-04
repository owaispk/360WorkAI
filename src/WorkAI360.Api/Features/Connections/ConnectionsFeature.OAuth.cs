using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Connections;
using WorkAI360.Api.Features.Library;

namespace WorkAI360.Api.Features.Connections;

public sealed partial class ConnectionsFeature
{
    private static string E(string value) => WebUtility.HtmlEncode(value);

    /// <summary>The small page the provider's browser tab lands on. It carries no token and never says why a sign-in failed beyond our own words.</summary>
    private static IResult CallbackPage(ConnectionService.CallbackResult r, string webUrl)
    {
        var title = r.Ok ? "You're connected" : "Connection failed";
        var body = r.Ok
            ? $"""<div class="status-row success"><span class="status-icon" aria-hidden="true">✓</span><span><strong data-testid="callback-name">{E(r.Name)} is connected to OpenWork.</strong><small>Connection complete</small></span></div><p>You can close this window and return to OpenWork, or <a href="{E(webUrl)}/dashboard/your-connections">open Your connections</a>.</p>"""
            : $"""<div class="status-row failure"><span class="status-icon" aria-hidden="true">!</span><span><strong data-testid="callback-name">{E(r.Name)}</strong><small>{E(r.Message ?? "")}</small></span></div>{(r.ReferenceId is null ? "" : $"<p class=\"reference\">Diagnostic reference: <code>{E(r.ReferenceId)}</code></p>")}<p>Return to OpenWork to try connecting again. You can close this window, or <a href="{E(webUrl)}/dashboard/your-connections">open Your connections</a>.</p>""";
        var html = $$"""
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light"><title>{{E(title)}} — OpenWork</title>
<style>:root{color-scheme:light;font-family:Inter,ui-sans-serif,system-ui,sans-serif}body{min-height:100vh;margin:0;display:grid;place-items:center;padding:64px 24px;color:#011627;background:#fff}main{width:min(100%,720px);padding:56px 64px;border:1px solid #e5e7eb;border-radius:24px}h1{margin:40px 0 0;font-size:38px;font-weight:600;letter-spacing:-.03em}p{margin:24px 0 0;color:#667085}.brand{font-size:15px;font-weight:600}.status-row{margin-top:36px;display:flex;align-items:center;gap:12px;padding:14px 16px;border:1px solid #e5e7eb;border-radius:12px}.status-row>span:last-child{display:grid;gap:3px}.status-row small{color:#667085}.status-icon{width:32px;height:32px;display:grid;place-items:center;border-radius:8px;background:#f2f4f7}.failure{border-color:#fecaca;background:#fef2f2}.failure .status-icon{color:#b42318;background:#fee2e2}code{font:12px ui-monospace,monospace}</style></head>
<body><main role="{{(r.Ok ? "status" : "alert")}}" aria-live="{{(r.Ok ? "polite" : "assertive")}}"><div class="brand">OpenWork</div><h1>{{E(title)}}</h1>{{body}}</main></body></html>
""";
        return Results.Content(html, "text/html; charset=UTF-8", statusCode: r.Status);
    }

    private static async Task<IResult> HandleCallbackAsync(HttpContext ctx, string? scopedConnectionId)
    {
        var service = ctx.RequestServices.GetRequiredService<ConnectionService>();
        var q = ctx.Request.Query;
        var result = await service.CompleteOAuthAsync(q["state"].ToString(), q["code"].ToString().Length > 0 ? q["code"].ToString() : null, q["error"].ToString().Length > 0 ? q["error"].ToString() : null,
            q.ContainsKey("iss") ? q["iss"].ToString() : null, scopedConnectionId, ctx.RequestAborted);
        ctx.Response.Headers.CacheControl = "no-store";
        return result.BadRequest ? Results.Json(new { error = "invalid_request", message = result.Message }, statusCode: 400) : CallbackPage(result, service.WebUrl);
    }

    private sealed record IssuerReviewInput(string Action, DateTime? ExpectedUpdatedAt, string? Issuer);

    /// <summary>The reference's body: <c>{action: "preview"}</c> or <c>{action: "confirm", expectedUpdatedAt, authorizationServerIssuer}</c>, with zod's wording.</summary>
    private static IssuerReviewInput ReadIssuerReview(JsonElement body)
    {
        var action = body.TryGetProperty("action", out var a) && a.ValueKind == JsonValueKind.String ? a.GetString() : null;
        if (action is not ("preview" or "confirm")) throw new Invalid([(["action"], "invalid_union", "Invalid input")]);
        if (action == "preview") return new IssuerReviewInput(action, null, null);
        var issues = new List<(string[] Path, string Code, string Message)>();
        DateTime? expected = null;
        string? issuer = null;
        try
        {
            var raw = Zod.Str(body, "expectedUpdatedAt", trim: false, min: 0)!;
            if (!DateTimeOffset.TryParse(raw, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out var at) || !Regex.IsMatch(raw, @"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$"))
                issues.Add((["expectedUpdatedAt"], "invalid_format", "Invalid ISO datetime"));
            else expected = at.UtcDateTime;
        }
        catch (Invalid invalid) { issues.AddRange(invalid.Issues); }
        try
        {
            issuer = Zod.Str(body, "authorizationServerIssuer", min: 0)!;
            if (!Uri.TryCreate(issuer, UriKind.Absolute, out _)) issues.Add((["authorizationServerIssuer"], "invalid_format", "Invalid URL"));
        }
        catch (Invalid invalid) { issues.AddRange(invalid.Issues); }
        if (issues.Count > 0) throw new Invalid(issues);
        return new IssuerReviewInput(action, expected, issuer);
    }

    /// <summary>
    /// The reference's issuer review: repeat live discovery and either preview the issuers the MCP resource advertises now, or confirm one of them.
    /// Confirming a different issuer drops everything bound to the old one (the shared sign-in, every member's account, OAuth clients and
    /// unfinished sign-ins) so people reconnect cleanly. This build never marks a connection as needing review, so reviewRequired is false.
    /// </summary>
    private static async Task<IResult> IssuerReviewAsync(HttpContext ctx, Caller caller, ConnectionService service, string connectionId)
    {
        if (Need(ctx, caller, "connections.manage") is { } denied) return denied;
        Zod.TypeId(connectionId, "emc", "connectionId");
        var input = ReadIssuerReview(await Zod.BodyAsync(ctx));
        if (input.Action == "confirm")
        {
            // Keys count as freshly signed in, so they are refused outright: re-trusting an issuer needs a person at the dashboard.
            if (caller.Context.ApiKeyId is not null) return Forbidden("Confirm an issuer from the dashboard; API keys can't do this.");
            if (!Fresh(ctx, caller)) return Reauth();
        }
        var c = await service.FindAsync(caller.OrgId, connectionId);
        if (c is null) return NotFound();
        if (c.AuthType != "oauth") return Bad("Issuer review is only available for OAuth MCP connections.");

        string[] advertised;
        try { advertised = await ctx.RequestServices.GetRequiredService<McpOAuth>().AdvertisedIssuersAsync(c.Url, ctx.RequestAborted); }
        catch (OAuthException e) { return Ok(new { error = "requirements_discovery_failed", message = e.Message }, 502); }
        catch (UrlRefusedException e) { return Ok(new { error = "requirements_discovery_failed", message = e.Message }, 502); }
        if (advertised.Length == 0) return Conflict("The MCP resource does not currently advertise an OAuth authorization server.");

        var config = service.OAuthConfig(c);
        var current = config["authorizationServerIssuer"]?.GetValueKind() == JsonValueKind.String ? config["authorizationServerIssuer"]!.GetValue<string>() : null;
        if (input.Action == "preview") return Ok(new { currentIssuer = current, advertisedIssuers = advertised, reviewRequired = false });
        if (!advertised.Contains(input.Issuer!, StringComparer.Ordinal))
            return Conflict("The selected issuer is not currently advertised by this MCP resource. Refresh the review before confirming.");

        const string changed = "This connection changed while the issuer was being reviewed. Reload and review the current provider metadata again.";
        if (!SameMillisecond(c.UpdatedAt, input.ExpectedUpdatedAt!.Value)) return Conflict(changed);
        var db = ctx.RequestServices.GetRequiredService<DenDbContext>();
        var issuerChanged = current != input.Issuer;
        await using var tx = await db.Database.BeginTransactionAsync();
        if (issuerChanged)
        {
            await db.Set<ConnectedAccount>().Where(x => x.OrganizationId == caller.OrgId && x.ConnectionId == c.Id).ExecuteDeleteAsync();
            await db.Set<ConnectionOAuthClient>().Where(x => x.OrganizationId == caller.OrgId && x.ConnectionId == c.Id).ExecuteDeleteAsync();
            await db.Set<ConnectionOAuthTransaction>().Where(x => x.OrganizationId == caller.OrgId && x.ConnectionId == c.Id).ExecuteDeleteAsync();
            c.AccessTokenEnc = null; c.RefreshTokenEnc = null; c.TokenType = null; c.Scope = null; c.ExpiresAt = null; c.ConnectedAt = null; c.CredentialHealthJson = null; c.ReadinessJson = null;
            // Addresses learned from the old sign-in service are not reused for the new one.
            config.Remove("tokenEndpoint"); config.Remove("resource");
        }
        config["authorizationServerIssuer"] = input.Issuer;
        c.OAuthConfigJson = config.ToJsonString();
        var now = Now();
        c.UpdatedAt = now > c.UpdatedAt ? now : c.UpdatedAt.AddMilliseconds(1);
        try { await db.SaveChangesAsync(); }
        catch (DbUpdateConcurrencyException) { return Conflict(changed); }
        await tx.CommitAsync();
        return Ok(new
        {
            currentIssuer = input.Issuer, advertisedIssuers = advertised, reviewRequired = false, issuerChanged, reconnectionRequired = issuerChanged,
            updatedAt = Responses.IsoUtc(c.UpdatedAt),
        });
    }

    private static void MapOAuthRoutes(WebApplication app)
    {
        app.MapPost("/v1/mcp-connections/{connectionId}/oauth/issuer-review", (string connectionId, HttpContext ctx) => Run(ctx, (caller, service) => IssuerReviewAsync(ctx, caller, service, connectionId)));

        app.MapGet("/oauth/client-metadata.json", (HttpContext ctx, ConnectionService _) =>
        {
            var service = ctx.RequestServices.GetRequiredService<ConnectionService>();
            ctx.Response.Headers.CacheControl = "public, max-age=300";
            return Results.Json(new
            {
                client_id = service.ApiOrigin + "/oauth/client-metadata.json", client_name = "OpenWork", application_type = "web", redirect_uris = new[] { service.CallbackUrl },
                grant_types = new[] { "authorization_code", "refresh_token" }, response_types = new[] { "code" }, token_endpoint_auth_method = "none",
            });
        });

        app.MapGet("/v1/mcp-connections/oauth/callback", (HttpContext ctx, ConnectionService _) => HandleCallbackAsync(ctx, null));
        app.MapGet("/v1/mcp-connections/{connectionId}/connect/callback", (string connectionId, HttpContext ctx) =>
        {
            try { Zod.TypeId(connectionId, "emc", "connectionId"); }
            catch (Invalid invalid) { return Task.FromResult(invalid.ToResult()); }
            return HandleCallbackAsync(ctx, connectionId);
        });

        app.MapGet("/v1/mcp-connections/{connectionId}/connect/start", (string connectionId, HttpContext ctx) => Run(ctx, async (caller, service) =>
        {
            Zod.TypeId(connectionId, "emc", "connectionId");
            var c = await service.FindAsync(caller.OrgId, connectionId);
            if (c is null) return NotFound();
            // Connecting the organization's one account is setting up the integration; connecting your own needs only a grant.
            if (c.CredentialMode == "shared")
            {
                if (Need(ctx, caller, "connections.manage") is { } denied) return denied;
            }
            else if (!await service.CanUseAsync(c, caller.MemberId, caller.TeamIds) && !caller.Has("connections.manage")) return Forbidden("You have not been granted access to this connection.");
            if (c.AuthType != "oauth") return Bad("This connection does not sign in with OAuth.");

            // Already signed in (for this person, or for the organization): nothing to open. Disconnect first to sign in again.
            if ((await service.ResolveCredentialAsync(c, caller.MemberId, ctx.RequestAborted)).Ok) return Ok(new { status = "connected", authorizeUrl = (string?)null });

            var (url, failure) = await service.StartOAuthAsync(c, caller, ctx.RequestAborted);
            if (url is not null) return Ok(new { status = "needs_auth", authorizeUrl = url });
            switch (failure!.Code)
            {
                case "configuration_required":
                    return Ok(new
                    {
                        error = "mcp_oauth_configuration_required", message = "This authorization server requires a pre-registered OAuth client before OpenWork can connect.",
                        callbackUrl = service.CallbackUrl, clientMetadataUrl = service.ApiOrigin + "/oauth/client-metadata.json",
                        manualRequirements = new[] { "Create an OAuth application in the external provider.", "Allowlist the callback URL shown by OpenWork.", "Save the client ID and optional client secret in OpenWork." },
                    }, 409);
                case "issuer_mismatch":
                    return Ok(new { error = "mcp_oauth_issuer_mismatch", message = failure.Message }, 409);
                default:
                    var reference = Ids.New("req");
                    return Ok(new
                    {
                        error = "oauth_handshake_failed", message = $"Could not connect \"{c.Name}\": {failure.Message} Reference: {reference}.",
                        diagnostic = new { referenceId = reference, phase = "AUTH_RESOURCE_DISCOVERY", category = "oauth_discovery_failed", code = "MCP_OAUTH_" + failure.Code.ToUpperInvariant(), retryable = true, actionOwner = "organization_admin", operatorAction = "Check the MCP server's sign-in setup, then retry.", message = failure.Message },
                    }, 424);
            }
        }));
    }
}
