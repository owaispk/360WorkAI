using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.OAuthExtras;

namespace WorkAI360.Api.OAuth;

/// <summary>
/// The token endpoint's extras, as the reference's OAuth provider has them: which grants a client may use, the <c>client_credentials</c> grant, and DPoP binding at
/// the token endpoint (<see cref="DpopVerifier"/> checks the proof itself). Kept apart from <see cref="OAuthEndpoints"/> so the original flows read as before.
/// </summary>
public sealed class OAuthExtrasService(DenDbContext db, DpopVerifier dpop, OAuthUrls urls, TokenService tokens)
{
    public static readonly string[] DefaultGrants = ["authorization_code", "refresh_token"];
    /// <summary>Scopes that speak for a person; a machine token never carries them (the reference's <c>isUserDelegatedScope</c>).</summary>
    public static readonly string[] UserDelegatedScopes = ["openid", "profile", "email", "offline_access"];

    public Task<OAuthClientExtras?> ExtrasAsync(string clientId) => db.Set<OAuthClientExtras>().AsNoTracking().FirstOrDefaultAsync(e => e.ClientId == clientId);

    public static string[] GrantsOf(OAuthClientExtras? extras) =>
        extras?.GrantTypesJson is { } json && JsonSerializer.Deserialize<string[]>(json) is { Length: > 0 } grants ? grants : DefaultGrants;

    /// <summary>The reference's <c>clientAllowsGrant</c>: a client allowed the authorization code grant may also refresh.</summary>
    public static bool AllowsGrant(OAuthClientExtras? extras, string grant)
    {
        var grants = GrantsOf(extras);
        return grants.Contains(grant) || (grant == "refresh_token" && grants.Contains("authorization_code"));
    }

    public static IResult Error(int status, string error, string description) => Results.Json(new { error, error_description = description }, statusCode: status);

    // ---------------------------------------------------------------- DPoP at the token endpoint

    private static IResult DpopError(string description) => Error(400, "invalid_dpop_proof", description);

    /// <summary>The addresses the token endpoint answers at (the advertised one, the API's own, and the address this request came to).</summary>
    public IEnumerable<string> TokenUrls(HttpContext ctx) =>
        [urls.TokenEndpoint, $"{urls.Api}/api/auth/oauth2/token", $"{ctx.Request.Scheme}://{ctx.Request.Host}{ctx.Request.Path}"];

    /// <summary>
    /// Reads the <c>DPoP</c> header of a token request. A proof is required when the client asks for bound tokens, the code was requested with <c>dpop_jkt</c>
    /// or the refresh token is bound (<paramref name="expectedJkt"/>); a proof that is sent is always checked, and binds the tokens to its key.
    /// </summary>
    public async Task<(string? Jkt, IResult? Failure)> TokenBindingAsync(HttpContext ctx, OAuthClientExtras? extras, string? expectedJkt)
    {
        var headers = ctx.Request.Headers["DPoP"];
        var required = extras?.DpopBoundAccessTokens == true || expectedJkt is not null;
        if (headers.Count == 0 || string.IsNullOrWhiteSpace(headers[0])) return required ? (null, DpopError("DPoP proof header is required")) : (null, null);
        if (headers.Count > 1) return (null, DpopError("Multiple DPoP proofs are not allowed"));
        try
        {
            var proof = await dpop.VerifyAsync(headers[0], "POST", TokenUrls(ctx), accessToken: null, expectedJkt, ctx.RequestAborted);
            return (proof.Jkt, null);
        }
        catch (DpopException e) { return (null, e.Code == DpopNonces.UseNonce ? Error(400, e.Code, e.Message) : DpopError(e.Message)); }
    }

    public async Task<string?> CodeBindingAsync(string codeHash) =>
        await db.Set<OAuthDpopBinding>().AsNoTracking().Where(b => b.Id == codeHash && b.ExpiresAt > DateTime.UtcNow).Select(b => b.Jkt).FirstOrDefaultAsync();

    public async Task<string?> FamilyBindingAsync(string familyId) =>
        await db.Set<OAuthDpopBinding>().AsNoTracking().Where(b => b.Id == familyId && b.ExpiresAt > DateTime.UtcNow).Select(b => b.Jkt).FirstOrDefaultAsync();

    public async Task BindCodeAsync(string codeHash, string jkt, DateTime expiresAt)
    {
        db.Set<OAuthDpopBinding>().Add(new OAuthDpopBinding { Id = codeHash, Jkt = jkt, ExpiresAt = expiresAt });
        await db.SaveChangesAsync();
    }

    // ---------------------------------------------------------------- client_credentials

    /// <summary>
    /// The <c>client_credentials</c> grant (RFC 6749 4.4), in the reference's order: the client may use the grant; a public client may not; it must have scopes
    /// authorized for the grant; requested scopes must be among them and never user-delegated ones; a <c>resource</c> must be ours. The token speaks for the
    /// client alone (<c>sub</c> is the client id): no person, no workspace, no refresh token and no ID token.
    /// </summary>
    public async Task<IResult> ClientCredentialsGrantAsync(HttpContext ctx, OAuthClient client, Dictionary<string, string> form)
    {
        var extras = await ExtrasAsync(client.Id);
        if (!AllowsGrant(extras, "client_credentials")) return Error(400, "unauthorized_client", "client is not authorized to use grant type client_credentials");
        if (client.AuthMethod == "none") return Error(400, "unauthorized_client", "public clients cannot use the client_credentials grant");
        var allowed = OAuthConstants.SplitScope(extras?.ClientCredentialsScope);
        if (allowed.Length == 0) return Error(400, "unauthorized_client", "client has no authorized client_credentials scopes");

        string[] scopes = allowed;
        if (form.TryGetValue("scope", out var requested))
        {
            var asked = requested.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var invalid = asked.Where(s => !allowed.Contains(s) || UserDelegatedScopes.Contains(s)).ToArray();
            if (invalid.Length > 0) return Error(400, "invalid_scope", $"The following scopes are invalid: {string.Join(", ", invalid)}");
            if (asked.Length > 0) scopes = [.. asked.Distinct()];
        }
        var resource = urls.CanonicalResource;
        if (form.TryGetValue("resource", out var requestedResource))
        {
            if (urls.NormalizeResource(requestedResource) is not { } normalized) return Error(400, "invalid_target", "The requested resource is not one this server issues tokens for.");
            resource = normalized;
        }

        var (jkt, failure) = await TokenBindingAsync(ctx, extras, expectedJkt: null);
        if (failure is not null) return failure;
        return Results.Json(await tokens.IssueClientCredentialsAsync(client.Id, OAuthConstants.JoinScope(scopes), resource, jkt));
    }
}
