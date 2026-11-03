using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using WorkAI360.Api.Domain.Onboarding;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>The RFC 7523 JWT-bearer grant: a provisional workspace's agent trades its pre-claim assertion for a short MCP token.</summary>
public sealed class PreclaimGrantTests(OnboardingFactory factory) : IClassFixture<OnboardingFactory>
{
    private const string GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    private async Task<(string Assertion, string BootstrapId, string OrgId, string OwnerLinkToken)> ProvisionAsync()
    {
        var r = await factory.Plain().PostAsJsonAsync("/v1/bootstrap/workspace", new { workspaceName = "Agent Space", claimRoles = new[] { "owner" } });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var body = await ReadJsonAsync(r);
        return (body.GetProperty("identity").GetProperty("assertion").GetString()!, body.GetProperty("setup").GetProperty("id").GetString()!,
            body.GetProperty("organization").GetProperty("id").GetString()!, body.GetProperty("claimLinks")[0].GetProperty("token").GetString()!);
    }

    private async Task<(HttpStatusCode Status, JsonElement Body, HttpResponseMessage Raw)> ExchangeAsync(string? assertion, string grant = GrantType)
    {
        var form = new Dictionary<string, string> { ["grant_type"] = grant };
        if (assertion is not null) form["assertion"] = assertion;
        var response = await factory.Plain().PostAsync("/api/auth/oauth2/token", new FormUrlEncodedContent(form));
        return (response.StatusCode, await ReadJsonAsync(response), response);
    }

    private async Task<HttpStatusCode> McpAsync(string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/mcp/agent") { Content = JsonContent.Create(new { jsonrpc = "2.0", id = 1, method = "ping" }) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return (await factory.Plain().SendAsync(request)).StatusCode;
    }

    private static JsonElement Payload(string jwt)
    {
        var part = jwt.Split('.')[1].Replace('-', '+').Replace('_', '/');
        return JsonDocument.Parse(Convert.FromBase64String(part.PadRight((part.Length + 3) / 4 * 4, '='))).RootElement.Clone();
    }

    [Fact]
    public async Task The_agent_exchanges_its_assertion_for_a_short_mcp_token_for_its_workspace()
    {
        var (assertion, bootstrapId, orgId, _) = await ProvisionAsync();
        var (status, body, raw) = await ExchangeAsync(assertion);
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal("no-store", raw.Headers.CacheControl?.ToString());
        Assert.Equal("Bearer", body.GetProperty("token_type").GetString());
        Assert.Equal("mcp:read mcp:write", body.GetProperty("scope").GetString());
        Assert.InRange(body.GetProperty("expires_in").GetInt32(), 890, 900);
        Assert.False(body.TryGetProperty("refresh_token", out _));

        var token = body.GetProperty("access_token").GetString()!;
        var claims = Payload(token);
        var agent = factory.WithDb(db => db.Set<WorkspaceBootstrap>().Single(b => b.Id == bootstrapId).AgentUserId);
        Assert.Equal(agent, claims.GetProperty("sub").GetString());
        Assert.Equal(orgId, claims.GetProperty("org_id").GetString());
        Assert.Equal("openwork-preclaim", claims.GetProperty("azp").GetString());
        Assert.Equal("mcp", claims.GetProperty("token_use").GetString());
        Assert.Equal(HttpStatusCode.OK, await McpAsync(token));

        // Exchanging again works (no refresh token: the agent re-exchanges).
        Assert.Equal(HttpStatusCode.OK, (await ExchangeAsync(assertion)).Status);
    }

    [Fact]
    public async Task Claiming_the_workspace_revokes_the_assertion_and_every_token_minted_from_it()
    {
        var (assertion, _, _, ownerLink) = await ProvisionAsync();
        var token = (await ExchangeAsync(assertion)).Body.GetProperty("access_token").GetString()!;
        Assert.Equal(HttpStatusCode.OK, await McpAsync(token));

        var (_, personToken, _) = await factory.SignUpAsync(factory.Plain(), "Claimer");
        var claim = await factory.Plain().SendAsync(Bearer(HttpMethod.Post, "/v1/bootstrap/claims/accept", personToken, new { token = ownerLink }));
        Assert.Equal(HttpStatusCode.OK, claim.StatusCode);

        var (status, body, _) = await ExchangeAsync(assertion);
        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_grant", body.GetProperty("error").GetString());
        Assert.Equal("This workspace was claimed or expired; its pre-claim credentials are revoked.", body.GetProperty("error_description").GetString());
        Assert.Equal(HttpStatusCode.Unauthorized, await McpAsync(token));
    }

    [Fact]
    public async Task Missing_forged_or_foreign_assertions_are_refused()
    {
        var (missingStatus, missing, _) = await ExchangeAsync(null);
        Assert.Equal(HttpStatusCode.BadRequest, missingStatus);
        Assert.Equal("invalid_request", missing.GetProperty("error").GetString());
        Assert.Equal("The assertion parameter is required.", missing.GetProperty("error_description").GetString());

        var (assertion, _, _, _) = await ProvisionAsync();
        var parts = assertion.Split('.');
        // A changed payload (another workspace id) with the old signature, a truncated token, a different signature and an access token are all invalid.
        var payload = Encoding.UTF8.GetString(Convert.FromBase64String(parts[1].Replace('-', '+').Replace('_', '/').PadRight((parts[1].Length + 3) / 4 * 4, '=')));
        var forgedPayload = Convert.ToBase64String(Encoding.UTF8.GetBytes(payload.Replace("\"bid\":\"", "\"bid\":\"x"))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var someToken = (await ExchangeAsync(assertion)).Body.GetProperty("access_token").GetString()!;
        foreach (var bad in new[] { $"{parts[0]}.{forgedPayload}.{parts[2]}", $"{parts[0]}.{parts[1]}", $"{parts[0]}.{parts[1]}.{parts[2][..^4]}AAAA", someToken, "not-a-jwt" })
        {
            var (status, body, _) = await ExchangeAsync(bad);
            Assert.Equal(HttpStatusCode.BadRequest, status);
            Assert.Equal("invalid_grant", body.GetProperty("error").GetString());
        }
    }

    [Fact]
    public async Task Discovery_advertises_the_grant_and_how_agents_start()
    {
        var meta = await ReadJsonAsync(await factory.Plain().GetAsync("/.well-known/oauth-authorization-server"));
        Assert.Contains(GrantType, meta.GetProperty("grant_types_supported").EnumerateArray().Select(g => g.GetString()));
        var agentAuth = meta.GetProperty("agent_auth");
        Assert.EndsWith("/v1/bootstrap/workspace", agentAuth.GetProperty("identity_endpoint").GetString());
        Assert.EndsWith("/v1/bootstrap/workspace/{bootstrap_id}/claim", agentAuth.GetProperty("claim_endpoint").GetString());
        Assert.Equal("anonymous", agentAuth.GetProperty("identity_types_supported")[0].GetString());
    }
}
