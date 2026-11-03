using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Domain.OAuthProviders;
using WorkAI360.Api.Features.OAuthProviders;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

public sealed class OAuthProviderTests : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _factory;
    public OAuthProviderTests(ApiFactory factory) => _factory = factory;

    private const string Secret = "s3cret-value-1234567890";

    [Fact]
    public async Task The_secret_is_stored_encrypted_never_returned_and_can_be_replaced()
    {
        var w = await Workspace.CreateAsync(_factory, "OAuth secrets");
        var saved = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/oauth-providers/google-workspace/client", new { clientId = "client-1", clientSecret = Secret });
        Assert.Equal(HttpStatusCode.OK, saved.Status);
        Assert.DoesNotContain(Secret, saved.Body.ToString());
        var read = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/oauth-providers/google-workspace/client");
        Assert.DoesNotContain(Secret, read.Body.ToString());
        Assert.False(read.Body.TryGetProperty("clientSecret", out _));

        var first = _factory.WithDb(db => db.Set<OrgOAuthClient>().AsNoTracking().Single(c => c.OrganizationId == w.OrgId));
        Assert.NotNull(first.ClientSecretEnc);
        Assert.DoesNotContain(Secret, first.ClientSecretEnc);
        Assert.StartsWith("v1.", first.ClientSecretEnc);

        // Saving again without a secret keeps it; with one replaces it (a fresh nonce, so the stored text differs).
        await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/oauth-providers/google-workspace/client", new { clientId = "client-2" });
        Assert.Equal(first.ClientSecretEnc, _factory.WithDb(db => db.Set<OrgOAuthClient>().AsNoTracking().Single(c => c.OrganizationId == w.OrgId).ClientSecretEnc));
        await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/oauth-providers/google-workspace/client", new { clientSecret = Secret });
        var replaced = _factory.WithDb(db => db.Set<OrgOAuthClient>().AsNoTracking().Single(c => c.OrganizationId == w.OrgId));
        Assert.NotEqual(first.ClientSecretEnc, replaced.ClientSecretEnc);
        Assert.Equal("client-2", replaced.ClientId);
        // A refused save does not echo the secret either.
        var refused = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/oauth-providers/microsoft-365/client", new { clientId = "ms", clientSecret = Secret });
        Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
        Assert.DoesNotContain(Secret, refused.Body.ToString());
    }

    [Fact]
    public async Task Reading_and_saving_follow_their_own_permissions_and_a_stale_sign_in_cannot_read()
    {
        var w = await Workspace.CreateAsync(_factory, "OAuth rights");
        var member = await w.AddAsync();
        var readers = await w.TeamAsync("App viewers", member);
        await w.RoleAsync(readers, "oauth_clients.view");

        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(member, HttpMethod.Get, "/v1/oauth-providers/google-workspace/client")).Status);
        var write = await w.CallAsync(member, HttpMethod.Post, "/v1/oauth-providers/google-workspace/client", new { clientId = "sneaky" });
        Assert.Equal(HttpStatusCode.Forbidden, write.Status);
        Assert.Equal("oauth_clients.manage", write.Body.GetProperty("requiredPermission").GetString());
        Assert.Empty(_factory.WithDb(db => db.Set<OrgOAuthClient>().Where(c => c.OrganizationId == w.OrgId).ToList()));

        var plain = await w.AddAsync();
        Assert.Equal("oauth_clients.view", (await w.CallAsync(plain, HttpMethod.Get, "/v1/oauth-providers/google-workspace/client")).Body.GetProperty("requiredPermission").GetString());
        Assert.Equal("oauth_clients.view", (await w.CallAsync(plain, HttpMethod.Get, "/v1/oauth-providers/google-workspace/api-check")).Body.GetProperty("requiredPermission").GetString());

        // The read needs a sign-in within the last 24 hours.
        var longAgo = DateTime.UtcNow.AddHours(-25);
        _factory.WithDb(db => db.Set<WorkAI360.Api.Domain.Session>().Where(x => x.UserId == member.UserId).ExecuteUpdate(x => x.SetProperty(y => y.CreatedAt, longAgo)));
        var stale = await w.CallAsync(member, HttpMethod.Get, "/v1/oauth-providers/google-workspace/client");
        Assert.Equal(HttpStatusCode.Forbidden, stale.Status);
        Assert.Equal("reauth", stale.Body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Each_workspace_has_its_own_app_and_two_first_saves_at_once_end_up_with_one()
    {
        var w = await Workspace.CreateAsync(_factory, "OAuth races");
        var other = await Workspace.CreateAsync(_factory, "OAuth races other");
        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(i => w.CallAsync(w.Owner, HttpMethod.Post, "/v1/oauth-providers/google-workspace/client", new { clientId = $"client-{i}", clientSecret = Secret })));
        Assert.All(results, r => Assert.Equal(HttpStatusCode.OK, r.Status));
        Assert.Equal(1, _factory.WithDb(db => db.Set<OrgOAuthClient>().Count(c => c.OrganizationId == w.OrgId)));
        var theirs = await other.CallAsync(other.Owner, HttpMethod.Get, "/v1/oauth-providers/google-workspace/client");
        Assert.False(theirs.Body.GetProperty("configured").GetBoolean());
        Assert.Equal(JsonValueKind.Null, theirs.Body.GetProperty("clientId").ValueKind);
    }

    [Fact]
    public void Tenants_and_scopes_follow_the_reference()
    {
        Assert.Equal("contoso.com", NativeProviders.NormalizeTenant(" Contoso.COM "));
        Assert.Equal("0f4b5c2e-1111-4222-8333-444455556666", NativeProviders.NormalizeTenant("0F4B5C2E-1111-4222-8333-444455556666"));
        Assert.Null(NativeProviders.NormalizeTenant("common"));
        Assert.Null(NativeProviders.NormalizeTenant("organizations"));
        Assert.Null(NativeProviders.NormalizeTenant("consumers"));
        Assert.Null(NativeProviders.NormalizeTenant("not a tenant"));
        Assert.Null(NativeProviders.NormalizeTenant(null));
        var google = NativeProviders.Find("google-workspace")!;
        Assert.Equal(["calendarRead", "gmailDraft", "driveFile"], google.Features(null));
        Assert.Equal(["gmailRead"], google.Features("""["gmailRead","nope","gmailRead",1]"""));
        // gmailDraft and gmailSend ask for the same scope, which is listed once.
        Assert.Single(google.Scopes(["gmailDraft", "gmailSend"]), "https://www.googleapis.com/auth/gmail.compose");
    }
}
