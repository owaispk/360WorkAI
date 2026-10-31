using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.Sso;
using WorkAI360.Api.Features.Scim;
using WorkAI360.Api.Features.Sso;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

public abstract class ScimBase(SsoFactory factory) : IClassFixture<SsoFactory>, IAsyncLifetime
{
    protected readonly SsoFactory Factory = factory;
    protected FakeIdp Idp = null!;
    protected SsoWorld W = null!;
    protected string Token = "";
    protected const string Base = "/api/auth/scim/v2";

    public async Task InitializeAsync()
    {
        Idp = await FakeIdp.StartAsync();
        W = await SsoWorld.CreateAsync(Factory, Idp, Factory.Dns);
        await W.VerifiedTestedAndEnabledAsync();
        Token = await NewTokenAsync(W);
    }
    public async Task DisposeAsync() => await Idp.DisposeAsync();

    protected static async Task<string> NewTokenAsync(SsoWorld w)
    {
        var r = await w.Owner(HttpMethod.Post, "/v1/scim/token", new { });
        Assert.Equal(HttpStatusCode.Created, r.Status);
        return r.Body.GetProperty("scimToken").GetString()!;
    }

    protected async Task<(HttpStatusCode Status, JsonElement Body, HttpResponseMessage Raw)> ScimAs(string? token, HttpMethod method, string path, object? body = null, string? rawBody = null)
    {
        var request = new HttpRequestMessage(method, Base + path);
        if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (rawBody is not null) request.Content = new StringContent(rawBody, Encoding.UTF8, "application/scim+json");
        else if (body is not null) request.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/scim+json");
        var response = await W.Http.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();
        return (response.StatusCode, string.IsNullOrEmpty(text) ? default : JsonDocument.Parse(text).RootElement.Clone(), response);
    }

    protected Task<(HttpStatusCode Status, JsonElement Body, HttpResponseMessage Raw)> Scim(HttpMethod method, string path, object? body = null) => ScimAs(Token, method, path, body);

    protected string Email(string local) => $"{local}@{W.Domain}";

    protected async Task<string> CreateUserAsync(string local, string? externalId = null)
    {
        var r = await Scim(HttpMethod.Post, "/Users", new { schemas = new[] { ScimService.UserSchema }, userName = Email(local), externalId, name = new { givenName = "Gina", familyName = local }, emails = new[] { new { value = Email(local), primary = true } }, active = true });
        Assert.True(r.Status == HttpStatusCode.Created, $"create user {local}: {r.Status} {r.Body}");
        return r.Body.GetProperty("id").GetString()!;
    }

    protected static object Patch(params object[] operations) => new { schemas = new[] { ScimService.PatchSchema }, Operations = operations };
    protected Guid Dummy => Guid.Empty;
}

public sealed class ScimConnectionTests(SsoFactory factory) : ScimBase(factory)
{
    [Fact]
    public async Task The_token_is_shown_once_and_only_its_hash_is_kept()
    {
        await W.Owner(HttpMethod.Delete, "/v1/scim");
        var state = await W.Owner(HttpMethod.Get, "/v1/scim");
        Assert.Equal(JsonValueKind.Null, state.Body.GetProperty("connection").ValueKind);
        Assert.True(state.Body.GetProperty("ssoReady").GetBoolean());
        Assert.Equal("http://localhost/api/auth/scim/v2", state.Body.GetProperty("baseUrl").GetString());

        var created = await W.Owner(HttpMethod.Post, "/v1/scim/token", new { });
        var token = created.Body.GetProperty("scimToken").GetString()!;
        Assert.Equal("metadata_only", created.Body.GetProperty("connection").GetProperty("groupMappingMode").GetString());
        Assert.DoesNotContain(token, (await W.Owner(HttpMethod.Get, "/v1/scim")).Body.ToString());

        var stored = W.Db(db => db.Set<ScimProvider>().Single(p => p.OrganizationId == W.OrgId));
        Assert.DoesNotContain(token, stored.TokenHash);
        var raw = Encoding.UTF8.GetString(Convert.FromBase64String(token.Replace('-', '+').Replace('_', '/').PadRight(token.Length + (4 - token.Length % 4) % 4, '='))).Split(':')[0];
        Assert.DoesNotContain(raw, stored.TokenHash);
        Assert.Equal(ScimService.HashToken(raw), stored.TokenHash);
        Assert.Equal($"openwork-scim-{W.OrgId}", stored.ProviderId);

        // Rotating replaces it: the old token stops working at once.
        Assert.Equal(HttpStatusCode.OK, (await ScimAs(token, HttpMethod.Get, "/Users")).Status);
        var rotated = await NewTokenAsync(W);
        Assert.NotEqual(token, rotated);
        Assert.Equal(HttpStatusCode.Unauthorized, (await ScimAs(token, HttpMethod.Get, "/Users")).Status);
        Assert.Equal(HttpStatusCode.OK, (await ScimAs(rotated, HttpMethod.Get, "/Users")).Status);
    }

    [Fact]
    public async Task A_token_needs_SSO_to_be_on_and_the_right_permission()
    {
        await using var idp = await FakeIdp.StartAsync();
        var fresh = await SsoWorld.CreateAsync(Factory, idp, Factory.Dns);
        var notReady = await fresh.Owner(HttpMethod.Post, "/v1/scim/token", new { });
        Assert.Equal(HttpStatusCode.Conflict, notReady.Status);
        Assert.Equal("sso_required", notReady.Body.GetProperty("error").GetString());
        Assert.Equal(JsonValueKind.Null, (await fresh.Owner(HttpMethod.Get, "/v1/scim")).Body.GetProperty("connection").ValueKind);
        Assert.False((await fresh.Owner(HttpMethod.Get, "/v1/scim")).Body.GetProperty("ssoReady").GetBoolean());

        var (email, token, _) = await Factory.SignUpAsync(W.Http, "Plain Member");
        var invite = await W.Owner(HttpMethod.Post, "/v1/invitations", new { email, role = "member" });
        await W.Http.SendAsync(Bearer(HttpMethod.Post, "/v1/orgs/invitations/accept", token, new { id = invite.Body.GetProperty("invitationId").GetString() }));
        var read = await W.Send(token, HttpMethod.Get, "/v1/scim");
        Assert.Equal(HttpStatusCode.Forbidden, read.Status);
        Assert.Equal("scim.view", read.Body.GetProperty("requiredPermission").GetString());
        foreach (var (method, url) in new[] { (HttpMethod.Post, "/v1/scim/token"), (HttpMethod.Patch, "/v1/scim"), (HttpMethod.Post, "/v1/scim/reconcile"), (HttpMethod.Delete, "/v1/scim") })
            Assert.Equal("scim.manage", (await W.Send(token, method, url, new { groupMappingMode = "create_teams" })).Body.GetProperty("requiredPermission").GetString());
        Assert.Equal(HttpStatusCode.Unauthorized, (await W.Http.GetAsync("/v1/scim")).StatusCode);
    }

    [Fact]
    public async Task Settings_validate_and_deleting_the_connection_ends_the_token()
    {
        var invalid = await W.Owner(HttpMethod.Patch, "/v1/scim", new { groupMappingMode = "everything" });
        Assert.Equal(HttpStatusCode.BadRequest, invalid.Status);
        var ok = await W.Owner(HttpMethod.Patch, "/v1/scim", new { groupMappingMode = "create_teams" });
        Assert.Equal("create_teams", ok.Body.GetProperty("connection").GetProperty("groupMappingMode").GetString());
        var reconcile = await W.Owner(HttpMethod.Post, "/v1/scim/reconcile", new { });
        Assert.Equal(0, reconcile.Body.GetProperty("checked").GetInt32());
        Assert.Equal(HttpStatusCode.NoContent, (await W.Owner(HttpMethod.Delete, "/v1/scim")).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Scim(HttpMethod.Get, "/Users")).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await W.Owner(HttpMethod.Patch, "/v1/scim", new { groupMappingMode = "metadata_only" })).Status);
        Assert.Equal(HttpStatusCode.NoContent, (await W.Owner(HttpMethod.Delete, "/v1/scim")).Status);
    }

    [Fact]
    public async Task Only_the_workspaces_own_token_opens_the_server()
    {
        var none = await ScimAs(null, HttpMethod.Get, "/Users");
        Assert.Equal(HttpStatusCode.Unauthorized, none.Status);
        Assert.Equal("SCIM token is required", none.Body.GetProperty("detail").GetString());
        Assert.Equal("application/scim+json", none.Raw.Content.Headers.ContentType!.MediaType);
        foreach (var bad in new[] { "garbage", "a:b:c", Token[..^2] + "xx", Token + "A", Convert.ToBase64String(Encoding.UTF8.GetBytes($"x:{W.ProviderId}:{W.OrgId}")) })
        {
            var r = await ScimAs(bad, HttpMethod.Get, "/Users");
            Assert.Equal(HttpStatusCode.Unauthorized, r.Status);
            Assert.Equal("Invalid SCIM token", r.Body.GetProperty("detail").GetString());
        }
        // A real secret under another workspace's ids does not open that workspace.
        await using var idp = await FakeIdp.StartAsync();
        var other = await SsoWorld.CreateAsync(Factory, idp, Factory.Dns);
        await other.VerifiedTestedAndEnabledAsync();
        var otherToken = await NewTokenAsync(other);
        var raw = Encoding.UTF8.GetString(Convert.FromBase64String(Token.Replace('-', '+').Replace('_', '/').PadRight(Token.Length + (4 - Token.Length % 4) % 4, '='))).Split(':')[0];
        var crossed = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{raw}:{other.ProviderId.Replace("sso", "scim")}:{other.OrgId}")).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        Assert.Equal(HttpStatusCode.Unauthorized, (await ScimAs(crossed, HttpMethod.Get, "/Users")).Status);
        Assert.Equal(HttpStatusCode.OK, (await ScimAs(otherToken, HttpMethod.Get, "/Users")).Status);
        // The support document is public.
        var config = await ScimAs(null, HttpMethod.Get, "/ServiceProviderConfig");
        Assert.Equal(HttpStatusCode.OK, config.Status);
        Assert.True(config.Body.GetProperty("patch").GetProperty("supported").GetBoolean());
        Assert.Equal(HttpStatusCode.Unauthorized, (await ScimAs(null, HttpMethod.Get, "/Schemas")).Status);
        Assert.Equal(2, (await Scim(HttpMethod.Get, "/ResourceTypes")).Body.GetProperty("totalResults").GetInt32());
        Assert.Equal(HttpStatusCode.NotFound, (await Scim(HttpMethod.Get, "/Schemas/nope")).Status);
    }
}

public sealed class ScimUserTests(SsoFactory factory) : ScimBase(factory)
{
    [Fact]
    public async Task Creating_a_person_makes_a_plain_member_and_answers_in_SCIM_shape()
    {
        var r = await Scim(HttpMethod.Post, "/Users", new { schemas = new[] { ScimService.UserSchema }, userName = Email("Gina").ToUpperInvariant(), externalId = "ext-1", name = new { givenName = "Gina", familyName = "Jones" }, emails = new[] { new { value = Email("gina"), primary = true } } });
        Assert.Equal(HttpStatusCode.Created, r.Status);
        var id = r.Body.GetProperty("id").GetString()!;
        Assert.StartsWith("usr_", id);
        Assert.Equal(Email("gina"), r.Body.GetProperty("userName").GetString());
        Assert.Equal("ext-1", r.Body.GetProperty("externalId").GetString());
        Assert.Equal("Gina Jones", r.Body.GetProperty("displayName").GetString());
        Assert.True(r.Body.GetProperty("active").GetBoolean());
        Assert.Equal(ScimService.UserSchema, r.Body.GetProperty("schemas")[0].GetString());
        Assert.Equal($"http://localhost/api/auth/scim/v2/Users/{id}", r.Body.GetProperty("meta").GetProperty("location").GetString());
        Assert.Equal($"http://localhost/api/auth/scim/v2/Users/{id}", r.Raw.Headers.Location!.ToString());
        Assert.Equal("application/scim+json", r.Raw.Content.Headers.ContentType!.MediaType);

        var member = W.Db(db => db.Members.Single(m => m.UserId == id && m.OrganizationId == W.OrgId));
        Assert.Equal("member", member.Role);   // SCIM never grants a role
        var user = W.Db(db => db.Users.Single(u => u.Id == id));
        Assert.False(user.EmailVerified);
        Assert.Equal(SsoProvisioning.UnusablePassword, user.PasswordHash);
        var identity = W.Db(db => db.Set<ExternalIdentity>().Single(i => i.UserId == id));
        Assert.Equal("scim", identity.Source);
        Assert.True(identity.Active);

        Assert.Equal(HttpStatusCode.Conflict, (await Scim(HttpMethod.Post, "/Users", new { userName = Email("other"), externalId = "ext-1" })).Status);
        var dup = await Scim(HttpMethod.Post, "/Users", new { userName = Email("gina"), externalId = "ext-2" });
        Assert.Equal(HttpStatusCode.Conflict, dup.Status);
        Assert.Equal("uniqueness", dup.Body.GetProperty("scimType").GetString());
        Assert.Equal(HttpStatusCode.BadRequest, (await Scim(HttpMethod.Post, "/Users", new { name = new { givenName = "x" } })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Scim(HttpMethod.Post, "/Users", new { userName = Email("bad"), emails = new[] { new { value = "not-an-email" } } })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Scim(HttpMethod.Post, "/Users", new { userName = Email("inactive"), active = false })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await ScimAs(Token, HttpMethod.Post, "/Users", rawBody: "[1,2")).Status);
    }

    [Fact]
    public async Task SCIM_cannot_adopt_an_account_that_is_not_already_in_the_workspace()
    {
        var (stranger, _, _) = await Factory.SignUpAsync(W.Http, "Stranger");
        var taken = await Scim(HttpMethod.Post, "/Users", new { userName = stranger, externalId = "ext-stranger" });
        Assert.Equal(HttpStatusCode.Conflict, taken.Status);
        Assert.Equal(0, W.Db(db => db.Members.Count(m => m.OrganizationId == W.OrgId && db.Users.Any(u => u.Id == m.UserId && u.Email == stranger))));
        // Someone already in the workspace is linked, not duplicated.
        var linked = await Scim(HttpMethod.Post, "/Users", new { userName = W.OwnerEmail, externalId = "ext-owner" });
        Assert.Equal(HttpStatusCode.Created, linked.Status);
        Assert.Equal(W.OwnerId, linked.Body.GetProperty("id").GetString());
        Assert.Equal(1, W.UsersWithEmail(W.OwnerEmail));
        Assert.Equal("owner", W.Db(db => db.Members.Single(m => m.UserId == W.OwnerId && m.OrganizationId == W.OrgId).Role));
    }

    [Fact]
    public async Task People_can_be_read_listed_and_found_by_user_name()
    {
        var a = await CreateUserAsync("ann", "e-ann");
        var b = await CreateUserAsync("ben", "e-ben");
        var one = await Scim(HttpMethod.Get, $"/Users/{a}");
        Assert.Equal("e-ann", one.Body.GetProperty("externalId").GetString());
        var all = await Scim(HttpMethod.Get, "/Users");
        Assert.Equal(2, all.Body.GetProperty("totalResults").GetInt32());
        Assert.Equal(ScimService.ListSchema, all.Body.GetProperty("schemas")[0].GetString());
        var found = await Scim(HttpMethod.Get, $"/Users?filter={Uri.EscapeDataString($"userName eq \"{Email("BEN")}\"")}");
        Assert.Equal(1, found.Body.GetProperty("totalResults").GetInt32());
        Assert.Equal(b, found.Body.GetProperty("Resources")[0].GetProperty("id").GetString());
        Assert.Equal(0, (await Scim(HttpMethod.Get, $"/Users?filter={Uri.EscapeDataString("userName eq \"nobody@x.test\"")}")).Body.GetProperty("totalResults").GetInt32());
        var bad = await Scim(HttpMethod.Get, "/Users?filter=" + Uri.EscapeDataString("emails.value eq \"x\""));
        Assert.Equal(HttpStatusCode.BadRequest, bad.Status);
        Assert.Equal("invalidFilter", bad.Body.GetProperty("scimType").GetString());
        Assert.Equal(HttpStatusCode.BadRequest, (await Scim(HttpMethod.Get, "/Users?filter=" + Uri.EscapeDataString("userName ne \"x\""))).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await Scim(HttpMethod.Get, "/Users/usr_00000000000000000000000000")).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await Scim(HttpMethod.Get, "/Users/not-an-id")).Status);
    }

    [Fact]
    public async Task One_workspaces_token_cannot_see_or_change_another_workspaces_people()
    {
        var mine = await CreateUserAsync("mine");
        await using var idp = await FakeIdp.StartAsync();
        var other = await SsoWorld.CreateAsync(Factory, idp, Factory.Dns);
        await other.VerifiedTestedAndEnabledAsync();
        var otherToken = await NewTokenAsync(other);
        Assert.Equal(HttpStatusCode.NotFound, (await ScimAs(otherToken, HttpMethod.Get, $"/Users/{mine}")).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await ScimAs(otherToken, HttpMethod.Delete, $"/Users/{mine}")).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await ScimAs(otherToken, HttpMethod.Patch, $"/Users/{mine}", Patch(new { op = "replace", path = "active", value = false }))).Status);
        Assert.Equal(0, (await ScimAs(otherToken, HttpMethod.Get, "/Users")).Body.GetProperty("totalResults").GetInt32());
        Assert.Equal(HttpStatusCode.OK, (await Scim(HttpMethod.Get, $"/Users/{mine}")).Status);
    }

    [Fact]
    public async Task Updating_a_person_changes_their_details_and_refuses_an_email_that_belongs_to_someone_else()
    {
        var a = await CreateUserAsync("uma");
        await CreateUserAsync("vic");
        var put = await Scim(HttpMethod.Put, $"/Users/{a}", new { userName = Email("uma.new"), externalId = "e-uma2", name = new { formatted = "Uma New" }, emails = new[] { new { value = Email("uma.new"), primary = true } }, active = true });
        Assert.Equal(HttpStatusCode.OK, put.Status);
        Assert.Equal("Uma New", put.Body.GetProperty("displayName").GetString());
        Assert.Equal(Email("uma.new"), put.Body.GetProperty("userName").GetString());
        Assert.False(W.Db(db => db.Users.Single(u => u.Id == a).EmailVerified));
        var clash = await Scim(HttpMethod.Put, $"/Users/{a}", new { userName = Email("vic"), emails = new[] { new { value = Email("vic") } } });
        Assert.Equal(HttpStatusCode.Conflict, clash.Status);
        Assert.Equal("Email already in use", clash.Body.GetProperty("detail").GetString());

        Assert.Equal(HttpStatusCode.NoContent, (await Scim(HttpMethod.Patch, $"/Users/{a}", Patch(new { op = "replace", path = "name.givenName", value = "Una" }, new { op = "Replace", value = new { externalId = "e-3" } }))).Status);
        Assert.StartsWith("Una", W.Db(db => db.Users.Single(u => u.Id == a).Name));
        Assert.Equal(Email("vic"), (await Scim(HttpMethod.Get, $"/Users?filter={Uri.EscapeDataString($"userName eq \"{Email("vic")}\"")}")).Body.GetProperty("Resources")[0].GetProperty("userName").GetString());
        Assert.Equal("No valid fields to update", (await Scim(HttpMethod.Patch, $"/Users/{a}", Patch(new { op = "replace", path = "nickName", value = "x" }))).Body.GetProperty("detail").GetString());
        Assert.Equal(HttpStatusCode.BadRequest, (await Scim(HttpMethod.Patch, $"/Users/{a}", new { Operations = new[] { new { op = "replace", path = "active", value = true } } })).Status);
        Assert.Equal(HttpStatusCode.Conflict, (await Scim(HttpMethod.Patch, $"/Users/{a}", Patch(new { op = "replace", path = "userName", value = Email("vic") }))).Status);
    }
}

public sealed class ScimDeprovisionTests(SsoFactory factory) : ScimBase(factory)
{
    private async Task<(HttpClient Browser, string UserId)> SignedInPersonAsync(string local)
    {
        var id = await CreateUserAsync(local, "e-" + local);
        Idp.Identity = ("sub-" + local, Email(local), local);
        var browser = Factory.Browser();
        Assert.Equal("http://localhost/dashboard", (await W.SignInAsync(browser)).Headers.Location!.ToString());
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/v1/me")).StatusCode);
        return (browser, id);
    }

    [Theory]
    [InlineData("patch")]
    [InlineData("put")]
    [InlineData("delete")]
    public async Task Deprovisioning_ends_every_session_and_removes_the_person(string how)
    {
        var (browser, id) = await SignedInPersonAsync("dora");
        var bearer = await Factory.Plain().PostAsJsonAsync("/api/auth/sign-in/email", new { email = W.OwnerEmail, password = Password });
        Assert.Equal(HttpStatusCode.Forbidden, bearer.StatusCode);
        var response = how switch
        {
            "patch" => await Scim(HttpMethod.Patch, $"/Users/{id}", Patch(new { op = "replace", value = new { active = false } })),
            "put" => await Scim(HttpMethod.Put, $"/Users/{id}", new { userName = Email("dora"), active = false }),
            _ => await Scim(HttpMethod.Delete, $"/Users/{id}"),
        };
        Assert.Equal(HttpStatusCode.NoContent, response.Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/v1/me")).StatusCode);
        Assert.Equal(0, W.Db(db => db.Members.Count(m => m.UserId == id)));
        Assert.Equal(0, W.Db(db => db.Sessions.Count(s => s.UserId == id)));
        Assert.Equal(HttpStatusCode.NotFound, (await Scim(HttpMethod.Get, $"/Users/{id}")).Status);
        Assert.Equal(0, W.Db(db => db.Set<ExternalAccount>().Count(a => a.UserId == id)));
        Assert.Equal(1, W.Db(db => db.Set<ScimUserTombstone>().Count(t => t.OrganizationId == W.OrgId && t.DeprovisionedUserId == id)));
        // No other workspace: the person is gone.
        Assert.Equal(0, W.UsersWithEmail(Email("dora")));
    }

    [Fact]
    public async Task A_deprovisioned_person_cannot_come_back_through_SSO_but_can_through_SCIM()
    {
        var (_, id) = await SignedInPersonAsync("evan");
        await Scim(HttpMethod.Delete, $"/Users/{id}");
        Idp.Identity = ("sub-evan", Email("evan"), "Evan");
        var browser = Factory.Browser();
        var refused = await W.SignInAsync(browser);
        Assert.Contains("error=access_denied", refused.Headers.Location!.ToString());
        Assert.Contains("deprovisioned", refused.Headers.Location!.ToString());
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/v1/me")).StatusCode);
        Assert.Equal(0, W.UsersWithEmail(Email("evan")));

        // The identity provider adding them again is the way back.
        var again = await CreateUserAsync("evan", "e-evan");
        Assert.NotEqual(id, again);
        Assert.Equal(0, W.Db(db => db.Set<ScimUserTombstone>().Count(t => t.OrganizationId == W.OrgId && t.Email == Email("evan"))));
        var back = Factory.Browser();
        Assert.Equal("http://localhost/dashboard", (await W.SignInAsync(back)).Headers.Location!.ToString());
        Assert.Equal(HttpStatusCode.OK, (await back.GetAsync("/v1/me")).StatusCode);
    }

    [Fact]
    public async Task Someone_who_belongs_elsewhere_too_keeps_that_and_the_owner_cannot_be_deprovisioned()
    {
        var id = await CreateUserAsync("fay", "e-fay");
        // Fay also belongs to another workspace.
        var (_, otherOwner, _) = await Factory.SignUpAsync(W.Http, "Other Owner");
        var org = await ReadJsonAsync(await W.Http.SendAsync(Bearer(HttpMethod.Post, "/v1/org", otherOwner, new { name = "Elsewhere" })));
        var orgId = org.GetProperty("organization").GetProperty("id").GetString()!;
        Factory.WithDb(db => { db.Members.Add(new Member { Id = Ids.New("om"), OrganizationId = orgId, UserId = id, Role = "member", CreatedAt = DateTime.UtcNow, JoinedAt = DateTime.UtcNow }); db.SaveChanges(); return 0; });
        Assert.Equal(HttpStatusCode.NoContent, (await Scim(HttpMethod.Delete, $"/Users/{id}")).Status);
        Assert.Equal(1, W.UsersWithEmail(Email("fay")));
        Assert.Equal(1, W.Db(db => db.Members.Count(m => m.UserId == id && m.OrganizationId == orgId)));
        Assert.Equal(0, W.Db(db => db.Members.Count(m => m.UserId == id && m.OrganizationId == W.OrgId)));

        await Scim(HttpMethod.Post, "/Users", new { userName = W.OwnerEmail, externalId = "ext-owner" });
        var owner = await Scim(HttpMethod.Delete, $"/Users/{W.OwnerId}");
        Assert.Equal(HttpStatusCode.Conflict, owner.Status);
        Assert.Equal(1, W.Db(db => db.Members.Count(m => m.UserId == W.OwnerId && m.OrganizationId == W.OrgId)));
    }
}

public sealed class ScimGroupTests(SsoFactory factory) : ScimBase(factory)
{
    private async Task<string> GroupAsync(string name, string? externalId = null, params string[] members)
    {
        var r = await Scim(HttpMethod.Post, "/Groups", new { schemas = new[] { ScimService.GroupSchema }, displayName = name, externalId, members = members.Select(m => new { value = m }).ToArray() });
        Assert.True(r.Status == HttpStatusCode.Created, $"create group {name}: {r.Status} {r.Body}");
        return r.Body.GetProperty("id").GetString()!;
    }

    private string[] TeamNames() => W.Db(db => db.Teams.Where(t => t.OrganizationId == W.OrgId).Select(t => t.Name).OrderBy(n => n).ToArray());
    private string[] Members(string teamName) => W.Db(db => (from t in db.Teams where t.OrganizationId == W.OrgId && t.Name == teamName join tm in db.TeamMembers on t.Id equals tm.TeamId join m in db.Members on tm.MemberId equals m.Id select m.UserId).OrderBy(x => x).ToArray());

    [Fact]
    public async Task Groups_are_created_read_listed_replaced_patched_and_deleted()
    {
        var u1 = await CreateUserAsync("g1"); var u2 = await CreateUserAsync("g2");
        var id = await GroupAsync("Engineering", "ext-eng", u1);
        var read = await Scim(HttpMethod.Get, $"/Groups/{id}");
        Assert.Equal(ScimService.GroupSchema, read.Body.GetProperty("schemas")[0].GetString());
        Assert.Equal("ext-eng", read.Body.GetProperty("externalId").GetString());
        Assert.Equal(u1, read.Body.GetProperty("members")[0].GetProperty("value").GetString());
        Assert.Equal($"http://localhost/api/auth/scim/v2/Users/{u1}", read.Body.GetProperty("members")[0].GetProperty("$ref").GetString());
        Assert.Equal($"http://localhost/api/auth/scim/v2/Groups/{id}", read.Body.GetProperty("meta").GetProperty("location").GetString());
        // The person lists the group they are in.
        Assert.Equal(id, (await Scim(HttpMethod.Get, $"/Users/{u1}")).Body.GetProperty("groups")[0].GetProperty("value").GetString());

        await GroupAsync("Sales", null);
        Assert.Equal(2, (await Scim(HttpMethod.Get, "/Groups")).Body.GetProperty("totalResults").GetInt32());
        var filtered = await Scim(HttpMethod.Get, "/Groups?filter=" + Uri.EscapeDataString("displayName eq \"Sales\""));
        Assert.Equal(1, filtered.Body.GetProperty("totalResults").GetInt32());
        var page = await Scim(HttpMethod.Get, "/Groups?startIndex=2&count=1");
        Assert.Equal(2, page.Body.GetProperty("totalResults").GetInt32());
        Assert.Equal(1, page.Body.GetProperty("itemsPerPage").GetInt32());

        var put = await Scim(HttpMethod.Put, $"/Groups/{id}", new { displayName = "Eng", externalId = "ext-eng", members = new[] { new { value = u2 } } });
        Assert.Equal("Eng", put.Body.GetProperty("displayName").GetString());
        Assert.Equal(u2, put.Body.GetProperty("members")[0].GetProperty("value").GetString());

        await Scim(HttpMethod.Patch, $"/Groups/{id}", Patch(new { op = "add", path = "members", value = new[] { new { value = u1 } } }));
        Assert.Equal(2, (await Scim(HttpMethod.Get, $"/Groups/{id}")).Body.GetProperty("members").GetArrayLength());
        await Scim(HttpMethod.Patch, $"/Groups/{id}", Patch(new { op = "remove", path = $"members[value eq \"{u2}\"]" }));
        Assert.Equal(u1, (await Scim(HttpMethod.Get, $"/Groups/{id}")).Body.GetProperty("members")[0].GetProperty("value").GetString());
        await Scim(HttpMethod.Patch, $"/Groups/{id}", Patch(new { op = "replace", path = "displayName", value = "Platform" }));
        Assert.Equal("Platform", (await Scim(HttpMethod.Get, $"/Groups/{id}")).Body.GetProperty("displayName").GetString());
        await Scim(HttpMethod.Patch, $"/Groups/{id}", Patch(new { op = "remove", path = "members" }));
        Assert.Equal(0, (await Scim(HttpMethod.Get, $"/Groups/{id}")).Body.GetProperty("members").GetArrayLength());

        Assert.Equal(HttpStatusCode.NoContent, (await Scim(HttpMethod.Delete, $"/Groups/{id}")).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await Scim(HttpMethod.Get, $"/Groups/{id}")).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await Scim(HttpMethod.Delete, $"/Groups/{id}")).Status);
    }

    [Fact]
    public async Task Groups_validate_their_input()
    {
        await GroupAsync("Dup", "same");
        Assert.Equal(HttpStatusCode.Conflict, (await Scim(HttpMethod.Post, "/Groups", new { displayName = "Another", externalId = "same" })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Scim(HttpMethod.Post, "/Groups", new { displayName = "  " })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Scim(HttpMethod.Post, "/Groups", new { externalId = "x" })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Scim(HttpMethod.Patch, "/Groups/scg_00000000000000000000000000", new { schemas = new[] { "x" }, Operations = new[] { new { op = "add" } } })).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await Scim(HttpMethod.Patch, "/Groups/scg_00000000000000000000000000", Patch(new { op = "add", path = "displayName", value = "x" }))).Status);
    }

    [Fact]
    public async Task By_default_groups_are_only_metadata_and_create_no_teams_or_roles()
    {
        var u = await CreateUserAsync("meta");
        await GroupAsync("Admins", null, u);
        Assert.Empty(TeamNames());
        Assert.Equal("member", W.Db(db => db.Members.Single(m => m.UserId == u && m.OrganizationId == W.OrgId).Role));
    }

    [Fact]
    public async Task Mapping_groups_to_teams_follows_the_identity_provider_and_locks_manual_edits()
    {
        await W.Owner(HttpMethod.Post, "/v1/teams", new { name = "Design", memberIds = Array.Empty<string>() });
        var u1 = await CreateUserAsync("t1"); var u2 = await CreateUserAsync("t2");
        var early = await GroupAsync("Design", null, u1);              // before mapping is on: only metadata
        Assert.Equal(["Design"], TeamNames());
        var on = await W.Owner(HttpMethod.Patch, "/v1/scim", new { groupMappingMode = "create_teams" });
        Assert.Equal("create_teams", on.Body.GetProperty("connection").GetProperty("groupMappingMode").GetString());
        // The group's team does not clash with the manual team of the same name.
        Assert.Equal(["Design", "Design (SCIM)"], TeamNames());
        Assert.Equal([u1], Members("Design (SCIM)"));

        await Scim(HttpMethod.Patch, $"/Groups/{early}", Patch(new { op = "add", path = "members", value = new[] { new { value = u2 } } }));
        Assert.Equal(new[] { u1, u2 }.Order().ToArray(), Members("Design (SCIM)"));
        await Scim(HttpMethod.Patch, $"/Groups/{early}", Patch(new { op = "remove", path = $"members[value eq \"{u1}\"]" }));
        Assert.Equal([u2], Members("Design (SCIM)"));
        await Scim(HttpMethod.Put, $"/Groups/{early}", new { displayName = "Product", members = new[] { new { value = u1 } } });
        Assert.Equal(["Design", "Product"], TeamNames());
        Assert.Equal([u1], Members("Product"));

        // A new group made after mapping is on gets a team straight away; a person who joins later is attached when they arrive.
        var later = await GroupAsync("Support", null, "usr_00000000000000000000000000");
        Assert.Contains("Support", TeamNames());
        Assert.Empty(Members("Support"));

        // The team is the identity provider's: manual edits and deletion are refused, the manual team is unaffected.
        var teamId = W.Db(db => db.Teams.Single(t => t.OrganizationId == W.OrgId && t.Name == "Product").Id);
        var rename = await W.Owner(HttpMethod.Patch, $"/v1/teams/{teamId}", new { name = "Renamed" });
        Assert.Equal(HttpStatusCode.Conflict, rename.Status);
        Assert.Equal("scim_managed_team", rename.Body.GetProperty("error").GetString());
        Assert.Equal(HttpStatusCode.Conflict, (await W.Owner(HttpMethod.Patch, $"/v1/teams/{teamId}", new { memberIds = Array.Empty<string>() })).Status);
        Assert.Equal("scim_managed_team", (await W.Owner(HttpMethod.Delete, $"/v1/teams/{teamId}")).Body.GetProperty("error").GetString());
        var manual = W.Db(db => db.Teams.Single(t => t.OrganizationId == W.OrgId && t.Name == "Design").Id);
        Assert.Equal(HttpStatusCode.OK, (await W.Owner(HttpMethod.Patch, $"/v1/teams/{manual}", new { name = "Design 2" })).Status);

        // Deleting the group removes its team's people; turning mapping off keeps the team but gives it back.
        await Scim(HttpMethod.Delete, $"/Groups/{later}");
        await W.Owner(HttpMethod.Patch, "/v1/scim", new { groupMappingMode = "metadata_only" });
        Assert.Equal(HttpStatusCode.OK, (await W.Owner(HttpMethod.Patch, $"/v1/teams/{teamId}", new { name = "Product Team" })).Status);
    }

    [Fact]
    public async Task A_group_projected_to_a_team_never_keeps_Admin_authority_when_it_is_handed_back_or_removed()
    {
        await W.Owner(HttpMethod.Patch, "/v1/scim", new { groupMappingMode = "create_teams" });
        var u = await CreateUserAsync("adm");
        await GroupAsync("Ops", null, u);
        var teamId = W.Db(db => db.Teams.Single(t => t.OrganizationId == W.OrgId && t.Name == "Ops").Id);
        Factory.WithDb(db => { db.Teams.Where(t => t.Id == teamId).ExecuteUpdate(s => s.SetProperty(t => t.GrantsOrganizationAdmin, true)); return 0; });
        await W.Owner(HttpMethod.Patch, "/v1/scim", new { groupMappingMode = "metadata_only" });
        Assert.False(W.Db(db => db.Teams.Single(t => t.Id == teamId).GrantsOrganizationAdmin));

        await W.Owner(HttpMethod.Patch, "/v1/scim", new { groupMappingMode = "create_teams" });
        Factory.WithDb(db => { db.Teams.Where(t => t.Id == teamId).ExecuteUpdate(s => s.SetProperty(t => t.GrantsOrganizationAdmin, true)); return 0; });
        await W.Owner(HttpMethod.Delete, "/v1/scim");
        Assert.False(W.Db(db => db.Teams.Single(t => t.Id == teamId).GrantsOrganizationAdmin));
        Assert.Equal(1, W.Db(db => db.Teams.Count(t => t.Id == teamId)));       // the team stays, as an ordinary team
    }
}

public sealed class ScimReconcileTests(SsoFactory factory) : ScimBase(factory)
{
    [Fact]
    public async Task Reconcile_repairs_drift_it_can_and_reports_what_needs_a_person()
    {
        var gone = await CreateUserAsync("gone");
        var broken = await CreateUserAsync("broken");
        await CreateUserAsync("fine");
        // One person was removed from the workspace behind SCIM's back; another lost their SCIM account.
        Factory.WithDb(db => { db.Members.Where(m => m.UserId == gone).ExecuteDelete(); db.Set<ExternalAccount>().Where(a => a.UserId == broken).ExecuteDelete(); return 0; });

        var run = await W.Owner(HttpMethod.Post, "/v1/scim/reconcile", new { });
        Assert.Equal(HttpStatusCode.OK, run.Status);
        Assert.Equal(3, run.Body.GetProperty("checked").GetInt32());
        Assert.Equal(1, run.Body.GetProperty("repaired").GetInt32());
        Assert.Equal(1, run.Body.GetProperty("failures").GetInt32());
        Assert.False(W.Db(db => db.Set<ExternalIdentity>().Single(i => i.UserId == gone).Active));

        var health = (await W.Owner(HttpMethod.Get, "/v1/scim")).Body.GetProperty("health");
        Assert.Equal(1, health.GetProperty("unresolvedFailureCount").GetInt32());
        Assert.Equal("reconcile_drift", health.GetProperty("lastFailureAction").GetString());
        Assert.NotEqual(JsonValueKind.Null, health.GetProperty("lastSuccessfulSyncAt").ValueKind);

        // Running again does not pile up duplicate reports, and what was repaired is no longer drift.
        var again = await W.Owner(HttpMethod.Post, "/v1/scim/reconcile", new { });
        Assert.Equal(0, again.Body.GetProperty("repaired").GetInt32());
        Assert.Equal(1, (await W.Owner(HttpMethod.Get, "/v1/scim")).Body.GetProperty("health").GetProperty("unresolvedFailureCount").GetInt32());
    }
}
