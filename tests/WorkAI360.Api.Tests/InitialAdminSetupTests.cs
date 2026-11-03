using System.Net;
using System.Net.Http.Json;
using System.Text;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Domain.PlatformAdmin;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>A private deployment waiting for its first administrator: two configured addresses and a one-time code. Each factory is a fresh database.</summary>
public class InitialAdminSetupFactory : ApiFactory
{
    public const string AdminEmail = "first.admin@example.com";
    public const string OtherAdminEmail = "second.admin@example.com";
    public const string Code = "correct-horse-battery-staple-42";
    protected override IEnumerable<KeyValuePair<string, string>> Settings =>
    [
        new("PlatformAdmin:BootstrapEmails", $"{AdminEmail.ToUpperInvariant()}, {OtherAdminEmail}"),
        new("PlatformAdmin:InitialAdminCode", Code),
        new("PlatformAdmin:InitialWorkspaceName", "Acme Deployment"),
    ];
}

public sealed class InitialAdminSetupFlowFactory : InitialAdminSetupFactory;
public sealed class InitialAdminSetupGateFactory : InitialAdminSetupFactory;
public sealed class InitialAdminSetupGrantFactory : InitialAdminSetupFactory;

/// <summary>Setup configured but with email verification on: the person is verified by the code and can sign in at once.</summary>
public sealed class InitialAdminSetupVerifiedFactory : InitialAdminSetupFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Settings => [.. base.Settings, new("Auth:RequireEmailVerification", "true")];
}

/// <summary>An address is configured but no code: setup is unavailable and ordinary sign-up is open.</summary>
public sealed class InitialAdminSetupNoCodeFactory : ApiFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Settings => [new("PlatformAdmin:BootstrapEmails", InitialAdminSetupFactory.AdminEmail)];
}

file static class Setup
{
    public static async Task<string> StatusAsync(HttpClient http) =>
        (await ReadJsonAsync(await http.GetAsync("/v1/auth/bootstrap/status"))).GetProperty("status").GetString()!;

    public static Task<HttpResponseMessage> VerifyAsync(HttpClient http, string email, string code) =>
        http.PostAsJsonAsync("/v1/auth/bootstrap/verify", new { email, code });

    public static async Task<string> GrantAsync(HttpClient http, string email)
    {
        var r = await VerifyAsync(http, email, InitialAdminSetupFactory.Code);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return (await ReadJsonAsync(r)).GetProperty("grant").GetString()!;
    }

    public static Task<HttpResponseMessage> SignUpAsync(HttpClient http, string email, string? grant) =>
        http.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "First Admin", email, password = Password, bootstrapGrant = grant });
}

public sealed class InitialAdminSetupFlowTests(InitialAdminSetupFlowFactory factory) : IClassFixture<InitialAdminSetupFlowFactory>
{
    [Fact]
    public async Task The_operator_creates_the_first_account_which_owns_a_workspace_and_is_a_platform_admin_then_setup_closes()
    {
        var http = factory.Plain();
        Assert.Equal("available", await Setup.StatusAsync(http));

        // Address matching ignores case and spaces, as everywhere else.
        var verify = await Setup.VerifyAsync(http, "  First.Admin@Example.com ", InitialAdminSetupFactory.Code);
        Assert.Equal(HttpStatusCode.OK, verify.StatusCode);
        var body = await ReadJsonAsync(verify);
        var grant = body.GetProperty("grant").GetString()!;
        Assert.StartsWith("ow_bootstrap_", grant);
        var expires = DateTime.Parse(body.GetProperty("expiresAt").GetString()!, null, System.Globalization.DateTimeStyles.RoundtripKind);
        Assert.InRange(expires - DateTime.UtcNow, TimeSpan.FromMinutes(9), TimeSpan.FromMinutes(10.1));

        var signUp = await Setup.SignUpAsync(http, InitialAdminSetupFactory.AdminEmail, grant);
        Assert.Equal(HttpStatusCode.OK, signUp.StatusCode);
        var created = await ReadJsonAsync(signUp);
        var token = created.GetProperty("token").GetString()!;
        Assert.True(created.GetProperty("user").GetProperty("emailVerified").GetBoolean());

        // The session lands in the new workspace, which the person owns.
        var orgs = await ReadJsonAsync(await http.SendAsync(Bearer(HttpMethod.Get, "/v1/me/orgs", token)));
        var org = Assert.Single(orgs.GetProperty("orgs").EnumerateArray());
        Assert.Equal("Acme Deployment", org.GetProperty("name").GetString());
        Assert.Equal("owner", org.GetProperty("role").GetString());
        Assert.True(org.GetProperty("isActive").GetBoolean());

        // A platform admin, recorded with the setup note.
        Assert.Equal(HttpStatusCode.OK, (await http.SendAsync(Bearer(HttpMethod.Get, "/v1/admin/overview", token))).StatusCode);
        var note = factory.WithDb(db => db.Set<AdminAllowlistEntry>().Single(a => a.Email == InitialAdminSetupFactory.AdminEmail).Note);
        Assert.Equal("Initial administrator bootstrap", note);

        // Closed for good: status, a second verification, and reusing the same grant.
        Assert.Equal("complete", await Setup.StatusAsync(http));
        var again = await Setup.VerifyAsync(http, InitialAdminSetupFactory.OtherAdminEmail, InitialAdminSetupFactory.Code);
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
        Assert.Equal("bootstrap_unavailable", (await ReadJsonAsync(again)).GetProperty("error").GetString());
        var otherGrantReuse = await Setup.SignUpAsync(http, InitialAdminSetupFactory.AdminEmail, grant);
        Assert.Equal(HttpStatusCode.Forbidden, otherGrantReuse.StatusCode);

        // Ordinary sign-up is open now.
        var ordinary = await http.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Later Person", email = NewEmail(), password = Password });
        Assert.Equal(HttpStatusCode.OK, ordinary.StatusCode);
    }
}

public sealed class InitialAdminSetupGateTests(InitialAdminSetupGateFactory factory) : IClassFixture<InitialAdminSetupGateFactory>
{
    [Fact]
    public async Task Wrong_code_unlisted_address_and_bad_bodies_get_one_answer_and_nothing_is_created()
    {
        var http = factory.Plain();
        foreach (var (email, code) in new[]
        {
            (InitialAdminSetupFactory.AdminEmail, "wrong-code"),
            (InitialAdminSetupFactory.AdminEmail, InitialAdminSetupFactory.Code + " "),
            ("someone.else@example.com", InitialAdminSetupFactory.Code),
            ("not-an-address", InitialAdminSetupFactory.Code),
            (InitialAdminSetupFactory.AdminEmail, ""),
        })
        {
            var r = await Setup.VerifyAsync(http, email, code);
            Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
            var body = await ReadJsonAsync(r);
            Assert.Equal("bootstrap_verification_failed", body.GetProperty("error").GetString());
            Assert.Equal("Setup could not be verified. Check the administrator email and one-time setup code.", body.GetProperty("message").GetString());
        }
        var notJson = await http.PostAsync("/v1/auth/bootstrap/verify", new StringContent("{", Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.Forbidden, notJson.StatusCode);
        Assert.Equal(0, factory.WithDb(db => db.Users.Count()));
        Assert.Equal("available", await Setup.StatusAsync(http));
    }

    [Fact]
    public async Task While_setup_is_open_no_other_way_creates_the_first_account()
    {
        var http = factory.Plain();
        var ordinary = await http.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Early Bird", email = NewEmail(), password = Password });
        Assert.Equal(HttpStatusCode.Forbidden, ordinary.StatusCode);
        Assert.Equal("setup_required", (await ReadJsonAsync(ordinary)).GetProperty("error").GetString());

        // Even a configured administrator address needs the grant: knowing the address is not enough.
        var noGrant = await http.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Admin", email = InitialAdminSetupFactory.AdminEmail, password = Password });
        Assert.Equal(HttpStatusCode.Forbidden, noGrant.StatusCode);

        var agent = await http.PostAsJsonAsync("/v1/bootstrap/workspace", new { workspaceName = "Agent Space" });
        Assert.Equal(HttpStatusCode.Forbidden, agent.StatusCode);
        Assert.Equal("setup_required", (await ReadJsonAsync(agent)).GetProperty("error").GetString());

        Assert.Equal(0, factory.WithDb(db => db.Users.Count()));
        Assert.Equal("available", await Setup.StatusAsync(http));
    }
}

public sealed class InitialAdminSetupGrantTests(InitialAdminSetupGrantFactory factory) : IClassFixture<InitialAdminSetupGrantFactory>
{
    [Fact]
    public async Task A_grant_only_works_unaltered_unexpired_and_for_its_own_address()
    {
        var http = factory.Plain();
        var grant = await Setup.GrantAsync(http, InitialAdminSetupFactory.AdminEmail);

        // Issued for the first address: the second configured address cannot use it.
        Assert.Equal(HttpStatusCode.Forbidden, (await Setup.SignUpAsync(http, InitialAdminSetupFactory.OtherAdminEmail, grant)).StatusCode);

        // Any change to the payload or signature breaks it, including one that names another address with the old signature.
        var payload = grant["ow_bootstrap_".Length..].Split('.')[0];
        var signature = grant.Split('.')[1];
        var forged = "ow_bootstrap_" + Base64Url(Encoding.UTF8.GetBytes($"{{\"email\":\"{InitialAdminSetupFactory.OtherAdminEmail}\",\"expiresAt\":{DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeMilliseconds()}}}")) + "." + signature;
        foreach (var bad in new[] { forged, grant + "x", grant.Replace(".", ".A"), "ow_bootstrap_" + payload, "ow_bootstrap_", "not-a-grant", grant[..^2] })
        {
            var r = await Setup.SignUpAsync(http, InitialAdminSetupFactory.AdminEmail, bad);
            Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
            Assert.Equal("bootstrap_verification_failed", (await ReadJsonAsync(r)).GetProperty("error").GetString());
        }

        // An expired grant, correctly signed (built with the server's own key derivation), is refused.
        var expired = Sign(InitialAdminSetupFactory.AdminEmail, DateTimeOffset.UtcNow.AddSeconds(-1));
        Assert.Equal(HttpStatusCode.Forbidden, (await Setup.SignUpAsync(http, InitialAdminSetupFactory.AdminEmail, expired)).StatusCode);
        // ...and a correctly signed unexpired one works, which proves the expired case failed on time alone.
        var fresh = Sign(InitialAdminSetupFactory.AdminEmail, DateTimeOffset.UtcNow.AddMinutes(5));
        Assert.Equal(0, factory.WithDb(db => db.Users.Count()));
        Assert.Equal(HttpStatusCode.OK, (await Setup.SignUpAsync(http, InitialAdminSetupFactory.AdminEmail, fresh)).StatusCode);
    }

    private static string Sign(string email, DateTimeOffset expiresAt)
    {
        var key = System.Security.Cryptography.HMACSHA256.HashData(Encoding.UTF8.GetBytes(Secret), "workai360:initial-admin-bootstrap"u8);
        var payload = Base64Url(Encoding.UTF8.GetBytes($"{{\"email\":\"{email}\",\"expiresAt\":{expiresAt.ToUnixTimeMilliseconds()}}}"));
        return "ow_bootstrap_" + payload + "." + Base64Url(System.Security.Cryptography.HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(payload)));
    }

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

public sealed class InitialAdminSetupVerifiedTests(InitialAdminSetupVerifiedFactory factory) : IClassFixture<InitialAdminSetupVerifiedFactory>
{
    [Fact]
    public async Task With_email_verification_on_the_setup_account_is_verified_and_signs_in_straight_into_its_workspace()
    {
        var http = factory.Plain();
        var grant = await Setup.GrantAsync(http, InitialAdminSetupFactory.AdminEmail);
        var signUp = await Setup.SignUpAsync(http, InitialAdminSetupFactory.AdminEmail, grant);
        Assert.Equal(HttpStatusCode.OK, signUp.StatusCode);
        Assert.Equal(System.Text.Json.JsonValueKind.Null, (await ReadJsonAsync(signUp)).GetProperty("token").ValueKind);

        var signIn = await http.PostAsJsonAsync("/api/auth/sign-in/email", new { email = InitialAdminSetupFactory.AdminEmail, password = Password });
        Assert.Equal(HttpStatusCode.OK, signIn.StatusCode);
        var token = (await ReadJsonAsync(signIn)).GetProperty("token").GetString()!;
        var orgs = await ReadJsonAsync(await http.SendAsync(Bearer(HttpMethod.Get, "/v1/me/orgs", token)));
        Assert.Equal("owner", Assert.Single(orgs.GetProperty("orgs").EnumerateArray()).GetProperty("role").GetString());
        Assert.Equal(HttpStatusCode.OK, (await http.SendAsync(Bearer(HttpMethod.Get, "/v1/admin/overview", token))).StatusCode);
    }
}

public sealed class InitialAdminSetupNoCodeTests(InitialAdminSetupNoCodeFactory factory) : IClassFixture<InitialAdminSetupNoCodeFactory>
{
    [Fact]
    public async Task Without_a_code_setup_is_unavailable_and_sign_up_is_open()
    {
        var http = factory.Plain();
        Assert.Equal("unavailable", await Setup.StatusAsync(http));
        var r = await Setup.VerifyAsync(http, InitialAdminSetupFactory.AdminEmail, "anything");
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        Assert.Equal("bootstrap_unavailable", (await ReadJsonAsync(r)).GetProperty("error").GetString());
        Assert.Equal(HttpStatusCode.OK, (await http.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Anyone", email = NewEmail(), password = Password })).StatusCode);
        Assert.Equal("complete", await Setup.StatusAsync(http));
    }
}
