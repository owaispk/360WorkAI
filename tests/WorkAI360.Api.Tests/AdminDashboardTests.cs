using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.PlatformAdmin;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>A fresh deployment with one platform admin address, so active-user counts are exact.</summary>
public sealed class AdminDashboardFactory : ApiFactory
{
    public const string AdminEmail = "dash.admin@example.com";
    protected override IEnumerable<KeyValuePair<string, string>> Settings => [new("PlatformAdmin:BootstrapEmails", AdminEmail)];
}

public sealed class AdminDashboardTests(AdminDashboardFactory factory) : IClassFixture<AdminDashboardFactory>
{
    private async Task<string> AdminTokenAsync()
    {
        var http = factory.Plain();
        var r = await http.PostAsJsonAsync("/api/auth/sign-in/email", new { email = AdminDashboardFactory.AdminEmail, password = Password });
        if (!r.IsSuccessStatusCode) r = await http.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Dash Admin", email = AdminDashboardFactory.AdminEmail, password = Password });
        return (await ReadJsonAsync(r)).GetProperty("token").GetString()!;
    }

    private async Task<(HttpStatusCode Status, JsonElement Body, HttpResponseMessage Raw)> GetAsync(string token, string url)
    {
        var r = await factory.Plain().SendAsync(Bearer(HttpMethod.Get, url, token));
        var text = await r.Content.ReadAsStringAsync();
        return (r.StatusCode, string.IsNullOrEmpty(text) ? default : JsonDocument.Parse(text).RootElement.Clone(), r);
    }

    [Fact]
    public async Task Active_users_count_distinct_people_by_sign_in_or_feature_use_today_7_and_30_days()
    {
        var token = await AdminTokenAsync(); // the admin signed in today
        var now = DateTime.UtcNow;
        factory.WithDb(db =>
        {
            User Person(string name) { var u = new User { Id = Ids.New("usr"), Email = $"{name}.{Guid.NewGuid():N}@example.com", Name = name, PasswordHash = "!", CreatedAt = now.AddDays(-60), UpdatedAt = now }; db.Users.Add(u); return u; }
            void SignIn(User u, DateTime at) => db.Sessions.Add(new Session { Id = Ids.New("ses"), TokenHash = Guid.NewGuid().ToString("N"), UserId = u.Id, Method = "email", CreatedAt = at, UpdatedAt = at, ExpiresAt = at.AddDays(7) });
            var a = Person("today"); SignIn(a, now); SignIn(a, now.AddDays(-2)); // twice: still one person
            var b = Person("five"); SignIn(b, now.AddDays(-5));
            var c = Person("twenty"); SignIn(c, now.AddDays(-20));
            var d = Person("forty"); SignIn(d, now.AddDays(-40)); // outside every window
            var e = Person("featureonly");
            var org = new Organization { Id = Ids.New("org"), Name = "Dash Org", Slug = "dash-org", CreatedAt = now };
            db.Organizations.Add(org);
            var memberE = new Member { Id = Ids.New("om"), OrganizationId = org.Id, UserId = e.Id, Role = "member", CreatedAt = now };
            var memberA = new Member { Id = Ids.New("om"), OrganizationId = org.Id, UserId = a.Id, Role = "member", CreatedAt = now };
            db.Members.AddRange(memberE, memberA);
            static string Day(DateTime t) => t.ToString("yyyy-MM-dd");
            db.Set<FeatureUsageDay>().Add(new FeatureUsageDay { MemberId = memberE.Id, FeatureKey = "browserUse", Day = Day(now.AddDays(-3)), OrganizationId = org.Id, FirstUsedAt = now, LastUsedAt = now });
            db.Set<FeatureUsageDay>().Add(new FeatureUsageDay { MemberId = memberA.Id, FeatureKey = "browserUse", Day = Day(now), OrganizationId = org.Id, FirstUsedAt = now, LastUsedAt = now });
            db.Set<FeatureUsageDay>().Add(new FeatureUsageDay { MemberId = memberE.Id, FeatureKey = "mermaidZoom", Day = Day(now.AddDays(-45)), OrganizationId = org.Id, FirstUsedAt = now, LastUsedAt = now });
            return db.SaveChanges();
        });

        var (status, body, raw) = await GetAsync(token, "/v1/admin/dashboard/active-users");
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal("no-store", raw.Headers.CacheControl?.ToString());
        Assert.Equal(2, body.GetProperty("today").GetInt32());  // admin, a
        Assert.Equal(4, body.GetProperty("days7").GetInt32());  // + b, e (feature use only)
        Assert.Equal(5, body.GetProperty("days30").GetInt32()); // + c; d is 40 days back
        Assert.True(DateTime.TryParse(body.GetProperty("generatedAt").GetString(), out _));
    }

    [Fact]
    public async Task The_usage_dashboard_has_the_reference_shape_with_nothing_recorded()
    {
        var token = await AdminTokenAsync();
        var (status, body, raw) = await GetAsync(token, "/v1/admin/dashboard");
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal("no-store", raw.Headers.CacheControl?.ToString());
        var today = DateTime.UtcNow.ToString("yyyy-MM-dd");
        Assert.Equal(today, body.GetProperty("to").GetString());
        Assert.Equal(DateTime.UtcNow.AddDays(-29).ToString("yyyy-MM-dd"), body.GetProperty("from").GetString());
        var daily = body.GetProperty("daily").EnumerateArray().ToList();
        Assert.Equal(30, daily.Count);
        Assert.Equal(body.GetProperty("from").GetString(), daily[0].GetProperty("date").GetString());
        Assert.Equal(today, daily[^1].GetProperty("date").GetString());
        Assert.All(daily, d => Assert.Equal(0, d.GetProperty("requests").GetInt32()));
        Assert.Equal(0, body.GetProperty("totals").GetProperty("requests").GetInt32());
        Assert.Equal(0, body.GetProperty("activeOrganizations").GetInt32());
        Assert.Empty(body.GetProperty("organizations").EnumerateArray());
    }
}

/// <summary>Separate database: signing up someone here would change the exact counts above.</summary>
public sealed class AdminDashboardAccessTests(PlatformAdminFactory factory) : IClassFixture<PlatformAdminFactory>
{
    [Fact]
    public async Task Both_routes_are_for_platform_admins_only()
    {
        var (_, token, _) = await factory.SignUpAsync(factory.Plain(), "Not Admin");
        foreach (var url in new[] { "/v1/admin/dashboard", "/v1/admin/dashboard/active-users" })
        {
            Assert.Equal(HttpStatusCode.Forbidden, (await factory.Plain().SendAsync(Bearer(HttpMethod.Get, url, token))).StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, (await factory.Plain().GetAsync(url)).StatusCode);
        }
    }
}
