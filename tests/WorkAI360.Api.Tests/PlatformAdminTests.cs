using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.OrgAdmin;
using WorkAI360.Api.Domain.PlatformAdmin;
using WorkAI360.Api.Features.PlatformAdmin;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>A deployment with one bootstrap platform admin address and an operator lock on one feature (mermaidZoom, on by default, locked off).</summary>
public sealed class PlatformAdminFactory : ApiFactory
{
    public const string BootstrapEmail = "boot.admin@example.com";
    protected override IEnumerable<KeyValuePair<string, string>> Settings =>
    [
        new("PlatformAdmin:BootstrapEmails", $"  {BootstrapEmail.ToUpperInvariant()} , , "),
        new("Features:Overrides:mermaidZoom", "false"),
        new("OrgAdmin:Audit:ExportSettleSeconds", "0"),
    ];
}

/// <summary>Emails must be verified: a platform admin address only counts once it is proven.</summary>
public sealed class PlatformAdminVerifiedFactory : ApiFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Settings => [new("Auth:RequireEmailVerification", "true")];
}

public sealed class PlatformAdminTests : IClassFixture<PlatformAdminFactory>
{
    private readonly PlatformAdminFactory _factory;
    public PlatformAdminTests(PlatformAdminFactory factory) => _factory = factory;

    private HttpClient Http => _factory.Plain();

    private async Task<Person> SignUpAsync(string email, string name = "Some Person")
    {
        var http = Http;
        var r = await http.PostAsJsonAsync("/api/auth/sign-up/email", new { name, email, password = Password });
        r.EnsureSuccessStatusCode();
        var body = await ReadJsonAsync(r);
        return new Person(email, body.GetProperty("token").GetString()!, body.GetProperty("user").GetProperty("id").GetString()!, "");
    }

    /// <summary>The bootstrap platform admin, signed in (created the first time).</summary>
    private async Task<Person> AdminAsync()
    {
        var http = Http;
        var signIn = await http.PostAsJsonAsync("/api/auth/sign-in/email", new { email = PlatformAdminFactory.BootstrapEmail, password = Password });
        if (!signIn.IsSuccessStatusCode) return await SignUpAsync(PlatformAdminFactory.BootstrapEmail, "Boot Admin");
        var body = await ReadJsonAsync(signIn);
        return new Person(PlatformAdminFactory.BootstrapEmail, body.GetProperty("token").GetString()!, body.GetProperty("user").GetProperty("id").GetString()!, "");
    }

    private async Task<(HttpStatusCode Status, JsonElement Body)> CallAsync(Person p, HttpMethod method, string url, object? body = null)
    {
        var r = await _factory.Plain().SendAsync(Bearer(method, url, p.Token, body));
        var text = await r.Content.ReadAsStringAsync();
        return (r.StatusCode, string.IsNullOrEmpty(text) ? default : JsonDocument.Parse(text).RootElement.Clone());
    }

    private async Task<(HttpStatusCode Status, JsonElement Body)> AnonymousAsync(HttpMethod method, string url, object? body = null)
    {
        var request = new HttpRequestMessage(method, url);
        if (body is not null) request.Content = JsonContent.Create(body);
        var r = await _factory.Plain().SendAsync(request);
        var text = await r.Content.ReadAsStringAsync();
        return (r.StatusCode, string.IsNullOrEmpty(text) ? default : JsonDocument.Parse(text).RootElement.Clone());
    }

    private static string Msg(JsonElement body) => body.GetProperty("message").GetString()!;

    private static (HttpMethod Method, string Url, object? Body)[] AllRoutes(string orgId, string userId) =>
    [
        (HttpMethod.Get, "/v1/admin/overview", null), (HttpMethod.Get, "/v1/admin/users", null), (HttpMethod.Get, "/v1/admin/organizations", null),
        (HttpMethod.Get, $"/v1/admin/organizations/{orgId}", null), (HttpMethod.Get, $"/v1/admin/organizations/{orgId}/capabilities", null),
        (HttpMethod.Get, "/v1/admin/features", null), (HttpMethod.Get, "/v1/admin/metrics", null),
        (HttpMethod.Post, "/v1/admin/admins", new { email = "nobody@example.com" }), (HttpMethod.Delete, "/v1/admin/admins/aal_01jzzzzzzzzzzzzzzzzzzzzzzz", null),
        (HttpMethod.Delete, $"/v1/admin/users/{userId}", null),
        (HttpMethod.Patch, $"/v1/admin/organizations/{orgId}/plan", new { tier = "team", seatLimit = 9 }),
        (HttpMethod.Patch, $"/v1/admin/organizations/{orgId}/free-seats", new { totalFreeSeats = 9 }),
        (HttpMethod.Patch, $"/v1/admin/organizations/{orgId}/dpa", new { dpaSigned = true, reason = "not allowed" }),
        (HttpMethod.Put, $"/v1/admin/organizations/{orgId}/openwork-web-access", new { enabled = true, reason = "not allowed" }),
        (HttpMethod.Put, $"/v1/admin/organizations/{orgId}/capabilities", new { capabilities = new { browserUse = true } }),
        (HttpMethod.Put, "/v1/admin/features/browserUse", new { enabled = true }),
    ];

    // ----- who is a platform admin -------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Nobody_signed_in_gets_401_on_every_admin_route()
    {
        var w = await Workspace.CreateAsync(_factory);
        foreach (var (method, url, body) in AllRoutes(w.OrgId, w.Owner.UserId))
        {
            var r = await AnonymousAsync(method, url, body);
            Assert.True(r.Status == HttpStatusCode.Unauthorized, $"{method} {url}: {r.Status}");
            Assert.Equal("unauthorized", Workspace.Error(r.Body));
        }
        var junk = await _factory.Plain().SendAsync(Bearer(HttpMethod.Get, "/v1/admin/overview", "not-a-token"));
        Assert.Equal(HttpStatusCode.Unauthorized, junk.StatusCode);
    }

    [Fact]
    public async Task A_workspace_owner_or_admin_role_is_not_a_platform_admin_on_any_route()
    {
        var w = await Workspace.CreateAsync(_factory);
        var admin = await w.AddAsync("admin");
        var member = await w.AddAsync();
        foreach (var person in new[] { w.Owner, admin, member })
            foreach (var (method, url, body) in AllRoutes(w.OrgId, w.Owner.UserId))
            {
                var r = await w.CallAsync(person, method, url, body);
                Assert.True(r.Status == HttpStatusCode.Forbidden, $"{method} {url}: {r.Status} {r.Body}");
                Assert.Equal("forbidden", Workspace.Error(r.Body));
                Assert.False(r.Body.TryGetProperty("message", out _));
            }
    }

    [Fact]
    public async Task Refused_calls_change_nothing()
    {
        var w = await Workspace.CreateAsync(_factory);
        var admins = _factory.WithDb(db => db.Set<AdminAllowlistEntry>().Count());
        foreach (var (method, url, body) in AllRoutes(w.OrgId, w.Owner.UserId).Where(r => r.Method != HttpMethod.Get && !r.Url.Contains("/users/")))
            await w.CallAsync(w.Owner, method, url, body);
        _factory.WithDb(db =>
        {
            Assert.Equal(admins, db.Set<AdminAllowlistEntry>().Count());
            Assert.Empty(db.Set<PlatformFeatureRollout>().Where(r => r.FeatureKey == "browserUse" && (r.Enabled || r.Killed)));
            Assert.Empty(db.Set<PlatformOrganizationFeature>().Where(o => o.OrganizationId == w.OrgId));
            Assert.Empty(db.Set<PlatformOrganization>().Where(o => o.OrganizationId == w.OrgId));
            Assert.Empty(db.Set<PlatformFeatureChange>().Where(c => c.OrganizationId == w.OrgId));
            return 0;
        });
        Assert.NotNull(_factory.WithDb(db => db.Users.FirstOrDefault(u => u.Id == w.Owner.UserId)));
    }

    [Fact]
    public async Task The_workspace_header_and_workspace_ownership_never_widen_access()
    {
        var w = await Workspace.CreateAsync(_factory);
        var request = w.As(w.Owner, HttpMethod.Get, "/v1/admin/organizations/" + w.OrgId);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.SendAsync(request)).StatusCode);
    }

    [Fact]
    public async Task A_platform_admin_address_works_with_any_capitalization_and_is_seeded_once_with_a_note()
    {
        var admin = await AdminAsync();
        var r = await CallAsync(admin, HttpMethod.Get, "/v1/admin/overview?limit=1");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal(PlatformAdminFactory.BootstrapEmail, r.Body.GetProperty("viewer").GetProperty("email").GetString());
        var seeded = _factory.WithDb(db => db.Set<AdminAllowlistEntry>().Where(a => a.Email == PlatformAdminFactory.BootstrapEmail).ToList());
        Assert.Single(seeded);
        Assert.Equal(PlatformAdmins.BootstrapNote, seeded[0].Note);
        Assert.StartsWith("aal_", seeded[0].Id);
        // Blank entries in the setting never became admins.
        Assert.DoesNotContain(_factory.WithDb(db => db.Set<AdminAllowlistEntry>().Select(a => a.Email).ToList()), e => e.Trim().Length == 0);
    }

    [Fact]
    public async Task An_organization_api_key_or_agent_token_of_a_platform_admin_does_not_reach_admin_routes()
    {
        var admin = await AdminAsync();
        var org = await CallAsync(admin, HttpMethod.Post, "/v1/org", new { name = "Admin Space" });
        var orgId = org.Body.GetProperty("organization").GetProperty("id").GetString()!;
        var key = await _factory.Plain().SendAsync(WithOrg(Bearer(HttpMethod.Post, "/v1/api-keys", admin.Token, new { name = "Admin Key" }), orgId));
        Assert.Equal(HttpStatusCode.Created, key.StatusCode);
        var secret = (await ReadJsonAsync(key)).GetProperty("key").GetString()!;

        var viaHeader = new HttpRequestMessage(HttpMethod.Get, "/v1/admin/overview");
        viaHeader.Headers.Add("x-api-key", secret);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.Plain().SendAsync(viaHeader)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.Plain().SendAsync(Bearer(HttpMethod.Get, "/v1/admin/overview", secret))).StatusCode);
        // The same call as the signed-in person works.
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(admin, HttpMethod.Get, "/v1/admin/overview?limit=1")).Status);
    }

    private static HttpRequestMessage WithOrg(HttpRequestMessage request, string orgId)
    {
        request.Headers.Add("x-openwork-org-id", orgId);
        return request;
    }

    [Fact]
    public async Task Admins_are_added_lower_cased_listed_and_lose_access_the_moment_they_are_removed()
    {
        var admin = await AdminAsync();
        var second = await SignUpAsync(NewEmail("second"));
        Assert.Equal(HttpStatusCode.Forbidden, (await CallAsync(second, HttpMethod.Get, "/v1/admin/features")).Status);

        var add = await CallAsync(admin, HttpMethod.Post, "/v1/admin/admins", new { email = "  " + second.Email.ToUpperInvariant() + " ", note = "ops" });
        Assert.Equal(HttpStatusCode.OK, add.Status);
        Assert.Equal(second.Email, add.Body.GetProperty("admin").GetProperty("email").GetString());
        // It takes effect on the next request, for a session that already existed.
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(second, HttpMethod.Get, "/v1/admin/features")).Status);
        var dup = await CallAsync(admin, HttpMethod.Post, "/v1/admin/admins", new { email = second.Email });
        Assert.Equal(HttpStatusCode.Conflict, dup.Status);
        Assert.Equal("conflict", Workspace.Error(dup.Body));

        var id = add.Body.GetProperty("admin").GetProperty("id").GetString()!;
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(admin, HttpMethod.Delete, $"/v1/admin/admins/{id}")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await CallAsync(second, HttpMethod.Get, "/v1/admin/features")).Status);
    }

    [Fact]
    public async Task Admins_are_validated_and_you_cannot_remove_yourself_or_the_last_admin()
    {
        var admin = await AdminAsync();
        Assert.Equal("Invalid email address", Msg((await CallAsync(admin, HttpMethod.Post, "/v1/admin/admins", new { email = "nope" })).Body));
        Assert.Equal("Invalid input: expected string, received undefined", Msg((await CallAsync(admin, HttpMethod.Post, "/v1/admin/admins", new { })).Body));
        Assert.Equal("Too big: expected string to have <=255 characters", Msg((await CallAsync(admin, HttpMethod.Post, "/v1/admin/admins", new { email = "a@example.com", note = new string('x', 256) })).Body));
        Assert.Equal("Invalid admin id.", Msg((await CallAsync(admin, HttpMethod.Delete, "/v1/admin/admins/xyz")).Body));
        Assert.Equal("Admin not found.", Msg((await CallAsync(admin, HttpMethod.Delete, "/v1/admin/admins/aal_01jzzzzzzzzzzzzzzzzzzzzzzq")).Body));

        var own = _factory.WithDb(db => db.Set<AdminAllowlistEntry>().Single(a => a.Email == PlatformAdminFactory.BootstrapEmail).Id);
        var self = await CallAsync(admin, HttpMethod.Delete, $"/v1/admin/admins/{own}");
        Assert.Equal(HttpStatusCode.BadRequest, self.Status);
        Assert.Equal("You cannot delete your own admin access.", Msg(self.Body));
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(admin, HttpMethod.Get, "/v1/admin/features")).Status);
    }

    [Fact]
    public async Task Two_admins_removing_each_other_at_the_same_time_never_leave_nobody()
    {
        await AdminAsync(); // the bootstrap admin is listed (seeded) before this test removes it
        var a = await SignUpAsync(NewEmail("race-a"));
        var b = await SignUpAsync(NewEmail("race-b"));
        var (idA, idB) = _factory.WithDb(db =>
        {
            var now = DateTime.UtcNow;
            // The two of them are the only admins of their own fixture: take the bootstrap admin out of the picture for this check.
            db.Set<AdminAllowlistEntry>().RemoveRange(db.Set<AdminAllowlistEntry>().Where(x => x.Email == PlatformAdminFactory.BootstrapEmail));
            var ea = new AdminAllowlistEntry { Id = Ids.New("aal"), Email = a.Email, CreatedAt = now, UpdatedAt = now };
            var eb = new AdminAllowlistEntry { Id = Ids.New("aal"), Email = b.Email, CreatedAt = now, UpdatedAt = now };
            db.Set<AdminAllowlistEntry>().AddRange(ea, eb);
            db.SaveChanges();
            return (ea.Id, eb.Id);
        });
        try
        {
            var results = await Task.WhenAll(CallAsync(a, HttpMethod.Delete, $"/v1/admin/admins/{idB}"), CallAsync(b, HttpMethod.Delete, $"/v1/admin/admins/{idA}"));
            Assert.True(results.Count(r => r.Status == HttpStatusCode.OK) <= 1, string.Join(" / ", results.Select(r => r.Status + " " + r.Body)) + " rows=" + string.Join(",", _factory.WithDb(db => db.Set<AdminAllowlistEntry>().Select(x => x.Email).ToList())));
            Assert.True(_factory.WithDb(db => db.Set<AdminAllowlistEntry>().Count(x => x.Email == a.Email || x.Email == b.Email)) >= 1);
        }
        finally
        {
            // Put the bootstrap admin back for the other tests (it is seeded once per process).
            _factory.WithDb(db =>
            {
                if (!db.Set<AdminAllowlistEntry>().Any(x => x.Email == PlatformAdminFactory.BootstrapEmail))
                    db.Set<AdminAllowlistEntry>().Add(new AdminAllowlistEntry { Id = Ids.New("aal"), Email = PlatformAdminFactory.BootstrapEmail, Note = PlatformAdmins.BootstrapNote, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow });
                db.SaveChanges();
                return 0;
            });
        }
    }

    // ----- users ------------------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Users_can_be_listed_searched_and_paged_and_percent_signs_are_literal()
    {
        var admin = await AdminAsync();
        var w = await Workspace.CreateAsync(_factory, "Searchable Space " + Guid.NewGuid().ToString("N")[..6]);
        var member = await w.AddAsync();
        var list = await CallAsync(admin, HttpMethod.Get, $"/v1/admin/users?search={Uri.EscapeDataString(member.Email)}");
        Assert.Equal(1, list.Body.GetProperty("page").GetProperty("total").GetInt32());
        var user = list.Body.GetProperty("users")[0];
        Assert.Equal(member.UserId, user.GetProperty("id").GetString());
        Assert.Equal("member", user.GetProperty("organizations")[0].GetProperty("role").GetString());
        Assert.Equal(2, user.GetProperty("organizations")[0].GetProperty("memberCount").GetInt32());
        Assert.DoesNotContain("password", list.Body.ToString(), StringComparison.OrdinalIgnoreCase);

        var wild = await CallAsync(admin, HttpMethod.Get, "/v1/admin/users?search=%25");
        Assert.Equal(0, wild.Body.GetProperty("page").GetProperty("total").GetInt32());
        var clamp = await CallAsync(admin, HttpMethod.Get, "/v1/admin/users?limit=9999&offset=junk");
        Assert.Equal(100, clamp.Body.GetProperty("page").GetProperty("limit").GetInt32());
        Assert.Equal(0, clamp.Body.GetProperty("page").GetProperty("offset").GetInt32());
        var one = await CallAsync(admin, HttpMethod.Get, "/v1/admin/users?limit=1");
        Assert.Equal(1, one.Body.GetProperty("users").GetArrayLength());
        Assert.True(one.Body.GetProperty("page").GetProperty("hasMore").GetBoolean());
        // Searching by workspace name finds its people.
        var byOrg = await CallAsync(admin, HttpMethod.Get, $"/v1/admin/users?search={Uri.EscapeDataString(w.OrgId)}");
        Assert.Equal(2, byOrg.Body.GetProperty("page").GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task Deleting_a_user_ends_their_sessions_keys_and_memberships_and_is_audited_in_each_workspace()
    {
        var admin = await AdminAsync();
        var w = await Workspace.CreateAsync(_factory);
        var victim = await w.AddAsync();
        var other = await Workspace.CreateAsync(_factory, "Second Space");
        await other.InviteAsync(victim.Email);
        var accepted = await _factory.Plain().SendAsync(Bearer(HttpMethod.Post, "/v1/orgs/invitations/accept", victim.Token, new { id = _factory.WithDb(db => db.Invitations.Single(i => i.OrganizationId == other.OrgId).Id) }));
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        // The victim has a key, a second session and a team.
        var key = await _factory.Plain().SendAsync(WithOrg(Bearer(HttpMethod.Post, "/v1/api-keys", victim.Token, new { name = "Victim Key" }), w.OrgId));
        Assert.Equal(HttpStatusCode.Forbidden, key.StatusCode); // a plain member cannot make keys: nothing to clean up there
        var signIn = await _factory.Plain().PostAsJsonAsync("/api/auth/sign-in/email", new { email = victim.Email, password = Password });
        var secondToken = (await ReadJsonAsync(signIn)).GetProperty("token").GetString()!;
        var team = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/teams", new { name = "Victim Team", memberIds = new[] { victim.MemberId } });
        Assert.Equal(HttpStatusCode.Created, team.Status);

        var r = await CallAsync(admin, HttpMethod.Delete, $"/v1/admin/users/{victim.UserId}");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal(victim.Email, r.Body.GetProperty("user").GetProperty("email").GetString());

        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.Plain().SendAsync(Bearer(HttpMethod.Get, "/v1/me", victim.Token))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.Plain().SendAsync(Bearer(HttpMethod.Get, "/v1/me", secondToken))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.Plain().PostAsJsonAsync("/api/auth/sign-in/email", new { email = victim.Email, password = Password })).StatusCode);
        _factory.WithDb(db =>
        {
            Assert.False(db.Users.Any(u => u.Id == victim.UserId));
            Assert.False(db.Members.Any(m => m.UserId == victim.UserId));
            Assert.False(db.Sessions.Any(s => s.UserId == victim.UserId));
            Assert.False(db.TeamMembers.Any(t => t.MemberId == victim.MemberId));
            // The workspaces and the other people in them stay.
            Assert.True(db.Organizations.Any(o => o.Id == w.OrgId) && db.Organizations.Any(o => o.Id == other.OrgId));
            Assert.True(db.Members.Any(m => m.UserId == w.Owner.UserId) && db.Members.Any(m => m.UserId == other.Owner.UserId));
            return 0;
        });
        Assert.Single((await w.OrgAsync()).GetProperty("members").EnumerateArray());
        // Each workspace's history says who removed the person, as a platform admin.
        foreach (var orgId in new[] { w.OrgId, other.OrgId })
        {
            var events = _factory.WithDb(db => db.Set<AuditEvent>().AsNoTracking().Where(e => e.OrganizationId == orgId && e.Action == "member.removed").Select(e => e.EnvelopeJson).ToList());
            var removal = Assert.Single(events);
            Assert.Contains("platform_admin", removal);
            Assert.Contains(admin.UserId, removal);
            Assert.Contains("user_deleted", removal);
        }
        Assert.Equal(HttpStatusCode.NotFound, (await CallAsync(admin, HttpMethod.Delete, $"/v1/admin/users/{victim.UserId}")).Status);
    }

    [Fact]
    public async Task Deleting_a_user_validates_the_id_and_refuses_the_admins_own_account()
    {
        var admin = await AdminAsync();
        Assert.Equal("You cannot delete your own admin user.", Msg((await CallAsync(admin, HttpMethod.Delete, $"/v1/admin/users/{admin.UserId}")).Body));
        Assert.Equal("Invalid user id.", Msg((await CallAsync(admin, HttpMethod.Delete, "/v1/admin/users/xyz")).Body));
        Assert.Equal("User not found.", Msg((await CallAsync(admin, HttpMethod.Delete, "/v1/admin/users/usr_01m68tknxje18aqs60j2j437zz")).Body));
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(admin, HttpMethod.Get, "/v1/admin/features")).Status);
    }

    // ----- organizations ---------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Plans_are_validated_stored_and_shown_in_the_list_the_detail_and_the_workspace_payload()
    {
        var admin = await AdminAsync();
        var w = await Workspace.CreateAsync(_factory);
        string Plan(string path) => $"/v1/admin/organizations/{w.OrgId}{path}";
        foreach (var (body, message) in new (object, string)[]
        {
            (new { tier = "x", seatLimit = 3 }, "Invalid option: expected one of \"free\"|\"team\"|\"enterprise\""),
            (new { tier = "team", seatLimit = 0 }, "Too small: expected number to be >=1"),
            (new { tier = "team", seatLimit = 100001 }, "Too big: expected number to be <=100000"),
            (new { tier = "free", seatLimit = 5, endsAt = "2027-01-31" }, "A Free plan has no end date."),
            (new { tier = "team", seatLimit = 5, endsAt = "2027-02-30" }, "Use a date such as 2026-11-22."),
        })
        {
            var bad = await CallAsync(admin, HttpMethod.Patch, Plan("/plan"), body);
            Assert.Equal(HttpStatusCode.BadRequest, bad.Status);
            Assert.Equal(message, Msg(bad.Body));
        }
        Assert.Equal(HttpStatusCode.NotFound, (await CallAsync(admin, HttpMethod.Patch, "/v1/admin/organizations/org_01m68tknxje18aqs60j2j437zz/plan", new { tier = "team", seatLimit = 8 })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await CallAsync(admin, HttpMethod.Patch, "/v1/admin/organizations/xyz/plan", new { tier = "team", seatLimit = 8 })).Status);

        var team = await CallAsync(admin, HttpMethod.Patch, Plan("/plan"), new { tier = "team", seatLimit = 3, endsAt = "2020-01-01" });
        Assert.Equal(HttpStatusCode.OK, team.Status);
        var plan = team.Body.GetProperty("organization").GetProperty("plan");
        Assert.Equal(5, plan.GetProperty("seats").GetInt32());      // raised to the minimum of 5
        Assert.True(plan.GetProperty("ended").GetBoolean());
        Assert.Equal("manual", plan.GetProperty("source").GetString());
        var mine = await w.OrgAsync();
        Assert.Equal("team", mine.GetProperty("plan").GetProperty("tier").GetString());
        Assert.Equal("manual", mine.GetProperty("plan").GetProperty("source").GetString());

        var free = await CallAsync(admin, HttpMethod.Patch, Plan("/plan"), new { tier = "free", seatLimit = 50 });
        Assert.Equal(50, free.Body.GetProperty("organization").GetProperty("seatLimit").GetInt32());
        var listed = (await CallAsync(admin, HttpMethod.Get, $"/v1/admin/organizations?search={w.OrgId}&includeFeatures=0")).Body.GetProperty("organizations")[0];
        Assert.Equal(45, listed.GetProperty("seatsFreeAdditional").GetInt32());
        Assert.Equal(JsonValueKind.Null, listed.GetProperty("endsAt").ValueKind);
        Assert.False(listed.TryGetProperty("capabilities", out _));
        // No billing provider is involved: nothing is paid by anyone.
        Assert.Equal("none", listed.GetProperty("paidBy").GetString());
    }

    [Fact]
    public async Task Free_seats_dpa_and_web_access_are_validated_stored_and_audited_without_the_reason_text()
    {
        var admin = await AdminAsync();
        var w = await Workspace.CreateAsync(_factory);
        var seats = await CallAsync(admin, HttpMethod.Patch, $"/v1/admin/organizations/{w.OrgId}/free-seats", new { totalFreeSeats = 2 });
        Assert.Equal("Too small: expected number to be >=5", Msg(seats.Body));
        Assert.Equal(9, (await CallAsync(admin, HttpMethod.Patch, $"/v1/admin/organizations/{w.OrgId}/free-seats", new { totalFreeSeats = 9 })).Body.GetProperty("organization").GetProperty("freeSeatCount").GetInt32());

        var shortReason = await CallAsync(admin, HttpMethod.Patch, $"/v1/admin/organizations/{w.OrgId}/dpa", new { dpaSigned = true, reason = "x" });
        Assert.Equal("reason: Too small: expected string to have >=3 characters", Msg(shortReason.Body));
        var extra = await CallAsync(admin, HttpMethod.Patch, $"/v1/admin/organizations/{w.OrgId}/dpa", new { dpaSigned = true, reason = "signed on file", foo = 1 });
        Assert.Equal("Unrecognized key: \"foo\"", Msg(extra.Body));
        var secretReason = "countersigned-by-legal-4711";
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(admin, HttpMethod.Patch, $"/v1/admin/organizations/{w.OrgId}/dpa", new { dpaSigned = true, reason = secretReason })).Status);
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(admin, HttpMethod.Put, $"/v1/admin/organizations/{w.OrgId}/openwork-web-access", new { enabled = true, reason = secretReason })).Status);
        Assert.True((await w.OrgAsync()).GetProperty("capabilities").GetProperty("openworkWeb").GetBoolean());
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(admin, HttpMethod.Put, $"/v1/admin/organizations/{w.OrgId}/openwork-web-access", new { enabled = false, reason = "ended" })).Status);
        Assert.False((await w.OrgAsync()).GetProperty("capabilities").GetProperty("openworkWeb").GetBoolean());

        var events = _factory.WithDb(db => db.Set<AuditEvent>().AsNoTracking().Where(e => e.OrganizationId == w.OrgId).Select(e => new { e.Action, e.EnvelopeJson }).ToList());
        Assert.Contains(events, e => e.Action == "organization.dpa_signed.updated");
        Assert.Contains(events, e => e.Action == "organization.complimentary_access.granted");
        Assert.Contains(events, e => e.Action == "organization.complimentary_access.revoked");
        Assert.Contains(events, e => e.Action == "organization.free_seats.updated");
        Assert.DoesNotContain(events, e => e.EnvelopeJson.Contains(secretReason));
        Assert.All(events.Where(e => e.Action.StartsWith("organization.") && e.Action != "organization.settings.update.succeeded"), e =>
        {
            Assert.Contains("platform_admin", e.EnvelopeJson);
            Assert.Contains(admin.UserId, e.EnvelopeJson);
        });
        // The workspace's own owner can read those events in their audit log.
        var ops = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/audit/operations?limit=100");
        Assert.Equal(HttpStatusCode.OK, ops.Status);
        Assert.Contains("organization.dpa_signed.updated", ops.Body.ToString());
    }

    [Fact]
    public async Task Organization_detail_and_search_cover_every_workspace_for_an_admin_and_malformed_ids_are_400()
    {
        var admin = await AdminAsync();
        var a = await Workspace.CreateAsync(_factory, "Alpha Space " + Guid.NewGuid().ToString("N")[..6]);
        var b = await Workspace.CreateAsync(_factory, "Beta Space");
        var detail = await CallAsync(admin, HttpMethod.Get, $"/v1/admin/organizations/{a.OrgId}");
        Assert.Equal(1, detail.Body.GetProperty("organization").GetProperty("memberCount").GetInt32());
        Assert.Equal("free", detail.Body.GetProperty("organization").GetProperty("planTier").GetString());
        var both = await CallAsync(admin, HttpMethod.Get, "/v1/admin/organizations?limit=100");
        var ids = both.Body.GetProperty("organizations").EnumerateArray().Select(o => o.GetProperty("id").GetString()).ToList();
        Assert.Contains(a.OrgId, ids);
        Assert.Contains(b.OrgId, ids);
        Assert.Equal(400, (int)(await CallAsync(admin, HttpMethod.Get, "/v1/admin/organizations/abc")).Status);
        Assert.Equal(404, (int)(await CallAsync(admin, HttpMethod.Get, "/v1/admin/organizations/org_01m68tknxje18aqs60j2j437zz")).Status);
        // The workspace's own people see only their own workspace through the ordinary routes.
        var crossed = await _factory.Plain().SendAsync(WithOrg(Bearer(HttpMethod.Get, "/v1/org", a.Owner.Token), b.OrgId));
        Assert.Equal(HttpStatusCode.NotFound, crossed.StatusCode);
    }

    // ----- feature flags ----------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task The_registry_lists_every_feature_and_validates_changes()
    {
        var admin = await AdminAsync();
        var list = await CallAsync(admin, HttpMethod.Get, "/v1/admin/features");
        var features = list.Body.GetProperty("features").EnumerateArray().ToList();
        Assert.Equal(56, features.Count);
        Assert.Equal("self_hosted", list.Body.GetProperty("deployment").GetString());
        Assert.Equal(56, features.Select(f => f.GetProperty("key").GetString()).Distinct().Count());
        Assert.False(features.Single(f => f.GetProperty("key").GetString() == "autoRouter").GetProperty("available").GetBoolean());

        string Put(string key) => $"/v1/admin/features/{key}";
        Assert.Equal("Unknown feature.", Msg((await CallAsync(admin, HttpMethod.Put, Put("nope"), new { enabled = true })).Body));
        Assert.Equal("Set enabled, killed, or both.", Msg((await CallAsync(admin, HttpMethod.Put, Put("browserUse"), new { })).Body));
        Assert.Equal("Unrecognized key: \"zzz\"", Msg((await CallAsync(admin, HttpMethod.Put, Put("browserUse"), new { enabled = true, zzz = 1 })).Body));
        Assert.Equal("Invalid input: expected boolean, received string", Msg((await CallAsync(admin, HttpMethod.Put, Put("browserUse"), new { enabled = "x" })).Body));
        Assert.Equal("autoRouter is not part of this deployment.", Msg((await CallAsync(admin, HttpMethod.Put, Put("autoRouter"), new { enabled = true })).Body));
    }

    [Fact]
    public async Task Features_resolve_in_the_reference_order_unavailable_killed_locked_override_everyone()
    {
        var admin = await AdminAsync();
        var w = await Workspace.CreateAsync(_factory);
        var other = await Workspace.CreateAsync(_factory);
        async Task<JsonElement> State(string key) => (await CallAsync(admin, HttpMethod.Get, $"/v1/admin/organizations/{w.OrgId}/capabilities")).Body.GetProperty("featureStates").GetProperty(key);
        async Task<bool> Org(Workspace x, string key) => (await x.OrgAsync()).GetProperty("features").GetProperty(key).GetBoolean();
        async Task<bool> Public(string key) => (await ReadJsonAsync(await _factory.Plain().GetAsync("/v1/features"))).GetProperty("features").GetProperty(key).GetBoolean();
        var caps = (object body) => CallAsync(admin, HttpMethod.Put, $"/v1/admin/organizations/{w.OrgId}/capabilities", body);

        // everyone: the build's default, then what the admin set.
        Assert.False(await Org(w, "browserUse"));
        Assert.Equal("everyone", (await State("browserUse")).GetProperty("source").GetString());
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(admin, HttpMethod.Put, "/v1/admin/features/browserUse", new { enabled = true })).Status);
        try
        {
            Assert.True(await Public("browserUse"));
            Assert.True(await Org(w, "browserUse"));
            Assert.True(await Org(other, "browserUse"));

            // override: this workspace only.
            await caps(new { capabilities = new { browserUse = false } });
            Assert.False(await Org(w, "browserUse"));
            Assert.True(await Org(other, "browserUse"));
            Assert.True(await Public("browserUse"));
            var overridden = await State("browserUse");
            Assert.Equal("override", overridden.GetProperty("source").GetString());
            Assert.True(overridden.GetProperty("everyone").GetBoolean());
            Assert.False(overridden.GetProperty("override").GetBoolean());

            // killed beats the override and the rollout, everywhere.
            Assert.Equal(HttpStatusCode.OK, (await CallAsync(admin, HttpMethod.Put, "/v1/admin/features/browserUse", new { killed = true })).Status);
            await caps(new { capabilities = new { browserUse = true } });
            Assert.False(await Org(w, "browserUse"));
            Assert.False(await Org(other, "browserUse"));
            Assert.False(await Public("browserUse"));
            Assert.Equal("killed", (await State("browserUse")).GetProperty("source").GetString());
            Assert.False((await State("browserUse")).GetProperty("overrideApplies").GetBoolean());
        }
        finally
        {
            await CallAsync(admin, HttpMethod.Put, "/v1/admin/features/browserUse", new { enabled = false, killed = false });
            await caps(new { capabilities = new { browserUse = (bool?)null } });
        }
        Assert.False(await Org(w, "browserUse"));
        Assert.False(await Public("browserUse"));

        // lock: mermaidZoom is on by default and locked off by configuration; neither an override nor "on for everyone" changes it.
        Assert.False(await Org(w, "mermaidZoom"));
        await caps(new { capabilities = new { mermaidZoom = true } });
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(admin, HttpMethod.Put, "/v1/admin/features/mermaidZoom", new { enabled = true })).Status);
        Assert.False(await Org(w, "mermaidZoom"));
        Assert.False(await Public("mermaidZoom"));
        var locked = await State("mermaidZoom");
        Assert.Equal("lock", locked.GetProperty("source").GetString());
        Assert.False(locked.GetProperty("lock").GetBoolean());
        Assert.False(locked.GetProperty("overrideApplies").GetBoolean());
        // killed outranks the lock too.
        await CallAsync(admin, HttpMethod.Put, "/v1/admin/features/mermaidZoom", new { killed = true });
        Assert.Equal("killed", (await State("mermaidZoom")).GetProperty("source").GetString());
        await CallAsync(admin, HttpMethod.Put, "/v1/admin/features/mermaidZoom", new { killed = false });
        await caps(new { capabilities = new { mermaidZoom = (bool?)null } });
    }

    [Fact]
    public async Task Overrides_record_who_changed_what_and_cloud_only_features_cannot_be_overridden()
    {
        var admin = await AdminAsync();
        var w = await Workspace.CreateAsync(_factory);
        string Caps() => $"/v1/admin/organizations/{w.OrgId}/capabilities";
        var cloud = await CallAsync(admin, HttpMethod.Put, Caps(), new { capabilities = new { autoRouter = true } });
        Assert.Equal("autoRouter is not part of this deployment.", Msg(cloud.Body));
        var unavailable = (await CallAsync(admin, HttpMethod.Get, Caps())).Body.GetProperty("featureStates").GetProperty("autoRouter");
        Assert.Equal("unavailable", unavailable.GetProperty("source").GetString());
        Assert.False(unavailable.GetProperty("enabled").GetBoolean());
        Assert.False((await w.OrgAsync()).GetProperty("features").GetProperty("autoRouter").GetBoolean());
        Assert.Equal("Invalid input: expected boolean, received string", Msg((await CallAsync(admin, HttpMethod.Put, Caps(), new { capabilities = new { browserDemonstrations = "yes" } })).Body));
        Assert.Equal("Invalid input: expected object, received undefined", Msg((await CallAsync(admin, HttpMethod.Put, Caps(), new { })).Body));

        var on = await CallAsync(admin, HttpMethod.Put, Caps(), new { capabilities = new { browserDemonstrations = true, notAFeature = true } });
        var change = on.Body.GetProperty("featureStates").GetProperty("browserDemonstrations").GetProperty("lastChange");
        Assert.Equal("organization", change.GetProperty("scope").GetString());
        Assert.Equal("on", change.GetProperty("action").GetString());
        Assert.Equal(PlatformAdminFactory.BootstrapEmail, change.GetProperty("by").GetProperty("email").GetString());
        // Setting the same value again is not a new change; clearing one is a "reset".
        await CallAsync(admin, HttpMethod.Put, Caps(), new { capabilities = new { browserDemonstrations = true } });
        Assert.Equal(1, _factory.WithDb(db => db.Set<PlatformFeatureChange>().Count(c => c.OrganizationId == w.OrgId && c.FeatureKey == "browserDemonstrations")));
        var cleared = await CallAsync(admin, HttpMethod.Put, Caps(), new { capabilities = new { browserDemonstrations = (bool?)null } });
        Assert.Equal("reset", cleared.Body.GetProperty("featureStates").GetProperty("browserDemonstrations").GetProperty("lastChange").GetProperty("action").GetString());
        Assert.Empty(_factory.WithDb(db => db.Set<PlatformOrganizationFeature>().Where(o => o.OrganizationId == w.OrgId).ToList()));
        Assert.True(on.Body.GetProperty("capabilities").GetProperty("gatewayDashboard").GetBoolean());
    }

    [Fact]
    public async Task Deleting_a_workspace_override_is_scoped_to_that_workspace_and_a_missing_workspace_is_404()
    {
        var admin = await AdminAsync();
        Assert.Equal(HttpStatusCode.NotFound, (await CallAsync(admin, HttpMethod.Put, "/v1/admin/organizations/org_01m68tknxje18aqs60j2j437zz/capabilities", new { capabilities = new { browserUse = true } })).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await CallAsync(admin, HttpMethod.Get, "/v1/admin/organizations/org_01m68tknxje18aqs60j2j437zz/capabilities")).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await CallAsync(admin, HttpMethod.Get, "/v1/admin/organizations/xyz/capabilities")).Status);
        Assert.Empty(_factory.WithDb(db => db.Set<PlatformOrganizationFeature>().Where(o => o.OrganizationId == "org_01m68tknxje18aqs60j2j437zz").ToList()));
    }

    // ----- overview and metrics ----------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Overview_and_metrics_count_this_database()
    {
        var admin = await AdminAsync();
        var users = _factory.WithDb(db => db.Users.Count());
        var organizations = _factory.WithDb(db => db.Organizations.Count());
        var w = await Workspace.CreateAsync(_factory);
        await w.AddAsync();
        var overview = await CallAsync(admin, HttpMethod.Get, "/v1/admin/overview?limit=3");
        Assert.Equal(users + 2, overview.Body.GetProperty("summary").GetProperty("totalUsers").GetInt32());
        Assert.Equal(organizations + 1, overview.Body.GetProperty("summary").GetProperty("totalOrganizations").GetInt32());
        Assert.Equal(3, overview.Body.GetProperty("users").GetArrayLength());
        var metrics = (await CallAsync(admin, HttpMethod.Get, "/v1/admin/metrics")).Body.GetProperty("summary");
        Assert.Equal(users + 2, metrics.GetProperty("totalUsers").GetInt32());
        Assert.True(metrics.GetProperty("recentUsers7d").GetInt32() >= 2);
        Assert.Equal(30, metrics.GetProperty("activitySeries").GetArrayLength());
        Assert.True(metrics.GetProperty("activitySeries")[29].GetProperty("signups").GetInt32() >= 2);
        Assert.True(metrics.GetProperty("inviters").GetInt32() >= 1);
        Assert.Equal(0, metrics.GetProperty("totalWorkers").GetInt32());
    }

    [Fact]
    public async Task The_public_feature_list_stays_public_and_unauthenticated_callers_cannot_see_admin_state()
    {
        var anonymous = await _factory.Plain().GetAsync("/v1/features");
        Assert.Equal(HttpStatusCode.OK, anonymous.StatusCode);
        var body = await ReadJsonAsync(anonymous);
        Assert.True(body.GetProperty("features").GetProperty("engineV2ForceUpgrade").GetBoolean());
        Assert.DoesNotContain("killed", body.ToString());
        Assert.DoesNotContain("lastChange", body.ToString());
    }
}

public sealed class PlatformAdminVerifiedTests : IClassFixture<PlatformAdminVerifiedFactory>
{
    private readonly PlatformAdminVerifiedFactory _factory;
    public PlatformAdminVerifiedTests(PlatformAdminVerifiedFactory factory) => _factory = factory;

    [Fact]
    public async Task Where_emails_are_verified_an_address_on_the_list_counts_only_while_it_is_proven()
    {
        var http = _factory.Plain();
        var (email, token, _) = await _factory.SignUpAsync(http, "Verified Admin");
        _factory.WithDb(db =>
        {
            db.Set<AdminAllowlistEntry>().Add(new AdminAllowlistEntry { Id = Ids.New("aal"), Email = email, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow });
            db.SaveChanges();
            return 0;
        });
        Assert.Equal(HttpStatusCode.OK, (await http.SendAsync(Bearer(HttpMethod.Get, "/v1/admin/features", token))).StatusCode);
        // The address stops being proven (for example after a change of email): the list entry no longer counts.
        _factory.WithDb(db =>
        {
            db.Users.Where(u => u.Email == email).ExecuteUpdate(s => s.SetProperty(u => u.EmailVerified, false));
            return 0;
        });
        var r = await http.SendAsync(Bearer(HttpMethod.Get, "/v1/admin/features", token));
        Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
        Assert.Equal("admin_email_unverified", Workspace.Error(await ReadJsonAsync(r)));
    }
}
