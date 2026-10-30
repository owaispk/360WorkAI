using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Email;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

public sealed record Person(string Email, string Token, string UserId, string MemberId);

/// <summary>A workspace with an owner, built through the public API.</summary>
public sealed class Workspace
{
    private readonly ApiFactory _factory;
    public HttpClient Http { get; }
    public string OrgId { get; private set; } = "";
    public Person Owner { get; private set; } = null!;

    public Workspace(ApiFactory factory) { _factory = factory; Http = factory.Plain(); }

    public static async Task<Workspace> CreateAsync(ApiFactory factory, string name = "Team Space")
    {
        var w = new Workspace(factory);
        var (email, token, userId) = await factory.SignUpAsync(w.Http, "Owner Person");
        var created = await w.Http.SendAsync(Bearer(HttpMethod.Post, "/v1/org", token, new { name }));
        w.OrgId = (await ReadJsonAsync(created)).GetProperty("organization").GetProperty("id").GetString()!;
        w.Owner = new Person(email, token, userId, await w.MemberIdAsync(token, userId));
        return w;
    }

    public HttpRequestMessage As(Person p, HttpMethod method, string url, object? body = null) => As(p.Token, method, url, body);

    public HttpRequestMessage As(string token, HttpMethod method, string url, object? body = null)
    {
        var request = Bearer(method, url, token, body);
        request.Headers.Add("x-openwork-org-id", OrgId);
        return request;
    }

    public async Task<JsonElement> OrgAsync(string? token = null)
    {
        var r = await Http.SendAsync(As(token ?? Owner.Token, HttpMethod.Get, "/v1/org"));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return await ReadJsonAsync(r);
    }

    public async Task<string> MemberIdAsync(string token, string userId)
    {
        var org = await OrgAsync(token);
        return org.GetProperty("members").EnumerateArray().First(m => m.GetProperty("userId").ValueKind == JsonValueKind.String && m.GetProperty("userId").GetString() == userId).GetProperty("id").GetString()!;
    }

    public async Task<JsonElement> InviteAsync(string email, string role = "member", Person? by = null)
    {
        var r = await Http.SendAsync(As(by ?? Owner, HttpMethod.Post, "/v1/invitations", new { email, role }));
        Assert.True((int)r.StatusCode is 200 or 201, $"invite failed: {(int)r.StatusCode} {await r.Content.ReadAsStringAsync()}");
        return await ReadJsonAsync(r);
    }

    /// <summary>A new person who accepts an invitation with the given role.</summary>
    public async Task<Person> AddAsync(string role = "member")
    {
        var (email, token, userId) = await _factory.SignUpAsync(Http, role + " Person");
        var invitation = await InviteAsync(email, role);
        var accepted = await Http.SendAsync(Bearer(HttpMethod.Post, "/v1/orgs/invitations/accept", token, new { id = invitation.GetProperty("invitationId").GetString() }));
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        return new Person(email, token, userId, await MemberIdAsync(Owner.Token, userId));
    }

    public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request) => Http.SendAsync(request);

    public async Task<(HttpStatusCode Status, JsonElement Body)> CallAsync(Person p, HttpMethod method, string url, object? body = null)
    {
        var r = await Http.SendAsync(As(p, method, url, body));
        var text = await r.Content.ReadAsStringAsync();
        return (r.StatusCode, string.IsNullOrEmpty(text) ? default : JsonDocument.Parse(text).RootElement.Clone());
    }

    public static string Error(JsonElement body) => body.ValueKind == JsonValueKind.Object && body.TryGetProperty("error", out var e) ? e.GetString() ?? "" : "";
}

public sealed class RolesAndPermissionsTests
{
    [Fact]
    public void Each_role_holds_the_same_permissions_as_the_reference()
    {
        Assert.Equal(59, Permissions.For(Roles.Owner).Count);
        Assert.Equal(43, Permissions.For(Roles.Admin).Count);
        Assert.Empty(Permissions.For(Roles.Member));
        Assert.Equal(Permissions.For(Roles.Owner).Order(StringComparer.Ordinal), Permissions.For(Roles.Owner));   // sorted, as the reference returns them
        Assert.Contains("invitations.manage", Permissions.For(Roles.Admin));
        Assert.Contains("members.delete", Permissions.For(Roles.Admin));
        Assert.DoesNotContain("members.update", Permissions.For(Roles.Admin));        // only the owner changes roles
        Assert.DoesNotContain("organization.update", Permissions.For(Roles.Admin));
        Assert.True(Permissions.Has(Roles.Owner, "members.update"));
        Assert.False(Permissions.Has(Roles.Member, "invitations.manage"));
    }

    [Theory]
    [InlineData(" ADMIN ", "admin")]
    [InlineData("Super Admin", "admin")]      // spaces become hyphens, and super-admin is read as admin
    [InlineData("  Some Role ", "some-role")]
    [InlineData("super-admin", "admin")]
    [InlineData("Member", "member")]
    public void Role_names_are_normalized(string input, string expected) => Assert.Equal(expected, Roles.Normalize(input));

    [Theory]
    [InlineData("member", "member", false, false)]
    [InlineData("admin", "admin", false, false)]
    [InlineData(" Admin ", "admin", false, false)]
    [InlineData("super-admin", "admin", false, false)]
    [InlineData("admin,member", "admin", false, false)]
    [InlineData("owner", null, true, false)]
    [InlineData("member,owner", null, true, false)]
    [InlineData("custom-role", null, false, true)]
    [InlineData("", null, false, true)]
    public void Invitation_roles_resolve_to_admin_or_member_and_owner_is_refused(string input, string? role, bool owner, bool invalid) =>
        Assert.Equal((role, owner, invalid), Roles.ForInvitation(input));

    [Theory]
    [InlineData("member", "admin", false)]   // promotion takes nothing away
    [InlineData("admin", "member", true)]
    [InlineData("owner", "admin", true)]
    [InlineData("admin", "admin", false)]
    [InlineData("custom", "member", true)]   // when the ordering cannot be proven, fail closed
    public void Only_changes_that_take_access_away_revoke_credentials(string previous, string next, bool revokes) =>
        Assert.Equal(revokes, Roles.RevokesCredentials(previous, next));
}

public sealed class OrgPayloadTests : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _factory;
    public OrgPayloadTests(ApiFactory factory) => _factory = factory;

    [Fact]
    public async Task The_workspace_payload_describes_the_owner_the_caller_and_everyone_including_pending_invitations()
    {
        var w = await Workspace.CreateAsync(_factory);
        var admin = await w.AddAsync("admin");
        var pendingEmail = NewEmail("pending");
        var pending = await w.InviteAsync(pendingEmail);

        var org = await w.OrgAsync(admin.Token);
        var owner = org.GetProperty("organization").GetProperty("owner");
        Assert.Equal(w.Owner.UserId, owner.GetProperty("userId").GetString());
        Assert.Equal(w.Owner.MemberId, owner.GetProperty("memberId").GetString());
        Assert.Matches(@"^om_", w.Owner.MemberId);

        var me = org.GetProperty("currentMember");
        Assert.Equal("admin", me.GetProperty("role").GetString());
        Assert.False(me.GetProperty("isOwner").GetBoolean());
        Assert.Equal(43, me.GetProperty("permissions").GetArrayLength());

        var members = org.GetProperty("members").EnumerateArray().ToList();
        Assert.Equal(3, members.Count);                                  // owner, admin, and the pending person
        var placeholder = members.Single(m => m.GetProperty("userId").ValueKind == JsonValueKind.Null);
        Assert.Equal(pending.GetProperty("invitationId").GetString(), placeholder.GetProperty("inviteId").GetString());
        Assert.Equal(JsonValueKind.Null, placeholder.GetProperty("joinedAt").ValueKind);
        Assert.Equal(pendingEmail, placeholder.GetProperty("user").GetProperty("email").GetString());
        Assert.Equal(placeholder.GetProperty("id").GetString(), placeholder.GetProperty("user").GetProperty("id").GetString());

        var joined = members.Single(m => m.GetProperty("userId").GetString() == admin.UserId);
        Assert.Equal("admin", joined.GetProperty("effectiveRole").GetString());
        Assert.NotNull(joined.GetProperty("inviteId").GetString());      // remembers the invitation it came from
        Assert.Equal(JsonValueKind.String, joined.GetProperty("joinedAt").ValueKind);

        var invitations = org.GetProperty("invitations").EnumerateArray().ToList();
        Assert.Equal(pendingEmail, invitations.Single().GetProperty("email").GetString());   // accepted invitations are not listed
        Assert.Equal("pending", invitations.Single().GetProperty("status").GetString());
    }

    [Fact]
    public async Task A_plain_member_sees_no_permissions_and_the_owner_sees_all()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        Assert.Equal(0, (await w.OrgAsync(member.Token)).GetProperty("currentMember").GetProperty("permissions").GetArrayLength());
        Assert.Equal(59, (await w.OrgAsync()).GetProperty("currentMember").GetProperty("permissions").GetArrayLength());
    }

    [Fact]
    public async Task Without_a_workspace_or_with_someone_elses_the_answer_is_404_and_without_a_session_401()
    {
        var w = await Workspace.CreateAsync(_factory);
        var outsider = await _factory.SignUpAsync(_factory.Plain());
        var other = Bearer(HttpMethod.Get, "/v1/org", outsider.Token);
        Assert.Equal(HttpStatusCode.NotFound, (await w.SendAsync(other)).StatusCode);                          // no active workspace
        Assert.Equal(HttpStatusCode.NotFound, (await w.SendAsync(w.As(outsider.Token, HttpMethod.Get, "/v1/org"))).StatusCode);   // not a member
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.SendAsync(new HttpRequestMessage(HttpMethod.Get, "/v1/org"))).StatusCode);
    }
}

public sealed class InvitationTests : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _factory;
    public InvitationTests(ApiFactory factory) => _factory = factory;

    [Fact]
    public async Task Inviting_creates_then_resends_with_the_same_link_and_the_latest_role()
    {
        var w = await Workspace.CreateAsync(_factory);
        var email = NewEmail("invitee");
        var first = await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Post, "/v1/invitations", new { email, role = "member" }));
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        var created = await ReadJsonAsync(first);
        Assert.Matches(@"^inv_", created.GetProperty("invitationId").GetString());
        Assert.Equal(21, created.GetProperty("inviteToken").GetString()!.Length);
        Assert.True(DateTime.Parse(created.GetProperty("expiresAt").GetString()!).ToUniversalTime() > DateTime.UtcNow.AddDays(6));

        var again = await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Post, "/v1/invitations", new { email = email.ToUpperInvariant(), role = "admin" }));
        Assert.Equal(HttpStatusCode.OK, again.StatusCode);                         // a resend, not a second invitation
        var resent = await ReadJsonAsync(again);
        Assert.Equal(created.GetProperty("invitationId").GetString(), resent.GetProperty("invitationId").GetString());
        Assert.Equal(created.GetProperty("inviteToken").GetString(), resent.GetProperty("inviteToken").GetString());
        Assert.Equal("admin", resent.GetProperty("role").GetString());
        Assert.Equal(email, resent.GetProperty("email").GetString());               // stored lower-case
        Assert.Single((await w.OrgAsync()).GetProperty("invitations").EnumerateArray());
        Assert.Equal(2, _factory.Outbox.To(email).Count);                          // each send is a real email
    }

    [Fact]
    public async Task Bad_invitations_are_refused_with_the_reference_errors()
    {
        var w = await Workspace.CreateAsync(_factory);
        async Task<(HttpStatusCode, string)> Try(object body) { var r = await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Post, "/v1/invitations", body)); var j = await ReadJsonAsync(r); return (r.StatusCode, j.GetProperty("error").GetString()!); }

        Assert.Equal((HttpStatusCode.Forbidden, "forbidden"), await Try(new { email = NewEmail(), role = "owner" }));
        Assert.Equal((HttpStatusCode.BadRequest, "invalid_role"), await Try(new { email = NewEmail(), role = "superuser" }));
        Assert.Equal((HttpStatusCode.BadRequest, "invalid_request"), await Try(new { email = "nope", role = "member" }));
        Assert.Equal((HttpStatusCode.BadRequest, "invalid_request"), await Try(new { email = NewEmail() }));
        Assert.Equal((HttpStatusCode.BadRequest, "invalid_request"), await Try(new { role = "member" }));

        var owner = await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Post, "/v1/invitations", new { email = NewEmail(), role = "owner" }));
        Assert.Equal("Owner can only be assigned by the Den ownership transfer API.", (await ReadJsonAsync(owner)).GetProperty("message").GetString());
        var role = await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Post, "/v1/invitations", new { email = NewEmail(), role = "superuser" }));
        Assert.Equal("Choose Member or Admin.", (await ReadJsonAsync(role)).GetProperty("message").GetString());

        // Someone who already belongs cannot be invited again, whatever the address casing.
        var member = await w.AddAsync();
        var existing = await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Post, "/v1/invitations", new { email = member.Email.ToUpperInvariant(), role = "member" }));
        Assert.Equal(HttpStatusCode.Conflict, existing.StatusCode);
        Assert.Equal("member_exists", (await ReadJsonAsync(existing)).GetProperty("error").GetString());
        var self = await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Post, "/v1/invitations", new { email = w.Owner.Email, role = "member" }));
        Assert.Equal(HttpStatusCode.Conflict, self.StatusCode);
    }

    [Fact]
    public async Task Who_may_invite_whom_depends_on_the_role()
    {
        var w = await Workspace.CreateAsync(_factory);
        var admin = await w.AddAsync("admin");
        var member = await w.AddAsync();

        // A plain member holds no invitation permission.
        var denied = await w.CallAsync(member, HttpMethod.Post, "/v1/invitations", new { email = NewEmail(), role = "member" });
        Assert.Equal(HttpStatusCode.Forbidden, denied.Status);
        Assert.Equal("You don't have permission to invite people. Ask an admin to change your permissions.", denied.Body.GetProperty("message").GetString());
        Assert.Equal("invitations.manage", denied.Body.GetProperty("requiredPermission").GetString());
        Assert.Equal("requires_admin", denied.Body.GetProperty("code").GetString());
        Assert.False(denied.Body.GetProperty("retryable").GetBoolean());
        Assert.EndsWith("/dashboard/members", denied.Body.GetProperty("action_url").GetString());

        // An admin can invite members, but making someone an admin is a role change, which only the owner may do.
        Assert.Equal(HttpStatusCode.Created, (await w.CallAsync(admin, HttpMethod.Post, "/v1/invitations", new { email = NewEmail(), role = "member" })).Status);
        var adminInvite = await w.CallAsync(admin, HttpMethod.Post, "/v1/invitations", new { email = NewEmail(), role = "admin" });
        Assert.Equal(HttpStatusCode.Forbidden, adminInvite.Status);
        Assert.Equal("You don't have permission to change member roles. Ask the organization owner.", adminInvite.Body.GetProperty("message").GetString());
        Assert.Equal("members.update", adminInvite.Body.GetProperty("requiredPermission").GetString());
        Assert.Equal(HttpStatusCode.Created, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/invitations", new { email = NewEmail(), role = "admin" })).Status);
    }

    [Fact]
    public async Task The_invitation_email_names_the_inviter_the_workspace_and_carries_the_join_link()
    {
        var w = await Workspace.CreateAsync(_factory, "Robotics Lab");
        var email = NewEmail("mail");
        var invitation = await w.InviteAsync(email, "admin");
        var mail = _factory.Outbox.To(email).Single().Message;

        Assert.Equal("Owner Person invited you to join Robotics Lab on OpenWork", mail.Subject);
        Assert.Contains($"http://localhost/join-org?invite={invitation.GetProperty("inviteToken").GetString()}", mail.Text);
        Assert.Contains("as an admin", mail.Text);
        Assert.Contains("Accept invitation", mail.Html);
        Assert.DoesNotContain(invitation.GetProperty("invitationId").GetString()!, mail.Text);   // the id is not the credential; only the token is
    }

    [Fact]
    public async Task A_mail_outage_keeps_the_invitation_and_says_so()
    {
        await using var broken = new ApiFactory().WithWebHostBuilder(b => b.ConfigureServices(s =>
        {
            s.RemoveAll<IEmailSender>();
            s.AddSingleton<IEmailSender, BrokenSender>();
        }));
        var http = broken.CreateClient();
        var (_, token, _) = await new ApiFactory().SignUpAsync(http);   // separate factory instance: only for sign-up helper reuse
        var created = await http.SendAsync(Bearer(HttpMethod.Post, "/v1/org", token, new { name = "Outage Org" }));
        var orgId = (await ReadJsonAsync(created)).GetProperty("organization").GetProperty("id").GetString()!;

        var invite = Bearer(HttpMethod.Post, "/v1/invitations", token, new { email = NewEmail(), role = "member" });
        invite.Headers.Add("x-openwork-org-id", orgId);
        var response = await http.SendAsync(invite);
        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        var body = await ReadJsonAsync(response);
        Assert.Equal("invitation_email_failed", body.GetProperty("error").GetString());

        var listing = Bearer(HttpMethod.Get, "/v1/org", token);
        listing.Headers.Add("x-openwork-org-id", orgId);
        var invitations = (await ReadJsonAsync(await http.SendAsync(listing))).GetProperty("invitations");
        Assert.Equal(body.GetProperty("invitationId").GetString(), invitations.EnumerateArray().Single().GetProperty("id").GetString());
    }

    private sealed class BrokenSender : IEmailSender
    {
        public Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default) => throw new IOException("smtp down");
    }

    [Fact]
    public async Task The_link_cancel_and_preview_follow_the_invitations_state()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        var invitation = await w.InviteAsync(NewEmail("state"));
        var id = invitation.GetProperty("invitationId").GetString()!;
        var token = invitation.GetProperty("inviteToken").GetString()!;

        var link = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/invitations/{id}/link");
        Assert.Equal($"http://localhost/join-org?invite={token}", link.Body.GetProperty("inviteLink").GetString());
        Assert.Equal(id, link.Body.GetProperty("invitationId").GetString());
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(member, HttpMethod.Get, $"/v1/invitations/{id}/link")).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/invitations/inv_01m00000000000000000000000/link")).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/invitations/not-an-id/link")).Status);

        // Preview needs no sign-in and accepts the id or the token.
        foreach (var key in new[] { id, token })
        {
            var preview = await ReadJsonAsync(await w.Http.GetAsync($"/v1/orgs/invitations/preview?id={key}"));
            Assert.Equal("pending", preview.GetProperty("invitation").GetProperty("status").GetString());
            Assert.Equal(w.OrgId, preview.GetProperty("organization").GetProperty("id").GetString());
            Assert.Equal("OpenWork", preview.GetProperty("organization").GetProperty("branding").GetProperty("appName").GetString());
        }
        Assert.Equal(HttpStatusCode.NotFound, (await w.Http.GetAsync("/v1/orgs/invitations/preview?id=bogus")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.Http.GetAsync("/v1/orgs/invitations/preview")).StatusCode);

        var cancel = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/invitations/{id}/cancel");
        Assert.Equal(HttpStatusCode.OK, cancel.Status);
        var again = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/invitations/{id}/cancel");
        Assert.Equal(HttpStatusCode.Conflict, again.Status);
        Assert.Equal("invitation_not_pending", again.Body.GetProperty("error").GetString());
        Assert.Equal("canceled", again.Body.GetProperty("status").GetString());
        var afterLink = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/invitations/{id}/link");
        Assert.Equal(HttpStatusCode.Conflict, afterLink.Status);
        Assert.Equal("This invitation can no longer be used. Resend it to create a new link.", afterLink.Body.GetProperty("message").GetString());
        Assert.Equal("canceled", (await ReadJsonAsync(await w.Http.GetAsync($"/v1/orgs/invitations/preview?id={id}"))).GetProperty("invitation").GetProperty("status").GetString());
        Assert.Empty((await w.OrgAsync()).GetProperty("invitations").EnumerateArray());
    }

    [Fact]
    public async Task An_expired_invitation_reports_expired_can_be_cleaned_up_and_cannot_be_accepted()
    {
        var w = await Workspace.CreateAsync(_factory);
        var (email, token, _) = await _factory.SignUpAsync(w.Http);
        var invitation = await w.InviteAsync(email);
        var id = invitation.GetProperty("invitationId").GetString()!;
        _factory.WithDb(db => db.Database.ExecuteSqlRaw("UPDATE Invitations SET ExpiresAt = {0} WHERE Id = {1}", DateTime.UtcNow.AddHours(-1), id));

        Assert.Equal("expired", (await ReadJsonAsync(await w.Http.GetAsync($"/v1/orgs/invitations/preview?id={id}"))).GetProperty("invitation").GetProperty("status").GetString());
        Assert.Equal("expired", (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/invitations/{id}/link")).Body.GetProperty("status").GetString());
        var accept = await w.Http.SendAsync(Bearer(HttpMethod.Post, "/v1/orgs/invitations/accept", token, new { id }));
        Assert.Equal(HttpStatusCode.NotFound, accept.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/invitations/{id}/cancel")).Status);

        // Inviting the same address again makes a fresh invitation.
        var fresh = await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Post, "/v1/invitations", new { email, role = "member" }));
        Assert.Equal(HttpStatusCode.Created, fresh.StatusCode);
        Assert.NotEqual(id, (await ReadJsonAsync(fresh)).GetProperty("invitationId").GetString());
    }

    [Fact]
    public async Task Only_the_invited_address_can_accept_and_accepting_is_idempotent()
    {
        var w = await Workspace.CreateAsync(_factory);
        var (email, invitee, userId) = await _factory.SignUpAsync(w.Http);
        var (_, stranger, _) = await _factory.SignUpAsync(w.Http);
        var invitation = await w.InviteAsync(email, "admin");
        var id = invitation.GetProperty("invitationId").GetString()!;
        var token = invitation.GetProperty("inviteToken").GetString()!;

        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.PostAsJsonAsync("/v1/orgs/invitations/accept", new { id })).StatusCode);
        var wrong = await w.Http.SendAsync(Bearer(HttpMethod.Post, "/v1/orgs/invitations/accept", stranger, new { id }));
        Assert.Equal(HttpStatusCode.NotFound, wrong.StatusCode);                  // for anyone else the invitation does not exist
        Assert.Equal("invitation_not_found", (await ReadJsonAsync(wrong)).GetProperty("error").GetString());

        // Eight simultaneous accepts (by token) create exactly one membership.
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => w.Http.SendAsync(Bearer(HttpMethod.Post, "/v1/orgs/invitations/accept", invitee, new { id = token }))));
        Assert.All(results, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
        var accepted = await ReadJsonAsync(results[0]);
        Assert.True(accepted.GetProperty("accepted").GetBoolean());
        Assert.Equal(w.OrgId, accepted.GetProperty("organizationId").GetString());
        Assert.Equal(1, _factory.WithDb(db => db.Members.Count(m => m.OrganizationId == w.OrgId && m.UserId == userId)));

        var org = await w.OrgAsync();
        var joined = org.GetProperty("members").EnumerateArray().Single(m => m.GetProperty("userId").ValueKind == JsonValueKind.String && m.GetProperty("userId").GetString() == userId);
        Assert.Equal("admin", joined.GetProperty("role").GetString());              // the role the invitation carried
        var me = await ReadJsonAsync(await w.Http.SendAsync(Bearer(HttpMethod.Get, "/v1/me/orgs", invitee)));
        Assert.Equal(w.OrgId, me.GetProperty("activeOrgId").GetString());            // a first workspace becomes the active one
        Assert.Equal(HttpStatusCode.NotFound, (await w.Http.SendAsync(Bearer(HttpMethod.Post, "/v1/orgs/invitations/accept", stranger, new { id }))).StatusCode);
    }

    [Fact]
    public async Task An_invitation_cannot_be_read_or_cancelled_from_another_workspace()
    {
        var a = await Workspace.CreateAsync(_factory, "Workspace A");
        var b = await Workspace.CreateAsync(_factory, "Workspace B");
        var inviteInB = (await b.InviteAsync(NewEmail())).GetProperty("invitationId").GetString()!;

        // Owner of A, working in A, names B's invitation.
        Assert.Equal(HttpStatusCode.NotFound, (await a.CallAsync(a.Owner, HttpMethod.Post, $"/v1/invitations/{inviteInB}/cancel")).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await a.CallAsync(a.Owner, HttpMethod.Get, $"/v1/invitations/{inviteInB}/link")).Status);
        // And naming B in the header is not allowed at all.
        Assert.Equal(HttpStatusCode.NotFound, (await b.Http.SendAsync(b.As(a.Owner, HttpMethod.Post, $"/v1/invitations/{inviteInB}/cancel"))).StatusCode);
        Assert.Equal("pending", (await ReadJsonAsync(await b.Http.GetAsync($"/v1/orgs/invitations/preview?id={inviteInB}"))).GetProperty("invitation").GetProperty("status").GetString());
    }

    [Fact]
    public async Task Sign_in_options_know_about_an_invitation()
    {
        var w = await Workspace.CreateAsync(_factory);
        var email = NewEmail("login-opt");
        var invitation = await w.InviteAsync(email);
        var token = invitation.GetProperty("inviteToken").GetString()!;

        async Task<bool> Allows(string? invite, string address) =>
            (await ReadJsonAsync(await w.Http.GetAsync($"/v1/auth/login-options?email={Uri.EscapeDataString(address)}{(invite is null ? "" : $"&invite={invite}")}"))).GetProperty("allowInvitationSignup").GetBoolean();
        Assert.True(await Allows(token, email));
        Assert.True(await Allows(invitation.GetProperty("invitationId").GetString(), email));
        Assert.False(await Allows(null, email));
        Assert.False(await Allows(token, NewEmail("someone-else")));
    }
}

public sealed class InvitedSignUpTests : IClassFixture<VerificationFactory>
{
    private readonly VerificationFactory _factory;
    public InvitedSignUpTests(VerificationFactory factory) => _factory = factory;

    [Fact]
    public async Task Signing_up_from_the_emailed_link_verifies_the_address_without_a_code()
    {
        var w = await Workspace.CreateAsync(_factory);
        var email = NewEmail("invited");
        var invitation = await w.InviteAsync(email);
        var token = invitation.GetProperty("inviteToken").GetString()!;
        // The owner needed a session, but sign-up itself requires verification in this fixture, so the owner was verified by hand.

        var signUp = await w.Http.PostAsJsonAsync($"/api/auth/sign-up/email?invite={token}", new { name = "Invited", email, password = Password });
        Assert.Equal(HttpStatusCode.OK, signUp.StatusCode);
        var json = await ReadJsonAsync(signUp);
        Assert.Equal(JsonValueKind.Null, json.GetProperty("token").ValueKind);        // the reference answers without a session, even here
        Assert.True(json.GetProperty("user").GetProperty("emailVerified").GetBoolean());
        Assert.Empty(Mail.CodesFor(_factory.Outbox, email));                          // no code to type: the link already proved it

        var signIn = await w.Http.PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = Password });
        Assert.Equal(HttpStatusCode.OK, signIn.StatusCode);
    }

    [Fact]
    public async Task Only_the_token_for_the_same_address_counts_not_the_id_nor_another_address()
    {
        var w = await Workspace.CreateAsync(_factory);
        var email = NewEmail("strict");
        var invitation = await w.InviteAsync(email);
        var id = invitation.GetProperty("invitationId").GetString()!;
        var token = invitation.GetProperty("inviteToken").GetString()!;

        async Task<bool> VerifiedAsync(string query, string address)
        {
            var r = await w.Http.PostAsJsonAsync($"/api/auth/sign-up/email{query}", new { name = "X", email = address, password = Password });
            return (await ReadJsonAsync(r)).GetProperty("user").GetProperty("emailVerified").GetBoolean();
        }
        Assert.False(await VerifiedAsync($"?invite={id}", email));                      // the id is visible to every member; it proves nothing
        Assert.False(await VerifiedAsync($"?invite={token}", NewEmail("not-invited"))); // a token for someone else's address proves nothing
        Assert.False(await VerifiedAsync("?invite=bogus", NewEmail("bogus")));
    }
}
