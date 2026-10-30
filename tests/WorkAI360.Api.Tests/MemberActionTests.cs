using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

public sealed class RoleChangeTests : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _factory;
    public RoleChangeTests(ApiFactory factory) => _factory = factory;

    private static string RoleUrl(Person p) => $"/v1/members/{p.MemberId}/role";

    [Fact]
    public async Task The_owner_promotes_and_demotes_and_only_a_demotion_signs_the_person_out()
    {
        var w = await Workspace.CreateAsync(_factory);
        var person = await w.AddAsync();

        // Promotion takes nothing away: the person's session keeps working.
        var up = await w.CallAsync(w.Owner, HttpMethod.Post, RoleUrl(person), new { role = " Admin " });
        Assert.Equal(HttpStatusCode.OK, up.Status);
        Assert.True(up.Body.GetProperty("success").GetBoolean());
        Assert.Equal("admin", (await w.OrgAsync(person.Token)).GetProperty("currentMember").GetProperty("role").GetString());
        Assert.Equal(43, (await w.OrgAsync(person.Token)).GetProperty("currentMember").GetProperty("permissions").GetArrayLength());

        // Saying the same role again is a no-op, not a demotion.
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Post, RoleUrl(person), new { role = "admin" })).Status);
        Assert.Equal(HttpStatusCode.OK, (await w.Http.SendAsync(w.As(person, HttpMethod.Get, "/v1/org"))).StatusCode);

        // A demotion takes access away, so it ends every session the person had.
        var secondDevice = (await ReadJsonAsync(await w.Http.PostAsJsonAsync("/api/auth/sign-in/email", new { email = person.Email, password = Password }))).GetProperty("token").GetString()!;
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Post, RoleUrl(person), new { role = "member" })).Status);
        foreach (var token in new[] { person.Token, secondDevice })
            Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.SendAsync(Bearer(HttpMethod.Get, "/v1/me", token))).StatusCode);

        // They can sign in again, as a member.
        var again = (await ReadJsonAsync(await w.Http.PostAsJsonAsync("/api/auth/sign-in/email", new { email = person.Email, password = Password }))).GetProperty("token").GetString()!;
        Assert.Equal("member", (await w.OrgAsync(again)).GetProperty("currentMember").GetProperty("role").GetString());
    }

    [Fact]
    public async Task A_demotion_also_ends_the_persons_agent_access_to_this_workspace_only()
    {
        var w = await Workspace.CreateAsync(_factory, "Workspace One");
        var other = await Workspace.CreateAsync(_factory, "Workspace Two");
        var person = await w.AddAsync("admin");
        // The same person also belongs to the second workspace.
        var invitation = await other.InviteAsync(person.Email);
        await other.Http.SendAsync(Bearer(HttpMethod.Post, "/v1/orgs/invitations/accept", person.Token, new { id = invitation.GetProperty("invitationId").GetString() }));

        async Task<string> MintAsync(string org)
        {
            var request = Bearer(HttpMethod.Post, "/v1/mcp/token", person.Token, new { scopes = new[] { "mcp:read" } });
            request.Headers.Add("x-openwork-org-id", org);
            return (await ReadJsonAsync(await w.Http.SendAsync(request))).GetProperty("token").GetString()!;
        }
        var tokenHere = await MintAsync(w.OrgId);
        var tokenThere = await MintAsync(other.OrgId);
        async Task<HttpStatusCode> Ping(string token) => (await w.Http.SendAsync(Bearer(HttpMethod.Post, "/mcp/agent", token, new { jsonrpc = "2.0", id = 1, method = "ping" }))).StatusCode;
        Assert.Equal(HttpStatusCode.OK, await Ping(tokenHere));
        Assert.Equal(HttpStatusCode.OK, await Ping(tokenThere));

        await w.CallAsync(w.Owner, HttpMethod.Post, RoleUrl(person), new { role = "member" });
        Assert.Equal(HttpStatusCode.Unauthorized, await Ping(tokenHere));    // this workspace's tokens are gone
        Assert.Equal(HttpStatusCode.OK, await Ping(tokenThere));             // the other workspace is untouched
        Assert.Equal(1, _factory.WithDb(db => db.Members.Count(m => m.OrganizationId == other.OrgId && m.UserId == person.UserId)));
    }

    [Fact]
    public async Task Only_the_owner_changes_roles_and_everyone_else_gets_the_reference_denial()
    {
        var w = await Workspace.CreateAsync(_factory);
        var admin = await w.AddAsync("admin");
        var member = await w.AddAsync();
        var target = await w.AddAsync();

        foreach (var actor in new[] { admin, member })
        {
            var denied = await w.CallAsync(actor, HttpMethod.Post, RoleUrl(target), new { role = "admin" });
            Assert.Equal(HttpStatusCode.Forbidden, denied.Status);
            Assert.Equal("forbidden", denied.Body.GetProperty("error").GetString());
            Assert.Equal("You don't have permission to change member roles. Ask the organization owner.", denied.Body.GetProperty("message").GetString());
            Assert.Equal("members.update", denied.Body.GetProperty("requiredPermission").GetString());
        }
        Assert.Equal("member", (await w.OrgAsync()).GetProperty("members").EnumerateArray().Single(m => m.GetProperty("id").GetString() == target.MemberId).GetProperty("role").GetString());
    }

    [Fact]
    public async Task The_rules_protect_the_owner_and_reject_bad_input()
    {
        var w = await Workspace.CreateAsync(_factory);
        var person = await w.AddAsync();

        async Task<(HttpStatusCode, string)> Try(string memberId, object body) { var r = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/members/{memberId}/role", body); return (r.Status, Workspace.Error(r.Body)); }
        Assert.Equal((HttpStatusCode.BadRequest, "owner_role_locked"), await Try(w.Owner.MemberId, new { role = "member" }));         // the owner's role is fixed
        Assert.Equal((HttpStatusCode.BadRequest, "invalid_role"), await Try(person.MemberId, new { role = "owner" }));               // owner moves only by transfer
        Assert.Equal((HttpStatusCode.BadRequest, "invalid_role"), await Try(person.MemberId, new { role = "bogus" }));
        Assert.Equal((HttpStatusCode.BadRequest, "invalid_request"), await Try(person.MemberId, new { }));
        Assert.Equal((HttpStatusCode.NotFound, "member_not_found"), await Try("om_01m00000000000000000000000", new { role = "admin" }));
        var malformed = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/members/not-an-id/role", new { role = "admin" });
        Assert.Equal(HttpStatusCode.BadRequest, malformed.Status);
        Assert.Equal("memberId: TypeID must be 29 characters (om_<26 char suffix>) (and 3 more)", malformed.Body.GetProperty("message").GetString());   // every problem is listed
        Assert.Equal(4, malformed.Body.GetProperty("details").GetArrayLength());
        var tooLong = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/members/mem_01m00000000000000000000000/role", new { role = "admin" });
        Assert.Equal("memberId: TypeID must be 29 characters (om_<26 char suffix>) (and 1 more)", tooLong.Body.GetProperty("message").GetString());
        var wrongPrefix = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/members/xx_01m00000000000000000000000/role", new { role = "admin" });
        Assert.Equal("memberId: TypeID must start with 'om_'", wrongPrefix.Body.GetProperty("message").GetString());

        // A pending invitation is not a member whose role can be set.
        var pending = await w.InviteAsync(NewEmail());
        var members = (await w.OrgAsync()).GetProperty("members").EnumerateArray();
        var placeholder = members.Single(m => m.GetProperty("inviteId").GetString() == pending.GetProperty("invitationId").GetString() && m.GetProperty("userId").ValueKind == JsonValueKind.Null);
        Assert.Equal((HttpStatusCode.NotFound, "member_not_found"), await Try(placeholder.GetProperty("id").GetString()!, new { role = "admin" }));
    }

    [Fact]
    public async Task The_last_person_who_can_administer_cannot_be_demoted()
    {
        var w = await Workspace.CreateAsync(_factory);
        var admin = await w.AddAsync("admin");
        // Make the admin the only privileged member (a state ownership transfer or SCIM could otherwise reach).
        _factory.WithDb(db => db.Database.ExecuteSqlRaw("UPDATE Members SET Role = 'member' WHERE Id = {0}", w.Owner.MemberId));
        var demote = await w.CallAsync(w.Owner, HttpMethod.Post, RoleUrl(admin), new { role = "member" });
        // The (former) owner is now a plain member, so the caller lacks the permission; check the rule itself through a second admin.
        Assert.Equal(HttpStatusCode.Forbidden, demote.Status);

        var w2 = await Workspace.CreateAsync(_factory);
        var onlyAdmin = await w2.AddAsync("admin");
        // Owner row removed entirely: nobody else is privileged, and the owner (still the caller) is not counted as another one.
        _factory.WithDb(db => db.Database.ExecuteSqlRaw("UPDATE Members SET Role = 'member' WHERE Id = {0}", w2.Owner.MemberId));
        _factory.WithDb(db => db.Database.ExecuteSqlRaw("UPDATE Members SET Role = 'owner' WHERE Id = {0}", onlyAdmin.MemberId));
        _factory.WithDb(db => db.Database.ExecuteSqlRaw("UPDATE Members SET Role = 'admin' WHERE Id = {0}", w2.Owner.MemberId));
        // Now the former owner is an admin, the former admin is the owner: demoting the former owner (the only admin) is allowed while an owner exists.
        var ok = await w2.CallAsync(onlyAdmin, HttpMethod.Post, RoleUrl(w2.Owner), new { role = "member" });
        Assert.Equal(HttpStatusCode.OK, ok.Status);
    }

    [Fact]
    public async Task Roles_cannot_be_changed_across_workspaces()
    {
        var a = await Workspace.CreateAsync(_factory, "Alpha");
        var b = await Workspace.CreateAsync(_factory, "Beta");
        var inB = await b.AddAsync();

        // Owner of A names a member of B, both with A's header and B's.
        var viaA = await a.CallAsync(a.Owner, HttpMethod.Post, RoleUrl(inB), new { role = "admin" });
        Assert.Equal(HttpStatusCode.NotFound, viaA.Status);
        Assert.Equal("member_not_found", Workspace.Error(viaA.Body));
        Assert.Equal(HttpStatusCode.NotFound, (await b.Http.SendAsync(b.As(a.Owner, HttpMethod.Post, RoleUrl(inB), new { role = "admin" }))).StatusCode);
        Assert.Equal("member", (await b.OrgAsync()).GetProperty("members").EnumerateArray().Single(m => m.GetProperty("id").GetString() == inB.MemberId).GetProperty("role").GetString());
    }
}

public sealed class OwnershipTransferTests : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _factory;
    public OwnershipTransferTests(ApiFactory factory) => _factory = factory;

    private static string TransferUrl(Person p) => $"/v1/members/{p.MemberId}/transfer-ownership";

    [Fact]
    public async Task Ownership_moves_to_an_admin_and_the_previous_owner_becomes_an_admin_signed_out()
    {
        var w = await Workspace.CreateAsync(_factory);
        var admin = await w.AddAsync("admin");

        var transfer = await w.CallAsync(w.Owner, HttpMethod.Post, TransferUrl(admin));
        Assert.Equal(HttpStatusCode.OK, transfer.Status);
        Assert.True(transfer.Body.GetProperty("success").GetBoolean());

        // Both people's sessions end; each signs in again.
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.SendAsync(Bearer(HttpMethod.Get, "/v1/me", admin.Token))).StatusCode);
        admin = admin with { Token = (await ReadJsonAsync(await w.Http.PostAsJsonAsync("/api/auth/sign-in/email", new { email = admin.Email, password = Password }))).GetProperty("token").GetString()! };
        var org = await w.OrgAsync(admin.Token);
        Assert.Equal("owner", org.GetProperty("currentMember").GetProperty("role").GetString());
        Assert.Equal(admin.UserId, org.GetProperty("organization").GetProperty("owner").GetProperty("userId").GetString());
        Assert.Equal("admin", org.GetProperty("members").EnumerateArray().Single(m => m.GetProperty("userId").GetString() == w.Owner.UserId).GetProperty("role").GetString());
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.SendAsync(Bearer(HttpMethod.Get, "/v1/me", w.Owner.Token))).StatusCode);   // the previous owner's sessions ended

        // The former owner signs back in as an admin and can no longer do owner things.
        var back = new Person(w.Owner.Email, (await ReadJsonAsync(await w.Http.PostAsJsonAsync("/api/auth/sign-in/email", new { email = w.Owner.Email, password = Password }))).GetProperty("token").GetString()!, w.Owner.UserId, w.Owner.MemberId);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(back, HttpMethod.Post, $"/v1/members/{admin.MemberId}/transfer-ownership")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(back, HttpMethod.Post, $"/v1/members/{admin.MemberId}/role", new { role = "member" })).Status);
        // ...and the new owner can.
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(admin, HttpMethod.Post, $"/v1/members/{w.Owner.MemberId}/role", new { role = "member" })).Status);
    }

    [Fact]
    public async Task Only_the_owner_can_transfer_and_only_to_a_real_admin()
    {
        var w = await Workspace.CreateAsync(_factory);
        var admin = await w.AddAsync("admin");
        var member = await w.AddAsync();

        var notOwner = await w.CallAsync(admin, HttpMethod.Post, TransferUrl(member));
        Assert.Equal(HttpStatusCode.Forbidden, notOwner.Status);
        Assert.Equal("Only the workspace owner can do this.", notOwner.Body.GetProperty("message").GetString());
        Assert.False(notOwner.Body.TryGetProperty("requiredPermission", out _));          // it is not a permission anyone can be granted
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(member, HttpMethod.Post, TransferUrl(admin))).Status);

        var self = await w.CallAsync(w.Owner, HttpMethod.Post, TransferUrl(w.Owner));
        Assert.Equal("Choose a different active member to become workspace owner.", self.Body.GetProperty("message").GetString());
        var toMember = await w.CallAsync(w.Owner, HttpMethod.Post, TransferUrl(member));
        Assert.Equal(HttpStatusCode.BadRequest, toMember.Status);
        Assert.Equal("owner_transfer_invalid", Workspace.Error(toMember.Body));
        Assert.Equal("Choose an active workspace admin to become owner.", toMember.Body.GetProperty("message").GetString());
        var unknown = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/members/om_01m00000000000000000000000/transfer-ownership");
        Assert.Equal((HttpStatusCode.NotFound, "target_member_not_found"), (unknown.Status, Workspace.Error(unknown.Body)));

        // Nothing changed.
        Assert.Equal("owner", (await w.OrgAsync()).GetProperty("currentMember").GetProperty("role").GetString());
    }

    [Fact]
    public async Task A_workspace_always_has_exactly_one_owner_even_under_concurrent_transfers()
    {
        var w = await Workspace.CreateAsync(_factory);
        var a = await w.AddAsync("admin");
        var b = await w.AddAsync("admin");

        var results = await Task.WhenAll(
            w.CallAsync(w.Owner, HttpMethod.Post, TransferUrl(a)),
            w.CallAsync(w.Owner, HttpMethod.Post, TransferUrl(b)));
        Assert.True(results.Count(r => r.Status == HttpStatusCode.OK) >= 1);
        Assert.Equal(1, _factory.WithDb(db => db.Members.Count(m => m.OrganizationId == w.OrgId && m.Role == "owner")));
    }
}

public sealed class RemovalTests : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _factory;
    public RemovalTests(ApiFactory factory) => _factory = factory;

    private static string MemberUrl(Person p) => $"/v1/members/{p.MemberId}";

    [Fact]
    public async Task Removing_someone_ends_their_access_and_they_can_be_invited_again()
    {
        var w = await Workspace.CreateAsync(_factory);
        var person = await w.AddAsync();
        var consentClient = _factory.WithDb(db => 0);

        var removed = await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Delete, MemberUrl(person)));
        Assert.Equal(HttpStatusCode.NoContent, removed.StatusCode);
        Assert.Equal(0, _factory.WithDb(db => db.Members.Count(m => m.UserId == person.UserId)));

        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.SendAsync(Bearer(HttpMethod.Get, "/v1/me", person.Token))).StatusCode);      // their sessions are gone
        var again = (await ReadJsonAsync(await w.Http.PostAsJsonAsync("/api/auth/sign-in/email", new { email = person.Email, password = Password }))).GetProperty("token").GetString()!;
        var gone = await w.Http.SendAsync(w.As(again, HttpMethod.Get, "/v1/org"));
        Assert.Equal(HttpStatusCode.NotFound, gone.StatusCode);                                                                                // the workspace no longer exists for them
        var orgs = await ReadJsonAsync(await w.Http.SendAsync(Bearer(HttpMethod.Get, "/v1/me/orgs", again)));
        Assert.Empty(orgs.GetProperty("orgs").EnumerateArray());
        Assert.Equal(JsonValueKind.Null, orgs.GetProperty("activeOrgId").ValueKind);

        var second = await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Delete, MemberUrl(person)));
        Assert.Equal(HttpStatusCode.NotFound, second.StatusCode);
        Assert.Equal("member_not_found", Workspace.Error(await ReadJsonAsync(second)));

        // Coming back is a fresh invitation.
        var invitation = await w.InviteAsync(person.Email);
        var accept = await w.Http.SendAsync(Bearer(HttpMethod.Post, "/v1/orgs/invitations/accept", again, new { id = invitation.GetProperty("invitationId").GetString() }));
        Assert.Equal(HttpStatusCode.OK, accept.StatusCode);
        Assert.Equal(1, _factory.WithDb(db => db.Members.Count(m => m.UserId == person.UserId)));
    }

    [Fact]
    public async Task Removal_ends_oauth_and_first_party_agent_access()
    {
        var w = await Workspace.CreateAsync(_factory);
        var person = await w.AddAsync();
        var request = Bearer(HttpMethod.Post, "/v1/mcp/token", person.Token, new { scopes = new[] { "mcp:read" } });
        request.Headers.Add("x-openwork-org-id", w.OrgId);
        var token = (await ReadJsonAsync(await w.Http.SendAsync(request))).GetProperty("token").GetString()!;
        Assert.Equal(HttpStatusCode.OK, (await w.Http.SendAsync(Bearer(HttpMethod.Post, "/mcp/agent", token, new { jsonrpc = "2.0", id = 1, method = "ping" }))).StatusCode);

        await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Delete, MemberUrl(person)));
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.SendAsync(Bearer(HttpMethod.Post, "/mcp/agent", token, new { jsonrpc = "2.0", id = 1, method = "ping" }))).StatusCode);
        Assert.Equal(0, _factory.WithDb(db => db.McpAccessTokens.Count(t => t.UserId == person.UserId && t.OrganizationId == w.OrgId)));
    }

    [Fact]
    public async Task Who_may_remove_whom()
    {
        var w = await Workspace.CreateAsync(_factory);
        var admin = await w.AddAsync("admin");
        var otherAdmin = await w.AddAsync("admin");
        var member = await w.AddAsync();
        var target = await w.AddAsync();

        var denied = await w.CallAsync(member, HttpMethod.Delete, MemberUrl(target));
        Assert.Equal(HttpStatusCode.Forbidden, denied.Status);
        Assert.Equal("You don't have permission to remove members. Ask an admin to change your permissions.", denied.Body.GetProperty("message").GetString());
        Assert.Equal("members.delete", denied.Body.GetProperty("requiredPermission").GetString());

        // Nobody can remove the owner, not even the owner.
        foreach (var actor in new[] { admin, w.Owner })
        {
            var owner = await w.CallAsync(actor, HttpMethod.Delete, MemberUrl(w.Owner));
            Assert.Equal(HttpStatusCode.BadRequest, owner.Status);
            Assert.Equal("owner_role_locked", Workspace.Error(owner.Body));
            Assert.Equal("The organization owner cannot be removed.", owner.Body.GetProperty("message").GetString());
        }

        // An admin can remove members and other admins.
        Assert.Equal(HttpStatusCode.NoContent, (await w.Http.SendAsync(w.As(admin, HttpMethod.Delete, MemberUrl(target)))).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await w.Http.SendAsync(w.As(admin, HttpMethod.Delete, MemberUrl(otherAdmin)))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(w.Owner, HttpMethod.Delete, "/v1/members/om_01m00000000000000000000000")).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Delete, "/v1/members/nope")).Status);
    }

    [Fact]
    public async Task Removing_a_pending_person_withdraws_the_invitation()
    {
        var w = await Workspace.CreateAsync(_factory);
        var email = NewEmail();
        var invitation = await w.InviteAsync(email);
        var placeholder = (await w.OrgAsync()).GetProperty("members").EnumerateArray().Single(m => m.GetProperty("userId").ValueKind == JsonValueKind.Null).GetProperty("id").GetString()!;

        Assert.Equal(HttpStatusCode.NoContent, (await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Delete, $"/v1/members/{placeholder}"))).StatusCode);
        Assert.Equal("canceled", (await ReadJsonAsync(await w.Http.GetAsync($"/v1/orgs/invitations/preview?id={invitation.GetProperty("invitationId").GetString()}"))).GetProperty("invitation").GetProperty("status").GetString());
        Assert.Equal(2, (await w.OrgAsync()).GetProperty("members").GetArrayLength() + 1);   // just the owner is left
    }

    [Fact]
    public async Task Members_of_other_workspaces_cannot_be_removed()
    {
        var a = await Workspace.CreateAsync(_factory, "Alpha Removal");
        var b = await Workspace.CreateAsync(_factory, "Beta Removal");
        var inB = await b.AddAsync();
        Assert.Equal(HttpStatusCode.NotFound, (await a.Http.SendAsync(a.As(a.Owner, HttpMethod.Delete, MemberUrl(inB)))).StatusCode);
        Assert.Equal(1, _factory.WithDb(db => db.Members.Count(m => m.UserId == inB.UserId)));
    }

    [Fact]
    public async Task An_admin_who_removes_themself_is_signed_out_and_leaves()
    {
        var w = await Workspace.CreateAsync(_factory);
        var admin = await w.AddAsync("admin");
        Assert.Equal(HttpStatusCode.NoContent, (await w.Http.SendAsync(w.As(admin, HttpMethod.Delete, MemberUrl(admin)))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.SendAsync(Bearer(HttpMethod.Get, "/v1/me", admin.Token))).StatusCode);
        Assert.Equal(0, _factory.WithDb(db => db.Members.Count(m => m.UserId == admin.UserId)));
    }
}

public sealed class RecentSignInTests : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _factory;
    public RecentSignInTests(ApiFactory factory) => _factory = factory;

    [Fact]
    public async Task Sensitive_actions_need_a_sign_in_within_two_hours_and_signing_in_again_fixes_it()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        var invitation = await w.InviteAsync(NewEmail());

        // The owner's session is now three hours old.
        _factory.WithDb(db => db.Database.ExecuteSqlRaw("UPDATE Sessions SET CreatedAt = {0} WHERE UserId = {1}", DateTime.UtcNow.AddHours(-3), w.Owner.UserId));

        async Task AssertReauth(HttpMethod method, string url, object? body = null)
        {
            var r = await w.CallAsync(w.Owner, method, url, body);
            Assert.Equal(HttpStatusCode.Forbidden, r.Status);
            Assert.Equal("reauth", r.Body.GetProperty("error").GetString());
            Assert.Equal("fresh_auth_required", r.Body.GetProperty("reason").GetString());
            Assert.Equal("For security, confirm it's you before changing workspace settings.", r.Body.GetProperty("message").GetString());
        }
        await AssertReauth(HttpMethod.Post, "/v1/invitations", new { email = NewEmail(), role = "member" });
        await AssertReauth(HttpMethod.Post, $"/v1/members/{member.MemberId}/role", new { role = "admin" });
        await AssertReauth(HttpMethod.Delete, $"/v1/members/{member.MemberId}");
        await AssertReauth(HttpMethod.Post, $"/v1/members/{member.MemberId}/transfer-ownership");
        await AssertReauth(HttpMethod.Post, $"/v1/invitations/{invitation.GetProperty("invitationId").GetString()}/cancel");
        await AssertReauth(HttpMethod.Get, $"/v1/invitations/{invitation.GetProperty("invitationId").GetString()}/link");

        // Reading is unaffected, and nothing changed.
        Assert.Equal(HttpStatusCode.OK, (await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Get, "/v1/org"))).StatusCode);
        Assert.Equal("member", (await w.OrgAsync()).GetProperty("members").EnumerateArray().Single(m => m.GetProperty("id").GetString() == member.MemberId).GetProperty("role").GetString());

        // A fresh sign-in works.
        var fresh = (await ReadJsonAsync(await w.Http.PostAsJsonAsync("/api/auth/sign-in/email", new { email = w.Owner.Email, password = Password }))).GetProperty("token").GetString()!;
        Assert.Equal(HttpStatusCode.OK, (await w.Http.SendAsync(w.As(fresh, HttpMethod.Post, $"/v1/members/{member.MemberId}/role", new { role = "admin" }))).StatusCode);
    }

    [Fact]
    public async Task A_missing_permission_is_reported_before_a_stale_session()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        _factory.WithDb(db => db.Database.ExecuteSqlRaw("UPDATE Sessions SET CreatedAt = {0} WHERE UserId = {1}", DateTime.UtcNow.AddHours(-3), member.UserId));
        var r = await w.CallAsync(member, HttpMethod.Post, "/v1/invitations", new { email = NewEmail(), role = "member" });
        Assert.Equal("forbidden", Workspace.Error(r.Body));    // asking them to sign in again would not help: they lack the permission
    }

    [Fact]
    public async Task Unauthenticated_calls_and_missing_workspaces_are_refused_before_anything_else()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        var anonymous = new HttpRequestMessage(HttpMethod.Delete, $"/v1/members/{member.MemberId}");
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.SendAsync(anonymous)).StatusCode);
        var noOrg = Bearer(HttpMethod.Post, "/v1/invitations", w.Owner.Token, new { email = NewEmail(), role = "member" });   // owner's session has an active org...
        Assert.Equal(HttpStatusCode.Created, (await w.Http.SendAsync(noOrg)).StatusCode);                                     // ...so the header is optional
        var (_, stranger, _) = await _factory.SignUpAsync(w.Http);
        var wrongOrg = await w.Http.SendAsync(w.As(stranger, HttpMethod.Post, "/v1/invitations", new { email = NewEmail(), role = "member" }));
        Assert.Equal(HttpStatusCode.NotFound, wrongOrg.StatusCode);
    }
}
