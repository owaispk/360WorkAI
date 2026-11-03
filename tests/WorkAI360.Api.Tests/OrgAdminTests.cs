using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Domain.OrgAdmin;
using WorkAI360.Api.Features.OrgAdmin;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>Audit on, capture exports available at once (no settle delay), as a self-hosted installation would run.</summary>
public sealed class OrgAdminFactory : ApiFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Settings => [new("OrgAdmin:Audit:ExportSettleSeconds", "0")];
}

/// <summary>Audit logs not entitled (the reference's default).</summary>
public sealed class AuditNotEntitledFactory : ApiFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Settings => [new("OrgAdmin:Audit:SelfHosted", "false")];
}

/// <summary>Audit visibility switched off for the deployment.</summary>
public sealed class AuditHiddenFactory : ApiFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Settings => [new("OrgAdmin:Audit:Visible", "false")];
}

internal static class OrgAdminHelpers
{
    public static async Task<(HttpStatusCode Status, JsonElement Body)> WithKeyAsync(this Workspace w, string key, HttpMethod method, string url, object? body = null, bool bearer = false)
    {
        var request = new HttpRequestMessage(method, url);
        if (bearer) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", key);
        else request.Headers.Add("x-api-key", key);
        if (body is not null) request.Content = JsonContent.Create(body);
        var r = await w.Http.SendAsync(request);
        var text = await r.Content.ReadAsStringAsync();
        return (r.StatusCode, string.IsNullOrEmpty(text) ? default : JsonDocument.Parse(text).RootElement.Clone());
    }

    public static async Task<(string Id, string Secret)> MakeKeyAsync(this Workspace w, string name = "Build Server")
    {
        var r = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/api-keys", new { name });
        Assert.Equal(HttpStatusCode.Created, r.Status);
        return (r.Body.GetProperty("apiKey").GetProperty("id").GetString()!, r.Body.GetProperty("key").GetString()!);
    }

    public static async Task<JsonElement[]> OperationsAsync(this Workspace w, Person by, string query = "")
    {
        var r = await w.CallAsync(by, HttpMethod.Get, "/v1/audit/operations?limit=100" + query);
        Assert.Equal(HttpStatusCode.OK, r.Status);
        return r.Body.GetProperty("operations").EnumerateArray().ToArray();
    }

    public static string[] Actions(this IEnumerable<JsonElement> operations) => operations.Select(o => o.GetProperty("action").GetString()!).ToArray();

    /// <summary>A valid PNG of the given size, built by hand (no image library here).</summary>
    public static byte[] Png(int width, int height)
    {
        static byte[] Chunk(string type, byte[] data)
        {
            var body = Encoding.ASCII.GetBytes(type).Concat(data).ToArray();
            var crc = Crc32(body);
            return [.. BitConverter.GetBytes(data.Length).Reverse(), .. body, .. BitConverter.GetBytes(crc).Reverse()];
        }
        var header = new byte[13];
        BitConverter.GetBytes(width).Reverse().ToArray().CopyTo(header, 0);
        BitConverter.GetBytes(height).Reverse().ToArray().CopyTo(header, 4);
        header[8] = 8; header[9] = 2;
        var row = new byte[1 + width * 3];
        Array.Fill(row, (byte)0x55, 1, row.Length - 1);
        using var raw = new MemoryStream();
        using (var z = new ZLibStream(raw, CompressionLevel.Fastest, leaveOpen: true)) for (var y = 0; y < height; y++) z.Write(row);
        return [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, .. Chunk("IHDR", header), .. Chunk("IDAT", raw.ToArray()), .. Chunk("IEND", [])];
    }

    private static uint Crc32(byte[] data)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var b in data)
        {
            crc ^= b;
            for (var i = 0; i < 8; i++) crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        }
        return ~crc;
    }

    public static async Task<HttpResponseMessage> UploadAsync(this Workspace w, Person by, params (string Field, byte[] Bytes, string Type)[] files)
    {
        var form = new MultipartFormDataContent { { new StringContent("note"), "note" } };
        foreach (var (field, bytes, type) in files)
        {
            var part = new ByteArrayContent(bytes);
            part.Headers.ContentType = new MediaTypeHeaderValue(type);
            form.Add(part, field, field + ".png");
        }
        var request = w.As(by, HttpMethod.Post, "/v1/org/brand-assets");
        request.Content = form;
        return await w.Http.SendAsync(request);
    }
}

public sealed class OrgAdminTests : IClassFixture<OrgAdminFactory>
{
    private readonly OrgAdminFactory _factory;
    public OrgAdminTests(OrgAdminFactory factory) => _factory = factory;

    // ----- API keys ---------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task A_key_is_shown_once_and_only_its_hash_is_stored_anywhere()
    {
        var w = await Workspace.CreateAsync(_factory);
        var (id, secret) = await w.MakeKeyAsync();
        Assert.StartsWith("den_", secret);
        Assert.Equal(68, secret.Length);

        var row = _factory.WithDb(db => db.Set<ApiKey>().AsNoTracking().Single(k => k.Id == id));
        Assert.Equal(Ids.Sha256Hex(secret), row.KeyHash);
        Assert.Equal(secret[..6], row.Start);
        // Not in the key row, not in the list, and not in any audit event.
        Assert.DoesNotContain(secret, JsonSerializer.Serialize(row));
        var list = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/api-keys");
        Assert.DoesNotContain(secret, list.Body.ToString());
        Assert.DoesNotContain("keyHash", list.Body.ToString(), StringComparison.OrdinalIgnoreCase);
        var events = _factory.WithDb(db => db.Set<AuditEvent>().AsNoTracking().Where(e => e.OrganizationId == w.OrgId).Select(e => e.EnvelopeJson).ToList());
        Assert.NotEmpty(events);
        Assert.DoesNotContain(events, e => e.Contains(secret) || e.Contains(row.KeyHash));
    }

    [Fact]
    public async Task Creating_a_key_validates_the_name_and_trims_it()
    {
        var w = await Workspace.CreateAsync(_factory);
        foreach (var body in new object[] { new { }, new { name = "a" }, new { name = "   " }, new { name = new string('x', 65) }, new { name = 7 } })
        {
            var r = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/api-keys", body);
            Assert.Equal(HttpStatusCode.BadRequest, r.Status);
            Assert.Equal("invalid_request", r.Body.GetProperty("error").GetString());
            Assert.StartsWith("name: ", r.Body.GetProperty("message").GetString());
        }
        var ok = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/api-keys", new { name = "  ab  " });
        Assert.Equal("ab", ok.Body.GetProperty("apiKey").GetProperty("name").GetString());
        Assert.Equal(HttpStatusCode.BadRequest, (await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Post, "/v1/api-keys", null))).StatusCode);
    }

    [Fact]
    public async Task Only_holders_of_the_key_permissions_may_list_create_or_delete_and_everyone_else_is_refused_by_name()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        var admin = await w.AddAsync("admin");
        var (id, _) = await w.MakeKeyAsync();
        Assert.Equal("api_keys.view", (await w.CallAsync(member, HttpMethod.Get, "/v1/api-keys")).Required());
        Assert.Equal("api_keys.manage", (await w.CallAsync(member, HttpMethod.Post, "/v1/api-keys", new { name = "Mine" })).Required());
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(admin, HttpMethod.Get, "/v1/api-keys")).Status);
        Assert.Equal("api_keys.manage", (await w.CallAsync(admin, HttpMethod.Post, "/v1/api-keys", new { name = "Mine" })).Required());
        Assert.Equal("api_keys.manage", (await w.CallAsync(admin, HttpMethod.Delete, $"/v1/api-keys/{id}")).Required());
        // Nothing was created or deleted by the refused calls.
        Assert.Equal(1, _factory.WithDb(db => db.Set<ApiKey>().Count(k => k.OrganizationId == w.OrgId)));
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.GetAsync("/v1/api-keys")).StatusCode);
    }

    [Fact]
    public async Task A_key_acts_as_its_member_in_its_own_workspace_only()
    {
        var a = await Workspace.CreateAsync(_factory);
        var b = await Workspace.CreateAsync(_factory);
        var (_, keyA) = await a.MakeKeyAsync();
        var (idB, keyB) = await b.MakeKeyAsync();

        var org = await a.WithKeyAsync(keyA, HttpMethod.Get, "/v1/org");
        Assert.Equal(a.OrgId, org.Body.GetProperty("organization").GetProperty("id").GetString());
        // The org header cannot steer a key into another workspace.
        var steered = new HttpRequestMessage(HttpMethod.Get, "/v1/org");
        steered.Headers.Add("x-api-key", keyA);
        steered.Headers.Add("x-openwork-org-id", b.OrgId);
        var steeredResponse = await a.Http.SendAsync(steered);
        Assert.Equal(a.OrgId, (await ReadJsonAsync(steeredResponse)).GetProperty("organization").GetProperty("id").GetString());
        // It cannot delete or see another workspace's keys.
        Assert.Equal(HttpStatusCode.NotFound, (await a.WithKeyAsync(keyA, HttpMethod.Delete, $"/v1/api-keys/{idB}")).Status);
        Assert.Equal(HttpStatusCode.OK, (await b.WithKeyAsync(keyB, HttpMethod.Get, "/v1/org")).Status);
        var listA = await a.WithKeyAsync(keyA, HttpMethod.Get, "/v1/api-keys");
        Assert.DoesNotContain(idB, listA.Body.ToString());
        // /v1/me shows the person with no web session.
        var me = await a.WithKeyAsync(keyA, HttpMethod.Get, "/v1/me");
        Assert.Equal(a.Owner.UserId, me.Body.GetProperty("user").GetProperty("id").GetString());
        Assert.Equal(JsonValueKind.Null, me.Body.GetProperty("session").ValueKind);
    }

    [Fact]
    public async Task A_key_is_refused_when_wrong_expired_disabled_deleted_or_not_a_key()
    {
        var w = await Workspace.CreateAsync(_factory);
        var (id, secret) = await w.MakeKeyAsync();
        Assert.Equal(HttpStatusCode.OK, (await w.WithKeyAsync(secret, HttpMethod.Get, "/v1/org")).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.WithKeyAsync(secret + "x", HttpMethod.Get, "/v1/org")).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.WithKeyAsync(secret[..^1], HttpMethod.Get, "/v1/org")).Status);
        // A session token is not a key, and a key is not a session token for routes that need a person.
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.WithKeyAsync(w.Owner.Token, HttpMethod.Get, "/v1/org")).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.WithKeyAsync(secret, HttpMethod.Post, "/v1/me/active-organization", new { organizationId = w.OrgId })).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.WithKeyAsync(secret, HttpMethod.Post, "/v1/mcp/token", new { })).Status);

        // Expired.
        _factory.WithDb(db => db.Set<ApiKey>().Where(k => k.Id == id).ExecuteUpdate(s => s.SetProperty(k => k.ExpiresAt, DateTime.UtcNow.AddMinutes(-1))));
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.WithKeyAsync(secret, HttpMethod.Get, "/v1/org")).Status);
        // Disabled.
        _factory.WithDb(db => db.Set<ApiKey>().Where(k => k.Id == id).ExecuteUpdate(s => s.SetProperty(k => k.ExpiresAt, DateTime.UtcNow.AddDays(1)).SetProperty(k => k.Enabled, false)));
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.WithKeyAsync(secret, HttpMethod.Get, "/v1/org")).Status);
        // Deleted.
        _factory.WithDb(db => db.Set<ApiKey>().Where(k => k.Id == id).ExecuteUpdate(s => s.SetProperty(k => k.Enabled, true)));
        Assert.Equal(HttpStatusCode.OK, (await w.WithKeyAsync(secret, HttpMethod.Get, "/v1/org")).Status);
        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/api-keys/{id}")).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.WithKeyAsync(secret, HttpMethod.Get, "/v1/org")).Status);
    }

    [Fact]
    public async Task A_den_prefixed_bearer_token_is_accepted_as_a_key()
    {
        var w = await Workspace.CreateAsync(_factory);
        var (_, secret) = await w.MakeKeyAsync();
        var r = await w.WithKeyAsync(secret, HttpMethod.Get, "/v1/org", bearer: true);
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.WithKeyAsync("den_" + new string('a', 64), HttpMethod.Get, "/v1/org", bearer: true)).Status);
    }

    [Fact]
    public async Task Removing_a_member_or_changing_their_standing_turns_their_keys_off_and_records_it()
    {
        var w = await Workspace.CreateAsync(_factory);
        var maker = await w.AddAsync();
        var teamId = await w.TeamAsync("Key Team", maker);
        await w.RoleAsync(teamId, "api_keys.manage", "api_keys.view");
        var made = await w.CallAsync(maker, HttpMethod.Post, "/v1/api-keys", new { name = "Maker key" });
        Assert.Equal(HttpStatusCode.Created, made.Status);
        var key = made.Body.GetProperty("key").GetString()!;
        var keyId = made.Body.GetProperty("apiKey").GetProperty("id").GetString()!;
        Assert.Equal(HttpStatusCode.OK, (await w.WithKeyAsync(key, HttpMethod.Get, "/v1/api-keys")).Status);

        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/members/{maker.MemberId}")).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.WithKeyAsync(key, HttpMethod.Get, "/v1/api-keys")).Status);
        Assert.False(_factory.WithDb(db => db.Set<ApiKey>().Single(k => k.Id == keyId).Enabled));
        var revoked = (await w.OperationsAsync(w.Owner, "&action=api_key.revoked")).ToArray();
        Assert.Single(revoked);

        // The owner's own key dies when ownership moves, as the owner's sessions do.
        var admin = await w.AddAsync("admin");
        var (_, ownerKey) = await w.MakeKeyAsync("Owner key");
        Assert.Equal(HttpStatusCode.OK, (await w.WithKeyAsync(ownerKey, HttpMethod.Post, $"/v1/members/{admin.MemberId}/transfer-ownership", new { })).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.WithKeyAsync(ownerKey, HttpMethod.Get, "/v1/org")).Status);
    }

    [Fact]
    public async Task A_key_that_sends_too_many_requests_is_answered_429_with_retry_after()
    {
        var w = await Workspace.CreateAsync(_factory);
        var (id, secret) = await w.MakeKeyAsync();
        _factory.WithDb(db => db.Set<ApiKey>().Where(k => k.Id == id).ExecuteUpdate(s => s.SetProperty(k => k.RateLimitMax, 3)));
        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 5; i++) statuses.Add((await w.WithKeyAsync(secret, HttpMethod.Get, "/v1/me")).Status);
        Assert.Equal([HttpStatusCode.OK, HttpStatusCode.OK, HttpStatusCode.OK, HttpStatusCode.TooManyRequests, HttpStatusCode.TooManyRequests], statuses);
        // Another key is unaffected.
        var (_, other) = await w.MakeKeyAsync("Other");
        Assert.Equal(HttpStatusCode.OK, (await w.WithKeyAsync(other, HttpMethod.Get, "/v1/me")).Status);
    }

    [Fact]
    public async Task Concurrent_creates_give_distinct_ids_and_secrets()
    {
        var w = await Workspace.CreateAsync(_factory);
        var results = await Task.WhenAll(Enumerable.Range(0, 20).Select(i => w.CallAsync(w.Owner, HttpMethod.Post, "/v1/api-keys", new { name = $"Key {i:00}" })));
        Assert.All(results, r => Assert.Equal(HttpStatusCode.Created, r.Status));
        Assert.Equal(20, results.Select(r => r.Body.GetProperty("key").GetString()).Distinct().Count());
        Assert.Equal(20, results.Select(r => r.Body.GetProperty("apiKey").GetProperty("id").GetString()).Distinct().Count());
        var list = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/api-keys");
        Assert.Equal(20, list.Body.GetProperty("apiKeys").GetArrayLength());
    }

    // ----- audit log --------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Changes_in_every_built_area_are_recorded_with_actor_resources_and_before_and_after()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        var teamId = await w.TeamAsync("Support", member);
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/teams/{teamId}", new { name = "Support Desk" })).Status);
        var setId = await w.RoleAsync(teamId, "teams.view");
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/members/{member.MemberId}/role", new { role = "admin" });
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/members/{member.MemberId}/role", new { role = "member" });
        await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/permissions/sets/{setId}/permissions", new { changes = new[] { new { key = "teams.view", status = "deny" } } });
        var invite = await w.InviteAsync(NewEmail("later"));
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/invitations/{invite.GetProperty("invitationId").GetString()}/cancel");
        await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/teams/{teamId}");
        await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/org/web-origins", new { origin = "https://a.example.com" });
        await w.CallAsync(w.Owner, HttpMethod.Patch, "/v1/org", new { name = "Audited Space" });
        await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/members/{member.MemberId}");

        var actions = (await w.OperationsAsync(w.Owner)).Actions();
        foreach (var expected in new[]
        {
            AuditActions.InvitationCreated, AuditActions.InvitationAccepted, AuditActions.InvitationCanceled, AuditActions.TeamCreated, AuditActions.TeamUpdated, AuditActions.TeamDeleted,
            AuditActions.PermissionSetCreated, AuditActions.PermissionSetPermissionsChanged, AuditActions.MemberRoleUpdated, AuditActions.MemberRemoved, AuditActions.WebOriginApproved,
            AuditActions.OrganizationSettingsUpdated, AuditActions.PolicyInitialized,
        })
            Assert.True(actions.Contains(expected), $"missing {expected}; recorded: {string.Join(", ", actions)}");
        Assert.Equal(2, actions.Count(a => a == AuditActions.MemberRoleUpdated));

        var changed = (await w.OperationsAsync(w.Owner, $"&action={AuditActions.PermissionSetPermissionsChanged}")).Single();
        var changedEvent = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/audit/operations/{changed.GetProperty("id").GetString()}/events")).Body.GetProperty("events")[0].GetProperty("changes");
        Assert.Equal("allow", changedEvent.GetProperty("before").GetProperty("teams.view").GetString());
        Assert.Equal("deny", changedEvent.GetProperty("after").GetProperty("teams.view").GetString());

        var update = (await w.OperationsAsync(w.Owner, $"&action={AuditActions.TeamUpdated}")).Single();
        Assert.Equal(w.Owner.UserId, update.GetProperty("initiatingActor").GetProperty("id").GetString());
        Assert.Equal("user", update.GetProperty("initiatingActor").GetProperty("type").GetString());
        var events = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/audit/operations/{update.GetProperty("id").GetString()}/events");
        var e = events.Body.GetProperty("events")[0];
        Assert.Equal(2, e.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(w.Owner.MemberId, e.GetProperty("actor").GetProperty("memberId").GetString());
        Assert.Equal("Support", e.GetProperty("changes").GetProperty("before").GetProperty("name").GetString());
        Assert.Equal("Support Desk", e.GetProperty("changes").GetProperty("after").GetProperty("name").GetString());
        Assert.Equal(["name"], e.GetProperty("changes").GetProperty("changedFields").EnumerateArray().Select(x => x.GetString()!).ToArray());
        Assert.Equal("PATCH", e.GetProperty("http").GetProperty("method").GetString());
        Assert.Contains(update.GetProperty("resources").EnumerateArray(), r => r.GetProperty("type").GetString() == "team" && r.GetProperty("id").GetString() == teamId && r.GetProperty("relationship").GetString() == "target");

        // Filtering by the resource id finds exactly the operations that touched it, and by the event id finds the operation.
        var byTeam = await w.OperationsAsync(w.Owner, $"&resourceType=team&resourceId={teamId}");
        Assert.Equal(3, byTeam.Length);   // created, updated, deleted
        var bySearch = await w.OperationsAsync(w.Owner, $"&searchId={e.GetProperty("id").GetString()}");
        Assert.Equal(update.GetProperty("id").GetString(), bySearch.Single().GetProperty("id").GetString());
    }

    [Fact]
    public async Task Signing_in_out_and_failing_to_sign_in_are_recorded_in_the_persons_workspaces()
    {
        var w = await Workspace.CreateAsync(_factory);
        var (email, _, _) = (w.Owner.Email, 0, 0);
        var browser = _factory.Plain();
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = "Wr0ng!Passw0rd#2026y" })).StatusCode);
        var signIn = await browser.PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = Password });
        var token = (await ReadJsonAsync(signIn)).GetProperty("token").GetString()!;
        await browser.SendAsync(Bearer(HttpMethod.Post, "/api/auth/sign-out", token));
        // Unknown addresses leave nothing behind.
        await browser.PostAsJsonAsync("/api/auth/sign-in/email", new { email = NewEmail("ghost"), password = Password });

        var ops = await w.OperationsAsync(w.Owner);
        var actions = ops.Actions();
        Assert.Contains(AuditActions.SessionCreated, actions);
        Assert.Contains(AuditActions.SessionRevoked, actions);
        var failed = ops.Single(o => o.GetProperty("action").GetString() == AuditActions.SessionSignInFailed);
        Assert.Equal("failed", failed.GetProperty("outcome").GetString());
        var ev = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/audit/operations/{failed.GetProperty("id").GetString()}/events")).Body.GetProperty("events")[0];
        Assert.Equal("security", ev.GetProperty("category").GetString());
        Assert.DoesNotContain(Password, ev.ToString());
        Assert.DoesNotContain("Wr0ng", ev.ToString());
    }

    [Fact]
    public async Task One_workspaces_history_never_shows_in_another()
    {
        var a = await Workspace.CreateAsync(_factory);
        var b = await Workspace.CreateAsync(_factory);
        var teamId = await a.TeamAsync("Secret Team");
        await b.TeamAsync("Other Team");
        var aOps = await a.OperationsAsync(a.Owner);
        var bOps = await b.OperationsAsync(b.Owner);
        Assert.Empty(aOps.Select(o => o.GetProperty("id").GetString()).Intersect(bOps.Select(o => o.GetProperty("id").GetString())));

        var aTeamOp = aOps.Single(o => o.GetProperty("action").GetString() == AuditActions.TeamCreated);
        var opId = aTeamOp.GetProperty("id").GetString();
        // B asking for A's operation (events, search by operation id, by resource id) finds nothing.
        Assert.Equal(HttpStatusCode.NotFound, (await b.CallAsync(b.Owner, HttpMethod.Get, $"/v1/audit/operations/{opId}/events")).Status);
        Assert.Empty(await b.OperationsAsync(b.Owner, $"&searchId={opId}"));
        Assert.Empty(await b.OperationsAsync(b.Owner, $"&resourceId={teamId}"));
        Assert.Empty(await b.OperationsAsync(b.Owner, $"&actorId={a.Owner.UserId}&action={AuditActions.TeamCreated}"));
        // And an export of B contains none of A's events.
        var export = await b.Http.SendAsync(b.As(b.Owner, HttpMethod.Get, "/v1/audit/export"));
        Assert.DoesNotContain(a.OrgId, await export.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Reading_audit_history_needs_audit_view_and_is_itself_recorded()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        var admin = await w.AddAsync("admin");
        foreach (var path in new[] { "/v1/audit/operations", "/v1/audit/usage", "/v1/audit/event-types", "/v1/audit/export" })
            Assert.Equal("audit.view", (await w.CallAsync(member, HttpMethod.Get, path)).Required());
        Assert.Equal("audit.manage", (await w.CallAsync(member, HttpMethod.Patch, "/v1/audit/settings", new { captureOn = false, expectedRevision = 1 })).Required());
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(admin, HttpMethod.Get, "/v1/audit/operations")).Status);

        // The owner's reads are recorded as a requested/served pair in one operation; a refused read leaves nothing.
        var first = await w.OperationsAsync(w.Owner);
        await w.CallAsync(member, HttpMethod.Get, "/v1/audit/operations");
        var second = await w.OperationsAsync(w.Owner);
        Assert.Equal(first.Length + 1, second.Length);   // only the owner's first read was added
        var read = second.First(o => o.GetProperty("action").GetString() == AuditActions.Requested("operations"));
        Assert.Equal("access", (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/audit/operations/{read.GetProperty("id").GetString()}/events")).Body.GetProperty("events")[0].GetProperty("category").GetString());
        var events = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/audit/operations/{read.GetProperty("id").GetString()}/events")).Body.GetProperty("events");
        Assert.Equal([AuditActions.Requested("operations"), AuditActions.Served("operations")], events.EnumerateArray().Select(e => e.GetProperty("action").GetString()!).ToArray());
        Assert.Equal(2, read.GetProperty("eventCount").GetInt32());
        Assert.Equal("succeeded", read.GetProperty("outcome").GetString());
    }

    [Fact]
    public async Task Capture_can_be_switched_with_the_current_revision_and_only_one_concurrent_change_wins()
    {
        var w = await Workspace.CreateAsync(_factory);
        var usage = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/audit/usage");
        var revision = usage.Body.GetProperty("policy").GetProperty("revision").GetInt32();
        Assert.True(usage.Body.GetProperty("captureEnabled").GetBoolean());

        // Ten simultaneous "switch off from this revision" requests: exactly one changes it, the rest see it already changed or the same state.
        var results = await Task.WhenAll(Enumerable.Range(0, 10).Select(_ => w.CallAsync(w.Owner, HttpMethod.Patch, "/v1/audit/settings", new { captureOn = false, expectedRevision = revision })));
        Assert.Equal(1, results.Count(r => r.Status == HttpStatusCode.OK && r.Body.GetProperty("policy").GetProperty("revision").GetInt32() == revision + 1 && !r.Body.GetProperty("captureOn").GetBoolean()));
        Assert.All(results, r => Assert.Contains(r.Status, new[] { HttpStatusCode.OK, HttpStatusCode.Conflict }));
        var final = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/audit/usage");
        Assert.Equal(revision + 1, final.Body.GetProperty("policy").GetProperty("revision").GetInt32());
        Assert.False(final.Body.GetProperty("captureOn").GetBoolean());
        Assert.Equal(1, _factory.WithDb(db => db.Set<AuditEvent>().Count(e => e.OrganizationId == w.OrgId && e.Action == AuditActions.CaptureDisabled)));

        // While capture is off, changes are not recorded; the switch back on is.
        var before = _factory.WithDb(db => db.Set<AuditEvent>().Count(e => e.OrganizationId == w.OrgId));
        await w.TeamAsync("Unrecorded");
        Assert.Equal(before, _factory.WithDb(db => db.Set<AuditEvent>().Count(e => e.OrganizationId == w.OrgId)));
        var on = await w.CallAsync(w.Owner, HttpMethod.Patch, "/v1/audit/settings", new { captureOn = true, expectedRevision = revision + 1 });
        Assert.Equal(revision + 2, on.Body.GetProperty("policy").GetProperty("revision").GetInt32());
        await w.TeamAsync("Recorded");
        Assert.Contains(AuditActions.TeamCreated, (await w.OperationsAsync(w.Owner)).Actions());
        Assert.Equal("audit_policy_changed", (await w.CallAsync(w.Owner, HttpMethod.Patch, "/v1/audit/settings", new { captureOn = false, expectedRevision = 99 })).Error());
        Assert.Equal("audit_policy_changed", (await w.CallAsync(w.Owner, HttpMethod.Patch, "/v1/audit/settings", new { captureOn = false, expectedRevision = 0 })).Error());
    }

    [Fact]
    public async Task Pages_are_stable_and_cursors_are_signed_bound_and_expire()
    {
        var w = await Workspace.CreateAsync(_factory);
        for (var i = 0; i < 6; i++) await w.TeamAsync($"Team {i}");
        var first = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/audit/operations?limit=3");
        var cursor = first.Body.GetProperty("nextCursor").GetString()!;
        var second = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/audit/operations?limit=3&cursor={Uri.EscapeDataString(cursor)}");
        var ids = first.Body.GetProperty("operations").EnumerateArray().Concat(second.Body.GetProperty("operations").EnumerateArray()).Select(o => o.GetProperty("id").GetString()).ToList();
        Assert.Equal(6, ids.Distinct().Count());
        Assert.Equal(first.Body.GetProperty("snapshotAt").GetString(), second.Body.GetProperty("snapshotAt").GetString());

        // New activity after the first page does not slide into the later pages.
        await w.TeamAsync("Late arrival");
        var third = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/audit/operations?limit=100&cursor={Uri.EscapeDataString(cursor)}");
        Assert.DoesNotContain(third.Body.GetProperty("operations").EnumerateArray(), o => o.GetProperty("resources").ToString().Contains("Late arrival"));

        // Other filters, a forged tail, another workspace and garbage are all refused.
        Assert.Equal("audit_invalid_cursor", (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/audit/operations?outcome=failed&cursor={Uri.EscapeDataString(cursor)}")).Error());
        Assert.Equal("audit_invalid_cursor", (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/audit/operations?cursor={Uri.EscapeDataString(cursor[..^3] + "AAA")}")).Error());
        var other = await Workspace.CreateAsync(_factory);
        Assert.Equal("audit_invalid_cursor", (await other.CallAsync(other.Owner, HttpMethod.Get, $"/v1/audit/operations?cursor={Uri.EscapeDataString(cursor)}")).Error());
        Assert.Equal("audit_invalid_cursor", (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/audit/operations?cursor=abc.def")).Error());
        Assert.Equal("audit_invalid_cursor", (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/audit/export?cursor={Uri.EscapeDataString(cursor)}")).Error());   // an operations cursor is not an export cursor

        // A genuine cursor past its 24 hours is 410 (re-signed with the server secret to move its expiry).
        var dot = cursor.IndexOf('.');
        var payload = Encoding.UTF8.GetString(Convert.FromBase64String(PadBase64(cursor[..dot])));
        using var doc = JsonDocument.Parse(payload);
        var expired = payload.Replace($"\"ExpiresAt\":{doc.RootElement.GetProperty("ExpiresAt").GetInt64()}", "\"ExpiresAt\":1000");
        var body = Convert.ToBase64String(Encoding.UTF8.GetBytes(expired)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var signature = Convert.ToBase64String(HMACSHA256.HashData(Encoding.UTF8.GetBytes(Secret), Encoding.UTF8.GetBytes(body))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var gone = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/audit/operations?limit=3&cursor={body}.{signature}");
        Assert.Equal(HttpStatusCode.Gone, gone.Status);
        Assert.Equal("audit_cursor_expired", gone.Error());
    }

    private static string PadBase64(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        return padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
    }

    [Fact]
    public async Task Queries_are_strict_about_names_values_and_repeats()
    {
        var w = await Workspace.CreateAsync(_factory);
        foreach (var query in new[] { "limit=0", "limit=101", "limit=1.5", "limit=%201", "outcome=zzz", "origin=cloud", "foo=1", "limit=1&limit=2", "actorId=usr_nope", "from=2026-13-01", "from=2026-01-01T00:00:00", "to=2026-01-01&from=2026-02-01", "resourceType=team", "action=Bad", "searchId=%00" })
        {
            var r = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/audit/operations?" + query);
            Assert.True(r.Status == HttpStatusCode.BadRequest && r.Error() == "audit_invalid_query", $"{query} -> {r.Status} {r.Body}");
        }
        foreach (var path in new[] { "/v1/audit/usage?x=1", "/v1/audit/event-types?x=1", "/v1/audit/export?format=xml", "/v1/audit/export?format=csv&format=csv", "/v1/audit/operations/zzz/events" })
            Assert.Equal("audit_invalid_query", (await w.CallAsync(w.Owner, HttpMethod.Get, path)).Error());
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/audit/operations?from=2026-01-01&to=2099-01-01T00:00:00%2B02:00&limit=100&outcome=succeeded&origin=api")).Status);
        Assert.Equal("audit_operation_not_found", (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/audit/operations/aop_01m679526ge3yv9fx8c8thmxd4/events")).Error());
    }

    [Fact]
    public async Task The_catalog_lists_every_action_this_build_records_and_nothing_twice()
    {
        var w = await Workspace.CreateAsync(_factory);
        var r = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/audit/event-types");
        var types = r.Body.GetProperty("eventTypes").EnumerateArray().Select(e => e.GetString()!).ToList();
        Assert.Equal(types.Order(StringComparer.Ordinal), types);
        Assert.Equal(types.Count, types.Distinct().Count());
        Assert.All(types, t => Assert.Matches("^[a-z][a-z0-9_.-]*$", t));
        // Every action constant is listed.
        var constants = typeof(AuditActions).GetFields().Where(f => f.IsLiteral && f.FieldType == typeof(string)).Select(f => (string)f.GetRawConstantValue()!);
        Assert.Empty(constants.Except(types));
    }

    [Theory]
    [InlineData("plain", "\"plain\"")]
    [InlineData("=1+1", "\"'=1+1\"")]
    [InlineData("+cmd", "\"'+cmd\"")]
    [InlineData("-5", "\"'-5\"")]
    [InlineData("@SUM(A1)", "\"'@SUM(A1)\"")]
    [InlineData("  =hidden", "\"'  =hidden\"")]
    [InlineData("\t=x", "\"'\\u0009=x\"")]
    [InlineData("a\"b", "\"a\"\"b\"")]
    [InlineData("back\\slash", "\"back\\\\slash\"")]
    [InlineData("line\nbreak", "\"line\\u000abreak\"")]
    [InlineData(null, "\"\"")]
    public void CSV_cells_are_quoted_neutralized_and_never_multiline(string? value, string expected) => Assert.Equal(expected, AuditEndpoints.CsvCell(value));

    [Fact]
    public async Task Exports_are_one_event_per_line_or_csv_rows_and_page_with_a_header_cursor()
    {
        var w = await Workspace.CreateAsync(_factory);
        for (var i = 0; i < 4; i++) await w.TeamAsync($"=Team {i}");
        var nd = await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Get, "/v1/audit/export?limit=3"));
        Assert.Equal("application/x-ndjson; charset=utf-8", nd.Content.Headers.ContentType!.ToString());
        Assert.True(nd.Headers.TryGetValues("X-Audit-Next-Cursor", out var next));
        var lines = (await nd.Content.ReadAsStringAsync()).TrimEnd('\n').Split('\n');
        Assert.Equal(3, lines.Length);
        Assert.All(lines, l => Assert.Equal(2, JsonDocument.Parse(l).RootElement.GetProperty("schemaVersion").GetInt32()));
        var more = await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Get, $"/v1/audit/export?limit=100&cursor={Uri.EscapeDataString(next!.Single())}"));
        var moreIds = (await more.Content.ReadAsStringAsync()).TrimEnd('\n').Split('\n').Select(l => JsonDocument.Parse(l).RootElement.GetProperty("id").GetString());
        Assert.Empty(moreIds.Intersect(lines.Select(l => JsonDocument.Parse(l).RootElement.GetProperty("id").GetString())));   // no event twice across pages
        Assert.False(more.Headers.Contains("X-Audit-Next-Cursor"));

        var csv = await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Get, "/v1/audit/export?format=csv&limit=100"));
        var text = await csv.Content.ReadAsStringAsync();
        Assert.StartsWith("\"schema_version\",\"event_id\"", text);
        Assert.All(text.TrimEnd('\r', '\n').Split("\r\n"), l => Assert.StartsWith("\"", l));
    }

    // ----- organization settings --------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Settings_changes_are_validated_and_restricted_to_those_who_may_make_them()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        var admin = await w.AddAsync("admin");
        Assert.Equal("organization.update", (await w.CallAsync(member, HttpMethod.Patch, "/v1/org", new { name = "Nope Nope" })).Required());
        Assert.Equal("organization.update", (await w.CallAsync(admin, HttpMethod.Patch, "/v1/org", new { name = "Nope Nope" })).Required());
        foreach (var body in new object[] { new { }, new { name = "a" }, new { name = 5 }, new { foo = 1 }, new { name = "Okay Name", foo = 1 }, new { brandLogoUrl = "nope" }, new { requireSso = "yes" },
                     new { allowedEmailDomains = "a.com" }, new { allowedEmailDomains = new[] { "" } }, new { brandAccentColor = new string('x', 33) }, new { allowedDesktopVersions = new[] { new string('1', 33) } } })
        {
            var r = await w.CallAsync(w.Owner, HttpMethod.Patch, "/v1/org", body);
            Assert.True(r.Status == HttpStatusCode.BadRequest && r.Error() == "invalid_request", $"{JsonSerializer.Serialize(body)} -> {r.Status} {r.Body}");
        }
        var bad = await w.CallAsync(w.Owner, HttpMethod.Patch, "/v1/org", new { allowedEmailDomains = new[] { "good.com", "not a domain", "-x.com" } });
        Assert.Equal("invalid_email_domain", bad.Error());
        Assert.Equal(["not a domain", "-x.com"], bad.Body.GetProperty("invalidDomains").EnumerateArray().Select(e => e.GetString()!).ToArray());
        // Nothing from the refused requests stuck.
        Assert.Equal("Team Space", (await w.OrgAsync()).GetProperty("organization").GetProperty("name").GetString());
    }

    [Fact]
    public async Task Allowed_email_domains_are_enforced_when_inviting_and_again_when_accepting()
    {
        var w = await Workspace.CreateAsync(_factory);
        var invitedEmail = $"early.{Guid.NewGuid():N}@later-blocked.example";
        var (email, token, _) = await _factory.SignUpAsync(w.Http);
        // Invited before any limit exists...
        var invite = await w.InviteAsync(email);
        var early = await w.InviteAsync(invitedEmail);
        // ...then the workspace is limited to another domain.
        var set = await w.CallAsync(w.Owner, HttpMethod.Patch, "/v1/org", new { allowedEmailDomains = new[] { "Only.Example", "@ONLY.example" } });
        Assert.Equal(["only.example"], set.Body.GetProperty("organization").GetProperty("allowedEmailDomains").EnumerateArray().Select(e => e.GetString()!).ToArray());
        var accept = await w.Http.SendAsync(Bearer(HttpMethod.Post, "/v1/orgs/invitations/accept", token, new { id = invite.GetProperty("invitationId").GetString() }));
        Assert.Equal(HttpStatusCode.Conflict, accept.StatusCode);
        var body = await ReadJsonAsync(accept);
        Assert.Equal("account_email_domain_not_allowed", body.GetProperty("error").GetString());
        Assert.Equal("example.com", body.GetProperty("emailDomain").GetString());
        Assert.DoesNotContain(email, (await w.OrgAsync()).GetProperty("members").ToString().Replace(invite.GetProperty("email").GetString()!, ""), StringComparison.Ordinal);
        Assert.Equal(1, (await w.OrgAsync()).GetProperty("members").EnumerateArray().Count(m => m.GetProperty("userId").ValueKind == JsonValueKind.String));

        var refused = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/invitations", new { email = "x@elsewhere.example", role = "member" });
        Assert.Equal("invite_email_domain_not_allowed", refused.Error());
        Assert.Equal("only.example", refused.Body.GetProperty("allowedEmailDomains")[0].GetString());
        Assert.Equal(HttpStatusCode.Created, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/invitations", new { email = "x@only.example", role = "member" })).Status);
        // The join page shows the limit, and lifting it lets the earlier invitation through.
        var preview = await w.Http.GetAsync($"/v1/orgs/invitations/preview?id={early.GetProperty("invitationId").GetString()}");
        Assert.Equal("only.example", (await ReadJsonAsync(preview)).GetProperty("organization").GetProperty("allowedEmailDomains")[0].GetString());
        await w.CallAsync(w.Owner, HttpMethod.Patch, "/v1/org", new { allowedEmailDomains = (string[]?)null });
        Assert.Equal(HttpStatusCode.OK, (await w.Http.SendAsync(Bearer(HttpMethod.Post, "/v1/orgs/invitations/accept", token, new { id = invite.GetProperty("invitationId").GetString() }))).StatusCode);
    }

    [Fact]
    public async Task Settings_round_trip_through_the_org_payload_with_brand_fields_in_the_metadata()
    {
        var w = await Workspace.CreateAsync(_factory);
        var set = await w.CallAsync(w.Owner, HttpMethod.Patch, "/v1/org", new { name = "  New Name  ", brandAppName = "Acme", brandAccentColor = "#123456", requireSso = true, allowedDesktopVersions = new[] { "1.2.3" } });
        Assert.Equal(HttpStatusCode.OK, set.Status);
        var organization = set.Body.GetProperty("organization");
        Assert.Equal("New Name", organization.GetProperty("name").GetString());
        Assert.Equal(JsonValueKind.Object, organization.GetProperty("metadata").ValueKind);   // an object here, a string in GET /v1/org (as in the reference)
        var got = (await w.OrgAsync()).GetProperty("organization");
        Assert.Equal(JsonValueKind.String, got.GetProperty("metadata").ValueKind);
        var metadata = JsonDocument.Parse(got.GetProperty("metadata").GetString()!).RootElement;
        Assert.Equal("Acme", metadata.GetProperty("brandAppName").GetString());
        Assert.True(metadata.GetProperty("requireSso").GetBoolean());
        Assert.Equal("1.2.3", metadata.GetProperty("allowedDesktopVersions")[0].GetString());
        await w.CallAsync(w.Owner, HttpMethod.Patch, "/v1/org", new { brandAppName = (string?)null, allowedDesktopVersions = Array.Empty<string>() });
        var after = JsonDocument.Parse((await w.OrgAsync()).GetProperty("organization").GetProperty("metadata").GetString()!).RootElement;
        Assert.False(after.TryGetProperty("brandAppName", out _));
        Assert.False(after.TryGetProperty("allowedDesktopVersions", out _));
        Assert.Equal("#123456", after.GetProperty("brandAccentColor").GetString());
        var org = await w.OrgAsync();
        Assert.True(org.GetProperty("features").GetProperty("engineV2ForceUpgrade").GetBoolean());
        Assert.True(org.GetProperty("capabilities").GetProperty("auditLogs").GetBoolean());
        Assert.Equal("free", org.GetProperty("plan").GetProperty("tier").GetString());
    }

    [Fact]
    public async Task Two_workspaces_keep_separate_settings()
    {
        var a = await Workspace.CreateAsync(_factory);
        var b = await Workspace.CreateAsync(_factory);
        await a.CallAsync(a.Owner, HttpMethod.Patch, "/v1/org", new { allowedEmailDomains = new[] { "a.example" }, brandAppName = "A Co" });
        var bOrg = (await b.OrgAsync()).GetProperty("organization");
        Assert.Equal(JsonValueKind.Null, bOrg.GetProperty("allowedEmailDomains").ValueKind);
        Assert.DoesNotContain("A Co", bOrg.GetProperty("metadata").GetString());
        Assert.Equal(HttpStatusCode.Created, (await b.CallAsync(b.Owner, HttpMethod.Post, "/v1/invitations", new { email = "x@b.example", role = "member" })).Status);
    }

    // ----- web origins ------------------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("https://work.example.com", "https://work.example.com")]
    [InlineData("HTTPS://Work.Example.com:443/", "https://work.example.com")]
    [InlineData("https://work.example.com:8443", "https://work.example.com:8443")]
    [InlineData(" https://a.io/ ", "https://a.io")]
    [InlineData("http://work.example.com", null)]
    [InlineData("https://work.example.com/path", null)]
    [InlineData("https://work.example.com?x=1", null)]
    [InlineData("https://work.example.com#frag", null)]
    [InlineData("https://*.example.com", null)]
    [InlineData("https://user:pw@work.example.com", null)]
    [InlineData("https://", null)]
    [InlineData("work.example.com", null)]
    [InlineData("", null)]
    public void Web_origins_normalize_exactly(string input, string? expected) => Assert.Equal(expected, WebOriginEndpoints.Normalize(input));

    [Fact]
    public async Task Origins_are_listed_removed_isolated_and_limited_to_twenty_even_under_concurrency()
    {
        var w = await Workspace.CreateAsync(_factory);
        var other = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        var theirs = await other.CallAsync(other.Owner, HttpMethod.Post, "/v1/org/web-origins", new { origin = "https://same.example.com" });
        var mine = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/org/web-origins", new { origin = "https://same.example.com" });   // the same origin may be approved by two workspaces
        Assert.Equal(HttpStatusCode.Created, mine.Status);
        Assert.Equal("Owner Person", mine.Body.GetProperty("createdByName").GetString());
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/org/web-origins/{theirs.Body.GetProperty("id").GetString()}")).Status);
        Assert.Equal("web_origins.view", (await w.CallAsync(member, HttpMethod.Get, "/v1/org/web-origins")).Required());
        Assert.Equal("web_origins.manage", (await w.CallAsync(member, HttpMethod.Post, "/v1/org/web-origins", new { origin = "https://m.example.com" })).Required());

        // Two simultaneous approvals of one origin: one wins, the other is "already approved".
        var pair = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ => w.CallAsync(w.Owner, HttpMethod.Post, "/v1/org/web-origins", new { origin = "https://race.example.com" })));
        Assert.Equal([HttpStatusCode.Created, HttpStatusCode.Conflict], pair.Select(r => r.Status).Order().ToArray());
        // Thirty simultaneous approvals of different origins stop at the limit of twenty.
        var many = await Task.WhenAll(Enumerable.Range(0, 30).Select(i => w.CallAsync(w.Owner, HttpMethod.Post, "/v1/org/web-origins", new { origin = $"https://o{i}.example.com" })));
        Assert.Equal(20, _factory.WithDb(db => db.Set<OrganizationWebOrigin>().Count(o => o.OrganizationId == w.OrgId)));
        Assert.All(many.Where(r => r.Status != HttpStatusCode.Created), r => Assert.Equal("web_origin_limit_reached", r.Error()));
        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/org/web-origins/{mine.Body.GetProperty("id").GetString()}")).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/org/web-origins/{mine.Body.GetProperty("id").GetString()}")).Status);
        Assert.Equal(1, _factory.WithDb(db => db.Set<OrganizationWebOrigin>().Count(o => o.OrganizationId == other.OrgId)));
    }

    // ----- brand assets -----------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Brand_images_are_checked_stored_signed_and_scoped_to_their_workspace()
    {
        var w = await Workspace.CreateAsync(_factory);
        var other = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        Assert.Equal("branding.update", (await w.CallAsync(member, HttpMethod.Post, "/v1/org/brand-assets", new { })).Required());

        var upload = await w.UploadAsync(w.Owner, ("logo", OrgAdminHelpers.Png(256, 64), "image/png"), ("icon", OrgAdminHelpers.Png(128, 128), "image/png"));
        Assert.Equal(HttpStatusCode.OK, upload.StatusCode);
        var assets = (await ReadJsonAsync(upload)).GetProperty("assets");
        var logo = assets.GetProperty("logo");
        var url = logo.GetProperty("url").GetString()!;
        Assert.Equal(256, logo.GetProperty("width").GetInt32());
        Assert.Matches("^[a-f0-9]{64}$", logo.GetProperty("version").GetString()!);

        var served = await w.Http.GetAsync(url);
        Assert.Equal(HttpStatusCode.OK, served.StatusCode);
        Assert.Equal("image/png", served.Content.Headers.ContentType!.MediaType);
        Assert.Contains("immutable", served.Headers.CacheControl!.ToString());
        Assert.Equal("nosniff", served.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal(OrgAdminHelpers.Png(256, 64), await served.Content.ReadAsByteArrayAsync());

        // No signature, a forged one, or the same signature on another workspace's path: not found.
        var path = new Uri(url).AbsolutePath;
        Assert.Equal(HttpStatusCode.NotFound, (await w.Http.GetAsync(path)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await w.Http.GetAsync(path + "?signature=AAAA")).StatusCode);
        var signature = new Uri(url).Query;
        Assert.Equal(HttpStatusCode.NotFound, (await w.Http.GetAsync(path.Replace(w.OrgId, other.OrgId) + signature)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await w.Http.GetAsync(path.Replace("/logo/", "/icon/") + signature)).StatusCode);
        // The metadata names the stored images, and the other workspace's is untouched.
        var metadata = JsonDocument.Parse((await w.OrgAsync()).GetProperty("organization").GetProperty("metadata").GetString()!).RootElement;
        Assert.Equal(url, metadata.GetProperty("brandLogoUrl").GetString());
        Assert.DoesNotContain("brandLogoUrl", (await other.OrgAsync()).GetProperty("organization").GetProperty("metadata").GetString());
        Assert.Equal(0, _factory.WithDb(db => db.Set<BrandAsset>().Count(a => a.OrganizationId == other.OrgId)));
        // A hand-typed hosted URL replaces the stored logo.
        await w.CallAsync(w.Owner, HttpMethod.Patch, "/v1/org", new { brandLogoUrl = "https://example.com/logo.png" });
        var after = JsonDocument.Parse((await w.OrgAsync()).GetProperty("organization").GetProperty("metadata").GetString()!).RootElement;
        Assert.False(after.TryGetProperty("brandLogoAsset", out _));
        Assert.True(after.TryGetProperty("brandIconAsset", out _));
    }

    [Fact]
    public async Task Brand_images_that_are_not_what_they_claim_or_the_wrong_shape_are_refused_and_nothing_is_stored()
    {
        var w = await Workspace.CreateAsync(_factory);
        var good = OrgAdminHelpers.Png(256, 64);
        async Task<(HttpStatusCode, string)> Try(string field, byte[] bytes, string type)
        {
            var r = await w.UploadAsync(w.Owner, (field, bytes, type));
            return (r.StatusCode, (await ReadJsonAsync(r)).GetProperty("reason").GetString()!);
        }
        Assert.Equal((HttpStatusCode.BadRequest, "unsupported-format"), await Try("logo", good, "image/gif"));
        Assert.Equal((HttpStatusCode.BadRequest, "unsupported-format"), await Try("logo", good, "image/svg+xml"));
        Assert.Equal((HttpStatusCode.BadRequest, "empty"), await Try("logo", [], "image/png"));
        Assert.Equal((HttpStatusCode.BadRequest, "type-mismatch"), await Try("logo", good, "image/jpeg"));
        Assert.Equal((HttpStatusCode.BadRequest, "invalid-image"), await Try("logo", Encoding.ASCII.GetBytes("<script>alert(1)</script>"), "image/png"));
        Assert.Equal((HttpStatusCode.BadRequest, "invalid-image"), await Try("logo", [.. good, .. Encoding.ASCII.GetBytes("<script>")], "image/png"));   // trailing data after IEND
        Assert.Equal((HttpStatusCode.BadRequest, "invalid-image"), await Try("logo", good[..40], "image/png"));                                          // truncated
        Assert.Equal((HttpStatusCode.BadRequest, "too-small"), await Try("logo", OrgAdminHelpers.Png(100, 30), "image/png"));
        Assert.Equal((HttpStatusCode.BadRequest, "invalid-aspect"), await Try("logo", OrgAdminHelpers.Png(200, 200), "image/png"));
        Assert.Equal((HttpStatusCode.BadRequest, "too-small"), await Try("icon", OrgAdminHelpers.Png(32, 32), "image/png"));
        Assert.Equal((HttpStatusCode.BadRequest, "invalid-aspect"), await Try("icon", good, "image/png"));
        Assert.Equal((HttpStatusCode.BadRequest, "too-large-dimensions"), await Try("icon", OrgAdminHelpers.Png(5000, 5000), "image/png"));
        var oversized = new byte[2 * 1024 * 1024 + 1];
        good.CopyTo(oversized, 0);
        Assert.Equal((HttpStatusCode.BadRequest, "too-large"), await Try("logo", oversized, "image/png"));
        var none = await w.UploadAsync(w.Owner);
        Assert.Equal("missing-file", (await ReadJsonAsync(none)).GetProperty("reason").GetString());
        var notForm = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/org/brand-assets", new { });
        Assert.Equal("invalid-request", notForm.Body.GetProperty("reason").GetString());
        Assert.Equal(0, _factory.WithDb(db => db.Set<BrandAsset>().Count(a => a.OrganizationId == w.OrgId)));
        Assert.DoesNotContain("brandLogoUrl", (await w.OrgAsync()).GetProperty("organization").GetProperty("metadata").GetString());
    }

    // ----- deleting a workspace ---------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Deleting_a_workspace_is_the_owners_alone_and_removes_everything_scoped_to_it()
    {
        var w = await Workspace.CreateAsync(_factory, "Doomed");
        var bystander = await Workspace.CreateAsync(_factory, "Bystander");
        var member = await w.AddAsync();
        var admin = await w.AddAsync("admin");
        var (_, key) = await w.MakeKeyAsync();
        var (_, bystanderKey) = await bystander.MakeKeyAsync();
        var teamId = await w.TeamAsync("Doomed Team", member);
        await w.RoleAsync(teamId, "teams.view");
        await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/org/web-origins", new { origin = "https://doomed.example.com" });
        await w.UploadAsync(w.Owner, ("logo", OrgAdminHelpers.Png(256, 64), "image/png"));
        await w.CallAsync(w.Owner, HttpMethod.Patch, "/v1/org", new { brandAppName = "Doomed Co" });
        await bystander.TeamAsync("Bystander Team");
        await bystander.CallAsync(bystander.Owner, HttpMethod.Post, "/v1/org/web-origins", new { origin = "https://bystander.example.com" });

        Assert.Equal("forbidden", (await w.CallAsync(admin, HttpMethod.Delete, "/v1/org")).Error());
        Assert.Equal("forbidden", (await w.CallAsync(member, HttpMethod.Delete, "/v1/org")).Error());
        // An API key cannot delete a workspace, even its owner's.
        Assert.Equal(HttpStatusCode.Forbidden, (await w.WithKeyAsync(key, HttpMethod.Delete, "/v1/org")).Status);
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/org")).Status);

        var deleted = await w.CallAsync(w.Owner, HttpMethod.Delete, "/v1/org");
        Assert.Equal(HttpStatusCode.OK, deleted.Status);
        Assert.True(deleted.Body.GetProperty("ok").GetBoolean());
        Assert.Equal(w.OrgId, deleted.Body.GetProperty("organization").GetProperty("id").GetString());

        _ = _factory.WithDb(db =>
        {
            Assert.False(db.Organizations.Any(o => o.Id == w.OrgId));
            Assert.False(db.Members.Any(m => m.OrganizationId == w.OrgId));
            Assert.False(db.Teams.Any(t => t.OrganizationId == w.OrgId));
            Assert.False(db.PermissionSets.Any(s => s.OrganizationId == w.OrgId));
            Assert.False(db.Invitations.Any(i => i.OrganizationId == w.OrgId));
            Assert.False(db.Set<ApiKey>().Any(k => k.OrganizationId == w.OrgId));
            Assert.False(db.Set<OrganizationWebOrigin>().Any(o => o.OrganizationId == w.OrgId));
            Assert.False(db.Set<BrandAsset>().Any(a => a.OrganizationId == w.OrgId));
            Assert.False(db.Set<OrganizationSettings>().Any(s => s.OrganizationId == w.OrgId));
            Assert.False(db.Set<AuditEvent>().Any(e => e.OrganizationId == w.OrgId));
            Assert.False(db.Set<AuditOperation>().Any(o => o.OrganizationId == w.OrgId));
            Assert.False(db.Set<AuditEventResource>().Any(r => r.OrganizationId == w.OrgId));
            Assert.False(db.Set<AuditPolicy>().Any(p => p.OrganizationId == w.OrgId));
            // The bystander is whole.
            Assert.True(db.Organizations.Any(o => o.Id == bystander.OrgId));
            Assert.True(db.Teams.Any(t => t.OrganizationId == bystander.OrgId));
            Assert.True(db.Set<OrganizationWebOrigin>().Any(o => o.OrganizationId == bystander.OrgId));
            Assert.True(db.Set<AuditEvent>().Any(e => e.OrganizationId == bystander.OrgId));
            return true;
        });
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.WithKeyAsync(key, HttpMethod.Get, "/v1/org")).Status);
        Assert.Equal(HttpStatusCode.OK, (await bystander.WithKeyAsync(bystanderKey, HttpMethod.Get, "/v1/org")).Status);
        // Asking for the deleted workspace by id is not found for anyone who still has a session.
        Assert.Contains((await w.CallAsync(member, HttpMethod.Get, "/v1/org")).Status, new[] { HttpStatusCode.NotFound, HttpStatusCode.Unauthorized });
        // A second delete (a double click) is not an error that leaks anything.
        Assert.Contains((await w.CallAsync(w.Owner, HttpMethod.Delete, "/v1/org")).Status, new[] { HttpStatusCode.NotFound, HttpStatusCode.Unauthorized });
    }

    [Fact]
    public async Task Deleting_needs_a_recent_sign_in()
    {
        var w = await Workspace.CreateAsync(_factory);
        _factory.WithDb(db => db.Sessions.Where(s => s.UserId == w.Owner.UserId).ExecuteUpdate(x => x.SetProperty(s => s.CreatedAt, DateTime.UtcNow.AddHours(-5))));
        var r = await w.CallAsync(w.Owner, HttpMethod.Delete, "/v1/org");
        Assert.Equal(HttpStatusCode.Forbidden, r.Status);
        Assert.Equal("reauth", r.Error());
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/org")).Status);
    }

    // ----- small routes ------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Features_are_public_and_the_org_payload_agrees_with_them()
    {
        var w = await Workspace.CreateAsync(_factory);
        var r = await w.Http.GetAsync("/v1/features");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Contains("max-age=60", r.Headers.CacheControl!.ToString());
        var body = await ReadJsonAsync(r);
        Assert.Equal(1, body.GetProperty("version").GetInt32());
        Assert.Equal("self_hosted", body.GetProperty("deployment").GetString());
        var features = body.GetProperty("features");
        Assert.True(features.GetProperty("engineV2ForceUpgrade").GetBoolean());
        // Things this build cannot serve are reported off, never on.
        Assert.False(features.GetProperty("customConnectorSetup").GetBoolean());
        Assert.True(features.GetProperty("activationChecklist").GetBoolean()); // the reference's default, now that the checklist is built
        var org = (await w.OrgAsync()).GetProperty("features");
        foreach (var property in features.EnumerateObject()) Assert.Equal(property.Value.GetBoolean(), org.GetProperty(property.Name).GetBoolean());
    }

    [Fact]
    public async Task Activity_is_for_admins_and_the_inventory_revision_moves_with_the_workspace()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        var admin = await w.AddAsync("admin");
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(member, HttpMethod.Get, "/v1/org/activity")).Status);
        var a = await w.CallAsync(admin, HttpMethod.Get, "/v1/org/activity");
        Assert.Equal(HttpStatusCode.OK, a.Status);
        Assert.Equal(0, a.Body.GetProperty("activity").GetArrayLength());

        var r1 = (await w.CallAsync(member, HttpMethod.Get, "/v1/org/inventory-revision")).Body.GetProperty("revision").GetString();
        Assert.Equal(r1, (await w.CallAsync(member, HttpMethod.Get, "/v1/org/inventory-revision")).Body.GetProperty("revision").GetString());
        await w.TeamAsync("Changes the revision");
        var r2 = (await w.CallAsync(member, HttpMethod.Get, "/v1/org/inventory-revision")).Body.GetProperty("revision").GetString();
        Assert.NotEqual(r1, r2);
        var other = await Workspace.CreateAsync(_factory);
        Assert.NotEqual(r2, (await other.CallAsync(other.Owner, HttpMethod.Get, "/v1/org/inventory-revision")).Body.GetProperty("revision").GetString());
    }

    [Fact]
    public async Task Feature_usage_reports_are_validated_and_always_acknowledged()
    {
        var w = await Workspace.CreateAsync(_factory);
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/org/feature-usage", new { features = new[] { "mermaidZoom", "unknown" } })).Status);
        foreach (var body in new object[] { new { }, new { features = "x" }, new { features = new object[] { 1 } }, new { features = Enumerable.Repeat("a", 101).ToArray() }, new { features = Array.Empty<string>(), extra = 1 }, new { features = new[] { new string('a', 65) } } })
            Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/org/feature-usage", body)).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.PostAsJsonAsync("/v1/org/feature-usage", new { features = Array.Empty<string>() })).StatusCode);
    }
}

public sealed class AuditNotEntitledTests : IClassFixture<AuditNotEntitledFactory>
{
    private readonly AuditNotEntitledFactory _factory;
    public AuditNotEntitledTests(AuditNotEntitledFactory factory) => _factory = factory;

    [Fact]
    public async Task Without_the_entitlement_nothing_is_recorded_and_capture_cannot_be_turned_on()
    {
        var w = await Workspace.CreateAsync(_factory);
        await w.TeamAsync("Unrecorded");
        var usage = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/audit/usage");
        Assert.False(usage.Body.GetProperty("entitlement").GetProperty("enabled").GetBoolean());
        Assert.Equal("none", usage.Body.GetProperty("entitlement").GetProperty("source").GetString());
        Assert.Equal(JsonValueKind.Null, usage.Body.GetProperty("policy").ValueKind);
        Assert.False(usage.Body.GetProperty("captureEnabled").GetBoolean());
        Assert.Empty(await w.OperationsAsync(w.Owner));
        Assert.Equal(0, _factory.WithDb(db => db.Set<AuditEvent>().Count(e => e.OrganizationId == w.OrgId)));

        var on = await w.CallAsync(w.Owner, HttpMethod.Patch, "/v1/audit/settings", new { captureOn = true, expectedRevision = 0 });
        Assert.Equal(HttpStatusCode.PaymentRequired, on.Status);
        Assert.Equal("enterprise_plan_required", on.Error());
        Assert.Equal("auditLogs", on.Body.GetProperty("feature").GetString());
        Assert.Equal("audit_policy_changed", (await w.CallAsync(w.Owner, HttpMethod.Patch, "/v1/audit/settings", new { captureOn = false, expectedRevision = 1 })).Error());
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Patch, "/v1/audit/settings", new { captureOn = false, expectedRevision = 0 })).Status);
        Assert.False((await w.OrgAsync()).GetProperty("entitlements").GetProperty("auditLogs").GetBoolean());
    }
}

public sealed class AuditHiddenTests : IClassFixture<AuditHiddenFactory>
{
    private readonly AuditHiddenFactory _factory;
    public AuditHiddenTests(AuditHiddenFactory factory) => _factory = factory;

    [Fact]
    public async Task With_visibility_off_every_audit_route_is_403_after_the_permission_check()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        foreach (var path in new[] { "/v1/audit/operations", "/v1/audit/usage", "/v1/audit/event-types", "/v1/audit/export" })
        {
            var r = await w.CallAsync(w.Owner, HttpMethod.Get, path);
            Assert.Equal(HttpStatusCode.Forbidden, r.Status);
            Assert.Equal("audit_visibility_disabled", r.Error());
            // Someone without the permission still hears about the permission, not about the deployment.
            Assert.Equal("audit.view", (await w.CallAsync(member, HttpMethod.Get, path)).Required());
        }
        Assert.Equal("audit_visibility_disabled", (await w.CallAsync(w.Owner, HttpMethod.Patch, "/v1/audit/settings", new { captureOn = false, expectedRevision = 0 })).Error());
        Assert.False((await w.OrgAsync()).GetProperty("capabilities").GetProperty("auditLogs").GetBoolean());
    }
}
