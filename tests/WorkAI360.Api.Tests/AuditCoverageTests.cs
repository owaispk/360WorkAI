using System.Net;
using System.Text.Json;
using WorkAI360.Api.Domain.OrgAdmin;
using WorkAI360.Api.Features.OrgAdmin;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>Audit events for areas built after the audit log: request evidence for change routes, and named change events with snapshots.</summary>
public sealed class AuditCoverageTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private List<JsonElement> Events(string orgId, string? action = null) => factory.WithDb(db => db.Set<AuditEvent>()
        .Where(e => e.OrganizationId == orgId && (action == null || e.Action == action)).OrderBy(e => e.RecordedAt).Select(e => e.EnvelopeJson).ToList())
        .Select(j => JsonDocument.Parse(j).RootElement.Clone()).ToList();

    private static string Resource(JsonElement e, string type) =>
        e.GetProperty("resources").EnumerateArray().First(r => r.GetProperty("type").GetString() == type).GetProperty("id").GetString()!;

    [Fact]
    public async Task A_change_route_records_its_reference_action_with_the_target_and_a_refusal_is_a_denied_attempt()
    {
        var w = await Workspace.CreateAsync(factory);
        var member = await w.AddAsync();
        var created = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/desktop-policies", new { policyName = "Lockdown", policy = new { } });
        Assert.Equal(HttpStatusCode.Created, created.Status);
        var id = created.Body.GetProperty("desktopPolicy").GetProperty("id").GetString()!;

        var create = Assert.Single(Events(w.OrgId, "desktop_policy.create.succeeded"));
        Assert.Equal("request", create.GetProperty("category").GetString());
        Assert.Equal("succeeded", create.GetProperty("outcome").GetString());
        Assert.Equal(w.Owner.UserId, create.GetProperty("actor").GetProperty("id").GetString());
        Assert.Equal(w.OrgId, Resource(create, "organization"));
        Assert.Equal("POST", create.GetProperty("http").GetProperty("method").GetString());

        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/desktop-policies/{id}", new { policyName = "Lockdown 2", policy = new { } })).Status);
        // The target is the policy named in the path.
        Assert.Equal(id, Resource(Assert.Single(Events(w.OrgId, "desktop_policy.update.succeeded")), "desktop_policy"));

        // A member without the permission is refused: a denied attempt in the security category, with no change recorded.
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(member, HttpMethod.Post, "/v1/desktop-policies", new { policyName = "Mine", policy = new { } })).Status);
        var denied = Assert.Single(Events(w.OrgId, "desktop_policy.create.attempted"));
        Assert.Equal("denied", denied.GetProperty("outcome").GetString());
        Assert.Equal("security", denied.GetProperty("category").GetString());
        Assert.Equal("request_denied", denied.GetProperty("reasonCode").GetString());
        Assert.Equal(member.UserId, denied.GetProperty("actor").GetProperty("id").GetString());

        // Validation failures are failed attempts.
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/desktop-policies", new { policyName = " ", policy = new { } })).Status);
        Assert.Contains(Events(w.OrgId, "desktop_policy.create.attempted"), e => e.GetProperty("reasonCode").GetString() == "validation_failed");

        // Reads record nothing.
        await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/desktop-policies");
        Assert.DoesNotContain(Events(w.OrgId), e => e.GetProperty("action").GetString()!.StartsWith("desktop_policy.list", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Model_provider_changes_are_recorded_without_the_key_and_in_the_right_workspace_only()
    {
        var w = await Workspace.CreateAsync(factory);
        var other = await Workspace.CreateAsync(factory, "Other Space");
        var r = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/llm-providers",
            new { name = "Team OpenAI", source = "models_dev", providerId = "openai", modelIds = new[] { "gpt-4o" }, apiKey = "sk-very-secret-value-123", allMembers = true });
        Assert.True(r.Status is HttpStatusCode.Created or HttpStatusCode.OK, r.Body.ToString());
        var e = Assert.Single(Events(w.OrgId, "llm_provider.create.succeeded"));
        Assert.DoesNotContain("sk-very-secret-value-123", e.GetRawText());
        Assert.Empty(Events(other.OrgId, "llm_provider.create.succeeded"));
    }

    [Fact]
    public async Task A_route_that_records_its_own_change_events_is_not_recorded_twice()
    {
        var w = await Workspace.CreateAsync(factory);
        Assert.True((await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/api-keys", new { name = "ci" })).Status is HttpStatusCode.Created or HttpStatusCode.OK);
        Assert.Single(Events(w.OrgId, AuditActions.ApiKeyCreated));
        Assert.DoesNotContain(Events(w.OrgId), e => e.GetProperty("action").GetString()!.StartsWith("api_key.create.", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Agent_permission_changes_are_snapshots_and_removal_says_so()
    {
        var w = await Workspace.CreateAsync(factory);
        var put = await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/agent-permissions/everyone", new { settings = new { webSearch = new { decision = "deny" } } });
        Assert.Equal(HttpStatusCode.OK, put.Status);
        var updated = Assert.Single(Events(w.OrgId, DomainAuditEvents.AgentPermissionPolicyUpdated));
        Assert.Equal(JsonValueKind.Null, updated.GetProperty("changes").GetProperty("before").ValueKind);
        Assert.Equal("deny", updated.GetProperty("changes").GetProperty("after").GetProperty("settings").GetProperty("webSearch").GetProperty("decision").GetString());
        // The same settings again change nothing and record nothing.
        await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/agent-permissions/everyone", new { settings = new { webSearch = new { decision = "deny" } } });
        Assert.Single(Events(w.OrgId, DomainAuditEvents.AgentPermissionPolicyUpdated));
        // Clearing every setting removes the policy.
        await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/agent-permissions/everyone", new { settings = new { } });
        var removed = Assert.Single(Events(w.OrgId, DomainAuditEvents.AgentPermissionPolicyRemoved));
        Assert.Equal(JsonValueKind.Null, removed.GetProperty("changes").GetProperty("after").ValueKind);
    }

    [Fact]
    public async Task A_profile_change_is_recorded_in_every_workspace_of_the_person()
    {
        var a = await Workspace.CreateAsync(factory, "Alpha");
        var b = await Workspace.CreateAsync(factory, "Beta");
        var person = await a.AddAsync();
        var invitation = await b.InviteAsync(person.Email);
        await b.Http.SendAsync(Bearer(HttpMethod.Post, "/v1/orgs/invitations/accept", person.Token, new { id = invitation.GetProperty("invitationId").GetString() }));

        var r = await a.Http.SendAsync(Bearer(HttpMethod.Patch, "/v1/me/profile", person.Token, new { firstName = "Renamed", lastName = "Person" }));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        foreach (var org in new[] { a.OrgId, b.OrgId })
        {
            var e = Assert.Single(Events(org, DomainAuditEvents.ProfileUpdated));
            Assert.Equal("Renamed Person", e.GetProperty("changes").GetProperty("after").GetProperty("name").GetString());
            Assert.Equal(person.UserId, Resource(e, "user"));
        }
        // The same name again records nothing.
        await a.Http.SendAsync(Bearer(HttpMethod.Patch, "/v1/me/profile", person.Token, new { firstName = "Renamed", lastName = "Person" }));
        Assert.Single(Events(a.OrgId, DomainAuditEvents.ProfileUpdated));
    }

    [Fact]
    public async Task The_event_type_catalog_lists_the_new_actions()
    {
        var w = await Workspace.CreateAsync(factory);
        var r = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/audit/event-types");
        var types = r.Body.GetProperty("eventTypes").EnumerateArray().Select(t => t.GetString()).ToList();
        foreach (var expected in new[] { "desktop_policy.create.succeeded", "desktop_policy.create.attempted", "llm_provider.create.succeeded", "mcp_connection.create.succeeded",
                     DomainAuditEvents.SsoRegistered, DomainAuditEvents.ScimTokenRotated, DomainAuditEvents.ProfileUpdated, AuditActions.ApiKeyCreated })
            Assert.Contains(expected, types);
        // Routes left to areas with their own run history are not listed.
        foreach (var owned in new[] { "automation.create.succeeded", "automation.update.succeeded", "workflow.run.confirmed", "workflow.version.create.succeeded" })
            Assert.DoesNotContain(owned, types);
        Assert.Equal(types.Order(StringComparer.Ordinal).ToList(), types);
    }

    [Theory]
    [InlineData("tenant_change", 201, "succeeded", "succeeded", null)]
    [InlineData("tenant_external", 200, "confirmed", "succeeded", null)]
    [InlineData("tenant_change", 403, "attempted", "denied", "request_denied")]
    [InlineData("tenant_change", 404, "attempted", "failed", "resource_not_found")]
    [InlineData("tenant_change", 409, "attempted", "failed", "request_conflict")]
    [InlineData("tenant_change", 422, "attempted", "failed", "validation_failed")]
    [InlineData("tenant_change", 429, "attempted", "failed", "request_rejected")]
    [InlineData("tenant_change", 500, "attempted", "failed", "request_failed")]
    [InlineData("tenant_external", 502, "unknown", "unknown", "external_outcome_unknown")]
    public void Outcomes_map_like_the_reference(string cls, int status, string suffix, string outcome, string? reason)
    {
        var (s, o, r, _) = AuditRoutes.Outcome(cls, status);
        Assert.Equal((suffix, outcome, reason), (s, o, r));
    }

    [Fact]
    public void Paths_match_by_shape_and_the_id_parameter_is_found_by_position()
    {
        var route = AuditRoutes.Find("PATCH", "/v1/desktop-policies/{policy}");
        Assert.NotNull(route);
        Assert.Equal("desktop_policy.update", route!.Declaration.Action);
        Assert.Equal("policy", route.IdParam);
        Assert.Null(AuditRoutes.Find("GET", "/v1/desktop-policies/{id}"));
        Assert.Null(AuditRoutes.Find("POST", "/v1/automations"));
    }
}

/// <summary>SSO and SCIM change events against a fake identity provider: snapshots never carry secrets.</summary>
public sealed class SsoAuditTests(SsoFactory factory) : IClassFixture<SsoFactory>, IAsyncLifetime
{
    private FakeIdp _idp = null!;
    private SsoWorld W = null!;

    public async Task InitializeAsync()
    {
        _idp = await FakeIdp.StartAsync();
        W = await SsoWorld.CreateAsync(factory, _idp, factory.Dns);
    }

    public async Task DisposeAsync() => await _idp.DisposeAsync();

    private List<string> Events(string action) => factory.WithDb(db => db.Set<AuditEvent>()
        .Where(e => e.OrganizationId == W.OrgId && e.Action == action).OrderBy(e => e.RecordedAt).Select(e => e.EnvelopeJson).ToList());

    [Fact]
    public async Task Registering_re_registering_and_deleting_record_snapshots_without_the_client_secret()
    {
        Assert.Equal(HttpStatusCode.Created, (await W.RegisterAsync(clientSecret: "first-very-secret-value")).Status);
        var first = Assert.Single(Events(DomainAuditEvents.SsoRegistered));
        Assert.DoesNotContain("first-very-secret-value", first);
        var envelope = JsonDocument.Parse(first).RootElement;
        Assert.Equal(JsonValueKind.Null, envelope.GetProperty("changes").GetProperty("before").ValueKind);
        Assert.Equal("disabled", envelope.GetProperty("changes").GetProperty("after").GetProperty("status").GetString());

        Assert.Equal(HttpStatusCode.Created, (await W.RegisterAsync(clientSecret: "second-very-secret-value")).Status);
        var second = Events(DomainAuditEvents.SsoRegistered)[1];
        Assert.DoesNotContain("second-very-secret-value", second);
        // A replaced configuration is the opaque marker, never its content.
        Assert.Contains("configuration", JsonDocument.Parse(second).RootElement.GetProperty("changes").GetProperty("changedFields").EnumerateArray().Select(f => f.GetString()));

        Assert.Equal(HttpStatusCode.NoContent, (await W.Owner(HttpMethod.Delete, "/v1/sso")).Status);
        var deleted = JsonDocument.Parse(Assert.Single(Events(DomainAuditEvents.SsoDeleted))).RootElement;
        Assert.Equal(JsonValueKind.Null, deleted.GetProperty("changes").GetProperty("after").ValueKind);
        // Deleting when there is nothing records nothing.
        await W.Owner(HttpMethod.Delete, "/v1/sso");
        Assert.Single(Events(DomainAuditEvents.SsoDeleted));
    }
}

/// <summary>SCIM: the connection's changes are snapshots without the token; provisioning is recorded in the token's workspace, acted by the connection.</summary>
public sealed class ScimAuditTests(SsoFactory factory) : ScimBase(factory)
{
    private List<JsonElement> Events(string action) => Factory.WithDb(db => db.Set<AuditEvent>()
        .Where(e => e.OrganizationId == W.OrgId && e.Action == action).OrderBy(e => e.RecordedAt).Select(e => e.EnvelopeJson).ToList())
        .Select(j => JsonDocument.Parse(j).RootElement.Clone()).ToList();

    [Fact]
    public async Task Token_rotation_mapping_reconcile_delete_and_provisioning_are_recorded()
    {
        var created = Assert.Single(Events(DomainAuditEvents.ScimTokenRotated));
        Assert.DoesNotContain(Token, created.GetRawText());
        Assert.Contains("credentialMaterial", created.GetProperty("changes").GetProperty("changedFields").EnumerateArray().Select(f => f.GetString()));

        Assert.Equal(HttpStatusCode.OK, (await W.Owner(HttpMethod.Patch, "/v1/scim", new { groupMappingMode = "create_teams" })).Status);
        var mapping = Assert.Single(Events(DomainAuditEvents.ScimGroupMappingUpdated));
        Assert.Equal("create_teams", mapping.GetProperty("changes").GetProperty("after").GetProperty("groupMappingMode").GetString());
        await W.Owner(HttpMethod.Patch, "/v1/scim", new { groupMappingMode = "create_teams" });
        Assert.Single(Events(DomainAuditEvents.ScimGroupMappingUpdated));

        var userId = await CreateUserAsync("gina");
        var provisioned = Assert.Single(Events("scim_user.create.succeeded"));
        Assert.Equal("service", provisioned.GetProperty("actor").GetProperty("type").GetString());
        Assert.StartsWith("scim:", provisioned.GetProperty("actor").GetProperty("id").GetString());
        Assert.Equal(HttpStatusCode.NoContent, (await Scim(HttpMethod.Delete, $"/Users/{userId}")).Status);
        Assert.Single(Events("scim_user.deprovision.confirmed"));
        // A bad token proves no workspace: nothing is recorded anywhere for it.
        await ScimAs("not-a-token", HttpMethod.Post, "/Users", new { });
        Assert.Single(Events("scim_user.create.succeeded"));

        Assert.Equal(HttpStatusCode.OK, (await W.Owner(HttpMethod.Post, "/v1/scim/reconcile", new { })).Status);
        Assert.Equal("execution", Assert.Single(Events(DomainAuditEvents.ScimReconciled)).GetProperty("category").GetString());

        Assert.Equal(HttpStatusCode.NoContent, (await W.Owner(HttpMethod.Delete, "/v1/scim")).Status);
        Assert.Single(Events(DomainAuditEvents.ScimDeleted));
    }
}
