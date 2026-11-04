using System.Net;
using System.Net.Http.Json;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>
/// GET /v1/org/service-readiness: the member-safe projection of the operator's cached service readiness. A fresh factory per class, so the
/// snapshot starts empty.
/// </summary>
public sealed class ServiceReadinessTests(PlatformAdminFactory factory) : IClassFixture<PlatformAdminFactory>
{
    private async Task<string> AdminTokenAsync()
    {
        var http = factory.Plain();
        var signIn = await http.PostAsJsonAsync("/api/auth/sign-in/email", new { email = PlatformAdminFactory.BootstrapEmail, password = Password });
        if (signIn.IsSuccessStatusCode) return (await ReadJsonAsync(signIn)).GetProperty("token").GetString()!;
        var signUp = await http.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Boot Admin", email = PlatformAdminFactory.BootstrapEmail, password = Password });
        signUp.EnsureSuccessStatusCode();
        return (await ReadJsonAsync(signUp)).GetProperty("token").GetString()!;
    }

    [Fact]
    public async Task Members_read_only_the_cached_member_safe_facts_and_503_before_any_check()
    {
        var w = await Workspace.CreateAsync(factory);
        var member = await w.AddAsync();

        // Not signed in, or not a member of the named workspace: the usual answers.
        Assert.Equal(HttpStatusCode.Unauthorized, (await factory.Plain().GetAsync("/v1/org/service-readiness")).StatusCode);
        var other = await Workspace.CreateAsync(factory, "Other Space");
        var foreign = w.As(member, HttpMethod.Get, "/v1/org/service-readiness");
        foreign.Headers.Remove("x-openwork-org-id");
        foreign.Headers.Add("x-openwork-org-id", other.OrgId);
        Assert.Equal(HttpStatusCode.NotFound, (await w.SendAsync(foreign)).StatusCode);

        // No check has run: 503 with no detail, and reading does not start one.
        var none = await w.Http.SendAsync(w.As(member, HttpMethod.Get, "/v1/org/service-readiness"));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, none.StatusCode);
        Assert.Equal("no-store", none.Headers.CacheControl?.ToString());
        var noneBody = await ReadJsonAsync(none);
        Assert.Equal(["error"], noneBody.EnumerateObject().Select(p => p.Name).ToArray());
        Assert.Equal("service_readiness_unavailable", Workspace.Error(noneBody));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await w.CallAsync(member, HttpMethod.Get, "/v1/org/service-readiness")).Status);

        // The operator's page runs the check; members then see the projection of that same snapshot.
        var admin = await factory.Plain().SendAsync(Bearer(HttpMethod.Get, "/v1/admin/services", await AdminTokenAsync()));
        Assert.Equal(HttpStatusCode.OK, admin.StatusCode);
        var adminBody = await ReadJsonAsync(admin);

        var r = await w.Http.SendAsync(w.As(member, HttpMethod.Get, "/v1/org/service-readiness"));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Equal("no-store", r.Headers.CacheControl?.ToString());
        var body = await ReadJsonAsync(r);
        Assert.Equal(["version", "checkedAt", "checking", "services"], body.EnumerateObject().Select(p => p.Name).ToArray());   // no server facts
        Assert.Equal(2, body.GetProperty("version").GetInt32());
        Assert.Equal(adminBody.GetProperty("checkedAt").GetString(), body.GetProperty("checkedAt").GetString());
        var services = body.GetProperty("services").EnumerateArray().ToList();
        Assert.Equal(["database", "gateway", "headlessRunner", "workbot", "email"], services.Select(s => s.GetProperty("id").GetString()!).ToArray());
        // Withheld: required, missingSettings, notes, durationMs.
        Assert.All(services, s => Assert.Equal(["id", "configured", "state", "reason", "dependencies", "checkedAt", "lastSuccessAt", "stale"], s.EnumerateObject().Select(p => p.Name).ToArray()));
        Assert.Equal("ready", services[0].GetProperty("state").GetString());
        Assert.Equal("database_verified", services[0].GetProperty("reason").GetString());
    }
}
