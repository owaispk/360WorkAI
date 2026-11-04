using System.Net;

namespace WorkAI360.Api.Tests;

/// <summary>GET /v1/orgs/sso/singleton answers as the reference does when single-organization mode is off (this build has no such mode).</summary>
public sealed class SingletonSsoStatusTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    [Fact]
    public async Task It_is_public_and_never_configured()
    {
        var w = await Workspace.CreateAsync(factory, "default");
        var r = await factory.Plain().GetAsync("/v1/orgs/sso/singleton");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var body = await ApiFactory.ReadJsonAsync(r);
        Assert.Equal(["configured", "organizationSlug", "signInPath", "signInUrl"], body.EnumerateObject().Select(p => p.Name).ToArray());
        Assert.False(body.GetProperty("configured").GetBoolean());
        Assert.Equal("default", body.GetProperty("organizationSlug").GetString());
        Assert.Equal("/sso/default", body.GetProperty("signInPath").GetString());
        Assert.EndsWith("/sso/default", body.GetProperty("signInUrl").GetString());
        Assert.True(Uri.IsWellFormedUriString(body.GetProperty("signInUrl").GetString(), UriKind.Absolute));
        // A signed-in caller gets the same answer: nothing about any workspace is disclosed.
        Assert.Equal(body.ToString(), (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/orgs/sso/singleton")).Body.ToString());
    }
}
