using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace WorkAI360.Web.Tests;

/// <summary>Starts the web host as if the caller's address were <see cref="Caller"/> (the in-memory server has none), with the given trusted proxies.</summary>
public sealed class WebFactory(string caller, params string[] trustedProxies) : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting("environment", "Production");
        // Nothing listens here: a request the origin guard lets through fails at the proxy (502), which is how these tests tell "allowed" from "refused".
        builder.UseSetting("Den:ApiBaseUrl", "http://127.0.0.1:9");
        for (var i = 0; i < trustedProxies.Length; i++) builder.UseSetting($"Den:TrustedProxies:{i}", trustedProxies[i]);
        builder.ConfigureServices(services => services.AddTransient<IStartupFilter>(_ => new CallerAddress(IPAddress.Parse(caller))));
    }

    private sealed class CallerAddress(IPAddress address) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((context, nextMiddleware) => { context.Connection.RemoteIpAddress = address; return nextMiddleware(context); });
            next(app);
        };
    }
}

public sealed class WebHostSecurityTests
{
    [Theory]
    [InlineData(null, "frame-ancestors 'none'")]
    [InlineData("frame-ancestors 'self'", "frame-ancestors 'none'")]
    [InlineData("default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'", "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")]
    [InlineData("default-src 'none'; frame-ancestors 'self'; form-action 'self'", "default-src 'none'; form-action 'self'; frame-ancestors 'none'")]
    public void A_strict_policy_from_the_api_keeps_its_other_directives(string? existing, string expected) =>
        Assert.Equal(expected, WorkAI360.Web.Proxy.WebHostSecurity.WithFrameLock(existing));

    private static HttpRequestMessage Write(string origin, string? proto = null, string? host = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/browser/v1/org") { Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json") };
        request.Headers.Add("Origin", origin);
        if (proto is not null) request.Headers.Add("X-Forwarded-Proto", proto);
        if (host is not null) request.Headers.Add("X-Forwarded-Host", host);
        return request;
    }

    private static async Task<bool> RefusedByOriginGuardAsync(HttpResponseMessage response) =>
        response.StatusCode == HttpStatusCode.Forbidden && (await response.Content.ReadAsStringAsync()).Contains("forbidden_origin");

    // ----- headers -----------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Pages_cannot_be_framed()
    {
        using var factory = new WebFactory("127.0.0.1");
        var response = await factory.CreateClient().GetAsync("/api/health");
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("frame-ancestors 'none'", response.Headers.GetValues("Content-Security-Policy").Single());
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("strict-origin-when-cross-origin", response.Headers.GetValues("Referrer-Policy").Single());
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/mcp/consent")]
    [InlineData("/device")]
    public async Task Blazor_pages_including_the_approval_pages_cannot_be_framed_even_by_the_same_site(string page)
    {
        // The framework sets `frame-ancestors 'self'` and SAMEORIGIN on its own pages; ours must win.
        using var factory = new WebFactory("127.0.0.1");
        var response = await factory.CreateClient().GetAsync(page);
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("frame-ancestors 'none'", response.Headers.GetValues("Content-Security-Policy").Single());
    }

    [Fact]
    public async Task Refusals_are_not_framable_either()
    {
        using var factory = new WebFactory("127.0.0.1");
        var response = await factory.CreateClient().SendAsync(Write("https://evil.example"));
        Assert.True(await RefusedByOriginGuardAsync(response));
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
    }

    [Fact]
    public async Task Hsts_is_sent_over_https_only()
    {
        // The proxy says the visitor used https and it is trusted: the page is https as far as the app knows.
        using var behindProxy = new WebFactory("10.1.2.3", "10.0.0.0/8");
        var secure = new HttpRequestMessage(HttpMethod.Get, "/api/health");
        secure.Headers.Add("X-Forwarded-Proto", "https");
        Assert.Equal("max-age=31536000", (await behindProxy.CreateClient().SendAsync(secure)).Headers.GetValues("Strict-Transport-Security").Single());

        Assert.False((await behindProxy.CreateClient().GetAsync("/api/health")).Headers.Contains("Strict-Transport-Security"));
    }

    // ----- the origin guard behind a TLS-terminating proxy ---------------------------------------------------------------------------

    [Fact]
    public async Task A_browser_write_from_the_sites_https_origin_passes_when_a_trusted_proxy_reports_https()
    {
        using var factory = new WebFactory("10.1.2.3", "10.0.0.0/8");
        var response = await factory.CreateClient().SendAsync(Write("https://app.example", proto: "https", host: "app.example"));
        Assert.False(await RefusedByOriginGuardAsync(response));
    }

    [Fact]
    public async Task The_same_request_is_refused_when_the_caller_is_not_a_trusted_proxy()
    {
        // Anyone can send X-Forwarded-Proto; only the configured proxies are believed.
        using var factory = new WebFactory("203.0.113.5", "10.0.0.0/8");
        var response = await factory.CreateClient().SendAsync(Write("https://app.example", proto: "https", host: "app.example"));
        Assert.True(await RefusedByOriginGuardAsync(response));
    }

    [Fact]
    public async Task A_spoofed_host_sent_alone_is_not_believed_from_an_untrusted_caller()
    {
        // The framework's own middleware would accept X-Forwarded-Host without X-Forwarded-For; the strip in front of it must not.
        using var factory = new WebFactory("203.0.113.5");
        var response = await factory.CreateClient().SendAsync(Write("http://evil.example", host: "evil.example"));
        Assert.True(await RefusedByOriginGuardAsync(response));
    }

    [Fact]
    public async Task A_foreign_origin_is_still_refused_through_a_trusted_proxy()
    {
        using var factory = new WebFactory("10.1.2.3", "10.0.0.0/8");
        var response = await factory.CreateClient().SendAsync(Write("https://evil.example", proto: "https", host: "app.example"));
        Assert.True(await RefusedByOriginGuardAsync(response));
    }

    [Fact]
    public async Task Without_configuration_only_loopback_is_trusted()
    {
        using var loopback = new WebFactory("127.0.0.1");
        Assert.False(await RefusedByOriginGuardAsync(await loopback.CreateClient().SendAsync(Write("https://app.example", proto: "https", host: "app.example"))));

        using var elsewhere = new WebFactory("10.1.2.3");
        Assert.True(await RefusedByOriginGuardAsync(await elsewhere.CreateClient().SendAsync(Write("https://app.example", proto: "https", host: "app.example"))));
    }

    [Fact]
    public void A_malformed_trusted_proxy_stops_the_host_starting()
    {
        using var factory = new WebFactory("127.0.0.1", "not-an-address");
        Assert.Throws<InvalidOperationException>(() => factory.CreateClient());
    }
}
