using System.Net;
using Microsoft.AspNetCore.HttpOverrides;

namespace WorkAI360.Web.Proxy;

/// <summary>
/// Two things every public deployment needs from the web host: to learn the real scheme, host and visitor address from the load balancer in front
/// of it (and from nobody else), and to refuse to be shown inside another site's frame.
/// </summary>
public static class WebHostSecurity
{
    public const string TrustedProxiesKey = "Den:TrustedProxies";

    private static readonly string[] ForwardingHeaders = ["X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Prefix", "Forwarded"];

    /// <summary>
    /// Believes <c>X-Forwarded-*</c> only from the proxies in <c>Den:TrustedProxies</c> (addresses or CIDR ranges such as <c>10.0.0.0/8</c>); with none
    /// configured only loopback is trusted. Without this the web host sees <c>http</c> behind a TLS-terminating proxy, so the same-origin check on
    /// <c>/api/browser/v1/*</c> would refuse every browser write, and every visitor would look like the proxy to the API's per-address limits.
    /// The framework's own middleware only checks the caller when <c>X-Forwarded-For</c> is present, so a spoofed <c>X-Forwarded-Host</c> or
    /// <c>-Proto</c> sent alone would be believed; every forwarding header is therefore stripped from other callers first.
    /// </summary>
    public static void UseTrustedForwardedHeaders(this WebApplication app)
    {
        var addresses = new List<IPAddress>();
        var networks = new List<System.Net.IPNetwork>();
        var configured = app.Configuration.GetSection(TrustedProxiesKey).Get<string[]>() ?? [];
        foreach (var entry in configured.Length > 0 ? configured : ["127.0.0.1", "::1"])
        {
            if (entry.Contains('/') && System.Net.IPNetwork.TryParse(entry, out var network)) networks.Add(network);
            else if (IPAddress.TryParse(entry, out var address)) addresses.Add(address);
            else throw new InvalidOperationException($"{TrustedProxiesKey} has an invalid address or range: {entry}");
        }

        app.Use(async (context, next) =>
        {
            var remote = context.Connection.RemoteIpAddress;
            if (remote is { IsIPv4MappedToIPv6: true }) remote = remote.MapToIPv4();
            if (remote is null || !(addresses.Contains(remote) || networks.Any(n => n.Contains(remote))))
                foreach (var header in ForwardingHeaders) context.Request.Headers.Remove(header);
            await next();
        });

        var options = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost,
            ForwardLimit = 1,
        };
        options.KnownProxies.Clear();
        options.KnownIPNetworks.Clear();
        foreach (var address in addresses) options.KnownProxies.Add(address);
        foreach (var network in networks) options.KnownIPNetworks.Add(network);
        app.UseForwardedHeaders(options);
    }

    /// <summary>
    /// No page of ours may be framed: the consent and device pages approve access, and a hidden frame could trick someone into clicking Allow.
    /// <c>frame-ancestors</c> is the modern control and <c>X-Frame-Options</c> covers old browsers. HSTS is sent only over HTTPS outside
    /// Development (it is ignored over plain HTTP, and a development machine should not pin itself to HTTPS).
    /// </summary>
    public static void UseSecurityHeaders(this WebApplication app)
    {
        var development = app.Environment.IsDevelopment();
        app.Use((context, next) =>
        {
            context.Response.OnStarting(() =>
            {
                var headers = context.Response.Headers;
                // Assigned, not added if missing: the framework's antiforgery middleware sets its own, weaker `frame-ancestors 'self'` on Blazor pages
                // (found by running the host), and nothing of ours is ever meant to be framed, even by ourselves.
                headers["X-Frame-Options"] = "DENY";
                headers["Content-Security-Policy"] = "frame-ancestors 'none'";
                headers.TryAdd("X-Content-Type-Options", "nosniff");
                headers.TryAdd("Referrer-Policy", "strict-origin-when-cross-origin");
                if (!development && context.Request.IsHttps) headers.TryAdd("Strict-Transport-Security", "max-age=31536000");
                return Task.CompletedTask;
            });
            return next(context);
        });
    }
}
