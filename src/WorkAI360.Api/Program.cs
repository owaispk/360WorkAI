using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Email;
using WorkAI360.Api.Endpoints;
using WorkAI360.Api.OAuth;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<AuthOptions>(builder.Configuration.GetSection(AuthOptions.Section));
builder.Services.AddDbContext<DenDbContext>(o =>
    o.UseSqlite(builder.Configuration.GetConnectionString("Default") ?? "Data Source=workai360.db"));
builder.Services.AddScoped<SessionService>();
builder.Services.AddSingleton<LoginThrottle>();
builder.Services.AddHttpContextAccessor();
builder.Services.Configure<EmailOptions>(builder.Configuration.GetSection(EmailOptions.Section));
builder.Services.AddSingleton<RateLimiter>();
builder.Services.AddScoped<EmailVerificationService>();
builder.Services.AddScoped<TrustedUrls>();
var emailProvider = builder.Configuration["Email:Provider"] ?? "dev";
if (emailProvider == "smtp")
{
    if (string.IsNullOrWhiteSpace(builder.Configuration["Email:Smtp:Host"])) throw new InvalidOperationException("Email:Smtp:Host is required when Email:Provider is smtp.");
    builder.Services.AddSingleton<IEmailSender, SmtpEmailSender>();
}
else if (emailProvider == "dev")
{
    // The dev provider keeps codes and links in memory. It must never run outside Development, where nothing would reach people.
    if (!builder.Environment.IsDevelopment()) throw new InvalidOperationException("Email:Provider must be smtp outside Development.");
    builder.Services.AddSingleton<DevOutbox>();
    builder.Services.AddSingleton<IEmailSender>(sp => sp.GetRequiredService<DevOutbox>());
}
else throw new InvalidOperationException($"Unknown Email:Provider '{emailProvider}' (use dev or smtp).");
builder.Services.AddSingleton<SigningKeyStore>();
builder.Services.AddSingleton<SignedQuery>();
builder.Services.AddScoped<OAuthUrls>();
builder.Services.AddScoped<TokenService>();
builder.Services.AddScoped<McpAuthenticator>();

var app = builder.Build();

// Believe X-Forwarded-* only from the configured proxies (the web host), so the client address and origin cannot be spoofed.
// The framework's middleware only checks the caller against its proxy list when X-Forwarded-For is present, so a spoofed
// X-Forwarded-Host sent alone would slip through. This strips every forwarding header from callers that are not trusted proxies first.
var trustedProxies = new List<System.Net.IPAddress>();
var configuredProxies = app.Services.GetRequiredService<IOptions<AuthOptions>>().Value.TrustedProxies;
foreach (var proxy in configuredProxies.Length > 0 ? configuredProxies : [AuthOptions.LoopbackV4, AuthOptions.LoopbackV6])
{
    if (!System.Net.IPAddress.TryParse(proxy, out var ip)) throw new InvalidOperationException($"Auth:TrustedProxies has an invalid address: {proxy}");
    trustedProxies.Add(ip);
}
app.Use(async (context, next) =>
{
    var remote = context.Connection.RemoteIpAddress;
    if (remote is { IsIPv4MappedToIPv6: true }) remote = remote.MapToIPv4();
    if (remote is null || !trustedProxies.Contains(remote))
    {
        foreach (var header in new[] { "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Prefix", "Forwarded" })
            context.Request.Headers.Remove(header);
    }
    await next();
});
var forwarded = new ForwardedHeadersOptions { ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost, ForwardLimit = 1 };
forwarded.KnownProxies.Clear();
forwarded.KnownIPNetworks.Clear();
foreach (var proxy in trustedProxies) forwarded.KnownProxies.Add(proxy);
app.UseForwardedHeaders(forwarded);

var secret = app.Configuration[$"{AuthOptions.Section}:Secret"];
if (string.IsNullOrWhiteSpace(secret) || secret.Length < 32)
    throw new InvalidOperationException("Auth:Secret must be set to at least 32 characters (environment variable Auth__Secret).");

using (var scope = app.Services.CreateScope())
{
    // Development convenience: create the schema on first start. Real deployments will use migrations.
    DevSchema.Ensure(scope.ServiceProvider.GetRequiredService<DenDbContext>());
}

app.MapMiscEndpoints();
app.MapAuthEndpoints();
app.MapDeviceEndpoints();
app.MapOrgEndpoints();
app.MapHandoffEndpoints();
app.MapEmailAuthEndpoints();
app.MapOAuthEndpoints();
app.MapMcpEndpoints();

if (app.Environment.IsDevelopment() && emailProvider == "dev")
{
    // Development only: lets tests and local runs read the codes and links that would have been emailed.
    app.MapGet("/dev/outbox", (string? to, DevOutbox outbox) =>
        Results.Json(outbox.To(to).Select(m => new { at = m.At, to = m.Message.To, subject = m.Message.Subject, text = m.Message.Text })));
    app.MapDelete("/dev/outbox", (DevOutbox outbox) => { outbox.Clear(); return Results.NoContent(); });
}

app.Run();

public partial class Program;
