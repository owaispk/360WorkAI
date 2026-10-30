using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Endpoints;
using WorkAI360.Api.OAuth;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<AuthOptions>(builder.Configuration.GetSection(AuthOptions.Section));
builder.Services.AddDbContext<DenDbContext>(o =>
    o.UseSqlite(builder.Configuration.GetConnectionString("Default") ?? "Data Source=workai360.db"));
builder.Services.AddScoped<SessionService>();
builder.Services.AddSingleton<LoginThrottle>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddSingleton<SigningKeyStore>();
builder.Services.AddSingleton<SignedQuery>();
builder.Services.AddScoped<OAuthUrls>();
builder.Services.AddScoped<TokenService>();
builder.Services.AddScoped<McpAuthenticator>();

var app = builder.Build();

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
app.MapOAuthEndpoints();
app.MapMcpEndpoints();

app.Run();

public partial class Program;
