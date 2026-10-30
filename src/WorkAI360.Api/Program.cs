using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Endpoints;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<AuthOptions>(builder.Configuration.GetSection(AuthOptions.Section));
builder.Services.AddDbContext<DenDbContext>(o =>
    o.UseSqlite(builder.Configuration.GetConnectionString("Default") ?? "Data Source=workai360.db"));
builder.Services.AddScoped<SessionService>();
builder.Services.AddSingleton<LoginThrottle>();

var app = builder.Build();

var secret = app.Configuration[$"{AuthOptions.Section}:Secret"];
if (string.IsNullOrWhiteSpace(secret) || secret.Length < 32)
    throw new InvalidOperationException("Auth:Secret must be set to at least 32 characters (environment variable Auth__Secret).");

using (var scope = app.Services.CreateScope())
{
    // Development convenience: create the schema on first start. Real deployments will use migrations.
    scope.ServiceProvider.GetRequiredService<DenDbContext>().Database.EnsureCreated();
}

app.MapMiscEndpoints();
app.MapAuthEndpoints();
app.MapDeviceEndpoints();
app.MapOrgEndpoints();
app.MapHandoffEndpoints();

app.Run();

public partial class Program;
