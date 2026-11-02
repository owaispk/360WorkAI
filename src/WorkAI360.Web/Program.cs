using Microsoft.AspNetCore.Components;
using WorkAI360.Web.Components;
using WorkAI360.Web.Proxy;

var builder = WebApplication.CreateBuilder(args);

// The browser hands API answers back to the circuit; the platform admin feature list is about 45 KB, over the 32 KB default.
builder.Services.AddRazorComponents().AddInteractiveServerComponents().AddHubOptions(options => options.MaximumReceiveMessageSize = 1024 * 1024);
builder.Services.AddScoped<WorkAI360.Web.Services.DenClient>();
builder.Services.AddDenReverseProxy(builder.Configuration);

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
}

app.UseMiddleware<BrowserOriginGuard>();
app.UseStaticFiles();
app.UseAntiforgery();

app.MapDenLocalEndpoints();
app.MapStaticAssets();
app.MapReverseProxy();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();

app.Run();

public partial class Program;
