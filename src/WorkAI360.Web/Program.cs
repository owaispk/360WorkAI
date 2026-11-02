using Microsoft.AspNetCore.Components;
using WorkAI360.Web.Components;
using WorkAI360.Web.Proxy;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddScoped<WorkAI360.Web.Services.DenClient>();
builder.Services.AddDenReverseProxy(builder.Configuration);

var app = builder.Build();

// First: everything after this (the origin guard, links, the proxy to the API) sees the real scheme, host and visitor address.
app.UseTrustedForwardedHeaders();
app.UseSecurityHeaders();

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
