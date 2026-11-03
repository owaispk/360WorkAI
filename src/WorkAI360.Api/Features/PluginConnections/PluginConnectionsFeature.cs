using WorkAI360.Api.Auth;
using WorkAI360.Api.Features.Library;

namespace WorkAI360.Api.Features.PluginConnections;

/// <summary>
/// Plugins that need MCP connections: which connection serves each server a plugin declares, who may use a connection through a plugin,
/// and whether a plugin is ready for the person asking. See docs/features/gaps.md.
/// </summary>
public sealed class PluginConnectionsFeature : IFeature
{
    public void AddServices(IServiceCollection services, IConfiguration configuration)
    {
        services.AddScoped<PluginBindingStore>();
        services.AddScoped<PluginReadiness>();
        services.AddScoped<PluginConnectionService>();
    }

    public void MapEndpoints(WebApplication app)
    {
        // Sets up (or reuses) the connection for one server a plugin declares. The desktop app calls this to save a key a person typed in chat.
        app.MapPost("/v1/plugins/{pluginId}/mcp-connections", (string pluginId, HttpContext ctx, LibraryRunner run, PluginConnectionService service, OrgAccess access) => run.RunAsync(ctx, async a =>
        {
            Zod.TypeId(pluginId, "plg", "pluginId");
            var body = await Zod.BodyAsync(ctx);
            var setup = McpSetup.Parse(body, "");
            var configObjectId = Zod.Id(body, "configObjectId", "cob");
            var serverName = Zod.Str(body, "serverName", max: 255)!;
            if (access.Require(a.Context, "connections.manage") is { } denied) return denied;
            if (a.Context.ApiKeyId is not null && setup.ApiKey is not null)
                return Results.Json(new { error = "secure_entry_required", message = "Do not send keys through the agent or an API key. Leave the key out; the person adds it in a private field in OpenWork." }, statusCode: 400);
            var configured = await service.ConfigureAsync(a, pluginId, configObjectId, serverName, setup, awaitKey: true, ctx.RequestAborted);
            ctx.Response.Headers.CacheControl = "no-store";
            var item = service.ConfiguredJson(configured, a.OrgId);
            return configured.AwaitingKey
                ? Results.Json(Merge(new Dictionary<string, object?> { ["ok"] = true, ["item"] = item }, service.CredentialPromptFields(configured)))
                : Results.Json(new { ok = true, item });
        }));

        // Not in the reference: what a plugin needs and which connections the caller may know of for each declared server.
        app.MapGet("/v1/plugins/{pluginId}/mcp-connections", (string pluginId, HttpContext ctx, LibraryRunner run, PluginConnectionService service) => run.RunAsync(ctx, async a =>
        {
            Zod.TypeId(pluginId, "plg", "pluginId");
            return Results.Json(new { requirements = await service.RequirementsAsync(a, pluginId) });
        }));
    }

    private static Dictionary<string, object?> Merge(Dictionary<string, object?> target, object extra)
    {
        foreach (var p in extra.GetType().GetProperties()) target[p.Name] = p.GetValue(extra);
        return target;
    }
}
