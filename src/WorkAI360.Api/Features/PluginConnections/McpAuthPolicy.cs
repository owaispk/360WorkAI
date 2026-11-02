using System.Text.Json.Nodes;
using WorkAI360.Api.Features.Connections;

namespace WorkAI360.Api.Features.PluginConnections;

/// <summary>Which sign-in a declared MCP server needs (the reference's external-mcp-auth-policy).</summary>
public static class McpAuthPolicy
{
    private static string? Normalized(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)) return null;
        var path = uri.AbsolutePath.Length > 1 ? uri.AbsolutePath.TrimEnd('/') : uri.AbsolutePath;
        return uri.GetLeftPart(UriPartial.Authority).ToLowerInvariant() + path;
    }

    public static McpPreset? PresetFor(string url)
    {
        var n = Normalized(url);
        return n is null ? null : McpPresets.All.FirstOrDefault(p => Normalized(p.Url) == n);
    }

    /// <summary>"oauth" when the declaration says <c>oauth</c> (anything but null or false), else null.</summary>
    public static string? Declared(JsonObject? config)
    {
        var oauth = config?["oauth"];
        return oauth is null || oauth is JsonValue v && v.TryGetValue<bool>(out var b) && !b ? null : "oauth";
    }

    public static string? Required(string? declared, string url)
    {
        if (declared is not null) return declared;
        var preset = PresetFor(url);
        if (preset?.SupportedAuthTypes is { Length: > 1 }) return null;
        return preset?.AuthType;
    }

    /// <summary>A stored connection only fails when a requirement names a type and it differs.</summary>
    public static bool ExistingCompatible(string authType, string? required) => required is null || authType == required;

    /// <summary>New setup must also pass the preset's own list of allowed sign-in types.</summary>
    public static bool Compatible(string authType, string? required, string url)
    {
        if (!ExistingCompatible(authType, required)) return false;
        var preset = PresetFor(url);
        return preset is null || (preset.SupportedAuthTypes ?? [preset.AuthType]).Contains(authType);
    }

    public static bool RequiresPreRegisteredClient(string url) => PresetFor(url)?.RequiresOAuthClient == true;

    /// <summary>The address as compared between a plugin's declaration and a connection: no fragment, no trailing slash on the path.</summary>
    public static string ComparableUrl(string value)
    {
        value = value.Trim();
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)) return value.TrimEnd('/');
        var path = uri.AbsolutePath.Length > 1 ? uri.AbsolutePath.TrimEnd('/') : uri.AbsolutePath;
        return $"{uri.Scheme}://{uri.Authority}{path}{uri.Query}";
    }
}
