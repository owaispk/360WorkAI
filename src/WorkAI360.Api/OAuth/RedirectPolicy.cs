namespace WorkAI360.Api.OAuth;

/// <summary>Which redirect URIs an MCP client may register: HTTPS, HTTP loopback, or a known private-use scheme.</summary>
public static class RedirectPolicy
{
    public const string ErrorDescription = "MCP OAuth redirect URIs must use HTTPS callbacks or HTTP loopback callbacks and must not include fragments.";

    /// <summary>Exact private-use URIs for native clients that support nothing else. PKCE S256 is mandatory for all clients.</summary>
    private static readonly HashSet<string> PrivateUse = ["cursor://anysphere.cursor-mcp/oauth/callback"];

    public static bool IsAllowed(string uri)
    {
        if (uri.Contains('#') || !Uri.TryCreate(uri, UriKind.Absolute, out var parsed)) return false;
        if (PrivateUse.Contains(uri)) return true;
        return parsed.Scheme switch
        {
            "https" => true,
            "http" => IsLoopback(parsed.Host),
            _ => false,
        };
    }

    public static bool IsLoopback(string host)
    {
        var h = host.Trim().Trim('[', ']').ToLowerInvariant();
        return h == "localhost" || h.EndsWith(".localhost") || h == "::1"
            || (System.Net.IPAddress.TryParse(h, out var ip) && System.Net.IPAddress.IsLoopback(ip));
    }

    /// <summary>
    /// Exact match against the registered URIs, except that a registered loopback URI matches on any port
    /// (RFC 8252 section 7.3), which native clients that pick a random free port depend on.
    /// </summary>
    public static bool Matches(IEnumerable<string> registered, string requested)
    {
        if (!Uri.TryCreate(requested, UriKind.Absolute, out var req)) return false;
        foreach (var uri in registered)
        {
            if (uri == requested) return true;
            if (Uri.TryCreate(uri, UriKind.Absolute, out var reg) && reg.Scheme == "http" && req.Scheme == "http"
                && IsLoopback(reg.Host) && IsLoopback(req.Host) && reg.AbsolutePath == req.AbsolutePath && reg.Query == req.Query
                && string.Equals(reg.Host.Trim('[', ']'), req.Host.Trim('[', ']'), StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}
