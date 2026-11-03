namespace WorkAI360.Api.Auth;

/// <summary>Headers every API response carries so that nothing it serves can be framed or sniffed as another type.</summary>
public static class SecurityHeaders
{
    public const string FramePolicy = "frame-ancestors 'none'";

    /// <summary>
    /// Sets <c>X-Frame-Options: DENY</c> and makes the CSP forbid framing. A CSP a page already chose (the logout page's <c>default-src 'none'</c>, for
    /// example) keeps its other directives: only <c>frame-ancestors</c> is set, replacing any other value.
    /// </summary>
    public static void Apply(IHeaderDictionary headers, bool https, bool development)
    {
        headers["X-Frame-Options"] = "DENY";
        headers["Content-Security-Policy"] = WithFrameLock(headers.ContentSecurityPolicy.ToString());
        headers.TryAdd("X-Content-Type-Options", "nosniff");
        if (https && !development) headers.TryAdd("Strict-Transport-Security", "max-age=31536000");
    }

    public static string WithFrameLock(string? existing)
    {
        var kept = (existing ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(d => !d.StartsWith("frame-ancestors", StringComparison.OrdinalIgnoreCase));
        return string.Join("; ", kept.Append(FramePolicy));
    }
}
