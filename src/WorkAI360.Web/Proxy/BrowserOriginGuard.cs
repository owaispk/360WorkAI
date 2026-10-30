namespace WorkAI360.Web.Proxy;

/// <summary>
/// /api/browser/v1/* carries the person's session cookie, so a page on another site must not be able to use it.
/// Reads are allowed from the same origin; writes must name this exact origin.
/// </summary>
public sealed class BrowserOriginGuard(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path;
        if (path.StartsWithSegments("/api/browser/v1"))
        {
            if (!IsSameOrigin(context.Request) || HasUnsafeSegment(path.Value ?? ""))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsJsonAsync(new { error = HasUnsafeSegment(path.Value ?? "") ? "invalid_api_path" : "forbidden_origin" });
                return;
            }
        }
        await next(context);
    }

    private static bool IsSameOrigin(HttpRequest request)
    {
        var site = request.Headers["Sec-Fetch-Site"].ToString();
        if (site.Length > 0 && site is not ("same-origin" or "none")) return false;

        var origin = request.Headers.Origin.ToString();
        if (origin.Length > 0) return string.Equals(origin, $"{request.Scheme}://{request.Host}", StringComparison.OrdinalIgnoreCase);
        // Browsers omit Origin on same-origin reads, but a write must prove its origin.
        return HttpMethods.IsGet(request.Method) || HttpMethods.IsHead(request.Method);
    }

    private static bool HasUnsafeSegment(string path) =>
        path.Split('/').Select(Uri.UnescapeDataString).Any(s => s is "." or ".." || s.Contains('\\') || s.Contains('\0'));
}
