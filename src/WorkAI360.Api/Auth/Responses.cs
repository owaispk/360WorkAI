using WorkAI360.Api.Domain;

namespace WorkAI360.Api.Auth;

/// <summary>JSON shapes shared by several endpoints. They mirror the reference API so existing clients keep working.</summary>
public static class Responses
{
    private static string Iso(DateTime value) => DateTime.SpecifyKind(value, DateTimeKind.Utc).ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

    public static object UserJson(User u) => new
    {
        name = u.Name,
        email = u.Email,
        emailVerified = u.EmailVerified,
        image = u.Image,
        createdAt = Iso(u.CreatedAt),
        updatedAt = Iso(u.UpdatedAt),
        id = u.Id,
    };

    public static object SessionJson(Session s, string? token = null) => new
    {
        id = s.Id,
        token,
        userId = s.UserId,
        expiresAt = Iso(s.ExpiresAt),
        createdAt = Iso(s.CreatedAt),
        updatedAt = Iso(s.UpdatedAt),
        ipAddress = s.IpAddress,
        userAgent = s.UserAgent,
        activeOrganizationId = s.ActiveOrganizationId,
    };

    public static object OrganizationJson(Organization o) => new { id = o.Id, name = o.Name, slug = o.Slug, logo = (string?)null, createdAt = Iso(o.CreatedAt) };

    public static IResult Error(int status, string error, string message) =>
        Results.Json(new { error, message }, statusCode: status);

    /// <summary>Better Auth's error shape: { message, code }.</summary>
    public static IResult AuthError(int status, string message, string code) => Results.Json(new { message, code }, statusCode: status);

    public static IResult Unauthorized() => Results.Json(new { error = "unauthorized" }, statusCode: StatusCodes.Status401Unauthorized);

    public static string IsoUtc(DateTime value) => Iso(value);
}
