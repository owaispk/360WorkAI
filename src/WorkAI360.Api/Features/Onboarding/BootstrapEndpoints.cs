using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Endpoints;
using WorkAI360.Api.Features.OrgAdmin;

namespace WorkAI360.Api.Features.Onboarding;

/// <summary>The routes of "provision now, claim later" (see <see cref="BootstrapService"/>).</summary>
public static class BootstrapEndpoints
{
    private static readonly string[] AllRoles = ["owner", "admin", "member"];

    public static void MapBootstrapEndpoints(this WebApplication app)
    {
        app.MapPost("/v1/bootstrap/workspace", async (HttpContext ctx, BootstrapService service, WindowLimiter limiter, IOptions<OnboardingOptions> options, OAuth.OAuthUrls urls) =>
        {
            var (root, invalid) = await Zod.ReadObjectAsync(ctx, "workspaceName");
            if (invalid is not null) return invalid;
            var issues = new List<ZodIssue>();
            if (Zod.String(root, "workspaceName", 2, 120, required: true, out var name) is { } i1) issues.Add(i1);
            if (Zod.String(root, "skillName", 1, 120, required: false, out var skill) is { } i2) issues.Add(i2);
            if (Zod.String(root, "devicePublicKey", 16, 4096, required: false, out var key) is { } i3) issues.Add(i3);
            string? ownerEmail = null;
            if (Zod.String(root, "ownerEmail", 0, 255, required: false, out var rawOwner) is { } i4) issues.Add(i4);
            else if (rawOwner is not null)
            {
                ownerEmail = rawOwner.ToLowerInvariant();
                if (!AuthEndpoints.IsValidEmail(ownerEmail)) issues.Add(new ZodIssue("invalid_format", ["ownerEmail"], "Invalid email address"));
            }

            var roles = new List<string>();
            if (root.TryGetProperty("claimRoles", out var rolesElement))
            {
                if (rolesElement.ValueKind != JsonValueKind.Array) issues.Add(new ZodIssue("invalid_type", ["claimRoles"], $"Invalid input: expected array, received {Zod.Kind(rolesElement)}"));
                else
                {
                    var index = 0;
                    foreach (var r in rolesElement.EnumerateArray())
                    {
                        var value = r.ValueKind == JsonValueKind.String ? r.GetString()! : null;
                        if (value is null || !AllRoles.Contains(value)) issues.Add(new ZodIssue("invalid_value", ["claimRoles", index.ToString()], "Invalid option: expected one of \"owner\"|\"admin\"|\"member\""));
                        else roles.Add(value);
                        index++;
                    }
                    if (index < 1) issues.Add(new ZodIssue("too_small", ["claimRoles"], "Too small: expected array to have >=1 items"));
                    else if (index > 3) issues.Add(new ZodIssue("too_big", ["claimRoles"], "Too big: expected array to have <=3 items"));
                }
            }
            if (roles.Count == 0 && !root.TryGetProperty("claimRoles", out _)) roles.Add("owner");

            var teammates = new List<string>();
            if (root.TryGetProperty("teammateEmails", out var mates))
            {
                if (mates.ValueKind != JsonValueKind.Array) issues.Add(new ZodIssue("invalid_type", ["teammateEmails"], $"Invalid input: expected array, received {Zod.Kind(mates)}"));
                else
                {
                    var index = 0;
                    foreach (var m in mates.EnumerateArray())
                    {
                        var value = m.ValueKind == JsonValueKind.String ? m.GetString()!.Trim().ToLowerInvariant() : null;
                        if (value is null) issues.Add(new ZodIssue("invalid_type", ["teammateEmails", index.ToString()], $"Invalid input: expected string, received {Zod.Kind(m)}"));
                        else if (value.Length > 255) issues.Add(new ZodIssue("too_big", ["teammateEmails", index.ToString()], "Too big: expected string to have <=255 characters"));
                        else if (!AuthEndpoints.IsValidEmail(value)) issues.Add(new ZodIssue("invalid_format", ["teammateEmails", index.ToString()], "Invalid email address"));
                        else teammates.Add(value);
                        index++;
                    }
                    if (index > 10) issues.Add(new ZodIssue("too_big", ["teammateEmails"], "Too big: expected array to have <=10 items"));
                }
            }
            if (issues.Count > 0) return Zod.Respond(issues);

            if (await limiter.HitAsync($"bootstrap:workspace:{AuthEndpoints.ClientIp(ctx)}", options.Value.Bootstrap.LimitPerHour, TimeSpan.FromHours(1)) is { } wait)
            {
                ctx.Response.Headers.RetryAfter = wait.ToString();
                return Results.Json(new { error = "rate_limited", message = "Too many bootstrap attempts. Try again later." }, statusCode: 429);
            }

            var created = await service.CreateAsync(name!, skill ?? "First OpenWork Skill", key, roles, ownerEmail, teammates);
            ctx.Response.Headers.CacheControl = "no-store";
            return Results.Json(new
            {
                ok = true,
                organization = new { id = created.Organization.Id, name = created.Organization.Name, slug = created.Organization.Slug, status = "provisional" },
                setup = new { id = created.Bootstrap.Id, expiresAt = Responses.IsoUtc(created.Bootstrap.ExpiresAt) },
                skill = new { id = created.Skill.Id, title = created.Skill.Title, output = BootstrapService.StarterOutput },
                claimLinks = created.Links.Select(l => new { id = l.Claim.Id, role = l.Claim.Role, token = l.Token, url = l.Url, expiresAt = Responses.IsoUtc(l.Claim.ExpiresAt) }),
                identity = new
                {
                    type = "anonymous",
                    assertion = created.Assertion,
                    assertionType = "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    tokenEndpoint = urls.TokenEndpoint,
                    scope = "mcp:read mcp:write",
                    expiresAt = Responses.IsoUtc(created.Bootstrap.ExpiresAt),
                    claimEndpoint = $"{urls.Api}/v1/bootstrap/workspace/{created.Bootstrap.Id}/claim",
                },
            });
        });

        app.MapPost("/v1/bootstrap/claims/accept", async (HttpContext ctx, SessionService sessions, BootstrapService service, DenDbContext db) =>
        {
            var auth = await sessions.ResolveAsync(ctx);
            if (auth is null) return Responses.Unauthorized();
            var (root, invalid) = await Zod.ReadObjectAsync(ctx, "token");
            if (invalid is not null) return invalid;
            if (Zod.String(root, "token", 24, 255, required: true, out var token) is { } issue) return Zod.Respond([issue]);

            var claimed = await service.ClaimWithLinkAsync(auth.User.Id, token!);
            if (claimed is null) return Results.Json(new { error = "claim_not_found", message = "This workspace claim link is missing, expired, or already used." }, statusCode: 404);
            await OrgEndpoints.SetActiveAsync(db, await db.Sessions.FirstAsync(s => s.Id == auth.Session.Id), claimed.OrganizationId);
            return Claimed(claimed);
        });

        app.MapPost("/v1/bootstrap/workspace/{bootstrapId}/claim", async (string bootstrapId, HttpContext ctx, BootstrapService service, IOptions<OnboardingOptions> options) =>
        {
            if (MemberEndpoints.ValidateTypeId(bootstrapId, "wbt", "bootstrapId") is { } malformed) return malformed;
            var (checkedAssertion, failure) = await Assertion(ctx, bootstrapId, service);
            if (failure is not null) return failure;
            if (checkedAssertion!.Value.Revoked) return Results.Json(new { error = "invalid_token", error_description = "This workspace was already claimed or expired." }, statusCode: 401);
            ctx.Response.Headers.CacheControl = "no-store";
            return Results.Json(await service.IssueCodeAsync(checkedAssertion.Value.Bootstrap, options.Value.Bootstrap.CodeMinutes));
        });

        app.MapGet("/v1/bootstrap/workspace/{bootstrapId}/claim", async (string bootstrapId, HttpContext ctx, BootstrapService service) =>
        {
            if (MemberEndpoints.ValidateTypeId(bootstrapId, "wbt", "bootstrapId") is { } malformed) return malformed;
            var (checkedAssertion, failure) = await Assertion(ctx, bootstrapId, service);
            if (failure is not null) return failure;
            ctx.Response.Headers.CacheControl = "no-store";
            return Results.Json(await service.ClaimStateAsync(checkedAssertion!.Value.Bootstrap));
        });

        app.MapGet("/v1/bootstrap/claim-codes/{userCode}", async (string userCode, HttpContext ctx, SessionService sessions, BootstrapService service) =>
        {
            var auth = await sessions.ResolveAsync(ctx);
            if (auth is null) return Responses.Unauthorized();
            if (CodeIssue(userCode) is { } issue) return Zod.Respond([issue.WithPath("userCode")]);
            var lookup = await service.LookupCodeAsync(userCode);
            if (lookup is null) return InvalidCode();
            return Results.Json(new { organization = new { id = lookup.Organization.Id, name = lookup.Organization.Name } });
        });

        app.MapPost("/v1/bootstrap/claim-codes/accept", async (HttpContext ctx, SessionService sessions, BootstrapService service, DenDbContext db) =>
        {
            var auth = await sessions.ResolveAsync(ctx);
            if (auth is null) return Responses.Unauthorized();
            var (root, invalid) = await Zod.ReadObjectAsync(ctx, "userCode");
            if (invalid is not null) return invalid;
            var issues = new List<ZodIssue>();
            if (Zod.String(root, "userCode", 4, 32, required: true, out var code) is { } i1) issues.Add(i1);
            if (root.TryGetProperty("mode", out var mode) && !(mode.ValueKind == JsonValueKind.String && mode.GetString() == "new_org"))
                issues.Add(new ZodIssue("invalid_value", ["mode"], "Invalid input: expected \"new_org\""));
            if (issues.Count > 0) return Zod.Respond(issues);

            var lookup = await service.LookupCodeAsync(code!);
            if (lookup is null) return InvalidCode();
            var claimed = await service.ClaimWithCodeAsync(auth.User.Id, lookup.Code, lookup.Bootstrap);
            if (claimed is null) return InvalidCode();
            await OrgEndpoints.SetActiveAsync(db, await db.Sessions.FirstAsync(s => s.Id == auth.Session.Id), claimed.OrganizationId);
            return Claimed(claimed);
        });
    }

    private static ZodIssue? CodeIssue(string code) =>
        code.Trim().Length < 4 ? new ZodIssue("too_small", [], "Too small: expected string to have >=4 characters")
        : code.Trim().Length > 32 ? new ZodIssue("too_big", [], "Too big: expected string to have <=32 characters") : null;

    private static ZodIssue WithPath(this ZodIssue issue, string path) => issue with { Path = [path] };

    private static IResult InvalidCode() => Results.Json(new { error = "invalid_user_code", message = "This code is invalid or has expired. Ask your agent for a new one." }, statusCode: 404);

    private static IResult Claimed(BootstrapService.Claimed c) => Results.Json(c.Teammates.Length > 0
        ? new { ok = true, organization = new { id = c.OrganizationId, name = c.OrganizationName, slug = c.Slug, role = c.Role }, teammateEmails = c.Teammates }
        : (object)new { ok = true, organization = new { id = c.OrganizationId, name = c.OrganizationName, slug = c.Slug, role = c.Role } });

    /// <summary>The bearer assertion for exactly this workspace. A token for another workspace is as good as no token.</summary>
    private static async Task<((Domain.Onboarding.WorkspaceBootstrap Bootstrap, bool Revoked)? Value, IResult? Failure)> Assertion(HttpContext ctx, string bootstrapId, BootstrapService service)
    {
        var header = ctx.Request.Headers.Authorization.ToString().Trim();
        var bearer = header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? header[7..].Trim() : null;
        if (string.IsNullOrEmpty(bearer)) return (null, Results.Json(new { error = "invalid_token", error_description = "Send the pre-claim assertion as a Bearer token." }, statusCode: 401));
        var (bootstrap, revoked) = await service.VerifyAssertionAsync(bearer);
        if (bootstrap is null || bootstrap.Id != bootstrapId)
            return (null, Results.Json(new { error = "invalid_token", error_description = "The pre-claim assertion is invalid for this workspace." }, statusCode: 401));
        return ((bootstrap, revoked), null);
    }
}
