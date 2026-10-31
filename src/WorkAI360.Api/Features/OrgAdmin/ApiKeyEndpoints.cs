using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.OrgAdmin;

namespace WorkAI360.Api.Features.OrgAdmin;

/// <summary>Organization API keys: list, create (the secret is shown once) and delete. A key acts as the member who made it, in that workspace only.</summary>
public static class ApiKeyEndpoints
{
    public const int RateLimitMax = 600;
    public const int RateLimitWindowMs = 60_000;
    public const int ExpiresInDays = 90;
    private const int SecretLength = 64;

    public static void MapApiKeyEndpoints(this WebApplication app)
    {
        app.MapGet("/v1/api-keys", async (HttpContext ctx, OrgAccess access, DenDbContext db) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "api_keys.view") is { } denied) return denied;
            var organizationId = context!.Organization.Id;
            // Only keys whose member still belongs to this workspace are listed, newest first.
            var rows = await (from k in db.Set<ApiKey>().AsNoTracking()
                              join m in db.Members.AsNoTracking() on k.MemberId equals m.Id
                              join u in db.Users.AsNoTracking() on m.UserId equals u.Id
                              where k.OrganizationId == organizationId && m.OrganizationId == organizationId && k.UserId == m.UserId
                              orderby k.CreatedAt descending, k.Id descending
                              select new { Key = k, Member = m, User = u }).ToListAsync();
            return Results.Json(new
            {
                apiKeys = rows.Select(r => new
                {
                    id = r.Key.Id,
                    configId = "default",
                    name = r.Key.Name,
                    start = r.Key.Start,
                    prefix = r.Key.Prefix,
                    enabled = r.Key.Enabled,
                    rateLimitEnabled = r.Key.RateLimitEnabled,
                    rateLimitMax = r.Key.RateLimitMax,
                    rateLimitTimeWindow = r.Key.RateLimitTimeWindow,
                    lastRequest = r.Key.LastRequestAt is { } l ? Responses.IsoUtc(l) : null,
                    expiresAt = Responses.IsoUtc(r.Key.ExpiresAt),
                    createdAt = Responses.IsoUtc(r.Key.CreatedAt),
                    updatedAt = Responses.IsoUtc(r.Key.UpdatedAt),
                    owner = new { userId = r.User.Id, memberId = r.Member.Id, name = r.User.Name, email = r.User.Email, image = r.User.Image },
                }),
            });
        });

        app.MapPost("/v1/api-keys", async (HttpContext ctx, OrgAccess access, DenDbContext db, IAuditLog audit) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "api_keys.manage") is { } denied) return denied;
            var (root, invalid) = await Zod.ReadObjectAsync(ctx, "name");
            if (invalid is not null) return invalid;
            if (Zod.String(root, "name", 2, 64, required: true, out var name) is { } issue) return Zod.Respond([issue]);

            // The secret is random and shown once; only its hash is kept.
            var secret = ApiKeyAuthenticator.Prefix + Ids.RandomAlnum(SecretLength);
            var now = DateTime.UtcNow;
            var key = new ApiKey
            {
                Id = Ids.New("apk"), OrganizationId = context!.Organization.Id, MemberId = context.Member.Id, UserId = context.Auth.User.Id,
                Name = name!, Prefix = ApiKeyAuthenticator.Prefix, Start = secret[..6], KeyHash = Ids.Sha256Hex(secret),
                Enabled = true, RateLimitEnabled = true, RateLimitMax = RateLimitMax, RateLimitTimeWindow = RateLimitWindowMs,
                ExpiresAt = now.AddDays(ExpiresInDays), CreatedAt = now, UpdatedAt = now,
            };
            db.Set<ApiKey>().Add(key);
            await db.SaveChangesAsync();
            await audit.RecordAsync(context, new AuditEntry(AuditActions.ApiKeyCreated,
                [new("api_key", key.Id, "target", key.Name), new("member", context.Member.Id, "parent")],
                After: Snapshot(key)));
            return Results.Json(new
            {
                apiKey = new
                {
                    id = key.Id, name = key.Name, start = key.Start, prefix = key.Prefix, enabled = key.Enabled,
                    rateLimitEnabled = key.RateLimitEnabled, rateLimitMax = key.RateLimitMax, rateLimitTimeWindow = key.RateLimitTimeWindow,
                    expiresAt = Responses.IsoUtc(key.ExpiresAt), createdAt = Responses.IsoUtc(key.CreatedAt), updatedAt = Responses.IsoUtc(key.UpdatedAt),
                },
                key = secret,
            }, statusCode: 201);
        });

        app.MapDelete("/v1/api-keys/{apiKeyId}", async (string apiKeyId, HttpContext ctx, OrgAccess access, DenDbContext db, IAuditLog audit) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "api_keys.manage") is { } denied) return denied;
            // A key of another workspace (or no key at all) reads the same: not found.
            var key = await db.Set<ApiKey>().FirstOrDefaultAsync(k => k.Id == apiKeyId && k.OrganizationId == context!.Organization.Id);
            if (key is null) return Results.Json(new { error = "api_key_not_found" }, statusCode: 404);
            var deleted = await db.Set<ApiKey>().Where(k => k.Id == key.Id).ExecuteDeleteAsync();
            if (deleted == 0) return Results.Json(new { error = "api_key_not_found" }, statusCode: 404);
            await audit.RecordAsync(context!, new AuditEntry(AuditActions.ApiKeyDeleted,
                [new("api_key", key.Id, "target", key.Name), new("member", key.MemberId, "parent")], Before: Snapshot(key)));
            return Results.NoContent();
        });
    }

    /// <summary>What an event records about a key: never the secret or its hash.</summary>
    public static System.Text.Json.Nodes.JsonObject Snapshot(ApiKey key) => new()
    {
        ["id"] = key.Id, ["name"] = key.Name, ["prefix"] = key.Prefix, ["start"] = key.Start, ["enabled"] = key.Enabled,
        ["memberId"] = key.MemberId, ["expiresAt"] = Responses.IsoUtc(key.ExpiresAt),
    };
}
