using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.Sso;
using WorkAI360.Api.Endpoints;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Scim;

/// <summary>SCIM 2.0 as identity providers call it: <c>/api/auth/scim/v2/*</c>, authenticated by the workspace's bearer token.</summary>
public static partial class ScimProtocolEndpoints
{
    public static readonly AuthLimitPolicy BadTokenLimit = new("scim-token", TimeSpan.FromMinutes(5), 60, 60);
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web) { PropertyNamingPolicy = null, DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull };

    private static IResult Scim(object body, int status = 200, string? location = null) =>
        Results.Content(JsonSerializer.Serialize(body, Web), "application/scim+json", System.Text.Encoding.UTF8, status);

    private static IResult Error(ScimFailure f) => Error(f.Status, f.Detail, f.ScimType);

    private static IResult Error(int status, string detail, string? scimType = null) =>
        Scim(scimType is null
            ? new { schemas = new[] { ScimService.ErrorSchema }, detail, status = status.ToString() }
            : new { schemas = new[] { ScimService.ErrorSchema }, detail, status = status.ToString(), scimType }, status);

    private static async Task<(ScimProvider? Provider, IResult? Failure)> AuthorizeAsync(HttpContext ctx, ScimService scim, RateLimiter limiter)
    {
        var bearer = SessionService.ReadBearer(ctx.Request);
        if (bearer is null)
        {
            if (limiter.Hit(BadTokenLimit, null, AuthEndpoints.ClientIp(ctx)) is { } w1) return (null, AuthEndpoints.TooManyRequests(ctx, w1));
            return (null, Error(401, "SCIM token is required"));
        }
        var provider = await scim.AuthenticateAsync(bearer);
        if (provider is null)
        {
            if (limiter.Hit(BadTokenLimit, null, AuthEndpoints.ClientIp(ctx)) is { } w2) return (null, AuthEndpoints.TooManyRequests(ctx, w2));
            return (null, Error(401, "Invalid SCIM token"));
        }
        // Provisioning requests are recorded in the token's workspace, acted by the SCIM connection (Features/OrgAdmin/AuditRoutes.cs).
        ctx.Items[WorkAI360.Api.Features.OrgAdmin.AuditRoutes.AttributionItem] =
            new WorkAI360.Api.Features.OrgAdmin.AuditAttribution(provider.OrganizationId, new WorkAI360.Api.Features.OrgAdmin.AuditActor("service", $"scim:{provider.ProviderId}"));
        return (provider, null);
    }

    private static async Task<JsonElement?> ReadBodyAsync(HttpRequest request)
    {
        try
        {
            using var doc = await JsonDocument.ParseAsync(request.Body);
            return doc.RootElement.ValueKind == JsonValueKind.Object ? doc.RootElement.Clone() : null;
        }
        catch (JsonException) { return null; }
    }

    private static string? Str(JsonElement e, string name) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static (ScimUserInput? Input, string? Problem) ParseUser(JsonElement body)
    {
        var userName = Str(body, "userName");
        if (userName is null) return (null, "userName is required");
        string? externalId = null;
        if (body.TryGetProperty("externalId", out var ext) && ext.ValueKind != JsonValueKind.Null) { if (ext.ValueKind != JsonValueKind.String) return (null, "externalId must be a string"); externalId = ext.GetString(); }
        string? formatted = null, given = null, family = null;
        if (body.TryGetProperty("name", out var name) && name.ValueKind == JsonValueKind.Object) { formatted = Str(name, "formatted"); given = Str(name, "givenName"); family = Str(name, "familyName"); }
        var emails = new List<(string, bool)>();
        if (body.TryGetProperty("emails", out var list) && list.ValueKind == JsonValueKind.Array)
            foreach (var item in list.EnumerateArray())
            {
                var value = Str(item, "value");
                if (value is null || !AuthEndpoints.IsValidEmail(value)) return (null, "emails.value must be an email address");
                emails.Add((value, item.TryGetProperty("primary", out var p) && p.ValueKind == JsonValueKind.True));
            }
        bool? active = body.TryGetProperty("active", out var a) ? a.ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => null } : null;
        return (new ScimUserInput(userName.Trim().ToLowerInvariant(), externalId, formatted, given, family, [.. emails], active), null);
    }

    private static string Base(OAuthUrls urls) => ScimAdminEndpoints.BaseUrl(urls);

    private static async Task<object> UserResourceAsync(DenDbContext db, OAuthUrls urls, ScimProvider provider, User user, ExternalAccount? account)
    {
        var groups = await (from m in db.Set<ScimGroupMember>() join g in db.Set<ScimGroup>() on m.GroupId equals g.Id where m.ProviderId == provider.ProviderId && m.RemoteUserId == user.Id select new { g.Id, g.DisplayName }).ToListAsync();
        var resource = new Dictionary<string, object?>
        {
            ["id"] = user.Id, ["externalId"] = account?.AccountId,
            ["meta"] = new { resourceType = "User", created = Responses.IsoUtc(user.CreatedAt), lastModified = Responses.IsoUtc(user.UpdatedAt), location = $"{Base(urls)}/Users/{user.Id}" },
            ["userName"] = user.Email, ["name"] = new { formatted = user.Name }, ["displayName"] = user.Name, ["active"] = true,
            ["emails"] = new[] { new { primary = true, value = user.Email } },
            ["schemas"] = new[] { ScimService.UserSchema },
        };
        if (groups.Count > 0) resource["groups"] = groups.Select(g => new Dictionary<string, string> { ["value"] = g.Id, ["$ref"] = $"{Base(urls)}/Groups/{g.Id}", ["display"] = g.DisplayName }).ToArray();
        return resource;
    }

    private static async Task<object> GroupResourceAsync(ScimService scim, OAuthUrls urls, ScimGroup g)
    {
        var members = (await scim.MemberValuesAsync(g)).Select(v => new Dictionary<string, string> { ["value"] = v, ["$ref"] = $"{Base(urls)}/Users/{Uri.EscapeDataString(v)}" }).ToArray();
        var resource = new Dictionary<string, object?>
        {
            ["schemas"] = new[] { ScimService.GroupSchema }, ["id"] = g.Id, ["externalId"] = g.ExternalId, ["displayName"] = g.DisplayName, ["members"] = members,
            ["meta"] = new { resourceType = "Group", created = Responses.IsoUtc(g.CreatedAt), lastModified = Responses.IsoUtc(g.UpdatedAt), location = $"{Base(urls)}/Groups/{g.Id}" },
        };
        return resource;
    }

    private static readonly object UserSchemaDoc = new
    {
        id = ScimService.UserSchema, name = "User", description = "User Account",
        attributes = new object[]
        {
            new { name = "userName", type = "string", multiValued = false, required = true, caseExact = false, mutability = "readWrite", returned = "default", uniqueness = "server" },
            new { name = "displayName", type = "string", multiValued = false, required = false, mutability = "readOnly", returned = "default", uniqueness = "none" },
            new { name = "active", type = "boolean", multiValued = false, required = false, mutability = "readWrite", returned = "default" },
            new { name = "name", type = "complex", multiValued = false, required = false, mutability = "readWrite", returned = "default" },
            new { name = "emails", type = "complex", multiValued = true, required = false, mutability = "readWrite", returned = "default", uniqueness = "none" },
        },
        meta = new { resourceType = "Schema", location = "/scim/v2/Schemas/" + ScimService.UserSchema },
    };

    private static readonly object GroupSchemaDoc = new
    {
        id = ScimService.GroupSchema, name = "Group", description = "Group",
        attributes = new object[]
        {
            new { name = "displayName", type = "string", multiValued = false, required = true, mutability = "readWrite", returned = "default", uniqueness = "none" },
            new { name = "members", type = "complex", multiValued = true, required = false, mutability = "readWrite", returned = "default", uniqueness = "none" },
        },
        meta = new { resourceType = "Schema", location = "/scim/v2/Schemas/" + ScimService.GroupSchema },
    };

    private static readonly object UserType = new { schemas = new[] { "urn:ietf:params:scim:schemas:core:2.0:ResourceType" }, id = "User", name = "User", endpoint = "/Users", description = "User Account", schema = ScimService.UserSchema, meta = new { resourceType = "ResourceType", location = "/scim/v2/ResourceTypes/User" } };
    private static readonly object GroupType = new { schemas = new[] { "urn:ietf:params:scim:schemas:core:2.0:ResourceType" }, id = "Group", name = "Group", endpoint = "/Groups", description = "Group", schema = ScimService.GroupSchema, meta = new { resourceType = "ResourceType", location = "/scim/v2/ResourceTypes/Group" } };

    private static object List(IReadOnlyCollection<object> resources, int startIndex = 1, int? total = null) =>
        new { schemas = new[] { ScimService.ListSchema }, totalResults = total ?? resources.Count, startIndex, itemsPerPage = resources.Count, Resources = resources };

    [GeneratedRegex(@"^\s*(?<attr>[^\s]+)\s+(?<op>eq|ne|co|sw|ew|pr)\s*(?:(?<value>""[^""]*""|[^\s]+))?\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex FilterPattern();

    [GeneratedRegex(@"^(displayName|externalId)\s+eq\s+[""']([^""']+)[""']$", RegexOptions.IgnoreCase)]
    private static partial Regex GroupFilterPattern();

    [GeneratedRegex(@"^members\s*\[\s*value\s+eq\s+[""']([^""']+)[""']\s*\]$", RegexOptions.IgnoreCase)]
    private static partial Regex MemberPathPattern();

    public static void Map(WebApplication app)
    {
        const string P = "/api/auth/scim/v2";

        // Public: what this server supports.
        app.MapGet(P + "/ServiceProviderConfig", () => Scim(new
        {
            patch = new { supported = true }, bulk = new { supported = false }, filter = new { supported = true }, changePassword = new { supported = false }, sort = new { supported = false }, etag = new { supported = false },
            authenticationSchemes = new[] { new { name = "OAuth Bearer Token", description = "Authentication scheme using the Authorization header with a bearer token tied to an organization.", specUri = "http://www.rfc-editor.org/info/rfc6750", type = "oauthbearertoken", primary = true } },
            schemas = new[] { "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig" }, meta = new { resourceType = "ServiceProviderConfig" },
        }));

        app.MapGet(P + "/Schemas", async (HttpContext ctx, ScimService scim, RateLimiter limiter) =>
        {
            var (provider, failure) = await AuthorizeAsync(ctx, scim, limiter);
            return failure ?? Scim(List([UserSchemaDoc, GroupSchemaDoc]));
        });
        app.MapGet(P + "/Schemas/{id}", async (string id, HttpContext ctx, ScimService scim, RateLimiter limiter) =>
        {
            var (provider, failure) = await AuthorizeAsync(ctx, scim, limiter);
            if (failure is not null) return failure;
            return id == ScimService.UserSchema ? Scim(UserSchemaDoc) : id == ScimService.GroupSchema ? Scim(GroupSchemaDoc) : Error(404, "Schema not found");
        });
        app.MapGet(P + "/ResourceTypes", async (HttpContext ctx, ScimService scim, RateLimiter limiter) =>
        {
            var (provider, failure) = await AuthorizeAsync(ctx, scim, limiter);
            return failure ?? Scim(List([UserType, GroupType]));
        });
        app.MapGet(P + "/ResourceTypes/{id}", async (string id, HttpContext ctx, ScimService scim, RateLimiter limiter) =>
        {
            var (provider, failure) = await AuthorizeAsync(ctx, scim, limiter);
            if (failure is not null) return failure;
            return id == "User" ? Scim(UserType) : id == "Group" ? Scim(GroupType) : Error(404, "Resource type not found");
        });

        // ---- Users ----
        app.MapPost(P + "/Users", async (HttpContext ctx, DenDbContext db, ScimService scim, OAuthUrls urls, RateLimiter limiter) =>
        {
            var (provider, failure) = await AuthorizeAsync(ctx, scim, limiter);
            if (failure is not null) return failure;
            if (await ReadBodyAsync(ctx.Request) is not { } body) return Error(400, "Invalid SCIM User resource");
            var (input, problem) = ParseUser(body);
            if (input is null) return Error(400, problem!);
            var (user, account, error) = await scim.CreateUserAsync(provider!, input);
            if (error is not null) return Error(error);
            ctx.Response.Headers.Location = $"{Base(urls)}/Users/{user!.Id}";
            return Scim(await UserResourceAsync(db, urls, provider!, user, account), 201);
        });

        app.MapGet(P + "/Users", async (HttpContext ctx, DenDbContext db, ScimService scim, OAuthUrls urls, RateLimiter limiter) =>
        {
            var (provider, failure) = await AuthorizeAsync(ctx, scim, limiter);
            if (failure is not null) return failure;
            string? wanted = null;
            if (ctx.Request.Query["filter"].ToString() is { Length: > 0 } filter)
            {
                var m = FilterPattern().Match(filter);
                if (!m.Success || !m.Groups["value"].Success) return Error(400, "Invalid filter expression", "invalidFilter");
                if (!m.Groups["attr"].Value.Equals("userName", StringComparison.OrdinalIgnoreCase)) return Error(400, $"The attribute \"{m.Groups["attr"].Value}\" is not supported", "invalidFilter");
                if (!m.Groups["op"].Value.Equals("eq", StringComparison.OrdinalIgnoreCase)) return Error(400, $"The operator \"{m.Groups["op"].Value.ToLowerInvariant()}\" is not supported", "invalidFilter");
                wanted = m.Groups["value"].Value.Trim('"').ToLowerInvariant();
            }
            var providerId = provider!.ProviderId;
            var organizationId = provider.OrganizationId;
            var rows = await (from a in db.Set<ExternalAccount>() where a.ProviderId == providerId
                              join m in db.Members on a.UserId equals m.UserId where m.OrganizationId == organizationId
                              join u in db.Users on a.UserId equals u.Id
                              orderby u.CreatedAt
                              select new { User = u, Account = a }).ToListAsync();
            if (wanted is not null) rows = rows.Where(r => r.User.Email == wanted).ToList();
            var resources = new List<object>();
            foreach (var r in rows) resources.Add(await UserResourceAsync(db, urls, provider!, r.User, r.Account));
            return Scim(List(resources));
        });

        app.MapGet(P + "/Users/{userId}", async (string userId, HttpContext ctx, DenDbContext db, ScimService scim, OAuthUrls urls, RateLimiter limiter) =>
        {
            var (provider, failure) = await AuthorizeAsync(ctx, scim, limiter);
            if (failure is not null) return failure;
            var (user, account) = await scim.FindUserAsync(provider!, userId);
            return user is null ? Error(404, "User not found") : Scim(await UserResourceAsync(db, urls, provider!, user, account));
        });

        app.MapPut(P + "/Users/{userId}", async (string userId, HttpContext ctx, DenDbContext db, ScimService scim, OAuthUrls urls, RateLimiter limiter) =>
        {
            var (provider, failure) = await AuthorizeAsync(ctx, scim, limiter);
            if (failure is not null) return failure;
            if (await ReadBodyAsync(ctx.Request) is not { } body) return Error(400, "Invalid SCIM User resource");
            var (input, problem) = ParseUser(body);
            if (input is null) return Error(400, problem!);
            var (user, account) = await scim.FindUserAsync(provider!, userId);
            if (user is null) return Error(404, "User not found");
            // Switching a person off removes their access and ends every session they hold.
            if (input.Active == false) return await scim.DeprovisionAsync(provider!, userId) is { } cannot ? Error(cannot) : Results.NoContent();
            if (await scim.ReplaceUserAsync(provider!, user, account!, input) is { } error) return Error(error);
            return Scim(await UserResourceAsync(db, urls, provider!, user, account));
        });

        app.MapPatch(P + "/Users/{userId}", async (string userId, HttpContext ctx, DenDbContext db, ScimService scim, RateLimiter limiter) =>
        {
            var (provider, failure) = await AuthorizeAsync(ctx, scim, limiter);
            if (failure is not null) return failure;
            if (await ReadBodyAsync(ctx.Request) is not { } body) return Error(400, "Invalid SCIM PATCH request");
            var operations = ReadOperations(body, out var problem);
            if (operations is null) return Error(400, problem!);
            var (user, account) = await scim.FindUserAsync(provider!, userId);
            if (user is null) return Error(404, "User not found");
            var patch = ScimService.BuildPatch(user, operations);
            if (!patch.Any) return Error(400, "No valid fields to update");
            if (patch.Deactivate) return await scim.DeprovisionAsync(provider!, userId) is { } cannot ? Error(cannot) : Results.NoContent();
            if (await scim.ApplyPatchAsync(provider!, user, account!, patch) is { } error) return Error(error);
            return Results.NoContent();
        });

        app.MapDelete(P + "/Users/{userId}", async (string userId, HttpContext ctx, ScimService scim, RateLimiter limiter) =>
        {
            var (provider, failure) = await AuthorizeAsync(ctx, scim, limiter);
            if (failure is not null) return failure;
            var (user, _) = await scim.FindUserAsync(provider!, userId);
            if (user is null) return Error(404, "User not found");
            return await scim.DeprovisionAsync(provider!, userId) is { } cannot ? Error(cannot) : Results.NoContent();
        });

        // ---- Groups ----
        app.MapGet(P + "/Groups", async (HttpContext ctx, DenDbContext db, ScimService scim, OAuthUrls urls, RateLimiter limiter) =>
        {
            var (provider, failure) = await AuthorizeAsync(ctx, scim, limiter);
            if (failure is not null) return failure;
            var groups = await db.Set<ScimGroup>().Where(g => g.ProviderId == provider!.ProviderId && g.OrganizationId == provider.OrganizationId).OrderBy(g => g.CreatedAt).ToListAsync();
            if (GroupFilterPattern().Match(ctx.Request.Query["filter"].ToString().Trim()) is { Success: true } m)
                groups = groups.Where(g => m.Groups[1].Value.Equals("displayName", StringComparison.OrdinalIgnoreCase) ? g.DisplayName == m.Groups[2].Value : g.ExternalId == m.Groups[2].Value).ToList();
            var all = new List<object>();
            foreach (var g in groups) all.Add(await GroupResourceAsync(scim, urls, g));
            var start = int.TryParse(ctx.Request.Query["startIndex"], out var s) ? Math.Max(1, s) : 1;
            var count = int.TryParse(ctx.Request.Query["count"], out var c) ? Math.Max(0, c) : all.Count;
            return Scim(List(all.Skip(start - 1).Take(count).ToList(), start, all.Count));
        });

        app.MapPost(P + "/Groups", async (HttpContext ctx, ScimService scim, OAuthUrls urls, RateLimiter limiter) =>
        {
            var (provider, failure) = await AuthorizeAsync(ctx, scim, limiter);
            if (failure is not null) return failure;
            if (await ReadBodyAsync(ctx.Request) is not { } body || !TryGroup(body, out var name, out var externalId, out var members)) return Error(400, "Invalid SCIM Group resource");
            var (group, error) = await scim.CreateGroupAsync(provider!, name!, externalId, members);
            return error is not null ? Error(error) : Scim(await GroupResourceAsync(scim, urls, group!), 201);
        });

        app.MapGet(P + "/Groups/{groupId}", async (string groupId, HttpContext ctx, ScimService scim, OAuthUrls urls, RateLimiter limiter) =>
        {
            var (provider, failure) = await AuthorizeAsync(ctx, scim, limiter);
            if (failure is not null) return failure;
            var group = await scim.FindGroupAsync(provider!, groupId);
            return group is null ? Error(404, "Group not found") : Scim(await GroupResourceAsync(scim, urls, group));
        });

        app.MapPut(P + "/Groups/{groupId}", async (string groupId, HttpContext ctx, ScimService scim, OAuthUrls urls, RateLimiter limiter) =>
        {
            var (provider, failure) = await AuthorizeAsync(ctx, scim, limiter);
            if (failure is not null) return failure;
            if (await ReadBodyAsync(ctx.Request) is not { } body || !TryGroup(body, out var name, out var externalId, out var members)) return Error(400, "Invalid SCIM Group resource");
            var group = await scim.FindGroupAsync(provider!, groupId);
            if (group is null) return Error(404, "Group not found");
            return await scim.UpdateGroupAsync(provider!, group, name!, externalId, members) is { } error ? Error(error) : Scim(await GroupResourceAsync(scim, urls, group));
        });

        app.MapPatch(P + "/Groups/{groupId}", async (string groupId, HttpContext ctx, ScimService scim, OAuthUrls urls, RateLimiter limiter) =>
        {
            var (provider, failure) = await AuthorizeAsync(ctx, scim, limiter);
            if (failure is not null) return failure;
            if (await ReadBodyAsync(ctx.Request) is not { } body) return Error(400, "Invalid SCIM PATCH request");
            var operations = ReadOperations(body, out _);
            if (operations is null) return Error(400, "Invalid SCIM PATCH request");
            var group = await scim.FindGroupAsync(provider!, groupId);
            if (group is null) return Error(404, "Group not found");
            var (name, externalId, members) = ApplyGroupPatch(group, await scim.MemberValuesAsync(group), operations);
            return await scim.UpdateGroupAsync(provider!, group, name, externalId, members) is { } error ? Error(error) : Scim(await GroupResourceAsync(scim, urls, group));
        });

        app.MapDelete(P + "/Groups/{groupId}", async (string groupId, HttpContext ctx, ScimService scim, RateLimiter limiter) =>
        {
            var (provider, failure) = await AuthorizeAsync(ctx, scim, limiter);
            if (failure is not null) return failure;
            var group = await scim.FindGroupAsync(provider!, groupId);
            if (group is null) return Error(404, "Group not found");
            await scim.DeleteGroupAsync(provider!, group);
            return Results.NoContent();
        });
    }

    private static List<(string Op, string? Path, JsonElement Value)>? ReadOperations(JsonElement body, out string? problem)
    {
        problem = null;
        if (body.TryGetProperty("schemas", out var schemas) && !(schemas.ValueKind == JsonValueKind.Array && schemas.EnumerateArray().Any(s => s.ValueKind == JsonValueKind.String && s.GetString() == ScimService.PatchSchema)))
        { problem = "Invalid schemas for PatchOp"; return null; }
        if (!body.TryGetProperty("schemas", out _)) { problem = "Invalid schemas for PatchOp"; return null; }
        if (!body.TryGetProperty("Operations", out var ops) || ops.ValueKind != JsonValueKind.Array || ops.GetArrayLength() == 0) { problem = "Operations must be a non-empty list"; return null; }
        var result = new List<(string, string?, JsonElement)>();
        foreach (var op in ops.EnumerateArray())
        {
            var name = (Str(op, "op") ?? "replace").ToLowerInvariant();
            if (name is not ("add" or "remove" or "replace")) { problem = $"Unsupported operation \"{name}\""; return null; }
            result.Add((name, Str(op, "path"), op.TryGetProperty("value", out var v) ? v.Clone() : default));
        }
        return result;
    }

    private static bool TryGroup(JsonElement body, out string? name, out string? externalId, out List<string> members)
    {
        name = Str(body, "displayName")?.Trim();
        externalId = body.TryGetProperty("externalId", out var e) && e.ValueKind == JsonValueKind.String ? e.GetString()!.Trim() : null;
        members = [];
        if (string.IsNullOrEmpty(name)) return false;
        if (externalId is { Length: 0 }) return false;
        if (body.TryGetProperty("members", out var list))
        {
            if (list.ValueKind != JsonValueKind.Array) return false;
            foreach (var m in list.EnumerateArray())
            {
                if (Str(m, "value")?.Trim() is not { Length: > 0 } v) return false;
                members.Add(v);
            }
        }
        return true;
    }

    private static List<string> MemberValues(JsonElement value) =>
        value.ValueKind == JsonValueKind.Array ? value.EnumerateArray().Select(m => Str(m, "value")?.Trim()).Where(v => !string.IsNullOrEmpty(v)).Select(v => v!).ToList() : [];

    private static (string Name, string? ExternalId, List<string> Members) ApplyGroupPatch(ScimGroup group, IReadOnlyList<string> current, List<(string Op, string? Path, JsonElement Value)> operations)
    {
        var name = group.DisplayName;
        var externalId = group.ExternalId;
        var members = current.ToList();
        foreach (var (op, rawPath, value) in operations)
        {
            var path = rawPath?.Trim() ?? "";
            if (path.Length == 0 && value.ValueKind == JsonValueKind.Object)
            {
                if (Str(value, "displayName") is { } d) name = d;
                if (value.TryGetProperty("externalId", out var ext)) externalId = ext.ValueKind == JsonValueKind.String ? ext.GetString() : null;
                if (value.TryGetProperty("members", out var m) && m.ValueKind == JsonValueKind.Array)
                    members = op == "add" ? members.Union(MemberValues(m)).ToList() : MemberValues(m);
                continue;
            }
            switch (path.ToLowerInvariant())
            {
                case "displayname": name = op == "remove" ? "" : value.ValueKind == JsonValueKind.String ? value.GetString()! : name; continue;
                case "externalid": externalId = op == "remove" ? null : value.ValueKind == JsonValueKind.String ? value.GetString() : externalId; continue;
                case "members":
                    var patchMembers = MemberValues(value);
                    if (op == "add") members = members.Union(patchMembers).ToList();
                    else if (op == "replace") members = patchMembers;
                    else members = patchMembers.Count == 0 ? [] : members.Where(x => !patchMembers.Contains(x)).ToList();
                    continue;
            }
            if (op == "remove" && MemberPathPattern().Match(path) is { Success: true } mm) members = members.Where(x => x != mm.Groups[1].Value).ToList();
        }
        return (name, externalId, members);
    }
}
