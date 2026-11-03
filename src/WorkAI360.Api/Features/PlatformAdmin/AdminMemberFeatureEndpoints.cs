using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Features.OrgAdmin;

namespace WorkAI360.Api.Features.PlatformAdmin;

/// <summary>
/// Per-member feature overrides (the reference's <c>routes/admin/member-features.ts</c>). A platform admin turns a feature on or off for one person
/// in one workspace; it wins over the workspace's override and the deployment-wide state, but not over "not part of this deployment", the kill
/// switch or an operator lock.
/// </summary>
public static class AdminMemberFeatureEndpoints
{
    private const string Path = "/v1/admin/organizations/{organizationId}/members/{memberId}/capabilities";
    private const string NotFoundMessage = "Active organization member not found.";

    public static void MapAdminMemberFeatureEndpoints(this WebApplication app)
    {
        app.MapGet(Path, async (string organizationId, string memberId, HttpContext ctx, PlatformAdminGuard guard, FeatureResolver resolver, FeatureChanges changes) =>
        {
            var (_, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            if (!ValidIds(organizationId, memberId)) return InvalidIds();
            var userId = await changes.ActiveMemberQuery(organizationId, memberId).Select(m => m.UserId).FirstOrDefaultAsync();
            if (userId is null) return AdminSupport.NotFound(NotFoundMessage);
            return Results.Json(new { featureStates = await StatesAsync(resolver, changes, organizationId, memberId, userId) });
        });

        app.MapPut(Path, async (string organizationId, string memberId, HttpContext ctx, PlatformAdminGuard guard, FeatureResolver resolver, FeatureChanges changes, IAuditLog audit) =>
        {
            var (admin, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            if (!ValidIds(organizationId, memberId)) return InvalidIds();
            var body = await AdminBody.ReadAsync(ctx);
            if (AdminBody.NotObject(body) is { } notObject) return AdminSupport.Invalid(notObject);
            // Strict, as the reference: only `capabilities`, and inside it only registry keys, each true, false or null (clear).
            foreach (var property in body!.Value.EnumerateObject())
                if (property.Name != "capabilities") return AdminSupport.Invalid($"Unrecognized key: \"{property.Name}\"");
            var capabilities = AdminBody.Get(body.Value, "capabilities");
            if (capabilities is not { ValueKind: JsonValueKind.Object } caps) return AdminSupport.Invalid($"Invalid input: expected object, received {AdminBody.Kind(capabilities)}");
            var requested = new List<(FeatureInfo Feature, bool? Value)>();
            foreach (var property in caps.EnumerateObject())
            {
                if (FeatureCatalog.Find(property.Name) is not { } feature) return AdminSupport.Invalid($"Unrecognized key: \"{property.Name}\"");
                if (property.Value.ValueKind is not (JsonValueKind.True or JsonValueKind.False or JsonValueKind.Null))
                    return AdminSupport.Invalid($"Invalid input: expected boolean, received {AdminBody.Kind(property.Value)}");
                var value = property.Value.ValueKind == JsonValueKind.Null ? (bool?)null : property.Value.GetBoolean();
                if (value is not null && !feature.Available) return AdminSupport.Invalid($"{feature.Key} is not part of this deployment.");
                requested.Add((feature, value));
            }

            if (!await changes.SetMemberOverridesAsync(organizationId, memberId, requested, admin!.User.Id)) return AdminSupport.NotFound(NotFoundMessage);
            var userId = await changes.ActiveMemberQuery(organizationId, memberId).Select(m => m.UserId).FirstOrDefaultAsync();
            if (userId is null) return AdminSupport.NotFound(NotFoundMessage);
            if (requested.Count > 0)
                await audit.RecordAsync(organizationId, AuditActor.User(admin.User.Id), new AuditEntry(AuditActions.MemberCapabilitiesUpdated,
                    [new("member", memberId, "target")],
                    After: new JsonObject(requested.Select(r => new KeyValuePair<string, JsonNode?>(r.Feature.Key, r.Value is { } v ? JsonValue.Create(v) : null))), Origin: "platform_admin"));
            return Results.Json(new { featureStates = await StatesAsync(resolver, changes, organizationId, memberId, userId) });
        });
    }

    private static bool ValidIds(string organizationId, string memberId) => AdminSupport.LooksLikeOrganizationId(organizationId) && memberId.StartsWith("om_", StringComparison.Ordinal);

    private static IResult InvalidIds() => Results.Json(new { error = "invalid_request", message = "Invalid organization or member id." }, statusCode: 400);

    /// <summary>
    /// Each feature for this member. <c>override</c> is the member's own setting (null inherits) and <c>everyone</c> is what they would get without
    /// it (the workspace's value), so the editor's "reset" shows where the feature goes back to.
    /// </summary>
    private static async Task<Dictionary<string, object?>> StatesAsync(FeatureResolver resolver, FeatureChanges changes, string organizationId, string memberId, string userId)
    {
        var rollouts = await resolver.RolloutsAsync();
        var overrides = await resolver.OverridesAsync(organizationId);
        var mine = await resolver.MemberOverridesAsync(organizationId, userId);
        var latest = await changes.LatestAsync(organizationId, memberId);
        var map = new Dictionary<string, object?>();
        foreach (var feature in FeatureCatalog.All)
        {
            var inherited = resolver.Resolve(feature, rollouts, overrides);
            var state = resolver.Resolve(feature, rollouts, overrides, mine);
            map[feature.Key] = new Dictionary<string, object?>
            {
                ["enabled"] = state.Enabled, ["source"] = state.Source, ["everyone"] = inherited.Enabled, ["killed"] = state.Killed, ["lock"] = state.Lock,
                ["override"] = mine.TryGetValue(feature.Key, out var v) ? v : null, ["overrideApplies"] = state.OverrideApplies, ["lastChange"] = latest.GetValueOrDefault(feature.Key),
            };
        }
        return map;
    }
}
