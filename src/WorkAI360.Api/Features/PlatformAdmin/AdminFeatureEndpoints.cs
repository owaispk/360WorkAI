using System.Text.Json;

namespace WorkAI360.Api.Features.PlatformAdmin;

/// <summary>The feature registry for the operator: what each feature is, whether it is on for everyone, the kill switch, and operator locks.</summary>
public static class AdminFeatureEndpoints
{
    public static void MapAdminFeatureEndpoints(this WebApplication app)
    {
        app.MapGet("/v1/admin/features", async (HttpContext ctx, PlatformAdminGuard guard, FeatureResolver resolver, FeatureChanges changes) =>
        {
            var (_, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            var rollouts = await resolver.RolloutsAsync();
            var latest = await changes.LatestAsync();
            return Results.Json(new { deployment = FeatureCatalog.Deployment, features = FeatureCatalog.All.Select(f => Describe(f, resolver, rollouts, latest)) });
        });

        app.MapPut("/v1/admin/features/{key}", async (string key, HttpContext ctx, PlatformAdminGuard guard, FeatureResolver resolver, FeatureChanges changes) =>
        {
            var (admin, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            if (FeatureCatalog.Find(key) is not { } feature) return AdminSupport.Invalid("Unknown feature.");
            var body = await AdminBody.ReadAsync(ctx);
            if (AdminBody.NotObject(body) is { } notObject) return AdminSupport.Invalid(notObject);
            var root = body!.Value;
            var extra = root.EnumerateObject().Select(p => p.Name).Where(n => n is not ("enabled" or "killed")).ToList();
            if (extra.Count > 0) return AdminSupport.Invalid(extra.Count == 1 ? $"Unrecognized key: \"{extra[0]}\"" : $"Unrecognized keys: {string.Join(", ", extra.Select(n => $"\"{n}\""))}");
            bool? enabled = null, killed = null;
            foreach (var name in new[] { "enabled", "killed" })
            {
                if (!root.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Undefined) continue;
                if (value.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) return AdminSupport.Invalid($"Invalid input: expected boolean, received {AdminBody.Kind(value)}");
                if (name == "enabled") enabled = value.GetBoolean(); else killed = value.GetBoolean();
            }
            if (enabled is null && killed is null) return AdminSupport.Invalid("Set enabled, killed, or both.");
            if (!feature.Available) return AdminSupport.Invalid($"{key} is not part of this deployment.");

            await changes.SetRolloutAsync(feature, enabled, killed, admin!.User.Id);
            var rollouts = await resolver.RolloutsAsync();
            return Results.Json(new { ok = true, feature = Describe(feature, resolver, rollouts, await changes.LatestAsync()) });
        });
    }

    private static object Describe(FeatureInfo f, FeatureResolver resolver, IReadOnlyDictionary<string, FeatureResolver.Rollout> rollouts, IReadOnlyDictionary<string, object?> latest)
    {
        var rollout = resolver.RolloutOf(f.Key, rollouts);
        return new
        {
            key = f.Key, label = f.Label, description = f.Description, category = f.Category, categoryLabel = f.CategoryLabel, added = f.Added, since = f.Since, author = f.Author,
            docs = f.Docs, docsUrl = f.DocsUrl, deployments = f.Deployments, @default = f.Default, available = f.Available, enabled = rollout.Enabled, killed = rollout.Killed,
            @lock = resolver.Lock(f.Key), lastChange = latest.GetValueOrDefault(f.Key),
        };
    }
}
