using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.PlatformAdmin;
using WorkAI360.Api.Features.OrgAdmin;

namespace WorkAI360.Api.Features.PlatformAdmin;

/// <summary>One feature of the registry as /admin describes it (generated from the reference: see <c>FeatureCatalog.g.cs</c>).</summary>
public sealed record FeatureInfo(string Key, string Label, string Description, string Category, string CategoryLabel, string Added, string Since, string Author,
    string? Docs, string? DocsUrl, string[] Deployments, bool Default)
{
    /// <summary>This build is always a self-hosted deployment.</summary>
    public bool Available => Deployments.Contains("self_hosted");
}

public static partial class FeatureCatalog
{
    public static readonly string Deployment = "self_hosted";
    private static Dictionary<string, FeatureInfo>? _byKey;

    public static FeatureInfo? Find(string key) => (_byKey ??= All.ToDictionary(f => f.Key, StringComparer.Ordinal)).GetValueOrDefault(key);
}

/// <summary>How one feature resolved, and why (the reference's ResolvedFeature).</summary>
public sealed record ResolvedFeature(string Key, bool Enabled, string Source, bool Everyone, bool Killed, bool? Lock, bool? Override, bool OverrideApplies);

/// <summary>
/// Decides whether each feature is on, in the reference's order: not part of this deployment (off), kill switch (off), operator lock (as set:
/// <c>Features:Overrides:&lt;key&gt;</c> in configuration), the workspace's override, then on or off for everyone (the stored rollout, else this
/// build's default from <see cref="FeatureState.Default"/>).
/// </summary>
public sealed class FeatureResolver(DenDbContext db, IConfiguration configuration)
{
    public sealed record Rollout(bool Enabled, bool Killed);

    public async Task<Dictionary<string, Rollout>> RolloutsAsync() =>
        (await db.Set<PlatformFeatureRollout>().AsNoTracking().ToListAsync()).ToDictionary(r => r.FeatureKey, r => new Rollout(r.Enabled, r.Killed), StringComparer.Ordinal);

    public async Task<Dictionary<string, bool>> OverridesAsync(string organizationId) =>
        (await db.Set<PlatformOrganizationFeature>().AsNoTracking().Where(o => o.OrganizationId == organizationId).ToListAsync()).ToDictionary(o => o.FeatureKey, o => o.Enabled, StringComparer.Ordinal);

    public bool? Lock(string key) => bool.TryParse(configuration.GetSection("Features:Overrides")[key], out var value) ? value : null;

    public Rollout RolloutOf(string key, IReadOnlyDictionary<string, Rollout> rollouts) => rollouts.GetValueOrDefault(key) ?? new Rollout(FeatureState.Default(key), false);

    public ResolvedFeature Resolve(FeatureInfo feature, IReadOnlyDictionary<string, Rollout> rollouts, IReadOnlyDictionary<string, bool> overrides)
    {
        var rollout = RolloutOf(feature.Key, rollouts);
        var @lock = Lock(feature.Key);
        bool? over = overrides.TryGetValue(feature.Key, out var stored) ? stored : null;
        if (!feature.Available) return new(feature.Key, false, "unavailable", rollout.Enabled, rollout.Killed, @lock, over, false);
        if (rollout.Killed) return new(feature.Key, false, "killed", rollout.Enabled, true, @lock, over, false);
        if (@lock is { } locked) return new(feature.Key, locked, "lock", rollout.Enabled, false, @lock, over, false);
        if (over is { } overridden) return new(feature.Key, overridden, "override", rollout.Enabled, false, null, over, true);
        return new(feature.Key, rollout.Enabled, "everyone", rollout.Enabled, false, null, null, true);
    }

    public async Task<IReadOnlyList<ResolvedFeature>> DescribeAsync(string? organizationId)
    {
        var rollouts = await RolloutsAsync();
        var overrides = organizationId is null ? new Dictionary<string, bool>() : await OverridesAsync(organizationId);
        return FeatureCatalog.All.Select(f => Resolve(f, rollouts, overrides)).ToList();
    }

    /// <summary>On or off for every feature, for one workspace (or for everyone when none is given). Order: the registry's.</summary>
    public async Task<Dictionary<string, bool>> EffectiveAsync(string? organizationId) =>
        (await DescribeAsync(organizationId)).ToDictionary(r => r.Key, r => r.Enabled);
}
