using System.Reflection;

namespace WorkAI360.Api.Features;

/// <summary>
/// A self-contained area of the API (its services and its routes). Any public class implementing this interface with a parameterless
/// constructor is found at startup and wired in, so adding an area means adding files, not editing <c>Program.cs</c>.
/// Entities go in <c>Domain/</c> with an <c>IEntityTypeConfiguration&lt;T&gt;</c> (picked up the same way); read and write them with
/// <c>db.Set&lt;T&gt;()</c>.
/// </summary>
public interface IFeature
{
    void AddServices(IServiceCollection services, IConfiguration configuration);

    void MapEndpoints(WebApplication app);
}

public static class FeatureRegistry
{
    /// <summary>All features in the assembly, in a fixed (alphabetical) order.</summary>
    public static IReadOnlyList<IFeature> Discover() =>
        typeof(IFeature).Assembly.GetTypes()
            .Where(t => t is { IsClass: true, IsAbstract: false } && typeof(IFeature).IsAssignableFrom(t) && t.GetConstructor(Type.EmptyTypes) is not null)
            .OrderBy(t => t.FullName, StringComparer.Ordinal)
            .Select(t => (IFeature)Activator.CreateInstance(t)!)
            .ToList();
}
