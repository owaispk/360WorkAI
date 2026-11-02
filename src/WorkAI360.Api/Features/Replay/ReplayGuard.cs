using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Replay;

namespace WorkAI360.Api.Features.Replay;

/// <summary>Registers <see cref="ReplayGuard"/>.</summary>
public sealed class ReplayFeature : IFeature
{
    public void AddServices(IServiceCollection services, IConfiguration configuration) => services.AddScoped<ReplayGuard>();

    public void MapEndpoints(WebApplication app) { }
}

/// <summary>
/// "Has this value been seen?" backed by the database: a reservation is one row under a primary key, so exactly one of any number of
/// concurrent callers (on any instance) wins, and a stored reservation outlives a restart. Expired reservations are removed as they are met
/// and swept now and then.
/// </summary>
public sealed class ReplayGuard(DenDbContext db)
{
    /// <summary>The key stored for a value: kind and value are hashed together, so no stored row reveals or collides with another kind.</summary>
    public static string KeyFor(string kind, string value) => Ids.Sha256Hex(kind + "\n" + value);

    /// <summary>True when this is the first use of the value (it is now reserved until <paramref name="expiresAt"/>); false when it was already used.</summary>
    public async Task<bool> ReserveAsync(string kind, string value, DateTime expiresAt, CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        var id = KeyFor(kind, value);
        // A reservation that ran out no longer blocks the value (its signature or lifetime has expired anyway).
        await db.Set<ReplayReservation>().Where(r => r.Id == id && r.ExpiresAt <= now).ExecuteDeleteAsync(ct);
        var row = new ReplayReservation { Id = id, Kind = kind, ExpiresAt = expiresAt <= now ? now.AddMinutes(1) : expiresAt };
        db.Set<ReplayReservation>().Add(row);
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            // The key exists (or a parallel caller just took it): a replay. Detach our row so the context stays usable.
            db.Entry(row).State = EntityState.Detached;
            return false;
        }
        if (Random.Shared.Next(64) == 0) await db.Set<ReplayReservation>().Where(r => r.ExpiresAt <= now.AddMinutes(-5)).ExecuteDeleteAsync(ct);
        return true;
    }
}
