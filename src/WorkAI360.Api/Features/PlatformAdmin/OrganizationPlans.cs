using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.PlatformAdmin;

namespace WorkAI360.Api.Features.PlatformAdmin;

/// <summary>A workspace's plan as platform admins recorded it. Nothing here is billed or enforced: no payment service is called.</summary>
public sealed record PlanState(string Tier, string Source, int? Seats, string? EndsAt, bool Ended, int SeatLimit, int SeatsFreeAdditional, bool? DpaSigned, bool ComplimentaryWebAccess, DateTime? UpdatedAt)
{
    public const int FreeSeats = 5;
    public const int MaxUsers = 100_000;
    public int FreeSeatCount => FreeSeats + SeatsFreeAdditional;

    public static PlanState From(PlatformOrganization? row)
    {
        if (row is null) return new("free", "default", null, null, false, FreeSeats, 0, null, false, null);
        var ended = row.PlanEndsAt is { } end && string.CompareOrdinal(end, DateTime.UtcNow.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)) < 0;
        return new(row.PlanTier ?? "free", row.PlanTier is null ? "default" : "manual", row.PlanSeats, row.PlanEndsAt, ended, row.SeatLimit, row.SeatsFreeAdditional, row.DpaSigned, row.ComplimentaryWebAccess, row.UpdatedAt);
    }

    /// <summary>The plan as GET /v1/admin/organizations/{id} reports it.</summary>
    public object Resolved(int users) => new { tier = Tier, source = Source, paidBy = "none", users, userLimit = (int?)null, seats = Seats, endsAt = EndsAt, ended = Ended };

    /// <summary>A YYYY-MM-DD date that exists, or null.</summary>
    public static string? NormalizeEndDate(string value) =>
        value.Length == 10 && DateOnly.TryParseExact(value, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var date) ? date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : null;
}

public sealed class OrganizationPlans(DenDbContext db)
{
    public async Task<PlanState> GetAsync(string organizationId) =>
        PlanState.From(await db.Set<PlatformOrganization>().AsNoTracking().FirstOrDefaultAsync(o => o.OrganizationId == organizationId));

    public async Task<Dictionary<string, PlanState>> GetManyAsync(IReadOnlyCollection<string> organizationIds) =>
        (await db.Set<PlatformOrganization>().AsNoTracking().Where(o => organizationIds.Contains(o.OrganizationId)).ToListAsync()).ToDictionary(o => o.OrganizationId, PlanState.From);

    /// <summary>The row for a workspace, created when an admin first records something about it. Call inside the caller's save.</summary>
    public async Task<PlatformOrganization> RowForUpdateAsync(string organizationId)
    {
        var row = await db.Set<PlatformOrganization>().FirstOrDefaultAsync(o => o.OrganizationId == organizationId);
        if (row is not null) return row;
        row = new PlatformOrganization { OrganizationId = organizationId, UpdatedAt = DateTime.UtcNow };
        db.Set<PlatformOrganization>().Add(row);
        return row;
    }

    /// <summary>
    /// Saves a plan: on Free the user limit is at least 5 and anything above 5 is extra free seats; on Team and Enterprise the seats are the limit (at least 5)
    /// and the extra free seats reset. Returns the seat limit the reference answers with.
    /// </summary>
    public async Task<(PlanState State, int SeatLimit)> SetPlanAsync(string organizationId, string tier, int seatLimit, string? endsAt)
    {
        var row = await RowForUpdateAsync(organizationId);
        var limit = Math.Max(PlanState.FreeSeats, seatLimit);
        row.PlanTier = tier;
        row.PlanEndsAt = tier == "free" ? null : endsAt;
        row.SeatLimit = limit;
        if (tier == "free") { row.PlanSeats = null; row.SeatsFreeAdditional = limit - PlanState.FreeSeats; }
        else { row.PlanSeats = limit; row.SeatsFreeAdditional = 0; }
        row.UpdatedAt = DateTime.UtcNow;
        await db.SaveChangesAsync();
        var state = PlanState.From(row);
        return (state, state.Seats ?? seatLimit);
    }
}

/// <summary>Request bodies of the admin routes, read and checked the way the reference's zod schemas do (first problem wins, plain message).</summary>
public static class AdminBody
{
    public static async Task<JsonElement?> ReadAsync(HttpContext ctx)
    {
        try
        {
            using var doc = await JsonDocument.ParseAsync(ctx.Request.Body);
            return doc.RootElement.Clone();
        }
        catch (JsonException) { return null; }
    }

    public static string Kind(JsonElement? e) => e is null ? "undefined" : e.Value.ValueKind switch
    {
        JsonValueKind.Null => "null", JsonValueKind.Number => "number", JsonValueKind.String => "string", JsonValueKind.Array => "array", JsonValueKind.Object => "object", _ => "boolean",
    };

    public static JsonElement? Get(JsonElement root, string name) => root.TryGetProperty(name, out var value) ? value : null;

    /// <summary>A message for a body that is not an object ("received null" for an unreadable one), or null when it is one.</summary>
    public static string? NotObject(JsonElement? body) => body is { ValueKind: JsonValueKind.Object } ? null : $"Invalid input: expected object, received {(body is null ? "null" : Kind(body))}";

    /// <summary>The message for an integer field out of range or of the wrong type, or null when fine.</summary>
    public static string? IntProblem(JsonElement? value, int min, int max)
    {
        if (value is not { ValueKind: JsonValueKind.Number } number) return $"Invalid input: expected number, received {Kind(value)}";
        if (!number.TryGetInt64(out var n)) return number.TryGetDouble(out var d) && d == Math.Floor(d) && !double.IsInfinity(d) ? $"Too {(d < 0 ? "small" : "big")}: expected number to be {(d < 0 ? ">=" + min : "<=" + max)}" : "Invalid input: expected int, received number";
        if (n < min) return $"Too small: expected number to be >={min}";
        if (n > max) return $"Too big: expected number to be <={max}";
        return null;
    }

    public static string? BoolProblem(JsonElement? value) => value is { ValueKind: JsonValueKind.True or JsonValueKind.False } ? null : $"Invalid input: expected boolean, received {Kind(value)}";

    /// <summary>A trimmed string of 3 to 500 characters (the reason an admin gives), or the reference's message.</summary>
    public static string? ReasonProblem(JsonElement? value, out string reason)
    {
        reason = "";
        if (value is not { ValueKind: JsonValueKind.String } s) return $"Invalid input: expected string, received {Kind(value)}";
        reason = s.GetString()!.Trim();
        if (reason.Length < 3) return "Too small: expected string to have >=3 characters";
        if (reason.Length > 500) return "Too big: expected string to have <=500 characters";
        return null;
    }
}
