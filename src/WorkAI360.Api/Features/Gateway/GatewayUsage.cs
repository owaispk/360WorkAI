using System.Globalization;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Gateway;

namespace WorkAI360.Api.Features.Gateway;

/// <summary>
/// Gateway usage, read back from LiteLLM's request logs (<c>/spend/logs/v2</c>, filtered to each provider's team) and attributed to people through
/// the token hashes of the keys Den issued. Tokens and cost are LiteLLM's numbers; a request LiteLLM priced at zero is "unpriced".
/// </summary>
public sealed class GatewayUsage(DenDbContext db, GatewayService gateway)
{
    public sealed record Row(string ProviderId, string ProviderName, string OrganizationId, string? MemberId, string? Model, long Tokens, double Spend, bool Success, DateOnly Day);

    public async Task<List<Row>> RowsAsync(IReadOnlyList<GatewayProvider> providers, DateOnly from, DateOnly toInclusive, CancellationToken ct)
    {
        var rows = new List<Row>();
        foreach (var p in providers)
        {
            if (p.LiteLlmTeamId is null) continue;
            var owners = await db.Set<GatewayIssuedKey>().AsNoTracking().Where(k => k.GatewayProviderId == p.Id).ToDictionaryAsync(k => k.TokenHash, k => k.MemberId, ct);
            var logs = await GatewayService.CallAsync(() => gateway.ClientFor(p).SpendLogsAsync(from, toInclusive.AddDays(1), p.LiteLlmTeamId, ct));
            foreach (var l in logs)
            {
                // A row counts for this provider only when LiteLLM put it in the provider's team or it was made with a key Den issued for the provider:
                // rows of the proxy's other keys (no team, another team) are never attributed here.
                if (l.TeamId != p.LiteLlmTeamId && !owners.ContainsKey(l.TokenHash)) continue;
                var day = DateOnly.FromDateTime(l.StartTime);
                if (day < from || day > toInclusive) continue;
                rows.Add(new Row(p.Id, p.Name, p.OrganizationId, owners.GetValueOrDefault(l.TokenHash), l.Model, l.TotalTokens, l.Spend, !string.Equals(l.Status, "failure", StringComparison.OrdinalIgnoreCase), day));
            }
        }
        return rows;
    }

    public static long Micro(double usd) => (long)Math.Round(usd * 1_000_000, MidpointRounding.AwayFromZero);
    public static string Day(DateOnly d) => d.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    /// <summary>The reference's <c>GET /v1/inference-providers/usage</c> answer for one workspace, grouped by provider ("model"), person or team.</summary>
    public async Task<object> WorkspaceAsync(string orgId, string groupBy, int days, IReadOnlyCollection<string> filterIds, string? memberId, CancellationToken ct)
    {
        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        var from = today.AddDays(1 - days);
        var providers = await db.Set<GatewayProvider>().AsNoTracking().Where(p => p.OrganizationId == orgId).ToListAsync(ct);
        var rows = (await RowsAsync(providers, from, today, ct)).Where(r => memberId is null || r.MemberId == memberId).ToList();

        var people = await (from m in db.Members.AsNoTracking() join u in db.Users.AsNoTracking() on m.UserId equals u.Id where m.OrganizationId == orgId select new { m.Id, u.Name, u.Email }).ToListAsync(ct);
        var teams = await db.Teams.AsNoTracking().Where(t => t.OrganizationId == orgId).Select(t => new { t.Id, t.Name }).ToListAsync(ct);
        var teamIds = teams.Select(t => t.Id).ToList();
        var memberTeams = (await db.TeamMembers.AsNoTracking().Where(tm => teamIds.Contains(tm.TeamId)).ToListAsync(ct)).GroupBy(t => t.MemberId).ToDictionary(g => g.Key, g => g.Select(t => t.TeamId).ToList());

        IEnumerable<string> SeriesOf(Row r) => groupBy switch
        {
            "person" => [r.MemberId ?? "unknown"],
            "team" => r.MemberId is not null && memberTeams.TryGetValue(r.MemberId, out var ts) ? ts : [],
            _ => [r.ProviderId],
        };
        string Label(string id) => groupBy switch
        {
            "person" => people.FirstOrDefault(p => p.Id == id) is { } p ? (string.IsNullOrWhiteSpace(p.Name) ? p.Email : p.Name) : "Former member",
            "team" => teams.FirstOrDefault(t => t.Id == id)?.Name ?? "Former team",
            _ => providers.FirstOrDefault(p => p.Id == id)?.Name ?? "Deleted provider",
        };

        var ok = rows.Where(r => r.Success).ToList();
        var keep = ok.Where(r => filterIds.Count == 0 || SeriesOf(r).Any(filterIds.Contains)).ToList();
        var seriesIds = keep.SelectMany(SeriesOf).Distinct().OrderBy(Label, StringComparer.OrdinalIgnoreCase).ToList();
        var allSeries = ok.SelectMany(SeriesOf).Distinct().ToList();
        var daily = Enumerable.Range(0, days).Select(i => from.AddDays(i)).Select(d =>
        {
            var dayRows = keep.Where(r => r.Day == d).ToList();
            var values = new JsonObject();
            var costs = new JsonObject();
            foreach (var id in seriesIds)
            {
                var mine = dayRows.Where(r => SeriesOf(r).Contains(id)).ToList();
                if (mine.Count == 0) continue;
                values[id] = mine.Sum(r => r.Tokens);
                costs[id] = mine.Any(r => r.Spend == 0 && r.Tokens > 0) && mine.All(r => r.Spend == 0) ? null : Micro(mine.Sum(r => r.Spend));
            }
            return new { date = Day(d), totalTokens = dayRows.Sum(r => r.Tokens), values, totalCostMicroUsd = Micro(dayRows.Sum(r => r.Spend)), costValues = costs };
        }).ToList();
        var options = groupBy switch
        {
            "person" => people.Select(p => new { id = p.Id, label = string.IsNullOrWhiteSpace(p.Name) ? p.Email : p.Name }).ToList(),
            "team" => teams.Select(t => new { id = t.Id, label = t.Name }).ToList(),
            _ => providers.Select(p => new { id = p.Id, label = p.Name }).ToList(),
        };
        return new
        {
            usage = new
            {
                groupBy, days, from = Day(from), to = Day(today), timezone = "UTC",
                requestCount = keep.Count,
                uncountableRequests = new { ok = (long?)null, upstream_error = (long?)null, upstream_unreachable = (long?)null, client_aborted = (long?)null, rejected = (long?)rows.Count(r => !r.Success) },
                totalTokens = keep.Sum(r => r.Tokens),
                unreportedRequests = keep.Count(r => r.Tokens == 0),
                totalCostMicroUsd = Micro(keep.Sum(r => r.Spend)),
                unpricedRequests = keep.Count(r => r.Tokens > 0 && r.Spend == 0),
                series = seriesIds.Select(id => new { id, label = Label(id) }),
                daily,
                filterOptions = options.OrderBy(o => o.label, StringComparer.OrdinalIgnoreCase),
                emptyReason = groupBy == "team" && teams.Count == 0 ? "no_teams" : null,
                seriesCount = allSeries.Count,
            },
        };
    }

    /// <summary>The platform admin dashboard's 30 days of usage across every workspace (the reference's readAdminGatewayDashboard).</summary>
    public async Task<object> PlatformAsync(CancellationToken ct)
    {
        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        var from = today.AddDays(-29);
        var providers = await db.Set<GatewayProvider>().AsNoTracking().ToListAsync(ct);
        var rows = new List<Row>();
        foreach (var p in providers)
        {
            try { rows.AddRange(await RowsAsync([p], from, today, ct)); }
            catch (GatewayError) { /* a proxy that cannot be read leaves its workspace out rather than failing the dashboard */ }
        }
        var ok = rows.Where(r => r.Success).ToList();
        object Totals(IReadOnlyCollection<Row> set) => new
        {
            requests = set.Count, tokens = set.Sum(r => r.Tokens), costMicroUsd = Micro(set.Sum(r => r.Spend)),
            unreportedRequests = set.Count(r => r.Tokens == 0), unpricedRequests = set.Count(r => r.Tokens > 0 && r.Spend == 0),
        };
        var orgIds = ok.Select(r => r.OrganizationId).Distinct().ToList();
        var names = await db.Organizations.AsNoTracking().Where(o => orgIds.Contains(o.Id)).ToDictionaryAsync(o => o.Id, o => o.Name, ct);
        return new
        {
            from = Day(from), to = Day(today), activeOrganizations = orgIds.Count, totals = Totals(ok),
            daily = Enumerable.Range(0, 30).Select(i => from.AddDays(i)).Select(d =>
            {
                var set = ok.Where(r => r.Day == d).ToList();
                return new { date = Day(d), requests = set.Count, tokens = set.Sum(r => r.Tokens), costMicroUsd = Micro(set.Sum(r => r.Spend)), unreportedRequests = set.Count(r => r.Tokens == 0), unpricedRequests = set.Count(r => r.Tokens > 0 && r.Spend == 0) };
            }),
            organizations = ok.GroupBy(r => r.OrganizationId).OrderByDescending(g => g.Count()).ThenBy(g => g.Key, StringComparer.Ordinal).Take(8).Select(g => new
            {
                id = g.Key, name = names.GetValueOrDefault(g.Key, "Deleted organization"), requests = g.Count(), tokens = g.Sum(r => r.Tokens), costMicroUsd = Micro(g.Sum(r => r.Spend)),
                unreportedRequests = g.Count(r => r.Tokens == 0), unpricedRequests = g.Count(r => r.Tokens > 0 && r.Spend == 0),
            }),
        };
    }
}
