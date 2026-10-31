using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.OrgAdmin;

namespace WorkAI360.Api.Features.OrgAdmin;

/// <summary>The extra organization fields (allowed email domains, metadata with brand fields) live in their own table; this reads and writes them.</summary>
public static partial class OrgSettings
{
    [GeneratedRegex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")]
    private static partial Regex DomainPattern();

    public static async Task<OrganizationSettings?> GetAsync(DenDbContext db, string organizationId) =>
        await db.Set<OrganizationSettings>().AsNoTracking().FirstOrDefaultAsync(s => s.OrganizationId == organizationId);

    public static string[]? Domains(OrganizationSettings? settings) =>
        settings?.AllowedEmailDomainsJson is { } json ? JsonSerializer.Deserialize<string[]>(json) : null;

    public static JsonObject Metadata(OrganizationSettings? settings) =>
        settings?.MetadataJson is { } json && JsonNode.Parse(json) is JsonObject o ? o : new JsonObject();

    /// <summary>Lower-cases, strips a leading "@", sorts and de-duplicates. Anything that is not a plain domain is reported back as invalid. Empty means "anyone".</summary>
    public static (string[]? Domains, List<string> Invalid) NormalizeDomains(IEnumerable<string>? input)
    {
        var list = input?.ToList() ?? [];
        if (list.Count == 0) return (null, []);
        var good = new SortedSet<string>(StringComparer.Ordinal);
        var invalid = new List<string>();
        foreach (var value in list)
        {
            var normalized = value.Trim().ToLowerInvariant().TrimStart('@');
            if (normalized.Length == 0 || !DomainPattern().IsMatch(normalized)) invalid.Add(value);
            else good.Add(normalized);
        }
        return (good.Count > 0 ? [.. good] : null, invalid);
    }

    /// <summary>Whether an address may join: always true when no restriction is set.</summary>
    public static bool IsAllowed(string[]? domains, string email)
    {
        if (domains is null || domains.Length == 0) return true;
        var at = email.LastIndexOf('@');
        return at > 0 && domains.Contains(email[(at + 1)..].Trim().ToLowerInvariant());
    }

    public static string RestrictionMessage(string[] domains) => domains.Length == 1
        ? $"This workspace only allows {domains[0]} email addresses."
        : $"This workspace only allows email addresses from these domains: {string.Join(", ", domains)}.";

    public static string? EmailDomain(string email) => email.Contains('@') ? email[(email.LastIndexOf('@') + 1)..].ToLowerInvariant() : null;

    /// <summary>The body of the 409 given when an address is outside the allowed domains.</summary>
    public static object Restriction(string error, string[] domains, string email) =>
        new { error, message = RestrictionMessage(domains), emailDomain = EmailDomain(email), allowedEmailDomains = domains };
}
