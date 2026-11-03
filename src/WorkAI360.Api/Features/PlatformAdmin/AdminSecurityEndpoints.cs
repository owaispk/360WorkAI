using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.OrgAdmin;
using WorkAI360.Api.Domain.PlatformAdmin;

namespace WorkAI360.Api.Features.PlatformAdmin;

public sealed record SecurityEntity(string Id, string Label, string? Detail, long Value, string Severity, object? Target);

public sealed record SecurityFinding(string Id, string Category, string Severity, string Title, string Summary, string Rule, string Why, string Review, long Value, string Unit, List<SecurityEntity> Entities, int EntityCount);

/// <summary>
/// The platform admin Security page (the reference's <c>GET /v1/admin/security</c>): threshold-based findings about accounts, credentials and use, each stating its rule,
/// from this database. They are prompts for review, not verdicts. The findings that need model-gateway usage (spend spikes, round-the-clock use, free allowance used on
/// day one) are always clear here, because this build has no gateway usage. Wording and thresholds are the reference's.
/// </summary>
public static partial class AdminSecurityEndpoints
{
    public const int EntityLimit = 20;
    private static readonly Dictionary<string, int> Rank = new() { ["high"] = 3, ["medium"] = 2, ["low"] = 1, ["clear"] = 0 };

    public static int SeverityRank(string severity) => Rank.GetValueOrDefault(severity);

    // ---- thresholds (the reference's) ----
    private static readonly (int High, int Medium) SignupNetwork = (15, 5);
    private static readonly (int High, int Medium, int Low) Disposable = (20, 5, 1);
    private static readonly (int High, int Medium) UnverifiedDomain = (20, 5);
    private static readonly (int High, int Medium, int Low) NetworkSpread = (30, 15, 8);
    private static readonly (int High, int Medium) OrganizationCreation = (15, 5);
    private static readonly (int High, int Medium) ApiKeyBurst = (20, 5);
    private static readonly (int High, int Medium) Invitations = (100, 25);
    private static readonly (int High, int Medium) AutomationSignIns = (20, 3);

    public static readonly string[] PersonalDomains =
    [
        "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "yahoo.fr", "yahoo.de", "yahoo.co.jp", "ymail.com", "rocketmail.com",
        "outlook.com", "hotmail.com", "hotmail.co.uk", "hotmail.fr", "live.com", "live.co.uk", "live.fr", "msn.com",
        "icloud.com", "me.com", "mac.com", "aol.com", "aim.com", "proton.me", "protonmail.com", "pm.me",
        "tuta.com", "tuta.io", "tutanota.com", "tutanota.de", "fastmail.com", "fastmail.fm", "hey.com",
        "mail.com", "email.com", "gmx.com", "gmx.net", "gmx.de", "web.de", "yandex.com", "yandex.ru", "ya.ru",
        "mail.ru", "inbox.ru", "bk.ru", "list.ru", "qq.com", "foxmail.com", "163.com", "126.com",
        "naver.com", "daum.net", "hanmail.net", "zoho.com", "rediffmail.com", "yopmail.com", "mailinator.com",
    ];

    private static readonly string[] DisposableDomains =
    [
        "mailinator.com", "yopmail.com", "guerrillamail.com", "guerrillamail.net", "sharklasers.com", "grr.la", "10minutemail.com",
        "temp-mail.org", "tempmail.com", "tempmail.dev", "tempmailo.com", "throwawaymail.com", "trashmail.com", "getnada.com",
        "dispostable.com", "maildrop.cc", "mailnesia.com", "mohmal.com", "emailondeck.com", "fakeinbox.com", "mintemail.com",
        "spamgourmet.com", "mytemp.email", "tempr.email", "discard.email", "burnermail.io", "inboxkitten.com", "1secmail.com",
    ];

    private static readonly (string Label, Regex Pattern)[] AutomationClients =
    [
        ("Headless Chrome", new("HeadlessChrome", RegexOptions.IgnoreCase)), ("Playwright", new("Playwright", RegexOptions.IgnoreCase)),
        ("Puppeteer", new("Puppeteer", RegexOptions.IgnoreCase)), ("Selenium or WebDriver", new("Selenium|WebDriver", RegexOptions.IgnoreCase)),
        ("PhantomJS", new("PhantomJS", RegexOptions.IgnoreCase)), ("Python script", new("python-requests|python-httpx|aiohttp|python-urllib", RegexOptions.IgnoreCase)),
        ("curl or Wget", new("^(?:curl|Wget)/", RegexOptions.IgnoreCase)), ("Go program", new("Go-http-client", RegexOptions.IgnoreCase)),
        ("Scrapy", new("Scrapy", RegexOptions.IgnoreCase)), ("Java program", new("Apache-HttpClient|Java-http-client", RegexOptions.IgnoreCase)),
        ("Postman", new("PostmanRuntime", RegexOptions.IgnoreCase)),
    ];

    // ---------------------------------------------------------------- helpers

    private static string Plural(long count, string one, string? many = null) => $"{count.ToString("N0", CultureInfo.InvariantCulture)} {(count == 1 ? one : many ?? one + "s")}";

    private static string Usd(long micro) => "$" + (micro / 1_000_000.0).ToString("N2", CultureInfo.InvariantCulture);

    private static string Tiered(long value, int? high = null, int? medium = null, int? low = null) =>
        high is { } h && value >= h ? "high" : medium is { } m && value >= m ? "medium" : low is { } l && value >= l ? "low" : "clear";

    public static SecurityFinding Finding(string id, string category, string title, string summary, string rule, string why, string review, long value, string unit, IEnumerable<SecurityEntity> entities)
    {
        var all = entities.ToList();
        var severity = all.Select(e => e.Severity).OrderByDescending(s => Rank[s]).FirstOrDefault() ?? "clear";
        var shown = all.OrderByDescending(e => Rank[e.Severity]).ThenByDescending(e => e.Value).Take(EntityLimit).ToList();
        return new(id, category, severity, title, summary, rule, why, review, value, unit, shown, all.Count);
    }

    /// <summary>The coarse network a sign-in came from (IPv4 /24, IPv6 /64), so a page never needs a full address.</summary>
    public static string? NetworkOf(string? ip)
    {
        var value = ip?.Trim().ToLowerInvariant() ?? "";
        if (value.StartsWith("::ffff:", StringComparison.Ordinal) && IPAddress.TryParse(value[7..], out var inner) && inner.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) value = value[7..];
        if (!IPAddress.TryParse(value.Split('%')[0], out var address)) return null;
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) return string.Join('.', address.ToString().Split('.').Take(3)) + ".0/24";
        var groups = address.GetAddressBytes();
        return string.Join(':', Enumerable.Range(0, 4).Select(i => ((groups[i * 2] << 8) | groups[i * 2 + 1]).ToString("x"))) + "::/64";
    }

    public static string? EmailDomain(string email)
    {
        var at = email.LastIndexOf('@');
        var domain = at > 0 ? email[(at + 1)..].Trim().ToLowerInvariant() : "";
        return Regex.IsMatch(domain, @"^[^@\s]+\.[^@\s]+$") ? domain : null;
    }

    private static string Sample(IReadOnlyList<string> emails) => emails.Count > 3 ? $"{string.Join(", ", emails.Take(3))} and {emails.Count - 3} more" : string.Join(", ", emails);

    private static object UserTarget(string userId) => new { type = "user", userId };

    private sealed record NewAccount(string UserId, string Email, bool EmailVerified, string? Network);

    // ---------------------------------------------------------------- the report

    public static async Task<object> ReadReportAsync(DenDbContext db, int days, DateTime now)
    {
        var from = now.AddDays(-days);
        var previousFrom = from.AddDays(-days);
        var accounts = await db.Users.AsNoTracking().Where(u => u.CreatedAt >= from).Select(u => new { u.Id, u.Email, u.EmailVerified }).ToListAsync();
        var accountIds = accounts.Select(a => a.Id).ToList();
        var firstSignIns = await db.Sessions.AsNoTracking().Where(s => accountIds.Contains(s.UserId)).Select(s => new { s.UserId, s.IpAddress, s.CreatedAt }).ToListAsync();
        var previous = await db.Users.AsNoTracking().Where(u => u.CreatedAt >= previousFrom && u.CreatedAt < from).Select(u => u.EmailVerified).ToListAsync();
        var sessions = await db.Sessions.AsNoTracking().Where(s => s.CreatedAt >= from).GroupBy(s => new { s.UserId, s.IpAddress, s.UserAgent }).Select(g => new { g.Key.UserId, g.Key.IpAddress, g.Key.UserAgent, SignIns = g.Count() }).ToListAsync();
        var owners = await db.Members.AsNoTracking().Where(m => m.CreatedAt >= from && m.Role.Contains("owner")).GroupBy(m => m.UserId).Select(g => new { UserId = g.Key, Organizations = g.Count() }).Where(o => o.Organizations >= OrganizationCreation.Medium).ToListAsync();
        var adminGrants = await db.Set<AdminAllowlistEntry>().AsNoTracking().Where(a => a.CreatedAt >= from).ToListAsync();
        var adminTotal = await db.Set<AdminAllowlistEntry>().CountAsync();
        var keyOwners = await db.Set<ApiKey>().AsNoTracking().Where(k => k.CreatedAt >= from).GroupBy(k => k.UserId).Select(g => new { OwnerId = g.Key, Keys = g.Count() }).Where(k => k.Keys >= ApiKeyBurst.Medium).ToListAsync();
        var enabledKeys = await db.Set<ApiKey>().CountAsync(k => k.Enabled);
        var clients = await db.OAuthClients.AsNoTracking().Where(c => c.CreatedAt >= previousFrom).Select(c => c.CreatedAt).ToListAsync();
        var inviters = await db.Invitations.AsNoTracking().Where(i => i.CreatedAt >= from).GroupBy(i => i.InvitedByUserId).Select(g => new { UserId = g.Key, Invitations = g.Count(), Organizations = g.Select(i => i.OrganizationId).Distinct().Count() }).Where(i => i.Invitations >= Invitations.Medium).ToListAsync();

        // The earliest sign-in on record stands for where each new account came from.
        var firstNetwork = firstSignIns.GroupBy(s => s.UserId).ToDictionary(g => g.Key, g => NetworkOf(g.OrderBy(s => s.CreatedAt).First().IpAddress));
        var newAccounts = accounts.Select(a => new NewAccount(a.Id, a.Email, a.EmailVerified, firstNetwork.GetValueOrDefault(a.Id))).ToList();

        var spread = sessions.GroupBy(s => s.UserId).Select(g => new
        {
            UserId = g.Key, Networks = g.Select(s => NetworkOf(s.IpAddress)).Where(n => n is not null).Distinct().Count(),
            Clients = g.Select(s => s.UserAgent).Where(a => !string.IsNullOrEmpty(a)).Distinct().Count(), SignIns = g.Sum(s => s.SignIns),
        }).Where(s => s.Networks >= NetworkSpread.Low).ToList();
        var newIds = accountIds.ToHashSet();
        var automationRows = sessions.Select(s => (s.UserId, Client: AutomationClients.FirstOrDefault(c => !string.IsNullOrWhiteSpace(s.UserAgent) && c.Pattern.IsMatch(s.UserAgent!.Trim())).Label, s.SignIns)).Where(r => r.Client is not null).ToList();

        var userIds = spread.Select(s => s.UserId).Concat(owners.Select(o => o.UserId)).Concat(keyOwners.Select(k => k.OwnerId)).Concat(inviters.Select(i => i.UserId)).Concat(automationRows.Select(r => r.UserId)).Distinct().ToList();
        var emails = await db.Users.AsNoTracking().Where(u => userIds.Contains(u.Id)).ToDictionaryAsync(u => u.Id, u => u.Email);
        string EmailOf(string userId) => emails.GetValueOrDefault(userId) ?? userId;
        var personal = PersonalDomains.ToHashSet();

        var findings = new List<SecurityFinding>
        {
            SignupNetworks(newAccounts, personal),
            UnverifiedSignups(newAccounts, previous.Count, previous.Count(v => !v)),
            DisposableSignups(newAccounts),
            UnverifiedDomains(newAccounts, personal),
            NetworkSpreadFinding(spread.Select(s => (s.UserId, EmailOf(s.UserId), s.Networks, s.SignIns, s.Clients))),
            OrganizationCreationFinding(owners.Select(o => (o.UserId, EmailOf(o.UserId), o.Organizations))),
            AdminGrantFinding(adminGrants, adminTotal),
            ApiKeyFinding(keyOwners.Select(k => (k.OwnerId, EmailOf(k.OwnerId), k.Keys)), enabledKeys, 0),
            ClientRegistrationFinding(clients.Count(c => c >= from), clients.Count(c => c < from)),
            InvitationFinding(inviters.Select(i => (i.UserId, EmailOf(i.UserId), i.Invitations, i.Organizations))),
            SpendSpikes(),
            AutomationClientFinding(automationRows.Select(r => (r.UserId, EmailOf(r.UserId), r.Client!, r.SignIns, newIds.Contains(r.UserId)))),
            RoundTheClock(),
            InstantAllowance(),
        };
        return new
        {
            generatedAt = Responses.IsoUtc(now), range = new { days, from = Responses.IsoUtc(from), to = Responses.IsoUtc(now) },
            findings = findings.OrderByDescending(f => Rank[f.Severity]).Select(Json),
        };
    }

    public static object FindingJson(SecurityFinding f) => Json(f);

    private static object Json(SecurityFinding f) => new
    {
        id = f.Id, category = f.Category, severity = f.Severity, title = f.Title, summary = f.Summary, rule = f.Rule, why = f.Why, review = f.Review, value = f.Value, unit = f.Unit,
        entities = f.Entities.Select(e => new { id = e.Id, label = e.Label, detail = e.Detail, value = e.Value, severity = e.Severity, target = e.Target }), entityCount = f.EntityCount,
    };

    // ---------------------------------------------------------------- the findings

    private static SecurityFinding SignupNetworks(List<NewAccount> accounts, HashSet<string> personal)
    {
        var entities = new List<SecurityEntity>();
        foreach (var group in accounts.Where(a => a.Network is not null).GroupBy(a => a.Network!))
        {
            var members = group.ToList();
            var severity = Tiered(members.Count, SignupNetwork.High, SignupNetwork.Medium);
            if (severity == "clear") continue;
            var domains = members.Where(m => m.EmailVerified).Select(m => EmailDomain(m.Email)).Where(d => d is not null && !personal.Contains(d)).GroupBy(d => d!).Select(g => (Domain: g.Key, Count: g.Count())).OrderByDescending(d => d.Count).ToList();
            var team = domains.Count > 0 && (double)domains[0].Count / members.Count >= 0.8;
            if (team) severity = "low";
            var verified = members.Count(m => m.EmailVerified);
            entities.Add(new(group.Key, group.Key, $"{(team ? $"Mostly verified {domains[0].Domain} addresses. " : "")}{Plural(verified, "verified address", "verified addresses")}: {Sample(members.Select(m => m.Email).ToList())}", members.Count, severity, null));
        }
        return Finding("signup-networks", "accounts", "Sign-up bursts from one network",
            entities.Count > 0 ? $"{Plural(entities.Count, "network")} created {SignupNetwork.Medium} or more accounts." : "No network created more than a few accounts.",
            $"Flags a network (IPv4 /24 or IPv6 /64 of each account's first sign-in) with {SignupNetwork.Medium}+ new accounts; {SignupNetwork.High}+ is high. When 80% or more share one verified company domain it is low.",
            "Scripted sign-ups usually come from one place. They farm free allowances, test stolen cards or prepare accounts for spam.",
            "Open the accounts. Look for random names, sequential addresses and accounts that never did real work.",
            entities.Sum(e => e.Value), "count", entities);
    }

    private static SecurityFinding UnverifiedSignups(List<NewAccount> accounts, int previousTotal, int previousUnverified)
    {
        var unverified = accounts.Count(a => !a.EmailVerified);
        var share = accounts.Count > 0 ? (double)unverified / accounts.Count : 0;
        var previousShare = previousTotal > 0 ? (double)previousUnverified / previousTotal : 0;
        var rising = share >= Math.Max(previousShare * 2, 0.02);
        var severity = unverified >= 50 && share >= 0.25 ? "high" : unverified >= 20 && share >= 0.1 && rising ? "medium" : unverified >= 10 && rising ? "low" : "clear";
        string Percent(double v) => $"{Math.Round(v * 100)}%";
        return new("unverified-signups", "accounts", severity, "Unverified sign-ups",
            $"{Plural(unverified, "new account")} never confirmed an email ({Percent(share)}, previously {Percent(previousShare)}).",
            "Medium when 20+ accounts and 10%+ of sign-ups are unverified and the share at least doubled; high at 50+ and 25%+.",
            "Bots rarely finish email confirmation. A rising unverified share is an early sign of automated sign-ups.",
            "Compare with the sign-up network and domain findings to see where they came from.", unverified, "count", [], 0);
    }

    private static SecurityFinding DisposableSignups(List<NewAccount> accounts)
    {
        var disposable = DisposableDomains.ToHashSet();
        var byDomain = accounts.Select(a => (Domain: EmailDomain(a.Email), a.Email)).Where(a => a.Domain is not null && disposable.Contains(a.Domain)).GroupBy(a => a.Domain!).ToList();
        var total = byDomain.Sum(g => g.Count());
        var severity = Tiered(total, Disposable.High, Disposable.Medium, Disposable.Low);
        return Finding("disposable-signups", "accounts", "Disposable email sign-ups",
            total > 0 ? $"{Plural(total, "new account")} used a throwaway inbox." : "No new account used a known throwaway inbox.",
            $"Lists sign-ups on {DisposableDomains.Length} known disposable inbox domains; {Disposable.Medium}+ is medium, {Disposable.High}+ is high.",
            "Throwaway inboxes let one person open many accounts and leave no way to reach them.", "Check whether these accounts used free allowances or invited others.",
            total, "count", byDomain.Select(g => new SecurityEntity(g.Key, g.Key, Sample(g.Select(a => a.Email).ToList()), g.Count(), severity, null)));
    }

    private static SecurityFinding UnverifiedDomains(List<NewAccount> accounts, HashSet<string> personal)
    {
        var excluded = personal.Concat(DisposableDomains).ToHashSet();
        var rows = accounts.Select(a => (Domain: EmailDomain(a.Email), a.EmailVerified)).Where(a => a.Domain is not null).GroupBy(a => a.Domain!).Select(g => (Domain: g.Key, Unverified: g.Count(a => !a.EmailVerified), Total: g.Count())).ToList();
        var entities = rows.Where(r => !excluded.Contains(r.Domain)).SelectMany(r =>
        {
            var severity = Tiered(r.Unverified, UnverifiedDomain.High, UnverifiedDomain.Medium);
            return severity == "clear" ? [] : new[] { new SecurityEntity(r.Domain, r.Domain, $"{r.Unverified} of {Plural(r.Total, "new account")} unverified", r.Unverified, severity, null) };
        }).ToList();
        return Finding("unverified-domains", "accounts", "Unverified sign-ups on one domain",
            entities.Count > 0 ? $"{Plural(entities.Count, "domain")} had {UnverifiedDomain.Medium}+ unverified sign-ups." : "No company domain had a run of unverified sign-ups.",
            $"Flags a non-personal domain with {UnverifiedDomain.Medium}+ unverified new accounts; {UnverifiedDomain.High}+ is high.",
            "Addresses on a domain nobody controls can be invented in bulk. Real teams confirm their email.",
            "Check whether the domain exists and belongs to a real company before trusting these accounts.", entities.Sum(e => e.Value), "count", entities);
    }

    private static SecurityFinding NetworkSpreadFinding(IEnumerable<(string UserId, string Email, int Networks, int SignIns, int Clients)> rows)
    {
        var entities = rows.SelectMany(r =>
        {
            var severity = Tiered(r.Networks, NetworkSpread.High, NetworkSpread.Medium, NetworkSpread.Low);
            return severity == "clear" ? [] : new[] { new SecurityEntity(r.UserId, r.Email, $"{Plural(r.Networks, "network")}, {Plural(r.SignIns, "sign-in")}, {Plural(r.Clients, "browser or app", "browsers or apps")}", r.Networks, severity, UserTarget(r.UserId)) };
        }).ToList();
        return Finding("network-spread", "accounts", "Accounts used from many networks",
            entities.Count > 0 ? $"{Plural(entities.Count, "account")} signed in from {NetworkSpread.Low}+ networks." : $"No account signed in from {NetworkSpread.Low} or more networks.",
            $"Counts distinct sign-in networks per account in the range; {NetworkSpread.Low}+ is low, {NetworkSpread.Medium}+ medium, {NetworkSpread.High}+ high.",
            "A shared or stolen login is used from many places at once. People who travel or use mobile data also move between networks.",
            "Look for many browsers or apps at once and for networks far apart. Ask the owner or end their sessions if it looks shared.", entities.Count, "count", entities);
    }

    private static SecurityFinding OrganizationCreationFinding(IEnumerable<(string UserId, string Email, int Organizations)> rows)
    {
        var entities = rows.SelectMany(r =>
        {
            var severity = Tiered(r.Organizations, OrganizationCreation.High, OrganizationCreation.Medium);
            return severity == "clear" ? [] : new[] { new SecurityEntity(r.UserId, r.Email, $"Owner of {Plural(r.Organizations, "new organization")}", r.Organizations, severity, UserTarget(r.UserId)) };
        }).ToList();
        return Finding("organization-creation", "accounts", "Many new organizations from one person",
            entities.Count > 0 ? $"{Plural(entities.Count, "person", "people")} created {OrganizationCreation.Medium}+ organizations." : "Nobody created more than a few organizations.",
            $"Counts organizations a person became the owner of in the range; {OrganizationCreation.Medium}+ is medium, {OrganizationCreation.High}+ high.",
            "Every organization starts with its own free allowances, so repeated creation can multiply them.",
            "Open the person and check whether the organizations hold real work or only used free model credits.", entities.Count, "count", entities);
    }

    private static SecurityFinding AdminGrantFinding(List<AdminAllowlistEntry> grants, int admins) =>
        Finding("admin-grants", "credentials", "New platform admins",
            grants.Count > 0 ? $"{Plural(grants.Count, "address", "addresses")} joined the admin allowlist, {Plural(admins, "admin")} in total." : $"No admin was added. {Plural(admins, "admin")} in total.",
            "Lists every address added to the platform admin allowlist in the range.",
            "Platform admins can read and change every organization. Each new admin should be expected.",
            "Confirm each address belongs to someone on the team and that someone asked for it.", grants.Count, "count",
            grants.Select(g => new SecurityEntity(g.Id, g.Email, $"Added {g.CreatedAt:yyyy-MM-dd}{(string.IsNullOrEmpty(g.Note) ? "" : $": {g.Note}")}", 1, "medium", null)));

    private static SecurityFinding ApiKeyFinding(IEnumerable<(string OwnerId, string Label, int Keys)> owners, int enabled, int withoutExpiry)
    {
        var entities = owners.SelectMany(o =>
        {
            var severity = Tiered(o.Keys, ApiKeyBurst.High, ApiKeyBurst.Medium);
            return severity == "clear" ? [] : new[] { new SecurityEntity(o.OwnerId, o.Label, $"Created {Plural(o.Keys, "API key")}", o.Keys, severity, UserTarget(o.OwnerId)) };
        }).ToList();
        var lifetime = withoutExpiry > 0 ? $" {Plural(withoutExpiry, "enabled key")} never expire." : "";
        return Finding("api-keys", "credentials", "API key bursts",
            $"{(entities.Count > 0 ? $"{Plural(entities.Count, "owner")} created {ApiKeyBurst.Medium}+ keys." : $"No owner created {ApiKeyBurst.Medium}+ keys.")} {Plural(enabled, "key")} enabled.{lifetime}",
            $"Flags an owner who created {ApiKeyBurst.Medium}+ API keys in the range; {ApiKeyBurst.High}+ is high.",
            "Keys act without a person signing in. Many new keys can mean automation that outgrew its limits or an account handing out access.",
            "Check what the keys are named for and whether the owner still needs them.", entities.Count, "count", entities);
    }

    /// <summary>Registrations are not attributed to a person in this build (a client has no owner), so only the volume rule applies.</summary>
    private static SecurityFinding ClientRegistrationFinding(int current, int previous)
    {
        var growth = previous > 0 ? (double)current / previous : current > 0 ? double.PositiveInfinity : 0;
        var volume = current >= 1000 && growth >= 3 ? "high" : current >= 200 && growth >= 2 ? "medium" : "clear";
        var entities = new List<SecurityEntity>();
        if (volume != "clear") entities.Add(new("all", "All registrations", $"{Plural(current, "registration")} without a signed-in person, {Plural(previous, "registration")} in the previous range", current, volume, null));
        return Finding("client-registrations", "credentials", "App registrations",
            $"{Plural(current, "app")} registered to sign in with OpenWork, previously {previous.ToString("N0", CultureInfo.InvariantCulture)}.",
            "Medium when registrations doubled to 200+, high when they tripled to 1,000+. One person registering 50+ apps is medium.",
            "MCP clients register themselves to request access. A sudden wave can be someone probing sign-in or phishing with a look-alike app.",
            "Check the names and redirect addresses of recent registrations for look-alikes.", current, "count", entities);
    }

    private static SecurityFinding InvitationFinding(IEnumerable<(string UserId, string Email, int Invitations, int Organizations)> rows)
    {
        var entities = rows.SelectMany(r =>
        {
            var severity = Tiered(r.Invitations, Invitations.High, Invitations.Medium);
            return severity == "clear" ? [] : new[] { new SecurityEntity(r.UserId, r.Email, $"{Plural(r.Invitations, "invitation")} from {Plural(r.Organizations, "organization")}", r.Invitations, severity, UserTarget(r.UserId)) };
        }).ToList();
        return Finding("invitations", "credentials", "Invitation bursts",
            entities.Count > 0 ? $"{Plural(entities.Count, "person", "people")} sent {Invitations.Medium}+ invitations." : $"Nobody sent {Invitations.Medium} or more invitations.",
            $"Flags a person who sent {Invitations.Medium}+ invitations in the range; {Invitations.High}+ is high.",
            "Invitation emails come from OpenWork, so they can be abused to send spam or phishing that looks trusted.",
            "Check who was invited. Many unrelated domains or addresses outside the team point to abuse.", entities.Count, "count", entities);
    }

    private static SecurityFinding AutomationClientFinding(IEnumerable<(string UserId, string Email, string Client, int SignIns, bool NewAccount)> rows)
    {
        var entities = rows.GroupBy(r => r.UserId).Select(g =>
        {
            var signIns = g.Sum(r => r.SignIns);
            var newAccount = g.First().NewAccount;
            var tier = Tiered(signIns, AutomationSignIns.High, AutomationSignIns.Medium);
            return new SecurityEntity(g.Key, g.First().Email, $"{string.Join(", ", g.Select(r => r.Client).Distinct())}{(newAccount ? ", on a new account" : "")}", signIns, tier == "clear" ? newAccount ? "medium" : "low" : tier, UserTarget(g.Key));
        }).ToList();
        return Finding("automation-clients", "automation", "Sign-ins from automation tools",
            entities.Count > 0 ? $"{Plural(entities.Count, "account")} signed in with a headless browser or a script." : "No sign-in came from a headless browser or a script.",
            $"Matches sign-in user agents from {string.Join(", ", AutomationClients.Select(c => c.Label))}. Low for an existing account, medium for a new one or {AutomationSignIns.Medium}+ sign-ins, high at {AutomationSignIns.High}+.",
            "People sign in with a browser or the OpenWork app. A scripted or headless sign-in means a program is driving the account.",
            "Check whether it is a developer testing on purpose. Otherwise look at what the account did after signing in.", entities.Count, "count", entities);
    }

    // These three read model-gateway usage, which this build does not have: they are always clear, with the reference's wording.
    private static SecurityFinding SpendSpikes() =>
        Finding("spend-spikes", "usage", "Model spend spikes", "No organization's model spend jumped.",
            $"Compares each organization's paid and free model spend with the previous range: {Usd(25_000_000)}+ and 3× is medium, {Usd(100_000_000)}+ and 10× is high.",
            "A sudden jump can be a leaked key, a runaway automation or an account reselling access.",
            "Open the organization's usage. Check which people and models drove it and whether the jump matches real work.", 0, "count", []);

    private static SecurityFinding RoundTheClock() =>
        Finding("round-the-clock", "automation", "Model use around the clock", "Nobody used models through a whole day without a break.",
            "Counts the UTC hours of each day with an OpenWork-billed model request, paid or free Auto. One day at 20+ hours is low, 2+ days medium, 4+ high. People who own active automations stay low.",
            "People sleep. An account that works every hour of the day is usually a program or computer use running on its own, and that can farm credits or run tasks nobody watches.",
            "Check the account's automations and Workbot tasks first. Without them, look at the models used and whether the work looks scripted.", 0, "count", []);

    private static SecurityFinding InstantAllowance() =>
        Finding("instant-allowance", "automation", "Free allowance used up on day one", "No new account used its weekly free Auto within its first day.",
            $"Lists accounts created in the range whose free Auto spend in their first 24 hours reached 90% of the {Usd(0)} weekly allowance.",
            "A person exploring a new product rarely spends a week of credits in a day. Scripts that sign up and drain the allowance do.",
            "Compare with the sign-up network and throwaway inbox findings. Several such accounts from one place point to farming.", 0, "count", []);

    // ---------------------------------------------------------------- route

    public static void MapAdminSecurityEndpoints(this WebApplication app)
    {
        app.MapGet("/v1/admin/security", async (HttpContext ctx, PlatformAdminGuard guard, DenDbContext db) =>
        {
            var (_, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            var days = 7;
            if (ctx.Request.Query.TryGetValue("days", out var raw))
            {
                string? problem = null;
                if (!double.TryParse(raw.ToString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var number) || string.IsNullOrWhiteSpace(raw)) problem = "Invalid input: expected number, received NaN";
                else if (number != Math.Floor(number)) problem = "Invalid input: expected int, received number";
                else if (number < 1) problem = "Too small: expected number to be >=1";
                else if (number > 30) problem = "Too big: expected number to be <=30";
                if (problem is not null) return Results.Json(new { error = "invalid_request", details = new[] { new { message = problem, path = new[] { "days" } } } }, statusCode: 400);
                days = (int)number;
            }
            ctx.Response.Headers.CacheControl = "no-store";
            return Results.Json(await ReadReportAsync(db, days, DateTime.UtcNow));
        });
    }
}
