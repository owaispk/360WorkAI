using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.Library;
using WorkAI360.Api.Domain.Onboarding;
using WorkAI360.Api.Features.Connections;
using WorkAI360.Api.Features.OrgAdmin;
using WorkAI360.Api.Features.Policy;

namespace WorkAI360.Api.Features.Onboarding;

/// <summary>What each step is computed from (the reference's <c>ActivationFacts</c>).</summary>
public sealed record ActivationFacts(
    bool Answered, int? DurationMs,
    bool CanInvite, int InvitedByMe, int Teammates, int Joined, int Pending,
    bool SkillUsed,
    bool ProviderReportedOnDevice, bool CanConfigureProviders,
    bool CanManageGateway,
    string? ReadyConnectionName,
    string? OwnerName,
    bool Dismissed);

/// <summary>
/// The "Get set up" checklist (the reference's <c>activation.ts</c> and <c>activation-steps.ts</c>): six steps, each checked off only from what
/// actually happened, with who can do a step the caller cannot. This build has no model providers and no AI Gateway, so "Set up a model provider"
/// is done only by a client report (or when the person may not add providers), and "Share a provider on AI Gateway" stays open.
/// </summary>
public static class Activation
{
    public static readonly string[] StepIds = ["first_response", "invite_teammate", "use_skill", "own_provider", "gateway_provider", "connector"];
    public static readonly string[] ClientEvents = ["first_response", "use_skill", "own_provider", "dismiss"];
    private const int MaxDurationMs = 24 * 60 * 60 * 1000;

    /// <summary>Pure: the steps from their facts, in recipe order.</summary>
    public static object Compute(ActivationFacts f)
    {
        var owner = string.IsNullOrWhiteSpace(f.OwnerName) ? "Your workspace owner" : f.OwnerName.Trim();
        Dictionary<string, object?> Step(string id)
        {
            var step = new Dictionary<string, object?> { ["id"] = id };
            switch (id)
            {
                case "first_response":
                    step["done"] = f.Answered;
                    if (f.Answered && f.DurationMs is { } ms) step["detail"] = AnsweredIn(ms);
                    break;
                case "invite_teammate":
                    var invited = f.CanInvite ? f.InvitedByMe > 0 : f.Teammates > 0;
                    step["done"] = invited;
                    if (invited) step["detail"] = $"{f.Joined} joined, {f.Pending} invited";
                    else if (!f.CanInvite) step["lockedReason"] = $"{owner} can invite people";
                    break;
                case "use_skill":
                    step["done"] = f.SkillUsed;
                    break;
                case "own_provider":
                    step["done"] = f.ProviderReportedOnDevice || !f.CanConfigureProviders;
                    if (f.ProviderReportedOnDevice) step["detail"] = "Your key, on this device";
                    else if (!f.CanConfigureProviders) step["detail"] = "Your team manages models";
                    break;
                case "gateway_provider":
                    step["done"] = false;
                    if (!f.CanManageGateway) step["lockedReason"] = $"{owner} manages AI Gateway";
                    break;
                case "connector":
                    step["done"] = f.ReadyConnectionName is not null;
                    if (f.ReadyConnectionName is not null) step["detail"] = $"{f.ReadyConnectionName} connected";
                    break;
            }
            return step;
        }
        return new { steps = StepIds.Select(Step).ToList(), dismissed = f.Dismissed };
    }

    /// <summary>"Answered in 2.1 s" / "Answered in 12 s".</summary>
    public static string AnsweredIn(int durationMs)
    {
        var seconds = durationMs / 1000.0;
        return $"Answered in {(seconds < 10 ? seconds.ToString("0.0", CultureInfo.InvariantCulture) : Math.Round(seconds, MidpointRounding.AwayFromZero).ToString(CultureInfo.InvariantCulture))} s";
    }

    public static async Task<ActivationFacts> FactsAsync(OrgContext c, DenDbContext db, ConnectionService connections, DesktopConfigService desktop, PolicyStore policy)
    {
        var orgId = c.Organization.Id;
        var member = c.Member;
        var now = DateTime.UtcNow;
        var reported = await db.Set<ActivationEvent>().AsNoTracking().Where(e => e.MemberId == member.Id && e.OrganizationId == orgId).ToListAsync();
        var first = reported.FirstOrDefault(e => e.Step == "first_response");

        var agentSuffix = "@" + BootstrapService.AgentEmailDomain;
        var others = await (from m in db.Members.AsNoTracking()
                            join u in db.Users.AsNoTracking() on m.UserId equals u.Id
                            where m.OrganizationId == orgId && m.Id != member.Id && !u.Email.EndsWith(agentSuffix)
                            select m.Id).CountAsync();
        var pending = await db.Invitations.AsNoTracking().CountAsync(i => i.OrganizationId == orgId && i.Status == InvitationStatus.Pending && i.ExpiresAt > now);
        var invitedByMe = await db.Invitations.AsNoTracking().CountAsync(i => i.OrganizationId == orgId && i.InvitedByUserId == member.UserId
            && (i.Status == InvitationStatus.Accepted || (i.Status == InvitationStatus.Pending && i.ExpiresAt > now)));
        var ownerName = await (from m in db.Members.AsNoTracking()
                               join u in db.Users.AsNoTracking() on m.UserId equals u.Id
                               where m.OrganizationId == orgId && m.Role == "owner"
                               orderby m.CreatedAt
                               select u.Name).FirstOrDefaultAsync();

        var skillUsed = reported.Any(e => e.Step == "use_skill")
            || await db.Set<LibraryUsageEvent>().AsNoTracking().AnyAsync(u => u.OrganizationId == orgId && u.MemberId == member.Id);

        var config = await desktop.BuildAsync(c);
        var canConfigure = config.GetValueOrDefault("allowCustomProviders") is not false;

        string? ready = null;
        var teamIds = (await policy.MemberTeamsAsync(orgId, member.Id)).Select(t => t.Id).ToHashSet();
        var caller = new Caller(c, teamIds);
        foreach (var connection in await connections.UsableAsync(orgId, member.Id, teamIds))
        {
            var json = await connections.ToJsonAsync(connection, caller, includeAccess: false, includeManualEndpoints: false);
            if (json.GetValueOrDefault("connectedForMe") is true && json.GetValueOrDefault("needsReconnect") is not true && json.GetValueOrDefault("setupRequired") is not true) { ready = connection.Name; break; }
        }

        return new ActivationFacts(
            Answered: first is not null, DurationMs: first?.DurationMs,
            CanInvite: c.Permissions.Has("invitations.manage"), InvitedByMe: invitedByMe, Teammates: others + pending, Joined: others + 1, Pending: pending,
            SkillUsed: skillUsed,
            ProviderReportedOnDevice: reported.Any(e => e.Step == "own_provider"), CanConfigureProviders: canConfigure,
            CanManageGateway: c.Permissions.Has("gateway_providers.manage"),
            ReadyConnectionName: ready, OwnerName: ownerName, Dismissed: reported.Any(e => e.Step == "dismiss"));
    }

    public static void MapActivationEndpoints(this WebApplication app)
    {
        app.MapGet("/v1/me/activation", async (HttpContext ctx, OrgAccess access, DenDbContext db, ConnectionService connections, DesktopConfigService desktop, PolicyStore policy) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            ctx.Response.Headers.CacheControl = "no-store";
            return Results.Json(Compute(await FactsAsync(context!, db, connections, desktop, policy)));
        });

        app.MapPost("/v1/me/activation/events", async (HttpContext ctx, OrgAccess access, DenDbContext db, ConnectionService connections, DesktopConfigService desktop, PolicyStore policy) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            var (root, invalid) = await Zod.ReadObjectAsync(ctx, "step");
            if (invalid is not null) return invalid;
            var issues = new List<ZodIssue>();
            string? step = null;
            if (!root.TryGetProperty("step", out var s) || s.ValueKind != JsonValueKind.String || !ClientEvents.Contains(s.GetString())) issues.Add(new("invalid_value", ["step"], StepMessage));
            else step = s.GetString();
            int? duration = null;
            if (root.TryGetProperty("durationMs", out var d))
            {
                if (d.ValueKind != JsonValueKind.Number) issues.Add(new("invalid_type", ["durationMs"], $"Invalid input: expected number, received {Zod.Kind(d)}"));
                else if (d.GetDouble() is var value && value != Math.Floor(value)) issues.Add(new("invalid_type", ["durationMs"], "Invalid input: expected int, received number"));
                else if (value > MaxDurationMs) issues.Add(new("too_big", ["durationMs"], $"Too big: expected number to be <={MaxDurationMs}"));
                else if (value < 0) issues.Add(new("too_small", ["durationMs"], "Too small: expected number to be >=0"));
                else duration = (int)value;
            }
            if (Zod.Unrecognized(root, "step", "durationMs") is { } extra) issues.Add(extra);
            if (issues.Count > 0) return Zod.Respond(issues);

            var orgId = context!.Organization.Id;
            var memberId = context.Member.Id;
            // The first report wins; a repeat (or a parallel tab) changes nothing.
            if (!await db.Set<ActivationEvent>().AnyAsync(e => e.MemberId == memberId && e.Step == step))
            {
                db.Set<ActivationEvent>().Add(new ActivationEvent { MemberId = memberId, Step = step!, OrganizationId = orgId, DurationMs = step == "first_response" ? duration : null, Source = "app", CreatedAt = DateTime.UtcNow });
                try { await db.SaveChangesAsync(); }
                catch (DbUpdateException) { db.ChangeTracker.Clear(); }
            }
            ctx.Response.Headers.CacheControl = "no-store";
            return Results.Json(Compute(await FactsAsync(context, db, connections, desktop, policy)));
        });
    }

    private const string StepMessage = "Invalid option: expected one of \"first_response\"|\"use_skill\"|\"own_provider\"|\"dismiss\"";
}
