using System.Text.RegularExpressions;
using WorkAI360.Api.Auth;

namespace WorkAI360.Api.Features.OrgAdmin;

/// <summary>One change route of the reference's audit route inventory (see AuditRoutes.g.cs).</summary>
public sealed record AuditRouteDeclaration(string Method, string Path, string Class, string Action, string ResourceType, string? IdParam);

/// <summary>A declaration matched to one of this build's endpoints: the id parameter is named as this build names it.</summary>
public sealed record AuditRoute(AuditRouteDeclaration Declaration, string? IdParam);

/// <summary>Who a request without a signed-in workspace member acted for, once its handler proved it (a SCIM bearer token names its workspace).</summary>
public sealed record AuditAttribution(string OrganizationId, AuditActor Actor);

/// <summary>
/// Request evidence for change routes, as the reference's request capture records it: when a route the reference declares as a change
/// (<c>tenant_change</c>) or a call to an outside system (<c>tenant_external</c>) finishes inside a workspace, one event named
/// <c>&lt;action&gt;.succeeded</c> (<c>.confirmed</c> for outside calls), <c>.attempted</c> (refused or rejected) or <c>.unknown</c> (an outside call that
/// failed) is written with the target resource and the workspace. A request whose handler already wrote its own change events is not recorded again.
/// Routes owned by areas that record their own run history (automations, workflows, workspace documents) are left to them.
/// </summary>
public static partial class AuditRoutes
{
    public const string OrgContextItem = "audit.orgContext";
    public const string RecordedItem = "audit.recorded";
    public const string AttributionItem = "audit.attribution";

    private static readonly string[] OwnHistoryPrefixes =
        ["/v1/automation", "/v1/cloud-automations", "/v1/workflows", "/v1/artifact-views", "/v1/documents", "/v1/workbot", "/v1/session-runners", "/v1/remote-session"];

    private static Dictionary<(string Method, string Path), AuditRoute>? _byShape;

    [GeneratedRegex(@"\{[^}]+\}")]
    private static partial Regex AspNetParameter();

    [GeneratedRegex(@":[A-Za-z_][A-Za-z0-9_]*")]
    private static partial Regex HonoParameter();

    [GeneratedRegex(@"\{\**([A-Za-z_][A-Za-z0-9_]*)")]
    private static partial Regex ParameterName();

    private static string Shape(string path) => path.TrimEnd('/').ToLowerInvariant();

    /// <summary>Path with every parameter replaced by <c>{}</c>, so the reference's <c>:id</c> and this build's <c>{id}</c> compare equal.</summary>
    public static string NormalizeReference(string path) => Shape(HonoParameter().Replace(path, "{}"));

    public static string NormalizeTemplate(string template) => Shape(AspNetParameter().Replace(template, "{}"));

    /// <summary>The declaration for this endpoint, or null. The table is built once from the declarations; the id parameter is matched by position.</summary>
    public static AuditRoute? Find(string method, string template)
    {
        var table = _byShape ??= Declarations
            .Where(d => !OwnHistoryPrefixes.Any(p => d.Path.StartsWith(p, StringComparison.Ordinal)))
            .GroupBy(d => (d.Method, NormalizeReference(d.Path))).ToDictionary(g => g.Key, g => new AuditRoute(g.First(), g.First().IdParam));
        if (!table.TryGetValue((method, NormalizeTemplate(template)), out var route)) return null;
        if (route.Declaration.IdParam is null) return route;
        // The reference names parameters its own way: take this build's name at the same position.
        var position = HonoParameter().Matches(route.Declaration.Path).Select(m => m.Value[1..]).ToList().IndexOf(route.Declaration.IdParam);
        var names = ParameterName().Matches(template).Select(m => m.Groups[1].Value).ToList();
        return route with { IdParam = position >= 0 && position < names.Count ? names[position] : null };
    }

    private static IReadOnlyList<string>? _eventTypes;

    /// <summary>
    /// Every action this build can record: the domain events (<see cref="AuditActions"/>) and, for each change route this build serves, its request
    /// events. Built once from the registered endpoints.
    /// </summary>
    public static IReadOnlyList<string> EventTypes(EndpointDataSource endpoints) => _eventTypes ??= endpoints.Endpoints.OfType<RouteEndpoint>()
        .SelectMany(e => (e.Metadata.GetMetadata<Microsoft.AspNetCore.Routing.HttpMethodMetadata>()?.HttpMethods ?? []).Select(m => (Method: m, Template: e.RoutePattern.RawText ?? "")))
        .Select(e => Find(e.Method, e.Template)).Where(r => r is not null)
        .SelectMany(r => r!.Declaration.Class == "tenant_external"
            ? new[] { $"{r.Declaration.Action}.confirmed", $"{r.Declaration.Action}.attempted", $"{r.Declaration.Action}.unknown" }
            : new[] { $"{r.Declaration.Action}.succeeded", $"{r.Declaration.Action}.attempted" })
        .Concat(AuditActions.EventTypes).Distinct().Order(StringComparer.Ordinal).ToList();

    /// <summary>The reference's outcome mapping: suffix, outcome, reason code and whether it was a refusal.</summary>
    public static (string Suffix, string Outcome, string? ReasonCode, bool Denied) Outcome(string auditClass, int status)
    {
        if (status < 400) return (auditClass == "tenant_external" ? "confirmed" : "succeeded", "succeeded", null, false);
        if (status is 401 or 403) return ("attempted", "denied", "request_denied", true);
        if (status < 500)
            return ("attempted", "failed", status switch { 404 => "resource_not_found", 409 => "request_conflict", 400 or 422 => "validation_failed", _ => "request_rejected" }, false);
        return auditClass == "tenant_external" ? ("unknown", "unknown", "external_outcome_unknown", false) : ("attempted", "failed", "request_failed", false);
    }

    public static void UseAuditRequestCapture(WebApplication app)
    {
        app.Use(async (context, next) =>
        {
            var failed = false;
            try { await next(); }
            catch { failed = true; throw; }
            finally
            {
                var attribution = context.Items.TryGetValue(OrgContextItem, out var item) && item is OrgContext org
                    ? new AuditAttribution(org.Organization.Id, AuditActor.User(org.Auth.User.Id, org.Member.Id, org.ApiKeyId))
                    : context.Items.TryGetValue(AttributionItem, out var proven) ? proven as AuditAttribution : null;
                if (context.GetEndpoint() is RouteEndpoint endpoint && endpoint.RoutePattern.RawText is { } template
                    && attribution is not null
                    && !context.Items.ContainsKey(RecordedItem)
                    && Find(context.Request.Method, template) is { } route)
                {
                    var (suffix, outcome, reason, denied) = Outcome(route.Declaration.Class, failed ? 500 : context.Response.StatusCode);
                    var id = route.IdParam is not null && context.Request.RouteValues.TryGetValue(route.IdParam, out var value) && value is string text && text.Length > 0
                        ? text : $"collection:{route.Declaration.ResourceType}";
                    var entry = new AuditEntry($"{route.Declaration.Action}.{suffix}",
                        [new(route.Declaration.ResourceType, id), new("organization", attribution.OrganizationId, "parent")],
                        denied ? "security" : "request", outcome, ReasonCode: reason);
                    await context.RequestServices.GetRequiredService<IAuditLog>().RecordAsync(attribution.OrganizationId, attribution.Actor, entry);
                }
            }
        });
    }
}
