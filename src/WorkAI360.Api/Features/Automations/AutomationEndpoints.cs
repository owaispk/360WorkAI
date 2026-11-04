using System.Text.Json;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Domain.Automations;
using WorkAI360.Api.Features.Library;
using WorkAI360.Api.Features.OrgAdmin;
using LibraryZod = WorkAI360.Api.Features.Library.Zod;

namespace WorkAI360.Api.Features.Automations;

/// <summary>The routes a person (or an agent acting for them) uses to manage their own Automations and read their runs.</summary>
public static class AutomationEndpoints
{
    public const string ModelAttentionHeader = "x-openwork-automation-model-attention";
    public const string ScheduleKindsHeader = "x-openwork-automation-schedule-kinds";

    /// <summary>Resolves the workspace and the person, builds what the request may use, and answers the reference's error shapes.</summary>
    private static async Task<IResult> RunAsync(HttpContext ctx, OrgAccess access, IConfiguration configuration, Func<Scope, Task<IResult>> handler)
    {
        var (context, failure) = await access.ResolveAsync(ctx);
        if (failure is not null) return failure;
        ctx.Items[ContextKey] = context;
        try { return await handler(ScopeOf(ctx, context!, configuration)); }
        catch (Invalid invalid) { return invalid.ToResult(); }
        catch (AutomationFailure failed) { return failed.ToResult(); }
    }

    public static Scope ScopeOf(HttpContext ctx, OrgContext context, IConfiguration configuration)
    {
        var attention = ctx.Request.Headers[ModelAttentionHeader].ToString() == RunnerCapability.ModelAttention;
        // Only first-party desktops send the model-attention header, so only they are narrowed to the schedule kinds they can read.
        var header = ctx.Request.Headers.TryGetValue(ScheduleKindsHeader, out var kinds) ? kinds.ToString() : null;
        IReadOnlySet<string>? readable = header is null
            ? attention ? AutomationSchedule.LegacyKinds.ToHashSet() : null
            : AutomationSchedule.LegacyKinds.Concat(header.Split(',').Select(k => k.Trim()).Where(AutomationSchedule.Kinds.Contains)).ToHashSet();
        return new Scope(context.Organization.Id, context.Member.Id, attention, readable,
            FeatureState.Resolve(configuration, "automationIntervalSchedules"), FeatureState.Resolve(configuration, "automationCalendarTriggers"));
    }

    private const string ContextKey = "automation.org-context";

    /// <summary>Records a successful change of the caller's Automation (the reference's route event names).</summary>
    private static async Task<IResult> AuditedAsync(HttpContext ctx, string action, Item? item, int status = 200)
    {
        if (item is null) return NotFound("automation_not_found");
        if (ctx.Items[ContextKey] is OrgContext context)
            await ctx.RequestServices.GetRequiredService<AutomationAudit>().ChangedAsync(context, action, item.Automation.Id);
        return Json(AutomationWire.Of(item), status);
    }

    private static IResult Json(object body, int status = 200) => Results.Json(body, statusCode: status);

    private static IResult NotFound(string error) => Results.Json(new { error }, statusCode: 404);

    private static (string? Cursor, int? Limit) Page(HttpContext ctx) => (LibraryZod.QueryString(ctx, "cursor", 160), LibraryZod.QueryInt(ctx, "limit", 1, 100));

    public static void Map(WebApplication app)
    {
        app.MapGet("/v1/automation-runners/presence", (HttpContext ctx, OrgAccess access, IConfiguration cfg, AutomationService service) =>
            RunAsync(ctx, access, cfg, async scope => Json(await service.PresenceAsync(scope))));

        app.MapGet("/v1/automation-runners", (HttpContext ctx, OrgAccess access, IConfiguration cfg, AutomationService service) =>
            RunAsync(ctx, access, cfg, async scope => Json(await service.ExecutionTargetsAsync(scope))));

        app.MapGet("/v1/automations", (HttpContext ctx, OrgAccess access, IConfiguration cfg, AutomationService service) =>
            RunAsync(ctx, access, cfg, async scope =>
            {
                var (cursor, limit) = Page(ctx);
                var (items, next) = await service.ListAsync(scope, cursor, limit ?? 50);
                return Json(new { items = items.Select(AutomationWire.Of), nextCursor = next });
            }));

        app.MapPost("/v1/automations", (HttpContext ctx, OrgAccess access, IConfiguration cfg, AutomationService service) =>
            RunAsync(ctx, access, cfg, async scope =>
            {
                var definition = AutomationInput.ParseCreate(await LibraryZod.BodyAsync(ctx));
                return await AuditedAsync(ctx, "automation.create", await service.CreateAsync(scope, definition), 201);
            }));

        app.MapPost("/v1/cloud-automations", (HttpContext ctx, OrgAccess access, IConfiguration cfg, AutomationService service) =>
            RunAsync(ctx, access, cfg, async scope =>
            {
                var definition = AutomationInput.ParseCreateCloud(await LibraryZod.BodyAsync(ctx));
                return await AuditedAsync(ctx, "automation.cloud.create", await service.CreateAsync(scope, definition), 201);
            }));

        app.MapGet("/v1/automations/{id}", (string id, HttpContext ctx, OrgAccess access, IConfiguration cfg, AutomationService service) =>
            RunAsync(ctx, access, cfg, async scope => await service.GetAsync(scope, id) is { } item ? Json(AutomationWire.Of(item)) : NotFound("automation_not_found")));

        app.MapPatch("/v1/automations/{id}", (string id, HttpContext ctx, OrgAccess access, IConfiguration cfg, AutomationService service) =>
            RunAsync(ctx, access, cfg, async scope =>
            {
                var changes = AutomationInput.ParseUpdate(await LibraryZod.BodyAsync(ctx));
                return await AuditedAsync(ctx, "automation.update", await service.UpdateAsync(scope, id, changes));
            }));

        app.MapPost("/v1/automations/{id}/activate", (string id, HttpContext ctx, OrgAccess access, IConfiguration cfg, AutomationService service) =>
            RunAsync(ctx, access, cfg, async scope => await AuditedAsync(ctx, "automation.activate", await service.ActivateAsync(scope, id))));

        app.MapPost("/v1/automations/{id}/deactivate", (string id, HttpContext ctx, OrgAccess access, IConfiguration cfg, AutomationService service) =>
            RunAsync(ctx, access, cfg, async scope => await AuditedAsync(ctx, "automation.deactivate", await service.DeactivateAsync(scope, id))));

        app.MapDelete("/v1/automations/{id}", (string id, HttpContext ctx, OrgAccess access, IConfiguration cfg, AutomationService service) =>
            RunAsync(ctx, access, cfg, async scope => await AuditedAsync(ctx, "automation.archive", await service.ArchiveAsync(scope, id))));

        app.MapPost("/v1/automations/{id}/run", (string id, HttpContext ctx, OrgAccess access, IConfiguration cfg, AutomationService service) =>
            RunAsync(ctx, access, cfg, async scope =>
            {
                // The body is optional: released clients send {} and agents may send nothing.
                using var reader = new StreamReader(ctx.Request.Body);
                var text = await reader.ReadToEndAsync();
                string? target = null;
                if (!string.IsNullOrWhiteSpace(text))
                {
                    JsonElement body;
                    try { body = JsonDocument.Parse(text).RootElement; }
                    catch (JsonException) { throw new Invalid("", "Invalid input: expected object, received undefined"); }
                    if (body.ValueKind != JsonValueKind.Object) throw new Invalid("", $"Invalid input: expected object, received {Reader.Kind(body)}");
                    if (body.TryGetProperty("executionTarget", out _))
                    {
                        target = Reader.Str(body, "executionTarget", [], 1, 16, trim: false);
                        if (target is not ("desktop" or "cloud")) throw new Invalid("executionTarget", "Invalid option: expected one of \"desktop\"|\"cloud\"", "invalid_value");
                    }
                }
                var run = await service.RunNowAsync(scope, id, target);
                if (run is null) return NotFound("automation_not_found");
                var runAudit = ctx.RequestServices.GetRequiredService<AutomationAudit>();
                await runAudit.ChangedAsync((OrgContext)ctx.Items[ContextKey]!, "automation.run.start", run.AutomationId, run.Id);
                // A run refused on the spot (policy, a lost model) has already ended.
                await runAudit.CompletedAsync(run.Id, await runAudit.OwnerActorAsync(scope.OrganizationId, scope.MemberId));
                return Json(new { run = AutomationWire.Of(run) }, 202);
            }));

        app.MapGet("/v1/automations/{id}/runs", (string id, HttpContext ctx, OrgAccess access, IConfiguration cfg, AutomationService service) =>
            RunAsync(ctx, access, cfg, async scope =>
            {
                var (cursor, limit) = Page(ctx);
                var (items, next) = await service.ListRunsAsync(scope, id, cursor, limit ?? 50);
                return Json(new { items = items.Select(AutomationWire.Of), nextCursor = next });
            }));

        app.MapGet("/v1/automation-runs", (HttpContext ctx, OrgAccess access, IConfiguration cfg, AutomationService service) =>
            RunAsync(ctx, access, cfg, async scope =>
            {
                const long maxDays = 45;
                var from = Number(ctx, "from", 0);
                var to = Number(ctx, "to", 1);
                var cursor = LibraryZod.QueryString(ctx, "cursor", 160);
                var limit = LibraryZod.QueryInt(ctx, "limit", 1, 500);
                if (to <= from) throw new Invalid([(["to"], "custom", "to must be after from")]);
                if (to - from > maxDays * 24 * 60 * 60 * 1000) throw new Invalid([(["to"], "custom", $"The range may cover at most {maxDays} days")]);
                var (items, next) = await service.ListRunsInRangeAsync(scope, from, to, cursor, limit ?? 200);
                return Json(new { items = items.Select(AutomationWire.Of), nextCursor = next });
            }));

        app.MapGet("/v1/automation-runs/{id}", (string id, HttpContext ctx, OrgAccess access, IConfiguration cfg, AutomationService service) =>
            RunAsync(ctx, access, cfg, async scope =>
            {
                var receipt = await service.GetRunAsync(scope, id);
                return receipt is null ? NotFound("automation_run_not_found") : Json(new
                {
                    run = AutomationWire.Of(receipt.Value.Run), automation = AutomationWire.Of(receipt.Value.Automation), revision = AutomationWire.Of(receipt.Value.Revision),
                    events = receipt.Value.Events.Select(AutomationWire.Of),
                });
            }));

        app.MapPost("/v1/automation-runs/{id}/cancel", (string id, HttpContext ctx, OrgAccess access, IConfiguration cfg, AutomationService service) =>
            RunAsync(ctx, access, cfg, async scope =>
            {
                if (await service.CancelRunAsync(scope, id) is not { } run) return NotFound("automation_run_not_found");
                var runAudit = ctx.RequestServices.GetRequiredService<AutomationAudit>();
                await runAudit.ChangedAsync((OrgContext)ctx.Items[ContextKey]!, "automation_run.cancel", run.AutomationId, run.Id);
                // A queued run is cancelled on the spot; one a runner holds ends when the runner reports it.
                if (run.Status == "cancelled" && run.FinishedAt == run.CancelRequestedAt) await runAudit.CompletedAsync(run.Id, await runAudit.OwnerActorAsync(scope.OrganizationId, scope.MemberId));
                return Json(new { run = AutomationWire.Of(run) });
            }));
    }

    /// <summary>A required query number (zod <c>coerce.number().int()</c>): <paramref name="min"/> 0 allows zero, 1 does not.</summary>
    private static long Number(HttpContext ctx, string name, long min)
    {
        var raw = ctx.Request.Query[name].ToString();
        if (!double.TryParse(raw, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var d))
            throw new Invalid(name, "Invalid input: expected number, received NaN");
        if (d != Math.Floor(d)) throw new Invalid(name, "Invalid input: expected int, received number");
        if (d < min) throw new Invalid([([name], "too_small", min == 0 ? "Too small: expected number to be >=0" : "Too small: expected number to be >0")]);
        return (long)d;
    }
}
