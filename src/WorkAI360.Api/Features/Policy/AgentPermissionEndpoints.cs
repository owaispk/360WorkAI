using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Policy;
using WorkAI360.Api.Features.Library;
using static WorkAI360.Api.Features.Policy.PolicyStore;

namespace WorkAI360.Api.Features.Policy;

/// <summary>Stored settings of agent permissions: the normalized form, as JSON.</summary>
public static class AgentSettingsJson
{
    public static Dictionary<string, object?> Wire(AgentSetting s)
    {
        var d = new Dictionary<string, object?>();
        if (s.Decision is not null) d["decision"] = s.Decision;
        if (s.Allow.Count > 0) d["allow"] = s.Allow;
        if (s.Block.Count > 0) d["block"] = s.Block;
        return d;
    }

    public static Dictionary<string, object?> Wire(IReadOnlyDictionary<string, AgentSetting> settings) =>
        AgentPermissionRules.Definitions.Where(d => settings.ContainsKey(d.Key)).ToDictionary(d => d.Key, d => (object?)Wire(settings[d.Key]));

    public static string Serialize(IReadOnlyDictionary<string, AgentSetting> settings) => JsonSerializer.Serialize(Wire(settings));

    /// <summary>Stored settings read tolerantly and normalized again (so a catalog that changed never loosens what was saved).</summary>
    public static Dictionary<string, AgentSetting> Read(string? json)
    {
        var result = new Dictionary<string, AgentSetting>();
        if (string.IsNullOrWhiteSpace(json)) return result;
        JsonElement root;
        try { root = JsonDocument.Parse(json).RootElement; } catch (JsonException) { return result; }
        if (root.ValueKind != JsonValueKind.Object) return result;
        foreach (var definition in AgentPermissionRules.Definitions)
        {
            if (!root.TryGetProperty(definition.Key, out var v) || v.ValueKind != JsonValueKind.Object) continue;
            var decision = v.TryGetProperty("decision", out var dec) && dec.ValueKind == JsonValueKind.String ? dec.GetString() : null;
            var setting = AgentPermissionRules.NormalizeSetting(definition, decision, Strings(v, "allow"), Strings(v, "block"));
            if (setting is not null) result[definition.Key] = setting;
        }
        return result;
    }

    private static List<string>? Strings(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array ? v.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!).ToList() : null;

    /// <summary>Validates the <c>settings</c> of a write with the reference's messages and returns them in stored form.</summary>
    public static Dictionary<string, AgentSetting> ParseWrite(JsonElement body)
    {
        foreach (var p in body.EnumerateObject())
            if (p.Name != "settings") throw new Invalid("", $"Unrecognized key: \"{p.Name}\"", "unrecognized_keys");
        var settings = Zod.Object(body, "settings");
        foreach (var p in settings.EnumerateObject())
            if (AgentPermissionRules.Definition(p.Name) is null) throw new Invalid("settings", $"Unrecognized key: \"{p.Name}\"", "unrecognized_keys");

        var parsed = new Dictionary<string, (string? Decision, List<string> Allow, List<string> Block)>();
        foreach (var definition in AgentPermissionRules.Definitions)
        {
            if (!settings.TryGetProperty(definition.Key, out var one)) continue;
            var path = $"settings.{definition.Key}";
            if (one.ValueKind != JsonValueKind.Object) throw new Invalid(path, $"Invalid input: expected object, received {Zod.Kind(one)}");
            foreach (var p in one.EnumerateObject())
                if (p.Name is not ("decision" or "allow" or "block")) throw new Invalid(path, $"Unrecognized key: \"{p.Name}\"", "unrecognized_keys");
            string? decision = null;
            if (one.TryGetProperty("decision", out var d))
            {
                if (d.ValueKind != JsonValueKind.String || !AgentPermissionRules.Decisions.Contains(d.GetString()!))
                    throw new Invalid($"{path}.decision", "Invalid option: expected one of \"allow\"|\"ask\"|\"deny\"", "invalid_value");
                decision = d.GetString();
            }
            parsed[definition.Key] = (decision, List(one, "allow", path), List(one, "block", path));
        }
        // Rules that need the catalog, in its order.
        foreach (var definition in AgentPermissionRules.Definitions)
        {
            if (!parsed.TryGetValue(definition.Key, out var s)) continue;
            if (s.Decision is not null && !definition.Decisions.Contains(s.Decision))
                throw new Invalid($"settings.{definition.Key}.decision", $"{definition.Label} is either allowed or blocked.", "custom");
            foreach (var (name, items, noun) in new[] { ("allow", s.Allow, "allowed"), ("block", s.Block, "blocked") })
            {
                if (items.Count > 0 && definition.Patterns is null) throw new Invalid($"settings.{definition.Key}.{name}", $"{definition.Label} has no {noun} list.", "custom");
                for (var i = 0; i < items.Count; i++)
                    if (definition.Patterns is not null && AgentPermissionRules.NormalizePattern(definition.Patterns, items[i]) is null)
                        throw new Invalid($"settings.{definition.Key}.{name}.{i}", AgentPermissionRules.PatternError(definition.Patterns), "custom");
            }
        }
        var result = new Dictionary<string, AgentSetting>();
        foreach (var definition in AgentPermissionRules.Definitions)
        {
            if (!parsed.TryGetValue(definition.Key, out var s)) continue;
            var normalized = AgentPermissionRules.NormalizeSetting(definition, s.Decision, s.Allow, s.Block);
            if (normalized is not null) result[definition.Key] = normalized;
        }
        return result;
    }

    private static List<string> List(JsonElement one, string name, string path)
    {
        if (!one.TryGetProperty(name, out var v)) return [];
        if (v.ValueKind != JsonValueKind.Array) throw new Invalid($"{path}.{name}", $"Invalid input: expected array, received {Zod.Kind(v)}");
        if (v.GetArrayLength() > AgentPermissionRules.ListMax) throw new Invalid($"{path}.{name}", $"Too big: expected array to have <={AgentPermissionRules.ListMax} items", "too_big");
        var items = new List<string>();
        foreach (var (e, i) in v.EnumerateArray().Select((e, i) => (e, i)))
        {
            if (e.ValueKind != JsonValueKind.String) throw new Invalid($"{path}.{name}.{i}", $"Invalid input: expected string, received {Zod.Kind(e)}");
            if (e.GetString()!.Length > 500) throw new Invalid($"{path}.{name}.{i}", "Too big: expected string to have <=500 characters", "too_big");
            items.Add(e.GetString()!);
        }
        return items;
    }
}

public static class AgentPermissionEndpoints
{
    private static object Policy(string? teamId, string name, int? memberCount, IReadOnlyDictionary<string, AgentSetting> settings, DateTime? updatedAt) => new Dictionary<string, object?>
    {
        ["teamId"] = teamId, ["name"] = name, ["memberCount"] = memberCount, ["settings"] = AgentSettingsJson.Wire(settings), ["updatedAt"] = updatedAt is null ? null : Iso(updatedAt.Value),
    };

    public static void Map(WebApplication app)
    {
        app.MapGet("/v1/agent-permissions", (HttpContext ctx, PolicyRunner run, PolicyStore store, DenDbContext db) =>
            run.RunAsync(ctx, "agent_permissions.view", async c =>
            {
                var orgId = c.Organization.Id;
                var rows = await db.Set<AgentPermissionPolicy>().AsNoTracking().Where(p => p.OrganizationId == orgId).ToListAsync();
                var teams = await store.TeamsAsync(orgId);
                var counts = await store.MemberCountsAsync(teams.Select(t => t.Id));
                var everyone = rows.FirstOrDefault(r => r.ScopeKey == AgentPermissionRules.Everyone.ToLowerInvariant());
                return Json(new
                {
                    everyone = Policy(null, AgentPermissionRules.Everyone, null, AgentSettingsJson.Read(everyone?.SettingsJson), everyone?.UpdatedAt),
                    teams = teams.Select(t =>
                    {
                        var row = rows.FirstOrDefault(r => r.TeamId == t.Id);
                        return Policy(t.Id, t.Name, counts.GetValueOrDefault(t.Id), AgentSettingsJson.Read(row?.SettingsJson), row?.UpdatedAt);
                    }).ToList(),
                    canEdit = c.Permissions.Has("agent_permissions.manage"),
                });
            }));

        app.MapPut("/v1/agent-permissions/everyone", (HttpContext ctx, PolicyRunner run, PolicyStore store, DenDbContext db) =>
            run.RunAsync(ctx, "agent_permissions.manage", async c =>
            {
                var settings = AgentSettingsJson.ParseWrite(await Zod.BodyAsync(ctx));
                return await SaveAsync(db, c, null, settings);
            }));

        app.MapPut("/v1/agent-permissions/teams/{teamId}", (string teamId, HttpContext ctx, PolicyRunner run, PolicyStore store, DenDbContext db) =>
            run.RunAsync(ctx, "agent_permissions.manage", async c =>
            {
                Zod.TypeId(teamId, "tem", "teamId");
                var settings = AgentSettingsJson.ParseWrite(await Zod.BodyAsync(ctx));
                var team = await store.FindTeamAsync(c.Organization.Id, teamId);
                return team is null ? NotFound("team_not_found") : await SaveAsync(db, c, team, settings);
            }));

        app.MapDelete("/v1/agent-permissions/teams/{teamId}", (string teamId, HttpContext ctx, PolicyRunner run, PolicyStore store, DenDbContext db) =>
            run.RunAsync(ctx, "agent_permissions.manage", async c =>
            {
                Zod.TypeId(teamId, "tem", "teamId");
                var team = await store.FindTeamAsync(c.Organization.Id, teamId);
                if (team is null) return NotFound("team_not_found");
                await db.Set<AgentPermissionPolicy>().Where(p => p.OrganizationId == c.Organization.Id && p.ScopeKey == team.Id).ExecuteDeleteAsync();
                return Results.NoContent();
            }));
    }

    /// <summary>Replaces one scope's settings; nothing left to set removes the row. A racing first save retries against the row the winner made.</summary>
    private static async Task<IResult> SaveAsync(DenDbContext db, OrgContext c, TeamInfo? team, Dictionary<string, AgentSetting> settings)
    {
        var scope = team?.Id ?? "everyone";
        var orgId = c.Organization.Id;
        DateTime? updatedAt = null;
        for (var attempt = 0; ; attempt++)
        {
            db.ChangeTracker.Clear();
            var row = await db.Set<AgentPermissionPolicy>().FirstOrDefaultAsync(p => p.OrganizationId == orgId && p.ScopeKey == scope);
            try
            {
                if (settings.Count == 0)
                {
                    if (row is not null) { db.Remove(row); await db.SaveChangesAsync(); }
                }
                else
                {
                    var now = DateTime.UtcNow;
                    if (row is null)
                    {
                        row = new AgentPermissionPolicy { Id = Ids.New("apo"), OrganizationId = orgId, ScopeKey = scope, TeamId = team?.Id, SettingsJson = "{}", CreatedAt = now, UpdatedAt = now };
                        db.Add(row);
                    }
                    row.SettingsJson = AgentSettingsJson.Serialize(settings);
                    row.UpdatedByMemberId = c.Member.Id;
                    row.UpdatedAt = now;
                    await db.SaveChangesAsync();
                    updatedAt = now;
                }
                break;
            }
            catch (DbUpdateException) when (attempt == 0) { }
            catch (DbUpdateException)
            {
                db.ChangeTracker.Clear();
                if (team is not null && !await db.Teams.AnyAsync(t => t.Id == team.Id)) return NotFound("team_not_found");
                return Json(new { error = "resource_conflict", message = "These permissions are being changed by someone else. Try again." }, 409);
            }
        }
        var count = team is null ? (int?)null : (await new PolicyStore(db).MemberCountsAsync([team.Id])).GetValueOrDefault(team.Id);
        return Json(new { policy = Policy(team?.Id, team?.Name ?? AgentPermissionRules.Everyone, count, settings, updatedAt) });
    }
}
