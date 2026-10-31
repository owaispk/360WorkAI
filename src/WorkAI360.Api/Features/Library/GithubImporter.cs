using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Library;

namespace WorkAI360.Api.Features.Library;

public sealed record GithubTarget(string? Branch, string Repo, string RootPath);

public sealed record ImportAccess(bool OrgWide, List<string> MemberIds, List<string> TeamIds);

public sealed record ImportRequest(string GithubUrl, ImportAccess? Access, string? Name, string? Description, string? MarketplaceId, List<string>? SelectedSkillKeys);

/// <summary>
/// Reads a public GitHub repository (or one folder of it) and turns its skills into a plugin. Preview shows what is there; import
/// creates the plugin, shares it, and on a second import updates what changed. The GitHub API and raw-file hosts come from
/// <see cref="LibraryOptions"/>, so tests can point them at a local server.
/// </summary>
public sealed class GithubImporter(IHttpClientFactory http, IOptions<LibraryOptions> options, DenDbContext db, LibraryStore store, LibraryAccess lib)
{
    public const string ClientName = "github-import";

    // ---------- request shapes ----------

    public static string ReadUrl(JsonElement body)
    {
        var url = Zod.Str(body, "githubUrl", max: 2048)!;
        if (!Uri.TryCreate(url, UriKind.Absolute, out _)) throw new Invalid(new[] { (new[] { "githubUrl" }, "invalid_format", "Invalid URL") });
        return url;
    }

    public static ImportRequest ReadImport(JsonElement body)
    {
        var url = ReadUrl(body);
        ImportAccess? access = null;
        if (Zod.Has(body, "access"))
        {
            var a = Zod.Object(body, "access");
            var orgWide = Zod.Bool(a, "orgWide") ?? true;
            List<string> Ids(string name, string prefix) => (Zod.Array(a, name, 200) ?? []).Select((e, i) => e.ValueKind == JsonValueKind.String ? Zod.TypeId(e.GetString()!, prefix, $"access.{name}.{i}") : throw new Invalid($"access.{name}.{i}", $"Invalid input: expected string, received {Zod.Kind(e)}")).ToList();
            var members = Ids("memberIds", "om");
            var teams = Ids("teamIds", "tem");
            if (!orgWide && members.Count == 0 && teams.Count == 0) throw new Invalid("access.orgWide", "Provide orgWide=true or at least one member/team grant.", "custom");
            access = new ImportAccess(orgWide, members, teams);
        }
        var description = Zod.Has(body, "description") && body.GetProperty("description").ValueKind != JsonValueKind.Null ? Zod.Str(body, "description", min: 0, max: 65535) : null;
        var name = Zod.Str(body, "name", required: false, max: 255);
        var marketplaceId = Zod.Has(body, "marketplaceId") ? Zod.Id(body, "marketplaceId", "mkt") : null;
        List<string>? skills = null;
        if (Zod.Has(body, "selectedSkillKeys"))
            skills = Zod.Array(body, "selectedSkillKeys", 200)!.Select((e, i) => e.ValueKind == JsonValueKind.String ? e.GetString()!.Trim() : throw new Invalid($"selectedSkillKeys.{i}", $"Invalid input: expected string, received {Zod.Kind(e)}")).ToList();
        return new ImportRequest(url, access, name, description, marketplaceId, skills);
    }

    public static GithubTarget ParseUrl(string raw)
    {
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var url)) throw new LibraryFailure(400, "invalid_github_url", "Enter a valid GitHub URL.");
        if (url.Host != "github.com" && url.Host != "www.github.com") throw new LibraryFailure(400, "invalid_github_url", "Only github.com plugin URLs are supported.");
        var segments = url.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries).Select(Uri.UnescapeDataString).ToList();
        if (segments.Count < 2) throw new LibraryFailure(400, "invalid_github_url", "GitHub URL must include an owner and repository.");
        var repo = segments[1].EndsWith(".git", StringComparison.OrdinalIgnoreCase) ? segments[1][..^4] : segments[1];
        if (repo.Length == 0) throw new LibraryFailure(400, "invalid_github_url", "GitHub URL must include a repository.");
        if (segments.Count == 2) return new GithubTarget(null, $"{segments[0]}/{repo}", "");
        if (segments[2] != "tree") throw new LibraryFailure(400, "invalid_github_url", "Use a GitHub repository or tree URL, for example /tree/main/sales.");
        if (segments.Count < 4) throw new LibraryFailure(400, "invalid_github_url", "GitHub tree URL must include a branch.");
        return new GithubTarget(segments[3], $"{segments[0]}/{repo}", NormalizePath(string.Join('/', segments.Skip(4))));
    }

    private static string NormalizePath(string value)
    {
        var v = value.Trim();
        if (v.StartsWith("./")) v = v[2..];
        return v.Trim('/');
    }

    // ---------- reading GitHub ----------

    private sealed record Snapshot(string Branch, string HeadSha, string Repo, string RootPath, List<string> Blobs, Dictionary<string, string> FullPath, bool Truncated);

    private async Task<(JsonElement Body, int Status)> GetJsonAsync(string path)
    {
        using var client = http.CreateClient(ClientName);
        client.Timeout = TimeSpan.FromSeconds(30);
        using var request = new HttpRequestMessage(HttpMethod.Get, options.Value.GithubApiBase.TrimEnd('/') + path);
        request.Headers.TryAddWithoutValidation("Accept", "application/vnd.github+json");
        request.Headers.TryAddWithoutValidation("User-Agent", "workai360-library");
        HttpResponseMessage response;
        try { response = await client.SendAsync(request); }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException) { throw new LibraryFailure(502, "github_request_failed", "GitHub could not be reached."); }
        using (response)
        {
            var text = await response.Content.ReadAsStringAsync();
            JsonElement body = default;
            try { if (text.Length > 0) body = JsonDocument.Parse(text).RootElement.Clone(); } catch (JsonException) { }
            if (!response.IsSuccessStatusCode)
            {
                var message = body.ValueKind == JsonValueKind.Object && body.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String ? m.GetString()! : $"GitHub request failed with status {(int)response.StatusCode}.";
                throw new LibraryFailure((int)response.StatusCode == 404 ? 404 : 502, "github_request_failed", message);
            }
            return (body, (int)response.StatusCode);
        }
    }

    private static string? Str(JsonElement obj, string name) => obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private async Task<Snapshot> ReadTreeAsync(GithubTarget target)
    {
        var parts = target.Repo.Split('/');
        var owner = Uri.EscapeDataString(parts[0]);
        var repo = Uri.EscapeDataString(parts[1]);
        var branch = target.Branch;
        if (branch is null)
        {
            var (info, _) = await GetJsonAsync($"/repos/{owner}/{repo}");
            branch = Str(info, "default_branch")?.Trim();
            if (string.IsNullOrEmpty(branch)) throw new LibraryFailure(502, "github_response_incomplete", "GitHub repository response was missing the default branch.");
            if (info.TryGetProperty("private", out var priv) && priv.ValueKind == JsonValueKind.True)
                throw new LibraryFailure(400, "private_github_repo", "Private GitHub repositories must be imported through the GitHub connector.");
        }
        var (commit, _) = await GetJsonAsync($"/repos/{owner}/{repo}/commits/{Uri.EscapeDataString(branch)}");
        var sha = Str(commit, "sha") ?? "";
        var treeSha = commit.ValueKind == JsonValueKind.Object && commit.TryGetProperty("commit", out var c) && c.TryGetProperty("tree", out var t) ? Str(t, "sha") ?? "" : "";
        if (sha.Length == 0 || treeSha.Length == 0) throw new LibraryFailure(502, "github_response_incomplete", "GitHub commit response was missing the head or tree sha.");
        var (tree, _) = await GetJsonAsync($"/repos/{owner}/{repo}/git/trees/{Uri.EscapeDataString(treeSha)}?recursive=1");
        if (tree.ValueKind != JsonValueKind.Object || !tree.TryGetProperty("tree", out var entries) || entries.ValueKind != JsonValueKind.Array)
            throw new LibraryFailure(502, "github_response_incomplete", "GitHub tree response was invalid.");

        var root = NormalizePath(target.RootPath);
        var blobs = new List<string>();
        var full = new Dictionary<string, string>();
        var any = false;
        foreach (var entry in entries.EnumerateArray())
        {
            var path = Str(entry, "path") is { } p ? NormalizePath(p) : "";
            var type = Str(entry, "type");
            if (path.Length == 0 || type is not ("blob" or "tree")) continue;
            if (root.Length > 0 && path != root && !path.StartsWith(root + "/")) continue;
            var relative = root.Length > 0 ? (path == root ? "" : path[(root.Length + 1)..]) : path;
            if (relative.Length == 0) continue;
            any = true;
            full[relative] = path;
            if (type == "blob") blobs.Add(relative);
        }
        if (!any) throw new LibraryFailure(404, "github_plugin_root_not_found", "No files were found at that GitHub plugin path.");
        return new Snapshot(branch, sha, target.Repo, root, blobs, full, tree.TryGetProperty("truncated", out var tr) && tr.ValueKind == JsonValueKind.True);
    }

    private async Task<string?> ReadFileAsync(Snapshot snapshot, string relativePath)
    {
        var parts = snapshot.Repo.Split('/');
        var fullPath = snapshot.FullPath.GetValueOrDefault(relativePath, relativePath);
        string Enc(string v) => string.Join('/', v.Split('/').Select(Uri.EscapeDataString));
        using var client = http.CreateClient(ClientName);
        client.Timeout = TimeSpan.FromSeconds(30);
        using var request = new HttpRequestMessage(HttpMethod.Get, $"{options.Value.GithubRawBase.TrimEnd('/')}/{Uri.EscapeDataString(parts[0])}/{Uri.EscapeDataString(parts[1])}/{Enc(snapshot.HeadSha)}/{Enc(fullPath)}");
        request.Headers.TryAddWithoutValidation("User-Agent", "workai360-library");
        try
        {
            using var response = await client.SendAsync(request);
            if ((int)response.StatusCode == 404) return null;
            if (!response.IsSuccessStatusCode) throw new LibraryFailure(502, "github_request_failed", $"GitHub file download failed with status {(int)response.StatusCode}.");
            return await response.Content.ReadAsStringAsync();
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException) { throw new LibraryFailure(502, "github_request_failed", "GitHub could not be reached."); }
    }

    // ---------- working out what is there ----------

    private sealed record FoundPlugin(string Key, string Root, string Name, string? Description);

    private sealed class PlanSkill
    {
        public required string PluginKey { get; init; }
        public required string PluginName { get; init; }
        public required string SkillKey { get; init; }
        public required string SourcePath { get; init; }
        public required string Name { get; init; }
        public string? Description { get; init; }
        public bool Supported { get; init; }
        public string? RawSourceText { get; init; }
    }

    private sealed class Plan
    {
        public required Snapshot Snapshot { get; init; }
        public required string Classification { get; init; }
        public object? Marketplace { get; init; }
        public required List<FoundPlugin> Plugins { get; init; }
        public required List<PlanSkill> Skills { get; init; }
        public required List<Dictionary<string, object?>> Servers { get; init; }
        public required List<string> Warnings { get; init; }
        public required Dictionary<string, int> McpCounts { get; init; }
    }

    private static string Join(string root, string child) => root.Length == 0 ? child : $"{root}/{child}";
    private static string Base(string path) => path.Contains('/') ? path[(path.LastIndexOf('/') + 1)..] : path;

    private async Task<JsonElement> ReadJsonFileAsync(Snapshot snapshot, string path)
    {
        if (!snapshot.Blobs.Contains(path)) return default;
        var text = await ReadFileAsync(snapshot, path);
        if (text is null) return default;
        try { return JsonDocument.Parse(text).RootElement.Clone(); } catch (JsonException) { return default; }
    }

    private async Task<Plan> BuildPlanAsync(GithubTarget target)
    {
        var snapshot = await ReadTreeAsync(target);
        var warnings = new List<string>();
        if (snapshot.Truncated) warnings.Add("GitHub cut the repository listing short, so some files may be missing.");
        var plugins = new List<FoundPlugin>();
        object? marketplace = null;
        string classification;

        var market = await ReadJsonFileAsync(snapshot, ".claude-plugin/marketplace.json");
        if (market.ValueKind == JsonValueKind.Object)
        {
            classification = "claude_marketplace_repo";
            var owner = market.TryGetProperty("owner", out var o) ? (o.ValueKind == JsonValueKind.Object ? Str(o, "name") : o.ValueKind == JsonValueKind.String ? o.GetString() : null) : null;
            var meta = market.TryGetProperty("metadata", out var m) ? m : default;
            marketplace = new { description = Str(meta, "description") ?? Str(market, "description"), name = Str(market, "name"), owner, version = Str(meta, "version") ?? Str(market, "version") };
            if (market.TryGetProperty("plugins", out var list) && list.ValueKind == JsonValueKind.Array)
                foreach (var entry in list.EnumerateArray())
                {
                    var name = Str(entry, "name") ?? "plugin";
                    if (!entry.TryGetProperty("source", out var source) || source.ValueKind != JsonValueKind.String)
                    {
                        warnings.Add($"Plugin \"{name}\" lives somewhere other than this repository and was skipped.");
                        continue;
                    }
                    var root = NormalizePath(source.GetString()!);
                    plugins.Add(new FoundPlugin(root.Length == 0 ? "." : root, root, name, Str(entry, "description")));
                }
        }
        else
        {
            var manifests = snapshot.Blobs.Where(b => b == "plugin.json" || b.EndsWith("/plugin.json")).ToList();
            if (manifests.Count > 0)
            {
                foreach (var manifest in manifests.OrderBy(x => x, StringComparer.Ordinal))
                {
                    var dir = manifest.Contains('/') ? manifest[..manifest.LastIndexOf('/')] : "";
                    var root = dir == ".claude-plugin" ? "" : dir.EndsWith("/.claude-plugin") ? dir[..^"/.claude-plugin".Length] : dir;
                    if (plugins.Any(p => p.Root == root)) continue;
                    var json = await ReadJsonFileAsync(snapshot, manifest);
                    plugins.Add(new FoundPlugin(root.Length == 0 ? "." : root, root, Str(json, "name") ?? (root.Length == 0 ? snapshot.Repo.Split('/')[1] : Base(root)), Str(json, "description")));
                }
                classification = plugins.Count == 1 ? "claude_single_plugin_repo" : "claude_multi_plugin_repo";
            }
            else
            {
                var roots = new SortedSet<string>(StringComparer.Ordinal);
                foreach (var blob in snapshot.Blobs)
                {
                    var i = blob.IndexOf("skills/", StringComparison.Ordinal);
                    if (i == 0) roots.Add("");
                    else if (i > 0 && blob[i - 1] == '/') roots.Add(blob[..(i - 1)]);
                }
                foreach (var root in roots) plugins.Add(new FoundPlugin(root.Length == 0 ? "." : root, root, root.Length == 0 ? snapshot.Repo.Split('/')[1] : Base(root), null));
                classification = plugins.Count > 0 ? "folder_inferred_repo" : "unsupported";
                if (plugins.Count == 0) warnings.Add("No skills or plugin files were found at that path.");
            }
        }

        var skills = new List<PlanSkill>();
        var servers = new List<Dictionary<string, object?>>();
        var mcpCounts = new Dictionary<string, int>();
        foreach (var plugin in plugins)
        {
            var prefix = plugin.Root.Length == 0 ? "skills/" : plugin.Root + "/skills/";
            foreach (var path in snapshot.Blobs.Where(b => b.StartsWith(prefix) && b.EndsWith("/SKILL.md") && b[prefix.Length..].Split('/').Length == 2).OrderBy(b => b, StringComparer.Ordinal))
            {
                var text = await ReadFileAsync(snapshot, path);
                var folder = path[prefix.Length..].Split('/')[0];
                string name = folder; string? description = null; var supported = false;
                if (text is not null)
                {
                    var parsed = SkillMarkdown.Parse(text);
                    if (parsed.Name.Length > 0) name = parsed.Name;
                    description = parsed.Description.Length > 0 ? parsed.Description : null;
                    try { Projections.Derive("skill", text, default, default); supported = true; }
                    catch (LibraryFailure) { supported = false; }
                }
                skills.Add(new PlanSkill { PluginKey = plugin.Key, PluginName = plugin.Name, SkillKey = path, SourcePath = path, Name = name, Description = description, Supported = supported, RawSourceText = supported ? text : null });
            }

            var mcpPath = Join(plugin.Root, ".mcp.json");
            var mcp = await ReadJsonFileAsync(snapshot, mcpPath);
            var map = mcp.ValueKind == JsonValueKind.Object ? (mcp.TryGetProperty("mcpServers", out var ms) && ms.ValueKind == JsonValueKind.Object ? ms : mcp) : default;
            if (map.ValueKind == JsonValueKind.Object)
                foreach (var server in map.EnumerateObject())
                {
                    var config = server.Value;
                    var url = Str(config, "url");
                    string? reason = null;
                    if (config.ValueKind != JsonValueKind.Object) reason = "invalid_config";
                    else if (url is null && config.TryGetProperty("command", out _)) reason = "local_unsupported";
                    else if (url is null) reason = "missing_url";
                    else if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != "https") reason = "invalid_url";
                    else if (uri.IsLoopback) reason = "local_unsupported";
                    else if (config.TryGetProperty("headers", out _)) reason = "headers_unsupported";
                    mcpCounts[plugin.Key] = mcpCounts.GetValueOrDefault(plugin.Key) + 1;
                    servers.Add(new Dictionary<string, object?>
                    {
                        ["authType"] = reason is null ? "oauth" : null, ["connectionId"] = null, ["mapsTo"] = null, ["name"] = server.Name, ["pluginKey"] = plugin.Key, ["pluginName"] = plugin.Name,
                        ["reuse"] = null, ["serverKey"] = $"{plugin.Key}:{server.Name}", ["skippedReason"] = reason, ["sourceSchemaVersion"] = null, ["sourcePath"] = mcpPath, ["supported"] = reason is null, ["url"] = url,
                    });
                }
        }
        if (servers.Any(s => (bool)s["supported"]!)) warnings.Add("Remote MCP servers are listed but are not imported yet: connecting them is not available in this version.");
        return new Plan { Snapshot = snapshot, Classification = classification, Marketplace = marketplace, Plugins = plugins, Skills = skills, Servers = servers, Warnings = warnings, McpCounts = mcpCounts };
    }

    public async Task<object> PreviewAsync(string url)
    {
        var plan = await BuildPlanAsync(ParseUrl(url));
        return new
        {
            branch = plan.Snapshot.Branch,
            classification = plan.Classification,
            marketplace = plan.Marketplace,
            plugins = plan.Plugins.Select(p => new { description = p.Description, key = p.Key, mcpCount = plan.McpCounts.GetValueOrDefault(p.Key), name = p.Name, skillCount = plan.Skills.Count(s => s.PluginKey == p.Key && s.Supported) }).ToList(),
            repositoryFullName = plan.Snapshot.Repo,
            rootPath = plan.Snapshot.RootPath,
            servers = plan.Servers,
            skills = plan.Skills.Select(s => new { description = s.Description, name = s.Name, pluginKey = s.PluginKey, pluginName = s.PluginName, skillKey = s.SkillKey, skippedReason = s.Supported ? null : "invalid_skill", sourceSchemaVersion = (string?)null, sourcePath = s.SourcePath, supported = s.Supported }).ToList(),
            sourceSchemaVersion = (string?)null,
            sourceRevisionRef = plan.Snapshot.HeadSha,
            warnings = plan.Warnings,
        };
    }

    // ---------- importing ----------

    public async Task<object> ImportAsync(Actor a, ImportRequest request)
    {
        if (!a.Has("plugins.import")) throw new LibraryForbidden("Only organization owners and admins can import plugins from GitHub.");
        if (request.MarketplaceId is not null) await lib.MarketplaceAsync(a, request.MarketplaceId, LibRole.Editor);
        var target = ParseUrl(request.GithubUrl);
        var plan = await BuildPlanAsync(target);

        var selected = request.SelectedSkillKeys is null ? plan.Skills : plan.Skills.Where(s => request.SelectedSkillKeys.Contains(s.SkillKey)).ToList();
        var supported = selected.Where(s => s.Supported && s.RawSourceText is not null).ToList();
        var skippedSkills = selected.Where(s => !s.Supported).Select(s => new { name = s.Name, reason = "invalid_skill", sourcePath = s.SourcePath }).ToList();
        var skippedServers = plan.Servers.Select(s => new { mapsTo = (object?)null, name = (string)s["name"]!, reason = (string?)s["skippedReason"] ?? "unsupported_auth", reuse = (object?)null }).ToList();
        if (supported.Count == 0) throw new LibraryFailure(400, "nothing_to_import", "Nothing selected can be imported. Choose at least one valid skill.");

        var name = Projections.Trimmed(request.Name) ?? (plan.Marketplace is not null && plan.Plugins.Count > 1 ? Str(JsonSerializer.SerializeToElement(plan.Marketplace), "name") : null)
            ?? (plan.Plugins.Count == 1 ? plan.Plugins[0].Name : plan.Snapshot.Repo.Split('/')[1]) ?? plan.Snapshot.Repo.Split('/')[1];
        var sourceUrl = $"https://github.com/{plan.Snapshot.Repo}" + (target.Branch is not null ? $"/tree/{target.Branch}" + (plan.Snapshot.RootPath.Length > 0 ? "/" + plan.Snapshot.RootPath : "") : "");

        var existing = await db.Set<Plugin>().FirstOrDefaultAsync(p => p.OrganizationId == a.OrgId && p.CreatedByMemberId == a.MemberId && p.Name == name && p.SourceRepositoryUrl == sourceUrl && p.Status == "active");
        var mode = existing is null ? "created" : "updated";
        var plugin = existing ?? await store.CreatePluginAsync(a, name, request.Description ?? plan.Plugins.FirstOrDefault()?.Description, sourceUrl, "claude-plugin", null, [], false, null);

        var importedSkills = new List<object>(); var updatedSkills = new List<object>(); var unchanged = new List<object>(); var removed = new List<object>();
        var heldBefore = existing is null ? [] : await (from m in db.Set<PluginConfigObject>().AsNoTracking()
                                                         join o in db.Set<ConfigObject>().AsNoTracking() on m.ConfigObjectId equals o.Id
                                                         where m.PluginId == plugin.Id && m.RemovedAt == null && o.CurrentRelativePath != null && o.ObjectType == "skill"
                                                         select o).ToListAsync();
        foreach (var skill in supported)
        {
            var match = heldBefore.FirstOrDefault(o => o.CurrentRelativePath == skill.SourcePath);
            if (match is null)
            {
                var created = await store.CreateConfigObjectAsync(a, "skill", "import", [plugin.Id], new ConfigInput(skill.RawSourceText!.Trim(), null, null, default, default), skill.SourcePath, createdVia: "import", revision: plan.Snapshot.HeadSha);
                importedSkills.Add(new { configObjectId = created.Id, name = created.Title, sourcePath = skill.SourcePath });
                if (request.Access is null || request.Access.OrgWide) await store.GrantAsync(a, GrantKinds.ConfigObject, created.Id, null, null, true, "viewer");
                else await ShareAsync(a, GrantKinds.ConfigObject, created.Id, request.Access);
                continue;
            }
            var latest = (await db.Set<ConfigObjectVersion>().AsNoTracking().Where(v => v.ConfigObjectId == match.Id).ToListAsync()).OrderByDescending(v => v.CreatedAt).ThenByDescending(v => v.Id, StringComparer.Ordinal).FirstOrDefault();
            if (latest?.RawSourceText == skill.RawSourceText!.Trim()) { unchanged.Add(new { name = match.Title, objectType = "skill" }); continue; }
            var updated = await store.CreateVersionAsync(a, match.Id, new ConfigInput(skill.RawSourceText.Trim(), null, null, default, default), plan.Snapshot.HeadSha);
            updatedSkills.Add(new { configObjectId = updated.Id, name = updated.Title, sourcePath = skill.SourcePath });
        }
        // Things imported before that the repository no longer has are taken out of the plugin and archived (never deleted).
        if (request.SelectedSkillKeys is null)
            foreach (var gone in heldBefore.Where(o => !plan.Skills.Any(s => s.SourcePath == o.CurrentRelativePath)))
            {
                await store.DetachAsync(a, gone.Id, plugin.Id);
                await store.SetConfigObjectLifecycleAsync(a, gone.Id, "archive");
                removed.Add(new { configObjectId = gone.Id, name = gone.Title, objectType = "skill", sourcePath = gone.CurrentRelativePath });
            }

        if (existing is null)
        {
            if (request.Access is null || request.Access.OrgWide) await store.GrantAsync(a, GrantKinds.Plugin, plugin.Id, null, null, true, "viewer");
            else await ShareAsync(a, GrantKinds.Plugin, plugin.Id, request.Access);
        }
        if (request.MarketplaceId is not null) await store.AttachPluginToMarketplaceAsync(a, request.MarketplaceId, plugin.Id, null);

        return new
        {
            imported = Array.Empty<object>(),
            importedSkills,
            marketplaceId = request.MarketplaceId,
            mode,
            plugin = await store.PluginJsonAsync(await db.Set<Plugin>().AsNoTracking().FirstAsync(p => p.Id == plugin.Id)),
            removed,
            skipped = skippedServers,
            skippedSkills,
            unchanged,
            updatedSkills,
        };
    }

    private async Task ShareAsync(Actor a, string kind, string id, ImportAccess access)
    {
        foreach (var memberId in access.MemberIds) await store.GrantAsync(a, kind, id, memberId, null, false, "viewer");
        foreach (var teamId in access.TeamIds) await store.GrantAsync(a, kind, id, null, teamId, false, "viewer");
    }
}
