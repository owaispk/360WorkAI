namespace WorkAI360.Api.Features.Connections;

/// <summary>A well-known MCP server an admin can add with one click. Static data copied from the reference's preset list.</summary>
public sealed record McpPreset(string PresetId, string DisplayName, string Description, string Url, string AuthType, string[]? SupportedAuthTypes, bool RequiresOAuthClient,
    string? DefaultOAuthClientId, string? AuthorizationServerIssuer, string[]? DefaultOAuthScopes, string[]? OptionalOAuthScopes, bool Expanded);

public static class McpPresets
{
    public static readonly IReadOnlyList<McpPreset> All =
    [
        new("github", "GitHub", "PRs, issues, code, and CI. Use a registered GitHub OAuth app for individual accounts, or a personal access token for a shared connection. Automatic app registration is not supported.", "https://api.githubcopilot.com/mcp/", "oauth", ["oauth", "apikey"], true, null, null, null, null, false),
        new("notion", "Notion", "Pages, databases, and project docs in sync.", "https://mcp.notion.com/mcp", "oauth", null, false, null, null, null, null, false),
        new("linear", "Linear", "Plan sprints and ship tickets faster.", "https://mcp.linear.app/mcp", "oauth", null, false, null, null, null, null, false),
        new("stripe", "Stripe", "Inspect payments, invoices, and subscriptions.", "https://mcp.stripe.com", "oauth", null, false, null, null, null, null, false),
        new("sentry", "Sentry", "Track releases and resolve production errors.", "https://mcp.sentry.dev/mcp", "oauth", null, false, null, null, null, null, false),
        new("granola", "Granola", "Search your meeting notes and transcripts.", "https://mcp.granola.ai/mcp", "oauth", null, false, null, null, null, null, false),
        new("polar", "Polar", "Products, subscriptions, orders, and customer billing.", "https://mcp.polar.sh/mcp/polar-mcp", "oauth", null, false, null, null, null, null, false),
        new("slack", "Slack", "Channels, DMs, and search. Requires an eligible internal or Slack Marketplace-published app; not every Slack app can use MCP. An admin configures its OAuth client once, then each person connects their own account. Automatic app registration is not supported.", "https://mcp.slack.com/mcp", "oauth", null, true, null, "https://mcp.slack.com", ["search:read.public", "search:read.private", "search:read.im", "search:read.mpim", "search:read.files", "chat:write", "channels:history", "groups:history", "im:history", "mpim:history", "users:read"], ["canvases:read", "canvases:write", "channels:read", "channels:write", "emoji:read", "files:read", "files:write", "groups:read", "groups:write", "im:read", "im:write", "lists:read", "lists:write", "mpim:read", "mpim:write", "reactions:read", "reactions:write", "search:read.users", "users:read.email"], false),
        new("exa", "Exa", "Web search, code context, and research. This connection uses your org's Exa API key from dashboard.exa.ai; provider usage limits and billing apply.", "https://mcp.exa.ai/mcp", "apikey", null, false, null, null, null, null, false),
        new("render", "Render", "Deploy and manage services, databases, and logs. Sign in with your Render account.", "https://mcp.render.com/mcp", "oauth", ["oauth", "apikey"], false, "openwork", "https://api.render.com", null, null, false),
        new("context7", "Context7", "Up-to-date library documentation and code examples. Connect without an API key using Context7's rate-limited anonymous access.", "https://mcp.context7.com/mcp", "none", null, false, null, null, null, null, false),
        new("airtable", "Airtable", "Read and update Airtable bases, tables, and records. Sign in with your Airtable account.", "https://mcp.airtable.com/mcp", "oauth", null, false, null, null, null, null, true),
        new("amplitude", "Amplitude", "Inspect Amplitude analytics, events, and product insights. Sign in with your Amplitude account.", "https://mcp.amplitude.com/mcp", "oauth", null, false, null, null, null, null, true),
        new("cal", "Cal.com", "Manage Cal.com scheduling, event types, and bookings. Sign in with your Cal.com account.", "https://mcp.cal.com/mcp", "oauth", null, false, null, null, null, null, true),
        new("canva", "Canva", "Search and create Canva designs, folders, and assets. Sign in with your Canva account.", "https://mcp.canva.com/mcp", "oauth", null, false, null, null, null, null, true),
        new("figma", "Figma", "Read Figma files, designs, and dev mode details. Sign in with your Figma account.", "https://mcp.figma.com/mcp", "oauth", null, false, null, null, null, null, true),
        new("fireflies", "Fireflies", "Search your Fireflies meeting notes and transcripts. Sign in with your Fireflies account.", "https://api.fireflies.ai/mcp", "oauth", null, false, null, null, null, null, true),
        new("huggingface", "Hugging Face", "Browse Hugging Face models, datasets, and Spaces. Sign in with your Hugging Face account.", "https://huggingface.co/mcp", "oauth", null, false, null, null, null, null, true),
        new("honeycomb", "Honeycomb", "Query Honeycomb traces, events, and SLOs. Sign in with your Honeycomb account.", "https://mcp.honeycomb.io/mcp", "oauth", null, false, null, null, null, null, true),
        new("klaviyo", "Klaviyo", "Inspect Klaviyo campaigns, flows, and contact data. Sign in with your Klaviyo account.", "https://mcp.klaviyo.com/mcp", "oauth", null, false, null, null, null, null, true),
        new("lucid", "Lucid", "Open and update Lucidchart and Lucidspark documents. Sign in with your Lucid account.", "https://mcp.lucid.app/mcp", "oauth", null, false, null, null, null, null, true),
        new("monday", "monday.com", "Manage monday.com boards, items, and workspaces. Sign in with your monday.com account.", "https://mcp.monday.com/mcp", "oauth", null, false, null, null, null, null, true),
        new("mural", "Mural", "Read and update Mural canvases, rooms, and workspaces. Sign in with your Mural account.", "https://mcp-canvas.mural.co/mcp", "oauth", null, false, null, null, null, null, true),
        new("posthog", "PostHog", "Inspect PostHog events, persons, and insights. Sign in with your PostHog account.", "https://mcp.posthog.com/mcp", "oauth", null, false, null, null, null, null, true),
        new("semgrep", "Semgrep", "Run Semgrep security scans and review findings. Sign in with your Semgrep account.", "https://mcp.semgrep.ai/mcp", "oauth", null, false, null, null, null, null, true),
        new("tavily", "Tavily", "Web search and research for agents. Uses your Tavily API key from app.tavily.com; provider rate limits and billing apply.", "https://mcp.tavily.com/mcp", "apikey", null, false, null, null, null, null, true),
        new("vercel", "Vercel", "Manage Vercel projects, deployments, and logs. Sign in with your Vercel account.", "https://mcp.vercel.com", "oauth", null, false, null, null, null, null, true),
    ];

    /// <summary>The catalog shown to people: the core presets, plus the extra reviewed ones when <paramref name="expanded"/> is on.</summary>
    public static IEnumerable<McpPreset> ForCatalog(bool expanded) => All.Where(p => expanded || !p.Expanded);

    public static Dictionary<string, object?> ToJson(McpPreset p, string? callbackUrl)
    {
        var d = new Dictionary<string, object?> { ["presetId"] = p.PresetId, ["displayName"] = p.DisplayName, ["description"] = p.Description, ["url"] = p.Url, ["authType"] = p.AuthType };
        if (p.SupportedAuthTypes is not null) d["supportedAuthTypes"] = p.SupportedAuthTypes;
        if (p.RequiresOAuthClient) d["requiresOAuthClient"] = true;
        if (p.DefaultOAuthClientId is not null) d["defaultOAuthClientId"] = p.DefaultOAuthClientId;
        if (p.AuthorizationServerIssuer is not null) d["authorizationServerIssuer"] = p.AuthorizationServerIssuer;
        if (p.DefaultOAuthScopes is not null) d["defaultOAuthScopes"] = p.DefaultOAuthScopes;
        if (p.OptionalOAuthScopes is not null) d["optionalOAuthScopes"] = p.OptionalOAuthScopes;
        if (p.RequiresOAuthClient && callbackUrl is not null) d["oauthCallbackUrl"] = callbackUrl;
        return d;
    }
}
