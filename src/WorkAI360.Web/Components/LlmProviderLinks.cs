namespace WorkAI360.Web.Components;

/// <summary>Dashboard button for model providers. Anyone may add a provider of their own, so it needs no permission.</summary>
public sealed class LlmProviderDashboardLinks : IDashboardLinkSource
{
    public IEnumerable<DashboardLink> Links => [new("Model providers", "/dashboard/custom-llm-providers", "llm-providers-link", 85)];
}
