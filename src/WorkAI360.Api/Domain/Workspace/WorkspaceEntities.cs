using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.Workspace;

/// <summary>
/// The receipt of one Workflow script run (a draft test, an exact-version run, a live run). A receipt keeps digests, the names of the tools the
/// script called, timings and the outcome. The result value and its Markdown are encrypted at rest and cleared (with a deletion time) when
/// someone erases the content; the receipt itself stays. Raw caller input is never stored, only its digest.
/// </summary>
public sealed class WorkflowRun
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public string? MemberId { get; set; }
    public string? AutomationRunId { get; set; }
    public string? PluginId { get; set; }
    public string? ConfigObjectId { get; set; }
    /// <summary>Set for runs of a saved version (the Workflow's snapshots); null for draft tests and ad hoc runs.</summary>
    public string? ConfigObjectVersionId { get; set; }
    /// <summary><c>plugin:{pluginId}:{configObjectId}</c> for a saved run, <c>live:plugin:…</c> for a live one, <c>workflow-test:…</c> for a draft test.</summary>
    public required string Source { get; set; }
    public required string CodeDigest { get; set; }
    /// <summary>succeeded or failed.</summary>
    public required string Status { get; set; }
    public string? ErrorKind { get; set; }
    public string? ErrorMessage { get; set; }
    /// <summary>JSON array of <c>{name}</c>.</summary>
    public string? ToolCallsJson { get; set; }
    public int ToolCallCount { get; set; }
    public int DurationMs { get; set; }
    public DateTime StartedAt { get; set; }
    public DateTime FinishedAt { get; set; }
    public string? ScriptInputDigest { get; set; }
    public string? InputSchemaDigest { get; set; }
    /// <summary>Encrypted JSON of the validated result, or null.</summary>
    public string? ValidatedResultCipher { get; set; }
    /// <summary>Encrypted Markdown rendering, or null.</summary>
    public string? ResultMarkdownCipher { get; set; }
    public string? ResultDigest { get; set; }
    public string? OutputSchemaDigest { get; set; }
    public string? RendererVersion { get; set; }
    public DateTime? ArtifactContentDeletedAt { get; set; }
    public DateTime CreatedAt { get; set; }
}

/// <summary>A generated view (an "app") bound to one Workflow. Its HTML lives in revisions; one revision is active.</summary>
public sealed class ArtifactView
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string ConfigObjectId { get; set; }
    public required string OwnerMemberId { get; set; }
    public required string Title { get; set; }
    public string? Description { get; set; }
    /// <summary>active or retired.</summary>
    public required string Status { get; set; }
    public string? ActiveRevisionId { get; set; }
    /// <summary>live or snapshot.</summary>
    public required string DataMode { get; set; }
    public bool UseInWorkflow { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

/// <summary>An immutable build of a view: the author's source, the compiled page, how the build went, and the output schema it was built against.</summary>
public sealed class ArtifactViewRevision
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string ArtifactViewId { get; set; }
    public required string CreatedByMemberId { get; set; }
    public required string ReactSource { get; set; }
    public required string CssSource { get; set; }
    public string? CompiledHtml { get; set; }
    /// <summary>JSON array of <c>{level, message, line, column}</c>.</summary>
    public required string BuildDiagnosticsJson { get; set; }
    /// <summary>ready or failed.</summary>
    public required string BuildStatus { get; set; }
    public required string SourceDigest { get; set; }
    public string? ResourceDigest { get; set; }
    public required string OutputSchemaDigest { get; set; }
    public required string OutputSchemaJson { get; set; }
    /// <summary>JSON <c>{connectDomains, resourceDomains, frameDomains, baseUriDomains}</c>.</summary>
    public required string CspJson { get; set; }
    public required string CompilerName { get; set; }
    public required string CompilerVersion { get; set; }
    public required string ReactVersion { get; set; }
    public int? CompiledHtmlBytes { get; set; }
    public DateTime? RetiredAt { get; set; }
    public DateTime CreatedAt { get; set; }
}

/// <summary>Personal placement of an app on one member's dashboard, separate from who may read the Workflow.</summary>
public sealed class DashboardApp
{
    public required string OrganizationId { get; set; }
    public required string MemberId { get; set; }
    public required string ArtifactViewId { get; set; }
    public DateTime CreatedAt { get; set; }
}

public sealed class WorkflowRunConfiguration : IEntityTypeConfiguration<WorkflowRun>
{
    public void Configure(EntityTypeBuilder<WorkflowRun> b)
    {
        b.HasIndex(r => new { r.OrganizationId, r.CreatedAt, r.Id });
        b.HasIndex(r => r.AutomationRunId);
        b.HasIndex(r => new { r.ConfigObjectId, r.FinishedAt });
    }
}

public sealed class ArtifactViewConfiguration : IEntityTypeConfiguration<ArtifactView>
{
    public void Configure(EntityTypeBuilder<ArtifactView> b)
    {
        b.HasIndex(v => new { v.OrganizationId, v.ConfigObjectId });
        b.HasIndex(v => new { v.OrganizationId, v.UpdatedAt, v.Id });
    }
}

public sealed class ArtifactViewRevisionConfiguration : IEntityTypeConfiguration<ArtifactViewRevision>
{
    public void Configure(EntityTypeBuilder<ArtifactViewRevision> b) => b.HasIndex(r => new { r.ArtifactViewId, r.CreatedAt, r.Id });
}

public sealed class DashboardAppConfiguration : IEntityTypeConfiguration<DashboardApp>
{
    public void Configure(EntityTypeBuilder<DashboardApp> b)
    {
        b.HasKey(d => new { d.OrganizationId, d.MemberId, d.ArtifactViewId });
        b.HasIndex(d => d.ArtifactViewId);
    }
}
