using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.Onboarding;

/// <summary>A fixed-window counter kept in the database (so every instance sees it): "at most N of this per hour". Used for download-link emails and workspace bootstraps.</summary>
public sealed class OnboardingRateLimit
{
    public required string Id { get; set; }
    public required string Key { get; set; }
    public int Count { get; set; }
    /// <summary>When the window opened, in Unix milliseconds.</summary>
    public long WindowStart { get; set; }
}

/// <summary>
/// A provisional workspace an agent created before any person signed up ("provision now, claim later"). It has a sign-in-less setup member
/// that owns the starter content until a person claims the workspace.
/// </summary>
public sealed class WorkspaceBootstrap
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string SetupMemberId { get; set; }
    public required string AgentUserId { get; set; }
    /// <summary>provisional, claimed or expired.</summary>
    public required string Status { get; set; }
    /// <summary>Random per bootstrap; the signed assertion names it, so only the newest assertion this server issued is recognized.</summary>
    public required string AssertionJti { get; set; }
    public string? DeviceKeyFingerprint { get; set; }
    public string? OwnerEmail { get; set; }
    /// <summary>JSON array of emails the new owner is asked to invite once the workspace is claimed.</summary>
    public string? TeammateEmailsJson { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? ClaimedAt { get; set; }
    /// <summary>When the agent's credentials stopped working (claimed or expired).</summary>
    public DateTime? CredentialsRevokedAt { get; set; }
    public DateTime CreatedAt { get; set; }
}

/// <summary>A one-use link a person opens to take over a provisional workspace. Only the SHA-256 of the token is stored.</summary>
public sealed class WorkspaceClaim
{
    public required string Id { get; set; }
    public required string BootstrapId { get; set; }
    public required string OrganizationId { get; set; }
    public required string TokenHash { get; set; }
    public required string Role { get; set; }
    /// <summary>pending, claimed or cancelled.</summary>
    public required string Status { get; set; }
    public DateTime ExpiresAt { get; set; }
    public string? ClaimedByUserId { get; set; }
    public DateTime? ClaimedAt { get; set; }
    public DateTime CreatedAt { get; set; }
}

/// <summary>A short code (ABCD-EFGH) the agent shows its person. Only the hash is stored.</summary>
public sealed class WorkspaceClaimCode
{
    public required string Id { get; set; }
    public required string BootstrapId { get; set; }
    public required string OrganizationId { get; set; }
    public required string CodeHash { get; set; }
    /// <summary>pending, accepted, reconciled or cancelled.</summary>
    public required string State { get; set; }
    public DateTime ExpiresAt { get; set; }
    public string? ClaimedByUserId { get; set; }
    public DateTime? AcceptedAt { get; set; }
    public DateTime? ReconciledAt { get; set; }
    public DateTime CreatedAt { get; set; }
}

/// <summary>One launch of the desktop app, reported by the app: step timings and a fixed failure code, nothing else.</summary>
public sealed class DesktopStartupReport
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string MemberId { get; set; }
    public required string AttemptId { get; set; }
    public required string AppVersion { get; set; }
    public required string Platform { get; set; }
    public bool Success { get; set; }
    public string? FailedStep { get; set; }
    public string? FailureReason { get; set; }
    public int? WindowMs { get; set; }
    public int? EngineMs { get; set; }
    public int? SignedInMs { get; set; }
    public int? OrgToolsMs { get; set; }
    public DateTime ObservedAt { get; set; }
}

/// <summary>The synthetic-diagnostics bearer token of a workspace, encrypted. Never returned by any route.</summary>
public sealed class EgressDiagnosticCredential
{
    public required string OrganizationId { get; set; }
    public required string TokenCipher { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class OnboardingRateLimitConfiguration : IEntityTypeConfiguration<OnboardingRateLimit>
{
    public void Configure(EntityTypeBuilder<OnboardingRateLimit> b) => b.HasIndex(r => r.Key).IsUnique();
}

public sealed class WorkspaceBootstrapConfiguration : IEntityTypeConfiguration<WorkspaceBootstrap>
{
    public void Configure(EntityTypeBuilder<WorkspaceBootstrap> b)
    {
        b.HasIndex(x => x.OrganizationId).IsUnique();
        b.HasIndex(x => x.AgentUserId).IsUnique();
        b.HasIndex(x => new { x.Status, x.ExpiresAt });
    }
}

public sealed class WorkspaceClaimConfiguration : IEntityTypeConfiguration<WorkspaceClaim>
{
    public void Configure(EntityTypeBuilder<WorkspaceClaim> b)
    {
        b.HasIndex(x => x.TokenHash).IsUnique();
        b.HasIndex(x => x.BootstrapId);
    }
}

public sealed class WorkspaceClaimCodeConfiguration : IEntityTypeConfiguration<WorkspaceClaimCode>
{
    public void Configure(EntityTypeBuilder<WorkspaceClaimCode> b)
    {
        b.HasIndex(x => x.CodeHash);
        b.HasIndex(x => x.BootstrapId);
    }
}

public sealed class DesktopStartupReportConfiguration : IEntityTypeConfiguration<DesktopStartupReport>
{
    public void Configure(EntityTypeBuilder<DesktopStartupReport> b)
    {
        // One row per launch of one workspace: a resend never changes the first report.
        b.HasIndex(x => new { x.OrganizationId, x.AttemptId }).IsUnique();
        b.HasIndex(x => new { x.OrganizationId, x.ObservedAt });
        b.Property(x => x.AppVersion).HasMaxLength(64);
        b.Property(x => x.Platform).HasMaxLength(16);
    }
}

public sealed class EgressDiagnosticCredentialConfiguration : IEntityTypeConfiguration<EgressDiagnosticCredential>
{
    public void Configure(EntityTypeBuilder<EgressDiagnosticCredential> b) => b.HasKey(x => x.OrganizationId);
}
