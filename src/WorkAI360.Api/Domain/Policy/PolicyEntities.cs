using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using WorkAI360.Api.Data;

namespace WorkAI360.Api.Domain.Policy;

/// <summary>
/// A desktop policy: what the desktop app may do for the people, teams and roles it is assigned to. Every workspace has one default policy
/// (always on, assigned to no one: it is the base for everyone). Deleting a policy hides it and frees its key.
/// </summary>
public sealed class DesktopPolicy : IDerivedKeys
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    /// <summary>A stable key for declarative provisioning; unique per workspace while set.</summary>
    public string? ExternalKey { get; set; }
    public required string PolicyName { get; set; }
    public bool IsDefault { get; set; }
    public bool IsEnabled { get; set; }
    public int Priority { get; set; }
    /// <summary>The policy document as JSON (see <c>DesktopPolicyRules</c>).</summary>
    public required string PolicyJson { get; set; }
    public string? CreatedByMemberId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public DateTime? DeletedAt { get; set; }

    /// <summary>The workspace id while this is the workspace's live default policy, empty otherwise: a plain unique index makes it "at most one default".</summary>
    public string? DefaultKey { get; set; }

    public void RefreshKeys() => DefaultKey = IsDefault && DeletedAt is null ? OrganizationId : null;
}

/// <summary>Who a policy applies to: one person, one team, or everyone holding a role (exactly one of the three is set).</summary>
public sealed class DesktopPolicyAssignment
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string PolicyId { get; set; }
    public string? MemberId { get; set; }
    public string? TeamId { get; set; }
    public string? Role { get; set; }
    /// <summary>m:id, t:id or r:role. Unique per policy, so two writes racing to assign the same thing end with one row.</summary>
    public required string SubjectKey { get; set; }
    public DateTime CreatedAt { get; set; }
}

/// <summary>What agents may do for everyone (ScopeKey "everyone") or for one team. Settings are stored in their normalized form; nothing set means no row.</summary>
public sealed class AgentPermissionPolicy
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string ScopeKey { get; set; }
    public string? TeamId { get; set; }
    public required string SettingsJson { get; set; }
    public string? UpdatedByMemberId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

/// <summary>The system prompt for everyone or for one team. One prompt per scope.</summary>
public sealed class OrgPrompt
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string ScopeKey { get; set; }
    public string? TeamId { get; set; }
    public required string Name { get; set; }
    public required string Content { get; set; }
    public string? UpdatedByMemberId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

/// <summary>The model new chats start with, for everyone or for one team.</summary>
public sealed class OrgDefaultModel
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string ScopeKey { get; set; }
    public string? TeamId { get; set; }
    public required string ProviderId { get; set; }
    public required string ModelId { get; set; }
    public string? UpdatedByMemberId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

/// <summary>Workspace-wide switches that are not tied to a team: which Automations are allowed and Workbot's chosen model. One row per workspace (the id is the workspace's).</summary>
public sealed class OrgPolicySettings
{
    public required string Id { get; set; }
    public bool DesktopAutomations { get; set; } = true;
    public bool CloudAutomations { get; set; } = true;
    public string? WorkbotModel { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class DesktopPolicyConfiguration : IEntityTypeConfiguration<DesktopPolicy>
{
    public void Configure(EntityTypeBuilder<DesktopPolicy> b)
    {
        b.HasIndex(p => new { p.OrganizationId, p.CreatedAt });
        b.HasIndex(p => p.DefaultKey).IsUnique();
        b.HasIndex(p => new { p.OrganizationId, p.ExternalKey }).IsUnique();   // policies without a key have none, and empty values are distinct
    }
}

public sealed class DesktopPolicyAssignmentConfiguration : IEntityTypeConfiguration<DesktopPolicyAssignment>
{
    public void Configure(EntityTypeBuilder<DesktopPolicyAssignment> b)
    {
        b.HasIndex(a => new { a.PolicyId, a.SubjectKey }).IsUnique();
        b.HasIndex(a => a.MemberId);
        b.HasIndex(a => a.TeamId);
        // Removing a team or a person removes what was assigned to them, in the same statement that removes them.
        b.HasOne<Team>().WithMany().HasForeignKey(a => a.TeamId).OnDelete(DeleteBehavior.Cascade);
        b.HasOne<Member>().WithMany().HasForeignKey(a => a.MemberId).OnDelete(DeleteBehavior.Cascade);
    }
}

public sealed class AgentPermissionPolicyConfiguration : IEntityTypeConfiguration<AgentPermissionPolicy>
{
    public void Configure(EntityTypeBuilder<AgentPermissionPolicy> b)
    {
        b.HasIndex(p => new { p.OrganizationId, p.ScopeKey }).IsUnique();
        b.HasOne<Team>().WithMany().HasForeignKey(p => p.TeamId).OnDelete(DeleteBehavior.Cascade);
    }
}

public sealed class OrgPromptConfiguration : IEntityTypeConfiguration<OrgPrompt>
{
    public void Configure(EntityTypeBuilder<OrgPrompt> b)
    {
        b.HasIndex(p => new { p.OrganizationId, p.ScopeKey }).IsUnique();
        b.HasOne<Team>().WithMany().HasForeignKey(p => p.TeamId).OnDelete(DeleteBehavior.Cascade);
    }
}

public sealed class OrgDefaultModelConfiguration : IEntityTypeConfiguration<OrgDefaultModel>
{
    public void Configure(EntityTypeBuilder<OrgDefaultModel> b)
    {
        b.HasIndex(p => new { p.OrganizationId, p.ScopeKey }).IsUnique();
        b.HasOne<Team>().WithMany().HasForeignKey(p => p.TeamId).OnDelete(DeleteBehavior.Cascade);
    }
}
