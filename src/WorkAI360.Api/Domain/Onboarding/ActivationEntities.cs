using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.Onboarding;

/// <summary>
/// A "Get set up" step only a client can see (its first answer, a provider key saved on the device, a local skill run) or the member hiding the
/// checklist. One row per member and step: the first report wins and repeats change nothing. Identifiers and a duration only.
/// </summary>
public sealed class ActivationEvent
{
    public required string MemberId { get; set; }
    /// <summary>first_response | use_skill | own_provider | dismiss</summary>
    public required string Step { get; set; }
    public required string OrganizationId { get; set; }
    public int? DurationMs { get; set; }
    /// <summary>app (the person's own client).</summary>
    public required string Source { get; set; }
    public DateTime CreatedAt { get; set; }
}

public sealed class ActivationEventConfiguration : IEntityTypeConfiguration<ActivationEvent>
{
    public void Configure(EntityTypeBuilder<ActivationEvent> b)
    {
        b.HasKey(e => new { e.MemberId, e.Step });
        b.Property(e => e.Step).HasMaxLength(32);
        b.Property(e => e.Source).HasMaxLength(16);
        b.HasIndex(e => e.OrganizationId);
    }
}
