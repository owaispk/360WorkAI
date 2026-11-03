using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.Replay;

/// <summary>
/// A value that may be used only once while it is valid: a SAML assertion id, a DPoP proof, a client assertion's <c>jti</c>. The primary key is
/// the lower-case hex SHA-256 of a namespaced value (so two kinds of value never collide and the table never holds anything usable), and the
/// unique key is what makes the second use fail, even across instances and under concurrent requests.
/// </summary>
public sealed class ReplayReservation
{
    public required string Id { get; set; }
    public required string Kind { get; set; }
    public DateTime ExpiresAt { get; set; }
}

public sealed class ReplayReservationConfiguration : IEntityTypeConfiguration<ReplayReservation>
{
    public void Configure(EntityTypeBuilder<ReplayReservation> b)
    {
        b.HasKey(r => r.Id);
        b.Property(r => r.Id).HasMaxLength(64);
        b.Property(r => r.Kind).HasMaxLength(32);
        b.HasIndex(r => r.ExpiresAt);
    }
}
