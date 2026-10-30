using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Domain;

namespace WorkAI360.Api.Data;

public sealed class DenDbContext(DbContextOptions<DenDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<Session> Sessions => Set<Session>();
    public DbSet<Organization> Organizations => Set<Organization>();
    public DbSet<Member> Members => Set<Member>();
    public DbSet<DesktopHandoffGrant> HandoffGrants => Set<DesktopHandoffGrant>();
    public DbSet<DeviceCode> DeviceCodes => Set<DeviceCode>();
    public DbSet<OAuthClient> OAuthClients => Set<OAuthClient>();
    public DbSet<AuthorizationCode> AuthorizationCodes => Set<AuthorizationCode>();
    public DbSet<OAuthConsent> OAuthConsents => Set<OAuthConsent>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<McpAccessToken> McpAccessTokens => Set<McpAccessToken>();
    public DbSet<SigningKey> SigningKeys => Set<SigningKey>();
    public DbSet<Invitation> Invitations => Set<Invitation>();
    public DbSet<EmailOtp> EmailOtps => Set<EmailOtp>();
    public DbSet<PasswordResetToken> PasswordResetTokens => Set<PasswordResetToken>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<User>().HasIndex(u => u.Email).IsUnique();
        b.Entity<Session>().HasIndex(s => s.TokenHash).IsUnique();
        b.Entity<Session>().HasIndex(s => s.UserId);
        b.Entity<Organization>().HasIndex(o => o.Slug).IsUnique();
        b.Entity<Member>().HasIndex(m => new { m.OrganizationId, m.UserId }).IsUnique();
        b.Entity<DeviceCode>().HasIndex(d => d.DeviceCodeHash).IsUnique();
        b.Entity<DeviceCode>().HasIndex(d => d.UserCode);
        b.Entity<OAuthConsent>().HasIndex(c => new { c.ClientId, c.UserId, c.OrganizationId }).IsUnique();
        b.Entity<RefreshToken>().HasIndex(t => t.FamilyId);
        b.Entity<RefreshToken>().HasIndex(t => t.CodeHash);
        b.Entity<EmailOtp>().HasIndex(o => new { o.Email, o.Type });
        b.Entity<Invitation>().HasIndex(i => new { i.OrganizationId, i.Email });
        b.Entity<Invitation>().HasIndex(i => i.InviteToken).IsUnique();
        b.Entity<Invitation>().HasIndex(i => i.PlaceholderMemberId).IsUnique();
        b.Entity<PasswordResetToken>().HasIndex(t => t.UserId);
    }
}
