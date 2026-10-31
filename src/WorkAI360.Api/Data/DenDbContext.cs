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
    public DbSet<Team> Teams => Set<Team>();
    public DbSet<TeamMember> TeamMembers => Set<TeamMember>();
    public DbSet<PermissionSet> PermissionSets => Set<PermissionSet>();
    public DbSet<PermissionSetPermission> PermissionSetPermissions => Set<PermissionSetPermission>();
    public DbSet<PermissionSetTeam> PermissionSetTeams => Set<PermissionSetTeam>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        // Entities added by feature areas describe themselves with IEntityTypeConfiguration<T>.
        b.ApplyConfigurationsFromAssembly(typeof(DenDbContext).Assembly);
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
        // Team names are unique per workspace regardless of case, as with the reference's default MySQL collation.
        // SQLite needs the collation named; MySQL's default utf8mb4 collation is already case-insensitive.
        if (this.IsSqlite()) b.Entity<Team>().Property(t => t.Name).UseCollation("NOCASE");
        b.Entity<Team>().HasIndex(t => new { t.OrganizationId, t.Name }).IsUnique();
        b.Entity<TeamMember>().HasIndex(t => new { t.TeamId, t.MemberId }).IsUnique();
        b.Entity<TeamMember>().HasIndex(t => t.MemberId);
        b.Entity<PermissionSet>().HasIndex(p => p.OrganizationId);
        // One Member set and one Admin set per workspace, even if two requests try to create them at once (roles have no DefaultKey, and
        // databases treat empty values as distinct, so they are unaffected).
        b.Entity<PermissionSet>().HasIndex(p => new { p.OrganizationId, p.DefaultKey }).IsUnique();
        b.Entity<PermissionSetPermission>().HasIndex(p => new { p.PermissionSetId, p.PermissionKey });
        // A team has at most one active role, even if two requests give it one at the same moment.
        b.Entity<PermissionSetTeam>().HasIndex(p => p.ActiveTeamId).IsUnique();
        b.Entity<PermissionSetTeam>().HasIndex(p => p.TeamId);
        b.Entity<PermissionSetTeam>().HasIndex(p => p.PermissionSetId);

        // MySQL cannot index unbounded text. Every key, foreign key and indexed text column gets a length (ids are 29 characters).
        if (!this.IsSqlite())
        {
            foreach (var entity in b.Model.GetEntityTypes())
            {
                var indexed = entity.GetKeys().SelectMany(k => k.Properties)
                    .Concat(entity.GetIndexes().SelectMany(i => i.Properties))
                    .Concat(entity.GetForeignKeys().SelectMany(f => f.Properties))
                    .Where(p => p.ClrType == typeof(string) && p.GetMaxLength() is null).Distinct();
                foreach (var property in indexed) property.SetMaxLength(255);
            }
        }
    }
}
