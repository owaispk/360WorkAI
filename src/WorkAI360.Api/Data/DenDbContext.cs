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

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<User>().HasIndex(u => u.Email).IsUnique();
        b.Entity<Session>().HasIndex(s => s.TokenHash).IsUnique();
        b.Entity<Session>().HasIndex(s => s.UserId);
        b.Entity<Organization>().HasIndex(o => o.Slug).IsUnique();
        b.Entity<Member>().HasIndex(m => new { m.OrganizationId, m.UserId }).IsUnique();
        b.Entity<DeviceCode>().HasIndex(d => d.DeviceCodeHash).IsUnique();
        b.Entity<DeviceCode>().HasIndex(d => d.UserCode);
    }
}
