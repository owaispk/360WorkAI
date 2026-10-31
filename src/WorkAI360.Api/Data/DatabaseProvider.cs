using Microsoft.EntityFrameworkCore;

namespace WorkAI360.Api.Data;

/// <summary>
/// Which database the API uses: <c>Database:Provider</c> is <c>sqlite</c> (default; development and tests) or <c>mysql</c> (production, as the
/// reference does). The connection string is <c>ConnectionStrings:Default</c> in either case.
/// </summary>
public static class DatabaseProvider
{
    public const string Sqlite = "sqlite";
    public const string MySql = "mysql";

    public static string Name(IConfiguration configuration)
    {
        var name = (configuration["Database:Provider"] ?? Sqlite).Trim().ToLowerInvariant();
        return name is Sqlite or MySql ? name : throw new InvalidOperationException($"Unknown Database:Provider '{name}' (use sqlite or mysql).");
    }

    public static void Configure(DbContextOptionsBuilder options, IConfiguration configuration)
    {
        var connection = configuration.GetConnectionString("Default");
        if (Name(configuration) == MySql)
        {
            if (string.IsNullOrWhiteSpace(connection)) throw new InvalidOperationException("ConnectionStrings:Default is required when Database:Provider is mysql.");
            options.UseMySQL(connection);
        }
        else options.UseSqlite(connection ?? "Data Source=workai360.db");
    }

    public static bool IsSqlite(this DbContext db) => db.Database.ProviderName?.Contains("Sqlite", StringComparison.OrdinalIgnoreCase) == true;
}

/// <summary>Brings the database schema up to date at startup.</summary>
public static class DatabaseSetup
{
    /// <summary>
    /// SQLite (development, tests): create or extend the schema automatically (<see cref="DevSchema"/>). MySQL: apply migrations when allowed
    /// (<c>Database:AutoMigrate</c>, default on in Development only); otherwise refuse to start while migrations are pending, so a deployment
    /// never runs against an old schema. With no migrations in the build, a Development MySQL database is created from the model.
    /// </summary>
    public static void Ensure(DenDbContext db, IConfiguration configuration, IHostEnvironment environment, bool migrateNow = false)
    {
        if (db.IsSqlite()) { DevSchema.Ensure(db); return; }

        var autoMigrate = migrateNow || (bool.TryParse(configuration["Database:AutoMigrate"], out var configured) ? configured : environment.IsDevelopment());
        if (!db.Database.GetMigrations().Any())
        {
            if (!environment.IsDevelopment()) throw new InvalidOperationException("This build has no database migrations; create them (see docs/database.md) before running outside Development.");
            db.Database.EnsureCreated();
            return;
        }
        if (autoMigrate) { db.Database.Migrate(); return; }
        if (db.Database.GetPendingMigrations().Any())
            throw new InvalidOperationException("The database has pending migrations. Run the API once with --migrate (or set Database:AutoMigrate=true).");
    }
}
