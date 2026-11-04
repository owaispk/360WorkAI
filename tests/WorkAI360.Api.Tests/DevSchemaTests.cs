using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Data;

namespace WorkAI360.Api.Tests;

/// <summary>Upgrading an existing development (SQLite) database to a newer build.</summary>
public sealed class DevSchemaTests
{
    [Fact]
    public void An_older_database_gains_new_columns_before_the_indexes_that_cover_them()
    {
        var path = Path.Combine(Path.GetTempPath(), $"workai360-devschema-{Guid.NewGuid():N}.db");
        DbContextOptions<DenDbContext> Options() => new DbContextOptionsBuilder<DenDbContext>().UseSqlite($"Data Source={path};Pooling=False").Options;
        try
        {
            using (var db = new DenDbContext(Options()))
            {
                DevSchema.Ensure(db);
                // What a build before OAuth client ownership left behind: no OwnerUserId column, so no index on it.
                db.Database.ExecuteSqlRaw("DROP INDEX \"IX_OAuthClientExtras_OwnerUserId\"");
                db.Database.ExecuteSqlRaw("ALTER TABLE \"OAuthClientExtras\" DROP COLUMN \"OwnerUserId\"");
            }

            using (var db = new DenDbContext(Options()))
            {
                DevSchema.Ensure(db); // threw "no such column: OwnerUserId" when indexes ran before columns were added
                var connection = db.Database.GetDbConnection();
                connection.Open();
                using var columns = connection.CreateCommand();
                columns.CommandText = "SELECT COUNT(*) FROM pragma_table_info('OAuthClientExtras') WHERE name = 'OwnerUserId'";
                Assert.Equal(1L, (long)columns.ExecuteScalar()!);
                using var index = connection.CreateCommand();
                index.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'IX_OAuthClientExtras_OwnerUserId'";
                Assert.Equal(1L, (long)index.ExecuteScalar()!);
            }
        }
        finally
        {
            foreach (var file in new[] { path, path + "-shm", path + "-wal" }) if (File.Exists(file)) File.Delete(file);
        }
    }
}
