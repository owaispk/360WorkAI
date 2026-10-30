using Microsoft.EntityFrameworkCore;

namespace WorkAI360.Api.Data;

/// <summary>
/// Development-only schema bootstrap until EF Core migrations exist. It creates the database if needed and adds any tables or indexes
/// a newer build introduced, so an existing dev database keeps working. It never alters or drops existing columns.
/// </summary>
public static class DevSchema
{
    public static void Ensure(DenDbContext db)
    {
        if (db.Database.EnsureCreated()) return;
        var script = db.Database.GenerateCreateScript()
            .Replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ")
            .Replace("CREATE UNIQUE INDEX ", "CREATE UNIQUE INDEX IF NOT EXISTS ")
            .Replace("CREATE INDEX ", "CREATE INDEX IF NOT EXISTS ");
        foreach (var statement in script.Split(";\n", StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (statement.Length > 0) db.Database.ExecuteSqlRaw(statement.Replace("{", "{{").Replace("}", "}}"));
        }
        AddMissingColumns(db);
    }

    /// <summary>Adds columns that a newer build introduced to tables that already exist. Only nullable ones can be added safely.</summary>
    private static void AddMissingColumns(DenDbContext db)
    {
        var connection = db.Database.GetDbConnection();
        if (connection.State != System.Data.ConnectionState.Open) connection.Open();
        foreach (var entity in db.Model.GetEntityTypes())
        {
            var table = entity.GetTableName();
            if (table is null) continue;
            var existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using (var command = connection.CreateCommand())
            {
                command.CommandText = $"PRAGMA table_info(\"{table}\")";
                using var reader = command.ExecuteReader();
                while (reader.Read()) existing.Add(reader.GetString(1));
            }
            foreach (var property in entity.GetProperties())
            {
                var column = property.GetColumnName();
                if (existing.Contains(column)) continue;
                if (!property.IsNullable)
                    throw new InvalidOperationException($"The development database lacks {table}.{column}, which is required. Delete the database file and start again.");
                using var alter = connection.CreateCommand();
                alter.CommandText = $"ALTER TABLE \"{table}\" ADD COLUMN \"{column}\" {property.GetColumnType()} NULL";
                alter.ExecuteNonQuery();
            }
        }
    }
}
