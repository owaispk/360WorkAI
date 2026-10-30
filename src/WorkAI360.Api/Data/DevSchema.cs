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
    }
}
