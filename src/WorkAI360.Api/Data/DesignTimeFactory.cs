using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace WorkAI360.Api.Data;

/// <summary>
/// Lets <c>dotnet ef migrations add</c> build the model for MySQL without starting the app (see docs/database.md). The connection string only
/// has to be well-formed; no connection is made when adding a migration.
/// </summary>
public sealed class DesignTimeFactory : IDesignTimeDbContextFactory<DenDbContext>
{
    public DenDbContext CreateDbContext(string[] args)
    {
        var connection = Environment.GetEnvironmentVariable("WORKAI_EF_CONNECTION") ?? "Server=localhost;Database=workai360;User=root;Password=unused";
        var options = new DbContextOptionsBuilder<DenDbContext>().UseMySQL(connection).Options;
        return new DenDbContext(options);
    }
}
