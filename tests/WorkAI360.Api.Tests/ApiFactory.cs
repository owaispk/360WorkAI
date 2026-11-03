using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using WorkAI360.Api.Data;

namespace WorkAI360.Api.Tests;

/// <summary>
/// A fresh API instance with its own database per test class: a SQLite file, or (when WORKAI_TEST_MYSQL names a server, for example
/// "Server=127.0.0.1;User=root;Password=...") a throwaway MySQL database that is dropped afterwards, so the same tests run on both.
/// </summary>
public class ApiFactory : WebApplicationFactory<Program>
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"workai360-test-{Guid.NewGuid():N}.db");
    private static readonly string? MySqlServer = Environment.GetEnvironmentVariable("WORKAI_TEST_MYSQL");
    private readonly string _mysqlDatabase = $"workai_test_{Guid.NewGuid():N}";
    public const string Secret = "test-secret-0123456789-abcdefghijklmnop";
    public const string Password = "Str0ng!Passw0rd#2026x";

    protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
    {
        builder.UseSetting("Auth:Secret", Secret);
        builder.UseSetting("Auth:WebUrl", "http://localhost");
        // The provider catalog comes from the bundled snapshot: tests never depend on the network.
        builder.UseSetting("LlmProviders:CatalogUrl", "");
        // The Control Center's background refresh stays off in tests; they refresh explicitly.
        builder.UseSetting("PlatformAdmin:Metrics:RefreshEnabled", "false");
        foreach (var (key, value) in Settings) builder.UseSetting(key, value);
        builder.UseSetting("Auth:ApiPublicUrl", "http://localhost");
        if (MySqlServer is null) builder.UseSetting("ConnectionStrings:Default", $"Data Source={_dbPath}");
        else
        {
            using (var admin = new MySql.Data.MySqlClient.MySqlConnection(MySqlServer))
            {
                admin.Open();
                using var create = admin.CreateCommand();
                create.CommandText = $"CREATE DATABASE IF NOT EXISTS `{_mysqlDatabase}` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci";
                create.ExecuteNonQuery();
            }
            builder.UseSetting("Database:Provider", "mysql");
            // A pool large enough for the concurrency tests (requests waiting on a lock each hold a connection, and the lock holder may need another);
            // it is released when the factory is disposed, because dozens of factories run in turn and the server only allows so many in total.
            builder.UseSetting("ConnectionStrings:Default", $"{MySqlServer};Database={_mysqlDatabase};Maximum Pool Size=40");
        }
        builder.UseSetting("environment", "Development");
    }

    /// <summary>Extra configuration for a fixture (for example, requiring email verification).</summary>
    protected virtual IEnumerable<KeyValuePair<string, string>> Settings => [];

    public WorkAI360.Api.Email.DevOutbox Outbox => Services.GetRequiredService<WorkAI360.Api.Email.DevOutbox>();

    public HttpClient Browser() => CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true, AllowAutoRedirect = false });
    public HttpClient Plain() => CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, AllowAutoRedirect = false });

    public T WithDb<T>(Func<DenDbContext, T> read)
    {
        using var scope = Services.CreateScope();
        return read(scope.ServiceProvider.GetRequiredService<DenDbContext>());
    }

    public static string NewEmail(string prefix = "user") => $"{prefix}.{Guid.NewGuid():N}@example.com";

    public async Task<(string Email, string Token, string UserId)> SignUpAsync(HttpClient client, string name = "Test User")
    {
        var email = NewEmail();
        var response = await client.PostAsJsonAsync("/api/auth/sign-up/email", new { name, email, password = Password });
        response.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var userId = doc.RootElement.GetProperty("user").GetProperty("id").GetString()!;
        var token = doc.RootElement.GetProperty("token").GetString();
        if (token is null)
        {
            // This fixture requires verification: use the emailed code, then sign in, as a person would.
            var verified = await client.PostAsJsonAsync("/api/auth/email-otp/verify-email", new { email, otp = Mail.LastCode(Outbox, email) });
            verified.EnsureSuccessStatusCode();
            var signIn = await client.PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = Password });
            signIn.EnsureSuccessStatusCode();
            token = (await ReadJsonAsync(signIn)).GetProperty("token").GetString();
        }
        return (email, token!, userId);
    }

    public override ValueTask DisposeAsync()
    {
        var disposed = base.DisposeAsync();
        if (MySqlServer is not null)
        {
            try
            {
                using (var pooled = new MySql.Data.MySqlClient.MySqlConnection($"{MySqlServer};Database={_mysqlDatabase};Maximum Pool Size=40")) MySql.Data.MySqlClient.MySqlConnection.ClearPool(pooled);
                using var admin = new MySql.Data.MySqlClient.MySqlConnection(MySqlServer);
                admin.Open();
                using var drop = admin.CreateCommand();
                drop.CommandText = $"DROP DATABASE IF EXISTS `{_mysqlDatabase}`";
                drop.ExecuteNonQuery();
            }
            catch (Exception) { /* a leftover scratch database is harmless */ }
        }
        foreach (var path in new[] { _dbPath, _dbPath + "-shm", _dbPath + "-wal" })
        {
            try { File.Delete(path); } catch (IOException) { }
        }
        return disposed;
    }

    public static HttpRequestMessage Bearer(HttpMethod method, string url, string token, object? body = null)
    {
        var request = new HttpRequestMessage(method, url);
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        if (body is not null) request.Content = JsonContent.Create(body);
        return request;
    }

    public static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response)
    {
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return doc.RootElement.Clone();
    }
}
