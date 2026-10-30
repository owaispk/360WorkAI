using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using WorkAI360.Api.Data;

namespace WorkAI360.Api.Tests;

/// <summary>A fresh API instance with its own SQLite file per test class.</summary>
public sealed class ApiFactory : WebApplicationFactory<Program>
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"workai360-test-{Guid.NewGuid():N}.db");
    public const string Secret = "test-secret-0123456789-abcdefghijklmnop";
    public const string Password = "Str0ng!Passw0rd#2026x";

    protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
    {
        builder.UseSetting("Auth:Secret", Secret);
        builder.UseSetting("Auth:WebUrl", "http://localhost");
        builder.UseSetting("Auth:ApiPublicUrl", "http://localhost");
        builder.UseSetting("ConnectionStrings:Default", $"Data Source={_dbPath}");
        builder.UseSetting("environment", "Development");
    }

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
        return (email, doc.RootElement.GetProperty("token").GetString()!, doc.RootElement.GetProperty("user").GetProperty("id").GetString()!);
    }

    public override ValueTask DisposeAsync()
    {
        foreach (var path in new[] { _dbPath, _dbPath + "-shm", _dbPath + "-wal" })
        {
            try { File.Delete(path); } catch (IOException) { }
        }
        return base.DisposeAsync();
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
