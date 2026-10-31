using System.Net;

namespace WorkAI360.Api.Tests;

/// <summary>Plugin names are unique per creator ignoring case, on every database, including when two requests race.</summary>
public sealed class LibraryNamingTests : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _factory;
    public LibraryNamingTests(ApiFactory factory) => _factory = factory;

    [Fact]
    public async Task The_same_plugin_name_in_any_case_is_a_409_and_an_archived_one_frees_the_name()
    {
        var w = await Workspace.CreateAsync(_factory);
        var first = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins", new { name = "Release Notes" });
        Assert.Equal(HttpStatusCode.Created, first.Status);
        foreach (var variant in new[] { "Release Notes", "release notes", "RELEASE NOTES" })
        {
            var again = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins", new { name = variant });
            Assert.Equal(HttpStatusCode.Conflict, again.Status);
            Assert.Equal("duplicate_plugin", again.Error());
        }
        // Another person may use the name.
        var other = await w.AddAsync();
        Assert.Equal(HttpStatusCode.Created, (await w.CallAsync(other, HttpMethod.Post, "/v1/plugins", new { name = "release notes" })).Status);
        // Archiving frees it for the creator.
        var id = first.Body.GetProperty("item").GetProperty("id").GetString();
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/plugins/{id}/archive")).Status);
        Assert.Equal(HttpStatusCode.Created, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins", new { name = "RELEASE notes" })).Status);
    }

    [Fact]
    public async Task Racing_creations_with_names_that_differ_only_in_case_make_exactly_one()
    {
        var w = await Workspace.CreateAsync(_factory);
        var names = new[] { "Racer", "racer", "RACER", "rAcEr", "Racer", "racer", "RACER", "rAcEr" };
        var results = await Task.WhenAll(names.Select(n => w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins", new { name = n })));
        Assert.Equal(1, results.Count(r => r.Status == HttpStatusCode.Created));
        Assert.All(results.Where(r => r.Status != HttpStatusCode.Created), r => Assert.Equal("duplicate_plugin", r.Error()));
        Assert.Equal(7, results.Count(r => r.Status == HttpStatusCode.Conflict));
    }
}
