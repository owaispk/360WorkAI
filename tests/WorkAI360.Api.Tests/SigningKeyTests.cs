using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WorkAI360.Api.OAuth;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

public sealed class RotatingFactory : ApiFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Settings => [new("Auth:SigningKeyRotationDays", "30"), new("Auth:SigningKeyGraceHours", "24")];
}

public sealed class SigningKeyTests : IClassFixture<RotatingFactory>
{
    private readonly RotatingFactory _factory;
    public SigningKeyTests(RotatingFactory factory) => _factory = factory;

    private SigningKeyStore Store => _factory.Services.GetRequiredService<SigningKeyStore>();
    private void Age(string kid, TimeSpan age) => _factory.WithDb(db => db.Database.ExecuteSqlRaw("UPDATE SigningKeys SET CreatedAt = {0} WHERE Id = {1}", DateTime.UtcNow - age, kid));
    private async Task<string[]> PublishedAsync() =>
        (await ReadJsonAsync(await _factory.Plain().GetAsync("/api/auth/jwks"))).GetProperty("keys").EnumerateArray().Select(k => k.GetProperty("kid").GetString()!).ToArray();

    [Fact]
    public async Task Keys_rotate_when_old_and_the_old_key_keeps_verifying_until_the_grace_period_ends()
    {
        var first = await Store.ActiveAsync();
        Assert.Equal([first.Kid], await PublishedAsync());
        var token = Jwt.Create(first, new Dictionary<string, object?> { ["sub"] = "u", ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds() });

        // The newest key is 31 days old: a new one appears and signs from then on; the old one is still published.
        Age(first.Kid, TimeSpan.FromDays(31));
        Store.Invalidate();
        var second = await Store.ActiveAsync();
        Assert.NotEqual(first.Kid, second.Kid);
        Assert.Equal([first.Kid, second.Kid], await PublishedAsync());
        Assert.NotNull(Jwt.Verify(token, await Store.KeysAsync()));                          // a token signed before rotation still verifies
        Assert.NotNull(Jwt.Verify(Jwt.Create(second, new Dictionary<string, object?> { ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds() }), await Store.KeysAsync()));

        // A day after the successor appeared the old key is retired and no longer published (the row is kept).
        Age(second.Kid, TimeSpan.FromHours(25));
        Store.Invalidate();
        Assert.Equal([second.Kid], await PublishedAsync());
        Assert.Null(Jwt.Verify(token, await Store.KeysAsync()));
        Assert.Equal(2, _factory.WithDb(db => db.SigningKeys.Count()));
        Assert.NotNull(_factory.WithDb(db => db.SigningKeys.Single(k => k.Id == first.Kid).RetiredAt));
    }

    [Fact]
    public async Task A_key_that_is_not_old_is_not_rotated_and_a_second_instance_sees_the_rotation()
    {
        var active = await Store.ActiveAsync();
        Store.Invalidate();
        Assert.Equal(active.Kid, (await Store.ActiveAsync()).Kid);
        Assert.Equal(HttpStatusCode.OK, (await _factory.Plain().GetAsync("/api/auth/jwks")).StatusCode);
    }
}
