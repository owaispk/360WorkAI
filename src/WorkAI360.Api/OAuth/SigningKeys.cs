using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;

namespace WorkAI360.Api.OAuth;

public sealed record LoadedKey(string Kid, ECDsa Key, string X, string Y);

/// <summary>
/// ES256 (ECDSA P-256) signing keys for access tokens, created on first use. The reference uses EdDSA; .NET has no built-in
/// Ed25519, and ES256 is universally supported by MCP clients and JWT libraries.
/// </summary>
public sealed class SigningKeyStore(IServiceScopeFactory scopes, IOptions<AuthOptions> options)
{
    private static readonly TimeSpan ReloadEvery = TimeSpan.FromMinutes(5);
    private readonly SemaphoreSlim _gate = new(1, 1);
    private List<LoadedKey>? _keys;
    private DateTime _loadedAt;

    /// <summary>Forces the next call to read the keys again (used after a rotation elsewhere, and in tests).</summary>
    public void Invalidate() => _keys = null;

    public async Task<IReadOnlyList<LoadedKey>> KeysAsync()
    {
        if (_keys is not null && DateTime.UtcNow - _loadedAt < ReloadEvery) return _keys;
        await _gate.WaitAsync();
        try
        {
            if (_keys is not null && DateTime.UtcNow - _loadedAt < ReloadEvery) return _keys;
            using var scope = scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<DenDbContext>();
            var rows = await db.SigningKeys.Where(k => k.RetiredAt == null).OrderBy(k => k.CreatedAt).ToListAsync();
            var now = DateTime.UtcNow;
            // Rotation: a new key appears when the newest is old enough; a key stops being published once its successor has been around for
            // the grace period (long enough for every token it signed to expire). Keys are never deleted, so the history stays.
            if (rows.Count == 0 || now - rows[^1].CreatedAt >= TimeSpan.FromDays(options.Value.SigningKeyRotationDays)) rows.Add(await CreateAsync(db));
            var grace = TimeSpan.FromHours(options.Value.SigningKeyGraceHours);
            foreach (var old in rows.Take(rows.Count - 1).Where(k => k.RetiredAt is null && now - rows[rows.IndexOf(k) + 1].CreatedAt >= grace).ToList())
            {
                old.RetiredAt = now;
                rows.Remove(old);
            }
            await db.SaveChangesAsync();
            _keys = rows.Select(Load).ToList();
            _loadedAt = now;
            return _keys;
        }
        finally { _gate.Release(); }
    }

    /// <summary>The newest key signs; every non-retired key is published for verification.</summary>
    public async Task<LoadedKey> ActiveAsync() => (await KeysAsync())[^1];

    private async Task<SigningKey> CreateAsync(DenDbContext db)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var p = ecdsa.ExportParameters(true);
        var row = new SigningKey
        {
            Id = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8)),
            X = Base64Url(p.Q.X!),
            Y = Base64Url(p.Q.Y!),
            ProtectedPrivate = Protect(p.D!),
            CreatedAt = DateTime.UtcNow,
        };
        db.SigningKeys.Add(row);
        await db.SaveChangesAsync();
        return row;
    }

    private LoadedKey Load(SigningKey row)
    {
        var d = Unprotect(row.ProtectedPrivate);
        var key = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = d,
            Q = new ECPoint { X = FromBase64Url(row.X), Y = FromBase64Url(row.Y) },
        });
        return new LoadedKey(row.Id, key, row.X, row.Y);
    }

    private byte[] ProtectionKey() =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, Encoding.UTF8.GetBytes(options.Value.Secret), 32, salt: null, info: Encoding.UTF8.GetBytes("workai360 signing-key protection"));

    private string Protect(byte[] plain)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var cipher = new byte[plain.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(ProtectionKey(), 16);
        aes.Encrypt(nonce, plain, cipher, tag);
        return Convert.ToBase64String([.. nonce, .. tag, .. cipher]);
    }

    private byte[] Unprotect(string value)
    {
        var all = Convert.FromBase64String(value);
        var nonce = all[..12];
        var tag = all[12..28];
        var cipher = all[28..];
        var plain = new byte[cipher.Length];
        using var aes = new AesGcm(ProtectionKey(), 16);
        aes.Decrypt(nonce, cipher, tag, plain);
        return plain;
    }

    public static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] FromBase64Url(string value)
    {
        var s = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
    }
}

/// <summary>Minimal JWT (JWS compact) support for ES256: just what access tokens need.</summary>
public static class Jwt
{
    public static string Create(LoadedKey key, IReadOnlyDictionary<string, object?> payload)
    {
        var header = SigningKeyStore.Base64Url(JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object?> { ["typ"] = "at+jwt", ["alg"] = "ES256", ["kid"] = key.Kid }));
        var body = SigningKeyStore.Base64Url(JsonSerializer.SerializeToUtf8Bytes(payload));
        var signingInput = $"{header}.{body}";
        var signature = key.Key.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return $"{signingInput}.{SigningKeyStore.Base64Url(signature)}";
    }

    /// <summary>Returns the payload only when alg, kid and signature all check out. Claims (iss, aud, exp…) are the caller's job.</summary>
    public static JsonElement? Verify(string jwt, IReadOnlyList<LoadedKey> keys)
    {
        var parts = jwt.Split('.');
        if (parts.Length != 3) return null;
        try
        {
            using var header = JsonDocument.Parse(SigningKeyStore.FromBase64Url(parts[0]));
            if (header.RootElement.GetProperty("alg").GetString() != "ES256") return null; // never trust "none" or a downgraded alg
            var kid = header.RootElement.TryGetProperty("kid", out var k) ? k.GetString() : null;
            var key = keys.FirstOrDefault(x => x.Kid == kid);
            if (key is null) return null;
            var ok = key.Key.VerifyData(Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"), SigningKeyStore.FromBase64Url(parts[2]), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            if (!ok) return null;
            return JsonDocument.Parse(SigningKeyStore.FromBase64Url(parts[1])).RootElement.Clone();
        }
        catch (Exception e) when (e is JsonException or FormatException or KeyNotFoundException or CryptographicException or InvalidOperationException)
        {
            return null;
        }
    }
}

/// <summary>
/// The authorization request, carried between the OAuth endpoint, the sign-in page and the consent page as a signed query string.
/// Nothing about the request is kept on the server, and none of it can be altered or replayed after it expires.
/// </summary>
public sealed class SignedQuery(IOptions<AuthOptions> options)
{
    private byte[] Key() =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, Encoding.UTF8.GetBytes(options.Value.Secret), 32, salt: null, info: Encoding.UTF8.GetBytes("workai360 oauth query"));

    public string Sign(IEnumerable<KeyValuePair<string, string>> parameters, TimeSpan lifetime)
    {
        var all = parameters.Where(p => p.Key is not ("exp" or "sig")).ToList();
        all.Add(new("exp", DateTimeOffset.UtcNow.Add(lifetime).ToUnixTimeSeconds().ToString()));
        var sig = SigningKeyStore.Base64Url(HMACSHA256.HashData(Key(), Encoding.UTF8.GetBytes(Canonical(all))));
        all.Add(new("sig", sig));
        return string.Join('&', all.Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));
    }

    /// <summary>The verified parameters, or null when the signature is wrong, the query is malformed, or it has expired.</summary>
    public Dictionary<string, string>? Verify(string? query)
    {
        if (string.IsNullOrWhiteSpace(query)) return null;
        var parsed = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(query.TrimStart('?'));
        if (!parsed.TryGetValue("sig", out var sigValues) || sigValues.Count != 1 || !parsed.TryGetValue("exp", out var expValues) || expValues.Count != 1) return null;
        if (parsed.Any(p => p.Value.Count != 1)) return null; // a repeated parameter would be ambiguous
        var pairs = parsed.Where(p => p.Key != "sig").Select(p => new KeyValuePair<string, string>(p.Key, p.Value[0]!)).ToList();
        var expected = HMACSHA256.HashData(Key(), Encoding.UTF8.GetBytes(Canonical(pairs)));
        byte[] given;
        try { given = SigningKeyStore.FromBase64Url(sigValues[0]!); } catch (FormatException) { return null; }
        if (!CryptographicOperations.FixedTimeEquals(expected, given)) return null;
        if (!long.TryParse(expValues[0], out var exp) || DateTimeOffset.UtcNow.ToUnixTimeSeconds() > exp) return null;
        return pairs.ToDictionary(p => p.Key, p => p.Value);
    }

    private static string Canonical(IEnumerable<KeyValuePair<string, string>> pairs) =>
        string.Join('&', pairs.OrderBy(p => p.Key, StringComparer.Ordinal).ThenBy(p => p.Value, StringComparer.Ordinal)
            .Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));
}
