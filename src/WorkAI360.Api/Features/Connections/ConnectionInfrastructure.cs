using System.Net.Http.Headers;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;

namespace WorkAI360.Api.Features.Connections;

public sealed class ConnectionsOptions
{
    public const string Section = "Connections";

    /// <summary>
    /// Allow connections to servers on private, loopback and link-local addresses, and plain http. Off by default: it is the SSRF guard.
    /// Meant for local development and tests only (the reference's DEN_ALLOW_PRIVATE_MCP_URLS).
    /// </summary>
    public bool AllowPrivateUrls { get; set; }

    /// <summary>Longest a whole MCP exchange (initialize, notification and the request) may take.</summary>
    public int ToolTimeoutSeconds { get; set; } = 60;

    /// <summary>The most bytes read from any response of a remote server.</summary>
    public int MaxResponseBytes { get; set; } = 5 * 1024 * 1024;
}

/// <summary>Encrypts secrets at rest with AES-GCM; the key is derived from <c>Auth:Secret</c>. Output is <c>v1.base64(nonce|tag|cipher)</c>.</summary>
public sealed class SecretBox(IOptions<AuthOptions> options)
{
    private const string Prefix = "v1.";

    private byte[] Key() => HKDF.DeriveKey(HashAlgorithmName.SHA256, Encoding.UTF8.GetBytes(options.Value.Secret), 32, salt: null, info: Encoding.UTF8.GetBytes("workai360 connection secrets"));

    public string Encrypt(string plain)
    {
        var data = Encoding.UTF8.GetBytes(plain);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var cipher = new byte[data.Length];
        using var aes = new AesGcm(Key(), 16);
        aes.Encrypt(nonce, data, cipher, tag);
        return Prefix + Convert.ToBase64String([.. nonce, .. tag, .. cipher]);
    }

    /// <summary>The plain text, or null when the value is missing or was not written by this key (never throws on bad data).</summary>
    public string? Decrypt(string? stored)
    {
        if (string.IsNullOrEmpty(stored) || !stored.StartsWith(Prefix, StringComparison.Ordinal)) return null;
        try
        {
            var raw = Convert.FromBase64String(stored[Prefix.Length..]);
            if (raw.Length < 28) return null;
            var plain = new byte[raw.Length - 28];
            using var aes = new AesGcm(Key(), 16);
            aes.Decrypt(raw.AsSpan(0, 12), raw.AsSpan(28), raw.AsSpan(12, 16), plain);
            return Encoding.UTF8.GetString(plain);
        }
        catch (Exception e) when (e is FormatException or CryptographicException) { return null; }
    }
}

/// <summary>A refused outbound address (private, loopback, link-local, unresolvable or the wrong scheme).</summary>
public sealed class UrlRefusedException(string message) : Exception(message);

public sealed class ResponseTooLargeException(int limit) : Exception($"The server's response was larger than {limit / 1024 / 1024} MB.");

/// <summary>
/// Outbound calls to addresses people typed in. Every connection is made to an address this class resolved and checked itself (so a name that
/// resolves differently a second later cannot reach an internal address), redirects are never followed, and responses are size-limited.
/// </summary>
public sealed class GuardedHttp : IDisposable
{
    private readonly IOptions<ConnectionsOptions> _options;
    private readonly HttpClient _client;

    public GuardedHttp(IOptions<ConnectionsOptions> options)
    {
        _options = options;
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            UseCookies = false,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            ConnectCallback = ConnectAsync,
        };
        _client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
    }

    public bool AllowPrivate => _options.Value.AllowPrivateUrls;
    public int MaxBytes => _options.Value.MaxResponseBytes;
    public TimeSpan ToolTimeout => TimeSpan.FromSeconds(_options.Value.ToolTimeoutSeconds);

    private async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken ct)
    {
        var host = context.DnsEndPoint.Host;
        IPAddress[] addresses = IPAddress.TryParse(host, out var literal) ? [literal] : await Dns.GetHostAddressesAsync(host, ct);
        if (addresses.Length == 0) throw new UrlRefusedException($"The address {host} could not be found.");
        if (!AllowPrivate && addresses.Any(a => !IsPublic(a))) throw new UrlRefusedException("That address points to a private or internal network, which is not allowed.");
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(addresses, context.DnsEndPoint.Port, ct);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch { socket.Dispose(); throw; }
    }

    /// <summary>Whether an address is on the public internet (not private, loopback, link-local, shared, multicast or reserved).</summary>
    public static bool IsPublic(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.IPv6None)) return false;
        var b = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return !(b[0] is 0 or 10 or 127
                || (b[0] == 100 && b[1] is >= 64 and <= 127)
                || (b[0] == 169 && b[1] == 254)
                || (b[0] == 172 && b[1] is >= 16 and <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 192 && b[1] == 0 && b[2] == 0)
                || (b[0] == 198 && b[1] is 18 or 19)
                || b[0] >= 224);
        }
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return !(address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast || (b[0] & 0xFE) == 0xFC
                || address.IsIPv6Teredo || (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8)
                // NAT64 / 6to4 can embed a private IPv4 address.
                || (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xFF && b[3] == 0x9B) || (b[0] == 0x20 && b[1] == 0x02));
        }
        return false;
    }

    /// <summary>Checks a URL is acceptable before any request: http(s), no credentials, a public address (unless private addresses are allowed).</summary>
    public async Task AssertPublicAsync(string url, CancellationToken ct = default)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https")) throw new UrlRefusedException("MCP URLs must use HTTP or HTTPS.");
        if (!string.IsNullOrEmpty(uri.UserInfo)) throw new UrlRefusedException("MCP URLs must not contain embedded credentials.");
        if (AllowPrivate) return;
        if (uri.Scheme == "http") throw new UrlRefusedException("Hosted MCP connections must use HTTPS.");
        IPAddress[] addresses;
        try { addresses = IPAddress.TryParse(uri.IdnHost, out var literal) ? [literal] : await Dns.GetHostAddressesAsync(uri.IdnHost, ct); }
        catch (SocketException) { throw new UrlRefusedException($"The address {uri.Host} could not be found."); }
        if (addresses.Length == 0) throw new UrlRefusedException($"The address {uri.Host} could not be found.");
        if (addresses.Any(a => !IsPublic(a))) throw new UrlRefusedException("That address points to a private or internal network, which is not allowed.");
    }

    public sealed record Reply(HttpStatusCode Status, HttpResponseHeaders Headers, string ContentType, byte[] Body, long ElapsedMs)
    {
        public string Text => Encoding.UTF8.GetString(Body);
        /// <summary>The content headers (.NET keeps Allow, Content-Type and the like there rather than with the response headers).</summary>
        public HttpContentHeaders? ContentHeaders { get; init; }
    }

    /// <summary>Sends one request with a deadline and a body size limit. Redirects are returned as they are (never followed).</summary>
    public async Task<Reply> SendAsync(HttpRequestMessage request, TimeSpan timeout, CancellationToken ct = default)
    {
        await AssertPublicAsync(request.RequestUri!.ToString(), ct);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        var started = Environment.TickCount64;
        using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token);
        var limit = MaxBytes;
        if (response.Content.Headers.ContentLength is { } declared && declared > limit) throw new ResponseTooLargeException(limit);
        await using var stream = await response.Content.ReadAsStreamAsync(cts.Token);
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        int read;
        while ((read = await stream.ReadAsync(chunk, cts.Token)) > 0)
        {
            buffer.Write(chunk, 0, read);
            if (buffer.Length > limit) throw new ResponseTooLargeException(limit);
        }
        return new Reply(response.StatusCode, response.Headers, response.Content.Headers.ContentType?.MediaType ?? "", buffer.ToArray(), Environment.TickCount64 - started) { ContentHeaders = response.Content.Headers };
    }

    public void Dispose() => _client.Dispose();
}
