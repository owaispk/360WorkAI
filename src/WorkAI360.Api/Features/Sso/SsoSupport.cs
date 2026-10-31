using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;

namespace WorkAI360.Api.Features.Sso;

/// <summary>Settings under "Sso:" (all optional).</summary>
public sealed class SsoOptions
{
    public const string Section = "Sso";

    /// <summary>
    /// Whether the identity provider's endpoints may be on loopback or private networks. Default: only in Development. Elsewhere such
    /// addresses are refused so a workspace admin cannot point the server at internal services (SSRF).
    /// </summary>
    public bool? AllowPrivateNetworks { get; set; }

    /// <summary>
    /// Development only: an issuer on loopback counts as a verified domain (nobody can publish DNS records for localhost). Default: true in Development.
    /// </summary>
    public bool? DevLoopbackIssuerIsVerified { get; set; }

    /// <summary>DNS servers used for domain verification. Empty uses the system's resolvers (/etc/resolv.conf), then public ones.</summary>
    public string[] DnsServers { get; set; } = [];
}

/// <summary>Reads and encrypts secrets (client secrets, PKCE verifiers) with a key derived from Auth:Secret.</summary>
public sealed class SecretProtector(IOptions<AuthOptions> options)
{
    private byte[] Key() => HKDF.DeriveKey(HashAlgorithmName.SHA256, Encoding.UTF8.GetBytes(options.Value.Secret), 32, salt: null, info: "workai360 sso secret protection"u8.ToArray());

    public string Protect(string plain)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var data = Encoding.UTF8.GetBytes(plain);
        var cipher = new byte[data.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(Key(), 16);
        aes.Encrypt(nonce, data, cipher, tag);
        return Convert.ToBase64String([.. nonce, .. tag, .. cipher]);
    }

    public string Unprotect(string protectedValue)
    {
        var all = Convert.FromBase64String(protectedValue);
        var nonce = all[..12];
        var tag = all[12..28];
        var cipher = all[28..];
        var plain = new byte[cipher.Length];
        using var aes = new AesGcm(Key(), 16);
        aes.Decrypt(nonce, cipher, tag, plain);
        return Encoding.UTF8.GetString(plain);
    }
}

/// <summary>Looks up TXT records. Injectable so tests (and the dev server) can answer without the network.</summary>
public interface IDnsTxtResolver
{
    /// <summary>The TXT strings at the name (each record's pieces joined). Empty when there are none; throws when the lookup itself failed.</summary>
    Task<IReadOnlyList<string>> ResolveTxtAsync(string name, CancellationToken cancellationToken);
}

/// <summary>A small DNS client for TXT records (.NET has none): UDP first, TCP when the answer is truncated.</summary>
public sealed class SystemDnsTxtResolver(IOptions<SsoOptions> options) : IDnsTxtResolver
{
    public async Task<IReadOnlyList<string>> ResolveTxtAsync(string name, CancellationToken cancellationToken)
    {
        Exception? last = null;
        foreach (var server in Servers())
        {
            try { return await QueryAsync(server, name, cancellationToken); }
            catch (Exception e) when (e is SocketException or TimeoutException or InvalidDataException or IOException or OperationCanceledException) { last = e; }
        }
        throw new InvalidOperationException("No DNS server answered.", last);
    }

    private IEnumerable<IPAddress> Servers()
    {
        var configured = new List<IPAddress>();
        foreach (var s in options.Value.DnsServers) if (IPAddress.TryParse(s, out var ip)) configured.Add(ip);
        if (configured.Count == 0 && File.Exists("/etc/resolv.conf"))
        {
            foreach (var line in File.ReadLines("/etc/resolv.conf"))
            {
                var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 2 && parts[0] == "nameserver" && IPAddress.TryParse(parts[1], out var ip)) configured.Add(ip);
            }
        }
        if (configured.Count == 0) configured.AddRange([IPAddress.Parse("1.1.1.1"), IPAddress.Parse("8.8.8.8")]);
        return configured;
    }

    public static byte[] BuildQuery(string name, ushort id)
    {
        var bytes = new List<byte>();
        bytes.AddRange([(byte)(id >> 8), (byte)id, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        foreach (var label in name.TrimEnd('.').Split('.'))
        {
            var l = Encoding.ASCII.GetBytes(label);
            if (l.Length is 0 or > 63) throw new InvalidDataException("Invalid DNS label.");
            bytes.Add((byte)l.Length);
            bytes.AddRange(l);
        }
        bytes.Add(0);
        bytes.AddRange([0, 16, 0, 1]); // TXT, IN
        return [.. bytes];
    }

    private static async Task<IReadOnlyList<string>> QueryAsync(IPAddress server, string name, CancellationToken ct)
    {
        var id = (ushort)RandomNumberGenerator.GetInt32(65536);
        var query = BuildQuery(name, id);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(4));
        byte[] response;
        using (var udp = new UdpClient(server.AddressFamily))
        {
            udp.Connect(server, 53);
            await udp.SendAsync(query, timeout.Token);
            response = (await udp.ReceiveAsync(timeout.Token)).Buffer;
        }
        if (response.Length >= 12 && (response[2] & 0x02) != 0)
        {
            using var tcp = new TcpClient(server.AddressFamily);
            await tcp.ConnectAsync(server, 53, timeout.Token);
            var stream = tcp.GetStream();
            var framed = new byte[query.Length + 2];
            BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)query.Length);
            query.CopyTo(framed, 2);
            await stream.WriteAsync(framed, timeout.Token);
            var len = new byte[2];
            await stream.ReadExactlyAsync(len, timeout.Token);
            response = new byte[BinaryPrimitives.ReadUInt16BigEndian(len)];
            await stream.ReadExactlyAsync(response, timeout.Token);
        }
        return ParseTxt(response, id);
    }

    public static IReadOnlyList<string> ParseTxt(byte[] m, ushort expectedId)
    {
        if (m.Length < 12 || BinaryPrimitives.ReadUInt16BigEndian(m) != expectedId) throw new InvalidDataException("Unexpected DNS response.");
        var rcode = m[3] & 0x0F;
        if (rcode == 3) return [];
        if (rcode != 0) throw new InvalidDataException($"DNS error {rcode}.");
        int qd = BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(4)), an = BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(6));
        var pos = 12;
        for (var i = 0; i < qd; i++) { pos = SkipName(m, pos) + 4; }
        var result = new List<string>();
        for (var i = 0; i < an; i++)
        {
            pos = SkipName(m, pos);
            var type = BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(pos));
            var rdLength = BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(pos + 8));
            pos += 10;
            if (type == 16)
            {
                var sb = new StringBuilder();
                var end = pos + rdLength;
                for (var p = pos; p < end;) { int l = m[p++]; sb.Append(Encoding.UTF8.GetString(m, p, l)); p += l; }
                result.Add(sb.ToString());
            }
            pos += rdLength;
        }
        return result;
    }

    private static int SkipName(byte[] m, int pos)
    {
        while (true)
        {
            var l = m[pos];
            if (l == 0) return pos + 1;
            if ((l & 0xC0) == 0xC0) return pos + 2;
            pos += l + 1;
        }
    }
}

/// <summary>Whether a URL may be fetched by the server on a workspace admin's say-so (identity provider endpoints).</summary>
public static class OutboundPolicy
{
    public static bool IsPublicAddress(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.None)) return false;
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast || ip.IsIPv6UniqueLocal) return false;
            return true;
        }
        var b = ip.GetAddressBytes();
        return !(b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254)
                 || (b[0] == 100 && b[1] is >= 64 and <= 127) || b[0] == 0 || b[0] >= 224);
    }

    /// <summary>Syntax and scheme rules: https always; plain http only when private networks are allowed (development); no embedded credentials.</summary>
    public static bool IsAcceptableUrl(string? value, bool allowPrivate)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)) return false;
        if (!string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment)) return false;
        if (!allowPrivate && (uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || uri.Host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase)
            || (IPAddress.TryParse(uri.Host.Trim('[', ']'), out var literal) && !IsPublicAddress(literal)))) return false;
        if (uri.Scheme == Uri.UriSchemeHttps) return true;
        return uri.Scheme == Uri.UriSchemeHttp && allowPrivate;
    }

    public static bool IsLoopbackHost(string host) =>
        host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || (IPAddress.TryParse(host.Trim('[', ']'), out var ip) && IPAddress.IsLoopback(ip));
}

/// <summary>The HTTP client for talking to identity providers: no redirects, short timeout, and (outside development) it refuses to connect to private addresses even after DNS.</summary>
public sealed class IdpHttp
{
    public const string ClientName = "sso-idp";
    public const int MaxBytes = 1_000_000;

    public static HttpMessageHandler CreateHandler(bool allowPrivate) => new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        UseProxy = false,
        ConnectTimeout = TimeSpan.FromSeconds(5),
        ConnectCallback = async (context, ct) =>
        {
            var host = context.DnsEndPoint.Host;
            var addresses = IPAddress.TryParse(host, out var literal) ? [literal] : await Dns.GetHostAddressesAsync(host, ct);
            var allowed = addresses.Where(a => allowPrivate || OutboundPolicy.IsPublicAddress(a)).ToArray();
            if (allowed.Length == 0) throw new HttpRequestException($"The address of {host} is not allowed.");
            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(allowed, context.DnsEndPoint.Port, ct);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch { socket.Dispose(); throw; }
        },
    };

    public static async Task<string> ReadLimitedAsync(HttpResponseMessage response, CancellationToken ct)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        int read;
        while ((read = await stream.ReadAsync(chunk, ct)) > 0)
        {
            buffer.Write(chunk, 0, read);
            if (buffer.Length > MaxBytes) throw new InvalidDataException("The identity provider's response is too large.");
        }
        return Encoding.UTF8.GetString(buffer.ToArray());
    }
}
