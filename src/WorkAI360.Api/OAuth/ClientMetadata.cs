using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;

namespace WorkAI360.Api.OAuth;

/// <summary>What fetching a client's metadata document gave back.</summary>
public sealed record MetadataResponse(int Status, string? ContentType, string Body);

/// <summary>Fetches a Client ID Metadata Document. Replaced in tests; the real one refuses private addresses, redirects and large bodies.</summary>
public interface IClientMetadataFetcher
{
    /// <summary>Null when the URL is not allowed or the fetch failed.</summary>
    Task<MetadataResponse?> FetchAsync(Uri url, CancellationToken cancellationToken);
}

public sealed class OAuthClientMetadataOptions
{
    /// <summary>Self-hosted and test deployments may allow documents on private networks. Off by default.</summary>
    public bool AllowPrivateUrls { get; set; }
}

/// <summary>
/// The pre-fetch policy for metadata document URLs (MCP authorization, draft-ietf-oauth-client-id-metadata-document): HTTPS with a path, no
/// credentials or fragment, never this deployment's own origins (it would turn the server into a proxy for its own routes), and no address
/// that is loopback, private, link-local or otherwise not public.
/// </summary>
public static class ClientMetadataPolicy
{
    public static bool IsAllowedUrl(Uri url, IEnumerable<string> ownOrigins, bool allowPrivate)
    {
        if (url.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(url.UserInfo) || url.Fragment.Length > 0) return false;
        if (url.AbsolutePath.Length <= 1) return false;                       // the document lives at a path
        if (url.AbsolutePath.Split('/').Any(seg => seg is "." or "..")) return false;
        if (ownOrigins.Any(o => string.Equals(o.TrimEnd('/'), url.GetLeftPart(UriPartial.Authority), StringComparison.OrdinalIgnoreCase))) return false;
        if (allowPrivate) return true;
        return !IPAddress.TryParse(url.Host.Trim('[', ']'), out var literal) || IsPublic(literal);
    }

    public static bool IsPublic(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) return false;
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast || address.IsIPv6UniqueLocal) return false;
            return true;
        }
        var b = address.GetAddressBytes();
        return !(b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168)   // private
            || (b[0] == 169 && b[1] == 254)                                                                // link-local (cloud metadata)
            || (b[0] == 100 && b[1] is >= 64 and <= 127)                                                   // shared address space
            || b[0] == 0 || b[0] >= 224                                                                    // "this network", multicast, reserved
            || (b[0] == 192 && b[1] == 0 && b[2] == 0));
    }
}

/// <summary>The real fetcher. The address it connects to is chosen here, after the policy check, so DNS cannot swap in a private one.</summary>
public sealed class HttpClientMetadataFetcher : IClientMetadataFetcher
{
    private const int MaxBytes = 5 * 1024;
    private readonly HttpClient _http;
    private readonly bool _allowPrivate;

    public HttpClientMetadataFetcher(IOptions<OAuthClientMetadataOptions> options)
    {
        _allowPrivate = options.Value.AllowPrivateUrls;
        _http = new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(4),
            ConnectCallback = async (context, cancellationToken) =>
            {
                var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, cancellationToken);
                var allowed = addresses.Where(a => _allowPrivate || ClientMetadataPolicy.IsPublic(a)).ToList();
                if (allowed.Count == 0) throw new HttpRequestException("The client metadata host does not resolve to a public address.");
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try { await socket.ConnectAsync(new IPEndPoint(allowed[0], context.DnsEndPoint.Port), cancellationToken); return new NetworkStream(socket, ownsSocket: true); }
                catch { socket.Dispose(); throw; }
            },
        }) { Timeout = TimeSpan.FromSeconds(6) };
    }

    public async Task<MetadataResponse?> FetchAsync(Uri url, CancellationToken cancellationToken)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Accept.ParseAdd("application/json");
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if ((int)response.StatusCode is >= 300 and < 400) return new MetadataResponse((int)response.StatusCode, null, "");   // a redirect is a refusal
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            var buffer = new byte[MaxBytes + 1];
            var read = 0;
            int n;
            while (read < buffer.Length && (n = await stream.ReadAsync(buffer.AsMemory(read), cancellationToken)) > 0) read += n;
            return read > MaxBytes ? null : new MetadataResponse((int)response.StatusCode, response.Content.Headers.ContentType?.MediaType, Encoding.UTF8.GetString(buffer, 0, read));
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or OperationCanceledException or IOException) { return null; }
    }
}

/// <summary>
/// Finds an OAuth client by its client_id. Registered clients come from the database. A client_id that is an HTTPS URL names a Client ID
/// Metadata Document the client hosts: it is fetched under the policy above, validated, and stored as a public client, so spec-following
/// MCP clients need no dynamic registration. Documents are refreshed when an hour old (a failed refresh keeps the stored copy).
/// </summary>
public sealed class ClientResolver(DenDbContext db, IClientMetadataFetcher fetcher, OAuthUrls urls, IOptions<OAuthClientMetadataOptions> options)
{
    private static readonly TimeSpan Refresh = TimeSpan.FromHours(1);

    public async Task<OAuthClient?> ResolveAsync(string? clientId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(clientId)) return null;
        var stored = await db.OAuthClients.AsNoTracking().FirstOrDefaultAsync(c => c.Id == clientId, cancellationToken);
        if (!Uri.TryCreate(clientId, UriKind.Absolute, out var url) || url.Scheme != Uri.UriSchemeHttps) return stored;
        if (stored is { MetadataFetchedAt: { } at } && DateTime.UtcNow - at < Refresh) return stored;

        var fresh = await LoadAsync(url, clientId, cancellationToken);
        if (fresh is null) return stored is { MetadataFetchedAt: not null } ? stored : null;   // an unreachable document leaves a known client as it was
        if (stored is null)
        {
            db.OAuthClients.Add(fresh);
            try { await db.SaveChangesAsync(cancellationToken); }
            catch (DbUpdateException) { db.Entry(fresh).State = EntityState.Detached; return await db.OAuthClients.AsNoTracking().FirstAsync(c => c.Id == clientId, cancellationToken); }
            db.Entry(fresh).State = EntityState.Detached;
            return fresh;
        }
        await db.OAuthClients.Where(c => c.Id == clientId).ExecuteUpdateAsync(s => s
            .SetProperty(c => c.Name, fresh.Name).SetProperty(c => c.RedirectUrisJson, fresh.RedirectUrisJson).SetProperty(c => c.LogoUri, fresh.LogoUri)
            .SetProperty(c => c.MetadataFetchedAt, fresh.MetadataFetchedAt), cancellationToken);
        return fresh;
    }

    private async Task<OAuthClient?> LoadAsync(Uri url, string clientId, CancellationToken cancellationToken)
    {
        if (!ClientMetadataPolicy.IsAllowedUrl(url, [urls.Web, urls.Api], options.Value.AllowPrivateUrls)) return null;
        var response = await fetcher.FetchAsync(url, cancellationToken);
        if (response is not { Status: 200 } || response.ContentType is null || !response.ContentType.Contains("json", StringComparison.OrdinalIgnoreCase)) return null;
        return Parse(clientId, response.Body);
    }

    /// <summary>A valid document becomes a public client; anything else is refused (null).</summary>
    public static OAuthClient? Parse(string clientId, string body)
    {
        JsonElement root;
        try { using var doc = JsonDocument.Parse(body); root = doc.RootElement.Clone(); }
        catch (JsonException) { return null; }
        if (root.ValueKind != JsonValueKind.Object) return null;

        // The document must be about this very client_id, must be a public client (no secret of any kind), and must name its redirects.
        if (!root.TryGetProperty("client_id", out var id) || id.ValueKind != JsonValueKind.String || id.GetString() != clientId) return null;
        if (root.TryGetProperty("client_secret", out _) || root.TryGetProperty("client_secret_expires_at", out _)) return null;
        if (root.TryGetProperty("token_endpoint_auth_method", out var method) && method.GetString() != "none") return null;
        if (!root.TryGetProperty("redirect_uris", out var redirects) || redirects.ValueKind != JsonValueKind.Array || redirects.GetArrayLength() is 0 or > 20) return null;
        var uris = new List<string>();
        foreach (var item in redirects.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String || !RedirectPolicy.IsAllowed(item.GetString()!)) return null;
            uris.Add(item.GetString()!);
        }
        if (root.TryGetProperty("grant_types", out var grants) && grants.ValueKind == JsonValueKind.Array
            && grants.EnumerateArray().Any(g => g.GetString() is not ("authorization_code" or "refresh_token"))) return null;

        var name = root.TryGetProperty("client_name", out var n) && n.ValueKind == JsonValueKind.String && n.GetString()!.Trim().Length > 0 ? n.GetString()!.Trim() : new Uri(clientId).Host;
        if (name.Length > 100) name = name[..100];
        string? logo = root.TryGetProperty("logo_uri", out var l) && l.ValueKind == JsonValueKind.String && Uri.TryCreate(l.GetString(), UriKind.Absolute, out var logoUri) && logoUri.Scheme == Uri.UriSchemeHttps ? logoUri.ToString() : null;
        var now = DateTime.UtcNow;
        return new OAuthClient { Id = clientId, Name = name, RedirectUrisJson = JsonSerializer.Serialize(uris), Scope = OAuthConstants.DefaultScope, AuthMethod = "none", LogoUri = logo, CreatedAt = now, MetadataFetchedAt = now };
    }
}
