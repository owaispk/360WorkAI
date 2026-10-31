using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.OrgAdmin;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.OrgAdmin;

/// <summary>
/// Brand images (wordmark and app icon): uploaded as multipart form data, checked, stored in the database (no object storage), and served from an
/// immutable, signed URL. Unlike the reference the bytes are checked but not re-encoded (there is no image library here), so image metadata is kept.
/// </summary>
public static class BrandAssetEndpoints
{
    public const int MaxBytes = 2 * 1024 * 1024;
    public const int MaxRequestBytes = MaxBytes * 2 + 128 * 1024;
    private const int MaxDimension = 4096;

    private sealed record Checked(bool Ok, string Reason, string Message, string Extension = "", string ContentType = "", int Width = 0, int Height = 0)
    {
        public static Checked Fail(string reason, string message) => new(false, reason, message);
    }

    public static void MapBrandAssetEndpoints(this WebApplication app)
    {
        app.MapGet("/v1/brand-assets/{organizationId}/{kind}/{version}", async (string organizationId, string kind, string version, string? signature, HttpContext ctx, DenDbContext db, IOptions<AuthOptions> auth) =>
        {
            var parts = version.Split('.');
            var notFound = Results.Json(new { error = "not_found" }, statusCode: 404);
            if (kind is not ("logo" or "icon") || parts.Length != 2 || parts[1] is not ("png" or "jpg") || parts[0].Length != 64 || !parts[0].All(Uri.IsHexDigit) || parts[0] != parts[0].ToLowerInvariant()) return notFound;
            if (!Verify(organizationId, kind, parts[0], parts[1], signature ?? "", auth.Value.Secret)) return notFound;
            var asset = await db.Set<BrandAsset>().AsNoTracking().FirstOrDefaultAsync(a => a.OrganizationId == organizationId && a.Kind == kind && a.Version == parts[0] && a.Extension == parts[1]);
            if (asset is null) return notFound;
            ctx.Response.Headers.CacheControl = "public, max-age=31536000, immutable";
            ctx.Response.Headers.ETag = $"\"{asset.Version}\"";
            ctx.Response.Headers.XContentTypeOptions = "nosniff";
            return Results.Bytes(asset.Bytes, asset.Extension == "png" ? "image/png" : "image/jpeg");
        });

        app.MapPost("/v1/org/brand-assets", async (HttpContext ctx, OrgAccess access, DenDbContext db, IAuditLog audit, OAuthUrls urls, IOptions<AuthOptions> auth) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "branding.update") is { } denied) return denied;
            if (ctx.Request.ContentLength > MaxRequestBytes)
                return Results.Json(new { error = "invalid_brand_asset", kind = (string?)null, reason = "too-large", message = "Upload PNG or JPEG images under 2 MB each." }, statusCode: 413);
            if (ctx.Request.ContentType?.StartsWith("multipart/form-data", StringComparison.OrdinalIgnoreCase) != true)
                return Results.Json(new { error = "invalid_brand_asset", kind = (string?)null, reason = "invalid-request", message = "Upload brand assets as multipart form data." }, statusCode: 400);

            if (ctx.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } limit) limit.MaxRequestBodySize = MaxRequestBytes;
            IFormCollection form;
            try { form = await ctx.Request.ReadFormAsync(); }
            catch (BadHttpRequestException e) when (e.StatusCode == StatusCodes.Status413PayloadTooLarge)
            {
                return Results.Json(new { error = "invalid_brand_asset", kind = (string?)null, reason = "too-large", message = "Upload PNG or JPEG images under 2 MB each." }, statusCode: 413);
            }
            catch (Exception e) when (e is InvalidDataException or BadHttpRequestException or IOException)
            {
                return Results.Json(new { error = "invalid_brand_asset", kind = (string?)null, reason = "invalid-request", message = "Upload brand assets as multipart form data." }, statusCode: 400);
            }
            var logo = form.Files.GetFile("logo");
            var icon = form.Files.GetFile("icon");
            if (logo is null && icon is null)
                return Results.Json(new { error = "invalid_brand_asset", kind = (string?)null, reason = "missing-file", message = "Choose a wordmark, an app icon, or both." }, statusCode: 400);

            var organizationId = context!.Organization.Id;
            var stored = new List<(string Kind, byte[] Bytes, Checked Result, string Name)>();
            foreach (var (kind, file) in new[] { ("logo", logo), ("icon", icon) })
            {
                if (file is null) continue;
                await using var stream = file.OpenReadStream();
                using var buffer = new MemoryStream();
                await stream.CopyToAsync(buffer);
                var bytes = buffer.ToArray();
                var result = Check(kind, bytes, file.ContentType);
                if (!result.Ok) return Results.Json(new { error = "invalid_brand_asset", kind, reason = result.Reason, message = result.Message }, statusCode: 400);
                stored.Add((kind, bytes, result, Path.GetFileName(file.FileName)));
            }

            var settings = await db.Set<OrganizationSettings>().FirstOrDefaultAsync(s => s.OrganizationId == organizationId);
            if (settings is null)
            {
                settings = new OrganizationSettings { OrganizationId = organizationId };
                db.Set<OrganizationSettings>().Add(settings);
            }
            var metadata = OrgSettings.Metadata(settings);
            var now = DateTime.UtcNow;
            var assets = new JsonObject();
            foreach (var (kind, bytes, result, name) in stored)
            {
                var version = Convert.ToHexStringLower(SHA256.HashData(bytes));
                if (!await db.Set<BrandAsset>().AnyAsync(a => a.OrganizationId == organizationId && a.Kind == kind && a.Version == version && a.Extension == result.Extension))
                    db.Set<BrandAsset>().Add(new BrandAsset { Id = Ids.New("bra"), OrganizationId = organizationId, Kind = kind, Version = version, Extension = result.Extension, Bytes = bytes, CreatedAt = now });
                var url = $"{urls.Api}/v1/brand-assets/{Uri.EscapeDataString(organizationId)}/{kind}/{version}.{result.Extension}?signature={Sign(organizationId, kind, version, result.Extension, auth.Value.Secret)}";
                var asset = new JsonObject
                {
                    ["kind"] = kind, ["version"] = version, ["extension"] = result.Extension, ["contentType"] = result.ContentType, ["url"] = url,
                    ["width"] = result.Width, ["height"] = result.Height, ["byteLength"] = bytes.Length,
                    ["originalName"] = name.Length > 255 ? name[..255] : name, ["uploadedAt"] = Responses.IsoUtc(now),
                };
                metadata[kind == "logo" ? "brandLogoUrl" : "brandIconUrl"] = url;
                metadata[kind == "logo" ? "brandLogoAsset" : "brandIconAsset"] = asset.DeepClone();
                assets[kind] = asset;
            }
            settings.MetadataJson = metadata.ToJsonString();
            settings.UpdatedAt = now;
            await db.SaveChangesAsync();
            await audit.RecordAsync(context, new AuditEntry(AuditActions.OrganizationBrandAssetsUpdated,
                [new("organization", organizationId, "target", context.Organization.Name)],
                After: new JsonObject(stored.Select(s => KeyValuePair.Create(s.Kind, (JsonNode?)JsonValue.Create(Convert.ToHexStringLower(SHA256.HashData(s.Bytes))))))));
            return Results.Json(new { assets });
        });
    }

    // ----- signed URLs -----------------------------------------------------------------------------------------------------------------

    private static string Sign(string organizationId, string kind, string version, string extension, string secret) =>
        Convert.ToBase64String(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(string.Join('\0', organizationId, kind, version, extension)))).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static bool Verify(string organizationId, string kind, string version, string extension, string signature, string secret) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(Sign(organizationId, kind, version, extension, secret)), Encoding.UTF8.GetBytes(signature));

    // ----- image checks ----------------------------------------------------------------------------------------------------------------

    private static Checked Check(string kind, byte[] bytes, string declaredType)
    {
        if (bytes.Length == 0) return Checked.Fail("empty", "Choose a non-empty PNG or JPEG image.");
        if (bytes.Length > MaxBytes) return Checked.Fail("too-large", "Use an image under 2 MB.");
        var type = declaredType.Split(';')[0].Trim().ToLowerInvariant();
        if (type is not ("image/png" or "image/jpeg")) return Checked.Fail("unsupported-format", "Use a PNG or JPEG image.");
        var isPng = IsPng(bytes);
        var isJpeg = bytes.Length > 3 && bytes[0] == 0xFF && bytes[1] == 0xD8;
        if ((type == "image/png" && !isPng) || (type == "image/jpeg" && !isJpeg)) return Checked.Fail(isPng || isJpeg ? "type-mismatch" : "invalid-image", isPng || isJpeg ? "The file contents do not match the selected image type." : "OpenWork could not decode that image. Use a valid PNG or JPEG file.");
        var size = isPng ? PngSize(bytes) : JpegSize(bytes);
        if (size is null) return Checked.Fail("invalid-image", "OpenWork could not decode that image. Use a valid PNG or JPEG file.");
        var (width, height) = size.Value;
        if (width <= 0 || height <= 0) return Checked.Fail("invalid-image", "OpenWork could not read that image's dimensions.");
        if (width > MaxDimension || height > MaxDimension) return Checked.Fail("too-large-dimensions", $"Use an image no larger than {MaxDimension}×{MaxDimension} pixels.");
        if (kind == "icon")
        {
            if (width < 64 || height < 64) return Checked.Fail("too-small", "Use a square icon at least 64×64 pixels.");
            if (width != height) return Checked.Fail("invalid-aspect", "Use a square image for the app icon.");
        }
        else
        {
            if (width < 128 || height < 32) return Checked.Fail("too-small", "Use a wordmark at least 128×32 pixels.");
            var ratio = (double)width / height;
            if (ratio < 1.5 || ratio > 8) return Checked.Fail("invalid-aspect", "Use a horizontal wordmark between 1.5:1 and 8:1.");
        }
        return new Checked(true, "", "", isPng ? "png" : "jpg", type, width, height);
    }

    private static readonly byte[] PngSignature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    private static bool IsPng(byte[] b) => b.Length > 8 && b.AsSpan(0, 8).SequenceEqual(PngSignature);

    /// <summary>Walks every chunk (lengths must fit, IHDR first, IEND last), so a file that only starts like a PNG is refused.</summary>
    private static (int, int)? PngSize(byte[] b)
    {
        var pos = 8;
        int? width = null, height = null;
        var first = true;
        while (pos + 12 <= b.Length)
        {
            var length = BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(pos, 4));
            if (length > int.MaxValue || pos + 12L + length > b.Length) return null;
            var type = Encoding.ASCII.GetString(b, pos + 4, 4);
            if (first && type != "IHDR") return null;
            if (type == "IHDR")
            {
                if (length != 13) return null;
                width = (int)BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(pos + 8, 4));
                height = (int)BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(pos + 12, 4));
            }
            first = false;
            pos += 12 + (int)length;
            if (type == "IEND") return pos == b.Length && width is not null ? (width.Value, height!.Value) : null;
        }
        return null;
    }

    private static (int, int)? JpegSize(byte[] b)
    {
        var pos = 2;
        while (pos + 4 <= b.Length)
        {
            if (b[pos] != 0xFF) return null;
            var marker = b[pos + 1];
            if (marker == 0xFF) { pos++; continue; }
            if (marker is 0xD8 or 0x01 or (>= 0xD0 and <= 0xD7)) { pos += 2; continue; }
            if (marker == 0xD9) return null;
            var length = BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(pos + 2, 2));
            if (length < 2 || pos + 2 + length > b.Length) return null;
            if (marker is >= 0xC0 and <= 0xCF and not (0xC4 or 0xC8 or 0xCC))
            {
                if (length < 8) return null;
                var height = BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(pos + 5, 2));
                var width = BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(pos + 7, 2));
                return b[^2] == 0xFF && b[^1] == 0xD9 ? (width, height) : null;
            }
            pos += 2 + length;
        }
        return null;
    }
}
