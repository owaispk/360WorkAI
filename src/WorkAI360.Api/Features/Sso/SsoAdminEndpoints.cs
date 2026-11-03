using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Sso;

/// <summary>Reads a JSON body field by field and reports problems in the reference's zod wording: <c>{error:"invalid_request", details:[{message, path}]}</c>.</summary>
public sealed class BodyReader
{
    private readonly JsonElement _root;
    public List<object> Details { get; } = [];

    private BodyReader(JsonElement root) => _root = root;

    public static async Task<BodyReader> ReadAsync(HttpRequest request)
    {
        try
        {
            using var doc = await JsonDocument.ParseAsync(request.Body);
            return new BodyReader(doc.RootElement.ValueKind == JsonValueKind.Object ? doc.RootElement.Clone() : default);
        }
        catch (JsonException) { return new BodyReader(default); }
    }

    private static string TypeName(JsonValueKind kind) => kind switch
    {
        JsonValueKind.Undefined => "undefined", JsonValueKind.Null => "null", JsonValueKind.String => "string", JsonValueKind.Number => "number",
        JsonValueKind.True or JsonValueKind.False => "boolean", JsonValueKind.Array => "array", _ => "object",
    };

    private void Add(string message, params object[] path) => Details.Add(new { message, path });

    private JsonElement Get(string name) => _root.ValueKind == JsonValueKind.Object && _root.TryGetProperty(name, out var v) ? v : default;

    public string? String(string name, bool required, bool url = false, bool minOne = false)
    {
        var v = Get(name);
        if (v.ValueKind == JsonValueKind.Undefined && !required) return null;
        if (v.ValueKind != JsonValueKind.String) { Add($"Invalid input: expected string, received {TypeName(v.ValueKind)}", name); return null; }
        var s = v.GetString()!;
        if (url && !Uri.TryCreate(s, UriKind.Absolute, out _)) { Add("Invalid URL", name); return null; }
        if (minOne && s.Length < 1) { Add("Too small: expected string to have >=1 characters", name); return null; }
        return s;
    }

    public bool? Bool(string name)
    {
        var v = Get(name);
        if (v.ValueKind == JsonValueKind.Undefined) return null;
        if (v.ValueKind is JsonValueKind.True or JsonValueKind.False) return v.GetBoolean();
        Add($"Invalid input: expected boolean, received {TypeName(v.ValueKind)}", name);
        return null;
    }

    public string[]? StringArray(string name)
    {
        var v = Get(name);
        if (v.ValueKind == JsonValueKind.Undefined) return null;
        if (v.ValueKind != JsonValueKind.Array) { Add($"Invalid input: expected array, received {TypeName(v.ValueKind)}", name); return null; }
        var result = new List<string>();
        var i = 0;
        foreach (var item in v.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String) Add($"Invalid input: expected string, received {TypeName(item.ValueKind)}", name, i);
            else result.Add(item.GetString()!);
            i++;
        }
        return [.. result];
    }

    public string? Enum(string name, params string[] allowed)
    {
        var v = Get(name);
        if (v.ValueKind == JsonValueKind.Undefined) return null;
        if (v.ValueKind == JsonValueKind.String && allowed.Contains(v.GetString())) return v.GetString();
        Add($"Invalid option: expected one of {string.Join("|", allowed.Select(a => $"\"{a}\""))}", name);
        return null;
    }

    public IResult? Failure => Details.Count == 0 ? null : Results.Json(new { error = "invalid_request", details = Details }, statusCode: 400);
}

/// <summary>The SSO settings API (<c>/v1/sso/*</c>) the dashboard's SSO page uses.</summary>
public static class SsoAdminEndpoints
{
    private static IResult Lifecycle(string message) => Results.Json(new { error = "sso_lifecycle_error", message }, statusCode: 409);
    private static IResult OrgNotFound() => Results.Json(new { error = "organization_not_found" }, statusCode: 404);
    private static IResult Invalid(string message) => Results.Json(new { error = "invalid_request", details = new[] { new { message } } }, statusCode: 400);

    public static void Map(WebApplication app)
    {
        app.MapGet("/v1/sso", async (HttpContext ctx, OrgAccess access, SsoService sso) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "sso.view") is { } denied) return denied;
            var connection = await sso.ForOrganizationAsync(context!.Organization.Id);
            return Results.Json(new { connection = connection is null ? null : sso.Payload(connection) });
        });

        app.MapPost("/v1/sso/oidc", async (HttpContext ctx, OrgAccess access, SsoService sso) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "sso.manage") is { } denied) return denied;
            var body = await BodyReader.ReadAsync(ctx.Request);
            var issuer = body.String("issuer", true, url: true);
            var domain = body.String("domain", true, minOne: true)?.Trim();
            var clientId = body.String("clientId", true, minOne: true);
            var clientSecret = body.String("clientSecret", true, minOne: true);
            var scopes = body.StringArray("scopes");
            var skipDiscovery = body.Bool("skipDiscovery");
            var authorization = body.String("authorizationEndpoint", false, url: true);
            var token = body.String("tokenEndpoint", false, url: true);
            var jwks = body.String("jwksEndpoint", false, url: true);
            var userInfo = body.String("userInfoEndpoint", false, url: true);
            var method = body.Enum("tokenEndpointAuthentication", "client_secret_basic", "client_secret_post");
            if (body.Failure is { } invalid) return invalid;

            var (connection, error) = await sso.RegisterOidcAsync(context!.Organization,
                new OidcRegistration(issuer!, domain!, clientId!, clientSecret!, scopes, skipDiscovery ?? false, authorization, token, jwks, userInfo, method), ctx.RequestAborted);
            if (connection is null) return Invalid(error!);
            // Like the reference, the response carries the DNS token to publish (unless the domain is already proven).
            var domainToken = connection.DomainVerified ? null : await sso.RequestDomainTokenAsync(connection, ctx.RequestAborted);
            return Results.Json(new { connection = sso.Payload(connection), domainVerificationToken = domainToken }, statusCode: 201);
        });

        app.MapPost("/v1/sso/saml", async (HttpContext ctx, OrgAccess access, SsoService sso) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "sso.manage") is { } denied) return denied;
            var body = await BodyReader.ReadAsync(ctx.Request);
            var issuer = body.String("issuer", true, url: true);
            var domain = body.String("domain", true, minOne: true)?.Trim();
            var entryPoint = body.String("entryPoint", true, url: true);
            var cert = body.String("cert", true, minOne: true);
            var audience = body.String("audience", false, url: true);
            var binding = body.Enum("binding", "redirect", "post");
            if (body.Failure is { } invalid) return invalid;

            var (connection, error) = await sso.RegisterSamlAsync(context!.Organization, new SamlRegistration(issuer!, domain!, entryPoint!, cert!, audience, binding), ctx.RequestAborted);
            if (connection is null) return Invalid(error!);
            var domainToken = connection.DomainVerified ? null : await sso.RequestDomainTokenAsync(connection, ctx.RequestAborted);
            return Results.Json(new { connection = sso.Payload(connection), domainVerificationToken = domainToken }, statusCode: 201);
        });

        app.MapDelete("/v1/sso", async (HttpContext ctx, OrgAccess access, SsoService sso) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "sso.manage") is { } denied) return denied;
            var connection = await sso.ForOrganizationAsync(context!.Organization.Id);
            if (connection is not null) await sso.DeleteAsync(connection, ctx.RequestAborted);
            return Results.NoContent();
        });

        app.MapPost("/v1/sso/test", async (HttpContext ctx, OrgAccess access, SsoService sso, OAuthUrls urls) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "sso.manage") is { } denied) return denied;
            var connection = await sso.ForOrganizationAsync(context!.Organization.Id);
            if (connection is null) return OrgNotFound();
            var (intent, expires, error) = await sso.CreateTestAsync(connection, context.Auth.User.Id, ctx.RequestAborted);
            if (intent is null) return Lifecycle(error!);
            var testUrl = $"{urls.Web}/sso/test?intentId={Uri.EscapeDataString(intent)}&organizationId={Uri.EscapeDataString(context.Organization.Id)}";
            return Results.Json(new { intentId = intent, expiresAt = Responses.IsoUtc(expires), testUrl }, statusCode: 201);
        });

        app.MapPost("/v1/sso/test/{intentId}/start", async (string intentId, HttpContext ctx, OrgAccess access, SsoService sso, OidcFlow flow, SamlFlow saml, OAuthUrls urls) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "sso.manage") is { } denied) return denied;
            var (connection, error) = await sso.BeginTestAsync(context!.Organization.Id, intentId, context.Auth.User.Id, ctx.RequestAborted);
            if (connection is null) return Lifecycle(error!);
            var completion = $"{urls.Web}/sso/test/complete?{SsoService.TestIntentQueryKey}={Uri.EscapeDataString(intentId)}";
            try
            {
                var start = new OidcFlow.Start(completion, completion, null, context.Auth.User.Email, intentId);
                var url = connection.Kind == "saml" ? await saml.StartAsync(ctx, connection, start, ctx.RequestAborted) : await flow.StartAsync(ctx, connection, start, ctx.RequestAborted);
                return Results.Json(new { url });
            }
            catch (Exception e) when (e is InvalidOperationException or DbUpdateException or JsonException)
            {
                await sso.FailTestAsync(intentId, "start_failed");
                return Lifecycle(SsoService.FailureMessages["start_failed"]);
            }
        });

        app.MapPost("/v1/sso/test/{intentId}/cancel", async (string intentId, HttpContext ctx, OrgAccess access, SsoService sso) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "sso.manage") is { } denied) return denied;
            // Unknown or someone else's intents are ignored, and still answer 204.
            await sso.CancelTestAsync(await sso.ForOrganizationAsync(context!.Organization.Id), intentId, context.Auth.User.Id);
            return Results.NoContent();
        });

        app.MapPost("/v1/sso/enable", async (HttpContext ctx, OrgAccess access, SsoService sso) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "sso.manage") is { } denied) return denied;
            var result = await sso.EnableAsync(context!.Organization.Id, ctx.RequestAborted);
            return result.Ok ? Results.NoContent() : Lifecycle(result.Message);
        });

        app.MapPost("/v1/sso/disable", async (HttpContext ctx, OrgAccess access, SsoService sso) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "sso.manage") is { } denied) return denied;
            return await sso.DisableAsync(context!.Organization.Id, ctx.RequestAborted) ? Results.NoContent() : OrgNotFound();
        });

        // Only SAML connections have service provider metadata. As in the reference, `format` is validated and the answer is always the XML document.
        app.MapGet("/v1/sso/metadata", async (HttpContext ctx, OrgAccess access, SsoService sso) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "sso.view") is { } denied) return denied;
            var format = ctx.Request.Query["format"].ToString();
            if (ctx.Request.Query.ContainsKey("format") && format is not ("xml" or "json"))
                return Results.Json(new { error = "invalid_request", details = new[] { new { message = "Invalid option: expected one of \"xml\"|\"json\"", path = new[] { "format" } } } }, statusCode: 400);
            var connection = await sso.ForOrganizationAsync(context!.Organization.Id);
            return (connection is null ? null : SamlEndpoints.SamlMetadataResult(sso, connection)) ?? OrgNotFound();
        });

        app.MapPost("/v1/sso/request-domain-verification", async (HttpContext ctx, OrgAccess access, SsoService sso) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "sso.manage") is { } denied) return denied;
            var connection = await sso.ForOrganizationAsync(context!.Organization.Id);
            if (connection is null) return OrgNotFound();
            if (connection.DomainVerified) return Invalid("Domain has already been verified");
            return Results.Json(new { domainVerificationToken = await sso.RequestDomainTokenAsync(connection, ctx.RequestAborted) }, statusCode: 201);
        });

        app.MapPost("/v1/sso/verify-domain", async (HttpContext ctx, OrgAccess access, SsoService sso) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "sso.manage") is { } denied) return denied;
            var connection = await sso.ForOrganizationAsync(context!.Organization.Id);
            if (connection is null) return OrgNotFound();
            var failed = await sso.VerifyDomainAsync(connection, ctx.RequestAborted);
            return failed is { } f ? Invalid(f.Message) : Results.NoContent();
        });
    }
}
