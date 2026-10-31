using System.Text.Json;
using Microsoft.JSInterop;

namespace WorkAI360.Web.Services;

public sealed record DenRaw(int Status, string Text);

public sealed record DenResponse(int Status, string Text)
{
    public bool Ok => Status is >= 200 and < 300;

    public JsonElement? Json
    {
        get
        {
            if (string.IsNullOrWhiteSpace(Text)) return null;
            try { return JsonDocument.Parse(Text).RootElement.Clone(); } catch (JsonException) { return null; }
        }
    }

    public string? String(params string[] path)
    {
        var node = Json;
        foreach (var key in path)
        {
            if (node is not { ValueKind: JsonValueKind.Object } obj || !obj.TryGetProperty(key, out var next)) return null;
            node = next;
        }
        return node is { ValueKind: JsonValueKind.String } s ? s.GetString() : null;
    }

    /// <summary>The server's human-readable message for a failed call, or a fallback.</summary>
    public string Message(string fallback) => String("message") ?? String("error_description") ?? fallback;
}

/// <summary>
/// Calls the web host's own /api routes from the browser (so the session cookie is set by the browser, exactly as
/// in the reference app) and hands the result back to the Blazor circuit.
/// </summary>
public sealed class DenClient(IJSRuntime js) : IAsyncDisposable
{
    private IJSObjectReference? _module;

    public async Task<DenResponse> RequestAsync(string path, string method = "GET", object? body = null)
    {
        _module ??= await js.InvokeAsync<IJSObjectReference>("import", "./js/den.js");
        var raw = await _module.InvokeAsync<DenRaw>("request", path, method, body is null ? null : JsonSerializer.Serialize(body, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        return new DenResponse(raw.Status, raw.Text);
    }

    /// <summary>Posts the files chosen in the given file inputs as multipart form data. <paramref name="fields"/> pairs a form field name with an input element id.</summary>
    public async Task<DenResponse> UploadAsync(string path, IEnumerable<(string Name, string InputId)> fields)
    {
        _module ??= await js.InvokeAsync<IJSObjectReference>("import", "./js/den.js");
        var raw = await _module.InvokeAsync<DenRaw>("upload", path, fields.Select(f => new { name = f.Name, inputId = f.InputId }).ToArray());
        return new DenResponse(raw.Status, raw.Text);
    }

    public async Task<bool> CopyAsync(string text)
    {
        _module ??= await js.InvokeAsync<IJSObjectReference>("import", "./js/den.js");
        return await _module.InvokeAsync<bool>("copyText", text);
    }

    public async ValueTask DisposeAsync()
    {
        if (_module is not null)
        {
            try { await _module.DisposeAsync(); } catch (JSDisconnectedException) { }
        }
    }
}
