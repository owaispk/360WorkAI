using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Jint;
using Jint.Native;
using Jint.Native.Json;
using Jint.Native.Object;
using Jint.Runtime;
using Jint.Runtime.Descriptors;
using Jint.Runtime.Interop;

namespace WorkAI360.Api.Features.Workspace;

/// <summary>One tool a script may call as <c>tools.&lt;namespace&gt;.&lt;name&gt;(arguments)</c>.</summary>
public sealed record CodeModeTool(string Namespace, string Name, string CapabilityName, bool ReadOnly, Func<JsonObject, CancellationToken, Task<JsonNode?>> Invoke)
{
    private static bool IsIdentifier(string s) => s.Length > 0 && (char.IsLetter(s[0]) || s[0] is '_' or '$') && s.All(c => char.IsLetterOrDigit(c) || c is '_' or '$');

    /// <summary>How a script spells the tool: <c>tools.den.whoami</c>, or <c>tools.docs["search-pages"]</c> when the name is not an identifier.</summary>
    public string ScriptPath => IsIdentifier(Name) ? $"tools.{Namespace}.{Name}" : $"tools.{Namespace}[{System.Text.Json.JsonSerializer.Serialize(Name)}]";

    /// <summary>The name a run records for a call: the path joined with dots (<c>docs.search-pages</c>).</summary>
    public string CallName => $"{Namespace}.{Name}";
}

public sealed record CodeModeLimits(int TimeoutMs, int MaxToolCalls, int MaxOutputBytes);

/// <summary>A failure a script run reports: the kind (<c>ParseError</c>, <c>ToolFailure</c>, <c>TimeoutExceeded</c>…) and a message safe to show.</summary>
public sealed record CodeModeDiagnostic(string Kind, string Message);

public sealed record CodeModeResult(bool Ok, JsonNode? Value, CodeModeDiagnostic? Error, List<string> Logs, List<string> ToolCalls, int DurationMs);

/// <summary>
/// Runs a Workflow script: JavaScript with top-level <c>await</c> and <c>return</c>, given <c>input</c> and a <c>tools</c> tree, and nothing else from the
/// host (no files, network, modules or .NET types). Time, memory, recursion, tool calls and output size are limited; a script that exceeds a
/// limit stops with a diagnostic. Results and inputs cross the boundary as plain JSON.
/// </summary>
public static class CodeModeRunner
{
    private sealed class AbortException(string kind, string message) : Exception(message) { public string Kind { get; } = kind; }

    public static Task<CodeModeResult> RunAsync(string code, JsonNode? input, bool freezeInput, IReadOnlyList<CodeModeTool> tools, CodeModeLimits limits, CancellationToken ct) =>
        // The interpreter is synchronous; tool calls block this one worker thread, never a request thread.
        Task.Run(() => Run(code, input, freezeInput, tools, limits, ct), ct);

    private static JsValue ToJs(Engine engine, JsonNode? node) => node is null ? JsValue.Null : new JsonParser(engine).Parse(node.ToJsonString());

    /// <summary>
    /// A script value as plain JSON data: <c>undefined</c> (also nested) becomes null; only finite numbers, strings, booleans, arrays and plain objects
    /// cross over. Anything else (a function, a symbol, NaN, a cycle, a Date or Map object) is refused as not JSON-safe.
    /// </summary>
    private static JsonNode? FromJs(Engine engine, JsValue value, int depth = 0)
    {
        if (depth > 64) throw new AbortException("InvalidDataValue", "The value is nested too deeply or refers to itself.");
        if (value.IsUndefined() || value.IsNull()) return null;
        if (value.IsBoolean()) return JsonValue.Create(value.AsBoolean());
        if (value.IsString()) return JsonValue.Create(value.AsString());
        if (value.IsNumber())
        {
            var d = value.AsNumber();
            if (double.IsNaN(d) || double.IsInfinity(d)) throw new AbortException("InvalidDataValue", "Numbers must be finite.");
            return JsonValue.Create(d);
        }
        if (value.IsArray())
        {
            var array = value.AsArray();
            var result = new JsonArray();
            for (uint i = 0; i < array.Length; i++) result.Add(FromJs(engine, array.Get(i), depth + 1));
            return result;
        }
        if (value.GetType() == typeof(JsObject))
        {
            var result = new JsonObject();
            foreach (var key in value.AsObject().GetOwnPropertyKeys(Jint.Runtime.Types.String))
            {
                var name = key.AsString();
                var property = value.AsObject().GetOwnProperty(key);
                if (!property.Enumerable) continue;
                result[name] = FromJs(engine, value.AsObject().Get(key), depth + 1);
            }
            return result;
        }
        throw new AbortException("InvalidDataValue", "The result must be plain JSON data.");
    }

    private static CodeModeResult Run(string code, JsonNode? input, bool freezeInput, IReadOnlyList<CodeModeTool> tools, CodeModeLimits limits, CancellationToken ct)
    {
        var watch = Stopwatch.StartNew();
        var logs = new List<string>();
        var calls = new List<string>();
        string? lastToolFailure = null;
        CodeModeResult Fail(string kind, string message) => new(false, null, new CodeModeDiagnostic(kind, message), logs, calls, (int)watch.ElapsedMilliseconds);

        var engine = new Engine(o =>
        {
            o.Strict();
            o.LimitMemory(64 * 1024 * 1024);
            o.LimitRecursion(256);
            o.TimeoutInterval(TimeSpan.FromMilliseconds(Math.Max(1, limits.TimeoutMs)));
            o.CancellationToken(ct);
        });
        try
        {
            var toolRoot = new JsObject(engine);
            var byNamespace = tools.GroupBy(t => t.Namespace, StringComparer.Ordinal);
            foreach (var group in byNamespace)
            {
                var ns = new JsObject(engine);
                foreach (var tool in group)
                {
                    var captured = tool;
                    ns.FastSetProperty(tool.Name, new PropertyDescriptor(new ClrFunction(engine, tool.Name, (_, args) =>
                    {
                        if (calls.Count >= limits.MaxToolCalls) throw new AbortException("ToolCallLimitExceeded", $"The script called more than {limits.MaxToolCalls} tools.");
                        calls.Add(captured.CallName);
                        JsonObject arguments;
                        try
                        {
                            var raw = args.Length > 0 ? FromJs(engine, args[0]) : null;
                            arguments = raw switch { null => new JsonObject(), JsonObject o => o, _ => throw new InvalidOperationException("Tool arguments must be an object.") };
                        }
                        catch (Exception e) when (e is InvalidOperationException or JsonException)
                        {
                            throw new AbortException("InvalidDataValue", $"{captured.CallName}: {e.Message}");
                        }
                        var promise = engine.Advanced.RegisterPromise();
                        try
                        {
                            var outcome = captured.Invoke(arguments, ct).GetAwaiter().GetResult();
                            promise.Resolve(ToJs(engine, outcome));
                        }
                        catch (OperationCanceledException) { throw; }
                        catch (Exception e) when (e is not AbortException)
                        {
                            lastToolFailure = e.Message;
                            promise.Reject(engine.Intrinsics.Error.Construct(e.Message));
                        }
                        return promise.Promise;
                    }), writable: false, enumerable: true, configurable: false));
                }
                toolRoot.FastSetProperty(group.Key, new PropertyDescriptor(ns, writable: false, enumerable: true, configurable: false));
            }
            engine.SetValue("tools", toolRoot);

            var console = new JsObject(engine);
            foreach (var level in new[] { "log", "info", "warn", "error", "debug" })
                console.FastSetProperty(level, new PropertyDescriptor(new ClrFunction(engine, level, (_, args) =>
                {
                    if (logs.Count < 200) logs.Add(string.Join(' ', args.Select(a => a.IsString() ? a.AsString() : FromJs(engine, a)?.ToJsonString() ?? "undefined")));
                    return JsValue.Undefined;
                }), true, true, true));
            engine.SetValue("console", console);

            engine.SetValue("input", input is null ? JsValue.Undefined : ToJs(engine, input));
            if (freezeInput && input is not null) engine.Execute("Object.freeze(input)");

            // The source is the body of an async function: `await` and `return` work at the top level.
            var program = "(async function () {\"use strict\";" + code + "\n})()";
            var completion = engine.Evaluate(program);
            engine.Advanced.ProcessTasks();
            JsValue result;
            try { result = completion.UnwrapIfPromise(); }
            catch (PromiseRejectedException rejected)
            {
                var message = rejected.RejectedValue.IsObject() && rejected.RejectedValue.AsObject().Get("message") is { } m && m.IsString() ? m.AsString() : rejected.Message;
                return Fail(lastToolFailure is not null && message == lastToolFailure ? "ToolFailure" : "ExecutionFailure", "Uncaught: " + message);
            }
            var value = FromJs(engine, result);
            var json = value?.ToJsonString() ?? "null";
            if (Encoding.UTF8.GetByteCount(json) > limits.MaxOutputBytes) return Fail("ExecutionFailure", $"The result is larger than {limits.MaxOutputBytes} bytes.");
            return new CodeModeResult(true, value, null, logs, calls, (int)watch.ElapsedMilliseconds);
        }
        catch (AbortException a) { return Fail(a.Kind, a.Message); }
        catch (Acornima.ParseErrorException e) { return Fail("ParseError", e.Message); }
        catch (TimeoutException) { return Fail("TimeoutExceeded", $"The script ran longer than {limits.TimeoutMs} ms."); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return Fail("TimeoutExceeded", $"The script ran longer than {limits.TimeoutMs} ms."); }
        catch (MemoryLimitExceededException) { return Fail("ExecutionFailure", "The script used too much memory."); }
        catch (RecursionDepthOverflowException) { return Fail("ExecutionFailure", "The script nested too deeply."); }
        catch (StatementsCountOverflowException) { return Fail("ExecutionFailure", "The script ran too many statements."); }
        catch (JavaScriptException e) { return Fail("ExecutionFailure", "Uncaught: " + e.Message); }
        catch (JintException e) { return Fail("ExecutionFailure", e.Message); }
    }
}
