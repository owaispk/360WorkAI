using System.Text.Json.Nodes;
using WorkAI360.Api.Features.Workspace;

namespace WorkAI360.Api.Tests;

/// <summary>The script runner: what a Workflow's JavaScript can and cannot do.</summary>
public sealed class CodeModeRunnerTests
{
    private static readonly CodeModeLimits Roomy = new(5000, 100, 65_536);

    private static Task<CodeModeResult> Run(string code, JsonNode? input = null, IReadOnlyList<CodeModeTool>? tools = null, CodeModeLimits? limits = null, bool freeze = false) =>
        CodeModeRunner.RunAsync(code, input, freeze, tools ?? [], limits ?? Roomy, CancellationToken.None);

    private static CodeModeTool Tool(string ns, string name, Func<JsonObject, JsonNode?> run) => new(ns, name, $"cap:{ns}.{name}", true, (args, _) => Task.FromResult(run(args)));

    [Fact]
    public async Task The_returned_value_comes_back_as_plain_json()
    {
        var r = await Run("return { a: 1, b: [true, 'x'], c: { d: null } }");
        Assert.True(r.Ok);
        Assert.Equal("""{"a":1,"b":[true,"x"],"c":{"d":null}}""", r.Value!.ToJsonString());
    }

    [Fact]
    public async Task A_script_that_returns_nothing_gives_null_and_nested_undefined_becomes_null()
    {
        Assert.Null((await Run("const x = 1")).Value);
        Assert.Equal("""{"a":[1,null],"b":null}""", (await Run("return { a: [1, undefined], b: undefined }")).Value!.ToJsonString());
    }

    [Fact]
    public async Task The_input_is_given_as_a_global_and_is_plain_data()
    {
        var r = await Run("return { sum: input.a + input.b, names: input.list.map((x) => x.n) }", JsonNode.Parse("""{"a":2,"b":3,"list":[{"n":"p"},{"n":"q"}]}"""));
        Assert.Equal("""{"sum":5,"names":["p","q"]}""", r.Value!.ToJsonString());
    }

    [Fact]
    public async Task Top_level_await_and_Promise_all_work()
    {
        var r = await Run("const [a, b] = await Promise.all([1, 2].map(async (x) => x * 10)); await null; return { a, b }");
        Assert.Equal("""{"a":10,"b":20}""", r.Value!.ToJsonString());
    }

    [Fact]
    public async Task Tools_are_called_as_functions_and_every_call_is_recorded_by_name()
    {
        var tool = Tool("den", "echo", a => new JsonObject { ["echoed"] = a["msg"]?.DeepClone() });
        var r = await Run("const one = await tools.den.echo({ msg: 'hi' }); const two = await tools.den.echo({ msg: 'again' }); return [one.echoed, two.echoed]", tools: [tool]);
        Assert.Equal("""["hi","again"]""", r.Value!.ToJsonString());
        Assert.Equal(["den.echo", "den.echo"], r.ToolCalls);
    }

    [Fact]
    public async Task A_tool_that_fails_rejects_and_an_uncaught_rejection_is_a_tool_failure_a_caught_one_is_not()
    {
        var failing = new CodeModeTool("x", "boom", "cap:x.boom", true, (_, _) => throw new InvalidOperationException("the service said no"));
        var uncaught = await Run("return await tools.x.boom({})", tools: [failing]);
        Assert.False(uncaught.Ok);
        Assert.Equal("ToolFailure", uncaught.Error!.Kind);
        Assert.Contains("the service said no", uncaught.Error.Message);
        var caught = await Run("try { await tools.x.boom({}) } catch (e) { return { handled: e.message } }", tools: [failing]);
        Assert.True(caught.Ok);
        Assert.Equal("""{"handled":"the service said no"}""", caught.Value!.ToJsonString());
    }

    [Fact]
    public async Task A_thrown_error_is_an_uncaught_execution_failure_with_its_message()
    {
        var r = await Run("throw new Error('boom')");
        Assert.False(r.Ok);
        Assert.Equal("ExecutionFailure", r.Error!.Kind);
        Assert.Equal("Uncaught: boom", r.Error.Message);
    }

    [Fact]
    public async Task A_syntax_error_is_a_parse_error()
    {
        var r = await Run("return (");
        Assert.False(r.Ok);
        Assert.Equal("ParseError", r.Error!.Kind);
    }

    [Fact]
    public async Task Calling_a_tool_that_was_not_offered_fails_the_script()
    {
        var r = await Run("return await tools.nothing.here({})");
        Assert.False(r.Ok);
        Assert.Equal("ExecutionFailure", r.Error!.Kind);
    }

    [Fact]
    public async Task An_endless_loop_is_stopped_by_the_time_limit()
    {
        var r = await Run("while (true) {}", limits: new CodeModeLimits(300, 10, 1000));
        Assert.False(r.Ok);
        Assert.Equal("TimeoutExceeded", r.Error!.Kind);
        Assert.True(r.DurationMs < 5000);
    }

    [Fact]
    public async Task More_tool_calls_than_the_limit_stop_the_script()
    {
        var tool = Tool("t", "n", _ => 1);
        var r = await Run("for (let i = 0; i < 10; i++) { await tools.t.n({}) } return 1", tools: [tool], limits: new CodeModeLimits(5000, 3, 1000));
        Assert.False(r.Ok);
        Assert.Equal("ToolCallLimitExceeded", r.Error!.Kind);
        Assert.Equal(3, r.ToolCalls.Count);
    }

    [Fact]
    public async Task A_result_larger_than_the_output_limit_is_refused()
    {
        var r = await Run("return 'x'.repeat(5000)", limits: new CodeModeLimits(5000, 10, 1000));
        Assert.False(r.Ok);
        Assert.Contains("larger than 1000 bytes", r.Error!.Message);
    }

    [Theory]
    [InlineData("return NaN")]
    [InlineData("return 1 / 0")]
    [InlineData("return () => 1")]
    [InlineData("return new Date(0)")]
    [InlineData("return new Map()")]
    [InlineData("const a = {}; a.self = a; return a")]
    [InlineData("return Symbol('x')")]
    public async Task Values_that_are_not_plain_json_data_cannot_leave_the_script(string code)
    {
        var r = await Run(code);
        Assert.False(r.Ok);
        Assert.Equal("InvalidDataValue", r.Error!.Kind);
    }

    [Theory]
    [InlineData("typeof process")]
    [InlineData("typeof require")]
    [InlineData("typeof System")]
    [InlineData("typeof Deno")]
    [InlineData("typeof fetch")]
    [InlineData("typeof XMLHttpRequest")]
    [InlineData("typeof setTimeout")]
    [InlineData("typeof importScripts")]
    public async Task The_script_has_no_ambient_authority(string expression)
    {
        var r = await Run($"return {expression}");
        Assert.True(r.Ok);
        Assert.Equal("undefined", r.Value!.GetValue<string>());
    }

    [Fact]
    public async Task The_script_cannot_reach_dotnet_types_through_the_engine()
    {
        var r = await Run("return (() => { try { return typeof importNamespace } catch (e) { return 'blocked' } })()");
        Assert.True(r.Ok);
        Assert.Equal("undefined", r.Value!.GetValue<string>());
        var viaConstructor = await Run("return typeof (function () {}).constructor('return typeof System')()");
        Assert.True(viaConstructor.Ok);
    }

    [Fact]
    public async Task Deep_recursion_is_stopped_not_a_crash()
    {
        var r = await Run("function f(n) { return f(n + 1) } return f(0)");
        Assert.False(r.Ok);
        Assert.Equal("ExecutionFailure", r.Error!.Kind);
    }

    [Fact]
    public async Task A_live_run_cannot_change_its_generated_input()
    {
        var input = JsonNode.Parse("""{"runtime":{"today":"2026-01-01"}}""");
        var r = await Run("input.runtime.today = 'changed'; return input.runtime.today", input, freeze: true);
        Assert.False(r.Ok);
        var ok = await Run("input.x = 1; return input.x", JsonNode.Parse("""{"a":1}"""), freeze: false);
        Assert.True(ok.Ok);
    }

    [Fact]
    public async Task Console_output_is_collected_and_capped()
    {
        var r = await Run("console.log('a', 1, { b: 2 }); for (let i = 0; i < 500; i++) console.log(i); return 1");
        Assert.Equal("a 1 {\"b\":2}", r.Logs[0]);
        Assert.Equal(200, r.Logs.Count);
    }

    [Fact]
    public async Task Two_scripts_do_not_share_state_and_tool_arguments_must_be_objects()
    {
        await Run("globalThis.leak = 1; return 1");
        Assert.Equal("undefined", (await Run("return typeof leak")).Value!.GetValue<string>());
        var tool = Tool("t", "n", _ => 1);
        var bad = await Run("return await tools.t.n(5)", tools: [tool]);
        Assert.False(bad.Ok);
        Assert.Equal("InvalidDataValue", bad.Error!.Kind);
    }

    [Fact]
    public async Task Tool_names_that_are_not_identifiers_are_called_with_brackets()
    {
        var tool = Tool("docs", "search-pages", _ => new JsonObject { ["n"] = 2 });
        var r = await Run("return (await tools.docs['search-pages']({})).n", tools: [tool]);
        Assert.Equal(2, r.Value!.GetValue<double>());
        Assert.Equal("tools.docs[\"search-pages\"]", tool.ScriptPath);
        Assert.Equal("docs.search-pages", tool.CallName);
    }

    [Fact]
    public async Task A_promise_that_never_settles_does_not_hang_the_run()
    {
        var r = await Run("await new Promise(() => {}); return 1", limits: new CodeModeLimits(500, 10, 1000));
        Assert.False(r.Ok);
    }
}
