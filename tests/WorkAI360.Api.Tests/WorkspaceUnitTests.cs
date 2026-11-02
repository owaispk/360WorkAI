using System.Text.Json.Nodes;
using WorkAI360.Api.Features.Workspace;

namespace WorkAI360.Api.Tests;

/// <summary>The pieces of the workspace area that need no server: canonical JSON and digests, Markdown, schema checks, call graphs, ids, source safety, the script runner.</summary>
public sealed class WorkspaceUnitTests
{
    private static JsonNode? N(string json) => JsonNode.Parse(json);

    // ---------- canonical JSON and digests ----------

    [Fact]
    public void Canonical_json_sorts_keys_and_matches_the_references_digest()
    {
        Assert.Equal("""{"doubled":6,"name":"x"}""", WorkflowArtifacts.Canonical(N("""{"name":"x","doubled":6}""")));
        // The same digest the reference computes for the same value (found by running both).
        Assert.Equal("sha256:b7a143f8f3a5e50542226ca8b765b6f48f492e53d29a759fde21437130049463", WorkflowArtifacts.Digest(N("""{"name":"x","doubled":6}""")));
    }

    [Theory]
    [InlineData(1, "1")]
    [InlineData(-0.0, "0")]
    [InlineData(1.5, "1.5")]
    [InlineData(100, "100")]
    [InlineData(1e21, "1e+21")]
    [InlineData(1e-7, "1e-7")]
    [InlineData(0.000001, "0.000001")]
    [InlineData(123456789012345680000.0, "123456789012345680000")]
    public void Numbers_print_the_way_JavaScript_prints_them(double value, string expected) => Assert.Equal(expected, WorkflowArtifacts.Number(value));

    [Fact]
    public void Canonical_json_escapes_strings_like_JSON_stringify()
    {
        Assert.Equal("\"a\\\"b\\\\c\\n\\u0001é<>&\"", WorkflowArtifacts.Canonical(JsonValue.Create("a\"b\\c\n\u0001é<>&")));
        Assert.Equal("null", WorkflowArtifacts.Canonical(null));
        Assert.Equal("[1,\"x\",true,null,{\"a\":[]}]", WorkflowArtifacts.Canonical(N("""[1,"x",true,null,{"a":[]}]""")));
    }

    [Fact]
    public void Null_and_an_absent_value_digest_the_same_but_an_optional_digest_is_null()
    {
        Assert.Equal(WorkflowArtifacts.Digest(null), WorkflowArtifacts.Digest(N("null")));
        Assert.Null(WorkflowArtifacts.OptionalDigest(null));
    }

    // ---------- Markdown ----------

    [Fact]
    public void A_flat_object_is_a_two_column_table_sorted_by_key()
        => Assert.Equal("| Key | Value |\n| --- | --- |\n| a | 1 |\n| b | x |", WorkflowArtifacts.RenderMarkdown(N("""{"b":"x","a":1}""")));

    [Fact]
    public void A_list_of_same_shaped_flat_objects_is_a_table_and_pipes_and_markup_are_escaped()
    {
        var md = WorkflowArtifacts.RenderMarkdown(N("""[{"n":"a|b","t":"<b>"},{"n":"c","t":null}]"""));
        Assert.Equal("| n | t |\n| --- | --- |\n| a\\|b | &lt;b&gt; |\n| c | null |", md);
    }

    [Fact]
    public void Anything_else_is_fenced_json_and_a_string_is_escaped_text()
    {
        Assert.Equal("```json\n[{\"a\":1},{\"b\":2}]\n```", WorkflowArtifacts.RenderMarkdown(N("""[{"a":1},{"b":2}]""")));
        Assert.Equal("```json\n{\"a\":{\"b\":1}}\n```", WorkflowArtifacts.RenderMarkdown(N("""{"a":{"b":1}}""")));
        Assert.Equal("1 &lt; 2 &amp; 3", WorkflowArtifacts.RenderMarkdown(JsonValue.Create("1 < 2 & 3")));
    }

    // ---------- freshness ----------

    [Fact]
    public void Freshness_is_never_run_fresh_stale_or_needs_attention()
    {
        var now = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
        Assert.Equal("never_run", WorkflowArtifacts.Freshness(null, null, null, null, 1000, null, now)["state"]!.GetValue<string>());
        var fresh = WorkflowArtifacts.Freshness(now.AddMilliseconds(-500), "succeeded", now.AddMilliseconds(-500), "wfr_x", 1000, null, now);
        Assert.Equal("fresh", fresh["state"]!.GetValue<string>());
        Assert.Equal(500, fresh["ageMs"]!.GetValue<long>());
        var stale = WorkflowArtifacts.Freshness(now.AddSeconds(-5), "succeeded", now.AddSeconds(-5), "wfr_x", 1000, null, now);
        Assert.Equal("stale", stale["state"]!.GetValue<string>());
        Assert.Equal(1000, stale["maxAgeMs"]!.GetValue<long>());
        var bad = WorkflowArtifacts.Freshness(now, "failed", now.AddSeconds(-3), "wfr_y", 1000, "  boom  ", now);
        Assert.Equal("needs_attention", bad["state"]!.GetValue<string>());
        Assert.Equal("boom", bad["reason"]!.GetValue<string>());
        Assert.Equal("wfr_y", bad["lastSuccessfulReceiptId"]!.GetValue<string>());
        Assert.Equal("The latest refresh failed.", WorkflowArtifacts.Freshness(now, "failed", null, null, 1000, " ", now)["reason"]!.GetValue<string>());
    }

    // ---------- JSON Schema ----------

    [Theory]
    [InlineData("""{"type":"object","required":["a"]}""", """{}""", "data must have required property 'a'")]
    [InlineData("""{"type":"object","properties":{"a":{"type":"string"}}}""", """{"a":1}""", "data/a must be string")]
    [InlineData("""{"type":"integer"}""", "1.5", "data must be integer")]
    [InlineData("""{"type":["string","null"]}""", "5", "data must be string,null")]
    [InlineData("""{"enum":["a","b"]}""", "\"c\"", "data must be equal to one of the allowed values")]
    [InlineData("""{"type":"object","additionalProperties":false,"properties":{"a":{}}}""", """{"a":1,"b":2}""", "data must NOT have additional properties")]
    [InlineData("""{"type":"array","items":{"type":"number"}}""", """[1,"x"]""", "data/1 must be number")]
    [InlineData("""{"type":"number","minimum":3}""", "2", "data must be >= 3")]
    [InlineData("""{"type":"string","minLength":2}""", "\"a\"", "data must NOT have fewer than 2 characters")]
    [InlineData("""{"type":"string","pattern":"^a+$"}""", "\"ab\"", "data must match pattern \"^a+$\"")]
    [InlineData("""{"oneOf":[{"type":"string"},{"type":"number"}]}""", "true", "data must match exactly one schema in oneOf")]
    [InlineData("""{"type":"array","uniqueItems":true}""", "[1,1]", "data must NOT have duplicate items")]
    [InlineData("""{"definitions":{"s":{"type":"string"}},"properties":{"a":{"$ref":"#/definitions/s"}}}""", """{"a":1}""", "data/a must be string")]
    public void A_value_that_breaks_the_schema_is_reported_the_way_Ajv_words_it(string schema, string value, string expected)
    {
        var result = JsonSchemaCheck.Validate(N(schema)!, N(value));
        Assert.True(result.SchemaValid);
        Assert.Contains(expected, result.Errors);
    }

    [Theory]
    [InlineData("""{"type":"object","properties":{"a":{"type":"string"}},"required":["a"]}""", """{"a":"x","b":1}""")]
    [InlineData("""{"type":["string","null"]}""", "null")]
    [InlineData("""{"anyOf":[{"type":"string"},{"type":"number"}]}""", "3")]
    [InlineData("""{"type":"number","exclusiveMinimum":0,"multipleOf":0.5}""", "1.5")]
    [InlineData("true", "{}")]
    [InlineData("""{"if":{"properties":{"k":{"const":1}}},"then":{"required":["v"]}}""", """{"k":2}""")]
    public void A_value_that_satisfies_the_schema_passes(string schema, string value) => Assert.True(JsonSchemaCheck.Validate(N(schema)!, N(value)).Ok);

    [Theory]
    [InlineData("""{"type":"wat"}""")]
    [InlineData("""{"type":"object","properties":{"a":{"$ref":"#/nope"}}}""")]
    [InlineData("""{"type":"string","pattern":"("}""")]
    [InlineData("42")]
    public void A_schema_that_cannot_be_used_is_reported_as_invalid_never_as_a_pass(string schema)
    {
        var result = JsonSchemaCheck.Validate(N(schema)!, N("""{"a":"x"}"""));
        Assert.False(result.Ok);
    }

    [Fact]
    public void An_asynchronous_schema_is_detected_anywhere_inside()
    {
        Assert.True(JsonSchemaCheck.HasAsync(N("""{"properties":{"a":{"$async":true}}}""")));
        Assert.False(JsonSchemaCheck.HasAsync(N("""{"properties":{"a":{"type":"string"}}}""")));
    }

    // ---------- the payload of a version ----------

    [Fact]
    public void A_valid_payload_parses_with_its_limits_and_capabilities()
    {
        var (payload, message) = CodemodePayload.Parse(N("""{"language":"codemode-js","inputSchema":{"type":"object"},"exampleInput":null,"requiredCapabilities":[{"capabilityName":"mcp:a:b","scriptPath":"tools.a.b"}],"limits":{"timeoutMs":500,"maxToolCalls":3,"maxOutputBytes":100}}"""));
        Assert.Null(message);
        Assert.NotNull(payload);
        Assert.Equal(500, payload!.TimeoutMs);
        Assert.Equal(3, payload.MaxToolCalls);
        Assert.True(payload.HasExampleInput);
        Assert.Equal("tools.a.b", Assert.Single(payload.Required).ScriptPath);
    }

    [Theory]
    [InlineData("""{"language":"codemode-js"}""", "The Workflow requiredCapabilities must be an array.")]
    [InlineData("""{"language":"python","requiredCapabilities":[]}""", "The Workflow language must be codemode-js.")]
    [InlineData("""{"language":"codemode-js","requiredCapabilities":[],"extra":1}""", "The Workflow payload must contain only language, inputSchema, outputSchema, exampleInput, requiredCapabilities, and limits.")]
    [InlineData("""{"language":"codemode-js","requiredCapabilities":[],"inputSchema":[]}""", "The Workflow inputSchema must be a JSON Schema object.")]
    [InlineData("""{"language":"codemode-js","requiredCapabilities":[],"outputSchema":{"$async":true}}""", "Asynchronous Workflow schemas are not supported.")]
    [InlineData("""{"language":"codemode-js","requiredCapabilities":[{"capabilityName":" ","scriptPath":"x"}]}""", "Each Workflow required capability must contain only non-empty capabilityName and scriptPath strings.")]
    [InlineData("""{"language":"codemode-js","requiredCapabilities":[],"limits":{"timeoutMs":0}}""", "The Workflow timeoutMs limit must be a positive safe integer.")]
    [InlineData("""{"language":"codemode-js","requiredCapabilities":[],"limits":{"maxToolCalls":-1}}""", "The Workflow maxToolCalls limit must be a non-negative safe integer.")]
    [InlineData("""{"language":"codemode-js","requiredCapabilities":[],"limits":{"other":1}}""", "The Workflow limits must contain only timeoutMs, maxToolCalls, and maxOutputBytes.")]
    [InlineData("[]", "The Workflow payload must contain only language, inputSchema, outputSchema, exampleInput, requiredCapabilities, and limits.")]
    public void A_malformed_payload_says_what_is_wrong(string json, string message) => Assert.Equal(message, CodemodePayload.Parse(N(json)).Message);

    // ---------- ids ----------

    [Theory]
    [InlineData("abc", "Invalid length. Suffix should have 26 characters, got 3")]
    [InlineData("cob_", "Invalid length. Suffix should have 26 characters, got 0")]
    [InlineData("_01m6797hhce34acegcde4y57bd", "Invalid TypeId. Prefix cannot be empty when there's a separator: _01m6797hhce34acegcde4y57bd")]
    [InlineData("cob_81m6797hhce34acegcde4y57bd", "Invalid suffix. First character \"8\" must be in the range [0-7]")]
    [InlineData("cob_01m6797hhce34acegcde4y57bu", "Invalid base32 character")]
    [InlineData("plg_01m6797hhce34acegcde4y57bd", "TypeID prefix mismatch: expected 'cob' but got 'plg'")]
    [InlineData("Cob_01m6797hhce34acegcde4y57bd", "Invalid prefix \"Cob\". Must be at most 63 ASCII letters [a-z_]")]
    public void A_bad_id_gets_the_id_librarys_words(string id, string message) => Assert.Equal(message, Assert.Throws<WorkflowException>(() => TypeIds.ConfigObject(id)).Message);

    [Fact]
    public void Receipt_ids_accept_the_old_prefix_too()
    {
        Assert.Equal("wfr_01m6797hhce34acegcde4y57bd", TypeIds.Receipt("wfr_01m6797hhce34acegcde4y57bd"));
        Assert.Equal("cmr_01m6797hhce34acegcde4y57bd", TypeIds.Receipt("cmr_01m6797hhce34acegcde4y57bd"));
        Assert.Throws<WorkflowException>(() => TypeIds.Receipt("cob_01m6797hhce34acegcde4y57bd"));
    }

    // ---------- literal credentials ----------

    [Theory]
    [InlineData("const token = 'abcdef123456'; return token")]
    [InlineData("const o = { api_key: \"zzzzzzzz\" }; return o")]
    [InlineData("headers['Authorization'] = 'Bearer abcdefgh12345'")]
    [InlineData("return fetchIt('https://user:pass@example.com/x')")]
    [InlineData("const k = 'ghp_abcdefghijklmnop'; return 1")]
    [InlineData("return { password: 'hunter2' + 'hunter3' }")]
    [InlineData("const t = '\\u0073k-abcdefghijklmnopqrst'; return t")]
    [InlineData("return url + '?api_key=abc123'")]
    [InlineData("-----BEGIN RSA PRIVATE KEY-----")]
    [InlineData("const { secret = 'literal-secret' } = input; return secret")]
    public void Source_with_a_literal_credential_is_refused(string code) => Assert.Equal("workflow_source_contains_secret", Assert.Throws<WorkflowException>(() => SourceSafety.AssertSafe(code)).Message);

    [Theory]
    [InlineData("const token = input.token; return token")]
    [InlineData("return { passwordLength: input.password.length }")]
    [InlineData("const total = input.a + input.b; return { total }")]
    [InlineData("return await tools.den.whoami({})")]
    [InlineData("const secret = process.env; return 1 +")]
    public void Ordinary_source_is_accepted(string code) => SourceSafety.AssertSafe(code);

    // ---------- keyset cursors ----------

    [Fact]
    public void A_cursor_round_trips_and_garbage_does_not_decode()
    {
        var at = new DateTime(2026, 5, 6, 7, 8, 9, 123, DateTimeKind.Utc);
        var decoded = Keyset.Decode(Keyset.Encode(at, "wfr_abc"));
        Assert.NotNull(decoded);
        Assert.Equal(at, decoded!.At);
        Assert.Equal("wfr_abc", decoded.Id);
        Assert.Null(Keyset.Decode("%%%"));
        Assert.Null(Keyset.Decode("bm90anNvbg"));
        Assert.Null(Keyset.Decode(""));
        Assert.Null(Keyset.Decode(Convert.ToBase64String("""{"at":"x","id":"y"}"""u8.ToArray())));
        Assert.Null(Keyset.Decode(new string('a', 201)));
    }

    // ---------- retained authoring source ----------

    private static AuthoringSource Source(string org = "org_1", string member = "om_1", string receipt = "wfr_1", string code = "return 1") =>
        new(receipt, org, member, code, "adhoc", "sha256:i", null, null, WorkflowArtifacts.CodeDigest(code), "adhoc", null);

    [Fact]
    public void Retained_source_is_found_for_its_person_and_workspace_only_and_expires_after_fifteen_minutes()
    {
        var store = new AuthoringSources();
        var t0 = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        Assert.True(store.Retain(Source(), t0));
        Assert.NotNull(store.Get("org_1", "om_1", "wfr_1", t0.AddMinutes(14)));
        Assert.Null(store.Get("org_2", "om_1", "wfr_1", t0));
        Assert.Null(store.Get("org_1", "om_2", "wfr_1", t0));
        Assert.Null(store.Get("org_1", "om_1", "wfr_2", t0));
        Assert.Null(store.Get("org_1", "om_1", "wfr_1", t0.AddMinutes(15)));
    }

    [Fact]
    public void Source_with_a_credential_or_a_duplicate_receipt_is_not_retained_and_the_oldest_go_first()
    {
        var store = new AuthoringSources();
        Assert.False(store.Retain(Source(code: "const token = 'abcdef123456'")));
        Assert.False(store.Retain(Source(code: "")));
        Assert.True(store.Retain(Source(receipt: "wfr_a")));
        Assert.False(store.Retain(Source(receipt: "wfr_a")));
        for (var i = 0; i < 200; i++) Assert.True(store.Retain(Source(receipt: $"wfr_x{i}")));
        Assert.Null(store.Get("org_1", "om_1", "wfr_a"));
        Assert.NotNull(store.Get("org_1", "om_1", "wfr_x199"));
    }

    // ---------- runtime facts for a live run ----------

    [Fact]
    public void The_runtime_for_a_live_run_has_the_days_bounds_in_the_time_zone()
    {
        var at = new DateTime(2026, 3, 10, 16, 30, 0, DateTimeKind.Utc);
        var utc = ArtifactRuntime.Build(null, at);
        Assert.Equal("2026-03-10", utc["today"]!.GetValue<string>());
        Assert.Equal("2026-03-10T00:00:00.000Z", utc["dayStart"]!.GetValue<string>());
        Assert.Equal("2026-03-11T00:00:00.000Z", utc["dayEnd"]!.GetValue<string>());
        var tokyo = ArtifactRuntime.Build("Asia/Tokyo", at);
        // 16:30 UTC is already the 11th in Tokyo (UTC+9).
        Assert.Equal("2026-03-11", tokyo["today"]!.GetValue<string>());
        Assert.Equal("2026-03-10T15:00:00.000Z", tokyo["dayStart"]!.GetValue<string>());
        Assert.Equal("2026-03-11T15:00:00.000Z", tokyo["dayEnd"]!.GetValue<string>());
        Assert.True(ArtifactRuntime.ValidZone("Europe/Berlin"));
        Assert.False(ArtifactRuntime.ValidZone("Mars/Base"));
    }

    // ---------- the call graph ----------

    [Fact]
    public void The_graph_shows_tool_calls_in_order_with_data_flowing_between_them()
    {
        var graph = WorkflowGraph.Analyze("const a = await tools.docs.search({ q: input.q });\nconst b = await tools.docs.read({ id: a.id });\nreturn { b };");
        Assert.Null(graph["parseError"]);
        var nodes = graph["nodes"]!.AsArray().Select(n => $"{n!["id"]}:{n["kind"]}:{n["label"]}").ToArray();
        Assert.Equal(["input:input:Input", "tool1:tool:docs.search", "tool2:tool:docs.read", "return1:return:{ b }"], nodes);
        var edges = graph["edges"]!.AsArray().Select(e => $"{e!["from"]}>{e["to"]}:{e["label"]}:{e["kind"]}").ToArray();
        Assert.Contains("tool1>tool2:a:data", edges);
        Assert.Contains("input>tool1:input.q:data", edges);
        Assert.Equal("tools.docs.search", graph["nodes"]![1]!["scriptPath"]!.GetValue<string>());
        Assert.Equal("a", graph["nodes"]![1]!["assignsTo"]!.GetValue<string>());
    }

    [Fact]
    public void Calls_inside_Promise_all_share_a_parallel_group_and_loops_and_branches_are_nodes()
    {
        var graph = WorkflowGraph.Analyze("const [x, y] = await Promise.all([tools.a.one({}), tools.b['two-x']({})]);\nfor (const i of input.items) { if (i > 1) { await tools.c.three({ i }); } }\nreturn x;");
        var tools = graph["nodes"]!.AsArray().Where(n => n!["kind"]!.GetValue<string>() == "tool").Select(n => n!).ToList();
        Assert.Equal(3, tools.Count);
        Assert.Equal("p1", tools[0]["parallelGroup"]!.GetValue<string>());
        Assert.Equal("p1", tools[1]["parallelGroup"]!.GetValue<string>());
        Assert.Null(tools[2]["parallelGroup"]);
        Assert.Equal("x", tools[0]["assignsTo"]!.GetValue<string>());
        Assert.Equal("y", tools[1]["assignsTo"]!.GetValue<string>());
        Assert.Contains(graph["nodes"]!.AsArray(), n => n!["kind"]!.GetValue<string>() == "loop");
        Assert.Contains(graph["nodes"]!.AsArray(), n => n!["kind"]!.GetValue<string>() == "branch");
    }

    [Fact]
    public void Source_that_does_not_parse_gives_an_empty_graph_with_the_error()
    {
        var graph = WorkflowGraph.Analyze("return (");
        Assert.Empty(graph["nodes"]!.AsArray());
        Assert.False(string.IsNullOrEmpty(graph["parseError"]?.GetValue<string>()));
    }

    [Fact]
    public void Redacting_a_graph_hides_source_derived_labels_and_mermaid_draws_it()
    {
        var graph = WorkflowGraph.Analyze("if (input.secretCondition) { return { hidden: 1 } }\nwhile (input.more) { await tools.a.b({ m: input.more }) }\nreturn 1");
        var redacted = WorkflowGraph.Redact(graph);
        Assert.Contains(redacted["nodes"]!.AsArray(), n => n!["label"]!.GetValue<string>() == "Condition");
        Assert.Contains(redacted["nodes"]!.AsArray(), n => n!["label"]!.GetValue<string>() == "Repeat");
        Assert.DoesNotContain(redacted["nodes"]!.AsArray(), n => n!["kind"]!.GetValue<string>() is "branch" or "loop" or "return" && n["label"]!.GetValue<string>().Contains("secretCondition"));
        Assert.Contains(graph["nodes"]!.AsArray(), n => n!["kind"]!.GetValue<string>() == "branch" && n["label"]!.GetValue<string>().Contains("secretCondition"));
        var mermaid = WorkflowGraph.ToMermaid(graph);
        Assert.StartsWith("flowchart TD", mermaid);
        Assert.Contains("branch1{", mermaid);
        Assert.Contains("-.->", mermaid);
    }

    // ---------- tool names ----------

    [Theory]
    [InlineData("Docs Search", "docs_search")]
    [InlineData("9lives", "_9lives")]
    [InlineData("---", "_")]
    [InlineData("Ünï", "_n_")]
    public void Connection_names_become_safe_namespaces(string name, string expected) => Assert.Equal(expected, WorkflowTools.Sanitize(name));

    [Theory]
    [InlineData("tools.docs.search", "docs.search")]
    [InlineData("tools.notion[\"notion-query\"]", "notion.notion-query")]
    public void A_scripts_call_name_is_its_path_joined_with_dots(string path, string expected) => Assert.Equal(expected, WorkflowTools.CallName(path));
}
