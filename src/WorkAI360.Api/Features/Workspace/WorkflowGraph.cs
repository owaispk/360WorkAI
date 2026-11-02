using System.Text.Json.Nodes;
using Acornima;
using Acornima.Ast;

namespace WorkAI360.Api.Features.Workspace;

/// <summary>
/// The call graph of a Workflow's source: which tools it calls, in what order, under which conditions, and what data flows between them
/// (the reference's <c>workflow-graph.ts</c>, over the same kind of syntax tree). The source is parsed, never run. Source that cannot be
/// parsed gives an empty graph with <c>parseError</c> set.
/// </summary>
public static class WorkflowGraph
{
    private const int LabelLimit = 80;

    private sealed record FlowSource(string Id, string? Label);
    private sealed record ToolCall(CallExpression Call, List<string> Segments);

    private static string Truncate(string label)
    {
        var compact = System.Text.RegularExpressions.Regex.Replace(label, @"\s+", " ").Trim();
        return compact.Length <= LabelLimit ? compact : compact[..(LabelLimit - 1)] + "…";
    }

    public static JsonObject Analyze(string code)
    {
        try
        {
            var parser = new Parser(new ParserOptions { AllowReturnOutsideFunction = true });
            // Wrapped like the script runner does, so top-level `await` and `return` parse as they run.
            var wrapped = "(async function () {" + code + "\n})";
            var program = parser.ParseScript(wrapped);
            var body = FunctionBody(program) ?? throw new InvalidOperationException("Unable to parse Workflow source.");
            return new Analyzer(wrapped, body).Analyze();
        }
        catch (Exception e) when (e is ParseErrorException or InvalidOperationException) { return Failure(e.Message); }
    }

    private static JsonObject Failure(string message) =>
        new() { ["nodes"] = new JsonArray(), ["edges"] = new JsonArray(), ["parseError"] = message };

    private static NodeList<Statement>? FunctionBody(Script program)
    {
        if (program.Body.Count != 1 || program.Body[0] is not ExpressionStatement { Expression: var e }) return null;
        while (e is ParenthesizedExpression p) e = p.Expression;
        return e is FunctionExpression f ? f.Body.Body : null;
    }

    private static string? StaticPropertyName(Node node) => node switch
    {
        Identifier i => i.Name,
        Literal { Value: string s } => s,
        Literal { Value: double d } => WorkflowArtifacts.Number(d),
        _ => null,
    };

    private static List<string>? MemberSegments(Node node)
    {
        switch (node)
        {
            case Identifier i: return i.Name == "tools" ? [] : null;
            case ChainExpression c: return MemberSegments(c.Expression);
            case MemberExpression m:
                var parent = MemberSegments(m.Object);
                if (parent is null) return null;
                var property = m.Computed ? StaticPropertyName(m.Property) : m.Property is Identifier pi ? pi.Name : null;
                if (property is null) return null;
                parent.Add(property);
                return parent;
            default: return null;
        }
    }

    private static ToolCall? AsToolCall(Node node)
    {
        if (node is not CallExpression call) return null;
        var segments = MemberSegments(call.Callee);
        return segments is { Count: > 0 } ? new ToolCall(call, segments) : null;
    }

    private static List<ToolCall> FindToolCalls(Node root)
    {
        var calls = new List<ToolCall>();
        void Visit(Node current)
        {
            foreach (var child in current.ChildNodes) if (child is not null) Visit(child);
            if (AsToolCall(current) is { } found) calls.Add(found);
        }
        Visit(root);
        return calls;
    }

    private static Expression Unwrap(Expression e) => e switch
    {
        AwaitExpression a => Unwrap(a.Argument),
        ChainExpression c => Unwrap(c.Expression),
        ParenthesizedExpression p => Unwrap(p.Expression),
        _ => e,
    };

    private static List<Expression?>? PromiseAllElements(Expression expression)
    {
        if (Unwrap(expression) is not CallExpression { Callee: MemberExpression { Computed: false, Object: Identifier { Name: "Promise" }, Property: Identifier { Name: "all" } } } call) return null;
        if (call.Arguments.Count == 0 || call.Arguments[0] is not ArrayExpression array) return null;
        return array.Elements.Select(e => e is null ? null : e is SpreadElement s ? s.Argument : (Expression)e).ToList();
    }

    private static HashSet<string> ReferencedIdentifiers(IEnumerable<Node> nodes)
    {
        var ids = new HashSet<string>(StringComparer.Ordinal);
        void Visit(Node node, Node? parent)
        {
            if (node is Identifier i)
            {
                var isMemberProperty = parent is MemberExpression { Computed: false } m && ReferenceEquals(m.Property, node);
                var isObjectKey = parent is Property { Computed: false } p && ReferenceEquals(p.Key, node);
                if (!isMemberProperty && !isObjectKey) ids.Add(i.Name);
            }
            foreach (var child in node.ChildNodes) if (child is not null) Visit(child, node);
        }
        foreach (var n in nodes) Visit(n, null);
        return ids;
    }

    private static List<string> InputFields(IEnumerable<Node> nodes)
    {
        var fields = new List<string>();
        void Walk(Node node)
        {
            if (node is MemberExpression { Object: Identifier { Name: "input" } } m)
            {
                var field = m.Computed ? StaticPropertyName(m.Property) : m.Property is Identifier pi ? pi.Name : null;
                if (field is not null && !fields.Contains(field)) fields.Add(field);
            }
            foreach (var child in node.ChildNodes) if (child is not null) Walk(child);
        }
        foreach (var n in nodes) Walk(n);
        return fields;
    }

    private sealed class Analyzer
    {
        private readonly string _code;
        private readonly NodeList<Statement> _body;
        private readonly JsonArray _nodes = [];
        private readonly JsonArray _edges = [];
        private readonly Dictionary<string, string> _assignedTools = new(StringComparer.Ordinal);
        private readonly Dictionary<string, int> _counters = new() { ["branch"] = 0, ["loop"] = 0, ["return"] = 0, ["search"] = 0, ["tool"] = 0 };
        private int _parallelCount;
        private readonly string? _inputNodeId;

        public Analyzer(string code, NodeList<Statement> body)
        {
            _code = code;
            _body = body;
            var fields = InputFields(body);
            if (fields.Count > 0)
            {
                _inputNodeId = "input";
                _nodes.Add(new JsonObject { ["id"] = "input", ["kind"] = "input", ["label"] = "Input", ["fields"] = new JsonArray(fields.Select(f => (JsonNode)f).ToArray()) });
            }
        }

        public JsonObject Analyze()
        {
            var incoming = _inputNodeId is null ? [] : new List<FlowSource> { new(_inputNodeId, null) };
            ProcessSequence(_body, incoming);
            return new JsonObject { ["nodes"] = _nodes, ["edges"] = _edges, ["parseError"] = null };
        }

        private string NextId(string kind) => $"{kind}{++_counters[kind]}";

        private string Source(Node n) => Truncate(_code[n.Start..n.End]);

        private void Connect(List<FlowSource> sources, string target)
        {
            foreach (var s in sources)
                _edges.Add(new JsonObject { ["from"] = s.Id, ["to"] = target, ["label"] = s.Label is { Length: > 0 } l ? Truncate(l) : null, ["kind"] = "flow" });
        }

        private string AddBranch(string label, List<FlowSource> incoming)
        {
            var id = NextId("branch");
            _nodes.Add(new JsonObject { ["id"] = id, ["kind"] = "branch", ["label"] = Truncate(label) });
            Connect(incoming, id);
            return id;
        }

        private List<FlowSource> ProcessSequence(IEnumerable<Node> statements, List<FlowSource> incoming)
        {
            var exits = incoming;
            foreach (var s in statements) exits = ProcessStatement(s, exits);
            return exits;
        }

        private List<FlowSource> ProcessVariableDeclaration(VariableDeclaration statement, List<FlowSource> incoming)
        {
            var exits = incoming;
            foreach (var d in statement.Declarations) if (d.Init is not null) exits = ProcessExpression(d.Init, exits, d.Id);
            return exits;
        }

        private List<FlowSource> ProcessStatement(Node statement, List<FlowSource> incoming)
        {
            switch (statement)
            {
                case BlockStatement b: return ProcessSequence(b.Body, incoming);
                case VariableDeclaration v: return ProcessVariableDeclaration(v, incoming);
                case ExpressionStatement e: return ProcessExpression(e.Expression, incoming, null);
                case ReturnStatement r:
                {
                    var exits = r.Argument is not null ? ProcessExpression(r.Argument, incoming, null) : incoming;
                    var id = NextId("return");
                    _nodes.Add(new JsonObject { ["id"] = id, ["kind"] = "return", ["label"] = ReturnLabel(r.Argument) });
                    Connect(exits, id);
                    return [];
                }
                case IfStatement i:
                {
                    var tested = ProcessExpression(i.Test, incoming, null);
                    var branchId = AddBranch(Source(i.Test), tested);
                    var consequent = ProcessStatement(i.Consequent, [new(branchId, "yes")]);
                    var alternate = i.Alternate is not null ? ProcessStatement(i.Alternate, [new(branchId, "no")]) : [new FlowSource(branchId, "no")];
                    return [.. consequent, .. alternate];
                }
                case TryStatement t:
                {
                    var branchId = AddBranch("try", incoming);
                    var attempted = ProcessStatement(t.Block, [new(branchId, "try")]);
                    var handled = t.Handler is not null ? ProcessStatement(t.Handler.Body, [new(branchId, "catch")]) : [];
                    var exits = t.Handler is not null ? [.. attempted, .. handled] : attempted;
                    return t.Finalizer is not null ? ProcessStatement(t.Finalizer, exits) : exits;
                }
                case WhileStatement w:
                    return ProcessLoop(Source(w.Test), w.Body, ProcessExpression(w.Test, incoming, null));
                case DoWhileStatement d:
                    return ProcessLoop(Source(d.Test), d.Body, ProcessExpression(d.Test, incoming, null));
                case ForStatement f:
                {
                    var exits = incoming;
                    if (f.Init is VariableDeclaration vd) exits = ProcessVariableDeclaration(vd, exits);
                    else if (f.Init is Expression ie) exits = ProcessExpression(ie, exits, null);
                    if (f.Test is not null) exits = ProcessExpression(f.Test, exits, null);
                    if (f.Update is not null) exits = ProcessExpression(f.Update, exits, null);
                    return ProcessLoop(f.Test is not null ? Source(f.Test) : "for", f.Body, exits);
                }
                case ForInStatement fi: return ProcessLoop(Source(fi.Right), fi.Body, ProcessExpression(fi.Right, incoming, null));
                case ForOfStatement fo: return ProcessLoop(Source(fo.Right), fo.Body, ProcessExpression(fo.Right, incoming, null));
                case ThrowStatement th: return ProcessExpression(th.Argument, incoming, null);
                case LabeledStatement l: return ProcessStatement(l.Body, incoming);
                case WithStatement ws: return ProcessStatement(ws.Body, incoming);
                default: return incoming;
            }
        }

        private List<FlowSource> ProcessLoop(string label, Node body, List<FlowSource> incoming)
        {
            var id = NextId("loop");
            _nodes.Add(new JsonObject { ["id"] = id, ["kind"] = "loop", ["label"] = Truncate(label) });
            Connect(incoming, id);
            var bodyExits = ProcessStatement(body, [new(id, null)]);
            return [new(id, null), .. bodyExits];
        }

        private List<FlowSource> ProcessExpression(Expression expression, List<FlowSource> incoming, Node? assignment)
        {
            var unwrapped = Unwrap(expression);
            if (unwrapped is ConditionalExpression c)
            {
                var tested = ProcessExpression(c.Test, incoming, null);
                var branchId = AddBranch(Source(c.Test), tested);
                var consequent = ProcessExpression(c.Consequent, [new(branchId, "yes")], assignment);
                var alternate = ProcessExpression(c.Alternate, [new(branchId, "no")], assignment);
                return [.. consequent, .. alternate];
            }
            if (PromiseAllElements(unwrapped) is { } parallel) return ProcessParallel(parallel, incoming, assignment);

            var calls = FindToolCalls(unwrapped);
            if (calls.Count == 0) return incoming;
            var outer = AsToolCall(unwrapped);
            var exits = incoming;
            foreach (var found in calls)
            {
                var assignsTo = outer is not null && ReferenceEquals(outer.Call, found.Call) ? (assignment as Identifier)?.Name : null;
                exits = AddCall(found, exits, assignsTo, null);
            }
            return exits;
        }

        private List<FlowSource> ProcessParallel(List<Expression?> elements, List<FlowSource> incoming, Node? assignment)
        {
            var group = $"p{++_parallelCount}";
            var patternElements = assignment is ArrayPattern ap ? ap.Elements.ToList() : [];
            var exits = new List<FlowSource>();
            for (var index = 0; index < elements.Count; index++)
            {
                var element = elements[index];
                if (element is null) continue;
                var calls = FindToolCalls(element);
                if (calls.Count == 0) continue;
                var outer = AsToolCall(Unwrap(element));
                var elementExits = incoming;
                foreach (var found in calls)
                {
                    var assignsTo = outer is not null && ReferenceEquals(outer.Call, found.Call) && index < patternElements.Count ? (patternElements[index] as Identifier)?.Name : null;
                    elementExits = AddCall(found, elementExits, assignsTo, group);
                }
                exits.AddRange(elementExits);
            }
            return exits.Count > 0 ? exits : incoming;
        }

        private List<FlowSource> AddCall(ToolCall found, List<FlowSource> incoming, string? assignsTo, string? parallelGroup)
        {
            var ns = found.Segments[0];
            var tool = string.Join('.', found.Segments.Skip(1));
            if (ns == "$codemode" && tool == "search")
            {
                var sid = NextId("search");
                _nodes.Add(new JsonObject { ["id"] = sid, ["kind"] = "search", ["label"] = "Search capabilities" });
                Connect(incoming, sid);
                return [new(sid, null)];
            }
            var id = NextId("tool");
            _nodes.Add(new JsonObject
            {
                ["id"] = id, ["kind"] = "tool", ["label"] = Truncate(ns + (tool.Length > 0 ? "." + tool : "")), ["namespace"] = ns, ["tool"] = tool,
                ["scriptPath"] = "tools." + string.Join('.', found.Segments), ["assignsTo"] = assignsTo, ["parallelGroup"] = parallelGroup,
            });
            Connect(incoming, id);
            var args = found.Call.Arguments.Cast<Node>().ToList();
            foreach (var identifier in ReferencedIdentifiers(args))
                if (_assignedTools.TryGetValue(identifier, out var source))
                    _edges.Add(new JsonObject { ["from"] = source, ["to"] = id, ["label"] = Truncate(identifier), ["kind"] = "data" });
            if (_inputNodeId is not null)
                foreach (var field in InputFields(args))
                    _edges.Add(new JsonObject { ["from"] = _inputNodeId, ["to"] = id, ["label"] = Truncate($"input.{field}"), ["kind"] = "data" });
            if (assignsTo is not null) _assignedTools[assignsTo] = id;
            return [new(id, null)];
        }

        private string ReturnLabel(Expression? argument)
        {
            if (argument is null) return "return";
            if (argument is ObjectExpression o)
            {
                var fields = o.Properties.Select(p => p is Property prop ? StaticPropertyName(prop.Key) ?? Source(prop.Key) : "…");
                return Truncate($"{{ {string.Join(", ", fields)} }}");
            }
            return Source(argument);
        }
    }

    private static string MermaidLabel(string label) =>
        "\"" + System.Text.RegularExpressions.Regex.Replace(label.Replace("&", "&amp;").Replace("\"", "&quot;"), @"\s+", " ") + "\"";

    public static string ToMermaid(JsonObject graph)
    {
        var lines = new List<string> { "flowchart TD" };
        foreach (var n in graph["nodes"]!.AsArray().Cast<JsonObject>())
        {
            var label = MermaidLabel(n["label"]!.GetValue<string>());
            var id = n["id"]!.GetValue<string>();
            var kind = n["kind"]!.GetValue<string>();
            lines.Add(kind is "branch" or "loop" ? $"  {id}{{{label}}}" : kind is "input" or "return" ? $"  {id}([{label}])" : $"  {id}[{label}]");
        }
        foreach (var e in graph["edges"]!.AsArray().Cast<JsonObject>())
        {
            var arrow = e["kind"]!.GetValue<string>() == "data" ? "-.->" : "-->";
            var label = e["label"] is { } l ? $"|{MermaidLabel(l.GetValue<string>())}|" : "";
            lines.Add($"  {e["from"]!.GetValue<string>()} {arrow}{label} {e["to"]!.GetValue<string>()}");
        }
        return string.Join('\n', lines);
    }

    /// <summary>The same graph with source-derived labels replaced, for people who may run a Workflow but not read its code.</summary>
    public static JsonObject Redact(JsonObject graph)
    {
        var copy = (JsonObject)graph.DeepClone();
        foreach (var n in copy["nodes"]!.AsArray().Cast<JsonObject>())
            switch (n["kind"]!.GetValue<string>())
            {
                case "branch": n["label"] = "Condition"; break;
                case "loop": n["label"] = "Repeat"; break;
                case "return": n["label"] = "Result"; break;
            }
        return copy;
    }
}
