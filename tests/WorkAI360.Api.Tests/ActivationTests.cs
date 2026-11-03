using System.Net;
using System.Text.Json;
using WorkAI360.Api.Domain.Library;
using WorkAI360.Api.Features.Onboarding;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>The "Get set up" checklist: GET /v1/me/activation and POST /v1/me/activation/events.</summary>
public sealed class ActivationTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private static JsonElement Step(JsonElement state, string id) => state.GetProperty("steps").EnumerateArray().Single(s => s.GetProperty("id").GetString() == id);
    private static bool Done(JsonElement state, string id) => Step(state, id).GetProperty("done").GetBoolean();
    private static string? Prop(JsonElement step, string name) => step.TryGetProperty(name, out var v) ? v.GetString() : null;

    private static async Task<JsonElement> StateAsync(Workspace w, Person p)
    {
        var r = await w.SendAsync(w.As(p, HttpMethod.Get, "/v1/me/activation"));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Equal("no-store", r.Headers.CacheControl?.ToString());
        return await ReadJsonAsync(r);
    }

    private static Task<(HttpStatusCode Status, JsonElement Body)> ReportAsync(Workspace w, Person p, object body) => w.CallAsync(p, HttpMethod.Post, "/v1/me/activation/events", body);

    [Fact]
    public async Task A_new_owner_sees_six_open_steps_in_recipe_order()
    {
        var w = await Workspace.CreateAsync(factory, "Fresh Space");
        var state = await StateAsync(w, w.Owner);
        Assert.Equal(["first_response", "invite_teammate", "use_skill", "own_provider", "gateway_provider", "connector"],
            state.GetProperty("steps").EnumerateArray().Select(s => s.GetProperty("id").GetString()!).ToArray());
        Assert.All(state.GetProperty("steps").EnumerateArray(), s => Assert.False(s.GetProperty("done").GetBoolean()));
        Assert.False(state.GetProperty("dismissed").GetBoolean());
        // The owner can do every step, so nothing names someone else.
        Assert.All(state.GetProperty("steps").EnumerateArray(), s => Assert.False(s.TryGetProperty("lockedReason", out _)));
    }

    [Fact]
    public async Task Inviting_checks_off_the_invite_step_with_counts_and_a_member_is_told_who_runs_the_gateway()
    {
        var w = await Workspace.CreateAsync(factory, "Invite Space");
        await w.InviteAsync(NewEmail("pending"));
        var state = await StateAsync(w, w.Owner);
        Assert.True(Done(state, "invite_teammate"));
        Assert.Equal("1 joined, 1 invited", Prop(Step(state, "invite_teammate"), "detail"));

        var member = await w.AddAsync(); // invited by the owner and accepted
        state = await StateAsync(w, w.Owner);
        Assert.Equal("2 joined, 1 invited", Prop(Step(state, "invite_teammate"), "detail"));

        // A member cannot invite: the step counts teammates, and the steps they cannot do name the owner.
        var mine = await StateAsync(w, member);
        Assert.True(Done(mine, "invite_teammate"));
        Assert.Null(Prop(Step(mine, "invite_teammate"), "lockedReason"));
        Assert.Equal("Owner Person manages AI Gateway", Prop(Step(mine, "gateway_provider"), "lockedReason"));
        Assert.Null(Prop(Step(state, "gateway_provider"), "lockedReason"));
    }

    [Fact]
    public async Task Client_reports_check_off_their_steps_once_and_only_for_the_reporter()
    {
        var w = await Workspace.CreateAsync(factory, "Report Space");
        var member = await w.AddAsync();

        var first = await ReportAsync(w, member, new { step = "first_response", durationMs = 2100 });
        Assert.Equal(HttpStatusCode.OK, first.Status);
        Assert.True(Done(first.Body, "first_response"));
        Assert.Equal("Answered in 2.1 s", Prop(Step(first.Body, "first_response"), "detail"));
        // Repeats change nothing: the first report wins.
        var again = await ReportAsync(w, member, new { step = "first_response", durationMs = 99000 });
        Assert.Equal("Answered in 2.1 s", Prop(Step(again.Body, "first_response"), "detail"));

        var provider = await ReportAsync(w, member, new { step = "own_provider" });
        Assert.True(Done(provider.Body, "own_provider"));
        Assert.Equal("Your key, on this device", Prop(Step(provider.Body, "own_provider"), "detail"));
        Assert.True(Done((await ReportAsync(w, member, new { step = "use_skill" })).Body, "use_skill"));
        Assert.True((await ReportAsync(w, member, new { step = "dismiss" })).Body.GetProperty("dismissed").GetBoolean());

        // The owner's checklist is their own.
        var owners = await StateAsync(w, w.Owner);
        Assert.False(Done(owners, "first_response"));
        Assert.False(Done(owners, "use_skill"));
        Assert.False(owners.GetProperty("dismissed").GetBoolean());
    }

    [Fact]
    public async Task A_skill_an_agent_read_through_the_library_counts_as_using_a_skill()
    {
        var w = await Workspace.CreateAsync(factory, "Skill Space");
        var member = await w.AddAsync();
        Assert.False(Done(await StateAsync(w, w.Owner), "use_skill"));
        void Used(string memberId) => factory.WithDb(db =>
        {
            db.Set<LibraryUsageEvent>().Add(new LibraryUsageEvent { Id = Guid.NewGuid().ToString("N"), OrganizationId = w.OrgId, MemberId = memberId, PluginId = "plg_x", ConfigObjectId = "cfg_x", Source = "mcp", CreatedAt = DateTime.UtcNow });
            return db.SaveChanges();
        });
        // A teammate's skill use is theirs, not the owner's.
        Used(member.MemberId);
        Assert.False(Done(await StateAsync(w, w.Owner), "use_skill"));
        Assert.True(Done(await StateAsync(w, member), "use_skill"));
        Used(w.Owner.MemberId);
        Assert.True(Done(await StateAsync(w, w.Owner), "use_skill"));
    }

    [Fact]
    public async Task A_provider_someone_added_checks_off_the_provider_step_for_them_and_their_teammates()
    {
        var w = await Workspace.CreateAsync(factory, "Provider Space");
        var member = await w.AddAsync();
        Assert.False(Done(await StateAsync(w, member), "own_provider"));
        var created = await w.CallAsync(member, HttpMethod.Post, "/v1/llm-providers",
            new { name = "My OpenAI", source = "models_dev", providerId = "openai", modelIds = new[] { "gpt-4o" }, apiKey = "sk-x" });
        Assert.Equal(HttpStatusCode.Created, created.Status);
        var mine = Step(await StateAsync(w, member), "own_provider");
        Assert.True(mine.GetProperty("done").GetBoolean());
        Assert.Equal("My OpenAI added", Prop(mine, "detail"));
        var owners = Step(await StateAsync(w, w.Owner), "own_provider");
        Assert.True(owners.GetProperty("done").GetBoolean());
        Assert.Equal("Models from your organization", Prop(owners, "detail"));
    }

    [Fact]
    public async Task Reports_are_validated_strictly_and_need_a_signed_in_member()
    {
        var w = await Workspace.CreateAsync(factory, "Strict Space");
        foreach (var (body, expected) in new (object Body, string Message)[]
        {
            (new { step = "invite_teammate" }, "step: Invalid option: expected one of \"first_response\"|\"use_skill\"|\"own_provider\"|\"dismiss\""),
            (new { }, "step: Invalid option: expected one of \"first_response\"|\"use_skill\"|\"own_provider\"|\"dismiss\""),
            (new { step = "first_response", durationMs = -1 }, "durationMs: Too small: expected number to be >=0"),
            (new { step = "first_response", durationMs = 1.5 }, "durationMs: Invalid input: expected int, received number"),
            (new { step = "first_response", durationMs = 86_400_001 }, "durationMs: Too big: expected number to be <=86400000"),
            (new { step = "first_response", durationMs = "fast" }, "durationMs: Invalid input: expected number, received string"),
            (new { step = "dismiss", extra = true }, "Unrecognized key: \"extra\""),
        })
        {
            var r = await ReportAsync(w, w.Owner, body);
            Assert.Equal(HttpStatusCode.BadRequest, r.Status);
            Assert.Equal("invalid_request", r.Body.GetProperty("error").GetString());
            Assert.Equal(expected, r.Body.GetProperty("message").GetString());
        }
        Assert.False(Done(await StateAsync(w, w.Owner), "first_response"));
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.GetAsync("/v1/me/activation")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.PostAsync("/v1/me/activation/events", null)).StatusCode);
    }

    [Theory]
    [InlineData(2100, "Answered in 2.1 s")]
    [InlineData(0, "Answered in 0.0 s")]
    [InlineData(9940, "Answered in 9.9 s")]
    [InlineData(12345, "Answered in 12 s")]
    [InlineData(12500, "Answered in 13 s")]
    public void Answer_times_read_like_the_reference(int ms, string expected) => Assert.Equal(expected, Activation.AnsweredIn(ms));
}
