using System.Text.Json.Nodes;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Domain.Sso;

namespace WorkAI360.Api.Features.OrgAdmin;

/// <summary>
/// Change events with before/after snapshots for areas built after the audit log (the reference's <c>audit/domain/*.ts</c>). Snapshots carry an
/// allowlist of fields: never client secrets, keys, certificates, tokens, configuration hashes or free text from an identity provider. A change
/// to secret material is an opaque marker (<c>configuration</c>, <c>credentialMaterial</c>) in <c>changedFields</c>, never its value.
/// </summary>
public static class DomainAuditEvents
{
    public const string SsoRegistered = "sso_connection.registered";
    public const string SsoEnabled = "sso_connection.enabled";
    public const string SsoDisabled = "sso_connection.disabled";
    public const string SsoDeleted = "sso_connection.deleted";
    public const string ScimTokenRotated = "scim_connection.token_rotated";
    public const string ScimDeleted = "scim_connection.deleted";
    public const string ScimReconciled = "scim_connection.reconciled";
    public const string ScimGroupMappingUpdated = "scim_group_mapping.updated";
    public const string ProfileUpdated = "account.profile_updated";
    public const string AgentPermissionPolicyUpdated = "agent_permission_policy.updated";
    public const string AgentPermissionPolicyRemoved = "agent_permission_policy.removed";

    public static readonly string[] All =
        [SsoRegistered, SsoEnabled, SsoDisabled, SsoDeleted, ScimTokenRotated, ScimDeleted, ScimReconciled, ScimGroupMappingUpdated, ProfileUpdated,
         AgentPermissionPolicyUpdated, AgentPermissionPolicyRemoved];

    private static string? Text(string? value, int max = 255) => value is null ? null : value.Length <= max ? value : value[..max];

    public static JsonObject Sso(SsoConnection c) => new()
    {
        ["id"] = c.Id, ["providerId"] = Text(c.ProviderId), ["kind"] = Text(c.Kind, 16), ["issuer"] = Text(c.Issuer, 2048), ["domain"] = Text(c.Domain),
        ["status"] = Text(c.Status, 32), ["signInPath"] = Text(c.SignInPath, 2048), ["testStatus"] = Text(c.TestStatus, 32),
        ["lastTestedAt"] = c.LastTestedAt is { } t ? Responses.IsoUtc(t) : null, ["domainVerified"] = c.DomainVerified,
    };

    private static AuditResource[] SsoResources(string organizationId, string id) => [new("sso_connection", id), new("organization", organizationId, "parent")];

    /// <summary>A re-registration replaces the identity provider configuration: recorded as the <c>configuration</c> marker.</summary>
    public static AuditEntry SsoRegisteredEntry(string organizationId, JsonObject? before, SsoConnection after) =>
        new(SsoRegistered, SsoResources(organizationId, after.Id), Before: before, After: before is null ? Sso(after) : WithMarker(Sso(after), "configuration"));

    public static AuditEntry? SsoStatusEntry(string organizationId, JsonObject before, SsoConnection after) =>
        before["status"]?.GetValue<string>() == after.Status ? null
            : new(after.Status == "enabled" ? SsoEnabled : SsoDisabled, SsoResources(organizationId, after.Id), Before: before, After: Sso(after));

    public static AuditEntry SsoDeletedEntry(string organizationId, JsonObject before, string id) => new(SsoDeleted, SsoResources(organizationId, id), Before: before);

    public static JsonObject Scim(ScimProvider p) => new()
    {
        ["id"] = p.Id, ["providerId"] = Text(p.ProviderId), ["groupMappingMode"] = Text(p.GroupMappingMode, 32), ["createdAt"] = Responses.IsoUtc(p.CreatedAt),
    };

    private static AuditResource[] ScimResources(string organizationId, string id) => [new("scim_connection", id), new("organization", organizationId, "parent")];

    /// <summary>The token is never read into evidence: rotation is the <c>credentialMaterial</c> marker. <paramref name="before"/> is null when this created the connector.</summary>
    public static AuditEntry ScimTokenRotatedEntry(string organizationId, JsonObject? before, ScimProvider after) =>
        new(ScimTokenRotated, ScimResources(organizationId, after.Id), Before: before, After: WithMarker(Scim(after), "credentialMaterial"));

    public static AuditEntry ScimDeletedEntry(string organizationId, ScimProvider before) => new(ScimDeleted, ScimResources(organizationId, before.Id), Before: Scim(before));

    public static AuditEntry? ScimGroupMappingEntry(string organizationId, ScimProvider before, string nextMode) =>
        before.GroupMappingMode == nextMode ? null
            : new(ScimGroupMappingUpdated, ScimResources(organizationId, before.Id),
                Before: new JsonObject { ["groupMappingMode"] = before.GroupMappingMode }, After: new JsonObject { ["groupMappingMode"] = nextMode });

    /// <summary>A reconciliation run is system work: execution category, counts only.</summary>
    public static AuditEntry ScimReconciledEntry(string organizationId, string? connectionId, int checkedCount, int repaired, int failures) =>
        new(ScimReconciled, [new("scim_connection", connectionId ?? "collection:scim_connection"), new("organization", organizationId, "parent")], "execution",
            After: new JsonObject { ["checked"] = checkedCount, ["repaired"] = repaired, ["failures"] = failures });

    /// <summary>The display name before and after; an image change is the <c>image</c> marker. Nothing when nothing changed.</summary>
    public static AuditEntry? ProfileUpdatedEntry(string userId, string beforeName, string afterName, bool imageChanged)
    {
        if (beforeName == afterName && !imageChanged) return null;
        var before = new JsonObject { ["name"] = Text(beforeName) };
        var after = new JsonObject { ["name"] = Text(afterName) };
        if (imageChanged) { before["image"] = "[changed]"; after["image"] = "[changed]"; }
        return new(ProfileUpdated, [new("user", userId)], Before: before, After: after);
    }

    public static AuditEntry AgentPermissionPolicyEntry(string organizationId, string scope, string? teamId, JsonObject? before, JsonObject? after) =>
        new(after is null ? AgentPermissionPolicyRemoved : AgentPermissionPolicyUpdated,
            [new("agent_permission_policy", teamId is null ? $"{organizationId}:everyone" : $"{organizationId}:team:{teamId}"), new("organization", organizationId, "parent"),
             .. teamId is null ? Array.Empty<AuditResource>() : [new AuditResource("team", teamId, "related")]],
            Before: before, After: after is null ? null : (JsonObject)after.DeepClone() is var a ? Scoped(a, scope) : null);

    private static JsonObject Scoped(JsonObject o, string scope) { o["scope"] = scope; return o; }

    private static JsonObject WithMarker(JsonObject after, string marker) { after[marker] = "[changed]"; return after; }
}
