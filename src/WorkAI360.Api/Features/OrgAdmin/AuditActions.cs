namespace WorkAI360.Api.Features.OrgAdmin;

/// <summary>
/// The stable action names of events this build records. They are the reference's names where it has one, so tooling that filters on them
/// keeps working. <see cref="EventTypes"/> is what GET /v1/audit/event-types lists (the reference lists 1,864 names, most for areas not built here).
/// </summary>
public static class AuditActions
{
    public const string SessionCreated = "session.created";
    public const string SessionRevoked = "session.revoked";
    public const string SessionSignInFailed = "session.sign_in_failed";
    public const string MemberRoleUpdated = "member.role_updated";
    public const string MemberOwnershipTransferred = "member.ownership_transferred";
    public const string MemberRemoved = "member.removed";
    public const string InvitationCreated = "invitation.created";
    public const string InvitationRefreshed = "invitation.refreshed";
    public const string InvitationCanceled = "invitation.canceled";
    public const string InvitationAccepted = "invitation.accept.confirmed";
    public const string TeamCreated = "team.create.succeeded";
    public const string TeamUpdated = "team.update.succeeded";
    public const string TeamDeleted = "team.delete.succeeded";
    public const string TeamPermissionSetUpdated = "team.permission_set.update.succeeded";
    public const string PermissionSetCreated = "permission_set.created";
    public const string PermissionSetRenamed = "permission_set.renamed";
    public const string PermissionSetPermissionsChanged = "permission_set.permissions_changed";
    public const string PermissionSetArchived = "permission_set.archived";
    public const string ApiKeyCreated = "api_key.created";
    public const string ApiKeyDeleted = "api_key.deleted";
    public const string ApiKeyRevoked = "api_key.revoked";
    public const string WebOriginApproved = "web_origin.approved";
    public const string WebOriginRemoved = "web_origin.removed";
    public const string OrganizationSettingsUpdated = "organization.settings.update.succeeded";
    public const string OrganizationBrandAssetsUpdated = "organization.brand_assets.update.succeeded";
    public const string CaptureEnabled = "audit.capture.enabled";
    public const string CaptureDisabled = "audit.capture.disabled";
    public const string PolicyInitialized = "audit.policy.initialized";

    /// <summary>Reading audit history is itself recorded (as a requested/served pair), like the reference's audit-read events.</summary>
    public static string Requested(string read) => $"audit.{read}.requested";
    public static string Served(string read) => $"audit.{read}.served";

    public static readonly string[] Reads = ["event_types", "operations", "events", "usage", "export"];

    public static IReadOnlyList<string> EventTypes { get; } = typeof(AuditActions).GetFields()
        .Where(f => f is { IsLiteral: true } && f.FieldType == typeof(string))
        .Select(f => (string)f.GetRawConstantValue()!)
        .Concat(Reads.SelectMany(r => new[] { Requested(r), Served(r) }))
        .Distinct().Order(StringComparer.Ordinal).ToList();
}
