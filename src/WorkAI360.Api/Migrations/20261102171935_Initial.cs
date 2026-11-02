using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace WorkAI360.Api.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterDatabase()
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "AdminAllowlistEntry",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Email = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Note = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AdminAllowlistEntry", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "ApiKey",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    MemberId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    UserId = table.Column<string>(type: "longtext", nullable: false),
                    Name = table.Column<string>(type: "longtext", nullable: false),
                    Prefix = table.Column<string>(type: "longtext", nullable: false),
                    Start = table.Column<string>(type: "longtext", nullable: false),
                    KeyHash = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Enabled = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    RateLimitEnabled = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    RateLimitMax = table.Column<int>(type: "int", nullable: false),
                    RateLimitTimeWindow = table.Column<int>(type: "int", nullable: false),
                    LastRequestAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    ExpiresAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ApiKey", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "AuditEvent",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OperationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Action = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    RequestId = table.Column<string>(type: "longtext", nullable: true),
                    RecordedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    EnvelopeJson = table.Column<string>(type: "longtext", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditEvent", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "AuditEventResource",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OperationId = table.Column<string>(type: "longtext", nullable: false),
                    EventId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ResourceType = table.Column<string>(type: "longtext", nullable: false),
                    ResourceId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Relationship = table.Column<string>(type: "longtext", nullable: false),
                    Label = table.Column<string>(type: "longtext", nullable: true),
                    Position = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditEventResource", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "AuditOperation",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Kind = table.Column<string>(type: "longtext", nullable: false),
                    Scope = table.Column<string>(type: "longtext", nullable: false),
                    Origin = table.Column<string>(type: "longtext", nullable: false),
                    OriginTrust = table.Column<string>(type: "longtext", nullable: false),
                    InitiatingActorJson = table.Column<string>(type: "longtext", nullable: false),
                    InitiatingActorType = table.Column<string>(type: "longtext", nullable: true),
                    InitiatingActorId = table.Column<string>(type: "longtext", nullable: true),
                    FirstRecordedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    Outcome = table.Column<string>(type: "longtext", nullable: false),
                    EventCount = table.Column<int>(type: "int", nullable: false),
                    LogicalBytes = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditOperation", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "AuditPolicy",
                columns: table => new
                {
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Revision = table.Column<int>(type: "int", nullable: false),
                    Source = table.Column<string>(type: "longtext", nullable: false),
                    Enabled = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    CategoriesJson = table.Column<string>(type: "longtext", nullable: false),
                    Allowance = table.Column<long>(type: "bigint", nullable: false),
                    ExcessMode = table.Column<string>(type: "longtext", nullable: false),
                    EffectiveAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    CaptureStartedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    AttachmentWindowSeconds = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditPolicy", x => x.OrganizationId);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "AuthorizationCodes",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ClientId = table.Column<string>(type: "longtext", nullable: false),
                    UserId = table.Column<string>(type: "longtext", nullable: false),
                    OrganizationId = table.Column<string>(type: "longtext", nullable: false),
                    RedirectUri = table.Column<string>(type: "longtext", nullable: false),
                    Scope = table.Column<string>(type: "longtext", nullable: false),
                    Resource = table.Column<string>(type: "longtext", nullable: false),
                    CodeChallenge = table.Column<string>(type: "longtext", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    ConsumedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuthorizationCodes", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "BrandAsset",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(192)", maxLength: 192, nullable: false),
                    Kind = table.Column<string>(type: "varchar(192)", maxLength: 192, nullable: false),
                    Version = table.Column<string>(type: "varchar(192)", maxLength: 192, nullable: false),
                    Extension = table.Column<string>(type: "varchar(192)", maxLength: 192, nullable: false),
                    Bytes = table.Column<byte[]>(type: "longblob", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BrandAsset", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "ConfigObject",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ObjectType = table.Column<string>(type: "longtext", nullable: false),
                    SourceMode = table.Column<string>(type: "longtext", nullable: false),
                    Title = table.Column<string>(type: "longtext", nullable: false),
                    Description = table.Column<string>(type: "longtext", nullable: true),
                    SearchText = table.Column<string>(type: "longtext", nullable: true),
                    CurrentRelativePath = table.Column<string>(type: "longtext", nullable: true),
                    Status = table.Column<string>(type: "longtext", nullable: false),
                    CreatedByMemberId = table.Column<string>(type: "longtext", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    DeletedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ConfigObject", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "ConfigObjectVersion",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "longtext", nullable: false),
                    ConfigObjectId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    NormalizedPayloadJson = table.Column<string>(type: "longtext", nullable: true),
                    RawSourceText = table.Column<string>(type: "longtext", nullable: true),
                    SchemaVersion = table.Column<string>(type: "longtext", nullable: true),
                    CreatedVia = table.Column<string>(type: "longtext", nullable: false),
                    CreatedByMemberId = table.Column<string>(type: "longtext", nullable: true),
                    SourceRevisionRef = table.Column<string>(type: "longtext", nullable: true),
                    IsDeletedVersion = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ConfigObjectVersion", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "ConnectedAccount",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "longtext", nullable: false),
                    MemberId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ConnectionId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    AccessTokenEnc = table.Column<string>(type: "longtext", nullable: true),
                    RefreshTokenEnc = table.Column<string>(type: "longtext", nullable: true),
                    TokenType = table.Column<string>(type: "longtext", nullable: true),
                    Scopes = table.Column<string>(type: "longtext", nullable: true),
                    ExpiresAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    ReadinessJson = table.Column<string>(type: "longtext", nullable: true),
                    CredentialHealthJson = table.Column<string>(type: "longtext", nullable: true),
                    ConnectedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ConnectedAccount", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "ConnectionAccessGrant",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "longtext", nullable: false),
                    ConnectionId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    MemberId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    TeamId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    OrgWide = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    CreatedByMemberId = table.Column<string>(type: "longtext", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ConnectionAccessGrant", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "ConnectionOAuthClient",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ConnectionId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ClientId = table.Column<string>(type: "longtext", nullable: false),
                    ClientSecretEnc = table.Column<string>(type: "longtext", nullable: true),
                    RegistrationSource = table.Column<string>(type: "longtext", nullable: false),
                    TokenEndpointAuthMethod = table.Column<string>(type: "longtext", nullable: true),
                    Issuer = table.Column<string>(type: "longtext", nullable: true),
                    CreatedByMemberId = table.Column<string>(type: "longtext", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ConnectionOAuthClient", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "ConnectionOAuthTransaction",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "longtext", nullable: false),
                    ConnectionId = table.Column<string>(type: "longtext", nullable: false),
                    MemberId = table.Column<string>(type: "longtext", nullable: false),
                    CodeVerifierEnc = table.Column<string>(type: "longtext", nullable: false),
                    RedirectUri = table.Column<string>(type: "longtext", nullable: false),
                    TokenEndpoint = table.Column<string>(type: "longtext", nullable: false),
                    Issuer = table.Column<string>(type: "longtext", nullable: false),
                    Resource = table.Column<string>(type: "longtext", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ConnectionOAuthTransaction", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "DesktopPolicy",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ExternalKey = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    PolicyName = table.Column<string>(type: "longtext", nullable: false),
                    IsDefault = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    IsEnabled = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    Priority = table.Column<int>(type: "int", nullable: false),
                    PolicyJson = table.Column<string>(type: "longtext", nullable: false),
                    CreatedByMemberId = table.Column<string>(type: "longtext", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    DeletedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    DefaultKey = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DesktopPolicy", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "DesktopStartupReport",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    MemberId = table.Column<string>(type: "longtext", nullable: false),
                    AttemptId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    AppVersion = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                    Platform = table.Column<string>(type: "varchar(16)", maxLength: 16, nullable: false),
                    Success = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    FailedStep = table.Column<string>(type: "longtext", nullable: true),
                    FailureReason = table.Column<string>(type: "longtext", nullable: true),
                    WindowMs = table.Column<int>(type: "int", nullable: true),
                    EngineMs = table.Column<int>(type: "int", nullable: true),
                    SignedInMs = table.Column<int>(type: "int", nullable: true),
                    OrgToolsMs = table.Column<int>(type: "int", nullable: true),
                    ObservedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DesktopStartupReport", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "DeviceCodes",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    DeviceCodeHash = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    UserCode = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ClientId = table.Column<string>(type: "longtext", nullable: false),
                    Status = table.Column<string>(type: "longtext", nullable: false),
                    UserId = table.Column<string>(type: "longtext", nullable: true),
                    OrganizationId = table.Column<string>(type: "longtext", nullable: true),
                    ExpiresAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    LastPolledAt = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeviceCodes", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "EgressDiagnosticCredential",
                columns: table => new
                {
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    TokenCipher = table.Column<string>(type: "longtext", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EgressDiagnosticCredential", x => x.OrganizationId);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "EmailOtps",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Email = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Type = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    CodeHash = table.Column<string>(type: "longtext", nullable: false),
                    Attempts = table.Column<int>(type: "int", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EmailOtps", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "ExternalAccount",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    UserId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ProviderId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    AccountId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ExternalAccount", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "ExternalIdentity",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    UserId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Source = table.Column<string>(type: "longtext", nullable: false),
                    SsoProviderId = table.Column<string>(type: "longtext", nullable: true),
                    ScimProviderId = table.Column<string>(type: "longtext", nullable: true),
                    RemoteId = table.Column<string>(type: "longtext", nullable: true),
                    ExternalId = table.Column<string>(type: "longtext", nullable: true),
                    UserName = table.Column<string>(type: "longtext", nullable: true),
                    Email = table.Column<string>(type: "longtext", nullable: true),
                    DisplayName = table.Column<string>(type: "longtext", nullable: true),
                    Active = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    LastSsoLoginAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    LastScimSyncAt = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ExternalIdentity", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "ExternalMcpConnection",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Name = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ExternalKey = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    Url = table.Column<string>(type: "varchar(2048)", maxLength: 2048, nullable: false),
                    AuthType = table.Column<string>(type: "longtext", nullable: false),
                    CredentialMode = table.Column<string>(type: "longtext", nullable: false),
                    ExposeDirectly = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    ApiKeyAuthScheme = table.Column<string>(type: "longtext", nullable: false),
                    ApiKeyEnc = table.Column<string>(type: "longtext", nullable: true),
                    RequestHeadersEnc = table.Column<string>(type: "longtext", nullable: true),
                    AccessTokenEnc = table.Column<string>(type: "longtext", nullable: true),
                    RefreshTokenEnc = table.Column<string>(type: "longtext", nullable: true),
                    TokenType = table.Column<string>(type: "longtext", nullable: true),
                    Scope = table.Column<string>(type: "longtext", nullable: true),
                    ExpiresAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    OAuthConfigJson = table.Column<string>(type: "longtext", nullable: true),
                    ToolPolicyJson = table.Column<string>(type: "longtext", nullable: true),
                    ReadinessJson = table.Column<string>(type: "longtext", nullable: true),
                    CredentialHealthJson = table.Column<string>(type: "longtext", nullable: true),
                    ConnectedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    CreatedByMemberId = table.Column<string>(type: "longtext", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ExternalMcpConnection", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "HandoffGrants",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    UserId = table.Column<string>(type: "longtext", nullable: false),
                    OrganizationId = table.Column<string>(type: "longtext", nullable: true),
                    ExpiresAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    ConsumedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_HandoffGrants", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "Invitations",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Email = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Role = table.Column<string>(type: "longtext", nullable: false),
                    Status = table.Column<string>(type: "longtext", nullable: false),
                    InviteToken = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    InvitedByUserId = table.Column<string>(type: "longtext", nullable: false),
                    PlaceholderMemberId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    AcceptedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    AcceptedByUserId = table.Column<string>(type: "longtext", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Invitations", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "LibraryGrant",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ResourceKind = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ResourceId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    SubjectKey = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    MemberId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    TeamId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    OrgWide = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    Role = table.Column<string>(type: "longtext", nullable: false),
                    CreatedByMemberId = table.Column<string>(type: "longtext", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    RemovedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LibraryGrant", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "LibraryUsageEvent",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    MemberId = table.Column<string>(type: "longtext", nullable: false),
                    PluginId = table.Column<string>(type: "longtext", nullable: false),
                    ConfigObjectId = table.Column<string>(type: "longtext", nullable: false),
                    Source = table.Column<string>(type: "longtext", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LibraryUsageEvent", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "Marketplace",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ExternalKey = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    Name = table.Column<string>(type: "longtext", nullable: false),
                    Description = table.Column<string>(type: "longtext", nullable: true),
                    LogoUrl = table.Column<string>(type: "longtext", nullable: true),
                    Status = table.Column<string>(type: "longtext", nullable: false),
                    CreatedByMemberId = table.Column<string>(type: "longtext", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    DeletedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Marketplace", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "MarketplacePlugin",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "longtext", nullable: false),
                    MarketplaceId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    PluginId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    MembershipSource = table.Column<string>(type: "longtext", nullable: false),
                    CreatedByMemberId = table.Column<string>(type: "longtext", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    RemovedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MarketplacePlugin", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "McpAccessTokens",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Kind = table.Column<string>(type: "longtext", nullable: false),
                    UserId = table.Column<string>(type: "longtext", nullable: false),
                    OrganizationId = table.Column<string>(type: "longtext", nullable: false),
                    Scope = table.Column<string>(type: "longtext", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_McpAccessTokens", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "Members",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    UserId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Role = table.Column<string>(type: "longtext", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    JoinedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    InviteId = table.Column<string>(type: "longtext", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Members", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "OAuthClients",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Name = table.Column<string>(type: "longtext", nullable: false),
                    RedirectUrisJson = table.Column<string>(type: "longtext", nullable: false),
                    Scope = table.Column<string>(type: "longtext", nullable: false),
                    AuthMethod = table.Column<string>(type: "longtext", nullable: false),
                    SecretHash = table.Column<string>(type: "longtext", nullable: true),
                    LogoUri = table.Column<string>(type: "longtext", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    MetadataFetchedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OAuthClients", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "OAuthConsents",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ClientId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    UserId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Scope = table.Column<string>(type: "longtext", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OAuthConsents", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "OidcClientSettings",
                columns: table => new
                {
                    ClientId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    EnableEndSession = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    PostLogoutRedirectUrisJson = table.Column<string>(type: "longtext", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OidcClientSettings", x => x.ClientId);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "OidcGrant",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ClientId = table.Column<string>(type: "longtext", nullable: false),
                    UserId = table.Column<string>(type: "longtext", nullable: false),
                    Nonce = table.Column<string>(type: "varchar(512)", maxLength: 512, nullable: true),
                    AuthTime = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    SessionId = table.Column<string>(type: "longtext", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OidcGrant", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "OnboardingRateLimit",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Key = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Count = table.Column<int>(type: "int", nullable: false),
                    WindowStart = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OnboardingRateLimit", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "Organizations",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Name = table.Column<string>(type: "longtext", nullable: false),
                    Slug = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Organizations", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "OrganizationSettings",
                columns: table => new
                {
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    AllowedEmailDomainsJson = table.Column<string>(type: "longtext", nullable: true),
                    MetadataJson = table.Column<string>(type: "longtext", nullable: true),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OrganizationSettings", x => x.OrganizationId);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "OrganizationWebOrigin",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Origin = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    CreatedByMemberId = table.Column<string>(type: "longtext", nullable: true),
                    CreatedByName = table.Column<string>(type: "longtext", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OrganizationWebOrigin", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "OrgPolicySettings",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    DesktopAutomations = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    CloudAutomations = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    WorkbotModel = table.Column<string>(type: "longtext", nullable: true),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OrgPolicySettings", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "PasswordResetTokens",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    UserId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    RedirectTo = table.Column<string>(type: "longtext", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    ConsumedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PasswordResetTokens", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "PermissionSetPermissions",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    PermissionSetId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    PermissionKey = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Status = table.Column<string>(type: "longtext", nullable: false),
                    Source = table.Column<string>(type: "longtext", nullable: false),
                    ChangedByMemberId = table.Column<string>(type: "longtext", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PermissionSetPermissions", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "PermissionSets",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    DefaultKey = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    Name = table.Column<string>(type: "longtext", nullable: false),
                    CreatedByMemberId = table.Column<string>(type: "longtext", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    ArchivedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PermissionSets", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "PermissionSetTeams",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    PermissionSetId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    TeamId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    RemovedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    ActiveTeamId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PermissionSetTeams", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "PlatformFeatureChange",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    FeatureKey = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                    Scope = table.Column<string>(type: "longtext", nullable: false),
                    Action = table.Column<string>(type: "longtext", nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    ChangedByUserId = table.Column<string>(type: "longtext", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PlatformFeatureChange", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "PlatformFeatureRollout",
                columns: table => new
                {
                    FeatureKey = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                    Enabled = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    Killed = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    UpdatedByUserId = table.Column<string>(type: "longtext", nullable: true),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PlatformFeatureRollout", x => x.FeatureKey);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "PlatformOrganization",
                columns: table => new
                {
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    PlanTier = table.Column<string>(type: "varchar(16)", maxLength: 16, nullable: true),
                    PlanSeats = table.Column<int>(type: "int", nullable: true),
                    PlanEndsAt = table.Column<string>(type: "varchar(10)", maxLength: 10, nullable: true),
                    SeatLimit = table.Column<int>(type: "int", nullable: false),
                    SeatsFreeAdditional = table.Column<int>(type: "int", nullable: false),
                    DpaSigned = table.Column<bool>(type: "tinyint(1)", nullable: true),
                    ComplimentaryWebAccess = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PlatformOrganization", x => x.OrganizationId);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "PlatformOrganizationFeature",
                columns: table => new
                {
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    FeatureKey = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                    Enabled = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    SetByUserId = table.Column<string>(type: "longtext", nullable: true),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PlatformOrganizationFeature", x => new { x.OrganizationId, x.FeatureKey });
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "Plugin",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Name = table.Column<string>(type: "longtext", nullable: false),
                    Description = table.Column<string>(type: "longtext", nullable: true),
                    SourceRepositoryUrl = table.Column<string>(type: "longtext", nullable: true),
                    SourceFormat = table.Column<string>(type: "longtext", nullable: true),
                    SourceSchemaVersion = table.Column<string>(type: "longtext", nullable: true),
                    Status = table.Column<string>(type: "longtext", nullable: false),
                    CreatedByMemberId = table.Column<string>(type: "longtext", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    DeletedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    ActiveKey = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Plugin", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "PluginConfigObject",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "longtext", nullable: false),
                    PluginId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ConfigObjectId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    MembershipSource = table.Column<string>(type: "longtext", nullable: false),
                    CreatedByMemberId = table.Column<string>(type: "longtext", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    RemovedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PluginConfigObject", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "RefreshTokens",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    FamilyId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    CodeHash = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    ClientId = table.Column<string>(type: "longtext", nullable: false),
                    UserId = table.Column<string>(type: "longtext", nullable: false),
                    OrganizationId = table.Column<string>(type: "longtext", nullable: false),
                    Scope = table.Column<string>(type: "longtext", nullable: false),
                    Resource = table.Column<string>(type: "longtext", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    RotatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    RevokedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RefreshTokens", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "ScimGroup",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ProviderId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ExternalId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    DisplayName = table.Column<string>(type: "longtext", nullable: false),
                    TeamId = table.Column<string>(type: "longtext", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScimGroup", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "ScimGroupMember",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    GroupId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "longtext", nullable: false),
                    ProviderId = table.Column<string>(type: "longtext", nullable: false),
                    RemoteUserId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    MemberId = table.Column<string>(type: "longtext", nullable: true),
                    TeamMemberId = table.Column<string>(type: "longtext", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScimGroupMember", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "ScimProvider",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ProviderId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    TokenHash = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    CreatedByUserId = table.Column<string>(type: "longtext", nullable: true),
                    GroupMappingMode = table.Column<string>(type: "longtext", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScimProvider", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "ScimSyncEvent",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ProviderId = table.Column<string>(type: "longtext", nullable: false),
                    UserId = table.Column<string>(type: "longtext", nullable: true),
                    Action = table.Column<string>(type: "longtext", nullable: false),
                    Status = table.Column<string>(type: "longtext", nullable: false),
                    Attempts = table.Column<int>(type: "int", nullable: false),
                    LastError = table.Column<string>(type: "longtext", nullable: true),
                    PayloadJson = table.Column<string>(type: "longtext", nullable: true),
                    NextRetryAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    ResolvedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScimSyncEvent", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "ScimUserTombstone",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ProviderId = table.Column<string>(type: "longtext", nullable: false),
                    DeprovisionedUserId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ExternalId = table.Column<string>(type: "longtext", nullable: true),
                    Email = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    DeprovisionedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScimUserTombstone", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "Sessions",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    TokenHash = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    UserId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ActiveOrganizationId = table.Column<string>(type: "longtext", nullable: true),
                    Method = table.Column<string>(type: "longtext", nullable: false),
                    IpAddress = table.Column<string>(type: "longtext", nullable: true),
                    UserAgent = table.Column<string>(type: "longtext", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Sessions", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "SigningKeys",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    X = table.Column<string>(type: "longtext", nullable: false),
                    Y = table.Column<string>(type: "longtext", nullable: false),
                    ProtectedPrivate = table.Column<string>(type: "longtext", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    RetiredAt = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SigningKeys", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "SocialAuthState",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Provider = table.Column<string>(type: "longtext", nullable: false),
                    BrowserBindingHash = table.Column<string>(type: "longtext", nullable: false),
                    NonceHash = table.Column<string>(type: "longtext", nullable: true),
                    CodeVerifierProtected = table.Column<string>(type: "longtext", nullable: false),
                    CallbackUrl = table.Column<string>(type: "longtext", nullable: false),
                    ErrorCallbackUrl = table.Column<string>(type: "longtext", nullable: true),
                    NewUserCallbackUrl = table.Column<string>(type: "longtext", nullable: true),
                    RequestSignUp = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    ConsumedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SocialAuthState", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "SsoAuthState",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ProviderId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ConfigRevision = table.Column<string>(type: "longtext", nullable: false),
                    BrowserBindingHash = table.Column<string>(type: "longtext", nullable: false),
                    NonceHash = table.Column<string>(type: "longtext", nullable: false),
                    CodeVerifierProtected = table.Column<string>(type: "longtext", nullable: false),
                    CallbackUrl = table.Column<string>(type: "longtext", nullable: false),
                    ErrorCallbackUrl = table.Column<string>(type: "longtext", nullable: true),
                    NewUserCallbackUrl = table.Column<string>(type: "longtext", nullable: true),
                    TestIntentId = table.Column<string>(type: "longtext", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    ConsumedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SsoAuthState", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "SsoConnection",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ProviderId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Kind = table.Column<string>(type: "longtext", nullable: false),
                    Issuer = table.Column<string>(type: "longtext", nullable: false),
                    Domain = table.Column<string>(type: "longtext", nullable: false),
                    Status = table.Column<string>(type: "longtext", nullable: false),
                    SignInPath = table.Column<string>(type: "longtext", nullable: false),
                    ConfigRevision = table.Column<string>(type: "longtext", nullable: false),
                    TestStatus = table.Column<string>(type: "longtext", nullable: false),
                    LastTestedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    LastTestedRevision = table.Column<string>(type: "longtext", nullable: true),
                    LastError = table.Column<string>(type: "longtext", nullable: true),
                    DomainVerified = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    DomainVerificationToken = table.Column<string>(type: "longtext", nullable: true),
                    DomainVerificationExpiresAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    OidcConfigJson = table.Column<string>(type: "longtext", nullable: true),
                    ClientSecretProtected = table.Column<string>(type: "longtext", nullable: true),
                    SamlConfigJson = table.Column<string>(type: "longtext", nullable: true),
                    ActiveTestIntentId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    ActiveTestUserId = table.Column<string>(type: "longtext", nullable: true),
                    ActiveTestProviderId = table.Column<string>(type: "longtext", nullable: true),
                    ActiveTestConfigRevision = table.Column<string>(type: "longtext", nullable: true),
                    ActiveTestExpiresAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    ActiveTestStartedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SsoConnection", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "TeamMembers",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    TeamId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    MemberId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TeamMembers", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "Teams",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Name = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    GrantsOrganizationAdmin = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Teams", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Email = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Name = table.Column<string>(type: "longtext", nullable: false),
                    EmailVerified = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    Image = table.Column<string>(type: "longtext", nullable: true),
                    PasswordHash = table.Column<string>(type: "longtext", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "WorkspaceBootstrap",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    SetupMemberId = table.Column<string>(type: "longtext", nullable: false),
                    AgentUserId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Status = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    AssertionJti = table.Column<string>(type: "longtext", nullable: false),
                    DeviceKeyFingerprint = table.Column<string>(type: "longtext", nullable: true),
                    OwnerEmail = table.Column<string>(type: "longtext", nullable: true),
                    TeammateEmailsJson = table.Column<string>(type: "longtext", nullable: true),
                    ExpiresAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    ClaimedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    CredentialsRevokedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WorkspaceBootstrap", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "WorkspaceClaim",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    BootstrapId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "longtext", nullable: false),
                    TokenHash = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Role = table.Column<string>(type: "longtext", nullable: false),
                    Status = table.Column<string>(type: "longtext", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    ClaimedByUserId = table.Column<string>(type: "longtext", nullable: true),
                    ClaimedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WorkspaceClaim", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "WorkspaceClaimCode",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    BootstrapId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "longtext", nullable: false),
                    CodeHash = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    State = table.Column<string>(type: "longtext", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    ClaimedByUserId = table.Column<string>(type: "longtext", nullable: true),
                    AcceptedAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    ReconciledAt = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WorkspaceClaimCode", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "Automation",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OwnerMemberId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Name = table.Column<string>(type: "varchar(120)", maxLength: 120, nullable: false),
                    State = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    CurrentRevisionId = table.Column<string>(type: "longtext", nullable: false),
                    NextDueAt = table.Column<long>(type: "bigint", nullable: true),
                    LatestRunAt = table.Column<long>(type: "bigint", nullable: true),
                    LatestSuccessfulRunId = table.Column<string>(type: "longtext", nullable: true),
                    LatestSuccessfulResultJson = table.Column<string>(type: "longtext", nullable: true),
                    NeedsAttentionJson = table.Column<string>(type: "longtext", nullable: true),
                    CreatedAt = table.Column<long>(type: "bigint", nullable: false),
                    UpdatedAt = table.Column<long>(type: "bigint", nullable: false),
                    ArchivedAt = table.Column<long>(type: "bigint", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Automation", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Automation_Organizations_OrganizationId",
                        column: x => x.OrganizationId,
                        principalTable: "Organizations",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "AutomationRunner",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OwnerMemberId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    InstallId = table.Column<string>(type: "longtext", nullable: false),
                    ProtocolVersion = table.Column<int>(type: "int", nullable: false),
                    CapabilitiesJson = table.Column<string>(type: "longtext", nullable: false),
                    AppVersion = table.Column<string>(type: "longtext", nullable: false),
                    Platform = table.Column<string>(type: "longtext", nullable: false),
                    Concurrency = table.Column<int>(type: "int", nullable: false),
                    LastSeenAt = table.Column<long>(type: "bigint", nullable: false),
                    CreatedAt = table.Column<long>(type: "bigint", nullable: false),
                    UpdatedAt = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AutomationRunner", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AutomationRunner_Organizations_OrganizationId",
                        column: x => x.OrganizationId,
                        principalTable: "Organizations",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "TelemetryEvent",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    MemberId = table.Column<string>(type: "longtext", nullable: false),
                    EventType = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                    EventTimestamp = table.Column<long>(type: "bigint", nullable: false),
                    Source = table.Column<string>(type: "varchar(32)", maxLength: 32, nullable: true),
                    SessionId = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: true),
                    DurationMs = table.Column<int>(type: "int", nullable: true),
                    Success = table.Column<bool>(type: "tinyint(1)", nullable: true),
                    CreatedAt = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TelemetryEvent", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TelemetryEvent_Organizations_OrganizationId",
                        column: x => x.OrganizationId,
                        principalTable: "Organizations",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "TelemetrySessionDimension",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    SessionId = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: false),
                    Source = table.Column<string>(type: "varchar(32)", maxLength: 32, nullable: false),
                    DimensionType = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                    DimensionValue = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: false),
                    DimensionLabel = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    MetadataJson = table.Column<string>(type: "longtext", nullable: true),
                    CreatedAt = table.Column<long>(type: "bigint", nullable: false),
                    UpdatedAt = table.Column<long>(type: "bigint", nullable: false),
                    LastSeenAt = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TelemetrySessionDimension", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TelemetrySessionDimension_Organizations_OrganizationId",
                        column: x => x.OrganizationId,
                        principalTable: "Organizations",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "AgentPermissionPolicy",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ScopeKey = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    TeamId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    SettingsJson = table.Column<string>(type: "longtext", nullable: false),
                    UpdatedByMemberId = table.Column<string>(type: "longtext", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AgentPermissionPolicy", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AgentPermissionPolicy_Teams_TeamId",
                        column: x => x.TeamId,
                        principalTable: "Teams",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "DesktopPolicyAssignment",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "longtext", nullable: false),
                    PolicyId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    MemberId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    TeamId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    Role = table.Column<string>(type: "longtext", nullable: true),
                    SubjectKey = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DesktopPolicyAssignment", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DesktopPolicyAssignment_Members_MemberId",
                        column: x => x.MemberId,
                        principalTable: "Members",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_DesktopPolicyAssignment_Teams_TeamId",
                        column: x => x.TeamId,
                        principalTable: "Teams",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "OrgDefaultModel",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ScopeKey = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    TeamId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    ProviderId = table.Column<string>(type: "longtext", nullable: false),
                    ModelId = table.Column<string>(type: "longtext", nullable: false),
                    UpdatedByMemberId = table.Column<string>(type: "longtext", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OrgDefaultModel", x => x.Id);
                    table.ForeignKey(
                        name: "FK_OrgDefaultModel_Teams_TeamId",
                        column: x => x.TeamId,
                        principalTable: "Teams",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "OrgPrompt",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    OrganizationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ScopeKey = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    TeamId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    Name = table.Column<string>(type: "longtext", nullable: false),
                    Content = table.Column<string>(type: "longtext", nullable: false),
                    UpdatedByMemberId = table.Column<string>(type: "longtext", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OrgPrompt", x => x.Id);
                    table.ForeignKey(
                        name: "FK_OrgPrompt_Teams_TeamId",
                        column: x => x.TeamId,
                        principalTable: "Teams",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "AutomationRevision",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    AutomationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Version = table.Column<int>(type: "int", nullable: false),
                    Instructions = table.Column<string>(type: "longtext", nullable: false),
                    ScheduleKind = table.Column<string>(type: "longtext", nullable: false),
                    ScheduleJson = table.Column<string>(type: "longtext", nullable: false),
                    ProviderId = table.Column<string>(type: "varchar(160)", maxLength: 160, nullable: false),
                    ModelId = table.Column<string>(type: "varchar(160)", maxLength: 160, nullable: false),
                    ModelVariant = table.Column<string>(type: "longtext", nullable: true),
                    ActionJson = table.Column<string>(type: "longtext", nullable: false),
                    ExecutionTarget = table.Column<string>(type: "longtext", nullable: false),
                    WorkspaceId = table.Column<string>(type: "longtext", nullable: true),
                    MaximumRuntimeMs = table.Column<int>(type: "int", nullable: false),
                    Digest = table.Column<string>(type: "longtext", nullable: false),
                    CreatedAt = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AutomationRevision", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AutomationRevision_Automation_AutomationId",
                        column: x => x.AutomationId,
                        principalTable: "Automation",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "AutomationRun",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    AutomationId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    RevisionId = table.Column<string>(type: "longtext", nullable: false),
                    Trigger = table.Column<string>(type: "longtext", nullable: false),
                    ScheduledFor = table.Column<long>(type: "bigint", nullable: true),
                    IdempotencyKey = table.Column<string>(type: "varchar(512)", maxLength: 512, nullable: false),
                    Status = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ExecutionTarget = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    ClaimDeadlineAt = table.Column<long>(type: "bigint", nullable: true),
                    LeaseOwner = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: true),
                    LeaseExpiresAt = table.Column<long>(type: "bigint", nullable: true),
                    HeartbeatAt = table.Column<long>(type: "bigint", nullable: true),
                    AttemptCount = table.Column<int>(type: "int", nullable: false),
                    CancelRequestedAt = table.Column<long>(type: "bigint", nullable: true),
                    EngineKind = table.Column<string>(type: "longtext", nullable: true),
                    EngineReceiptJson = table.Column<string>(type: "longtext", nullable: true),
                    EngineSequence = table.Column<int>(type: "int", nullable: false),
                    ThreadId = table.Column<string>(type: "longtext", nullable: false),
                    ProviderId = table.Column<string>(type: "longtext", nullable: false),
                    ModelId = table.Column<string>(type: "longtext", nullable: false),
                    ModelVariant = table.Column<string>(type: "longtext", nullable: true),
                    StartedAt = table.Column<long>(type: "bigint", nullable: true),
                    FinishedAt = table.Column<long>(type: "bigint", nullable: true),
                    ErrorJson = table.Column<string>(type: "longtext", nullable: true),
                    ResultSummary = table.Column<string>(type: "longtext", nullable: true),
                    TriggerContextJson = table.Column<string>(type: "longtext", nullable: true),
                    UsageJson = table.Column<string>(type: "longtext", nullable: false),
                    CreatedAt = table.Column<long>(type: "bigint", nullable: false),
                    UpdatedAt = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AutomationRun", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AutomationRun_Automation_AutomationId",
                        column: x => x.AutomationId,
                        principalTable: "Automation",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "AutomationRunEvent",
                columns: table => new
                {
                    Id = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    RunId = table.Column<string>(type: "varchar(255)", maxLength: 255, nullable: false),
                    Attempt = table.Column<int>(type: "int", nullable: false),
                    Sequence = table.Column<int>(type: "int", nullable: false),
                    EventType = table.Column<string>(type: "longtext", nullable: false),
                    PayloadJson = table.Column<string>(type: "longtext", nullable: false),
                    IdempotencyKey = table.Column<string>(type: "varchar(400)", maxLength: 400, nullable: false),
                    CreatedAt = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AutomationRunEvent", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AutomationRunEvent_AutomationRun_RunId",
                        column: x => x.RunId,
                        principalTable: "AutomationRun",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "IX_AdminAllowlistEntry_Email",
                table: "AdminAllowlistEntry",
                column: "Email",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AgentPermissionPolicy_OrganizationId_ScopeKey",
                table: "AgentPermissionPolicy",
                columns: new[] { "OrganizationId", "ScopeKey" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AgentPermissionPolicy_TeamId",
                table: "AgentPermissionPolicy",
                column: "TeamId");

            migrationBuilder.CreateIndex(
                name: "IX_ApiKey_KeyHash",
                table: "ApiKey",
                column: "KeyHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ApiKey_OrganizationId_MemberId",
                table: "ApiKey",
                columns: new[] { "OrganizationId", "MemberId" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditEvent_OrganizationId_Action",
                table: "AuditEvent",
                columns: new[] { "OrganizationId", "Action" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditEvent_OrganizationId_OperationId_RecordedAt_Id",
                table: "AuditEvent",
                columns: new[] { "OrganizationId", "OperationId", "RecordedAt", "Id" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditEventResource_EventId",
                table: "AuditEventResource",
                column: "EventId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditEventResource_OrganizationId_ResourceId",
                table: "AuditEventResource",
                columns: new[] { "OrganizationId", "ResourceId" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditOperation_OrganizationId_FirstRecordedAt_Id",
                table: "AuditOperation",
                columns: new[] { "OrganizationId", "FirstRecordedAt", "Id" });

            migrationBuilder.CreateIndex(
                name: "IX_Automation_OrganizationId",
                table: "Automation",
                column: "OrganizationId");

            migrationBuilder.CreateIndex(
                name: "IX_Automation_OwnerMemberId_Id",
                table: "Automation",
                columns: new[] { "OwnerMemberId", "Id" });

            migrationBuilder.CreateIndex(
                name: "IX_Automation_State_NextDueAt",
                table: "Automation",
                columns: new[] { "State", "NextDueAt" });

            migrationBuilder.CreateIndex(
                name: "IX_AutomationRevision_AutomationId_Version",
                table: "AutomationRevision",
                columns: new[] { "AutomationId", "Version" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AutomationRun_AutomationId_Id",
                table: "AutomationRun",
                columns: new[] { "AutomationId", "Id" });

            migrationBuilder.CreateIndex(
                name: "IX_AutomationRun_AutomationId_Status",
                table: "AutomationRun",
                columns: new[] { "AutomationId", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_AutomationRun_IdempotencyKey",
                table: "AutomationRun",
                column: "IdempotencyKey",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AutomationRun_Status_ExecutionTarget",
                table: "AutomationRun",
                columns: new[] { "Status", "ExecutionTarget" });

            migrationBuilder.CreateIndex(
                name: "IX_AutomationRunEvent_RunId_Attempt_Sequence",
                table: "AutomationRunEvent",
                columns: new[] { "RunId", "Attempt", "Sequence" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AutomationRunner_OrganizationId_OwnerMemberId_LastSeenAt",
                table: "AutomationRunner",
                columns: new[] { "OrganizationId", "OwnerMemberId", "LastSeenAt" });

            migrationBuilder.CreateIndex(
                name: "IX_BrandAsset_OrganizationId_Kind_Version_Extension",
                table: "BrandAsset",
                columns: new[] { "OrganizationId", "Kind", "Version", "Extension" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ConfigObject_OrganizationId_UpdatedAt_Id",
                table: "ConfigObject",
                columns: new[] { "OrganizationId", "UpdatedAt", "Id" });

            migrationBuilder.CreateIndex(
                name: "IX_ConfigObjectVersion_ConfigObjectId_CreatedAt_Id",
                table: "ConfigObjectVersion",
                columns: new[] { "ConfigObjectId", "CreatedAt", "Id" });

            migrationBuilder.CreateIndex(
                name: "IX_ConnectedAccount_ConnectionId",
                table: "ConnectedAccount",
                column: "ConnectionId");

            migrationBuilder.CreateIndex(
                name: "IX_ConnectedAccount_MemberId_ConnectionId",
                table: "ConnectedAccount",
                columns: new[] { "MemberId", "ConnectionId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ConnectionAccessGrant_ConnectionId",
                table: "ConnectionAccessGrant",
                column: "ConnectionId");

            migrationBuilder.CreateIndex(
                name: "IX_ConnectionAccessGrant_ConnectionId_MemberId",
                table: "ConnectionAccessGrant",
                columns: new[] { "ConnectionId", "MemberId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ConnectionAccessGrant_ConnectionId_TeamId",
                table: "ConnectionAccessGrant",
                columns: new[] { "ConnectionId", "TeamId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ConnectionAccessGrant_MemberId",
                table: "ConnectionAccessGrant",
                column: "MemberId");

            migrationBuilder.CreateIndex(
                name: "IX_ConnectionAccessGrant_TeamId",
                table: "ConnectionAccessGrant",
                column: "TeamId");

            migrationBuilder.CreateIndex(
                name: "IX_ConnectionOAuthClient_OrganizationId_ConnectionId",
                table: "ConnectionOAuthClient",
                columns: new[] { "OrganizationId", "ConnectionId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ConnectionOAuthTransaction_ExpiresAt",
                table: "ConnectionOAuthTransaction",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_DesktopPolicy_DefaultKey",
                table: "DesktopPolicy",
                column: "DefaultKey",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DesktopPolicy_OrganizationId_CreatedAt",
                table: "DesktopPolicy",
                columns: new[] { "OrganizationId", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_DesktopPolicy_OrganizationId_ExternalKey",
                table: "DesktopPolicy",
                columns: new[] { "OrganizationId", "ExternalKey" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DesktopPolicyAssignment_MemberId",
                table: "DesktopPolicyAssignment",
                column: "MemberId");

            migrationBuilder.CreateIndex(
                name: "IX_DesktopPolicyAssignment_PolicyId_SubjectKey",
                table: "DesktopPolicyAssignment",
                columns: new[] { "PolicyId", "SubjectKey" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DesktopPolicyAssignment_TeamId",
                table: "DesktopPolicyAssignment",
                column: "TeamId");

            migrationBuilder.CreateIndex(
                name: "IX_DesktopStartupReport_OrganizationId_AttemptId",
                table: "DesktopStartupReport",
                columns: new[] { "OrganizationId", "AttemptId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DesktopStartupReport_OrganizationId_ObservedAt",
                table: "DesktopStartupReport",
                columns: new[] { "OrganizationId", "ObservedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_DeviceCodes_DeviceCodeHash",
                table: "DeviceCodes",
                column: "DeviceCodeHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DeviceCodes_UserCode",
                table: "DeviceCodes",
                column: "UserCode");

            migrationBuilder.CreateIndex(
                name: "IX_EmailOtps_Email_Type",
                table: "EmailOtps",
                columns: new[] { "Email", "Type" });

            migrationBuilder.CreateIndex(
                name: "IX_ExternalAccount_ProviderId_AccountId",
                table: "ExternalAccount",
                columns: new[] { "ProviderId", "AccountId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ExternalAccount_UserId",
                table: "ExternalAccount",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_ExternalIdentity_OrganizationId_UserId",
                table: "ExternalIdentity",
                columns: new[] { "OrganizationId", "UserId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ExternalMcpConnection_OrganizationId",
                table: "ExternalMcpConnection",
                column: "OrganizationId");

            migrationBuilder.CreateIndex(
                name: "IX_ExternalMcpConnection_OrganizationId_ExternalKey",
                table: "ExternalMcpConnection",
                columns: new[] { "OrganizationId", "ExternalKey" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Invitations_InviteToken",
                table: "Invitations",
                column: "InviteToken",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Invitations_OrganizationId_Email",
                table: "Invitations",
                columns: new[] { "OrganizationId", "Email" });

            migrationBuilder.CreateIndex(
                name: "IX_Invitations_PlaceholderMemberId",
                table: "Invitations",
                column: "PlaceholderMemberId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_LibraryGrant_OrganizationId_MemberId",
                table: "LibraryGrant",
                columns: new[] { "OrganizationId", "MemberId" });

            migrationBuilder.CreateIndex(
                name: "IX_LibraryGrant_OrganizationId_TeamId",
                table: "LibraryGrant",
                columns: new[] { "OrganizationId", "TeamId" });

            migrationBuilder.CreateIndex(
                name: "IX_LibraryGrant_ResourceKind_ResourceId_SubjectKey",
                table: "LibraryGrant",
                columns: new[] { "ResourceKind", "ResourceId", "SubjectKey" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_LibraryUsageEvent_OrganizationId_CreatedAt",
                table: "LibraryUsageEvent",
                columns: new[] { "OrganizationId", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_Marketplace_OrganizationId",
                table: "Marketplace",
                column: "OrganizationId");

            migrationBuilder.CreateIndex(
                name: "IX_Marketplace_OrganizationId_ExternalKey",
                table: "Marketplace",
                columns: new[] { "OrganizationId", "ExternalKey" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MarketplacePlugin_MarketplaceId_PluginId",
                table: "MarketplacePlugin",
                columns: new[] { "MarketplaceId", "PluginId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MarketplacePlugin_PluginId",
                table: "MarketplacePlugin",
                column: "PluginId");

            migrationBuilder.CreateIndex(
                name: "IX_Members_OrganizationId_UserId",
                table: "Members",
                columns: new[] { "OrganizationId", "UserId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_OAuthConsents_ClientId_UserId_OrganizationId",
                table: "OAuthConsents",
                columns: new[] { "ClientId", "UserId", "OrganizationId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_OnboardingRateLimit_Key",
                table: "OnboardingRateLimit",
                column: "Key",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Organizations_Slug",
                table: "Organizations",
                column: "Slug",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_OrganizationWebOrigin_OrganizationId_Origin",
                table: "OrganizationWebOrigin",
                columns: new[] { "OrganizationId", "Origin" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_OrgDefaultModel_OrganizationId_ScopeKey",
                table: "OrgDefaultModel",
                columns: new[] { "OrganizationId", "ScopeKey" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_OrgDefaultModel_TeamId",
                table: "OrgDefaultModel",
                column: "TeamId");

            migrationBuilder.CreateIndex(
                name: "IX_OrgPrompt_OrganizationId_ScopeKey",
                table: "OrgPrompt",
                columns: new[] { "OrganizationId", "ScopeKey" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_OrgPrompt_TeamId",
                table: "OrgPrompt",
                column: "TeamId");

            migrationBuilder.CreateIndex(
                name: "IX_PasswordResetTokens_UserId",
                table: "PasswordResetTokens",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_PermissionSetPermissions_PermissionSetId_PermissionKey",
                table: "PermissionSetPermissions",
                columns: new[] { "PermissionSetId", "PermissionKey" });

            migrationBuilder.CreateIndex(
                name: "IX_PermissionSets_OrganizationId",
                table: "PermissionSets",
                column: "OrganizationId");

            migrationBuilder.CreateIndex(
                name: "IX_PermissionSets_OrganizationId_DefaultKey",
                table: "PermissionSets",
                columns: new[] { "OrganizationId", "DefaultKey" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_PermissionSetTeams_ActiveTeamId",
                table: "PermissionSetTeams",
                column: "ActiveTeamId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_PermissionSetTeams_PermissionSetId",
                table: "PermissionSetTeams",
                column: "PermissionSetId");

            migrationBuilder.CreateIndex(
                name: "IX_PermissionSetTeams_TeamId",
                table: "PermissionSetTeams",
                column: "TeamId");

            migrationBuilder.CreateIndex(
                name: "IX_PlatformFeatureChange_FeatureKey_CreatedAt",
                table: "PlatformFeatureChange",
                columns: new[] { "FeatureKey", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_PlatformFeatureChange_OrganizationId",
                table: "PlatformFeatureChange",
                column: "OrganizationId");

            migrationBuilder.CreateIndex(
                name: "IX_Plugin_ActiveKey",
                table: "Plugin",
                column: "ActiveKey",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Plugin_OrganizationId_UpdatedAt_Id",
                table: "Plugin",
                columns: new[] { "OrganizationId", "UpdatedAt", "Id" });

            migrationBuilder.CreateIndex(
                name: "IX_PluginConfigObject_ConfigObjectId",
                table: "PluginConfigObject",
                column: "ConfigObjectId");

            migrationBuilder.CreateIndex(
                name: "IX_PluginConfigObject_PluginId_ConfigObjectId",
                table: "PluginConfigObject",
                columns: new[] { "PluginId", "ConfigObjectId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_CodeHash",
                table: "RefreshTokens",
                column: "CodeHash");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_FamilyId",
                table: "RefreshTokens",
                column: "FamilyId");

            migrationBuilder.CreateIndex(
                name: "IX_ScimGroup_OrganizationId",
                table: "ScimGroup",
                column: "OrganizationId");

            migrationBuilder.CreateIndex(
                name: "IX_ScimGroup_ProviderId_ExternalId",
                table: "ScimGroup",
                columns: new[] { "ProviderId", "ExternalId" });

            migrationBuilder.CreateIndex(
                name: "IX_ScimGroupMember_GroupId_RemoteUserId",
                table: "ScimGroupMember",
                columns: new[] { "GroupId", "RemoteUserId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ScimGroupMember_RemoteUserId",
                table: "ScimGroupMember",
                column: "RemoteUserId");

            migrationBuilder.CreateIndex(
                name: "IX_ScimProvider_OrganizationId",
                table: "ScimProvider",
                column: "OrganizationId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ScimProvider_ProviderId",
                table: "ScimProvider",
                column: "ProviderId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ScimProvider_TokenHash",
                table: "ScimProvider",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ScimSyncEvent_OrganizationId",
                table: "ScimSyncEvent",
                column: "OrganizationId");

            migrationBuilder.CreateIndex(
                name: "IX_ScimUserTombstone_OrganizationId_DeprovisionedUserId",
                table: "ScimUserTombstone",
                columns: new[] { "OrganizationId", "DeprovisionedUserId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ScimUserTombstone_OrganizationId_Email",
                table: "ScimUserTombstone",
                columns: new[] { "OrganizationId", "Email" });

            migrationBuilder.CreateIndex(
                name: "IX_Sessions_TokenHash",
                table: "Sessions",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Sessions_UserId",
                table: "Sessions",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_SocialAuthState_ExpiresAt",
                table: "SocialAuthState",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_SsoAuthState_ExpiresAt",
                table: "SsoAuthState",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_SsoAuthState_ProviderId",
                table: "SsoAuthState",
                column: "ProviderId");

            migrationBuilder.CreateIndex(
                name: "IX_SsoConnection_ActiveTestIntentId",
                table: "SsoConnection",
                column: "ActiveTestIntentId");

            migrationBuilder.CreateIndex(
                name: "IX_SsoConnection_OrganizationId",
                table: "SsoConnection",
                column: "OrganizationId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SsoConnection_ProviderId",
                table: "SsoConnection",
                column: "ProviderId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_TeamMembers_MemberId",
                table: "TeamMembers",
                column: "MemberId");

            migrationBuilder.CreateIndex(
                name: "IX_TeamMembers_TeamId_MemberId",
                table: "TeamMembers",
                columns: new[] { "TeamId", "MemberId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Teams_OrganizationId_Name",
                table: "Teams",
                columns: new[] { "OrganizationId", "Name" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_TelemetryEvent_OrganizationId_EventTimestamp",
                table: "TelemetryEvent",
                columns: new[] { "OrganizationId", "EventTimestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_TelemetryEvent_OrganizationId_SessionId_EventTimestamp",
                table: "TelemetryEvent",
                columns: new[] { "OrganizationId", "SessionId", "EventTimestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_TelemetrySessionDimension_OrganizationId_DimensionType_Dimen~",
                table: "TelemetrySessionDimension",
                columns: new[] { "OrganizationId", "DimensionType", "DimensionValue" });

            migrationBuilder.CreateIndex(
                name: "IX_TelemetrySessionDimension_OrganizationId_Source_SessionId_Di~",
                table: "TelemetrySessionDimension",
                columns: new[] { "OrganizationId", "Source", "SessionId", "DimensionType" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Users_Email",
                table: "Users",
                column: "Email",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_WorkspaceBootstrap_AgentUserId",
                table: "WorkspaceBootstrap",
                column: "AgentUserId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_WorkspaceBootstrap_OrganizationId",
                table: "WorkspaceBootstrap",
                column: "OrganizationId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_WorkspaceBootstrap_Status_ExpiresAt",
                table: "WorkspaceBootstrap",
                columns: new[] { "Status", "ExpiresAt" });

            migrationBuilder.CreateIndex(
                name: "IX_WorkspaceClaim_BootstrapId",
                table: "WorkspaceClaim",
                column: "BootstrapId");

            migrationBuilder.CreateIndex(
                name: "IX_WorkspaceClaim_TokenHash",
                table: "WorkspaceClaim",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_WorkspaceClaimCode_BootstrapId",
                table: "WorkspaceClaimCode",
                column: "BootstrapId");

            migrationBuilder.CreateIndex(
                name: "IX_WorkspaceClaimCode_CodeHash",
                table: "WorkspaceClaimCode",
                column: "CodeHash");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AdminAllowlistEntry");

            migrationBuilder.DropTable(
                name: "AgentPermissionPolicy");

            migrationBuilder.DropTable(
                name: "ApiKey");

            migrationBuilder.DropTable(
                name: "AuditEvent");

            migrationBuilder.DropTable(
                name: "AuditEventResource");

            migrationBuilder.DropTable(
                name: "AuditOperation");

            migrationBuilder.DropTable(
                name: "AuditPolicy");

            migrationBuilder.DropTable(
                name: "AuthorizationCodes");

            migrationBuilder.DropTable(
                name: "AutomationRevision");

            migrationBuilder.DropTable(
                name: "AutomationRunEvent");

            migrationBuilder.DropTable(
                name: "AutomationRunner");

            migrationBuilder.DropTable(
                name: "BrandAsset");

            migrationBuilder.DropTable(
                name: "ConfigObject");

            migrationBuilder.DropTable(
                name: "ConfigObjectVersion");

            migrationBuilder.DropTable(
                name: "ConnectedAccount");

            migrationBuilder.DropTable(
                name: "ConnectionAccessGrant");

            migrationBuilder.DropTable(
                name: "ConnectionOAuthClient");

            migrationBuilder.DropTable(
                name: "ConnectionOAuthTransaction");

            migrationBuilder.DropTable(
                name: "DesktopPolicy");

            migrationBuilder.DropTable(
                name: "DesktopPolicyAssignment");

            migrationBuilder.DropTable(
                name: "DesktopStartupReport");

            migrationBuilder.DropTable(
                name: "DeviceCodes");

            migrationBuilder.DropTable(
                name: "EgressDiagnosticCredential");

            migrationBuilder.DropTable(
                name: "EmailOtps");

            migrationBuilder.DropTable(
                name: "ExternalAccount");

            migrationBuilder.DropTable(
                name: "ExternalIdentity");

            migrationBuilder.DropTable(
                name: "ExternalMcpConnection");

            migrationBuilder.DropTable(
                name: "HandoffGrants");

            migrationBuilder.DropTable(
                name: "Invitations");

            migrationBuilder.DropTable(
                name: "LibraryGrant");

            migrationBuilder.DropTable(
                name: "LibraryUsageEvent");

            migrationBuilder.DropTable(
                name: "Marketplace");

            migrationBuilder.DropTable(
                name: "MarketplacePlugin");

            migrationBuilder.DropTable(
                name: "McpAccessTokens");

            migrationBuilder.DropTable(
                name: "OAuthClients");

            migrationBuilder.DropTable(
                name: "OAuthConsents");

            migrationBuilder.DropTable(
                name: "OidcClientSettings");

            migrationBuilder.DropTable(
                name: "OidcGrant");

            migrationBuilder.DropTable(
                name: "OnboardingRateLimit");

            migrationBuilder.DropTable(
                name: "OrganizationSettings");

            migrationBuilder.DropTable(
                name: "OrganizationWebOrigin");

            migrationBuilder.DropTable(
                name: "OrgDefaultModel");

            migrationBuilder.DropTable(
                name: "OrgPolicySettings");

            migrationBuilder.DropTable(
                name: "OrgPrompt");

            migrationBuilder.DropTable(
                name: "PasswordResetTokens");

            migrationBuilder.DropTable(
                name: "PermissionSetPermissions");

            migrationBuilder.DropTable(
                name: "PermissionSets");

            migrationBuilder.DropTable(
                name: "PermissionSetTeams");

            migrationBuilder.DropTable(
                name: "PlatformFeatureChange");

            migrationBuilder.DropTable(
                name: "PlatformFeatureRollout");

            migrationBuilder.DropTable(
                name: "PlatformOrganization");

            migrationBuilder.DropTable(
                name: "PlatformOrganizationFeature");

            migrationBuilder.DropTable(
                name: "Plugin");

            migrationBuilder.DropTable(
                name: "PluginConfigObject");

            migrationBuilder.DropTable(
                name: "RefreshTokens");

            migrationBuilder.DropTable(
                name: "ScimGroup");

            migrationBuilder.DropTable(
                name: "ScimGroupMember");

            migrationBuilder.DropTable(
                name: "ScimProvider");

            migrationBuilder.DropTable(
                name: "ScimSyncEvent");

            migrationBuilder.DropTable(
                name: "ScimUserTombstone");

            migrationBuilder.DropTable(
                name: "Sessions");

            migrationBuilder.DropTable(
                name: "SigningKeys");

            migrationBuilder.DropTable(
                name: "SocialAuthState");

            migrationBuilder.DropTable(
                name: "SsoAuthState");

            migrationBuilder.DropTable(
                name: "SsoConnection");

            migrationBuilder.DropTable(
                name: "TeamMembers");

            migrationBuilder.DropTable(
                name: "TelemetryEvent");

            migrationBuilder.DropTable(
                name: "TelemetrySessionDimension");

            migrationBuilder.DropTable(
                name: "Users");

            migrationBuilder.DropTable(
                name: "WorkspaceBootstrap");

            migrationBuilder.DropTable(
                name: "WorkspaceClaim");

            migrationBuilder.DropTable(
                name: "WorkspaceClaimCode");

            migrationBuilder.DropTable(
                name: "AutomationRun");

            migrationBuilder.DropTable(
                name: "Members");

            migrationBuilder.DropTable(
                name: "Teams");

            migrationBuilder.DropTable(
                name: "Automation");

            migrationBuilder.DropTable(
                name: "Organizations");
        }
    }
}
