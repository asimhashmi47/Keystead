using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Keystead.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class InitialSchema : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "audit_entries",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Seq = table.Column<long>(type: "INTEGER", nullable: false),
                    WorkspaceId = table.Column<Guid>(type: "TEXT", nullable: true),
                    ActorType = table.Column<int>(type: "INTEGER", nullable: false),
                    ActorId = table.Column<Guid>(type: "TEXT", nullable: true),
                    ActorLabel = table.Column<string>(type: "TEXT", maxLength: 320, nullable: false),
                    Action = table.Column<int>(type: "INTEGER", nullable: false),
                    Outcome = table.Column<int>(type: "INTEGER", nullable: false),
                    ResourceType = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    ResourceId = table.Column<Guid>(type: "TEXT", nullable: true),
                    ResourceLabel = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    IpAddress = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    UserAgent = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    CorrelationId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    DataJson = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    CreatedUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    PreviousHash = table.Column<byte[]>(type: "BLOB", fixedLength: true, maxLength: 32, nullable: false),
                    Hash = table.Column<byte[]>(type: "BLOB", fixedLength: true, maxLength: 32, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_audit_entries", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "master_key_versions",
                columns: table => new
                {
                    Version = table.Column<int>(type: "INTEGER", nullable: false),
                    KeyCheckValue = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    CreatedUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    RetiredUtc = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_master_key_versions", x => x.Version);
                });

            migrationBuilder.CreateTable(
                name: "service_identities",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    WorkspaceId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ClientId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    ClientSecretHash = table.Column<byte[]>(type: "BLOB", fixedLength: true, maxLength: 32, nullable: false),
                    PreviousClientSecretHash = table.Column<byte[]>(type: "BLOB", fixedLength: true, maxLength: 32, nullable: true),
                    PreviousSecretExpiresUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ExpiresUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ip_allowlist = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                    CreatedUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    LastUsedUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    IsActive = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_service_identities", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "users",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Email = table.Column<string>(type: "TEXT", maxLength: 320, nullable: false),
                    DisplayName = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    PasswordHash = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    PasswordChangedUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    MfaSecretCiphertext = table.Column<byte[]>(type: "BLOB", maxLength: 256, nullable: true),
                    MfaSecretNonce = table.Column<byte[]>(type: "BLOB", fixedLength: true, maxLength: 12, nullable: true),
                    MfaSecretTag = table.Column<byte[]>(type: "BLOB", fixedLength: true, maxLength: 16, nullable: true),
                    MfaSeedMasterKeyVersion = table.Column<int>(type: "INTEGER", nullable: false),
                    MfaEnrolledUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    LastUsedTotpWindow = table.Column<long>(type: "INTEGER", nullable: true),
                    FailedSignInCount = table.Column<int>(type: "INTEGER", nullable: false),
                    LockoutEndUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    CreatedUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    IsActive = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_users", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "vaults",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    WorkspaceId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Slug = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    ColorToken = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    CreatedUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    SoftDeletedUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    RecoveryWindowDays = table.Column<int>(type: "INTEGER", nullable: false),
                    PurgeProtection = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_vaults", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "workspaces",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Slug = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    CreatedUtc = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_workspaces", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "user_recovery_codes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    UserId = table.Column<Guid>(type: "TEXT", nullable: false),
                    CodeHash = table.Column<byte[]>(type: "BLOB", fixedLength: true, maxLength: 32, nullable: false),
                    UsedUtc = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_user_recovery_codes", x => x.Id);
                    table.ForeignKey(
                        name: "FK_user_recovery_codes_users_UserId",
                        column: x => x.UserId,
                        principalTable: "users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "user_sessions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    UserId = table.Column<Guid>(type: "TEXT", nullable: false),
                    CreatedUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    LastSeenUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    AbsoluteExpiryUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedIp = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    UserAgent = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    RevokedUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    LastStepUpUtc = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_user_sessions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_user_sessions_users_UserId",
                        column: x => x.UserId,
                        principalTable: "users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "secrets",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    VaultId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    Environment = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    ContentType = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    ExpiresUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    RotationReminderDays = table.Column<int>(type: "INTEGER", nullable: true),
                    CreatedUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    SoftDeletedUtc = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_secrets", x => x.Id);
                    table.ForeignKey(
                        name: "FK_secrets_vaults_VaultId",
                        column: x => x.VaultId,
                        principalTable: "vaults",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "vault_assignments",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    VaultId = table.Column<Guid>(type: "TEXT", nullable: false),
                    SubjectId = table.Column<Guid>(type: "TEXT", nullable: false),
                    SubjectType = table.Column<int>(type: "INTEGER", nullable: false),
                    Permission = table.Column<int>(type: "INTEGER", nullable: false),
                    GrantedUtc = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_vault_assignments", x => x.Id);
                    table.ForeignKey(
                        name: "FK_vault_assignments_vaults_VaultId",
                        column: x => x.VaultId,
                        principalTable: "vaults",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "vault_keks",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    VaultId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Version = table.Column<int>(type: "INTEGER", nullable: false),
                    WrappedKek = table.Column<byte[]>(type: "BLOB", maxLength: 128, nullable: false),
                    MasterKeyVersion = table.Column<int>(type: "INTEGER", nullable: false),
                    CreatedUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    RetiredUtc = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_vault_keks", x => x.Id);
                    table.ForeignKey(
                        name: "FK_vault_keks_vaults_VaultId",
                        column: x => x.VaultId,
                        principalTable: "vaults",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "workspace_memberships",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    WorkspaceId = table.Column<Guid>(type: "TEXT", nullable: false),
                    UserId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Role = table.Column<int>(type: "INTEGER", nullable: false),
                    GrantedUtc = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_workspace_memberships", x => x.Id);
                    table.ForeignKey(
                        name: "FK_workspace_memberships_users_UserId",
                        column: x => x.UserId,
                        principalTable: "users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_workspace_memberships_workspaces_WorkspaceId",
                        column: x => x.WorkspaceId,
                        principalTable: "workspaces",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "secret_tags",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    SecretId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Key = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Value = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_secret_tags", x => x.Id);
                    table.ForeignKey(
                        name: "FK_secret_tags_secrets_SecretId",
                        column: x => x.SecretId,
                        principalTable: "secrets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "secret_versions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    SecretId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Version = table.Column<int>(type: "INTEGER", nullable: false),
                    Ciphertext = table.Column<byte[]>(type: "BLOB", nullable: false),
                    Nonce = table.Column<byte[]>(type: "BLOB", fixedLength: true, maxLength: 12, nullable: false),
                    AuthTag = table.Column<byte[]>(type: "BLOB", fixedLength: true, maxLength: 16, nullable: false),
                    WrappedDek = table.Column<byte[]>(type: "BLOB", maxLength: 128, nullable: false),
                    KekVersion = table.Column<int>(type: "INTEGER", nullable: false),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedBySubjectId = table.Column<Guid>(type: "TEXT", nullable: false),
                    CreatedByLabel = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_secret_versions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_secret_versions_secrets_SecretId",
                        column: x => x.SecretId,
                        principalTable: "secrets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_audit_entries_Seq",
                table: "audit_entries",
                column: "Seq",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_audit_entries_WorkspaceId_Action",
                table: "audit_entries",
                columns: new[] { "WorkspaceId", "Action" });

            migrationBuilder.CreateIndex(
                name: "IX_audit_entries_WorkspaceId_CreatedUtc",
                table: "audit_entries",
                columns: new[] { "WorkspaceId", "CreatedUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_secret_tags_Key_Value",
                table: "secret_tags",
                columns: new[] { "Key", "Value" });

            migrationBuilder.CreateIndex(
                name: "IX_secret_tags_SecretId_Key",
                table: "secret_tags",
                columns: new[] { "SecretId", "Key" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_secret_versions_SecretId_Version",
                table: "secret_versions",
                columns: new[] { "SecretId", "Version" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_secrets_ExpiresUtc",
                table: "secrets",
                column: "ExpiresUtc");

            migrationBuilder.CreateIndex(
                name: "IX_secrets_VaultId",
                table: "secrets",
                column: "VaultId");

            migrationBuilder.CreateIndex(
                name: "IX_secrets_VaultId_Environment_Name",
                table: "secrets",
                columns: new[] { "VaultId", "Environment", "Name" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_service_identities_ClientId",
                table: "service_identities",
                column: "ClientId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_service_identities_WorkspaceId",
                table: "service_identities",
                column: "WorkspaceId");

            migrationBuilder.CreateIndex(
                name: "IX_user_recovery_codes_UserId",
                table: "user_recovery_codes",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_user_sessions_UserId",
                table: "user_sessions",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_users_Email",
                table: "users",
                column: "Email",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_vault_assignments_SubjectId_SubjectType",
                table: "vault_assignments",
                columns: new[] { "SubjectId", "SubjectType" });

            migrationBuilder.CreateIndex(
                name: "IX_vault_assignments_VaultId_SubjectId_SubjectType",
                table: "vault_assignments",
                columns: new[] { "VaultId", "SubjectId", "SubjectType" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_vault_keks_VaultId_Version",
                table: "vault_keks",
                columns: new[] { "VaultId", "Version" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_vaults_WorkspaceId",
                table: "vaults",
                column: "WorkspaceId");

            migrationBuilder.CreateIndex(
                name: "IX_vaults_WorkspaceId_Slug",
                table: "vaults",
                columns: new[] { "WorkspaceId", "Slug" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_workspace_memberships_UserId",
                table: "workspace_memberships",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_workspace_memberships_WorkspaceId_UserId",
                table: "workspace_memberships",
                columns: new[] { "WorkspaceId", "UserId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_workspaces_Slug",
                table: "workspaces",
                column: "Slug",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "audit_entries");

            migrationBuilder.DropTable(
                name: "master_key_versions");

            migrationBuilder.DropTable(
                name: "secret_tags");

            migrationBuilder.DropTable(
                name: "secret_versions");

            migrationBuilder.DropTable(
                name: "service_identities");

            migrationBuilder.DropTable(
                name: "user_recovery_codes");

            migrationBuilder.DropTable(
                name: "user_sessions");

            migrationBuilder.DropTable(
                name: "vault_assignments");

            migrationBuilder.DropTable(
                name: "vault_keks");

            migrationBuilder.DropTable(
                name: "workspace_memberships");

            migrationBuilder.DropTable(
                name: "secrets");

            migrationBuilder.DropTable(
                name: "users");

            migrationBuilder.DropTable(
                name: "workspaces");

            migrationBuilder.DropTable(
                name: "vaults");
        }
    }
}
