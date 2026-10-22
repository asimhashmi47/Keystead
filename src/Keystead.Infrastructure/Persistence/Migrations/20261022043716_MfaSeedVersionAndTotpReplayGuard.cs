using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Keystead.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class MfaSeedVersionAndTotpReplayGuard : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "LastUsedTotpWindow",
                table: "users",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "MfaSeedMasterKeyVersion",
                table: "users",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "LastUsedTotpWindow",
                table: "users");

            migrationBuilder.DropColumn(
                name: "MfaSeedMasterKeyVersion",
                table: "users");
        }
    }
}
