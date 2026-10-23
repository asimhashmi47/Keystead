using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Keystead.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class TokenSigningKeys : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "signing_keys",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Kid = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    PrivateKeyCiphertext = table.Column<byte[]>(type: "BLOB", maxLength: 512, nullable: false),
                    PrivateKeyNonce = table.Column<byte[]>(type: "BLOB", fixedLength: true, maxLength: 12, nullable: false),
                    PrivateKeyTag = table.Column<byte[]>(type: "BLOB", fixedLength: true, maxLength: 16, nullable: false),
                    MasterKeyVersion = table.Column<int>(type: "INTEGER", nullable: false),
                    PublicKey = table.Column<byte[]>(type: "BLOB", maxLength: 256, nullable: false),
                    CreatedUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    RetiredUtc = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_signing_keys", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_signing_keys_Kid",
                table: "signing_keys",
                column: "Kid",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "signing_keys");
        }
    }
}
