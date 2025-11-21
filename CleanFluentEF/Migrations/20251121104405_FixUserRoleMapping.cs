using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CleanFluentEF.Migrations
{
    /// <inheritdoc />
    public partial class FixUserRoleMapping : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "UserRoles",
                schema: "Person");

            migrationBuilder.DropPrimaryKey(
                name: "PK_Users",
                schema: "Person",
                table: "Users");

            migrationBuilder.RenameTable(
                name: "Users",
                schema: "Person",
                newName: "UsersTable",
                newSchema: "Person");

            migrationBuilder.AddPrimaryKey(
                name: "PK_UsersTable",
                schema: "Person",
                table: "UsersTable",
                column: "Id");

            migrationBuilder.CreateTable(
                name: "UserRoleMapping",
                schema: "Person",
                columns: table => new
                {
                    RoleId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserRoleMapping", x => new { x.RoleId, x.UserId });
                    table.ForeignKey(
                        name: "FK_UserRoleMapping_Roles_RoleId",
                        column: x => x.RoleId,
                        principalSchema: "Person",
                        principalTable: "Roles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_UserRoleMapping_UsersTable_UserId",
                        column: x => x.UserId,
                        principalSchema: "Person",
                        principalTable: "UsersTable",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_UserRoleMapping_UserId",
                schema: "Person",
                table: "UserRoleMapping",
                column: "UserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "UserRoleMapping",
                schema: "Person");

            migrationBuilder.DropPrimaryKey(
                name: "PK_UsersTable",
                schema: "Person",
                table: "UsersTable");

            migrationBuilder.RenameTable(
                name: "UsersTable",
                schema: "Person",
                newName: "Users",
                newSchema: "Person");

            migrationBuilder.AddPrimaryKey(
                name: "PK_Users",
                schema: "Person",
                table: "Users",
                column: "Id");

            migrationBuilder.CreateTable(
                name: "UserRoles",
                schema: "Person",
                columns: table => new
                {
                    RoleId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserRoles", x => new { x.RoleId, x.UserId });
                    table.ForeignKey(
                        name: "FK_UserRoles_Roles_RoleId",
                        column: x => x.RoleId,
                        principalSchema: "Person",
                        principalTable: "Roles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_UserRoles_Users_UserId",
                        column: x => x.UserId,
                        principalSchema: "Person",
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_UserRoles_UserId",
                schema: "Person",
                table: "UserRoles",
                column: "UserId");
        }
    }
}
