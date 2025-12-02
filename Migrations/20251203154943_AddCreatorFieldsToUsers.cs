using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace server.Migrations
{
    /// <inheritdoc />
    public partial class AddCreatorFieldsToUsers : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "created_by",
                table: "Users",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "updated_by",
                table: "Users",
                type: "int",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Users_created_by",
                table: "Users",
                column: "created_by");

            migrationBuilder.CreateIndex(
                name: "IX_Users_updated_by",
                table: "Users",
                column: "updated_by");

            migrationBuilder.AddForeignKey(
                name: "FK_Users_Users_created_by",
                table: "Users",
                column: "created_by",
                principalTable: "Users",
                principalColumn: "id");

            migrationBuilder.AddForeignKey(
                name: "FK_Users_Users_updated_by",
                table: "Users",
                column: "updated_by",
                principalTable: "Users",
                principalColumn: "id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Users_Users_created_by",
                table: "Users");

            migrationBuilder.DropForeignKey(
                name: "FK_Users_Users_updated_by",
                table: "Users");

            migrationBuilder.DropIndex(
                name: "IX_Users_created_by",
                table: "Users");

            migrationBuilder.DropIndex(
                name: "IX_Users_updated_by",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "created_by",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "updated_by",
                table: "Users");
        }
    }
}
