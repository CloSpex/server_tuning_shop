using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace server.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "BodyTypes",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Name = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BodyTypes", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "EngineTypes",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Name = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EngineTypes", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "PartCategories",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    name = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    is_exterior = table.Column<bool>(type: "bit", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PartCategories", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "TransmissionTypes",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Name = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TransmissionTypes", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    username = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    email = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    password = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    role = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: true),
                    created_at = table.Column<DateTime>(type: "datetime2", nullable: false),
                    updated_at = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "Brands",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    name = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    description = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    created_at = table.Column<DateTime>(type: "datetime2", nullable: false),
                    updated_at = table.Column<DateTime>(type: "datetime2", nullable: false),
                    created_by = table.Column<int>(type: "int", nullable: true),
                    updated_by = table.Column<int>(type: "int", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Brands", x => x.id);
                    table.ForeignKey(
                        name: "FK_Brands_Users_created_by",
                        column: x => x.created_by,
                        principalTable: "Users",
                        principalColumn: "id");
                    table.ForeignKey(
                        name: "FK_Brands_Users_updated_by",
                        column: x => x.updated_by,
                        principalTable: "Users",
                        principalColumn: "id");
                });

            migrationBuilder.CreateTable(
                name: "FAQs",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    question = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    answer = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    created_at = table.Column<DateTime>(type: "datetime2", nullable: false),
                    updated_at = table.Column<DateTime>(type: "datetime2", nullable: false),
                    created_by = table.Column<int>(type: "int", nullable: true),
                    updated_by = table.Column<int>(type: "int", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_FAQs", x => x.id);
                    table.ForeignKey(
                        name: "FK_FAQs_Users_created_by",
                        column: x => x.created_by,
                        principalTable: "Users",
                        principalColumn: "id");
                    table.ForeignKey(
                        name: "FK_FAQs_Users_updated_by",
                        column: x => x.updated_by,
                        principalTable: "Users",
                        principalColumn: "id");
                });

            migrationBuilder.CreateTable(
                name: "Models",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    name = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    brand_id = table.Column<int>(type: "int", nullable: false),
                    created_at = table.Column<DateTime>(type: "datetime2", nullable: false),
                    updated_at = table.Column<DateTime>(type: "datetime2", nullable: false),
                    created_by = table.Column<int>(type: "int", nullable: true),
                    updated_by = table.Column<int>(type: "int", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Models", x => x.id);
                    table.ForeignKey(
                        name: "FK_Models_Brands_brand_id",
                        column: x => x.brand_id,
                        principalTable: "Brands",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_Models_Users_created_by",
                        column: x => x.created_by,
                        principalTable: "Users",
                        principalColumn: "id");
                    table.ForeignKey(
                        name: "FK_Models_Users_updated_by",
                        column: x => x.updated_by,
                        principalTable: "Users",
                        principalColumn: "id");
                });

            migrationBuilder.CreateTable(
                name: "Specifications",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    model_id = table.Column<int>(type: "int", nullable: false),
                    engine_id = table.Column<int>(type: "int", nullable: true),
                    transmission_id = table.Column<int>(type: "int", nullable: true),
                    body_id = table.Column<int>(type: "int", nullable: true),
                    volume_litres = table.Column<double>(type: "float", nullable: true),
                    power_kilowatts = table.Column<double>(type: "float", nullable: true),
                    year_start = table.Column<int>(type: "int", nullable: true),
                    year_end = table.Column<int>(type: "int", nullable: true),
                    created_at = table.Column<DateTime>(type: "datetime2", nullable: false),
                    updated_at = table.Column<DateTime>(type: "datetime2", nullable: false),
                    created_by = table.Column<int>(type: "int", nullable: true),
                    updated_by = table.Column<int>(type: "int", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Specifications", x => x.id);
                    table.ForeignKey(
                        name: "FK_Specifications_BodyTypes_body_id",
                        column: x => x.body_id,
                        principalTable: "BodyTypes",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_Specifications_EngineTypes_engine_id",
                        column: x => x.engine_id,
                        principalTable: "EngineTypes",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_Specifications_Models_model_id",
                        column: x => x.model_id,
                        principalTable: "Models",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_Specifications_TransmissionTypes_transmission_id",
                        column: x => x.transmission_id,
                        principalTable: "TransmissionTypes",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_Specifications_Users_created_by",
                        column: x => x.created_by,
                        principalTable: "Users",
                        principalColumn: "id");
                    table.ForeignKey(
                        name: "FK_Specifications_Users_updated_by",
                        column: x => x.updated_by,
                        principalTable: "Users",
                        principalColumn: "id");
                });

            migrationBuilder.CreateTable(
                name: "Parts",
                columns: table => new
                {
                    id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    name = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    price = table.Column<decimal>(type: "decimal(10,2)", nullable: true),
                    quantity = table.Column<int>(type: "int", nullable: true),
                    image_path = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: true),
                    car_specification_id = table.Column<int>(type: "int", nullable: true),
                    color = table.Column<string>(type: "nvarchar(7)", maxLength: 7, nullable: false),
                    part_category_id = table.Column<int>(type: "int", nullable: false),
                    is_viewed = table.Column<bool>(type: "bit", nullable: false),
                    created_at = table.Column<DateTime>(type: "datetime2", nullable: false),
                    updated_at = table.Column<DateTime>(type: "datetime2", nullable: false),
                    created_by = table.Column<int>(type: "int", nullable: true),
                    updated_by = table.Column<int>(type: "int", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Parts", x => x.id);
                    table.ForeignKey(
                        name: "FK_Parts_PartCategories_part_category_id",
                        column: x => x.part_category_id,
                        principalTable: "PartCategories",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_Parts_Specifications_car_specification_id",
                        column: x => x.car_specification_id,
                        principalTable: "Specifications",
                        principalColumn: "id");
                    table.ForeignKey(
                        name: "FK_Parts_Users_created_by",
                        column: x => x.created_by,
                        principalTable: "Users",
                        principalColumn: "id");
                    table.ForeignKey(
                        name: "FK_Parts_Users_updated_by",
                        column: x => x.updated_by,
                        principalTable: "Users",
                        principalColumn: "id");
                });

            migrationBuilder.CreateIndex(
                name: "IX_Brands_created_by",
                table: "Brands",
                column: "created_by");

            migrationBuilder.CreateIndex(
                name: "IX_Brands_name",
                table: "Brands",
                column: "name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Brands_updated_by",
                table: "Brands",
                column: "updated_by");

            migrationBuilder.CreateIndex(
                name: "IX_FAQs_created_by",
                table: "FAQs",
                column: "created_by");

            migrationBuilder.CreateIndex(
                name: "IX_FAQs_updated_by",
                table: "FAQs",
                column: "updated_by");

            migrationBuilder.CreateIndex(
                name: "IX_Models_brand_id",
                table: "Models",
                column: "brand_id");

            migrationBuilder.CreateIndex(
                name: "IX_Models_created_by",
                table: "Models",
                column: "created_by");

            migrationBuilder.CreateIndex(
                name: "IX_Models_name",
                table: "Models",
                column: "name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Models_updated_by",
                table: "Models",
                column: "updated_by");

            migrationBuilder.CreateIndex(
                name: "IX_Parts_car_specification_id",
                table: "Parts",
                column: "car_specification_id");

            migrationBuilder.CreateIndex(
                name: "IX_Parts_created_by",
                table: "Parts",
                column: "created_by");

            migrationBuilder.CreateIndex(
                name: "IX_Parts_name_car_specification_id_color",
                table: "Parts",
                columns: new[] { "name", "car_specification_id", "color" },
                unique: true,
                filter: "[car_specification_id] IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_Parts_part_category_id",
                table: "Parts",
                column: "part_category_id");

            migrationBuilder.CreateIndex(
                name: "IX_Parts_updated_by",
                table: "Parts",
                column: "updated_by");

            migrationBuilder.CreateIndex(
                name: "IX_Specifications_body_id",
                table: "Specifications",
                column: "body_id");

            migrationBuilder.CreateIndex(
                name: "IX_Specifications_created_by",
                table: "Specifications",
                column: "created_by");

            migrationBuilder.CreateIndex(
                name: "IX_Specifications_engine_id",
                table: "Specifications",
                column: "engine_id");

            migrationBuilder.CreateIndex(
                name: "IX_Specifications_model_id",
                table: "Specifications",
                column: "model_id");

            migrationBuilder.CreateIndex(
                name: "IX_Specifications_transmission_id",
                table: "Specifications",
                column: "transmission_id");

            migrationBuilder.CreateIndex(
                name: "IX_Specifications_updated_by",
                table: "Specifications",
                column: "updated_by");

            migrationBuilder.CreateIndex(
                name: "IX_Users_email",
                table: "Users",
                column: "email",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Users_username",
                table: "Users",
                column: "username",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "FAQs");

            migrationBuilder.DropTable(
                name: "Parts");

            migrationBuilder.DropTable(
                name: "PartCategories");

            migrationBuilder.DropTable(
                name: "Specifications");

            migrationBuilder.DropTable(
                name: "BodyTypes");

            migrationBuilder.DropTable(
                name: "EngineTypes");

            migrationBuilder.DropTable(
                name: "Models");

            migrationBuilder.DropTable(
                name: "TransmissionTypes");

            migrationBuilder.DropTable(
                name: "Brands");

            migrationBuilder.DropTable(
                name: "Users");
        }
    }
}
