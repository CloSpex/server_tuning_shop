using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TuningStore.Models
{
    [Table("Parts")]
    public class Part
    {
        [Key]
        [Column("id")]
        public int Id { get; set; }

        [Required]
        [Column("name")]
        [StringLength(255, MinimumLength = 3)]
        public string Name { get; set; } = string.Empty;

        [Column("price", TypeName = "decimal(10,2)")]
        public decimal? Price { get; set; }

        [Column("quantity")]
        public int? Quantity { get; set; }

        [Column("image_path")]
        [StringLength(255)]
        public string? ImagePath { get; set; } = "images/default_part_image.jpg";

        [Column("car_specification_id")]
        public int? CarSpecificationId { get; set; }

        [Column("color")]
        [StringLength(7)]
        public string Color { get; set; } = "#d3d3d3";

        [Column("part_category_id")]
        public int PartCategoryId { get; set; }

        [Column("is_viewed")]
        public bool IsViewed { get; set; } = false;

        [Column("created_at")]
        public DateTime? CreatedAt { get; set; }

        [Column("updated_at")]
        public DateTime? UpdatedAt { get; set; }

        [Column("created_by")]
        public int? CreatedBy { get; set; }

        [Column("updated_by")]
        public int? UpdatedBy { get; set; }

        [ForeignKey(nameof(CarSpecificationId))]
        public Specification? CarSpecification { get; set; }

        [ForeignKey(nameof(PartCategoryId))]
        public PartCategory PartCategory { get; set; } = null!;

        [ForeignKey(nameof(CreatedBy))]
        public User? Creator { get; set; }

        [ForeignKey(nameof(UpdatedBy))]
        public User? Updater { get; set; }
    }
}