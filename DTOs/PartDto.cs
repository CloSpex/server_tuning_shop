using System.ComponentModel.DataAnnotations;

namespace TuningStore.DTOs
{
    public class PartDto
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public decimal? Price { get; set; }
        public int? Quantity { get; set; }
        public string? ImagePath { get; set; }
        public int? CarSpecificationId { get; set; }
        public DateTime? CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
        public int? CreatedBy { get; set; }
        public int? UpdatedBy { get; set; }
        public UserDto? Creator { get; set; }
        public UserDto? Updater { get; set; }
    }

    public class CreatePartDto
    {
        [Required]
        [StringLength(255, MinimumLength = 3)]
        public string Name { get; set; } = string.Empty;

        [Range(0.01, 999999.99, ErrorMessage = "Price must be between 0.01 and 999999.99")]
        public decimal? Price { get; set; }

        [Range(0, int.MaxValue, ErrorMessage = "Quantity must be non-negative")]
        public int? Quantity { get; set; }

        public string? ImagePath { get; set; }

        public int? CarSpecificationId { get; set; }
    }

    public class UpdatePartDto
    {
        [StringLength(255, MinimumLength = 3)]
        public string? Name { get; set; }

        [Range(0.01, 999999.99, ErrorMessage = "Price must be between 0.01 and 999999.99")]
        public decimal? Price { get; set; }

        [Range(0, int.MaxValue, ErrorMessage = "Quantity must be non-negative")]
        public int? Quantity { get; set; }

        public string? ImagePath { get; set; }

        public int? CarSpecificationId { get; set; }
    }
}