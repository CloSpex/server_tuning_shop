using System.ComponentModel.DataAnnotations;

namespace TuningStore.DTOs
{
    public class BrandDto
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string? Description { get; set; }
        public DateTime? CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
        public int? CreatedBy { get; set; }
        public int? UpdatedBy { get; set; }
        public List<ModelDto> Models { get; set; } = new();
    }

    public class CreateBrandDto
    {
        [Required]
        [StringLength(255, MinimumLength = 3)]
        public string Name { get; set; } = string.Empty;

        public string? Description { get; set; }
    }

    public class UpdateBrandDto
    {
        [StringLength(255, MinimumLength = 3)]
        public string? Name { get; set; }

        public string? Description { get; set; }
    }
}