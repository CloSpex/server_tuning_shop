using System.ComponentModel.DataAnnotations;

namespace TuningStore.DTOs
{
    public class ModelDto
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public DateTime? CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
        public int? CreatedBy { get; set; }
        public int? UpdatedBy { get; set; }
        public int BrandId { get; set; }
        public List<SpecificationDto> Specifications { get; set; } = new();
    }

    public class CreateModelDto
    {
        [Required]
        [StringLength(255, MinimumLength = 3)]
        public string Name { get; set; } = string.Empty;

        [Required]
        public int BrandId { get; set; }
    }

    public class UpdateModelDto
    {
        [StringLength(255, MinimumLength = 3)]
        public string? Name { get; set; }

        public int? BrandId { get; set; }
    }


}