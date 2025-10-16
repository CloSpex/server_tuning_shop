using System.ComponentModel.DataAnnotations;

namespace TuningStore.DTOs
{
    public class BrandDto : BaseCreatorDto
    {
        public string Name { get; set; } = string.Empty;
        public string? Description { get; set; }
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