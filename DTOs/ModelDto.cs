using System.ComponentModel.DataAnnotations;

namespace TuningStore.DTOs
{
    public class ModelDto : BaseCreatorDto
    {
        public string Name { get; set; } = string.Empty;
        public int BrandId { get; set; }
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