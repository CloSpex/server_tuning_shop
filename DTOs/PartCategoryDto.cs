using System.ComponentModel.DataAnnotations;

namespace TuningStore.DTOs
{
    public class PartCategoryDto
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public bool IsExterior { get; set; }
    }

    public class CreatePartCategoryDto
    {
        [Required]
        [StringLength(255, MinimumLength = 3)]
        public string Name { get; set; } = string.Empty;

        public bool IsExterior { get; set; } = false;
    }

    public class UpdatePartCategoryDto
    {
        [StringLength(255, MinimumLength = 3)]
        public string? Name { get; set; }

        public bool? IsExterior { get; set; }
    }
}
