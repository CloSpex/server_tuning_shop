using System.ComponentModel.DataAnnotations;

namespace TuningStore.DTOs
{
    public class FAQDto : BaseCreatorDto
    {
        public string Question { get; set; } = string.Empty;
        public string? Answer { get; set; }
    }

    public class CreateFAQDto
    {
        [Required]
        [StringLength(255, MinimumLength = 3)]
        public string Question { get; set; } = string.Empty;

        [Required]
        [StringLength(5000, MinimumLength = 10)]
        public string Answer { get; set; } = string.Empty;
    }

    public class UpdateFAQDto
    {
        [StringLength(255, MinimumLength = 3)]
        public string? Question { get; set; }

        [StringLength(5000, MinimumLength = 10)]
        public string? Answer { get; set; }
    }

}