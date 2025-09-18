using System.ComponentModel.DataAnnotations;

namespace TuningStore.DTOs
{
    public class FAQDto
    {
        public int Id { get; set; }
        public string Question { get; set; } = string.Empty;
        public string? Answer { get; set; }
        public DateTime? CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
        public int? CreatedBy { get; set; }
        public int? UpdatedBy { get; set; }

        public UserDto? Creator { get; set; }
        public UserDto? Updater { get; set; }
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