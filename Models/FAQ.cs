using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TuningStore.Models
{
    [Table("FAQs")]
    public class FAQ : BaseCreatorModel
    {
        [Required]
        [Column("question")]
        [StringLength(255, MinimumLength = 3)]
        public string Question { get; set; } = string.Empty;

        [Required]
        [Column("answer")]
        public string? Answer { get; set; }
    }
}