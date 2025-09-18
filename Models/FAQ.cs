using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TuningStore.Models
{
    [Table("FAQs")]
    public class FAQ
    {
        [Key]
        [Column("id")]
        public int Id { get; set; }

        [Required]
        [Column("question")]
        [StringLength(255, MinimumLength = 3)]
        public string Question { get; set; } = string.Empty;

        [Required]
        [Column("answer")]
        public string? Answer { get; set; }

        [Column("created_at")]
        public DateTime? CreatedAt { get; set; }

        [Column("updated_at")]
        public DateTime? UpdatedAt { get; set; }

        [Column("created_by")]
        public int? CreatedBy { get; set; }
        [Column("updated_by")]
        public int? UpdatedBy { get; set; }

        [ForeignKey(nameof(CreatedBy))]
        public User? Creator { get; set; }

        [ForeignKey(nameof(UpdatedBy))]
        public User? Updater { get; set; }
    }
}