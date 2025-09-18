using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TuningStore.Models
{
    [Table("Brands")]
    public class Brand
    {
        [Key]
        [Column("id")]
        public int Id { get; set; }

        [Required]
        [Column("name")]
        [StringLength(255, MinimumLength = 3)]
        public string Name { get; set; } = string.Empty;

        [Column("description")]
        public string? Description { get; set; }

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
        public ICollection<Model> Models { get; set; } = new List<Model>();
    }
}