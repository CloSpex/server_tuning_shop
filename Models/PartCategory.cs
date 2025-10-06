using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TuningStore.Models
{
    [Table("PartCategories")]
    public class PartCategory
    {
        [Key]
        [Column("id")]
        public int Id { get; set; }

        [Required]
        [Column("name")]
        [StringLength(100)]
        public string Name { get; set; } = string.Empty;

        [Column("is_exterior")]
        public bool IsExterior { get; set; } = false;

        public ICollection<Part> Parts { get; set; } = new List<Part>();
    }
}