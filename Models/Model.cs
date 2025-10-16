using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TuningStore.Models
{
    [Table("Models")]
    public class Model : BaseCreatorModel
    {

        [Required]
        [Column("name")]
        [StringLength(255, MinimumLength = 3)]
        public string Name { get; set; } = string.Empty;

        [Column("brand_id")]
        public int BrandId { get; set; }
        public ICollection<Specification> Specifications { get; set; } = new List<Specification>();
    }
}