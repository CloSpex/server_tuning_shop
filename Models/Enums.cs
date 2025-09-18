using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TuningStore.Models
{
    [Table("EngineTypes")]
    public class EngineType
    {
        [Key]
        public int Id { get; set; }
        [Required]
        [MaxLength(100)]
        public string Name { get; set; }

        public ICollection<Specification> Specifications { get; set; }
    }

    [Table("TransmissionTypes")]
    public class TransmissionType
    {
        [Key]
        public int Id { get; set; }
        [Required]
        [MaxLength(100)]
        public string Name { get; set; }

        public ICollection<Specification> Specifications { get; set; }
    }
    [Table("BodyTypes")]

    public class BodyType
    {
        [Key]
        public int Id { get; set; }
        [Required]
        [MaxLength(100)]
        public string Name { get; set; }

        public ICollection<Specification> Specifications { get; set; }
    }
}