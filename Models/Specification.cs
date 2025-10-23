using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TuningStore.Models
{
    [Table("Specifications")]
    public class Specification : BaseCreatorModel
    {

        [Required]
        [Column("model_id")]
        public int ModelId { get; set; }

        [Column("engine_id")]
        public int EngineTypeId { get; set; }
        [ForeignKey("EngineTypeId")]
        public EngineType EngineType { get; set; }

        [Column("transmission_id")]
        public int TransmissionTypeId { get; set; }
        [ForeignKey("TransmissionTypeId")]
        public TransmissionType TransmissionType { get; set; }

        [Column("body_id")]
        public int BodyTypeId { get; set; }
        [ForeignKey("BodyTypeId")]
        public BodyType BodyType { get; set; }

        [Column("volume_litres")]
        public double? VolumeLitres { get; set; }

        [Column("power_kilowatts")]
        public double? PowerKilowatts { get; set; }

        [Column("year_start")]
        public int? YearStart { get; set; }

        [Column("year_end")]
        public int? YearEnd { get; set; }

        [ForeignKey("ModelId")]
        public Model Model { get; set; }
    }

}