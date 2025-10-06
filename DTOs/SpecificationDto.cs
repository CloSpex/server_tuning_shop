using System.ComponentModel.DataAnnotations;

namespace TuningStore.DTOs
{
    public class SpecificationDto
    {
        public int Id { get; set; }
        public int ModelId { get; set; }
        public int? EngineTypeId { get; set; }
        public int? TransmissionTypeId { get; set; }
        public int? BodyTypeId { get; set; }
        public double? VolumeLitres { get; set; }
        public double? PowerKilowatts { get; set; }
        public int? YearStart { get; set; }
        public int? YearEnd { get; set; }
        public DateTime? CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
        public int? CreatedBy { get; set; }
        public int? UpdatedBy { get; set; }

        public EngineTypeDto? EngineType { get; set; }
        public TransmissionTypeDto? TransmissionType { get; set; }
        public BodyTypeDto? BodyType { get; set; }
    }



    public class CreateSpecificationDto
    {
        [Required(ErrorMessage = "Model ID is required")]
        public int ModelId { get; set; }

        public int? EngineTypeId { get; set; }

        public int? TransmissionTypeId { get; set; }

        public int? BodyTypeId { get; set; }

        [Range(0.1, 20.0, ErrorMessage = "Volume must be between 0.1 and 20.0 litres")]
        public double? VolumeLitres { get; set; }

        [Range(1, 2000, ErrorMessage = "Power must be between 1 and 2000 kilowatts")]
        public double? PowerKilowatts { get; set; }

        [Range(1900, 2100, ErrorMessage = "Year start must be between 1900 and 2100")]
        public int? YearStart { get; set; }

        [Range(1900, 2100, ErrorMessage = "Year end must be between 1900 and 2100")]
        public int? YearEnd { get; set; }
    }

    public class UpdateSpecificationDto
    {
        [Required(ErrorMessage = "Model ID is required")]
        public int ModelId { get; set; }

        public int? EngineTypeId { get; set; }

        public int? TransmissionTypeId { get; set; }

        public int? BodyTypeId { get; set; }

        [Range(0.1, 20.0, ErrorMessage = "Volume must be between 0.1 and 20.0 litres")]
        public double? VolumeLitres { get; set; }

        [Range(1, 2000, ErrorMessage = "Power must be between 1 and 2000 kilowatts")]
        public double? PowerKilowatts { get; set; }

        [Range(1900, 2100, ErrorMessage = "Year start must be between 1900 and 2100")]
        public int? YearStart { get; set; }

        [Range(1900, 2100, ErrorMessage = "Year end must be between 1900 and 2100")]
        public int? YearEnd { get; set; }
    }
}