using System.ComponentModel.DataAnnotations;

namespace TuningStore.DTOs
{
    public class EngineTypeDto
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
    }

    public class CreateEngineTypeDto
    {
        [Required]
        [MaxLength(100)]
        public string Name { get; set; } = string.Empty;
    }

    public class UpdateEngineTypeDto
    {
        [MaxLength(100)]
        public string? Name { get; set; }
    }

    public class TransmissionTypeDto
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
    }

    public class CreateTransmissionTypeDto
    {
        [Required]
        [MaxLength(100)]
        public string Name { get; set; } = string.Empty;
    }

    public class UpdateTransmissionTypeDto
    {
        [MaxLength(100)]
        public string? Name { get; set; }
    }

    public class BodyTypeDto
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
    }

    public class CreateBodyTypeDto
    {
        [Required]
        [MaxLength(100)]
        public string Name { get; set; } = string.Empty;
    }

    public class UpdateBodyTypeDto
    {
        [MaxLength(100)]
        public string? Name { get; set; }
    }

    public class VehicleTypesDto
    {
        public List<EngineTypeDto> EngineTypes { get; set; } = new();
        public List<TransmissionTypeDto> TransmissionTypes { get; set; } = new();
        public List<BodyTypeDto> BodyTypes { get; set; } = new();
    }
}