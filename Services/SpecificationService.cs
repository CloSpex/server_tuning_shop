using TuningStore.DTOs;
using TuningStore.Models;
using TuningStore.Repositories;

namespace TuningStore.Services
{
    public interface ISpecificationService
    {
        Task<IEnumerable<SpecificationDto>> GetAllSpecificationsAsync();
        Task<SpecificationDto?> GetSpecificationByIdAsync(int id);
        Task<SpecificationDto> CreateSpecificationAsync(CreateSpecificationDto dto);
        Task<SpecificationDto?> UpdateSpecificationAsync(int id, UpdateSpecificationDto dto);
        Task<bool> DeleteSpecificationAsync(int id);
        Task<IEnumerable<SpecificationDto>> GetSpecificationsByModelIdAsync(int modelId);
    }

    public class SpecificationService : ISpecificationService
    {
        private readonly ISpecificationRepository _specificationRepository;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public SpecificationService(
            ISpecificationRepository specificationRepository,
            IHttpContextAccessor httpContextAccessor)
        {
            _specificationRepository = specificationRepository;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task<IEnumerable<SpecificationDto>> GetAllSpecificationsAsync()
        {
            var specifications = await _specificationRepository.GetAllAsync();
            return specifications.Select(MapToDto);
        }

        public async Task<SpecificationDto?> GetSpecificationByIdAsync(int id)
        {
            var specification = await _specificationRepository.GetByIdAsync(id);
            return specification != null ? MapToDto(specification) : null;
        }

        public async Task<SpecificationDto> CreateSpecificationAsync(CreateSpecificationDto dto)
        {
            if (!await _specificationRepository.ModelExistsAsync(dto.ModelId))
                throw new InvalidOperationException($"Model with ID {dto.ModelId} does not exist.");

            var userId = GetCurrentUserId();

            var specification = new Specification
            {
                ModelId = dto.ModelId,
                EngineTypeId = dto.EngineTypeId,
                TransmissionTypeId = dto.TransmissionTypeId,
                BodyTypeId = dto.BodyTypeId,
                VolumeLitres = dto.VolumeLitres,
                PowerKilowatts = dto.PowerKilowatts,
                YearStart = dto.YearStart,
                YearEnd = dto.YearEnd,
                CreatedBy = userId,
                UpdatedBy = userId
            };

            await _specificationRepository.AddAsync(specification);

            var created = await _specificationRepository.GetByIdAsync(specification.Id);
            return MapToDto(created!);
        }

        public async Task<SpecificationDto?> UpdateSpecificationAsync(int id, UpdateSpecificationDto dto)
        {
            var specification = await _specificationRepository.GetByIdAsync(id);
            if (specification == null)
                return null;

            if (specification.ModelId != dto.ModelId)
            {
                if (!await _specificationRepository.ModelExistsAsync(dto.ModelId))
                    throw new InvalidOperationException($"Model with ID {dto.ModelId} does not exist.");
            }

            var userId = GetCurrentUserId();

            specification.ModelId = dto.ModelId;
            specification.EngineTypeId = dto.EngineTypeId;
            specification.TransmissionTypeId = dto.TransmissionTypeId;
            specification.BodyTypeId = dto.BodyTypeId;
            specification.VolumeLitres = dto.VolumeLitres;
            specification.PowerKilowatts = dto.PowerKilowatts;
            specification.YearStart = dto.YearStart;
            specification.YearEnd = dto.YearEnd;
            specification.UpdatedBy = userId;

            await _specificationRepository.UpdateAsync(specification);

            var updated = await _specificationRepository.GetByIdAsync(id);
            return MapToDto(updated!);
        }

        public async Task<bool> DeleteSpecificationAsync(int id)
        {
            var specification = await _specificationRepository.GetByIdAsync(id);
            if (specification == null)
                return false;

            await _specificationRepository.DeleteAsync(id);
            return true;
        }

        public async Task<IEnumerable<SpecificationDto>> GetSpecificationsByModelIdAsync(int modelId)
        {
            var specifications = await _specificationRepository.GetByModelIdAsync(modelId);
            return specifications.Select(MapToDto);
        }

        private int? GetCurrentUserId()
        {
            var userIdClaim = _httpContextAccessor.HttpContext?.User.FindFirst("id")?.Value;
            return int.TryParse(userIdClaim, out int userId) ? userId : null;
        }

        private static SpecificationDto MapToDto(Specification spec)
        {
            return new SpecificationDto
            {
                Id = spec.Id,
                ModelId = spec.ModelId,
                EngineTypeId = spec.EngineTypeId,
                TransmissionTypeId = spec.TransmissionTypeId,
                BodyTypeId = spec.BodyTypeId,
                VolumeLitres = spec.VolumeLitres,
                PowerKilowatts = spec.PowerKilowatts,
                YearStart = spec.YearStart,
                YearEnd = spec.YearEnd,
                CreatedAt = spec.CreatedAt,
                UpdatedAt = spec.UpdatedAt,
                CreatedBy = spec.CreatedBy,
                UpdatedBy = spec.UpdatedBy,
                EngineType = spec.EngineType != null ? new EngineTypeDto
                {
                    Id = spec.EngineType.Id,
                    Name = spec.EngineType.Name
                } : null,
                TransmissionType = spec.TransmissionType != null ? new TransmissionTypeDto
                {
                    Id = spec.TransmissionType.Id,
                    Name = spec.TransmissionType.Name
                } : null,
                BodyType = spec.BodyType != null ? new BodyTypeDto
                {
                    Id = spec.BodyType.Id,
                    Name = spec.BodyType.Name
                } : null
            };
        }
    }
}