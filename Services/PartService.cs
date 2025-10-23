using TuningStore.DTOs;
using TuningStore.Models;
using TuningStore.Repositories;
namespace TuningStore.Services
{
    public interface IPartService
    {
        Task<IEnumerable<PartDto>> GetAllPartsAsync();
        Task<PartDto?> GetPartByIdAsync(int id);
        Task<PartDto> CreatePartAsync(CreatePartDto dto);
        Task<PartDto?> UpdatePartAsync(int id, UpdatePartDto dto);
        Task<bool> DeletePartAsync(int id);
        Task<IEnumerable<PartDto>> GetPartsByCategoryAsync(int categoryId);
        Task<IEnumerable<PartDto>> GetPartsBySpecificationAsync(int specificationId);
    }

    public class PartService : IPartService
    {
        private readonly IPartRepository _partRepository;

        public PartService(IPartRepository partRepository)
        {
            _partRepository = partRepository;
        }

        public async Task<IEnumerable<PartDto>> GetAllPartsAsync()
        {
            var parts = await _partRepository.GetAllAsync();
            return parts.Select(MapToDto);
        }

        public async Task<PartDto?> GetPartByIdAsync(int id)
        {
            var part = await _partRepository.GetByIdAsync(id);
            return part != null ? MapToDto(part) : null;
        }

        public async Task<PartDto> CreatePartAsync(CreatePartDto dto)
        {
            if (!await _partRepository.CategoryExistsAsync(dto.PartCategoryId))
                throw new InvalidOperationException($"Category with ID {dto.PartCategoryId} does not exist.");

            if (!await _partRepository.SpecificationExistsAsync(dto.CarSpecificationId))
                throw new InvalidOperationException($"Specification with ID {dto.CarSpecificationId} does not exist.");

            var part = new Part
            {
                Name = dto.Name,
                Price = dto.Price,
                Quantity = dto.Quantity,
                ImagePath = dto.ImagePath,
                PartCategoryId = dto.PartCategoryId,
                CarSpecificationId = dto.CarSpecificationId,
                Color = dto.Color
            };

            await _partRepository.CreateAsync(part);
            return MapToDto(part);
        }
        public async Task<PartDto?> UpdatePartAsync(int id, UpdatePartDto dto)
        {
            var part = await _partRepository.GetByIdAsync(id);
            if (part == null)
                return null;

            if (dto.PartCategoryId != 0 && part.PartCategoryId != dto.PartCategoryId)
            {
                if (!await _partRepository.CategoryExistsAsync((int)dto.PartCategoryId))
                    throw new InvalidOperationException($"Category with ID {dto.PartCategoryId} does not exist.");
                part.PartCategoryId = (int)dto.PartCategoryId;
            }

            if (dto.CarSpecificationId != 0 && part.CarSpecificationId != dto.CarSpecificationId)
            {
                if (!await _partRepository.SpecificationExistsAsync((int)dto.CarSpecificationId))
                    throw new InvalidOperationException($"Specification with ID {dto.CarSpecificationId} does not exist.");
                part.CarSpecificationId = dto.CarSpecificationId;
            }

            if (!string.IsNullOrWhiteSpace(dto.Name))
                part.Name = dto.Name;

            if (dto.Price.HasValue)
                part.Price = dto.Price.Value;

            if (dto.Quantity.HasValue)
                part.Quantity = dto.Quantity.Value;

            if (!string.IsNullOrWhiteSpace(dto.ImagePath))
                part.ImagePath = dto.ImagePath;

            if (!string.IsNullOrWhiteSpace(dto.Color))
                part.Color = dto.Color;

            part.UpdatedAt = DateTime.UtcNow;
            await _partRepository.UpdateAsync(part);
            return MapToDto(part);
        }
        public async Task<bool> DeletePartAsync(int id)
        {
            return await _partRepository.DeleteAsync(id);
        }
        public async Task<IEnumerable<PartDto>> GetPartsByCategoryAsync(int categoryId)
        {
            var parts = await _partRepository.GetPartsByCategoryAsync(categoryId);
            return parts.Select(MapToDto);
        }
        public async Task<IEnumerable<PartDto>> GetPartsBySpecificationAsync(int specificationId)
        {
            var parts = await _partRepository.GetPartsBySpecificationAsync(specificationId);
            return parts.Select(MapToDto);
        }
        private PartDto MapToDto(Part part)
        {
            return new PartDto
            {
                Id = part.Id,
                Name = part.Name,
                Price = part.Price,
                PartCategoryId = part.PartCategoryId,
                CarSpecificationId = part.CarSpecificationId,
                CreatedBy = part.CreatedBy,
                UpdatedBy = part.UpdatedBy
            };
        }
    }
}