using TuningStore.DTOs;
using TuningStore.Models;
using TuningStore.Repositories;

namespace TuningStore.Services
{
    public interface IPartCategoryService
    {
        Task<IEnumerable<PartCategoryDto>> GetAllCategoriesAsync();
        Task<PartCategoryDto?> GetCategoryByIdAsync(int id);
        Task<PartCategoryDto> CreateCategoryAsync(CreatePartCategoryDto dto);
        Task<PartCategoryDto?> UpdateCategoryAsync(int id, UpdatePartCategoryDto dto);
        Task<bool> DeleteCategoryAsync(int id);
    }

    public class PartCategoryService : IPartCategoryService
    {
        private readonly IPartCategoryRepository _repository;

        public PartCategoryService(IPartCategoryRepository repository)
        {
            _repository = repository;
        }

        public async Task<IEnumerable<PartCategoryDto>> GetAllCategoriesAsync()
        {
            var categories = await _repository.GetAllAsync();
            return categories.Select(c => MapToDto(c));
        }

        public async Task<PartCategoryDto?> GetCategoryByIdAsync(int id)
        {
            var category = await _repository.GetByIdAsync(id);
            return category == null ? null : MapToDto(category);
        }

        public async Task<PartCategoryDto> CreateCategoryAsync(CreatePartCategoryDto dto)
        {
            var category = new PartCategory
            {
                Name = dto.Name,
                IsExterior = dto.IsExterior
            };

            await _repository.CreateAsync(category);
            return MapToDto(category);
        }

        public async Task<PartCategoryDto?> UpdateCategoryAsync(int id, UpdatePartCategoryDto dto)
        {
            var category = await _repository.GetByIdAsync(id);
            if (category == null) return null;

            if (!string.IsNullOrWhiteSpace(dto.Name))
                category.Name = dto.Name;

            if (dto.IsExterior.HasValue)
                category.IsExterior = dto.IsExterior.Value;

            await _repository.UpdateAsync(category);
            return MapToDto(category);
        }

        public async Task<bool> DeleteCategoryAsync(int id) => await _repository.DeleteAsync(id);

        private static PartCategoryDto MapToDto(PartCategory category)
        {
            return new PartCategoryDto
            {
                Id = category.Id,
                Name = category.Name,
                IsExterior = category.IsExterior
            };
        }
    }
}
