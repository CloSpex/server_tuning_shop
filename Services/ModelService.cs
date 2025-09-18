using TuningStore.DTOs;
using TuningStore.Models;
using TuningStore.Repositories;
namespace TuningStore.Services
{
    public interface IModelService
    {
        Task<IEnumerable<ModelDto>> GetAllModelsAsync();
        Task<ModelDto?> GetModelByIdAsync(int id);
        Task<ModelDto> CreateModelAsync(CreateModelDto createModelDto);
        Task<ModelDto?> UpdateModelAsync(int id, UpdateModelDto updateModelDto);
        Task<bool> DeleteModelAsync(int id);
    }
    public class ModelService : IModelService
    {
        private readonly IModelRepository _modelRepository;

        public ModelService(IModelRepository modelRepository)
        {
            _modelRepository = modelRepository;
        }

        public async Task<IEnumerable<ModelDto>> GetAllModelsAsync()
        {
            var models = await _modelRepository.GetAllAsync();
            return models.Select(MapToDto);
        }

        public async Task<ModelDto?> GetModelByIdAsync(int id)
        {
            var model = await _modelRepository.GetByIdAsync(id);
            return model != null ? MapToDto(model) : null;
        }

        public async Task<ModelDto> CreateModelAsync(CreateModelDto createModelDto)
        {
            if (await _modelRepository.ModelExistsAsync(createModelDto.Name))
            {
                throw new InvalidOperationException("Model with the same name already exists.");
            }

            var model = new Model
            {
                Name = createModelDto.Name,
                BrandId = createModelDto.BrandId,
            };

            await _modelRepository.AddAsync(model);
            return MapToDto(model);
        }

        public async Task<ModelDto?> UpdateModelAsync(int id, UpdateModelDto updateModelDto)
        {
            var model = await _modelRepository.GetByIdAsync(id);
            if (model == null)
                return null;

            if (model.Name != updateModelDto.Name && await _modelRepository.ModelExistsAsync(updateModelDto.Name))
            {
                throw new InvalidOperationException("Another model with the same name already exists.");
            }

            model.Name = updateModelDto.Name;
            if (updateModelDto.BrandId.HasValue)
            {
                model.BrandId = (int)updateModelDto.BrandId.Value;
            }
            else
            {
                throw new InvalidOperationException("BrandId cannot be null.");
            }

            await _modelRepository.UpdateAsync(model);
            return MapToDto(model);
        }

        public async Task<bool> DeleteModelAsync(int id)
        {
            var model = await _modelRepository.GetByIdAsync(id);
            if (model == null)
                return false;

            await _modelRepository.DeleteAsync(id);
            return true;
        }

        private ModelDto MapToDto(Model model) => new ModelDto
        {
            Id = model.Id,
            Name = model.Name,
            BrandId = model.BrandId
        };
    }
}