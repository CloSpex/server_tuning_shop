using TuningStore.DTOs;
using TuningStore.Models;
using TuningStore.Repositories;
namespace TuningStore.Services
{
    public interface IBrandService
    {
        Task<IEnumerable<BrandDto>> GetAllBrandsAsync();
        Task<BrandDto?> GetBrandByIdAsync(int id);
        Task<BrandDto> CreateBrandAsync(CreateBrandDto createBrandDto);
        Task<BrandDto?> UpdateBrandAsync(int id, UpdateBrandDto updateBrandDto);
        Task<bool> DeleteBrandAsync(int id);
    }
    public class BrandService : IBrandService
    {
        private readonly IBrandRepository _brandRepository;

        public BrandService(IBrandRepository brandRepository)
        {
            _brandRepository = brandRepository;
        }

        public async Task<IEnumerable<BrandDto>> GetAllBrandsAsync()
        {
            var brands = await _brandRepository.GetAllAsync();
            return brands.Select(MapToDto);
        }

        public async Task<BrandDto?> GetBrandByIdAsync(int id)
        {
            var brand = await _brandRepository.GetByIdAsync(id);
            return brand != null ? MapToDto(brand) : null;
        }

        public async Task<BrandDto> CreateBrandAsync(CreateBrandDto createBrandDto)
        {
            if (await _brandRepository.BrandExistsAsync(createBrandDto.Name))
            {
                throw new InvalidOperationException("Brand with the same name already exists.");
            }

            var brand = new Brand
            {
                Name = createBrandDto.Name,
                Description = createBrandDto.Description

            };

            await _brandRepository.AddAsync(brand);
            return MapToDto(brand);
        }

        public async Task<BrandDto?> UpdateBrandAsync(int id, UpdateBrandDto updateBrandDto)
        {
            var brand = await _brandRepository.GetByIdAsync(id);
            if (brand == null)
                return null;
            if (!string.IsNullOrWhiteSpace(updateBrandDto.Name) &&
                updateBrandDto.Name != brand.Name &&
                await _brandRepository.BrandExistsAsync(updateBrandDto.Name))
            {
                throw new InvalidOperationException("Brand with the same name already exists.");
            }

            if (!string.IsNullOrWhiteSpace(updateBrandDto.Name))
                brand.Name = updateBrandDto.Name;
            if (!string.IsNullOrWhiteSpace(updateBrandDto.Description))
                brand.Description = updateBrandDto.Description;

            await _brandRepository.UpdateAsync(brand);
            return MapToDto(brand);
        }

        public async Task<bool> DeleteBrandAsync(int id)
        {
            var brand = await _brandRepository.GetByIdAsync(id);
            if (brand == null)
                return false;

            await _brandRepository.DeleteAsync(id);
            return true;
        }
        private BrandDto MapToDto(Brand brand) => new BrandDto
        {
            Id = brand.Id,
            Name = brand.Name,
            Description = brand.Description
        };
    }
}