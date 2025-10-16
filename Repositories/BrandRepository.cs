using Microsoft.EntityFrameworkCore;
using TuningStore.Data;
using TuningStore.Models;

namespace TuningStore.Repositories
{
    public interface IBrandRepository
    {
        Task<IEnumerable<Brand>> GetAllAsync();
        Task<Brand?> GetByIdAsync(int id);
        Task AddAsync(Brand brand);
        Task UpdateAsync(Brand brand);
        Task DeleteAsync(int id);
        Task<bool> BrandExistsAsync(string name);
    }

    public class BrandRepository : IBrandRepository
    {
        private readonly AppDbContext _context;
        private readonly DbSet<Brand> _brands;
        public BrandRepository(AppDbContext context)
        {
            _context = context;
            _brands = context.Set<Brand>();
        }

        public async Task<IEnumerable<Brand>> GetAllAsync()
        {
            return await _brands.ToListAsync();
        }

        public async Task<Brand?> GetByIdAsync(int id)
        {
            return await _brands.FindAsync(id);
        }

        public async Task AddAsync(Brand brand)
        {
            brand.CreatedAt = DateTime.UtcNow;
            brand.UpdatedAt = DateTime.UtcNow;
            await _brands.AddAsync(brand);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateAsync(Brand brand)
        {
            var existingBrand = await _brands.FindAsync(brand.Id);
            if (existingBrand == null)
                return;
            if (!string.IsNullOrWhiteSpace(brand.Name))
                existingBrand.Name = brand.Name;
            if (!string.IsNullOrWhiteSpace(brand.Description))
                existingBrand.Description = brand.Description;
            existingBrand.CreatedAt = existingBrand.CreatedAt;
            existingBrand.UpdatedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();
        }

        public async Task DeleteAsync(int id)
        {
            var brand = await _brands.FindAsync(id);
            if (brand != null)
            {
                _brands.Remove(brand);
                await _context.SaveChangesAsync();
            }
        }

        public async Task<bool> BrandExistsAsync(string name)
        {
            return await _brands.AnyAsync(b => b.Name == name);
        }
    }
}
