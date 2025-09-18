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
        Task<IEnumerable<Model>> GetAllModelsAsync(int id);
    }

    public class BrandRepository : IBrandRepository
    {
        private readonly AppDbContext _context;

        public BrandRepository(AppDbContext context)
        {
            _context = context;
        }

        public async Task<IEnumerable<Brand>> GetAllAsync()
        {
            return await _context.Brands.ToListAsync();
        }

        public async Task<Brand?> GetByIdAsync(int id)
        {
            return await _context.Brands.FindAsync(id);
        }

        public async Task AddAsync(Brand brand)
        {
            brand.CreatedAt = DateTime.UtcNow;
            brand.UpdatedAt = DateTime.UtcNow;
            await _context.Brands.AddAsync(brand);
            await _context.SaveChangesAsync();
        }
        public async Task<IEnumerable<Model>> GetAllModelsAsync(int id)
        {
            return await _context.Brands
                .Where(b => b.Id == id)
                .Include(b => b.Models)
                .SelectMany(b => b.Models)
                .ToListAsync();
        }

        public async Task UpdateAsync(Brand brand)
        {
            brand.UpdatedAt = DateTime.UtcNow;
            _context.Brands.Update(brand);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteAsync(int id)
        {
            var brand = await _context.Brands.FindAsync(id);
            if (brand != null)
            {
                _context.Brands.Remove(brand);
                await _context.SaveChangesAsync();
            }
        }

        public async Task<bool> BrandExistsAsync(string name)
        {
            return await _context.Brands.AnyAsync(b => b.Name == name);
        }
    }
}
