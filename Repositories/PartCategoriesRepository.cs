using Microsoft.EntityFrameworkCore;
using TuningStore.Data;
using TuningStore.Models;

namespace TuningStore.Repositories
{
    public interface IPartCategoryRepository
    {
        Task<IEnumerable<PartCategory>> GetAllAsync();
        Task<PartCategory?> GetByIdAsync(int id);
        Task<PartCategory> CreateAsync(PartCategory category);
        Task<PartCategory?> UpdateAsync(PartCategory category);
        Task<bool> DeleteAsync(int id);
    }

    public class PartCategoryRepository : IPartCategoryRepository
    {
        private readonly AppDbContext _context;
        private readonly DbSet<PartCategory> _categories;

        public PartCategoryRepository(AppDbContext context)
        {
            _context = context;
            _categories = context.Set<PartCategory>();
        }

        public async Task<IEnumerable<PartCategory>> GetAllAsync() => await _categories.ToListAsync();

        public async Task<PartCategory?> GetByIdAsync(int id) => await _categories.FindAsync(id);

        public async Task<PartCategory> CreateAsync(PartCategory category)
        {
            _categories.Add(category);
            await _context.SaveChangesAsync();
            return category;
        }

        public async Task<PartCategory?> UpdateAsync(PartCategory category)
        {
            var existing = await _categories.FindAsync(category.Id);
            if (existing == null) return null;

            if (!string.IsNullOrWhiteSpace(category.Name))
                existing.Name = category.Name;

            existing.IsExterior = category.IsExterior;

            await _context.SaveChangesAsync();
            return existing;
        }

        public async Task<bool> DeleteAsync(int id)
        {
            var category = await _categories.FindAsync(id);
            if (category == null) return false;

            _categories.Remove(category);
            await _context.SaveChangesAsync();
            return true;
        }
    }
}
