using Microsoft.EntityFrameworkCore;
using TuningStore.Data;
using TuningStore.Models;

namespace TuningStore.Repositories
{
    public interface IModelRepository
    {
        Task<IEnumerable<Model>> GetAllAsync();
        Task<Model?> GetByIdAsync(int id);
        Task AddAsync(Model model);
        Task UpdateAsync(Model model);
        Task DeleteAsync(int id);
        Task<bool> ModelExistsAsync(string name);
        Task<IEnumerable<Specification>> GetAllSpecificationsAsync();
    }

    public class ModelRepository : IModelRepository
    {
        private readonly AppDbContext _context;

        public ModelRepository(AppDbContext context)
        {
            _context = context;
        }


        public async Task<IEnumerable<Model>> GetAllAsync()
        {
            return await _context.Models.ToListAsync();
        }

        public async Task<Model?> GetByIdAsync(int id)
        {
            return await _context.Models.FindAsync(id);
        }

        public async Task AddAsync(Model model)
        {
            model.CreatedAt = DateTime.UtcNow;
            model.UpdatedAt = DateTime.UtcNow;
            await _context.Models.AddAsync(model);
            await _context.SaveChangesAsync();
        }
        public async Task<IEnumerable<Specification>> GetAllSpecificationsAsync()
        {
            return await _context.Models.Include(m => m.Specifications).SelectMany(m => m.Specifications).ToListAsync();
        }

        public async Task UpdateAsync(Model model)
        {
            model.UpdatedAt = DateTime.UtcNow;
            _context.Models.Update(model);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteAsync(int id)
        {
            var model = await _context.Models.FindAsync(id);
            if (model != null)
            {
                _context.Models.Remove(model);
                await _context.SaveChangesAsync();
            }
        }

        public async Task<bool> ModelExistsAsync(string name)
        {
            return await _context.Models.AnyAsync(m => m.Name == name);
        }
    }
}
