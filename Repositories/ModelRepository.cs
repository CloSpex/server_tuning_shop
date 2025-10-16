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
        Task<IEnumerable<Model>> GetByBrandIdAsync(int brandId);

        Task<IEnumerable<Model>> GetModelsByBrandAsync(int id);
    }

    public class ModelRepository : IModelRepository
    {
        private readonly AppDbContext _context;
        private readonly DbSet<Model> _models;

        public ModelRepository(AppDbContext context)
        {
            _context = context;
            _models = context.Set<Model>();
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
            await _models.AddAsync(model);
            await _context.SaveChangesAsync();
        }

        public async Task<IEnumerable<Model>> GetModelsByBrandAsync(int id)
        {
            return await _models.Where(m => m.BrandId == id).ToListAsync();
        }
        public async Task UpdateAsync(Model model)
        {
            var existingModel = await _models.FindAsync(model.Id);
            if (existingModel == null)
                return;
            if (!string.IsNullOrWhiteSpace(model.Name))
                existingModel.Name = model.Name;
            if (existingModel.BrandId != 0)
                existingModel.BrandId = model.BrandId;
            existingModel.UpdatedAt = DateTime.UtcNow;
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
        public async Task<IEnumerable<Model>> GetByBrandIdAsync(int brandId)
        {
            return await _context.Models.Where(m => m.BrandId == brandId).ToListAsync();
        }

        public async Task<bool> ModelExistsAsync(string name)
        {
            return await _context.Models.AnyAsync(m => m.Name == name);
        }
    }
}
