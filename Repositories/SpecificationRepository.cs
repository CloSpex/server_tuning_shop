using Microsoft.EntityFrameworkCore;
using TuningStore.Data;
using TuningStore.Models;

namespace TuningStore.Repositories
{
    public interface ISpecificationRepository
    {
        Task<IEnumerable<Specification>> GetAllAsync();
        Task<Specification?> GetByIdAsync(int id);
        Task<IEnumerable<Specification>> GetByModelIdAsync(int modelId);

        Task<IEnumerable<Specification>> GetAllSpecificationsByModelIdAsync(int modelId);
        Task AddAsync(Specification specification);
        Task UpdateAsync(Specification specification);
        Task DeleteAsync(int id);
        Task<bool> ModelExistsAsync(int modelId);
    }

    public class SpecificationRepository : ISpecificationRepository
    {
        private readonly AppDbContext _context;
        private readonly DbSet<Specification> _specifications;

        public SpecificationRepository(AppDbContext context)
        {
            _context = context;
            _specifications = context.Set<Specification>();
        }

        public async Task<IEnumerable<Specification>> GetAllAsync()
        {
            return await _specifications
                .Include(s => s.Model)
                .Include(s => s.EngineType)
                .Include(s => s.TransmissionType)
                .Include(s => s.BodyType)
                .OrderBy(s => s.ModelId)
                .ThenBy(s => s.YearStart)
                .ToListAsync();
        }

        public async Task<Specification?> GetByIdAsync(int id)
        {
            return await _specifications
                .Include(s => s.Model)
                .Include(s => s.EngineType)
                .Include(s => s.TransmissionType)
                .Include(s => s.BodyType)
                .FirstOrDefaultAsync(s => s.Id == id);
        }

        public async Task<IEnumerable<Specification>> GetByModelIdAsync(int modelId)
        {
            return await _specifications
                .Where(s => s.ModelId == modelId)
                .Include(s => s.Model)
                .Include(s => s.EngineType)
                .Include(s => s.TransmissionType)
                .Include(s => s.BodyType)
                .OrderBy(s => s.YearStart)
                .ToListAsync();
        }

        public async Task AddAsync(Specification specification)
        {
            specification.CreatedAt = DateTime.UtcNow;
            specification.UpdatedAt = DateTime.UtcNow;
            await _specifications.AddAsync(specification);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateAsync(Specification specification)
        {
            var existingSpecification = await _specifications.FindAsync(specification.Id);
            if (existingSpecification == null)
                return;
            if (specification.ModelId != 0)
                existingSpecification.ModelId = specification.ModelId;
            if (specification.YearStart != null)
                existingSpecification.YearStart = specification.YearStart;
            if (specification.YearEnd != null)
                existingSpecification.YearEnd = specification.YearEnd;
            if (specification.EngineTypeId != existingSpecification.EngineTypeId)
                existingSpecification.EngineTypeId = specification.EngineTypeId;
            if (specification.TransmissionTypeId != existingSpecification.TransmissionTypeId)
                existingSpecification.TransmissionTypeId = specification.TransmissionTypeId;
            if (specification.BodyTypeId != existingSpecification.BodyTypeId)
                existingSpecification.BodyTypeId = specification.BodyTypeId;
            specification.UpdatedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();
        }
        public async Task<IEnumerable<Specification>> GetAllSpecificationsByModelIdAsync(int modelId)
        {
            return await _specifications.Where(s => s.ModelId == modelId).ToListAsync();
        }
        public async Task DeleteAsync(int id)
        {
            var specification = await _specifications.FindAsync(id);
            if (specification != null)
            {
                _specifications.Remove(specification);
                await _context.SaveChangesAsync();
            }
        }

        public async Task<bool> ModelExistsAsync(int modelId)
        {
            return await _context.Models.AnyAsync(m => m.Id == modelId);
        }

    }
}