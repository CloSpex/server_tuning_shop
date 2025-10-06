using TuningStore.Models;
using TuningStore.Data;
using Microsoft.EntityFrameworkCore;
namespace TuningStore.Repositories
{
    public interface IPartRepository
    {
        Task<IEnumerable<Part>> GetAllAsync();
        Task<Part?> GetByIdAsync(int id);
        Task<Part> CreateAsync(Part part);
        Task<Part?> UpdateAsync(Part part);
        Task<bool> DeleteAsync(int id);
        Task<bool> CategoryExistsAsync(int categoryId);
        Task<bool> SpecificationExistsAsync(int specificationId);
        Task<IEnumerable<Part>> GetPartsByCategoryAsync(int categoryId);
        Task<IEnumerable<Part>> GetPartsBySpecificationAsync(int specificationId);
    }

    public class PartRepository : IPartRepository
    {
        private readonly AppDbContext _context;
        private readonly DbSet<Part> _parts;

        public PartRepository(AppDbContext context)
        {
            _context = context;
            _parts = context.Set<Part>();
        }

        public async Task<IEnumerable<Part>> GetAllAsync()
        {
            return await _parts.ToListAsync();
        }

        public async Task<Part?> GetByIdAsync(int id)
        {
            return await _parts.FindAsync(id);
        }

        public async Task<Part> CreateAsync(Part part)
        {
            part.CreatedAt = DateTime.UtcNow;
            part.UpdatedAt = DateTime.UtcNow;
            _parts.Add(part);
            await _context.SaveChangesAsync();
            return part;
        }

        public async Task<Part?> UpdateAsync(Part part)
        {
            var existingPart = await _context.Parts.FindAsync(part.Id);
            if (existingPart == null)
                return null;

            existingPart.Name = part.Name;
            existingPart.Price = part.Price;
            existingPart.Quantity = part.Quantity;
            existingPart.ImagePath = part.ImagePath;
            existingPart.CarSpecificationId = part.CarSpecificationId;
            existingPart.Color = part.Color;
            existingPart.PartCategoryId = part.PartCategoryId;
            existingPart.IsViewed = part.IsViewed;
            existingPart.UpdatedAt = DateTime.UtcNow;

            await _context.SaveChangesAsync();
            return existingPart;
        }

        public async Task<bool> DeleteAsync(int id)
        {
            var part = await _parts.FindAsync(id);
            if (part == null)
                return false;

            _parts.Remove(part);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> CategoryExistsAsync(int categoryId)
        {
            return await _parts.AnyAsync(c => c.PartCategoryId == categoryId);
        }

        public async Task<bool> SpecificationExistsAsync(int specificationId)
        {
            return await _parts.AnyAsync(s => s.CarSpecificationId == specificationId);
        }
        public async Task<IEnumerable<Part>> GetPartsByCategoryAsync(int categoryId)
        {
            return await _parts
                .Where(p => p.PartCategoryId == categoryId)
                .ToListAsync();
        }
        public async Task<IEnumerable<Part>> GetPartsBySpecificationAsync(int specificationId)
        {
            return await _parts
                .Where(p => p.CarSpecificationId == specificationId)
                .ToListAsync();
        }
    }
}