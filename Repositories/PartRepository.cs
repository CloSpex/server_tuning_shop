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
            var existingPart = await _parts.FindAsync(part.Id);
            if (existingPart == null)
                return null;

            if (!string.IsNullOrWhiteSpace(part.Name))
                existingPart.Name = part.Name;

            if (part.Price.HasValue)
                existingPart.Price = part.Price;

            if (part.Quantity.HasValue)
                existingPart.Quantity = part.Quantity;

            if (!string.IsNullOrWhiteSpace(part.ImagePath))
                existingPart.ImagePath = part.ImagePath;

            if (part.CarSpecificationId != existingPart.CarSpecificationId)
                existingPart.CarSpecificationId = part.CarSpecificationId;

            if (!string.IsNullOrWhiteSpace(part.Color))
                existingPart.Color = part.Color;

            if (part.PartCategoryId != existingPart.PartCategoryId)
                existingPart.PartCategoryId = part.PartCategoryId;

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