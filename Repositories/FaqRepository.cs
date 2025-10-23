using Microsoft.EntityFrameworkCore;
using TuningStore.Data;
using TuningStore.Models;

namespace TuningStore.Repositories
{
    public interface IFaqRepository
    {
        Task<IEnumerable<FAQ>> GetAllAsync();
        Task<FAQ?> GetByIdAsync(int id);
        Task AddAsync(FAQ brand);
        Task UpdateAsync(FAQ brand);
        Task DeleteAsync(int id);
        Task<bool> QuestionExistsAsync(string name);
    }

    public class FaqRepository : IFaqRepository
    {
        private readonly AppDbContext _context;
        private readonly DbSet<FAQ> _faqs;
        public FaqRepository(AppDbContext context)
        {
            _context = context;
            _faqs = context.Set<FAQ>();
        }

        public async Task<IEnumerable<FAQ>> GetAllAsync()
        {
            return await _faqs.ToListAsync();
        }

        public async Task<FAQ?> GetByIdAsync(int id)
        {
            return await _faqs.FindAsync(id);
        }

        public async Task AddAsync(FAQ faq)
        {
            faq.CreatedAt = DateTime.UtcNow;
            faq.UpdatedAt = DateTime.UtcNow;
            await _faqs.AddAsync(faq);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateAsync(FAQ faq)
        {
            var existingFaq = await _faqs.FindAsync(faq.Id);
            if (existingFaq == null)
                return;
            if (!string.IsNullOrWhiteSpace(faq.Question))
                existingFaq.Question = faq.Question;
            if (!string.IsNullOrWhiteSpace(faq.Answer))
                existingFaq.Answer = faq.Answer;
            existingFaq.CreatedAt = existingFaq.CreatedAt;
            existingFaq.UpdatedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();
        }

        public async Task DeleteAsync(int id)
        {
            var faq = await _faqs.FindAsync(id);
            if (faq != null)
            {
                _faqs.Remove(faq);
                await _context.SaveChangesAsync();
            }
        }

        public async Task<bool> QuestionExistsAsync(string question)
        {
            return await _faqs.AnyAsync(f => f.Question == question);
        }
    }
}
