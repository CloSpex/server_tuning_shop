using TuningStore.DTOs;
using TuningStore.Models;
using TuningStore.Repositories;
namespace TuningStore.Services
{
    public interface IFaqService
    {
        Task<IEnumerable<FAQDto>> GetAllFaqsAsync();
        Task<FAQDto?> GetFaqByIdAsync(int id);
        Task<FAQDto> CreateFaqAsync(CreateFAQDto createFaqDto);
        Task<FAQDto?> UpdateFaqAsync(int id, UpdateFAQDto updateFaqDto);
        Task<bool> DeleteFaqAsync(int id);
    }
    public class FaqService : IFaqService
    {
        private readonly IFaqRepository _faqRepository;

        public FaqService(IFaqRepository faqRepository)
        {
            _faqRepository = faqRepository;
        }

        public async Task<IEnumerable<FAQDto>> GetAllFaqsAsync()
        {
            var faqs = await _faqRepository.GetAllAsync();
            return faqs.Select(MapToDto);
        }

        public async Task<FAQDto?> GetFaqByIdAsync(int id)
        {
            var faq = await _faqRepository.GetByIdAsync(id);
            return faq != null ? MapToDto(faq) : null;
        }

        public async Task<FAQDto> CreateFaqAsync(CreateFAQDto createFaqDto)
        {
            if (await _faqRepository.QuestionExistsAsync(createFaqDto.Question))
            {
                throw new InvalidOperationException("FAQ with the same question already exists.");
            }

            var faq = new FAQ
            {
                Question = createFaqDto.Question,
                Answer = createFaqDto.Answer

            };

            await _faqRepository.AddAsync(faq);
            return MapToDto(faq);
        }

        public async Task<FAQDto?> UpdateFaqAsync(int id, UpdateFAQDto updateFaqDto)
        {
            var faq = await _faqRepository.GetByIdAsync(id);
            if (faq == null)
                return null;
            if (!string.IsNullOrWhiteSpace(updateFaqDto.Question) &&
                updateFaqDto.Question != faq.Question &&
                await _faqRepository.QuestionExistsAsync(updateFaqDto.Question))
            {
                throw new InvalidOperationException("FAQ with the same question already exists.");
            }
            await _faqRepository.UpdateAsync(faq);
            return MapToDto(faq);
        }

        public async Task<bool> DeleteFaqAsync(int id)
        {
            var faq = await _faqRepository.GetByIdAsync(id);
            if (faq == null)
                return false;

            await _faqRepository.DeleteAsync(id);
            return true;
        }
        private FAQDto MapToDto(FAQ faq) => new FAQDto
        {
            Question = faq.Question,
            Answer = faq.Answer
        };
    }
}