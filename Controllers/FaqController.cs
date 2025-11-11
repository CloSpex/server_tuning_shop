using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TuningStore.Authorization.Policies;
using TuningStore.DTOs;
using TuningStore.Services;

namespace TuningStore.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class FaqController : ControllerBase
    {
        private readonly IFaqService _faqService;

        public FaqController(IFaqService faqService)
        {
            _faqService = faqService;
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult<IEnumerable<FAQDto>>> GetFaqs()
        {
            var faqs = await _faqService.GetAllFaqsAsync();
            return Ok(faqs);
        }

        [HttpGet("{id}")]
        [AllowAnonymous]
        public async Task<ActionResult<FAQDto>> GetFaq(int id)
        {
            var faq = await _faqService.GetFaqByIdAsync(id);

            if (faq == null)
                return NotFound($"FAQ with ID {id} not found.");

            return Ok(faq);
        }

        [HttpPost]
        [Authorize(Policy = AuthorizationPolicies.AdminOnly)]
        public async Task<ActionResult<FAQDto>> CreateFaq([FromBody] CreateFAQDto createFaqDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var createdFaq = await _faqService.CreateFaqAsync(createFaqDto);
                return CreatedAtAction(nameof(GetFaq), new { id = createdFaq.Id }, createdFaq);
            }
            catch (InvalidOperationException ex)
            {
                return Conflict(ex.Message);
            }
            catch (Exception ex)
            {
                return StatusCode(500, "An error occurred while creating the FAQ.");
            }
        }

        [HttpPatch("{id}")]
        [Authorize(Policy = AuthorizationPolicies.AdminOnly)]
        public async Task<ActionResult<FAQDto>> UpdateFaq(int id, [FromBody] UpdateFAQDto updateFaqDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var updatedFaq = await _faqService.UpdateFaqAsync(id, updateFaqDto);
                if (updatedFaq == null)
                    return NotFound($"FAQ with ID {id} not found.");

                return Ok(updatedFaq);
            }
            catch (InvalidOperationException ex)
            {
                return Conflict(ex.Message);
            }
            catch (Exception ex)
            {
                return StatusCode(500, "An error occurred while updating the FAQ.");
            }
        }

        [HttpDelete("{id}")]
        [Authorize(Policy = AuthorizationPolicies.AdminOnly)]
        public async Task<IActionResult> DeleteFAQ(int id)
        {
            try
            {
                var deleted = await _faqService.DeleteFaqAsync(id);
                if (!deleted)
                    return NotFound($"FAQ with ID {id} not found.");

                return NoContent();
            }
            catch (Exception ex)
            {
                return StatusCode(500, "An error occurred while deleting the FAQ.");
            }
        }
    }
}