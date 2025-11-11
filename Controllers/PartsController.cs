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
    public class PartsController : ControllerBase
    {
        private readonly IPartService _partService;

        public PartsController(IPartService partService)
        {
            _partService = partService;
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult<IEnumerable<PartDto>>> GetParts()
        {
            var parts = await _partService.GetAllPartsAsync();
            return Ok(parts);
        }

        [HttpGet("{id}")]
        [AllowAnonymous]
        public async Task<ActionResult<PartDto>> GetPart(int id)
        {
            var part = await _partService.GetPartByIdAsync(id);

            if (part == null)
                return NotFound($"Part with ID {id} not found.");

            return Ok(part);
        }

        [HttpGet("category/{categoryId}")]
        [AllowAnonymous]
        public async Task<ActionResult<IEnumerable<PartDto>>> GetPartsByCategory(int categoryId)
        {
            var parts = await _partService.GetPartsByCategoryAsync(categoryId);
            return Ok(parts);
        }

        [HttpGet("specification/{specificationId}")]
        [AllowAnonymous]
        public async Task<ActionResult<IEnumerable<PartDto>>> GetPartsBySpecification(int specificationId)
        {
            var parts = await _partService.GetPartsBySpecificationAsync(specificationId);
            return Ok(parts);
        }

        [HttpPost]
        [Authorize(Policy = AuthorizationPolicies.AdminOnly)]
        public async Task<ActionResult<PartDto>> CreatePart([FromBody] CreatePartDto createPartDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var part = await _partService.CreatePartAsync(createPartDto);
                return CreatedAtAction(nameof(GetPart), new { id = part.Id }, part);
            }
            catch (InvalidOperationException ex)
            {
                return Conflict(ex.Message);
            }
            catch (Exception)
            {
                return StatusCode(500, "An error occurred while creating the part.");
            }
        }

        [HttpPatch("{id}")]
        [Authorize(Policy = AuthorizationPolicies.AdminOnly)]
        public async Task<ActionResult<PartDto>> UpdatePart(int id, [FromBody] UpdatePartDto updatePartDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var part = await _partService.UpdatePartAsync(id, updatePartDto);

                if (part == null)
                    return NotFound($"Part with ID {id} not found.");

                return Ok(part);
            }
            catch (InvalidOperationException ex)
            {
                return Conflict(ex.Message);
            }
            catch (Exception)
            {
                return StatusCode(500, "An error occurred while updating the part.");
            }
        }

        [HttpDelete("{id}")]
        [Authorize(Policy = AuthorizationPolicies.AdminOnly)]
        public async Task<IActionResult> DeletePart(int id)
        {
            try
            {
                var success = await _partService.DeletePartAsync(id);

                if (!success)
                    return NotFound($"Part with ID {id} not found.");

                return NoContent();
            }
            catch (Exception)
            {
                return StatusCode(500, "An error occurred while deleting the part.");
            }
        }
    }
}