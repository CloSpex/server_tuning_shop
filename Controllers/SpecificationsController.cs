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
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status403Forbidden)]
    public class SpecificationsController : ControllerBase
    {
        private readonly ISpecificationService _specificationService;

        public SpecificationsController(ISpecificationService specificationService)
        {
            _specificationService = specificationService;
        }

        [HttpGet]
        [AllowAnonymous]
        [ProducesResponseType(typeof(IEnumerable<SpecificationDto>), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<IEnumerable<SpecificationDto>>> GetSpecifications()
        {
            var specifications = await _specificationService.GetAllSpecificationsAsync();
            return Ok(specifications);
        }
        [HttpGet("{id}")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(SpecificationDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
        public async Task<ActionResult<SpecificationDto>> GetSpecification(int id)
        {
            var specification = await _specificationService.GetSpecificationByIdAsync(id);

            if (specification == null)
                return NotFound($"Specification with ID {id} not found.");

            return Ok(specification);
        }

        [HttpGet("model/{modelId}")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(IEnumerable<SpecificationDto>), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<IEnumerable<SpecificationDto>>> GetSpecificationsByModelId(int modelId)
        {
            var specifications = await _specificationService.GetSpecificationsByModelIdAsync(modelId);
            return Ok(specifications);
        }
        [HttpPost]
        [Authorize(Policy = AuthorizationPolicies.AdminOnly)]
        [ProducesResponseType(typeof(SpecificationDto), StatusCodes.Status201Created)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status409Conflict)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<SpecificationDto>> CreateSpecification(
            [FromBody] CreateSpecificationDto createSpecificationDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var specification = await _specificationService.CreateSpecificationAsync(createSpecificationDto);
                return CreatedAtAction(
                    nameof(GetSpecification),
                    new { id = specification.Id },
                    specification);
            }
            catch (InvalidOperationException ex)
            {
                return Conflict(ex.Message);
            }
            catch (Exception)
            {
                return StatusCode(500, "An error occurred while creating the specification.");
            }
        }

        [HttpPatch("{id}")]
        [Authorize(Policy = AuthorizationPolicies.AdminOnly)]
        [ProducesResponseType(typeof(SpecificationDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status409Conflict)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<SpecificationDto>> UpdateSpecification(
            int id,
            [FromBody] UpdateSpecificationDto updateSpecificationDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var specification = await _specificationService.UpdateSpecificationAsync(id, updateSpecificationDto);

                if (specification == null)
                    return NotFound($"Specification with ID {id} not found.");

                return Ok(specification);
            }
            catch (InvalidOperationException ex)
            {
                return Conflict(ex.Message);
            }
            catch (Exception)
            {
                return StatusCode(500, "An error occurred while updating the specification.");
            }
        }

        [HttpDelete("{id}")]
        [Authorize(Policy = AuthorizationPolicies.AdminOnly)]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> DeleteSpecification(int id)
        {
            try
            {
                var success = await _specificationService.DeleteSpecificationAsync(id);

                if (!success)
                    return NotFound($"Specification with ID {id} not found.");

                return NoContent();
            }
            catch (Exception)
            {
                return StatusCode(500, "An error occurred while deleting the specification.");
            }
        }
    }
}