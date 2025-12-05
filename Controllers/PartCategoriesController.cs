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
    public class PartCategoriesController : ControllerBase
    {
        private readonly IPartCategoryService _service;

        public PartCategoriesController(IPartCategoryService service)
        {
            _service = service;
        }

        [HttpGet]
        [AllowAnonymous]
        [ProducesResponseType(typeof(IEnumerable<PartCategoryDto>), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<IEnumerable<PartCategoryDto>>> GetAll()
        {
            var categories = await _service.GetAllCategoriesAsync();
            return Ok(categories);
        }

        [HttpGet("{id}")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(PartCategoryDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
        public async Task<ActionResult<PartCategoryDto>> GetById(int id)
        {
            var category = await _service.GetCategoryByIdAsync(id);
            if (category == null)
                return NotFound($"Category with ID {id} not found.");

            return Ok(category);
        }

        [HttpPost]
        [Authorize(Policy = AuthorizationPolicies.AdminOnly)]
        [ProducesResponseType(typeof(PartCategoryDto), StatusCodes.Status201Created)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<PartCategoryDto>> Create([FromBody] CreatePartCategoryDto dto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var category = await _service.CreateCategoryAsync(dto);
            return CreatedAtAction(nameof(GetById), new { id = category.Id }, category);
        }

        [HttpPatch("{id}")]
        [Authorize(Policy = AuthorizationPolicies.AdminOnly)]
        [ProducesResponseType(typeof(PartCategoryDto), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]

        public async Task<ActionResult<PartCategoryDto>> Update(int id, [FromBody] UpdatePartCategoryDto dto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var category = await _service.UpdateCategoryAsync(id, dto);
            if (category == null)
                return NotFound($"Category with ID {id} not found.");

            return Ok(category);
        }

        [HttpDelete("{id}")]
        [Authorize(Policy = AuthorizationPolicies.AdminOnly)]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> Delete(int id)
        {
            var success = await _service.DeleteCategoryAsync(id);
            if (!success)
                return NotFound($"Category with ID {id} not found.");

            return NoContent();
        }
    }
}
