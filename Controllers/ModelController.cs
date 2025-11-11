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
    public class ModelController : ControllerBase
    {

        private readonly IModelService _modelService;

        public ModelController(IModelService modelService)
        {
            _modelService = modelService;
        }
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult<IEnumerable<ModelDto>>> GetModels()
        {
            var models = await _modelService.GetAllModelsAsync();
            return Ok(models);
        }
        [HttpGet("{id}")]
        [AllowAnonymous]
        public async Task<ActionResult<ModelDto>> GetModel(int id)
        {
            var model = await _modelService.GetModelByIdAsync(id);
            return model != null ? Ok(model) : NotFound();
        }

        [HttpGet("brand/{brandId}")]
        [AllowAnonymous]
        public async Task<ActionResult<IEnumerable<ModelDto>>> GetModelsByBrand(int brandId)
        {
            var models = await _modelService.GetModelsByBrandIdAsync(brandId);
            return Ok(models);
        }
        [HttpPost]
        [Authorize(Policy = AuthorizationPolicies.AdminOnly)]
        public async Task<ActionResult<ModelDto>> CreateModel([FromBody] CreateModelDto createModelDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var model = await _modelService.CreateModelAsync(createModelDto);
            return CreatedAtAction(nameof(GetModel), new { id = model.Id }, model);
        }
        [HttpPatch("{id}")]
        [Authorize(Policy = AuthorizationPolicies.AdminOnly)]
        public async Task<ActionResult<ModelDto>> UpdateModel(int id, [FromBody] UpdateModelDto updateModelDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var model = await _modelService.UpdateModelAsync(id, updateModelDto);
            return model != null ? Ok(model) : NotFound();
        }
        [HttpDelete("{id}")]
        [Authorize(Policy = AuthorizationPolicies.AdminOnly)]
        public async Task<IActionResult> DeleteModel(int id)
        {
            var success = await _modelService.DeleteModelAsync(id);
            return success ? NoContent() : NotFound();
        }
    }
}