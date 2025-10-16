using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using TuningStore.DTOs;
using TuningStore.Services;

namespace TuningStore.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class BrandController : ControllerBase
    {
        private readonly IBrandService _brandService;

        public BrandController(IBrandService brandService)
        {
            _brandService = brandService;
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<BrandDto>>> GetBrands()
        {
            var brands = await _brandService.GetAllBrandsAsync();
            return Ok(brands);
        }

        [HttpGet("{id}")]
        public async Task<ActionResult<BrandDto>> GetBrand(int id)
        {
            var brand = await _brandService.GetBrandByIdAsync(id);

            if (brand == null)
                return NotFound($"Brand with ID {id} not found.");

            return Ok(brand);
        }

        [HttpPost]
        public async Task<ActionResult<BrandDto>> CreateBrand([FromBody] CreateBrandDto createBrandDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var createdBrand = await _brandService.CreateBrandAsync(createBrandDto);
                return CreatedAtAction(nameof(GetBrand), new { id = createdBrand.Id }, createdBrand);
            }
            catch (InvalidOperationException ex)
            {
                return Conflict(ex.Message);
            }
            catch (Exception ex)
            {
                return StatusCode(500, "An error occurred while creating the brand.");
            }
        }

        [HttpPatch("{id}")]
        public async Task<ActionResult<BrandDto>> UpdateBrand(int id, [FromBody] UpdateBrandDto updateBrandDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var updatedBrand = await _brandService.UpdateBrandAsync(id, updateBrandDto);
                if (updatedBrand == null)
                    return NotFound($"Brand with ID {id} not found.");

                return Ok(updatedBrand);
            }
            catch (InvalidOperationException ex)
            {
                return Conflict(ex.Message);
            }
            catch (Exception ex)
            {
                return StatusCode(500, "An error occurred while updating the brand.");
            }
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteBrand(int id)
        {
            try
            {
                var deleted = await _brandService.DeleteBrandAsync(id);
                if (!deleted)
                    return NotFound($"Brand with ID {id} not found.");

                return NoContent();
            }
            catch (Exception ex)
            {
                return StatusCode(500, "An error occurred while deleting the brand.");
            }
        }
    }
}