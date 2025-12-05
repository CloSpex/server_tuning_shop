using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TuningStore.Authorization.Policies;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Threading.Tasks;
using TuningStore.DTOs;
using TuningStore.Models;
[ApiController]
[Route("api/[controller]")]
[Authorize]
[ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
[ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status403Forbidden)]
public class CarEnumsController : ControllerBase
{
    private readonly ICarEnumService<EngineType, EngineTypeDto, CreateEngineTypeDto, UpdateEngineTypeDto> _engineService;
    private readonly ICarEnumService<BodyType, BodyTypeDto, CreateBodyTypeDto, UpdateBodyTypeDto> _bodyService;
    private readonly ICarEnumService<TransmissionType, TransmissionTypeDto, CreateTransmissionTypeDto, UpdateTransmissionTypeDto> _transService;

    public CarEnumsController(
        ICarEnumService<EngineType, EngineTypeDto, CreateEngineTypeDto, UpdateEngineTypeDto> engineService,
        ICarEnumService<BodyType, BodyTypeDto, CreateBodyTypeDto, UpdateBodyTypeDto> bodyService,
        ICarEnumService<TransmissionType, TransmissionTypeDto, CreateTransmissionTypeDto, UpdateTransmissionTypeDto> transService)
    {
        _engineService = engineService;
        _bodyService = bodyService;
        _transService = transService;
    }

    [HttpGet("enginetypes")]
    [ProducesResponseType(typeof(IEnumerable<EngineTypeDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
    public async Task<IEnumerable<EngineTypeDto>> GetEngineTypes() => await _engineService.GetAllAsync();

    [HttpGet("enginetypes/{id}")]
    [ProducesResponseType(typeof(EngineTypeDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    public async Task<ActionResult<EngineTypeDto>> GetEngineTypeById(int id)
    {
        var result = await _engineService.GetByIdAsync(id);
        return result == null ? NotFound() : Ok(result);
    }

    [HttpGet("bodytypes")]

    [ProducesResponseType(typeof(IEnumerable<EngineTypeDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
    public async Task<IEnumerable<BodyTypeDto>> GetBodyTypes() => await _bodyService.GetAllAsync();

    [HttpGet("bodytypes/{id}")]
    [ProducesResponseType(typeof(EngineTypeDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    public async Task<ActionResult<BodyTypeDto>> GetBodyTypeById(int id)
    {
        var result = await _bodyService.GetByIdAsync(id);
        return result == null ? NotFound() : Ok(result);
    }

    [HttpGet("transmissiontypes")]

    [ProducesResponseType(typeof(IEnumerable<EngineTypeDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status500InternalServerError)]
    public async Task<IEnumerable<TransmissionTypeDto>> GetTransmissionTypes() => await _transService.GetAllAsync();

    [HttpGet("transmissiontypes/{id}")]
    [ProducesResponseType(typeof(EngineTypeDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    public async Task<ActionResult<TransmissionTypeDto>> GetTransmissionTypeById(int id)
    {
        var result = await _transService.GetByIdAsync(id);
        return result == null ? NotFound() : Ok(result);
    }
}
