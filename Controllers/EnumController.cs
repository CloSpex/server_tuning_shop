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
    public async Task<IEnumerable<EngineTypeDto>> GetEngineTypes() => await _engineService.GetAllAsync();

    [HttpGet("enginetypes/{id}")]
    public async Task<ActionResult<EngineTypeDto>> GetEngineTypeById(int id)
    {
        var result = await _engineService.GetByIdAsync(id);
        return result == null ? NotFound() : Ok(result);
    }

    [HttpGet("bodytypes")]
    public async Task<IEnumerable<BodyTypeDto>> GetBodyTypes() => await _bodyService.GetAllAsync();

    [HttpGet("bodytypes/{id}")]
    public async Task<ActionResult<BodyTypeDto>> GetBodyTypeById(int id)
    {
        var result = await _bodyService.GetByIdAsync(id);
        return result == null ? NotFound() : Ok(result);
    }

    [HttpGet("transmissiontypes")]
    public async Task<IEnumerable<TransmissionTypeDto>> GetTransmissionTypes() => await _transService.GetAllAsync();

    [HttpGet("transmissiontypes/{id}")]
    public async Task<ActionResult<TransmissionTypeDto>> GetTransmissionTypeById(int id)
    {
        var result = await _transService.GetByIdAsync(id);  // FIXED
        return result == null ? NotFound() : Ok(result);
    }
}
