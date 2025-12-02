using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

public interface ICarEnumService<T, TDto, TCreateDto, TUpdateDto>
    where T : class, new()
    where TDto : class
{
    Task<IEnumerable<TDto>> GetAllAsync();
    Task<TDto?> GetByIdAsync(int id);
    Task<TDto> CreateAsync(TCreateDto dto);
    Task<TDto?> UpdateAsync(int id, TUpdateDto dto);
    Task<bool> DeleteAsync(int id);
}

public class CarEnumService<T, TDto, TCreateDto, TUpdateDto> : ICarEnumService<T, TDto, TCreateDto, TUpdateDto>
    where T : class, new()
    where TDto : class
{
    private readonly ICarEnumRepository<T> _repository;
    private readonly Func<T, TDto> _mapToDto;
    private readonly Action<T, TCreateDto> _mapCreate;
    private readonly Action<T, TUpdateDto> _mapUpdate;

    public CarEnumService(
        ICarEnumRepository<T> repository,
        Func<T, TDto> mapToDto,
        Action<T, TCreateDto> mapCreate,
        Action<T, TUpdateDto> mapUpdate)
    {
        _repository = repository;
        _mapToDto = mapToDto;
        _mapCreate = mapCreate;
        _mapUpdate = mapUpdate;
    }

    public async Task<IEnumerable<TDto>> GetAllAsync() =>
        (await _repository.GetAllAsync()).Select(_mapToDto);

    public async Task<TDto?> GetByIdAsync(int id)
    {
        var entity = await _repository.GetByIdAsync(id);
        return entity == null ? null : _mapToDto(entity);
    }

    public async Task<TDto> CreateAsync(TCreateDto dto)
    {
        var entity = new T();
        _mapCreate(entity, dto);
        var created = await _repository.CreateAsync(entity);
        return _mapToDto(created);
    }

    public async Task<TDto?> UpdateAsync(int id, TUpdateDto dto)
    {
        var entity = await _repository.GetByIdAsync(id);
        if (entity == null) return null;
        _mapUpdate(entity, dto);
        await _repository.UpdateAsync(entity);
        return _mapToDto(entity);
    }

    public async Task<bool> DeleteAsync(int id) => await _repository.DeleteAsync(id);
}
