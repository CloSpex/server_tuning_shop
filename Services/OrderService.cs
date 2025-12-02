using TuningStore.DTOs;
using TuningStore.Models;
using TuningStore.Repositories;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace TuningStore.Services
{
    public interface IOrderService
    {
        Task<IEnumerable<OrderDto>> GetAllOrdersAsync();
        Task<OrderDto?> GetOrderByIdAsync(int id);
        Task<IEnumerable<OrderDto>> GetOrdersForCurrentUserAsync(int userId);
        Task<OrderDto> CreateOrderAsync(CreateOrderDto dto, int createdById);
        Task<OrderDto?> UpdateOrderAsync(int id, UpdateOrderDto dto);
        Task<bool> DeleteOrderAsync(int id);
    }

    public class OrderService : IOrderService
    {
        private readonly IOrderRepository _orderRepository;
        private readonly IPartRepository _partRepository;

        public OrderService(IOrderRepository orderRepository, IPartRepository partRepository)
        {
            _orderRepository = orderRepository;
            _partRepository = partRepository;
        }

        public async Task<IEnumerable<OrderDto>> GetAllOrdersAsync()
        {
            var orders = await _orderRepository.GetAllAsync();
            return orders.Select(MapToDto);
        }

        public async Task<OrderDto?> GetOrderByIdAsync(int id)
        {
            var order = await _orderRepository.GetByIdAsync(id);
            return order != null ? MapToDto(order) : null;
        }

        public async Task<IEnumerable<OrderDto>> GetOrdersForCurrentUserAsync(int userId)
        {
            var orders = await _orderRepository.GetOrdersByUserIdAsync(userId);
            return orders.Select(MapToDto);
        }

        public async Task<OrderDto> CreateOrderAsync(CreateOrderDto dto, int createdById)
        {
            var order = new Order
            {
                Status = "Pending",
                CreatedBy = createdById,
                OrderItems = new List<OrderItem>()
            };

            decimal totalPrice = 0;

            foreach (var itemDto in dto.Items)
            {
                var part = await _partRepository.GetByIdAsync(itemDto.PartId);

                if (part == null || part.Price == null)
                    throw new InvalidOperationException($"Part with ID {itemDto.PartId} not found or has no price.");

                if (part.Quantity == null || part.Quantity.Value < itemDto.Quantity)
                    throw new InvalidOperationException($"Insufficient quantity for part ID {itemDto.PartId}. Available: {part.Quantity ?? 0}");

                var orderItem = new OrderItem
                {
                    PartId = itemDto.PartId,
                    Quantity = itemDto.Quantity,
                    UnitPrice = part.Price.Value
                };

                order.OrderItems.Add(orderItem);
                totalPrice += orderItem.UnitPrice * itemDto.Quantity;

                part.Quantity -= itemDto.Quantity;
                await _partRepository.UpdateAsync(part);
            }

            order.TotalPrice = totalPrice;
            await _orderRepository.CreateAsync(order);
            return MapToDto(order);
        }

        public async Task<OrderDto?> UpdateOrderAsync(int id, UpdateOrderDto dto)
        {
            var existingOrder = await _orderRepository.GetByIdAsync(id);
            if (existingOrder == null)
                return null;

            if (!string.IsNullOrWhiteSpace(dto.Status))
            {
                existingOrder.Status = dto.Status;
            }

            await _orderRepository.UpdateAsync(existingOrder);
            return MapToDto(existingOrder);
        }

        public async Task<bool> DeleteOrderAsync(int id)
        {
            var orderToDelete = await _orderRepository.GetByIdAsync(id);

            if (orderToDelete == null)
            {
                return false;
            }

            var statusRequiresRestock = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Pending",
                "Processing",
                "Shipped",
                "Canceled"
            };

            if (statusRequiresRestock.Contains(orderToDelete.Status))
            {
                await RestockOrderItemsAsync(orderToDelete);
            }

            return await _orderRepository.DeleteAsync(id);
        }

        private async Task RestockOrderItemsAsync(Order order)
        {
            if (order.OrderItems == null)
            {
                return;
            }

            foreach (var item in order.OrderItems)
            {
                var part = await _partRepository.GetByIdAsync(item.PartId);

                if (part != null)
                {
                    part.Quantity = (part.Quantity ?? 0) + item.Quantity;

                    await _partRepository.UpdateAsync(part);
                }
            }
        }

        private OrderDto MapToDto(Order order)
        {
            return new OrderDto
            {
                Id = order.Id,
                OrderDate = order.OrderDate,
                Status = order.Status,
                TotalPrice = order.TotalPrice,
                CreatedBy = order.CreatedBy,
                UpdatedBy = order.UpdatedBy,
                Items = order.OrderItems.Select(oi => new OrderItemDto
                {
                    PartId = oi.PartId,
                    PartName = oi.Part.Name,
                    Quantity = oi.Quantity,
                    UnitPrice = oi.UnitPrice
                })
            };
        }
    }
}