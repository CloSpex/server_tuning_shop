using TuningStore.Models;
using TuningStore.Data;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace TuningStore.Repositories
{
    public interface IOrderRepository
    {
        Task<IEnumerable<Order>> GetAllAsync();
        Task<Order?> GetByIdAsync(int id);
        Task<IEnumerable<Order>> GetOrdersByUserIdAsync(int userId);
        Task<Order> CreateAsync(Order order);
        Task<Order?> UpdateAsync(Order order);
        Task<bool> DeleteAsync(int id);
    }

    public class OrderRepository : IOrderRepository
    {
        private readonly AppDbContext _context;
        private readonly DbSet<Order> _orders;

        public OrderRepository(AppDbContext context)
        {
            _context = context;
            _orders = context.Set<Order>();
        }

        private IQueryable<Order> IncludeNavigationProperties(IQueryable<Order> query)
        {
            return query
                .Include(o => o.OrderItems)
                .ThenInclude(oi => oi.Part)
                .Include(o => o.Creator);
        }

        public async Task<IEnumerable<Order>> GetAllAsync()
        {
            return await IncludeNavigationProperties(_orders).ToListAsync();
        }

        public async Task<Order?> GetByIdAsync(int id)
        {
            return await IncludeNavigationProperties(_orders)
                .FirstOrDefaultAsync(o => o.Id == id);
        }

        public async Task<IEnumerable<Order>> GetOrdersByUserIdAsync(int userId)
        {
            return await IncludeNavigationProperties(_orders)
                .Where(o => o.CreatedBy == userId)
                .ToListAsync();
        }

        public async Task<Order> CreateAsync(Order order)
        {
            order.OrderDate = DateTime.UtcNow;
            order.CreatedAt = DateTime.UtcNow;
            order.UpdatedAt = DateTime.UtcNow;

            _orders.Add(order);
            await _context.SaveChangesAsync();
            return order;
        }

        public async Task<Order?> UpdateAsync(Order order)
        {
            var existingOrder = await _orders.FindAsync(order.Id);
            if (existingOrder == null)
                return null;

            if (!string.IsNullOrWhiteSpace(order.Status))
                existingOrder.Status = order.Status;

            existingOrder.UpdatedAt = DateTime.UtcNow;

            await _context.SaveChangesAsync();
            return existingOrder;
        }

        public async Task<bool> DeleteAsync(int id)
        {
            var order = await _orders.FindAsync(id);
            if (order == null)
                return false;

            _orders.Remove(order);
            await _context.SaveChangesAsync();
            return true;
        }
    }
}