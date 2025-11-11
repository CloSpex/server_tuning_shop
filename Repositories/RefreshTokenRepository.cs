using Microsoft.EntityFrameworkCore;
using TuningStore.Data;
using TuningStore.Models;

namespace TuningStore.Repositories
{
    public interface IRefreshTokenRepository
    {
        Task<RefreshToken?> GetByTokenAsync(string token);
        Task<List<RefreshToken>> GetActiveTokensByUserIdAsync(int userId);
        Task AddAsync(RefreshToken refreshToken);
        Task UpdateAsync(RefreshToken refreshToken);
        Task RevokeAsync(RefreshToken refreshToken, string? ipAddress = null);
        Task RevokeDescendantTokensAsync(RefreshToken refreshToken, string? ipAddress = null);
        Task RemoveOldTokensAsync(int userId, int keepMostRecentCount = 5);
        Task<int> SaveChangesAsync();
    }

    public class RefreshTokenRepository : IRefreshTokenRepository
    {
        private readonly AppDbContext _context;

        public RefreshTokenRepository(AppDbContext context)
        {
            _context = context;
        }

        public async Task<RefreshToken?> GetByTokenAsync(string token)
        {
            return await _context.RefreshTokens
                .Include(rt => rt.User)
                .FirstOrDefaultAsync(rt => rt.Token == token);
        }

        public async Task<List<RefreshToken>> GetActiveTokensByUserIdAsync(int userId)
        {
            return await _context.RefreshTokens
                .Where(rt => rt.UserId == userId && rt.RevokedAt == null && rt.ExpiresAt > DateTime.UtcNow)
                .OrderByDescending(rt => rt.CreatedAt)
                .ToListAsync();
        }

        public async Task AddAsync(RefreshToken refreshToken)
        {
            await _context.RefreshTokens.AddAsync(refreshToken);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateAsync(RefreshToken refreshToken)
        {
            _context.RefreshTokens.Update(refreshToken);
            await _context.SaveChangesAsync();
        }

        public async Task RevokeAsync(RefreshToken refreshToken, string? ipAddress = null)
        {
            refreshToken.RevokedAt = DateTime.UtcNow;
            refreshToken.RevokedByIp = ipAddress;
            await UpdateAsync(refreshToken);
        }

        public async Task RevokeDescendantTokensAsync(RefreshToken refreshToken, string? ipAddress = null)
        {
            if (string.IsNullOrEmpty(refreshToken.ReplacedByToken))
                return;

            var childToken = await GetByTokenAsync(refreshToken.ReplacedByToken);
            if (childToken != null && childToken.IsActive)
            {
                await RevokeAsync(childToken, ipAddress);
                await RevokeDescendantTokensAsync(childToken, ipAddress);
            }
        }

        public async Task RemoveOldTokensAsync(int userId, int keepMostRecentCount = 5)
        {
            var tokens = await _context.RefreshTokens
                .Where(rt => rt.UserId == userId)
                .OrderByDescending(rt => rt.CreatedAt)
                .ToListAsync();

            var cutoffDate = DateTime.UtcNow.AddDays(-30);

            var tokensToRemove = tokens.Where(rt =>
                (rt.IsExpired && rt.ExpiresAt < cutoffDate) ||
                (rt.IsRevoked && rt.RevokedAt < cutoffDate) ||
                (tokens.IndexOf(rt) >= keepMostRecentCount && !rt.IsActive)
            ).ToList();


            if (tokensToRemove.Any())
            {
                _context.RefreshTokens.RemoveRange(tokensToRemove);
                await _context.SaveChangesAsync();
            }
        }

        public async Task<int> SaveChangesAsync()
        {
            return await _context.SaveChangesAsync();
        }
    }
}
