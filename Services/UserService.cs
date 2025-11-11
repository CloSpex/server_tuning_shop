using TuningStore.DTOs;
using TuningStore.Models;
using TuningStore.Repositories;
using BCrypt.Net;

namespace TuningStore.Services
{
    public interface IUserService
    {
        Task<IEnumerable<UserDto>> GetAllUsersAsync();
        Task<UserDto?> GetUserByIdAsync(int id);
        Task<UserDto?> GetUserByUsernameAsync(string username);
        Task<UserDto?> GetUserByEmailAsync(string email);
        Task<UserDto> CreateUserAsync(CreateUserDto createUserDto);
        Task<UserDto?> UpdateUserAsync(int id, UpdateUserDto updateUserDto);
        Task<bool> DeleteUserAsync(int id);
        Task<LoginResponseDto?> AuthenticateAsync(LoginDto loginDto);
        Task<TokenResponseDto?> RefreshTokenAsync(string accessToken, string refreshToken);
        Task<bool> LogoutAsync(string refreshToken);
    }

    public class UserService : IUserService
    {
        private readonly IUserRepository _userRepository;
        private readonly IJwtService _jwtService;

        public UserService(IUserRepository userRepository, IJwtService jwtService)
        {
            _userRepository = userRepository;
            _jwtService = jwtService;
        }

        public async Task<IEnumerable<UserDto>> GetAllUsersAsync()
        {
            var users = await _userRepository.GetAllAsync();
            return users.Select(MapToDto);
        }

        public async Task<UserDto?> GetUserByIdAsync(int id)
        {
            var user = await _userRepository.GetByIdAsync(id);
            return user != null ? MapToDto(user) : null;
        }

        public async Task<UserDto?> GetUserByUsernameAsync(string username)
        {
            var user = await _userRepository.GetByUsernameAsync(username);
            return user != null ? MapToDto(user) : null;
        }

        public async Task<UserDto?> GetUserByEmailAsync(string email)
        {
            var user = await _userRepository.GetByEmailAsync(email);
            return user != null ? MapToDto(user) : null;
        }

        public async Task<UserDto> CreateUserAsync(CreateUserDto createUserDto)
        {
            if (await _userRepository.UsernameExistsAsync(createUserDto.Username))
            {
                throw new InvalidOperationException("Username already exists.");
            }

            if (await _userRepository.EmailExistsAsync(createUserDto.Email))
            {
                throw new InvalidOperationException("Email already exists.");
            }

            var user = new User
            {
                Username = createUserDto.Username,
                Email = createUserDto.Email,
                Password = BCrypt.Net.BCrypt.HashPassword(createUserDto.Password),
                Role = "User"
            };

            await _userRepository.AddAsync(user);
            return MapToDto(user);
        }

        public async Task<UserDto?> UpdateUserAsync(int id, UpdateUserDto updateUserDto)
        {
            var user = await _userRepository.GetByIdAsync(id);
            if (user == null)
                return null;

            if (!string.IsNullOrEmpty(updateUserDto.Username) &&
                updateUserDto.Username != user.Username)
            {
                if (await _userRepository.UsernameExistsAsync(updateUserDto.Username))
                {
                    throw new InvalidOperationException("Username already exists.");
                }
                user.Username = updateUserDto.Username;
            }

            if (!string.IsNullOrEmpty(updateUserDto.Email) &&
                updateUserDto.Email != user.Email)
            {
                if (await _userRepository.EmailExistsAsync(updateUserDto.Email))
                {
                    throw new InvalidOperationException("Email already exists.");
                }
                user.Email = updateUserDto.Email;
            }

            if (!string.IsNullOrEmpty(updateUserDto.Password))
            {
                user.Password = BCrypt.Net.BCrypt.HashPassword(updateUserDto.Password);
            }

            if (!string.IsNullOrEmpty(updateUserDto.Role))
            {
                user.Role = updateUserDto.Role;
            }

            await _userRepository.UpdateAsync(user);
            return MapToDto(user);
        }

        public async Task<bool> DeleteUserAsync(int id)
        {
            var user = await _userRepository.GetByIdAsync(id);
            if (user == null)
                return false;

            await _userRepository.DeleteAsync(id);
            return true;
        }

        public async Task<LoginResponseDto?> AuthenticateAsync(LoginDto loginDto)
        {
            var user = await _userRepository.GetByUsernameAsync(loginDto.Username);
            if (user == null || !BCrypt.Net.BCrypt.Verify(loginDto.Password, user.Password))
            {
                return null;
            }

            var refreshToken = _jwtService.GenerateRefreshToken();
            var accessToken = _jwtService.GenerateAccessToken(user);

            return new LoginResponseDto
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                ExpiresAt = DateTime.UtcNow.AddMinutes(15),
                User = MapToDto(user)
            };
        }

        public async Task<TokenResponseDto?> RefreshTokenAsync(string accessToken, string refreshToken)
        {
            if (!_jwtService.ValidateRefreshToken(refreshToken))
            {
                return null;
            }

            var principal = _jwtService.GetPrincipalFromToken(accessToken, validateLifetime: false);
            if (principal == null)
            {
                return null;
            }

            var userIdClaim = principal.FindFirst("id") ?? principal.FindFirst("sub");
            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out int userId))
            {
                return null;
            }

            var user = await _userRepository.GetByIdAsync(userId);
            if (user == null)
            {
                return null;
            }
            var newAccessToken = _jwtService.GenerateAccessToken(user);

            return new TokenResponseDto
            {
                AccessToken = newAccessToken,
                RefreshToken = refreshToken,
                ExpiresAt = DateTime.UtcNow.AddMinutes(15)
            };
        }

        public Task<bool> LogoutAsync(string refreshToken)
        {
            return Task.FromResult(_jwtService.ValidateRefreshToken(refreshToken));
        }

        private static UserDto MapToDto(User user)
        {
            return new UserDto
            {
                Id = user.Id,
                Username = user.Username,
                Email = user.Email,
                CreatedAt = user.CreatedAt,
                UpdatedAt = user.UpdatedAt,
                Role = user.Role
            };
        }
    }
}