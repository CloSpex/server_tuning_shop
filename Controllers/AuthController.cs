using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TuningStore.DTOs;
using TuningStore.Services;

namespace TuningStore.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly IConfiguration _configuration;

        public AuthController(IUserService userService, IConfiguration configuration)
        {
            _userService = userService;
            _configuration = configuration;
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<ActionResult<object>> Login([FromBody] LoginDto loginDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var ipAddress = GetIpAddress();
                var result = await _userService.AuthenticateAsync(loginDto, ipAddress);

                if (result == null)
                    return Unauthorized(new { error = "Invalid username or password." });

                SetRefreshTokenCookie(result.RefreshToken);

                return Ok(new
                {
                    accessToken = result.AccessToken,
                    expiresAt = result.ExpiresAt,
                    user = result.User,
                    message = "Login successful"
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = "An error occurred during authentication.", details = ex.Message });
            }
        }

        [HttpPost("refresh")]
        [AllowAnonymous]
        public async Task<ActionResult> RefreshToken()
        {
            try
            {
                var refreshToken = Request.Cookies["refreshToken"];

                if (!string.IsNullOrEmpty(refreshToken))
                {
                    refreshToken = Uri.UnescapeDataString(refreshToken);
                }

                if (string.IsNullOrEmpty(refreshToken))
                    return Unauthorized(new { error = "No refresh token provided." });

                var authHeader = Request.Headers["Authorization"].FirstOrDefault();
                var accessToken = string.Empty;

                if (authHeader != null && authHeader.StartsWith("Bearer "))
                {
                    accessToken = authHeader.Substring("Bearer ".Length).Trim();
                }

                if (string.IsNullOrEmpty(accessToken))
                    return Unauthorized(new { error = "No access token provided." });

                var ipAddress = GetIpAddress();
                var result = await _userService.RefreshTokenAsync(accessToken, refreshToken, ipAddress);

                if (result == null)
                    return Unauthorized(new { error = "Invalid or expired token. Please login again." });

                SetRefreshTokenCookie(result.RefreshToken);

                return Ok(new
                {
                    accessToken = result.AccessToken,
                    expiresAt = result.ExpiresAt,
                    message = "Token refreshed successfully"
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = "An error occurred while refreshing the token.", details = ex.Message });
            }
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<ActionResult> Logout()
        {
            try
            {
                var refreshToken = Request.Cookies["refreshToken"];

                if (!string.IsNullOrEmpty(refreshToken))
                {
                    var ipAddress = GetIpAddress();
                    await _userService.RevokeTokenAsync(refreshToken, ipAddress);
                }

                Response.Cookies.Delete("refreshToken", new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Path = "/"
                });

                return Ok(new { message = "Logged out successfully." });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = "An error occurred during logout.", details = ex.Message });
            }
        }

        [HttpGet("me")]
        [Authorize]
        public async Task<ActionResult<object>> GetCurrentUser()
        {
            try
            {
                var userIdClaim = User.FindFirst("id")?.Value;
                if (!int.TryParse(userIdClaim, out int userId))
                    return Unauthorized();

                var user = await _userService.GetUserByIdAsync(userId);
                if (user == null)
                    return NotFound();

                return Ok(new { user });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = "An error occurred while fetching user data.", details = ex.Message });
            }
        }

        private void SetRefreshTokenCookie(string refreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(double.Parse(_configuration["Jwt:RefreshTokenExpirationDays"]!)),
                Path = "/"
            };

            Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
        }

        private string? GetIpAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
            {
                return Request.Headers["X-Forwarded-For"].ToString().Split(',')[0].Trim();
            }

            return HttpContext.Connection.RemoteIpAddress?.ToString();
        }
    }
}