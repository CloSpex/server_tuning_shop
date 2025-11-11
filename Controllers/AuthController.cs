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

        public AuthController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<ActionResult<object>> Login([FromBody] LoginDto loginDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var result = await _userService.AuthenticateAsync(loginDto);
                if (result == null)
                    return Unauthorized("Invalid username or password.");

                Response.Cookies.Append("refreshToken", result.RefreshToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = false,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTime.UtcNow.AddDays(7),
                    Path = "/"
                });

                return Ok(new
                {
                    accessToken = result.AccessToken,
                    expiresAt = result.ExpiresAt,
                    user = result.User,
                    message = "Login successful"
                });
            }
            catch (Exception)
            {
                return StatusCode(500, "An error occurred during authentication.");
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

                var result = await _userService.RefreshTokenAsync(accessToken, refreshToken);
                if (result == null)
                    return Unauthorized(new { error = "Invalid or expired token. Please login again." });

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
                    await _userService.LogoutAsync(refreshToken);
                }

                Response.Cookies.Delete("refreshToken", new CookieOptions
                {
                    HttpOnly = true,
                    Secure = false,
                    SameSite = SameSiteMode.Strict,
                    Path = "/"
                });

                return Ok(new { message = "Logged out successfully." });
            }
            catch (Exception)
            {
                return StatusCode(500, "An error occurred during logout.");
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
            catch (Exception)
            {
                return StatusCode(500, "An error occurred while fetching user data.");
            }
        }
    }
}