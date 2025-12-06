using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Api.Models;
using SafeVault.Api.Services;

namespace SafeVault.Api.Controllers
{
  [ApiController]
  [Route("auth")]
  public class AuthController : ControllerBase
  {
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
      _authService = authService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromForm] RegisterRequest request)
    {
      if (!ModelState.IsValid)
        return BadRequest(ModelState);

      var result = await _authService.RegisterAsync(request);

      if (result is null)
        return Conflict("User already exists.");

      return Ok(result);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
      if (!ModelState.IsValid)
        return BadRequest(ModelState);

      var result = await _authService.LoginAsync(request);
      if (result is null)
        return Unauthorized("Invalid username or password.");

      return Ok(result);
    }

    [HttpGet("admin-dashboard")]
    [Authorize(Roles = "admin")]
    public IActionResult GetAdminDashboard()
    {
      return Ok("Welcome, admin! Sensitive data would be here.");
    }
  }
}
