using Microsoft.AspNetCore.Mvc;
using SafeVault.Api.Models;
using SafeVault.Api.Services;

namespace SafeVault.Api.Controllers
{
  [ApiController]
  public class SafeVaultController : ControllerBase
  {
    private readonly IInputSanitizer _sanitizer;
    private readonly IUserRepository _userRepository;

    public SafeVaultController(IInputSanitizer sanitizer, IUserRepository userRepository)
    {
      _sanitizer = sanitizer;
      _userRepository = userRepository;
    }

    [HttpPost("/submit")]
    public async Task<IActionResult> Submit([FromForm] UserInputDto input)
    {
      if (!ModelState.IsValid)
        return BadRequest(ModelState);

      var safeUsername = _sanitizer.Sanitize(input.Username);
      var safeEmail = _sanitizer.Sanitize(input.Email);

      if (string.IsNullOrEmpty(safeUsername) || string.IsNullOrEmpty(safeEmail))
        return BadRequest("Invalid sanitized input.");

      // Opcional: evitar usuarios duplicados
      var exists = await _userRepository.UserExistsAsync(safeUsername);

      if (exists)
        return Conflict("User already exists.");

      await _userRepository.InsertUserAsync(safeUsername, safeEmail);

      return Ok("User stored securely.");
    }
  }
}
