using System.ComponentModel.DataAnnotations;

namespace SafeVault.Api.Models
{
  public class RegisterRequest
  {
    [Required, StringLength(100, MinimumLength = 3)]
    public string Username { get; set; } = string.Empty;

    [Required, EmailAddress, StringLength(100)]
    public string Email { get; set; } = string.Empty;

    [Required, StringLength(100, MinimumLength = 6)]
    public string Password { get; set; } = string.Empty;

    public string Role { get; set; } = "user"; // opcional
  }

  public class LoginRequest
  {
    [Required]
    public string Username { get; set; } = string.Empty;

    [Required]
    public string Password { get; set; } = string.Empty;
  }

  public class AuthResponse
  {
    public string Token { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
  }
}
