using System.ComponentModel.DataAnnotations;

namespace SafeVault.Api.Models
{
  public class UserInputDto
  {
    [Required]
    [StringLength(100, MinimumLength = 3)]
    public string Username { get; set; } = string.Empty;

    [Required]
    [EmailAddress]
    [StringLength(100)]
    public string Email { get; set; } = string.Empty;
  }
}
