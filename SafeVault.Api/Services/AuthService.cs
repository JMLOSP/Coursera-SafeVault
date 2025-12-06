using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Api.Models;

namespace SafeVault.Api.Services
{
  public interface IAuthService
  {
    Task<AuthResponse?> RegisterAsync(RegisterRequest request);
    Task<AuthResponse?> LoginAsync(LoginRequest request);
  }

  public class AuthService : IAuthService
  {
    private readonly IUserRepository _userRepository;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IConfiguration _configuration;

    public AuthService(IUserRepository userRepository,
                       IPasswordHasher passwordHasher,
                       IConfiguration configuration)
    {
      _userRepository = userRepository;
      _passwordHasher = passwordHasher;
      _configuration = configuration;
    }

    public async Task<AuthResponse?> RegisterAsync(RegisterRequest request)
    {
      var exists = await _userRepository.UserExistsAsync(request.Username);
      if (exists) return null;

      var hash = _passwordHasher.HashPassword(request.Password);

      var role = string.IsNullOrWhiteSpace(request.Role) ? "user" : request.Role;

      await _userRepository.CreateUserWithPasswordAsync(
          request.Username,
          request.Email,
          hash,
          role);

      return await GenerateTokenAsync(request.Username, role);
    }

    public async Task<AuthResponse?> LoginAsync(LoginRequest request)
    {
      var user = await _userRepository.GetUserByUsernameAsync(request.Username);
      if (user is null) return null;

      var valid = _passwordHasher.VerifyPassword(request.Password, user.PasswordHash);
      if (!valid) return null;

      return await GenerateTokenAsync(user.Username, user.Role);
    }

    private Task<AuthResponse> GenerateTokenAsync(string username, string role)
    {
      var jwtSection = _configuration.GetSection("JwtSettings");
      var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSection["Key"]!));
      var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

      var claims = new[]
      {
                new Claim(JwtRegisteredClaimNames.Sub, username),
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.Role, role)
            };

      var token = new JwtSecurityToken(
          issuer: jwtSection["Issuer"],
          audience: jwtSection["Audience"],
          claims: claims,
          expires: DateTime.UtcNow.AddMinutes(int.Parse(jwtSection["ExpiryMinutes"]!)),
          signingCredentials: creds
      );

      var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

      return Task.FromResult(new AuthResponse
      {
        Token = tokenString,
        Username = username,
        Role = role
      });
    }
  }
}
