using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Configuration;
using SafeVault.Api.Models;
using SafeVault.Api.Services;

namespace SafeVault.Tests
{
  [TestFixture]
  public class SecurityRegressionTests
  {
    private IInputSanitizer _sanitizer = null!;

    [SetUp]
    public void Setup()
    {
      _sanitizer = new InputSanitizer();
    }

    // QL injection más agresivo
    [Test]
    public void Sanitizer_Should_Remove_SQLInjection_Patterns()
    {
      var payload = "x'; DROP TABLE Users; UPDATE Users SET Role='admin';--";
      var sanitized = _sanitizer.Sanitize(payload);

      Assert.That(sanitized, Does.Not.Contain("'"));
      Assert.That(sanitized, Does.Not.Contain(";"));
      Assert.That(sanitized, Does.Contain("DROP TABLE")); // queda como texto seguro
    }

    //XSS más elaborado
    [Test]
    public void Sanitizer_Should_Remove_Advanced_XSS()
    {
      var payload = @"<img src=x onerror='alert(1)'><script>alert(2)</script>juan";
      var sanitized = _sanitizer.Sanitize(payload);

      Assert.That(sanitized, Does.Not.Contain("<"));
      Assert.That(sanitized, Does.Not.Contain("script"));
      Assert.That(sanitized, Does.Not.Contain("alert"));
      Assert.That(sanitized, Does.Contain("juan"));
    }

    //Mixto SQLi + XSS
    [Test]
    public void Sanitizer_Should_Handle_Mixed_Attack_Payload()
    {
      var payload = "<script>mal()</script>john'; DROP TABLE Users;--";
      var sanitized = _sanitizer.Sanitize(payload);

      Assert.That(sanitized, Does.Not.Contain("<"));
      Assert.That(sanitized, Does.Not.Contain("'"));
      Assert.That(sanitized, Does.Not.Contain(";"));
      Assert.That(sanitized, Does.Contain("john"));
    }
  }

  [TestFixture]
  public class AuthServiceTests
  {
    private AuthService _authService = null!;
    private FakeUserRepository _userRepository = null!;

    [SetUp]
    public void Setup()
    {
      _userRepository = new FakeUserRepository();
      var hasher = new BcryptPasswordHasher();
      var configuration = BuildTestConfiguration();

      _authService = new AuthService(_userRepository, hasher, configuration);
    }

    [Test]
    public async Task Register_NewUser_Should_ReturnToken_And_PersistUser()
    {
      var request = new RegisterRequest
      {
        Username = "juanma",
        Email = "juanma@example.com",
        Password = "SuperSecret123!",
        Role = "admin"
      };

      var result = await _authService.RegisterAsync(request);

      Assert.That(result, Is.Not.Null);
      Assert.That(result!.Username, Is.EqualTo("juanma"));
      Assert.That(result.Role, Is.EqualTo("admin"));
      Assert.That(result.Token, Is.Not.Empty);

      // Comprobamos que el usuario se ha guardado en el repo fake
      var stored = await _userRepository.GetUserByUsernameAsync("juanma");
      Assert.That(stored, Is.Not.Null);
      Assert.That(stored!.Email, Is.EqualTo("juanma@example.com"));
      Assert.That(stored.Role, Is.EqualTo("admin"));

      // La contraseña debe estar hasheada (no en claro)
      Assert.That(stored.PasswordHash, Is.Not.EqualTo("SuperSecret123!"));
      Assert.That(stored.PasswordHash, Is.Not.Empty);
    }

    // 🔹 Registro de usuario ya existente → null (conflict)
    [Test]
    public async Task Register_ExistingUser_Should_ReturnNull()
    {
      // Creamos primero un usuario
      await _userRepository.CreateUserWithPasswordAsync(
          "juanma",
          "juanma@example.com",
          "hash",
          "user");

      var request = new RegisterRequest
      {
        Username = "juanma",
        Email = "otro@example.com",
        Password = "OtroPass123!"
      };

      var result = await _authService.RegisterAsync(request);

      Assert.That(result, Is.Null);
    }

    // 🔹 Login correcto → devuelve token y rol
    [Test]
    public async Task Login_ValidCredentials_Should_ReturnToken()
    {
      // Preparamos usuario con hash real
      var hasher = new BcryptPasswordHasher();
      var hash = hasher.HashPassword("SuperSecret123!");

      await _userRepository.CreateUserWithPasswordAsync(
          "juanma",
          "juanma@example.com",
          hash,
          "admin");

      var request = new LoginRequest
      {
        Username = "juanma",
        Password = "SuperSecret123!"
      };

      var result = await _authService.LoginAsync(request);

      Assert.That(result, Is.Not.Null);
      Assert.That(result!.Username, Is.EqualTo("juanma"));
      Assert.That(result.Role, Is.EqualTo("admin"));
      Assert.That(result.Token, Is.Not.Empty);
    }

    // 🔹 Login con usuario inexistente → null
    [Test]
    public async Task Login_UnknownUser_Should_ReturnNull()
    {
      var request = new LoginRequest
      {
        Username = "noexisto",
        Password = "whatever"
      };

      var result = await _authService.LoginAsync(request);

      Assert.That(result, Is.Null);
    }

    // 🔹 Login con password incorrecto → null
    [Test]
    public async Task Login_WrongPassword_Should_ReturnNull()
    {
      // Usuario existe, pero password no coincide
      var hasher = new BcryptPasswordHasher();
      var hash = hasher.HashPassword("CorrectPass123!");

      await _userRepository.CreateUserWithPasswordAsync(
          "juanma",
          "juanma@example.com",
          hash,
          "user");

      var request = new LoginRequest
      {
        Username = "juanma",
        Password = "WrongPass!"
      };

      var result = await _authService.LoginAsync(request);

      Assert.That(result, Is.Null);
    }

    // 🔹 Token de un admin contiene el rol "admin"
    [Test]
    public async Task Token_ForAdmin_Should_ContainAdminRoleClaim()
    {
      var request = new RegisterRequest
      {
        Username = "adminUser",
        Email = "admin@example.com",
        Password = "AdminPass123!",
        Role = "admin"
      };

      var result = await _authService.RegisterAsync(request);

      Assert.That(result, Is.Not.Null);
      var tokenString = result!.Token;

      var handler = new JwtSecurityTokenHandler();
      var token = handler.ReadJwtToken(tokenString);

      var roleClaim = token.Claims.FirstOrDefault(c =>
          c.Type == ClaimTypes.Role || c.Type == "role");

      Assert.That(roleClaim, Is.Not.Null);
      Assert.That(roleClaim!.Value, Is.EqualTo("admin"));
    }

    // 🔹 Token de un usuario normal contiene el rol "user"
    [Test]
    public async Task Token_ForNormalUser_Should_ContainUserRoleClaim()
    {
      var request = new RegisterRequest
      {
        Username = "normalUser",
        Email = "user@example.com",
        Password = "UserPass123!",
        Role = "user"
      };

      var result = await _authService.RegisterAsync(request);

      Assert.That(result, Is.Not.Null);
      var tokenString = result!.Token;

      var handler = new JwtSecurityTokenHandler();
      var token = handler.ReadJwtToken(tokenString);

      var roleClaim = token.Claims.FirstOrDefault(c =>
          c.Type == ClaimTypes.Role || c.Type == "role");

      Assert.That(roleClaim, Is.Not.Null);
      Assert.That(roleClaim!.Value, Is.EqualTo("user"));
    }

    // ----------------------
    //   Helpers de test
    // ----------------------

    private static IConfiguration BuildTestConfiguration()
    {
      var settings = new Dictionary<string, string?>
      {
        ["JwtSettings:Key"] = "TestKey_123456789012345678901234567890",
        ["JwtSettings:Issuer"] = "SafeVaultTests",
        ["JwtSettings:Audience"] = "SafeVaultTestClients",
        ["JwtSettings:ExpiryMinutes"] = "60"
      };

      return new ConfigurationBuilder()
          .AddInMemoryCollection(settings)
          .Build();
    }

    // Fake simple de IUserRepository en memoria
    private class FakeUserRepository : IUserRepository
    {
      private readonly Dictionary<string, UserAccount> _users =
          new(StringComparer.OrdinalIgnoreCase);

      public Task InsertUserAsync(string username, string email)
      {
        // Para compatibilidad con la Activity 1,
        // aquí podríamos crear un usuario sin password ni rol.
        if (!_users.ContainsKey(username))
        {
          _users[username] = new UserAccount
          {
            UserID = _users.Count + 1,
            Username = username,
            Email = email,
            Role = "user",
            PasswordHash = string.Empty
          };
        }

        return Task.CompletedTask;
      }

      public Task<bool> UserExistsAsync(string username)
      {
        return Task.FromResult(_users.ContainsKey(username));
      }

      public Task CreateUserWithPasswordAsync(string username, string email, string passwordHash, string role)
      {
        _users[username] = new UserAccount
        {
          UserID = _users.Count + 1,
          Username = username,
          Email = email,
          PasswordHash = passwordHash,
          Role = role
        };

        return Task.CompletedTask;
      }

      public Task<UserAccount?> GetUserByUsernameAsync(string username)
      {
        _users.TryGetValue(username, out var user);
        return Task.FromResult(user);
      }
    }
  }
}
