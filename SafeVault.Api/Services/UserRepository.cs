using Microsoft.Data.Sqlite;
using SafeVault.Api.Models;

namespace SafeVault.Api.Services
{
  public interface IUserRepository
  {
    Task InsertUserAsync(string username, string email);
    Task<bool> UserExistsAsync(string username);
    Task CreateUserWithPasswordAsync(string username, string email, string passwordHash, string role);
    Task<UserAccount?> GetUserByUsernameAsync(string username);
  }

  public class UserRepository : IUserRepository
  {
    private readonly string _connectionString;

    public UserRepository(IConfiguration configuration)
    {
      _connectionString = configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string not configured.");
    }

    public async Task InsertUserAsync(string username, string email)
    {
      const string sql = @"INSERT INTO Users (Username, Email) VALUES (@Username, @Email);";

      await using var conn = new SqliteConnection(_connectionString);
      await using var cmd = new SqliteCommand(sql, conn);

      //usar parámetros para evitar inyección SQL
      cmd.Parameters.Add("@Username", SqliteType.Text, 100).Value = username;
      cmd.Parameters.Add("@Email", SqliteType.Text, 100).Value = email;

      //abrir conexión y ejecutar
      await conn.OpenAsync();
      await cmd.ExecuteNonQueryAsync();
    }

    public async Task<bool> UserExistsAsync(string username)
    {
      const string sql = @"SELECT COUNT(1)  FROM Users WHERE Username = @Username;";

      await using var conn = new SqliteConnection(_connectionString);
      await using var cmd = new SqliteCommand(sql, conn);

      cmd.Parameters.Add("@Username", SqliteType.Text, 100).Value = username;

      await conn.OpenAsync();
      var count = (Int64)await cmd.ExecuteScalarAsync();

      return count > 0;
    }

    public async Task CreateUserWithPasswordAsync(string username, string email, string passwordHash, string role)
    {
      const string sql = @"INSERT INTO Users (Username, Email, PasswordHash, Role)VALUES ($username, $email, $passwordHash, $role);";

      await using var conn = new SqliteConnection(_connectionString);
      await using var cmd = new SqliteCommand(sql, conn);

      cmd.Parameters.AddWithValue("$username", username);
      cmd.Parameters.AddWithValue("$email", email);
      cmd.Parameters.AddWithValue("$passwordHash", passwordHash);
      cmd.Parameters.AddWithValue("$role", role);

      await conn.OpenAsync();
      await cmd.ExecuteNonQueryAsync();
    }

    public async Task<UserAccount?> GetUserByUsernameAsync(string username)
    {
      const string sql = @" SELECT UserID, Username, Email, PasswordHash, Role FROM Users WHERE Username = $username;";

      await using var conn = new SqliteConnection(_connectionString);
      await using var cmd = new SqliteCommand(sql, conn);

      cmd.Parameters.AddWithValue("$username", username);

      await conn.OpenAsync();
      await using var reader = await cmd.ExecuteReaderAsync();

      if (!await reader.ReadAsync())
        return null;

      return new UserAccount
      {
        UserID = reader.GetInt64(0),
        Username = reader.GetString(1),
        Email = reader.GetString(2),
        PasswordHash = reader.GetString(3),
        Role = reader.GetString(4)
      };
    }
  }
}
