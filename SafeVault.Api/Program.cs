using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Api.Services;

internal class Program
{
  private static void Main(string[] args)
  {
    var builder = WebApplication.CreateBuilder(args);

    //controllers
    builder.Services.AddControllers();

    //nuestros servicios
    builder.Services.AddScoped<IInputSanitizer, InputSanitizer>();
    builder.Services.AddScoped<IUserRepository, UserRepository>();
    builder.Services.AddScoped<IPasswordHasher, BcryptPasswordHasher>();
    builder.Services.AddScoped<IAuthService, AuthService>();

    //configuración JWT
    var jwtSection = builder.Configuration.GetSection("JwtSettings");
    var key = System.Text.Encoding.UTF8.GetBytes(jwtSection["Key"]!);

    builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
     .AddJwtBearer(options =>
     {
       options.TokenValidationParameters = new TokenValidationParameters
       {
         ValidateIssuer = true,
         ValidateAudience = true,
         ValidateIssuerSigningKey = true,
         ValidIssuer = jwtSection["Issuer"],
         ValidAudience = jwtSection["Audience"],
         IssuerSigningKey = new SymmetricSecurityKey(key)
       };
     });

    builder.Services.AddAuthorization(options =>
    {
      options.AddPolicy("AdminOnly",
          policy => policy.RequireRole("admin"));
    });

    var app = builder.Build();

    app.UseHttpsRedirection();
    app.UseDefaultFiles();
    app.UseStaticFiles();

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapControllers();

    app.Run();
  }
}