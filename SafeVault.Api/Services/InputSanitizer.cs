using System.Text.RegularExpressions;

namespace SafeVault.Api.Services
{
  public interface IInputSanitizer
  {
    string Sanitize(string? input);
  }

  public class InputSanitizer : IInputSanitizer
  {
    public string Sanitize(string? input)
    {
      if (string.IsNullOrWhiteSpace(input))
        return string.Empty;

      var value = input.Trim();

      // 1) Eliminar etiquetas HTML (incluyendo <script>, <img>, etc.)
      value = Regex.Replace(value, "<.*?>", string.Empty, RegexOptions.Singleline);

      // 2) Eliminar llamadas típicas a funciones JS peligrosas, como alert(...)
      value = Regex.Replace(value, @"alert\s*\([^)]*\)", string.Empty, RegexOptions.IgnoreCase);

      // 3) Eliminar algunos caracteres típicos de inyección
      value = value.Replace("'", string.Empty).Replace("\"", string.Empty).Replace(";", string.Empty);

      return value;
    }
  }
}