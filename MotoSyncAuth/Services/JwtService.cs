using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using MotoSyncAuth.Models;

namespace MotoSyncAuth.Services;

public class JwtService
{
    private readonly byte[] _key;

    // Construtor: lê a chave secreta do appsettings.json via IConfiguration
    public JwtService(IConfiguration config)
    {
        var secret = config["JwtSettings:Secret"];
        if (string.IsNullOrEmpty(secret))
            throw new Exception("JWT Secret não configurado.");
        
        // Converte a chave em bytes para criar o token
        _key = Encoding.ASCII.GetBytes(secret);
    }

    // Gera o token JWT com as informações do usuário
    public string GenerateToken(User user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();

        // Define as informações (claims) que vão dentro do token
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Role, user.Role?.Name ?? "Usuario")
        };

        // Cria as credenciais com a chave e o algoritmo HMAC SHA256
        var credentials = new SigningCredentials(
            new SymmetricSecurityKey(_key),
            SecurityAlgorithms.HmacSha256Signature
        );

        // Define o conteúdo do token: claims, validade, assinatura
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddHours(4), // expira em 4horas
            SigningCredentials = credentials
        };

        // Gera e escreve o token JWT em string
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    // Extrai os dados do usuário a partir do token JWT presente no header da requisição
    public User? ExtractUserFromRequest(HttpContext context)
    {
        // Obtém o cabeçalho Authorization da requisição HTTP
        var authHeader = context.Request.Headers.Authorization.ToString();

        // Se o cabeçalho estiver vazio ou não começar com "Bearer ", retorna null (não autorizado)
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
            return null;

        // Extrai apenas o token, removendo "Bearer " do início
        var token = authHeader["Bearer ".Length..];

        var handler = new JwtSecurityTokenHandler();

        try
        {
            // Define os parâmetros de validação do token
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false, // Não valida o emissor (Issuer)
                ValidateAudience = false, // Não valida o público (Audience)
                ValidateLifetime = true, // Valida a expiração do token
                ValidateIssuerSigningKey = true, // Valida a assinatura do token
                IssuerSigningKey = new SymmetricSecurityKey(_key) // Chave secreta
            };

            // Valida o token e extrai as claims (privilégios do usuário)
            var principal = handler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

            // Extrai os dados (claims) do token válido
            var username = principal.FindFirst(ClaimTypes.Name)?.Value ?? "";
            var email = principal.FindFirst(ClaimTypes.Email)?.Value ?? "";
            var role = principal.FindFirst(ClaimTypes.Role)?.Value ?? "";

            // Retorna um objeto User preenchido com os dados extraídos do token
            return new User
            {
                Username = username,
                Email = email,
                Role = new Role { Name = role }
            };
        }
        catch
        {
            // Se o token for inválido ou expirado, retorna null (não autorizado)
            return null;
        }
    }
}
