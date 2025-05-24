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
            Expires = DateTime.UtcNow.AddHours(1), // expira em 1hora
            SigningCredentials = credentials
        };

        // Gera e escreve o token JWT em string
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    // Extrai os dados do usuário a partir do token JWT presente no header da requisição
    public User? ExtractUserFromRequest(HttpContext context)
    {
        // Pega o cabeçalho Authorization: Bearer <token>
        var authHeader = context.Request.Headers.Authorization.ToString();

        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
            return null;

        // Remove "Bearer " e pega o token
        var token = authHeader["Bearer ".Length..];
        var handler = new JwtSecurityTokenHandler();

        try
        {
            // Lê o token JWT
            var jwt = handler.ReadJwtToken(token);

            // Extrai as claims
            var username = jwt.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;
            var email = jwt.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
            var role = jwt.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;

            // Se alguma claim for nula, retorna null
            if (username == null || email == null || role == null)
                return null;

            // Retorna um objeto User preenchido com os dados do token
            return new User
            {
                Username = username,
                Email = email,
                Role = new Role { Name = role }
            };
        }
        catch
        {
            // Token inválido
            return null;
        }
    }
}
