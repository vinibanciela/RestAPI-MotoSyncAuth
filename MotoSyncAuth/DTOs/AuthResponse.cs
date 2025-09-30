namespace MotoSyncAuth.DTOs;

/// <summary>
/// Representa a resposta bem-sucedida de um login, contendo o token JWT.
/// </summary>
/// <param name="Username">Nome do usuário autenticado.</param>
/// <param name="Token">Token de acesso JWT.</param>
public record AuthResponse(string Username, string Token);