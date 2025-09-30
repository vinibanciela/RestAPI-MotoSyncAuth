namespace MotoSyncAuth.DTOs;

/// <summary>
/// Representa as credenciais para a autenticação de um usuário.
/// </summary>
/// <param name="Email">E-mail de login.</param>
/// <param name="Password">Senha de acesso.</param>
public record LoginRequest(string Email, string Password);