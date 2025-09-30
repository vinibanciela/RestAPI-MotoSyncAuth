namespace MotoSyncAuth.DTOs;

/// <summary>
/// Representa a requisição para iniciar o processo de redefinição de senha.
/// </summary>
/// <param name="Email">E-mail do usuário que esqueceu a senha.</param>
public record ForgotPasswordRequest(string Email);