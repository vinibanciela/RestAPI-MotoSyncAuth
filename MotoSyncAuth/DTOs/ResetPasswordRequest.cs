namespace MotoSyncAuth.DTOs;

/// <summary>
/// Representa a requisição para finalizar o processo de redefinição de senha.
/// </summary>
/// <param name="Token">O token de redefinição recebido (ex: por e-mail).</param>
/// <param name="NewPassword">A nova senha desejada.</param>
public record ResetPasswordRequest(string Token, string NewPassword);