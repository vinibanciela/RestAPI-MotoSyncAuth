namespace MotoSyncAuth.DTOs;

// DTO usado para redefinir a senha com token
public record ResetPasswordRequest(string Token, string NewPassword);