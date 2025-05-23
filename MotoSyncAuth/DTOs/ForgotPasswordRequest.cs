namespace MotoSyncAuth.DTOs;

// DTO usado para enviar o e-mail de redefinição de senha
public record ForgotPasswordRequest(string Email);