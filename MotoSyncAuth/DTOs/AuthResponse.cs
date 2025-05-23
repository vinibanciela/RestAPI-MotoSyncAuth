namespace MotoSyncAuth.DTOs;

// Resposta do login com JWT
public record AuthResponse(string Username, string Token);