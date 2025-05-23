namespace MotoSyncAuth.DTOs;

// Requisição de login
public record LoginRequest(string Email, string Password);