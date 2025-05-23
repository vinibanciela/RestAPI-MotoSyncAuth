namespace MotoSyncAuth.DTOs;

// DTO de resposta com dados públicos do usuário
public record UserResponse(int Id, string Username, string Email, string Role);