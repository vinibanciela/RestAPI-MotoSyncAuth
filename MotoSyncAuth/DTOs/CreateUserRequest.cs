namespace MotoSyncAuth.DTOs;

// DTO usado para criação de um novo usuário
public record CreateUserRequest(string Username, string Email, string Password, int RoleId);