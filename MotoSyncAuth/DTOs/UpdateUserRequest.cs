namespace MotoSyncAuth.DTOs;

// DTO usado para atualizar parcialmente um usuário existente
public record UpdateUserRequest(string? Username, string? Email, string? Password, int? RoleId);