namespace MotoSyncAuth.DTOs;

/// <summary>
/// Representa os dados para a criação de um novo cargo.
/// </summary>
/// <param name="Name">Nome do novo cargo.</param>
public record CreateRoleRequest(string Name);