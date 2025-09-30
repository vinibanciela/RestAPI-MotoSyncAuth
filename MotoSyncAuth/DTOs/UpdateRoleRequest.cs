namespace MotoSyncAuth.DTOs;

/// <summary>
/// Representa os dados para a atualização de um cargo existente.
/// </summary>
/// <param name="Name">Novo nome para o cargo.</param>
public record UpdateRoleRequest(string Name);