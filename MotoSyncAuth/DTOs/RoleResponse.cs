namespace MotoSyncAuth.DTOs;

/// <summary>
/// Representa os dados de um cargo retornados pela API.
/// </summary>
/// <param name="Id">ID único do cargo.</param>
/// <param name="Name">Nome do cargo.</param>
public record RoleResponse(int Id, string Name);