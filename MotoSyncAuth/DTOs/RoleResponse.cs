namespace MotoSyncAuth.DTOs;

/// <summary>
/// Representa os dados de um cargo retornados pela API.
/// </summary>
/// <param name="Id">ID único do cargo.</param>
/// <param name="Name">Nome do cargo.</param>
public record RoleResponse(int Id, string Name)
{
    /// <summary>
    /// Lista de links HATEOAS para ações possíveis com este cargo.
    /// </summary>
    public List<LinkDto> Links { get; set; } = new();
}