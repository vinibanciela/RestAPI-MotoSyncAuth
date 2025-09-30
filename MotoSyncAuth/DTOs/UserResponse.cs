namespace MotoSyncAuth.DTOs;

/// <summary>
/// Representa os dados públicos de um usuário retornados pela API.
/// </summary>
/// <param name="Id">ID único do usuário.</param>
/// <param name="Username">Nome de usuário.</param>
/// <param name="Email">Endereço de e-mail.</param>
/// <param name="Role">Nome do cargo do usuário.</param>
public record UserResponse(int Id, string Username, string Email, string Role)
{
    /// <summary>
    /// Lista de links HATEOAS para as ações possíveis com este usuário.
    /// </summary>
    public List<LinkDto> Links { get; set; } = new();
}