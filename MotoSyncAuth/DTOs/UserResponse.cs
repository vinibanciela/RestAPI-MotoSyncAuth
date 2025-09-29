namespace MotoSyncAuth.DTOs;

// DTO de resposta com dados públicos do usuário
public record UserResponse(int Id, string Username, string Email, string Role)
{
    // Lista de links HATEOAS para as ações possíveis com este usuário.
    public List<LinkDto> Links { get; set; } = new();
}