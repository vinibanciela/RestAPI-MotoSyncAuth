namespace MotoSyncAuth.DTOs;

// Representa uma resposta de erro padrão, que pode incluir links para ações subsequentes.
public record ErrorResponse(string Message)
{
    public List<LinkDto> Links { get; set; } = new();
}