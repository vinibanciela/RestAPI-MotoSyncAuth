namespace MotoSyncAuth.DTOs;

/// <summary>
/// Representa uma resposta de erro padrão, que pode incluir links para ações subsequentes.
/// </summary>
/// <param name="Message">A mensagem de erro descritiva.</param>
public record ErrorResponse(string Message)
{
    /// <summary>
    /// Lista de links HATEOAS para possíveis ações de correção (ex: "forgot-password").
    /// </summary>
    public List<LinkDto> Links { get; set; } = new();
}