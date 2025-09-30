namespace MotoSyncAuth.DTOs;

/// <summary>
/// DTO genérico para encapsular respostas paginadas da API.
/// </summary>
/// <typeparam name="T">O tipo dos itens contidos na página.</typeparam>
/// <param name="Items">A lista de itens da página atual.</param>
/// <param name="PageNumber">O número da página atual que está sendo retornada.</param>
/// <param name="PageSize">A quantidade máxima de itens por página.</param>
/// <param name="TotalCount">O número total de itens disponíveis no banco de dados.</param>
/// <param name="TotalPages">O número total de páginas existentes com base no PageSize.</param>
public record PagedResponse<T>(
    IEnumerable<T> Items,
    int PageNumber,
    int PageSize,
    int TotalCount,
    int TotalPages
)
{
    /// <summary>
    /// Lista de links HATEOAS para navegação na coleção (ex: self, next-page).
    /// </summary>
    public List<LinkDto> Links { get; set; } = new();
}