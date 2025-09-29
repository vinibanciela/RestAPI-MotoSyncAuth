namespace MotoSyncAuth.DTOs;

// DTO genérico para respostas paginadas
public record PagedResponse<T>(
    IEnumerable<T> Items, // A lista de itens da página atual
    int PageNumber,      // O número da página atual
    int PageSize,        // O tamanho da página
    int TotalCount,      // O número total de itens no banco
    int TotalPages       // O número total de páginas
);