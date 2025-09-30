namespace MotoSyncAuth.DTOs;

/// <summary>
/// Representa um link HATEOAS (Hypermedia as the Engine of Application State).
/// </summary>
/// <param name="Href">A URL do recurso ou ação.</param>
/// <param name="Rel">A relação do link com o recurso atual (ex: "self", "delete-user").</param>
/// <param name="Method">O método HTTP a ser usado para a ação (ex: "GET", "POST", "DELETE").</param>
public record LinkDto(string Href, string Rel, string Method);