namespace MotoSyncAuth.DTOs;

/// <summary>
/// Representa um link HATEOAS (Hypermedia as the Engine of Application State).
/// </summary>
/// <param name="Href">A URL do recurso.</param>
/// <param name="Rel">A relação do link com o recurso atual (ex: "self", "delete-user").</param>
/// <param name="Method">O método HTTP a ser usado (ex: "GET", "PUT").</param>
public record LinkDto(string Href, string Rel, string Method);