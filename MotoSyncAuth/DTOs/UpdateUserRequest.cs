namespace MotoSyncAuth.DTOs;

/// <summary>
/// Representa os dados que podem ser atualizados em um usuário existente. Todos os campos são opcionais.
/// </summary>
/// <param name="Username">Novo nome de usuário.</param>
/// <param name="Email">Novo endereço de e-mail.</param>
/// <param name="Password">Nova senha.</param>
/// <param name="RoleId">Novo ID de cargo.</param>
public record UpdateUserRequest(string? Username, string? Email, string? Password, int? RoleId);