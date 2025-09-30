namespace MotoSyncAuth.DTOs;

/// <summary>
/// Representa os dados necessários para criar um novo usuário.
/// </summary>
/// <param name="Username">Nome de usuário desejado.</param>
/// <param name="Email">Endereço de e-mail único para o novo usuário.</param>
/// <param name="Password">Senha de acesso para o novo usuário.</param>
/// <param name="RoleId">ID do cargo a ser atribuído (1=Admin, 2=Gerente, 3=Funcionário).</param>
public record CreateUserRequest(string Username, string Email, string Password, int RoleId);