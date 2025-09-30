namespace MotoSyncAuth.Models;

/// <summary>
/// Representa a entidade de um usuário no banco de dados.
/// </summary>
public class User
{
    /// <summary>
    /// ID único do usuário.
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// Nome de usuário.
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Endereço de e-mail do usuário (usado para login).
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Hash da senha do usuário (gerado com BCrypt).
    /// </summary>
    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>
    /// Token temporário para redefinição de senha.
    /// </summary>
    public string? PasswordResetToken { get; set; }

    /// <summary>
    /// Data e hora de expiração do token de redefinição de senha.
    /// </summary>
    public DateTime? PasswordResetTokenExpiration { get; set; }

    // Relacionamento com a Role (cargo)
    /// <summary>
    /// Chave estrangeira para o cargo (Role) do usuário.
    /// </summary>
    public int RoleId { get; set; }

    /// <summary>
    /// Propriedade de navegação para o cargo (Role) do usuário.
    /// </summary>
    public Role? Role { get; set; }
}