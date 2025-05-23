namespace MotoSyncAuth.Models;

public class User
{
    public int Id { get; set; }

    public string Username { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;

    public string PasswordHash { get; set; } = string.Empty;

    // Token de atualização (simulado, opcional para depois)
    public string? RefreshToken { get; set; }
    public DateTime? RefreshTokenExpiration { get; set; }

    // Reset de senha (simulado, opcional para depois)
    public string? PasswordResetToken { get; set; }
    public DateTime? PasswordResetTokenExpiration { get; set; }

    // Relacionamento com a Role (cargo)
    public int RoleId { get; set; }
    public Role? Role { get; set; }
}