namespace MotoSyncAuth.Models;

public class AuditLog
{
    public int Id { get; set; }
    public int? UserId { get; set; } // ID do usuário que realizou a ação
    public string UserEmail { get; set; } = string.Empty; // Email para fácil identificação (útil em falhas de login)
    public string Action { get; set; } = string.Empty; // Ex: "UserLoginSuccess", "UserCreated"
    public DateTime Timestamp { get; set; } // Data e hora do evento
    public string? Details { get; set; } // Detalhes, como o ID do recurso afetado
}