namespace MotoSyncAuth.Models;

/// <summary>
/// Representa um registro de evento de auditoria no sistema.
/// </summary>
public class AuditLog
{
    /// <summary>
    /// ID único do registro de log.
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// ID do usuário que realizou a ação (pode ser nulo para eventos de sistema ou falhas de login).
    /// </summary>
    public int? UserId { get; set; }

    /// <summary>
    /// E-mail do usuário associado ao evento.
    /// </summary>
    public string UserEmail { get; set; } = string.Empty;

    /// <summary>
    /// Ação que foi realizada (ex: "UserLoginSuccess", "UserCreated").
    /// </summary>
    public string Action { get; set; } = string.Empty;

    /// <summary>
    /// Data e hora em que o evento ocorreu (em UTC).
    /// </summary>
    public DateTime Timestamp { get; set; }

    /// <summary>
    /// Detalhes adicionais sobre o evento (ex: ID do recurso afetado).
    /// </summary>
    public string? Details { get; set; }
}