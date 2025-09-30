namespace MotoSyncAuth.DTOs;

/// <summary>
/// Representa os dados de um log de auditoria retornados pela API.
/// </summary>
/// <param name="Id">ID único do registro de log.</param>
/// <param name="UserId">ID do usuário que realizou a ação.</param>
/// <param name="UserEmail">E-mail do usuário associado ao evento.</param>
/// <param name="Action">Ação que foi realizada (ex: "UserLoginSuccess").</param>
/// <param name="Timestamp">Data e hora em que o evento ocorreu.</param>
/// <param name="Details">Detalhes adicionais sobre o evento.</param>
public record AuditLogResponse(
    int Id,
    int? UserId,
    string UserEmail,
    string Action,
    DateTime Timestamp,
    string? Details
);