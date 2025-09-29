namespace MotoSyncAuth.DTOs;

// DTO de resposta com os dados de um log de auditoria
public record AuditLogResponse(
    int Id,
    int? UserId,
    string UserEmail,
    string Action,
    DateTime Timestamp,
    string? Details
);