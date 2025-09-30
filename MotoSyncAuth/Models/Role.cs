namespace MotoSyncAuth.Models;

/// <summary>
/// Representa a entidade de um cargo (nível de permissão) no banco de dados.
/// </summary>
public class Role
{
    /// <summary>
    /// ID único do cargo.
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// Nome do cargo (ex: "Administrador", "Gerente").
    /// </summary>
    public string Name { get; set; } = string.Empty;
}