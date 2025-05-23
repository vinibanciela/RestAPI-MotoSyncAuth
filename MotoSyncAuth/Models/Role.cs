namespace MotoSyncAuth.Models;

public class Role
{
    public int Id { get; set; }

    public string Name { get; set; } = string.Empty;

    // Uma role pode ter várias permissões
    public ICollection<Permission>? Permissions { get; set; }
}