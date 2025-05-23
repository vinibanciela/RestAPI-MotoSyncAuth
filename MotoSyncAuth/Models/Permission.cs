namespace MotoSyncAuth.Models;

public class Permission
{
    public int Id { get; set; }

    public string Name { get; set; } = string.Empty;

    // Permissões podem estar associadas a várias Roles
    public ICollection<Role>? Roles { get; set; }
}