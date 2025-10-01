using Microsoft.EntityFrameworkCore;

namespace MotoSyncAuth.Data;

// DbContext específico para o provedor SQL Server (Azure SQL)
public class AzureDbContext : AppDbContextBase
{
    public AzureDbContext(DbContextOptions<AzureDbContext> options) : base(options) { }
}