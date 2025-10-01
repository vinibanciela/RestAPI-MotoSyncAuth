using Microsoft.EntityFrameworkCore;

namespace MotoSyncAuth.Data;

public class PostgresDbContext : AppDbContextBase
{
    public PostgresDbContext(DbContextOptions<PostgresDbContext> options) : base(options) { }
}