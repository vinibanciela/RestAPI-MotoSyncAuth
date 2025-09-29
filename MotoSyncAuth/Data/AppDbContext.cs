using Microsoft.EntityFrameworkCore;
using MotoSyncAuth.Models; // Importa os Models que representam as tabelas

namespace MotoSyncAuth.Data
{
    public class AppDbContext : DbContext
    {
        // Construtor que recebe as opções de configuração (string de conexão, etc.)
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        // Define os DbSets que representam as tabelas no banco
        public DbSet<User> Usuarios { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }

        // Configurações adicionais (mapeamento de tabelas, nomes, etc.)
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // Configura a tabela Usuario para mapear a entidade Usuario
            modelBuilder.Entity<User>().ToTable("USUARIO");

            // Configura a tabela Role para mapear a entidade Role
            modelBuilder.Entity<Role>().ToTable("ROLE");

            // Configura a tabela Role para mapear a entidade Role
            modelBuilder.Entity<AuditLog>().ToTable("AUDIT_LOG");

            // Adicione outros mapeamentos se necessário, por exemplo:
            // modelBuilder.Entity<OutraEntidade>().ToTable("OUTRA_TABELA");

            base.OnModelCreating(modelBuilder);
        }
    }
}