using Microsoft.EntityFrameworkCore;
using MotoSyncAuth.Models; // Importa os Models que representam as tabelas
using MotoSyncAuth.Services; // Importa o SecurityService para hashear a senha padrão

namespace MotoSyncAuth.Data
{
    // Esta classe foi refatorada para ser uma classe base abstrata.
    // Ela contém toda a lógica comum do DbContext que será compartilhada
    // entre as implementações específicas para PostgreSQL e SQL Server.
    public abstract class AppDbContextBase : DbContext
    {
        // Construtor protegido que recebe as opções de configuração do provedor específico.
        protected AppDbContextBase(DbContextOptions options) : base(options)
        {
        }

        // Define os DbSets que representam as tabelas no banco
        public DbSet<User> Usuarios { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }

        // Configurações adicionais (mapeamento de tabelas, nomes, etc.)
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // É importante chamar o método base primeiro para garantir que as configurações padrão sejam aplicadas.
            base.OnModelCreating(modelBuilder);

            // Configura a tabela Usuario para mapear a entidade Usuario
            modelBuilder.Entity<User>().ToTable("USUARIO");

            // Configura a tabela Role para mapear a entidade Role
            modelBuilder.Entity<Role>().ToTable("ROLE");

            // Configura a tabela AuditLog para mapear a entidade AuditLog
            modelBuilder.Entity<AuditLog>().ToTable("AUDIT_LOG");

            // --- INÍCIO DO CÓDIGO DE DATA SEEDING ---
            // Esta seção é usada para "semear" o banco de dados com dados iniciais essenciais
            // sempre que uma nova migração for aplicada, garantindo um estado inicial consistente.

            // 1. Seed dos Cargos (Roles): Cria os cargos padrão do sistema.
            modelBuilder.Entity<Role>().HasData(
                new Role { Id = 1, Name = "Administrador" },
                new Role { Id = 2, Name = "Gerente" },
                new Role { Id = 3, Name = "Funcionario" }
            );

            // 2. Seed do Usuário Administrador Padrão: Cria um usuário admin para o primeiro acesso.
            // A senha é hasheada usando um HASH ESTÁTICO.
            const string staticAdminPasswordHash = "$2a$11$4nsFZ2KQaPd40Ri1xwSLXuvCnf4RtbfC2qIuweQmh/ByEKe80CvIy";

            modelBuilder.Entity<User>().HasData(
                new User
                {
                    Id = 1,
                    Username = "admin",
                    Email = "admin@motosync.com",
                    PasswordHash = staticAdminPasswordHash, //usa o hash estático
                    RoleId = 1 // ID correspondente ao cargo "Administrador"
                }
            );
            // --- FIM DO CÓDIGO DE DATA SEEDING ---
        }
    }
}