// Imports necessários
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;
using MotoSyncAuth.Services;
using MotoSyncAuth.Models;
using MotoSyncAuth.DTOs;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using MotoSyncAuth.Data;
using Microsoft.EntityFrameworkCore;
using BCrypt.Net;


var builder = WebApplication.CreateBuilder(args);


// -----------------------------------------------------------
// REGISTRO DE SERVIÇOS
// -----------------------------------------------------------

// Swagger (documentação automática da API)
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    // Adiciona esquema de segurança JWT
    options.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Description = "Insira o token JWT no formato: Bearer {token}",
        Name = "Authorization",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    options.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});


// CORS: libera acesso de outras origens (ex: frontend em outra porta)
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});


// Rate Limiting: evita flood de chamadas (ex: brute force no login)
builder.Services.AddRateLimiter(opt =>
{
    opt.AddFixedWindowLimiter("default", options =>
    {
        options.Window = TimeSpan.FromSeconds(10);  // janela de tempo
        options.PermitLimit = 5;                    // máximo 5 requisições
        options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        options.QueueLimit = 2;
    });
});


// Injeção de dependência dos nossos serviços customizados
builder.Services.AddSingleton<JwtService>();    // Gera e valida tokens
//builder.Services.AddSingleton<UserService>();   // Simula usuários em memória (utilizado para testar API sem conexão oracle)


// AppDbContext com conexão para múltiplos provedores conforme o ambiente
builder.Services.AddDbContext<AppDbContext>(options =>
{
    if (builder.Environment.IsDevelopment())
    {
        // Usa PostgreSQL em ambiente de desenvolvimento
        options.UseNpgsql(builder.Configuration.GetConnectionString("PostgresConnection"));
    }
    else
    {
        // Usa SQL Server (Azure SQL) em qualquer outro ambiente (Produção)
        // A Connection String será lida de uma variável de ambiente no Azure
        options.UseSqlServer(builder.Configuration.GetConnectionString("AzureSqlConnection"));
    }
});


// Configura Autenticação JWT (com chave secreta)
builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", options =>
    {
        options.RequireHttpsMetadata = false;
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["JwtSettings:Secret"])
            )
        };
    });


// Configura Autorização (para controle de acesso)
builder.Services.AddAuthorization();

var app = builder.Build();



// -----------------------------------------------------------
// MIDDLEWARES DO PIPELINE HTTP
// -----------------------------------------------------------


// Adiciona a geração de documentação Swagger (OpenAPI) para a API - Disponibiliza o JSON com a especificação da API.
app.UseSwagger(); 

// Configura e habilita a interface do Swagger UI - Por padrão, fica disponível na URL /swagger.
app.UseSwaggerUI(); 

// Configura o ReDoc para documentação alternativa e mais elegante - acessível na rota /redoc, usando o mesmo JSON do Swagger.
app.UseReDoc(c =>
{
    c.RoutePrefix = "redoc"; // Define o prefixo para a rota (padrão: /redoc)
    c.SpecUrl("/swagger/v1/swagger.json"); // Define o caminho para o arquivo JSON do Swagger
});

// Configura o middleware de CORS
app.UseCors("AllowAll");

// Aplica o controle de taxa de requisições (Rate Limiting)
app.UseRateLimiter(); 

// Habilita o middleware de autenticação JWT (Bearer Token) para proteger rotas privadas.
app.UseAuthentication(); 

// Habilita o middleware de autorização para verificar permissões com base no JWT extraído.
app.UseAuthorization(); 




// -----------------------------------------------------------
// ROTAS DE AUTENTICAÇÃO
// -----------------------------------------------------------

var authGroup = app.MapGroup("/auth").WithTags("Autenticação");

// POST /auth/login → Realiza login e retorna JWT
authGroup.MapPost("/login", async (LoginRequest request, AppDbContext dbContext, JwtService jwt) =>
{
    // Busca o usuário no banco pelo e-mail
    var user = await dbContext.Usuarios
        .Include(u => u.Role)
        .FirstOrDefaultAsync(u => u.Email.ToLower() == request.Email.ToLower());

    if (user == null)
        return Results.Unauthorized();

    // Verifica o hash da senha
    var hashedInput = SecurityService.HashPassword(request.Password);
    if (user.PasswordHash != hashedInput)
        return Results.Unauthorized();

    // Gera token JWT
    var token = jwt.GenerateToken(user);
    return Results.Ok(new AuthResponse(user.Username, token));
})
.WithSummary("Login do usuário")
.WithDescription("Autentica o usuário e retorna um token JWT.")
.Produces<AuthResponse>(200)
.Produces(401)
.RequireRateLimiting("default");


// GET /auth/me → Retorna dados do usuário autenticado via token
authGroup.MapGet("/me", (HttpContext http, AppDbContext dbContext, JwtService jwt) =>
{
    // Extrai os dados do token JWT
    var tokenUser = jwt.ExtractUserFromRequest(http);
    if (tokenUser == null)
        return Results.Unauthorized();

    // Busca o usuário no banco de dados pelo e-mail extraído do token
    var user = dbContext.Usuarios
        .Include(u => u.Role)
        .FirstOrDefault(u => u.Email.ToLower() == tokenUser.Email.ToLower());

    if (user == null)
        return Results.Unauthorized();

    return Results.Ok(user);
})
.WithSummary("Dados do usuário logado")
.WithDescription("Retorna os dados do usuário a partir do token JWT.")
.Produces<User>(200)
.Produces(401);


// POST /auth/forgot-password → Gera token de redefinição de senha
authGroup.MapPost("/forgot-password", (ForgotPasswordRequest request, AppDbContext dbContext) =>
{
    // Busca o usuário no banco de dados pelo e-mail informado
    var user = dbContext.Usuarios.FirstOrDefault(u => u.Email.ToLower() == request.Email.ToLower());
    if (user == null)
        return Results.NotFound("Usuário não encontrado.");

    // Gera um token e define a validade (15 minutos)
    user.PasswordResetToken = Guid.NewGuid().ToString();
    user.PasswordResetTokenExpiration = DateTime.UtcNow.AddMinutes(15);

    // Salva as alterações no banco
    dbContext.SaveChanges();

    // OBS: Em uma aplicação real, esse token seria enviado por e-mail
    return Results.Ok("Token de redefinição gerado com sucesso.");
})
.WithSummary("Solicitação de redefinição de senha")
.WithDescription("Gera um token de redefinição de senha para o e-mail informado.")
.Produces<string>(200)
.Produces(404);


// POST /auth/reset-password → Redefine a senha com token
authGroup.MapPost("/reset-password", (ResetPasswordRequest request, AppDbContext dbContext) =>
{
    // Busca o usuário pelo token de redefinição de senha
    var user = dbContext.Usuarios.FirstOrDefault(u =>
        u.PasswordResetToken == request.Token &&
        u.PasswordResetTokenExpiration.HasValue &&
        u.PasswordResetTokenExpiration > DateTime.UtcNow
    );

    if (user == null)
        return Results.BadRequest("Token inválido ou expirado.");

    // Atualiza a senha com o hash da nova senha
    user.PasswordHash = SecurityService.HashPassword(request.NewPassword);

    // Limpa o token de redefinição e sua expiração
    user.PasswordResetToken = null;
    user.PasswordResetTokenExpiration = null;

    // Salva as alterações no banco
    dbContext.SaveChanges();

    return Results.Ok("Senha redefinida com sucesso.");
})
.WithSummary("Redefinir senha")
.WithDescription("Permite redefinir a senha com um token válido.")
.Produces<string>(200)
.Produces(400);



// -----------------------------------------------------------
// ROTAS DE GESTÃO DE USUÁRIOS
// -----------------------------------------------------------

var userGroup = app.MapGroup("/users").WithTags("Usuários");

// GET /users → Lista todos os usuários
userGroup.MapGet("/", (HttpContext http, AppDbContext dbContext, JwtService jwt) =>
{
    // Extrai o usuário autenticado a partir do token JWT
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    // Obtém todos os usuários do banco com suas roles
    var users = dbContext.Usuarios.Include(u => u.Role).AsQueryable();

    if (user.Role?.Name == "Administrador")
    {
        // Se for Administrador, retorna todos os usuários
        var response = users.Select(u => new UserResponse(u.Id, u.Username, u.Email, u.Role!.Name));
        return Results.Ok(response);
    }
    else if (user.Role?.Name == "Gerente")
    {
        // Se for Gerente, retorna apenas Gerentes e Funcionários
        var response = users
            .Where(u => u.Role!.Name == "Gerente" || u.Role!.Name == "Funcionario")
            .Select(u => new UserResponse(u.Id, u.Username, u.Email, u.Role!.Name));
        return Results.Ok(response);
    }
    else
    {
        // Funcionário Administrativo não tem permissão para listar usuários
        return Results.Forbid();
    }
})
.WithSummary("Listar usuários")
.WithDescription("Administrador vê todos. Gerente vê Gerentes e Funcionários. Funcionário não vê ninguém.")
.Produces<IEnumerable<UserResponse>>(200)
.Produces(401)
.Produces(403);


// GET /users/{id} → Retorna um usuário específico por ID
userGroup.MapGet("/{id}", (int id, HttpContext http, AppDbContext dbContext, JwtService jwt) =>
{
    // Extrai o usuário autenticado a partir do token JWT
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    // Busca o usuário alvo pelo ID no banco, incluindo a Role
    var targetUser = dbContext.Usuarios.Include(u => u.Role).FirstOrDefault(u => u.Id == id);
    if (targetUser == null)
        return Results.NotFound("Usuário não encontrado.");

    if (user.Role?.Name == "Administrador")
    {
        // Se for Administrador, pode visualizar qualquer usuário
        var response = new UserResponse(targetUser.Id, targetUser.Username, targetUser.Email, targetUser.Role!.Name);
        return Results.Ok(response);
    }
    else if (user.Role?.Name == "Gerente")
    {
        // Gerente pode visualizar Gerentes e Funcionários, mas não Administradores
        if (targetUser.Role?.Name == "Administrador")
            return Results.Forbid();

        var response = new UserResponse(targetUser.Id, targetUser.Username, targetUser.Email, targetUser.Role!.Name);
        return Results.Ok(response);
    }
    else
    {
        // Funcionário não pode visualizar ninguém
        return Results.Forbid();
    }
})
.WithSummary("Buscar usuário por ID")
.WithDescription("Administrador vê todos. Gerente vê Gerentes e Funcionários (não Admin). Funcionário não vê ninguém.")
.Produces<UserResponse>(200)
.Produces(401)
.Produces(403)
.Produces(404);


// GET /users/by-email → Busca usuário pelo e-mail
userGroup.MapGet("/by-email", (string email, HttpContext http, AppDbContext dbContext, JwtService jwt) =>
{
    // Extrai o usuário autenticado a partir do token JWT
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    // Busca o usuário alvo pelo e-mail no banco, incluindo a Role
    var targetUser = dbContext.Usuarios.Include(u => u.Role).FirstOrDefault(u => u.Email == email);
    if (targetUser == null)
        return Results.NotFound("Usuário não encontrado.");

    if (user.Role?.Name == "Administrador")
    {
        // Se for Administrador, pode visualizar qualquer usuário
        var response = new UserResponse(targetUser.Id, targetUser.Username, targetUser.Email, targetUser.Role!.Name);
        return Results.Ok(response);
    }
    else if (user.Role?.Name == "Gerente")
    {
        // Gerente pode visualizar Gerentes e Funcionários, mas não Administradores
        if (targetUser.Role?.Name == "Administrador")
            return Results.Forbid();

        var response = new UserResponse(targetUser.Id, targetUser.Username, targetUser.Email, targetUser.Role!.Name);
        return Results.Ok(response);
    }
    else
    {
        // Funcionário não pode visualizar ninguém
        return Results.Forbid();
    }
})
.WithSummary("Buscar usuário por e-mail")
.WithDescription("Administrador vê todos. Gerente vê Gerentes e Funcionários (não Admin). Funcionário não vê ninguém.")
.Produces<UserResponse>(200)
.Produces(401)
.Produces(403)
.Produces(404);


// POST /users → Cria um novo usuário
userGroup.MapPost("/", (CreateUserRequest request, HttpContext http, AppDbContext dbContext, JwtService jwt) =>
{
    // Extrai o usuário autenticado
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    // Funcionário não pode criar ninguém
    if (user.Role?.Name == "Funcionario")
        return Results.Forbid();

    // Gerente só pode criar Funcionários
    if (user.Role?.Name == "Gerente" && request.RoleId != 3)
        return Results.Forbid();

    // Verifica se o e-mail já existe no banco
    if (dbContext.Usuarios.Any(u => u.Email == request.Email))
        return Results.BadRequest("E-mail já cadastrado.");

    // Cria um novo usuário com base na request
    var newUser = new User
    {
        Username = request.Username,
        Email = request.Email,
        PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password),
        Role = dbContext.Roles.FirstOrDefault(r => r.Id == request.RoleId)
    };

    dbContext.Usuarios.Add(newUser);
    dbContext.SaveChanges();

    var response = new UserResponse(newUser.Id, newUser.Username, newUser.Email, newUser.Role!.Name);
    return Results.Created($"/users/{newUser.Id}", response);
})
.WithSummary("Criar usuário")
.WithDescription("Administrador pode criar qualquer cargo. Gerente apenas Funcionários.")
.Produces<UserResponse>(201)
.Produces(401)
.Produces(403)
.Produces(400);


/// PUT /users/{id} → Atualiza os dados de um usuário
userGroup.MapPut("/{id}", (int id, UpdateUserRequest request, HttpContext http, AppDbContext dbContext, JwtService jwt) =>
{
    // Extrai o usuário autenticado
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    // Funcionário não pode atualizar ninguém
    if (user.Role?.Name == "Funcionario")
        return Results.Forbid();

    // Busca o usuário alvo no banco de dados
    var targetUser = dbContext.Usuarios
        .Include(u => u.Role) // Inclui o Role associado
        .FirstOrDefault(u => u.Id == id);

    if (targetUser == null)
        return Results.NotFound("Usuário não encontrado.");

    // Gerente só pode editar Funcionários
    if (user.Role?.Name == "Gerente" && targetUser.Role?.Name != "Funcionario")
        return Results.Forbid();

    // Atualiza os campos permitidos
    targetUser.Username = request.Username;
    targetUser.Email = request.Email;
    targetUser.PasswordHash = SecurityService.HashPassword(request.Password); // Atualiza a senha com hash seguro

    // Atualiza o role, se fornecido
    var newRole = dbContext.Roles.FirstOrDefault(r => r.Id == request.RoleId);
    if (newRole != null)
        targetUser.Role = newRole;

    // Salva as alterações
    dbContext.SaveChanges();

    return Results.Ok("Usuário atualizado.");
})
.WithSummary("Atualizar usuário")
.WithDescription("Administrador pode editar qualquer usuário. Gerente apenas Funcionários.")
.Produces<string>(200)
.Produces(400) // Não usado diretamente, mas mantido para consistência
.Produces(401)
.Produces(403)
.Produces(404);


// DELETE /users/{id} → Remove um usuário do sistema
userGroup.MapDelete("/{id}", (int id, HttpContext http, AppDbContext dbContext, JwtService jwt) =>
{
    // Extrai o usuário autenticado
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    // Funcionário não pode excluir ninguém
    if (user.Role?.Name == "Funcionario")
        return Results.Forbid();

    // Busca o usuário alvo no banco de dados
    var targetUser = dbContext.Usuarios
        .Include(u => u.Role) // Inclui o Role associado
        .FirstOrDefault(u => u.Id == id);

    if (targetUser == null)
        return Results.NotFound("Usuário não encontrado.");

    // Se for Gerente, só pode excluir Funcionários
    if (user.Role?.Name == "Gerente" && targetUser.Role?.Name != "Funcionario")
        return Results.Forbid();

    // Remove o usuário
    dbContext.Usuarios.Remove(targetUser);
    dbContext.SaveChanges();

    return Results.Ok("Usuário excluído.");
}) 
.WithSummary("Deletar usuário")
.WithDescription("Administrador pode excluir qualquer usuário. Gerente apenas Funcionários.")
.Produces<string>(200)
.Produces(400) // Não usado diretamente, mas mantido para consistência
.Produces(401)
.Produces(403)
.Produces(404);



// -----------------------------------------------------------
// ROTAS DE GESTÃO DE CARGOS (ROLES)
// -----------------------------------------------------------

var roleGroup = app.MapGroup("/roles").WithTags("Cargos");


/// GET /roles → Lista todas as roles
roleGroup.MapGet("/", (HttpContext http, AppDbContext dbContext, JwtService jwt) =>
{
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    if (user.Role?.Name != "Administrador")
        return Results.Forbid();

    // Busca todas as roles no banco de dados
    var roles = dbContext.Roles
        .Select(r => new RoleResponse(r.Id, r.Name))
        .ToList();

    return Results.Ok(roles);
})
.WithSummary("Listar roles")
.WithDescription("Apenas Administrador pode acessar lista de cargos.")
.Produces<IEnumerable<RoleResponse>>(200)
.Produces(401)
.Produces(403);


/// GET /roles/{id} → Busca uma role por ID
roleGroup.MapGet("/{id}", (int id, HttpContext http, AppDbContext dbContext, JwtService jwt) =>
{
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    if (user.Role?.Name != "Administrador")
        return Results.Forbid();

    // Busca a role no banco de dados
    var role = dbContext.Roles
        .Where(r => r.Id == id)
        .Select(r => new RoleResponse(r.Id, r.Name))
        .FirstOrDefault();

    return role is not null 
        ? Results.Ok(role) 
        : Results.NotFound("Role não encontrada.");
})
.WithSummary("Buscar role por ID")
.WithDescription("Apenas Administrador pode consultar cargos.")
.Produces<RoleResponse>(200)
.Produces(401)
.Produces(403)
.Produces(404);


/// POST /roles → Cria uma nova role
roleGroup.MapPost("/", async (CreateRoleRequest request, HttpContext http, AppDbContext dbContext, JwtService jwt) =>
{
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    if (user.Role?.Name != "Administrador")
        return Results.Forbid();

    // Cria uma nova role no banco de dados
    var newRole = new Role
    {
        Name = request.Name
    };

    dbContext.Roles.Add(newRole);
    await dbContext.SaveChangesAsync();

    var response = new RoleResponse(newRole.Id, newRole.Name);
    return Results.Created($"/roles/{newRole.Id}", response);
})
.WithSummary("Criar role")
.WithDescription("Apenas Administrador pode criar novos cargos.")
.Produces<RoleResponse>(201)
.Produces(401)
.Produces(403);


/// PUT /roles/{id} → Atualiza uma role existente
roleGroup.MapPut("/{id}", async (int id, UpdateRoleRequest request, HttpContext http, AppDbContext dbContext, JwtService jwt) =>
{
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    if (user.Role?.Name != "Administrador")
        return Results.Forbid();

    // Busca a role pelo ID
    var existingRole = await dbContext.Roles.FindAsync(id);
    if (existingRole == null)
        return Results.NotFound("Role não encontrada.");

    // Atualiza o nome da role
    existingRole.Name = request.Name;

    await dbContext.SaveChangesAsync();

    return Results.Ok($"Role {id} atualizada para: {request.Name}");
})
.WithSummary("Atualizar role")
.WithDescription("Apenas Administrador pode atualizar cargos.")
.Produces<string>(200)
.Produces(401)
.Produces(403)
.Produces(404);


/// DELETE /roles/{id} → Exclui uma role
roleGroup.MapDelete("/{id}", async (int id, HttpContext http, AppDbContext dbContext, JwtService jwt) =>
{
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    if (user.Role?.Name != "Administrador")
        return Results.Forbid();

    // Busca a role pelo ID
    var existingRole = await dbContext.Roles.FindAsync(id);
    if (existingRole == null)
        return Results.NotFound("Role não encontrada.");

    // Remove a role do contexto e salva as mudanças
    dbContext.Roles.Remove(existingRole);
    await dbContext.SaveChangesAsync();

    return Results.Ok($"Role {id} excluída com sucesso.");
})
.WithSummary("Excluir role")
.WithDescription("Apenas Administrador pode excluir cargos.")
.Produces<string>(200)
.Produces(401)
.Produces(403)
.Produces(404);


// 🚀 Inicializa o servidor
app.Run();
