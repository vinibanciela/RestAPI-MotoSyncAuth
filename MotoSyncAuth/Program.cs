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
using MotoSyncAuth.Constants;


var builder = WebApplication.CreateBuilder(args);

// Linha temporária para gerar o hash de senha para o admin seed
// Utilizada uma vez, depois deixada comentada, para caso queira gerar outro hash de senha (estático) para o nosso admin seed
//Console.WriteLine($"Hash BCrypt para 'Admin@123': {SecurityService.HashPassword("Admin@123")}");

// -----------------------------------------------------------
// REGISTRO DE SERVIÇOS
// -----------------------------------------------------------

// Swagger (documentação automática da API)
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    // Adiciona esquema de segurança JWT
    options.AddSecurityDefinition(AppConstants.BearerScheme, new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Description = "Insira o token JWT no formato: Bearer {token}",
        Name = "Authorization",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Scheme = AppConstants.BearerScheme
    });

    options.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = AppConstants.BearerScheme
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


// Pega a chave secreta da configuração
var jwtSecret = builder.Configuration["JwtSettings:Secret"];
if (string.IsNullOrEmpty(jwtSecret))
{
    // Lança um erro claro se a chave não estiver no appsettings.json
    throw new InvalidOperationException("JWT Secret não está configurado no appsettings.json");
}
// Cria a chave de segurança uma vez, de forma segura
var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));

// Configura Autenticação JWT (com chave secreta)
builder.Services.AddAuthentication(AppConstants.BearerScheme)
    .AddJwtBearer(AppConstants.BearerScheme, options =>
    {
        options.RequireHttpsMetadata = false;
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key // <-- Usa a chave já validada e segura
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
        
    // LÓGICA DE FALHA COM HATEOAS
    // Se o usuário não existe ou a senha está incorreta, retorna um erro 401 estruturado.
    if (user == null || !SecurityService.VerifyPassword(request.Password, user.PasswordHash))
    {
        // Prepara a resposta de erro
        var errorResponse = new ErrorResponse("E-mail ou senha inválidos.");
        // Adiciona um link HATEOAS para guiar o cliente sobre a próxima ação possível (recuperar a senha).
        errorResponse.Links.Add(new LinkDto("/auth/forgot-password", "forgot-password", "POST"));
        // Retorna um status 401 com o corpo de erro customizado
        return Results.Json(errorResponse, statusCode: StatusCodes.Status401Unauthorized);
    }

    // LOG DE SUCESSO
    var successLog = new AuditLog { UserId = user.Id, UserEmail = user.Email, Action = "UserLoginSuccess", Timestamp = DateTime.UtcNow };
    dbContext.AuditLogs.Add(successLog);
    await dbContext.SaveChangesAsync();

    // Gera token JWT
    var token = jwt.GenerateToken(user);
    return Results.Ok(new AuthResponse(user.Username, token));
})
.WithSummary("Login do usuário")
.WithDescription("Autentica o usuário e retorna um token JWT.")
.Produces<AuthResponse>(200)
.Produces<ErrorResponse>(401) // Atualiza a documentação do Swagger para o novo tipo de erro
.RequireRateLimiting("default");


// GET /auth/me → Retorna dados do usuário autenticado via token
authGroup.MapGet("/me", async (HttpContext http, AppDbContext dbContext, JwtService jwt) =>
{
    // Extrai os dados do token JWT
    var tokenUser = jwt.ExtractUserFromRequest(http);
    if (tokenUser == null)
        return Results.Unauthorized();

    // Busca o usuário no banco de dados pelo e-mail extraído do token
    var requestingUser = await dbContext.Usuarios
        .Include(u => u.Role)
        .AsNoTracking()
        .FirstOrDefaultAsync(u => u.Email.ToLower() == tokenUser.Email.ToLower());

    if (requestingUser == null)
        return Results.Unauthorized();

    // Mapeia para o DTO de resposta para não expor dados sensíveis
    var response = new UserResponse(requestingUser.Id, requestingUser.Username, requestingUser.Email, requestingUser.Role!.Name);
    return Results.Ok(response);
})
.WithSummary("Dados do usuário logado")
.WithDescription("Retorna os dados do usuário a partir do token JWT.")
.Produces<UserResponse>(200) // Atualiza o tipo de produção no Swagger
.Produces(401);

// POST /auth/forgot-password → Gera token de redefinição de senha
authGroup.MapPost("/forgot-password", (ForgotPasswordRequest request, AppDbContext dbContext) =>
{
    // Busca o usuário no banco de dados pelo e-mail informado
    var user = dbContext.Usuarios
        .FirstOrDefault(u => u.Email
        .ToLower() == request.Email
        .ToLower());
    if (user == null)
        return Results.NotFound(AppConstants.UserNotFoundMessage);

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

/// GET /users → Lista todos os usuários
userGroup.MapGet("/", async (
    int pageNumber, // Parâmetro para o número da página
    int pageSize,   // Parâmetro para o tamanho da página
    HttpContext http, 
    AppDbContext dbContext, 
    JwtService jwt) =>
{
    // Validação básica para os parâmetros de paginação
    if (pageNumber <= 0) pageNumber = 1;
    if (pageSize <= 0) pageSize = 10; // Tamanho de página padrão

    // Extrai o usuário autenticado a partir do token JWT
    var tokenUser = jwt.ExtractUserFromRequest(http);
    if (tokenUser == null)
        return Results.Unauthorized();
    // Busca o usuário que está fazendo a requisição no banco para checar suas permissões reais
    var requestingUser = await dbContext.Usuarios
        .Include(u => u.Role)
        .AsNoTracking()
        .FirstOrDefaultAsync(u => u.Email == tokenUser.Email);
    if (requestingUser == null) 
        return Results.Unauthorized();

    // Inicia a consulta (IQueryable permite que o EF otimize o SQL)
    IQueryable<User> query = dbContext.Usuarios.Include(u => u.Role);

    if (requestingUser.Role?.Name == RoleNames.Gerente)
    {
        // Se for Gerente, filtra para ver apenas Gerentes e Funcionários
        query = query.Where(u => u.Role!.Name == RoleNames.Gerente || u.Role!.Name == RoleNames.Funcionario);
    }
    else if (requestingUser.Role?.Name != RoleNames.Administrador)
    {
        // Se não for Admin nem Gerente, não pode listar ninguém
        return Results.Forbid();
    }

    // 1. Obter a contagem total de itens ANTES de paginar
    var totalCount = await query.CountAsync();

    // 2. Aplicar a paginação na consulta
    var items = await query
        .Skip((pageNumber - 1) * pageSize)
        .Take(pageSize)
        .Select(u => new UserResponse(u.Id, u.Username, u.Email, u.Role!.Name))
        .ToListAsync();

    // 3. Calcular o total de páginas
    var totalPages = (int)Math.Ceiling(totalCount / (double)pageSize);
    
    // 4. Criar a resposta paginada
    var pagedResponse = new PagedResponse<UserResponse>(items, pageNumber, pageSize, totalCount, totalPages);

    return Results.Ok(pagedResponse);
})
.WithSummary("Listar usuários com paginação")
.WithDescription("Administrador vê todos. Gerente vê Gerentes e Funcionários. Usa os parâmetros 'pageNumber' e 'pageSize' para paginar.")
.Produces<PagedResponse<UserResponse>>(200)
.Produces(401)
.Produces(403);


// GET /users/{id} → Retorna um usuário específico por ID
userGroup.MapGet(AppConstants.IdRouteParameter, async (int id, HttpContext http, AppDbContext dbContext, JwtService jwt) =>
{
    // Extrai o usuário autenticado a partir do token JWT
    var tokenUser = jwt.ExtractUserFromRequest(http);
    if (tokenUser == null)
        return Results.Unauthorized();
    // Busca o usuário que está fazendo a requisição no banco para checar suas permissões reais
    var requestingUser = await dbContext.Usuarios
        .Include(u => u.Role)
        .AsNoTracking()
        .FirstOrDefaultAsync(u => u.Email == tokenUser.Email);
    if (requestingUser == null) 
        return Results.Unauthorized();

    // Busca o usuário alvo pelo ID no banco, incluindo a Role
    var targetUser = await dbContext.Usuarios.Include(u => u.Role).FirstOrDefaultAsync(u => u.Id == id);
    if (targetUser == null)
        return Results.NotFound(AppConstants.UserNotFoundMessage);

    // Mapeia os dados do usuário para o DTO de resposta
    var response = new UserResponse(targetUser.Id, targetUser.Username, targetUser.Email, targetUser.Role!.Name);

    // LÓGICA HATEOAS
    // Adiciona o link "self" para o próprio recurso, que sempre está presente.
    response.Links.Add(new LinkDto($"/users/{targetUser.Id}", "self", "GET"));

    // Adiciona links de outras ações (atualizar, deletar) condicionalmente, com base nas permissões.
    bool canModify = false;
    if (requestingUser.Role?.Name == RoleNames.Administrador)
    {
        // Administrador pode modificar qualquer um, exceto a si mesmo (regra de negócio).
        if(requestingUser.Id != targetUser.Id)
            canModify = true;
    }
    else if (requestingUser.Role?.Name == RoleNames.Gerente && targetUser.Role?.Name == RoleNames.Funcionario)
    {
        // Gerente só pode modificar Funcionários.
            canModify = true;
    }

    if (canModify)
    {
        response.Links.Add(new LinkDto($"/users/{targetUser.Id}", "update-user", "PUT"));
        response.Links.Add(new LinkDto($"/users/{targetUser.Id}", "delete-user", "DELETE"));
    }

    return Results.Ok(response);
})
.WithSummary("Buscar usuário por ID")
.WithDescription("Administrador vê todos. Gerente vê Gerentes e Funcionários (não Admin). Funcionário não vê ninguém.")
.Produces<UserResponse>(200)
.Produces(401)
.Produces(403)
.Produces(404);


// GET /users/by-email → Busca usuário pelo e-mail
userGroup.MapGet("/by-email", async (string email, HttpContext http, AppDbContext dbContext, JwtService jwt) =>
{
    // Extrai o usuário autenticado a partir do token JWT
    var tokenUser = jwt.ExtractUserFromRequest(http);
    if (tokenUser == null)
        return Results.Unauthorized();
    // Busca o usuário que está fazendo a requisição no banco para checar suas permissões reais
    var requestingUser = await dbContext.Usuarios
        .Include(u => u.Role)
        .AsNoTracking()
        .FirstOrDefaultAsync(u => u.Email == tokenUser.Email);
    if (requestingUser == null)
        return Results.Unauthorized();

    // Busca o usuário alvo pelo e-mail no banco, incluindo a Role
    var targetUser = await dbContext.Usuarios.Include(u => u.Role).FirstOrDefaultAsync(u => u.Email == email);
    if (targetUser == null)
        return Results.NotFound(AppConstants.UserNotFoundMessage);

    if (requestingUser.Role?.Name == RoleNames.Administrador)
    {
        // Se for Administrador, pode visualizar qualquer usuário
        var response = new UserResponse(targetUser.Id, targetUser.Username, targetUser.Email, targetUser.Role!.Name);
        return Results.Ok(response);
    }
    else if (requestingUser.Role?.Name == RoleNames.Gerente)
    {
        // Gerente pode visualizar Gerentes e Funcionários, mas não Administradores
        if (targetUser.Role?.Name == RoleNames.Administrador)
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
userGroup.MapPost("/", async (CreateUserRequest request, HttpContext http, AppDbContext dbContext, JwtService jwt) =>
{
    // Extrai o usuário autenticado do token
    var tokenUser = jwt.ExtractUserFromRequest(http);
    if (tokenUser == null)
        return Results.Unauthorized();
    // Busca o usuário que está realizando a ação no banco para checar suas permissões reais
    var requestingUser = await dbContext.Usuarios
        .Include(u => u.Role)
        .AsNoTracking()
        .FirstOrDefaultAsync(u => u.Email == tokenUser.Email);
    if (requestingUser == null)
        return Results.Unauthorized();

    // Funcionário não pode criar ninguém
    if (requestingUser.Role?.Name == RoleNames.Funcionario)
        return Results.Forbid();

    // Gerente só pode criar Funcionários (Exemplo: RoleId 3 = Funcionário)
    var roleOfNewUser = await dbContext.Roles.FindAsync(request.RoleId);
    if (roleOfNewUser == null)
        return Results.BadRequest("Cargo inválido.");
        
    if (requestingUser.Role?.Name == RoleNames.Gerente && roleOfNewUser.Name != RoleNames.Funcionario)
    {
        return Results.Problem(
            detail: "Gerentes só podem criar usuários com o cargo de Funcionário.",
            statusCode: StatusCodes.Status403Forbidden
        );
    }

    // Verifica se o e-mail já existe no banco
    if (await dbContext.Usuarios.AnyAsync(u => u.Email == request.Email))
        return Results.BadRequest("E-mail já cadastrado.");

    // Cria um novo usuário com base na request
    var newUser = new User
    {
        Username = request.Username,
        Email = request.Email,
        PasswordHash = SecurityService.HashPassword(request.Password),
        RoleId = request.RoleId,
    };

    dbContext.Usuarios.Add(newUser);
    await dbContext.SaveChangesAsync();

    // LOG DE CRIAÇÃO DE USUÁRIO
    var log = new AuditLog
    {
        UserId = requestingUser.Id,
        UserEmail = requestingUser.Email,
        Action = "UserCreated",
        Timestamp = DateTime.UtcNow,
        Details = $"New user created with ID {newUser.Id} and role '{roleOfNewUser.Name}'."
    };
    dbContext.AuditLogs.Add(log);
    await dbContext.SaveChangesAsync();

    var response = new UserResponse(newUser.Id, newUser.Username, newUser.Email, roleOfNewUser.Name);
    return Results.Created($"/users/{newUser.Id}", response);
})
.WithSummary("Criar usuário")
.WithDescription("Administrador pode criar qualquer cargo. Gerente apenas Funcionários.")
.Produces<UserResponse>(201)
.Produces(401)
.Produces(403)
.Produces(400);


/// PUT /users/{id} → Atualiza os dados de um usuário
userGroup.MapPut(AppConstants.IdRouteParameter, async (int id, UpdateUserRequest request, HttpContext http, AppDbContext dbContext, JwtService jwt) =>
{
    // Extrai o usuário autenticado
    var tokenUser = jwt.ExtractUserFromRequest(http);
    if (tokenUser == null)
        return Results.Unauthorized();
    // Busca o usuário que está fazendo a requisição no banco para checar suas permissões reais
    var requestingUser = await dbContext.Usuarios
        .Include(u => u.Role)
        .AsNoTracking()
        .FirstOrDefaultAsync(u => u.Email == tokenUser.Email);
    if (requestingUser == null)
        return Results.Unauthorized();

    // Funcionário não pode atualizar ninguém
    if (requestingUser.Role?.Name == RoleNames.Funcionario)
        return Results.Forbid();

    // Busca o usuário alvo no banco de dados pelo ID
    var targetUser = await dbContext.Usuarios
        .Include(u => u.Role) // Inclui o Role associado
        .FirstOrDefaultAsync(u => u.Id == id);

    if (targetUser == null)
        return Results.NotFound(AppConstants.UserNotFoundMessage);

    // Gerente só pode editar Funcionários
    if (requestingUser.Role?.Name == RoleNames.Gerente && targetUser.Role?.Name != RoleNames.Funcionario)
        return Results.Forbid();

    // Atualiza os campos permitidos
    if(request.Username is not null) targetUser.Username = request.Username;
    if(request.Email is not null) targetUser.Email = request.Email;
    if(request.Password is not null) targetUser.PasswordHash = SecurityService.HashPassword(request.Password);

    // Atualiza o role, se fornecido
    if (request.RoleId is not null)
    {
        var newRole = await dbContext.Roles.FindAsync(request.RoleId);
        if (newRole != null)
            targetUser.RoleId = newRole.Id;
    }
    
    // Salva as alterações
    await dbContext.SaveChangesAsync();

    return Results.Ok("Usuário atualizado.");
})
.WithSummary("Atualizar usuário")
.WithDescription("Administrador pode editar qualquer usuário. Gerente apenas Funcionários.")
.Produces<string>(200)
.Produces(401)
.Produces(403)
.Produces(404);


// DELETE /users/{id} → Remove um usuário do sistema
userGroup.MapDelete(AppConstants.IdRouteParameter, async (int id, HttpContext http, AppDbContext dbContext, JwtService jwt) =>
{
    // Extrai o usuário autenticado
    var tokenUser = jwt.ExtractUserFromRequest(http);
    if (tokenUser == null)
        return Results.Unauthorized();
    // Busca o usuário que está fazendo a requisição no banco para checar suas permissões reais
    var requestingUser = await dbContext.Usuarios
        .Include(u => u.Role)
        .AsNoTracking()
        .FirstOrDefaultAsync(u => u.Email == tokenUser.Email);
    if (requestingUser == null)
        return Results.Unauthorized();
        
    // Funcionário não pode excluir ninguém
    if (requestingUser.Role?.Name == RoleNames.Funcionario)
        return Results.Forbid();

    // Busca o usuário alvo no banco de dados
    var targetUser = await dbContext.Usuarios
        .Include(u => u.Role) // Inclui o Role associado
        .FirstOrDefaultAsync(u => u.Id == id);

    if (targetUser == null)
        return Results.NotFound(AppConstants.UserNotFoundMessage);
        
    // Usuário não pode deletar a si mesmo
    if (requestingUser.Id == targetUser.Id)
        return Results.BadRequest("Não é permitido excluir o próprio usuário.");

    // Se for Gerente, só pode excluir Funcionários
    if (requestingUser.Role?.Name == RoleNames.Gerente && targetUser.Role?.Name != RoleNames.Funcionario)
        return Results.Forbid();

    // Remove o usuário
    dbContext.Usuarios.Remove(targetUser);
    
    // LOG DE EXCLUSÃO DE USUÁRIO
    var log = new AuditLog
    {
        UserId = requestingUser.Id,
        UserEmail = requestingUser.Email,
        Action = "UserDeleted",
        Timestamp = DateTime.UtcNow,
        Details = $"User with ID {targetUser.Id} and email '{targetUser.Email}' was deleted."
    };
    dbContext.AuditLogs.Add(log);
    
    await dbContext.SaveChangesAsync();

    return Results.Ok("Usuário excluído.");
})
.WithSummary("Deletar usuário")
.WithDescription("Administrador pode excluir qualquer usuário. Gerente apenas Funcionários.")
.Produces<string>(200)
.Produces(400) 
.Produces(401)
.Produces(403)
.Produces(404);


// -----------------------------------------------------------
// ROTAS DE GESTÃO DE CARGOS (ROLES)
// -----------------------------------------------------------

var roleGroup = app.MapGroup("/roles").WithTags("Cargos");


/// GET /roles → Lista todas as roles
roleGroup.MapGet("/", async (HttpContext http, AppDbContext dbContext, JwtService jwt) =>
{
    var tokenUser = jwt.ExtractUserFromRequest(http);
    if (tokenUser == null) return Results.Unauthorized();

    var user = await dbContext.Usuarios.Include(u => u.Role)
        .FirstOrDefaultAsync(u => u.Email == tokenUser.Email);

    if (user?.Role?.Name != RoleNames.Administrador)
        return Results.Forbid();

    // Busca todas as roles no banco de dados
    var roles = await dbContext.Roles
        .Select(r => new RoleResponse(r.Id, r.Name))
        .ToListAsync();

    return Results.Ok(roles);
})
.WithSummary("Listar roles")
.WithDescription("Apenas Administrador pode acessar lista de cargos.")
.Produces<IEnumerable<RoleResponse>>(200)
.Produces(401)
.Produces(403);


/// GET /roles/{id} → Busca uma role por ID
roleGroup.MapGet(AppConstants.IdRouteParameter, async (int id, HttpContext http, AppDbContext dbContext, JwtService jwt) =>
{
    var tokenUser = jwt.ExtractUserFromRequest(http);
    if (tokenUser == null) return Results.Unauthorized();
    
    var user = await dbContext.Usuarios.Include(u => u.Role)
        .FirstOrDefaultAsync(u => u.Email == tokenUser.Email);

    if (user?.Role?.Name != RoleNames.Administrador)
        return Results.Forbid();

    // Busca a role no banco de dados
    var role = await dbContext.Roles
        .Where(r => r.Id == id)
        .Select(r => new RoleResponse(r.Id, r.Name))
        .FirstOrDefaultAsync();

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
    var tokenUser = jwt.ExtractUserFromRequest(http);
    if (tokenUser == null) return Results.Unauthorized();
    
    var user = await dbContext.Usuarios.Include(u => u.Role)
        .FirstOrDefaultAsync(u => u.Email == tokenUser.Email);

    if (user?.Role?.Name != RoleNames.Administrador)
        return Results.Forbid();

    // Cria uma nova role no banco de dados
    var newRole = new Role { Name = request.Name };

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
roleGroup.MapPut(AppConstants.IdRouteParameter, async (int id, UpdateRoleRequest request, HttpContext http, AppDbContext dbContext, JwtService jwt) =>
{
    var tokenUser = jwt.ExtractUserFromRequest(http);
    if (tokenUser == null) return Results.Unauthorized();

    var user = await dbContext.Usuarios.Include(u => u.Role)
        .FirstOrDefaultAsync(u => u.Email == tokenUser.Email);

    if (user?.Role?.Name != RoleNames.Administrador)
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
roleGroup.MapDelete(AppConstants.IdRouteParameter, async (int id, HttpContext http, AppDbContext dbContext, JwtService jwt) =>
{
    var tokenUser = jwt.ExtractUserFromRequest(http);
    if (tokenUser == null) return Results.Unauthorized();

    var user = await dbContext.Usuarios.Include(u => u.Role)
        .FirstOrDefaultAsync(u => u.Email == tokenUser.Email);

    if (user?.Role?.Name != RoleNames.Administrador)
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

// -----------------------------------------------------------
// ROTAS DE AUDITORIA
// -----------------------------------------------------------
var auditGroup = app.MapGroup("/audits")
    .WithTags("Auditoria")
    .RequireAuthorization(); // Protege todo o grupo

//GET /audits -> lista os logs do sistema para auditoria
auditGroup.MapGet("/", async (
    int pageNumber, 
    int pageSize,
    HttpContext http, 
    AppDbContext dbContext, 
    JwtService jwt) =>
{
    if (pageNumber <= 0) pageNumber = 1;
    if (pageSize <= 0) pageSize = 20; // Um tamanho padrão para logs

    var user = jwt.ExtractUserFromRequest(http);
    if (user == null) 
        return Results.Unauthorized();

    var userFromDb = await dbContext.Usuarios.Include(u => u.Role).AsNoTracking()
        .FirstOrDefaultAsync(u => u.Email == user.Email);

    if (userFromDb?.Role?.Name != RoleNames.Administrador) 
        return Results.Forbid();
    
    // Consulta base
    IQueryable<AuditLog> query = dbContext.AuditLogs.OrderByDescending(a => a.Timestamp);

    // 1. Obter contagem total
    var totalCount = await query.CountAsync();

    // 2. Aplicar paginação e selecionar o DTO
    var items = await query
        .Skip((pageNumber - 1) * pageSize)
        .Take(pageSize)
        .Select(a => new AuditLogResponse(a.Id, a.UserId, a.UserEmail, a.Action, a.Timestamp, a.Details))
        .ToListAsync();

    // 3. Calcular total de páginas
    var totalPages = (int)Math.Ceiling(totalCount / (double)pageSize);

    // 4. Criar a resposta paginada
    var pagedResponse = new PagedResponse<AuditLogResponse>(items, pageNumber, pageSize, totalCount, totalPages);
    
    return Results.Ok(pagedResponse);
})
.WithSummary("Listar logs de auditoria com paginação")
.WithDescription("Retorna os eventos do sistema de forma paginada. Acesso exclusivo para Administradores. Usa 'pageNumber' e 'pageSize' para paginar.")
.Produces<PagedResponse<AuditLogResponse>>(200)
.Produces(401)
.Produces(403);

// Rota para Health Check do Docker
app.MapGet("/healthz", () => Results.Ok("Healthy")).ExcludeFromDescription();

// 🚀 Inicializa o servidor
await app.RunAsync();