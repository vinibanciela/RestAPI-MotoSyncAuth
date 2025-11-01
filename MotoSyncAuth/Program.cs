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
using System.Security.Claims;


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
     // Ativando comentários (usamos nos DTOs e Models)
    var xmlFilename = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
    options.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory, xmlFilename));

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
// Injeta a classe base AppDbContextBase, e o sistema de injeção de dependênciafornece a implementação correta (Postgres ou Azure) com base no ambiente.
if (builder.Environment.IsDevelopment())
{
    // Registra e configura o DbContext para PostgreSQL em ambiente de desenvolvimento
    builder.Services.AddDbContext<AppDbContextBase, PostgresDbContext>(options =>
        options.UseNpgsql(builder.Configuration.GetConnectionString("PostgresConnection")));
}
else
{
    // Registra e configura o DbContext para SQL Server (Azure SQL) em qualquer outro ambiente (Produção)
    builder.Services.AddDbContext<AppDbContextBase, AzureDbContext>(options =>
        options.UseSqlServer(builder.Configuration.GetConnectionString("AzureSqlConnection")));
}


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
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Authenticated", policy =>
        policy.RequireAuthenticatedUser());

    options.AddPolicy("ManagerOrAdmin", policy =>
        policy.RequireRole(RoleNames.Administrador, RoleNames.Gerente));

    options.AddPolicy("AdminOnly", policy =>
        policy.RequireRole(RoleNames.Administrador));
});



builder.Services.AddHealthChecks()
    // Checa se consegue resolver e conversar com o DbContext
    .AddDbContextCheck<AppDbContextBase>("database");


var app = builder.Build();

// --- INÍCIO DO CÓDIGO PARA APLICAR MIGRATIONS NO STARTUP ---
// Este bloco garante que o banco de dados seja atualizado com as últimas migrations toda vez que a aplicação for iniciada.
// Na próxima sprint configurar no pipeline

using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContextBase>();
    dbContext.Database.Migrate(); //aplica migrations automaticamente
}



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


// ENDPOINTS DE HEALTH
// Liveness: processo está no ar
app.MapGet("/health/live", () => Results.Ok(new { status = "ok", message = "API process running" }))
    .WithName("Liveness")
    .WithSummary("Verifica se a API está viva")
    .WithDescription("Retorna 200 OK se o processo da API está em execução. Não verifica dependências externas.")
    .Produces<object>(200)
    .WithTags("Health Checks")
    .WithOpenApi(); // <-- isso faz o Swagger exibir
    //.ExcludeFromDescription(); <-- isso deixa oculto do swagger, removendo os demais acima

// Readiness: pronto pra receber tráfego (DB, etc.)
app.MapHealthChecks("/health/ready")
    .WithName("Readiness")
    .WithSummary("Verifica se a API está pronta para receber tráfego")
    .WithDescription("Retorna 200 OK se a API está operacional e consegue falar com o banco. Retorna 503 se alguma dependência crítica falhar.")
    .WithTags("Health Checks")
    .WithOpenApi(); // <-- Swagger exibe
    //.ExcludeFromDescription(); <-- isso deixa oculto do swagger, removendo os demais acima

// Health legado usado no Dockerfile (igual liveness antigo)
app.MapGet("/healthz", () => Results.Ok("Healthy"))
    .WithName("CompatHealthz")
    .WithSummary("Endpoint de compatibilidade para probes Docker")
    .WithDescription("Usado pelo Docker HEALTHCHECK para saber se o contêiner está vivo.")
    .Produces<string>(200)
    .WithTags("Health Checks")
    .WithOpenApi(); // <-- Swagger exibe
    //.ExcludeFromDescription(); <-- isso deixa oculto do swagger, removendo os demais acima



// -----------------------------------------------------------
// ROTAS DE AUTENTICAÇÃO
// -----------------------------------------------------------

var authGroup = app.MapGroup("/auth").WithTags("Autenticação");


// POST /auth/login → Realiza login e retorna JWT
authGroup.MapPost("/login", async (LoginRequest request, AppDbContextBase dbContext, JwtService jwt) =>
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
.WithDescription("Autentica o usuário e retorna um token JWT.Em caso de falha (401), a resposta incluirá um link para recuperação de senha.")
.Produces<AuthResponse>(200)
.Produces<ErrorResponse>(401)
.RequireRateLimiting("default");


// GET /auth/me → Retorna dados do usuário autenticado via token
authGroup.MapGet("/me", async (HttpContext http, AppDbContextBase dbContext, JwtService jwt) =>
{
    // Extrai o email da claim do token já validado pelo middleware
    var email = http.User.FindFirst(ClaimTypes.Email)?.Value;
    if (string.IsNullOrEmpty(email))
        return Results.Unauthorized();
    //Busca o usuário autenticado no banco
    var requestingUser = await dbContext.Usuarios
        .Include(u => u.Role)
        .AsNoTracking()
        .FirstOrDefaultAsync(u => u.Email == email);

    if (requestingUser == null)
        return Results.Unauthorized();


    // Mapeia para o DTO de resposta para não expor dados sensíveis
    var response = new UserResponse(requestingUser.Id, requestingUser.Username, requestingUser.Email, requestingUser.Role!.Name);
    
    // Adiciona o link HATEOAS 'self' para o recurso do próprio usuário
    response.Links.Add(new LinkDto($"/users/{requestingUser.Id}", "self", "GET"));

    return Results.Ok(response);
})
.RequireAuthorization("Authenticated")
.WithSummary("Dados do usuário logado")
.WithDescription("Retorna os dados do usuário a partir do token JWT, incluindo um link HATEOAS para o recurso do usuário.")
.Produces<UserResponse>(200)
.Produces(401);


// POST /auth/forgot-password → Gera token de redefinição de senha
authGroup.MapPost("/forgot-password", (ForgotPasswordRequest request, AppDbContextBase dbContext) =>
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
authGroup.MapPost("/reset-password", (ResetPasswordRequest request, AppDbContextBase dbContext) =>
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

var userGroup = app.MapGroup("/users")
    .WithTags("Usuários")
    .RequireAuthorization("ManagerOrAdmin");


// GET /users → Lista todos os usuários
userGroup.MapGet("/", async (
    int pageNumber, // Parâmetro para o número da página
    int pageSize,   // Parâmetro para o tamanho da página
    HttpContext http, 
    AppDbContextBase dbContext, 
    JwtService jwt) =>
{
    // Validação básica para os parâmetros de paginação
    if (pageNumber <= 0) pageNumber = 1;
    if (pageSize <= 0) pageSize = 10; // Tamanho de página padrão

    // Extrai o email da claim do token já validado pelo middleware
    var email = http.User.FindFirst(ClaimTypes.Email)?.Value;
    if (string.IsNullOrEmpty(email))
        return Results.Unauthorized();
    //Busca o usuário autenticado no banco
    var requestingUser = await dbContext.Usuarios
        .Include(u => u.Role)
        .AsNoTracking()
        .FirstOrDefaultAsync(u => u.Email == email);

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

    // 5. Adicionar os links HATEOAS à resposta paginada
    pagedResponse.Links.Add(new LinkDto($"/users?pageNumber={pageNumber}&pageSize={pageSize}", "self", "GET"));
    if (pageNumber < totalPages)
    {
        pagedResponse.Links.Add(new LinkDto($"/users?pageNumber={pageNumber + 1}&pageSize={pageSize}", "next-page", "GET"));
    }
    if (pageNumber > 1)
    {
        pagedResponse.Links.Add(new LinkDto($"/users?pageNumber={pageNumber - 1}&pageSize={pageSize}", "prev-page", "GET"));
    }

    return Results.Ok(pagedResponse);
})
.WithSummary("Listar usuários com paginação")
.WithDescription("Admin vê todos. Gerente vê Gerentes e Funcionários. A resposta é paginada e inclui links HATEOAS para navegação.")
.Produces<PagedResponse<UserResponse>>(200)
.Produces(401)
.Produces(403);


userGroup.MapGet(AppConstants.IdRouteParameter, async (int id, HttpContext http, AppDbContextBase dbContext, JwtService jwt) =>
{
    // Extrai o email da claim do token já validado pelo middleware
    var email = http.User.FindFirst(ClaimTypes.Email)?.Value;
    if (string.IsNullOrEmpty(email))
        return Results.Unauthorized();

    // Busca o usuário autenticado no banco
    var requestingUser = await dbContext.Usuarios
        .Include(u => u.Role)
        .AsNoTracking()
        .FirstOrDefaultAsync(u => u.Email == email);

    if (requestingUser == null)
        return Results.Unauthorized();

    // Busca o usuário alvo pelo ID no banco, incluindo a Role
    var targetUser = await dbContext.Usuarios
        .Include(u => u.Role)
        .FirstOrDefaultAsync(u => u.Id == id);

    if (targetUser == null)
        return Results.NotFound(AppConstants.UserNotFoundMessage);

    // 🔧 Regra de visibilidade (Gerente não pode ver Admin)
    if (requestingUser.Role?.Name == RoleNames.Gerente &&
        targetUser.Role?.Name == RoleNames.Administrador)
    {
        return Results.Forbid();
    }

    // Mapeia os dados do usuário para o DTO de resposta
    var response = new UserResponse(
        targetUser.Id,
        targetUser.Username,
        targetUser.Email,
        targetUser.Role!.Name
    );

    // LÓGICA HATEOAS
    response.Links.Add(new LinkDto($"/users/{targetUser.Id}", "self", "GET"));

    bool canModify = false;
    if (requestingUser.Role?.Name == RoleNames.Administrador)
    {
        // Administrador pode modificar qualquer um, exceto a si mesmo (regra de negócio).
        if (requestingUser.Id != targetUser.Id)
            canModify = true;
    }
    else if (requestingUser.Role?.Name == RoleNames.Gerente &&
             targetUser.Role?.Name == RoleNames.Funcionario)
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
.WithDescription("Administrador vê todos. Gerente vê Gerentes e Funcionários (não Admin). Funcionário não vê ninguém. A resposta inclui links HATEOAS...")
.Produces<UserResponse>(200)
.Produces(401)
.Produces(403)
.Produces(404);



// GET /users/by-email → Busca usuário pelo e-mail
userGroup.MapGet("/by-email", async (string targetEmail, HttpContext http, AppDbContextBase dbContext, JwtService jwt) =>
{
    // Extrai o email de quem está autenticado
    var email = http.User.FindFirst(ClaimTypes.Email)?.Value;
    if (string.IsNullOrEmpty(email))
        return Results.Unauthorized();

    // Busca o usuário autenticado no banco
    var requestingUser = await dbContext.Usuarios
        .Include(u => u.Role)
        .AsNoTracking()
        .FirstOrDefaultAsync(u => u.Email == email);

    if (requestingUser == null)
        return Results.Unauthorized();

    // Busca o usuário alvo pelo e-mail passado como parâmetro
    var targetUser = await dbContext.Usuarios
        .Include(u => u.Role)
        .FirstOrDefaultAsync(u => u.Email == targetEmail);

    if (targetUser == null)
        return Results.NotFound(AppConstants.UserNotFoundMessage);

    // 🔧 Mesma regra: Gerente não pode ver Admin
    if (requestingUser.Role?.Name == RoleNames.Gerente &&
        targetUser.Role?.Name == RoleNames.Administrador)
    {
        return Results.Forbid();
    }

    // Admin pode ver qualquer coisa,
    // Gerente pode ver Gerente/Funcionário,
    // Funcionário nem entra porque o grupo já tem .RequireAuthorization("ManagerOrAdmin")

    var response = new UserResponse(
        targetUser.Id,
        targetUser.Username,
        targetUser.Email,
        targetUser.Role!.Name
    );

    return Results.Ok(response);
})
.WithSummary("Buscar usuário por e-mail")
.WithDescription("Administrador vê todos. Gerente vê Gerentes e Funcionários (não Admin). Funcionário não vê ninguém.")
.Produces<UserResponse>(200)
.Produces(401)
.Produces(403)
.Produces(404);


// POST /users → Cria um novo usuário
userGroup.MapPost("/", async (CreateUserRequest request, HttpContext http, AppDbContextBase dbContext, JwtService jwt) =>
{
    // Extrai o email da claim do token já validado pelo middleware
    var email = http.User.FindFirst(ClaimTypes.Email)?.Value;
    if (string.IsNullOrEmpty(email))
        return Results.Unauthorized();
    //Busca o usuário autenticado no banco
    var requestingUser = await dbContext.Usuarios
        .Include(u => u.Role)
        .AsNoTracking()
        .FirstOrDefaultAsync(u => u.Email == email);

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


// PUT /users/{id} → Atualiza os dados de um usuário
userGroup.MapPut(AppConstants.IdRouteParameter, async (int id, UpdateUserRequest request, HttpContext http, AppDbContextBase dbContext, JwtService jwt) =>
{
    // Extrai o email da claim do token já validado pelo middleware
    var email = http.User.FindFirst(ClaimTypes.Email)?.Value;
    if (string.IsNullOrEmpty(email))
        return Results.Unauthorized();
    //Busca o usuário autenticado no banco
    var requestingUser = await dbContext.Usuarios
        .Include(u => u.Role)
        .AsNoTracking()
        .FirstOrDefaultAsync(u => u.Email == email);

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
userGroup.MapDelete(AppConstants.IdRouteParameter, async (int id, HttpContext http, AppDbContextBase dbContext, JwtService jwt) =>
{
    // Extrai o email da claim do token já validado pelo middleware
    var email = http.User.FindFirst(ClaimTypes.Email)?.Value;
    if (string.IsNullOrEmpty(email))
        return Results.Unauthorized();
    //Busca o usuário autenticado no banco
    var requestingUser = await dbContext.Usuarios
        .Include(u => u.Role)
        .AsNoTracking()
        .FirstOrDefaultAsync(u => u.Email == email);

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

var roleGroup = app.MapGroup("/roles")
    .WithTags("Cargos")
    .RequireAuthorization("AdminOnly");


// GET /roles → Lista todas as roles
roleGroup.MapGet("/", async (
    int pageNumber,
    int pageSize,
    HttpContext http,
    AppDbContextBase dbContext,
    JwtService jwt) =>
{
    if (pageNumber <= 0) pageNumber = 1;
    if (pageSize <= 0) pageSize = 10;

    // Extrai o email da claim do token já validado pelo middleware
    var email = http.User.FindFirst(ClaimTypes.Email)?.Value;
    if (string.IsNullOrEmpty(email))
        return Results.Unauthorized();
    //Busca o usuário autenticado no banco
    var requestingUser = await dbContext.Usuarios
        .Include(u => u.Role)
        .AsNoTracking()
        .FirstOrDefaultAsync(u => u.Email == email);

    if (requestingUser == null)
        return Results.Unauthorized();
    //Acesso somente pelo Admin
    if (requestingUser.Role?.Name != RoleNames.Administrador)
        return Results.Forbid();

    // Consulta base
    IQueryable<Role> query = dbContext.Roles;

    var totalCount = await query.CountAsync();
    var items = await query
        .Skip((pageNumber - 1) * pageSize)
        .Take(pageSize)
        .Select(r => new RoleResponse(r.Id, r.Name))
        .ToListAsync();

    var totalPages = (int)Math.Ceiling(totalCount / (double)pageSize);
    var pagedResponse = new PagedResponse<RoleResponse>(items, pageNumber, pageSize, totalCount, totalPages);

    // Adiciona os links HATEOAS à resposta paginada
    pagedResponse.Links.Add(new LinkDto($"/roles?pageNumber={pageNumber}&pageSize={pageSize}", "self", "GET"));
    if (pageNumber < totalPages)
    {
        pagedResponse.Links.Add(new LinkDto($"/roles?pageNumber={pageNumber + 1}&pageSize={pageSize}", "next-page", "GET"));
    }
    if (pageNumber > 1)
    {
        pagedResponse.Links.Add(new LinkDto($"/roles?pageNumber={pageNumber - 1}&pageSize={pageSize}", "prev-page", "GET"));
    }

    return Results.Ok(pagedResponse);
})
.WithSummary("Listar roles com paginação")
.WithDescription("Apenas Administrador pode acessar a lista de cargos. A resposta é paginada e inclui links HATEOAS para navegação.")
.Produces<PagedResponse<RoleResponse>>(200)
.Produces(401)
.Produces(403);


// GET /roles/{id} → Busca uma role por ID
roleGroup.MapGet(AppConstants.IdRouteParameter, async (int id, HttpContext http, AppDbContextBase dbContext, JwtService jwt) =>
{
    // Extrai o email da claim do token já validado pelo middleware
    var email = http.User.FindFirst(ClaimTypes.Email)?.Value;
    if (string.IsNullOrEmpty(email))
        return Results.Unauthorized();
    //Busca o usuário autenticado no banco
    var requestingUser = await dbContext.Usuarios
        .Include(u => u.Role)
        .AsNoTracking()
        .FirstOrDefaultAsync(u => u.Email == email);

    if (requestingUser == null)
        return Results.Unauthorized();
    //Acesso somente pelo Admin
    if (requestingUser.Role?.Name != RoleNames.Administrador)
        return Results.Forbid();

    // Busca a entidade 'Role' completa no banco de dados
    var role = await dbContext.Roles.FindAsync(id);

    if (role is null)
    {
        return Results.NotFound("Role não encontrada.");
    }
        
    // Mapeia a entidade para o DTO de resposta
    var response = new RoleResponse(role.Id, role.Name);

    // Adiciona os links HATEOAS para as ações possíveis
    response.Links.Add(new LinkDto($"/roles/{role.Id}", "self", "GET"));
    response.Links.Add(new LinkDto($"/roles/{role.Id}", "update-role", "PUT"));
    response.Links.Add(new LinkDto($"/roles/{role.Id}", "delete-role", "DELETE"));
    
    return Results.Ok(response);
})
.WithSummary("Buscar role por ID")
.WithDescription("Apenas Administrador pode consultar cargos. A resposta inclui links HATEOAS para atualizar e deletar o cargo, e um link 'self'.")
.Produces<RoleResponse>(200)
.Produces(401)
.Produces(403)
.Produces(404);


// POST /roles → Cria uma nova role
roleGroup.MapPost("/", async (CreateRoleRequest request, HttpContext http, AppDbContextBase dbContext, JwtService jwt) =>
{
    // Extrai o email da claim do token já validado pelo middleware
    var email = http.User.FindFirst(ClaimTypes.Email)?.Value;
    if (string.IsNullOrEmpty(email))
        return Results.Unauthorized();
    //Busca o usuário autenticado no banco
    var requestingUser = await dbContext.Usuarios
        .Include(u => u.Role)
        .AsNoTracking()
        .FirstOrDefaultAsync(u => u.Email == email);

    if (requestingUser == null)
        return Results.Unauthorized();
    //Acesso somente pelo Admin
    if (requestingUser.Role?.Name != RoleNames.Administrador)
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


// PUT /roles/{id} → Atualiza uma role existente
roleGroup.MapPut(AppConstants.IdRouteParameter, async (int id, UpdateRoleRequest request, HttpContext http, AppDbContextBase dbContext, JwtService jwt) =>
{
    // Extrai o email da claim do token já validado pelo middleware
    var email = http.User.FindFirst(ClaimTypes.Email)?.Value;
    if (string.IsNullOrEmpty(email))
        return Results.Unauthorized();
    //Busca o usuário autenticado no banco
    var requestingUser = await dbContext.Usuarios
        .Include(u => u.Role)
        .AsNoTracking()
        .FirstOrDefaultAsync(u => u.Email == email);

    if (requestingUser == null)
        return Results.Unauthorized();
    //Acesso somente pelo Admin
    if (requestingUser.Role?.Name != RoleNames.Administrador)
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


// DELETE /roles/{id} → Exclui uma role
roleGroup.MapDelete(AppConstants.IdRouteParameter, async (int id, HttpContext http, AppDbContextBase dbContext, JwtService jwt) =>
{
    // Extrai o email da claim do token já validado pelo middleware
    var email = http.User.FindFirst(ClaimTypes.Email)?.Value;
    if (string.IsNullOrEmpty(email))
        return Results.Unauthorized();
    //Busca o usuário autenticado no banco
    var requestingUser = await dbContext.Usuarios
        .Include(u => u.Role)
        .AsNoTracking()
        .FirstOrDefaultAsync(u => u.Email == email);

    if (requestingUser == null)
        return Results.Unauthorized();
    //Acesso somente pelo Admin
    if (requestingUser.Role?.Name != RoleNames.Administrador)
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
    .RequireAuthorization("AdminOnly");


//GET /audits -> lista os logs do sistema para auditoria
auditGroup.MapGet("/", async (
    int pageNumber, 
    int pageSize,
    HttpContext http, 
    AppDbContextBase dbContext, 
    JwtService jwt) =>
{
    if (pageNumber <= 0) pageNumber = 1;
    if (pageSize <= 0) pageSize = 20; // Um tamanho padrão para logs

   // Extrai o email da claim do token já validado pelo middleware
    var email = http.User.FindFirst(ClaimTypes.Email)?.Value;
    if (string.IsNullOrEmpty(email))
        return Results.Unauthorized();
    //Busca o usuário autenticado no banco
    var requestingUser = await dbContext.Usuarios
        .Include(u => u.Role)
        .AsNoTracking()
        .FirstOrDefaultAsync(u => u.Email == email);

    if (requestingUser == null)
        return Results.Unauthorized();
    //Acesso somente pelo Admin
    if (requestingUser.Role?.Name != RoleNames.Administrador)
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
    
    // 5. Adicionar os links HATEOAS à resposta paginada
    pagedResponse.Links.Add(new LinkDto($"/audits?pageNumber={pageNumber}&pageSize={pageSize}", "self", "GET"));
    if (pageNumber < totalPages)
    {
        pagedResponse.Links.Add(new LinkDto($"/audits?pageNumber={pageNumber + 1}&pageSize={pageSize}", "next-page", "GET"));
    }
    if (pageNumber > 1)
    {
        pagedResponse.Links.Add(new LinkDto($"/audits?pageNumber={pageNumber - 1}&pageSize={pageSize}", "prev-page", "GET"));
    }
    
    return Results.Ok(pagedResponse);
})
.WithSummary("Listar logs de auditoria com paginação")
.WithDescription("Acesso exclusivo para Admins.Retorna os eventos do sistema de forma paginada. Inclui links HATEOAS para navegação.")
.Produces<PagedResponse<AuditLogResponse>>(200)
.Produces(401)
.Produces(403);



// 🚀 Inicializa o servidor
await app.RunAsync();