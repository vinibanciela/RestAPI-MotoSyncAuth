// Imports necessários
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;
using MotoSyncAuth.Services;
using MotoSyncAuth.Models;
using MotoSyncAuth.DTOs;
using Microsoft.IdentityModel.Tokens;
using System.Text;


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
builder.Services.AddSingleton<UserService>();   // Simula usuários em memória

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

app.UseSwagger();
app.UseSwaggerUI();
app.UseCors("AllowAll");
app.UseRateLimiter(); // protege as rotas com limites de requisições
app.UseAuthentication();
app.UseAuthorization();



// -----------------------------------------------------------
// ROTAS DE AUTENTICAÇÃO
// -----------------------------------------------------------

var authGroup = app.MapGroup("/auth").WithTags("Autenticação");

// POST /auth/login → Realiza login e retorna JWT
authGroup.MapPost("/login", (LoginRequest request, UserService userService, JwtService jwt) =>
{
    //Valida se o usuário existe e se a senha está correta
    var user = userService.ValidateUser(request.Email, request.Password);
    if (user == null)
        return Results.Unauthorized();

    //Gera  token JWT para o usuário autenticado
    var token = jwt.GenerateToken(user);
    
    //Retorna o token e o nome do usuário
    return Results.Ok(new AuthResponse(user.Username, token));
})
.WithSummary("Login do usuário")
.WithDescription("Autentica o usuário e retorna um token JWT.")
.Produces<AuthResponse>(200)
.Produces(401)
.RequireRateLimiting("default");


// GET /auth/me → Retorna dados do usuário autenticado via token
authGroup.MapGet("/me", (HttpContext http, JwtService jwt) =>
{
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    return Results.Ok(user);
})
.WithSummary("Dados do usuário logado")
.WithDescription("Retorna os dados do usuário a partir do token JWT.")
.Produces<User>(200)
.Produces(401);


// POST /auth/forgot-password → Gera token de redefinição de senha
authGroup.MapPost("/forgot-password", (ForgotPasswordRequest request, UserService userService) =>
{
    var result = userService.GeneratePasswordResetToken(request.Email);
    return result ? Results.Ok("Token de redefinição gerado com sucesso.") : Results.NotFound("Usuário não encontrado.");
})
.WithSummary("Solicitação de redefinição de senha")
.WithDescription("Gera um token de redefinição de senha para o e-mail informado.")
.Produces<string>(200)
.Produces(404);

// POST /auth/reset-password → Redefine a senha com token
authGroup.MapPost("/reset-password", (ResetPasswordRequest request, UserService userService) =>
{
    var result = userService.ResetPassword(request.Token, request.NewPassword);
    return result ? Results.Ok("Senha redefinida com sucesso.") : Results.BadRequest("Token inválido ou expirado.");
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
userGroup.MapGet("/", (HttpContext http, UserService userService, JwtService jwt) =>
{
    // Extrai o usuário autenticado a partir do token JWT
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    // Obtém todos os usuários do sistema
    var users = userService.GetAllUsers();

    if (user.Role?.Name == "Administrador")
    {
        // Se for Administrador, retorna todos os usuários
        var response = users.Select(u => new UserResponse(u.Id, u.Username, u.Email, u.Role?.Name ?? ""));
        return Results.Ok(response);
    }
    else if (user.Role?.Name == "Gerente")
    {
        // Se for Gerente, retorna apenas Gerentes e Funcionários
        users = users.Where(u => u.Role?.Name == "Gerente" || u.Role?.Name == "Funcionario");
        var response = users.Select(u => new UserResponse(u.Id, u.Username, u.Email, u.Role?.Name ?? ""));
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
userGroup.MapGet("/{id}", (int id, HttpContext http, UserService userService, JwtService jwt) =>
{
    // Extrai o usuário autenticado a partir do token JWT
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    // Busca o usuário alvo pelo ID
    var targetUser = userService.GetUserById(id);
    if (targetUser == null)
        return Results.NotFound("Usuário não encontrado.");

    if (user.Role?.Name == "Administrador")
    {
        // Se for Administrador, pode visualizar qualquer usuário
        var response = new UserResponse(targetUser.Id, targetUser.Username, targetUser.Email, targetUser.Role?.Name ?? "");
        return Results.Ok(response);
    }
    else if (user.Role?.Name == "Gerente")
    {
        // Gerente pode visualizar Gerentes e Funcionários, mas não Administradores
        if (targetUser.Role?.Name == "Administrador")
            return Results.Forbid();

        var response = new UserResponse(targetUser.Id, targetUser.Username, targetUser.Email, targetUser.Role?.Name ?? "");
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


/// GET /users/by-email → Busca usuário pelo e-mail
userGroup.MapGet("/by-email", (string email, HttpContext http, UserService userService, JwtService jwt) =>
{
    // Extrai o usuário autenticado a partir do token JWT
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    // Busca o usuário alvo pelo e-mail informado
    var targetUser = userService.GetUserByEmail(email);
    if (targetUser == null)
        return Results.NotFound("Usuário não encontrado.");

    if (user.Role?.Name == "Administrador")
    {
        // Se for Administrador, pode visualizar qualquer usuário
        var response = new UserResponse(targetUser.Id, targetUser.Username, targetUser.Email, targetUser.Role?.Name ?? "");
        return Results.Ok(response);
    }
    else if (user.Role?.Name == "Gerente")
    {
        // Gerente pode visualizar Gerentes e Funcionários, mas não Administradores
        if (targetUser.Role?.Name == "Administrador")
            return Results.Forbid();

        var response = new UserResponse(targetUser.Id, targetUser.Username, targetUser.Email, targetUser.Role?.Name ?? "");
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



/// POST /users → Cria um novo usuário
userGroup.MapPost("/", (CreateUserRequest request, HttpContext http, UserService userService, JwtService jwt) =>
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

    // Cria o novo usuário
    var newUser = userService.CreateUser(request);
    if (newUser == null)
        return Results.BadRequest("E-mail já cadastrado.");

    // Mapeia para DTO
    var response = new UserResponse(newUser.Id, newUser.Username, newUser.Email, newUser.Role?.Name ?? "");
    return Results.Created($"/users/{newUser.Id}", response);
})
.WithSummary("Criar usuário")
.WithDescription("Administrador pode criar qualquer cargo. Gerente apenas Funcionários.")
.Produces<UserResponse>(201)
.Produces(401)
.Produces(403)
.Produces(400);


/// PUT /users/{id} → Atualiza os dados de um usuário
userGroup.MapPut("/{id}", (int id, UpdateUserRequest request, HttpContext http, UserService userService, JwtService jwt) =>
{
    // Extrai o usuário autenticado
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    // Funcionário não pode atualizar ninguém
    if (user.Role?.Name == "Funcionario")
        return Results.Forbid();

    // Busca o usuário alvo
    var targetUser = userService.GetUserById(id);
    if (targetUser == null)
        return Results.NotFound("Usuário não encontrado.");

    // Gerente só pode editar Funcionários
    if (user.Role?.Name == "Gerente" && targetUser.Role?.Name != "Funcionario")
        return Results.Forbid();

    // Executa a atualização
    var success = userService.UpdateUser(id, request);
    return success ? Results.Ok("Usuário atualizado.") : Results.BadRequest("Falha ao atualizar.");
})
.WithSummary("Atualizar usuário")
.WithDescription("Administrador pode editar qualquer usuário. Gerente apenas Funcionários.")
.Produces<string>(200)
.Produces(400)
.Produces(401)
.Produces(403)
.Produces(404);


// DELETE /users/{id} → Remove um usuário do sistema
userGroup.MapDelete("/{id}", (int id, HttpContext http, UserService userService, JwtService jwt) =>
{
    // Extrai o usuário autenticado
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    // Funcionário não pode excluir ninguém
    if (user.Role?.Name == "Funcionario")
        return Results.Forbid();

    // Busca o usuário alvo
    var targetUser = userService.GetUserById(id);
    if (targetUser == null)
        return Results.NotFound("Usuário não encontrado.");

    // Se for Gerente, só pode excluir Funcionários
    if (user.Role?.Name == "Gerente" && targetUser.Role?.Name != "Funcionario")
        return Results.Forbid();

    // Executa a exclusão
    var success = userService.DeleteUser(id);
    return success ? Results.Ok("Usuário excluído.") : Results.BadRequest("Erro ao excluir usuário.");
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
roleGroup.MapGet("/", (HttpContext http, JwtService jwt) =>
{
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    if (user.Role?.Name != "Administrador")
        return Results.Forbid();

    var roles = new List<RoleResponse>
    {
        new(1, "Administrador"),
        new(2, "Gerente"),
        new(3, "Funcionario")
    };
    return Results.Ok(roles);
})
.WithSummary("Listar roles")
.WithDescription("Apenas Administrador pode acessar.")
.Produces<IEnumerable<RoleResponse>>(200)
.Produces(401)
.Produces(403);


// GET /roles/{id} → Busca uma role por ID
roleGroup.MapGet("/{id}", (int id, HttpContext http, JwtService jwt) =>
{
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    if (user.Role?.Name != "Administrador")
        return Results.Forbid();

    var role = id switch
    {
        1 => new RoleResponse(1, "Administrador"),
        2 => new RoleResponse(2, "Gerente"),
        3 => new RoleResponse(3, "Funcionario"),
        _ => null
    };

    return role is not null ? Results.Ok(role) : Results.NotFound("Role não encontrada.");
})
.WithSummary("Buscar role por ID")
.WithDescription("Apenas Administrador pode consultar cargos.")
.Produces<RoleResponse>(200)
.Produces(401)
.Produces(403)
.Produces(404);


// POST /roles → Cria uma nova role
roleGroup.MapPost("/", (CreateRoleRequest request, HttpContext http, JwtService jwt) =>
{
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    if (user.Role?.Name != "Administrador")
        return Results.Forbid();

    // Simulação: cria uma role com ID fictício
    return Results.Created("/roles/999", new RoleResponse(999, request.Name));
})
.WithSummary("Criar role")
.WithDescription("Apenas Administrador pode criar novos cargos.")
.Produces<RoleResponse>(201)
.Produces(401)
.Produces(403);


// PUT /roles/{id} → Atualiza uma role existente
roleGroup.MapPut("/{id}", (int id, UpdateRoleRequest request, HttpContext http, JwtService jwt) =>
{
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    if (user.Role?.Name != "Administrador")
        return Results.Forbid();

    return id is >= 1 and <= 3
        ? Results.Ok($"Role {id} atualizada para: {request.Name}")
        : Results.NotFound("Role não encontrada.");
})
.WithSummary("Atualizar role")
.WithDescription("Apenas Administrador pode atualizar cargos.")
.Produces<string>(200)
.Produces(401)
.Produces(403)
.Produces(404);


/// DELETE /roles/{id} → Exclui uma role
roleGroup.MapDelete("/{id}", (int id, HttpContext http, JwtService jwt) =>
{
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null)
        return Results.Unauthorized();

    if (user.Role?.Name != "Administrador")
        return Results.Forbid();

    return id is >= 1 and <= 3
        ? Results.Ok($"Role {id} excluída com sucesso.")
        : Results.NotFound("Role não encontrada.");
})
.WithSummary("Excluir role")
.WithDescription("Apenas Administrador pode excluir cargos.")
.Produces<string>(200)
.Produces(401)
.Produces(403)
.Produces(404);


// 🚀 Inicializa o servidor
app.Run();
