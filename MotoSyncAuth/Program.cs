// Imports necessários
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;
using MotoSyncAuth.Services;
using MotoSyncAuth.Models;
using MotoSyncAuth.DTOs;

var builder = WebApplication.CreateBuilder(args);

// -----------------------------------------------------------
// REGISTRO DE SERVIÇOS
// -----------------------------------------------------------

// Swagger (documentação automática da API)
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

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

var app = builder.Build();

// -----------------------------------------------------------
// MIDDLEWARES DO PIPELINE HTTP
// -----------------------------------------------------------

app.UseSwagger();
app.UseSwaggerUI();
app.UseCors("AllowAll");
app.UseRateLimiter(); // protege as rotas com limites de requisições

// -----------------------------------------------------------
// ROTAS DE AUTENTICAÇÃO
// -----------------------------------------------------------

var authGroup = app.MapGroup("/auth").WithTags("Autenticação");

// POST /auth/login → Realiza login e retorna JWT
authGroup.MapPost("/login", (LoginRequest request, UserService userService, JwtService jwt) =>
{
    var user = userService.ValidateUser(request.Email, request.Password);
    if (user == null)
        return Results.Unauthorized(); // email/senha inválidos

    var token = jwt.GenerateToken(user);
    return Results.Ok(new AuthResponse(user.Username, token));
})
.WithSummary("Login do usuário")
.WithDescription("Autentica o usuário e retorna um token JWT.")
.Produces<AuthResponse>()   // retorno esperado
.Produces(401)              // retorno se falhar
.RequireRateLimiting("default"); // aplica controle de frequência

// GET /auth/me → Retorna dados do usuário autenticado via token
authGroup.MapGet("/me", (HttpContext http, JwtService jwt, UserService userService) =>
{
    var user = jwt.ExtractUserFromRequest(http);
    if (user == null) return Results.Unauthorized();
    return Results.Ok(user);
})
.WithSummary("Dados do usuário logado")
.Produces<User>()
.Produces(401);

// POST /auth/forgot-password → Gera token de redefinição de senha
authGroup.MapPost("/forgot-password", (ForgotPasswordRequest request, UserService userService) =>
{
    var result = userService.GeneratePasswordResetToken(request.Email);
    return result ? Results.Ok("Token de redefinição gerado com sucesso.") : Results.NotFound("Usuário não encontrado.");
})
.WithSummary("Solicitação de redefinição de senha")
.WithDescription("Gera um token de redefinição de senha para o e-mail informado.")
.Produces<string>()
.Produces(404);

// POST /auth/reset-password → Redefine a senha com token
authGroup.MapPost("/reset-password", (ResetPasswordRequest request, UserService userService) =>
{
    var result = userService.ResetPassword(request.Token, request.NewPassword);
    return result ? Results.Ok("Senha redefinida com sucesso.") : Results.BadRequest("Token inválido ou expirado.");
})
.WithSummary("Redefinir senha")
.WithDescription("Permite redefinir a senha com um token válido.")
.Produces<string>()
.Produces(400);

// POST /auth/refresh-token → Renova JWT com base no refresh token
authGroup.MapPost("/refresh-token", (HttpContext http, UserService userService, JwtService jwt) =>
{
    var refreshToken = http.Request.Headers["X-Refresh-Token"].ToString();
    var user = userService.ValidateRefreshToken(refreshToken);

    if (user == null || user.RefreshTokenExpiration < DateTime.UtcNow)
        return Results.Unauthorized();

    var newToken = jwt.GenerateToken(user);
    return Results.Ok(new AuthResponse(user.Username, newToken));
})
.WithSummary("Renova o JWT com base no Refresh Token")
.WithDescription("Valida o refresh token e retorna um novo token JWT válido.")
.Produces<AuthResponse>()
.Produces(401);

// -----------------------------------------------------------
// ROTAS DE GESTÃO DE USUÁRIOS
// -----------------------------------------------------------

var userGroup = app.MapGroup("/users").WithTags("Usuários");

// GET /users → Lista todos os usuários
userGroup.MapGet("/", (UserService userService) =>
{
    var users = userService.GetAllUsers()
        .Select(u => new UserResponse(u.Id, u.Username, u.Email, u.Role?.Name ?? ""));
    return Results.Ok(users);
})
.WithSummary("Listar usuários")
.WithDescription("Retorna todos os usuários do sistema.")
.Produces<IEnumerable<UserResponse>>();

// GET /users/{id} → Busca um usuário por ID
userGroup.MapGet("/{id}", (int id, UserService userService) =>
{
    var user = userService.GetUserById(id);
    return user is null 
        ? Results.NotFound() 
        : Results.Ok(new UserResponse(user.Id, user.Username, user.Email, user.Role?.Name ?? ""));
})
.WithSummary("Buscar usuário por ID")
.Produces<UserResponse>()
.Produces(404);

// GET /users/by-email → Busca usuário pelo e-mail
userGroup.MapGet("/by-email", (string email, UserService userService) =>
{
    var user = userService.GetUserByEmail(email);
    return user is null 
        ? Results.NotFound() 
        : Results.Ok(new UserResponse(user.Id, user.Username, user.Email, user.Role?.Name ?? ""));
})
.WithSummary("Buscar usuário por e-mail")
.Produces<UserResponse>()
.Produces(404);

// GET /users/{id}/permissions → Lista as permissões do usuário
userGroup.MapGet("/{id}/permissions", (int id, UserService userService) => 
{
    var permissions = userService.GetUserPermissions(id);
    return permissions is null
        ? Results.NotFound("Usuário ou permissões não encontradas.")
        : Results.Ok(permissions);
})
.WithSummary("Permissões do usuário")
.WithDescription("Retorna as permissões associadas ao usuário.")
.Produces<IEnumerable<string>>()
.Produces(404);

// POST /users → Cria um novo usuário
userGroup.MapPost("/", (CreateUserRequest request, UserService userService) =>
{
    var user = userService.CreateUser(request);
    return user is null 
        ? Results.BadRequest("Email já cadastrado.")
        : Results.Ok(new UserResponse(user.Id, user.Username, user.Email, user.Role?.Name ?? ""));
})
.WithSummary("Criar usuário")
.WithDescription("Cria um novo usuário com base no payload recebido.")
.Produces<UserResponse>()
.Produces(400);

// PUT /users/{id} → Atualiza os dados de um usuário
userGroup.MapPut("/{id}", (int id, UpdateUserRequest request, UserService userService) =>
{
    var success = userService.UpdateUser(id, request);
    return success ? Results.Ok("Usuário atualizado.") : Results.NotFound("Usuário não encontrado.");
})
.WithSummary("Atualizar usuário")
.WithDescription("Atualiza parcialmente os dados do usuário.")
.Produces<string>()
.Produces(404);

// DELETE /users/{id} → Remove um usuário do sistema
userGroup.MapDelete("/{id}", (int id, UserService userService) =>
{
    var success = userService.DeleteUser(id);
    return success ? Results.Ok("Usuário excluído.") : Results.NotFound("Usuário não encontrado.");
})
.WithSummary("Deletar usuário")
.WithDescription("Remove o usuário com base no ID informado.")
.Produces<string>()
.Produces(404);

// -----------------------------------------------------------
// ROTAS DE GESTÃO DE CARGOS (ROLES)
// -----------------------------------------------------------

var roleGroup = app.MapGroup("/roles").WithTags("Cargos");

// GET /roles → Lista todas as roles
roleGroup.MapGet("/", () =>
{
    var roles = new List<RoleResponse>
    {
        new(1, "Administrador"),
        new(2, "Gerente"),
        new(3, "Funcionario")
    };
    return Results.Ok(roles);
})
.WithSummary("Listar roles")
.WithDescription("Retorna todos os cargos disponíveis.")
.Produces<IEnumerable<RoleResponse>>();

// GET /roles/{id} → Busca uma role por ID
roleGroup.MapGet("/{id}", (int id) =>
{
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
.Produces<RoleResponse>()
.Produces(404);

// POST /roles → Cria uma nova role
roleGroup.MapPost("/", (CreateRoleRequest request) =>
{
    // Simulação de criação (sem persistência)
    return Results.Created($"/roles/999", new RoleResponse(999, request.Name));
})
.WithSummary("Criar role")
.WithDescription("Cria um novo cargo no sistema.")
.Produces<RoleResponse>(201);

// PUT /roles/{id} → Atualiza uma role existente
roleGroup.MapPut("/{id}", (int id, UpdateRoleRequest request) =>
{
    return id is >= 1 and <= 3
        ? Results.Ok($"Role {id} atualizada para: {request.Name}")
        : Results.NotFound("Role não encontrada.");
})
.WithSummary("Atualizar role")
.Produces<string>()
.Produces(404);

// DELETE /roles/{id} → Exclui uma role
roleGroup.MapDelete("/{id}", (int id) =>
{
    return id is >= 1 and <= 3
        ? Results.Ok($"Role {id} excluída com sucesso.")
        : Results.NotFound("Role não encontrada.");
})
.WithSummary("Excluir role")
.Produces<string>()
.Produces(404);

// -----------------------------------------------------------
// ROTAS DE GESTÃO DE PERMISSÕES
// -----------------------------------------------------------

var permissionGroup = app.MapGroup("/permissions").WithTags("Permissões");

// GET /permissions → Lista todas as permissões
permissionGroup.MapGet("/", () =>
{
    var permissions = new List<PermissionResponse>
    {
        new(1, "All"),
        new(2, "ManageUsers"),
        new(3, "ViewDashboard")
    };
    return Results.Ok(permissions);
})
.WithSummary("Listar permissões")
.WithDescription("Retorna todas as permissões disponíveis.")
.Produces<IEnumerable<PermissionResponse>>();

// GET /permissions/{id} → Busca permissão por ID
permissionGroup.MapGet("/{id}", (int id) =>
{
    var permission = id switch
    {
        1 => new PermissionResponse(1, "All"),
        2 => new PermissionResponse(2, "ManageUsers"),
        3 => new PermissionResponse(3, "ViewDashboard"),
        _ => null
    };
    return permission is not null ? Results.Ok(permission) : Results.NotFound("Permissão não encontrada.");
})
.WithSummary("Buscar permissão por ID")
.Produces<PermissionResponse>()
.Produces(404);

// POST /permissions → Cria nova permissão
permissionGroup.MapPost("/", (CreatePermissionRequest request) =>
{
    // Simulação: cria uma permissão com ID fictício
    return Results.Created("/permissions/999", new PermissionResponse(999, request.Name));
})
.WithSummary("Criar permissão")
.WithDescription("Cria uma nova permissão no sistema.")
.Produces<PermissionResponse>(201);

// PUT /permissions/{id} → Atualiza permissão
permissionGroup.MapPut("/{id}", (int id, UpdatePermissionRequest request) =>
{
    return id is >= 1 and <= 3
        ? Results.Ok($"Permissão {id} atualizada para: {request.Name}")
        : Results.NotFound("Permissão não encontrada.");
})
.WithSummary("Atualizar permissão")
.Produces<string>()
.Produces(404);

// DELETE /permissions/{id} → Exclui permissão
permissionGroup.MapDelete("/{id}", (int id) =>
{
    return id is >= 1 and <= 3
        ? Results.Ok($"Permissão {id} excluída com sucesso.")
        : Results.NotFound("Permissão não encontrada.");
})
.WithSummary("Excluir permissão")
.Produces<string>()
.Produces(404);

// 🚀 Inicializa o servidor
app.Run();
