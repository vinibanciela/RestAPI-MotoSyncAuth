using MotoSyncAuth.Models;
using MotoSyncAuth.DTOs;
using System.Security.Cryptography;
using System.Text;

namespace MotoSyncAuth.Services;

public class UserService
{
    // Lista em memória simulando um banco de dados de usuários
    private readonly List<User> _users = new()
    {
        new User
        {
            Id = 1,
            Username = "Admin",
            Email = "admin@mottu.com",
            PasswordHash = HashPassword("admin123"),
            Role = new Role { Id = 1, Name = "Administrador" }
        },
        new User
        {
            Id = 2,
            Username = "Gerente",
            Email = "gerente@mottu.com",
            PasswordHash = HashPassword("gerente123"),
            Role = new Role { Id = 2, Name = "Gerente" }
        },
        new User
        {
            Id = 3,
            Username = "Funcionario",
            Email = "funcionario@mottu.com",
            PasswordHash = HashPassword("func123"),
            Role = new Role { Id = 3, Name = "Funcionario" }
        }
    };

    private int _nextId = 4;

    // ------------------ Métodos para autenticação ------------------

    // Valida email e senha para login (/auth/login)
    public User? ValidateUser(string email, string password)
    {
        var hash = HashPassword(password);
        var user = _users.FirstOrDefault(u =>
            u.Email.Equals(email, StringComparison.OrdinalIgnoreCase)
            && u.PasswordHash == hash);
        return user;
    }
    
    // ------------------ Métodos de recuperação ------------------

    // Gera token de reset de senha (/auth/forgot-password)
    public bool GeneratePasswordResetToken(string email)
    {
        var user = _users.FirstOrDefault(u => u.Email.Equals(email, StringComparison.OrdinalIgnoreCase));
        if (user == null) return false;

        user.PasswordResetToken = Guid.NewGuid().ToString();
        user.PasswordResetTokenExpiration = DateTime.UtcNow.AddMinutes(15);
        return true;
    }

    // Redefine senha com token válido (/auth/reset-password)
    public bool ResetPassword(string token, string newPassword)
    {
        var user = _users.FirstOrDefault(u =>
            u.PasswordResetToken == token &&
            u.PasswordResetTokenExpiration.HasValue &&
            u.PasswordResetTokenExpiration > DateTime.UtcNow);

        if (user == null) return false;

        user.PasswordHash = HashPassword(newPassword);
        user.PasswordResetToken = null;
        user.PasswordResetTokenExpiration = null;
        return true;
    }

    // ------------------ CRUD de usuários (/users) ------------------

    // Retorna todos os usuários (/users)
    public IEnumerable<User> GetAllUsers() => _users;

    // Retorna um usuário pelo ID (/users/{id})
    public User? GetUserById(int id) => _users.FirstOrDefault(u => u.Id == id);

    // Retorna um usuário pelo email (/users/by-email)
    public User? GetUserByEmail(string email) =>
        _users.FirstOrDefault(u => u.Email.Equals(email, StringComparison.OrdinalIgnoreCase));
    
    // Cria um novo usuário (/users [POST])
    public User? CreateUser(CreateUserRequest request)
    {
        if (_users.Any(u => u.Email.Equals(request.Email, StringComparison.OrdinalIgnoreCase)))
            return null;

        var user = new User
        {
            Id = _nextId++,
            Username = request.Username,
            Email = request.Email,
            PasswordHash = HashPassword(request.Password),
            Role = new Role
            {
                Id = request.RoleId,
                Name = request.RoleId == 1 ? "Administrador" : request.RoleId == 2 ? "Gerente" : "Funcionario",
            }
        };

        _users.Add(user);
        return user;
    }

    // Atualiza um usuário existente (/users/{id} [PUT])
    public bool UpdateUser(int id, UpdateUserRequest request)
    {
        var user = GetUserById(id);
        if (user == null) return false;

        if (!string.IsNullOrWhiteSpace(request.Username))
            user.Username = request.Username;
        if (!string.IsNullOrWhiteSpace(request.Email))
            user.Email = request.Email;
        if (!string.IsNullOrWhiteSpace(request.Password))
            user.PasswordHash = HashPassword(request.Password);
        if (request.RoleId.HasValue)
        {
            user.Role = new Role
            {
                Id = request.RoleId.Value,
                Name = request.RoleId == 1 ? "Administrador" : request.RoleId == 2 ? "Gerente" : "Funcionario",
            };
        }

        return true;
    }

    // Deleta um usuário (/users/{id} [DELETE])
    public bool DeleteUser(int id)
    {
        var user = GetUserById(id);
        if (user == null) return false;
        _users.Remove(user);
        return true;
    }

    // Utilitário para gerar hash de senha (simples com SHA256)
    private static string HashPassword(string password)
    {
        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
        return Convert.ToBase64String(bytes);
    }
}
