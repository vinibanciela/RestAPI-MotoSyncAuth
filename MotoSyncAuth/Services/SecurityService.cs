using BCrypt.Net;

namespace MotoSyncAuth.Services
{
    public static class SecurityService
    {
        // Cria o hash do password usando BCrypt
        public static string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password);
        }

        // Verifica se o password corresponde ao hash
        public static bool VerifyPassword(string password, string hashedPassword)
        {
            return BCrypt.Net.BCrypt.Verify(password, hashedPassword);
        }
    }
}