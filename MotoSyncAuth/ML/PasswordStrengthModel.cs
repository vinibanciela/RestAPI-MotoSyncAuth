using Microsoft.ML.Data;

namespace MotoSyncAuth.ML
{
    // Dados de entrada para o "modelo"
    // O [LoadColumn(0)] é usado para dizer ao ML.NET qual coluna do 
    // "arquivo de dados" (que não temos ainda) ele deve ler.
    public class PasswordInput
    {
        [LoadColumn(0)]
        public string Password { get; set; } = string.Empty;
    }

    // Saída prevista pelo "modelo"
    // Note que esta é uma classe C# simples (POCO).
    // Ela não precisa de atributos do ML.NET por enquanto.
    public class PasswordStrengthPrediction
    {
        // 0.0 fraca, 1.0 forte
        public float Score { get; set; }
        public string Classification { get; set; } = string.Empty;
        public string Advice { get; set; } = string.Empty;
    }
}