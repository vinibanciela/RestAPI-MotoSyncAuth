using MotoSyncAuth.ML;
using System.Text.RegularExpressions;

namespace MotoSyncAuth.Services
{
    public class PasswordStrengthService
    {
        // No futuro, este serviço poderia carregar um PredictionEnginePool.
        // Por enquanto, ele apenas executa uma lógica de regras (heurística)
        // e retorna o mesmo objeto de "Prediction" que o ML.NET retornaria.

        public PasswordStrengthPrediction Evaluate(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                return new PasswordStrengthPrediction
                {
                    Score = 0f,
                    Classification = "inválida",
                    Advice = "Senha vazia ou nula."
                };
            }

            int length = password.Length;
            // Usamos Regex para checar a presença de diferentes tipos de caracteres
            bool hasUpper = Regex.IsMatch(password, "[A-Z]");
            bool hasLower = Regex.IsMatch(password, "[a-z]");
            bool hasDigit = Regex.IsMatch(password, "[0-9]");
            bool hasSymbol = Regex.IsMatch(password, "[^a-zA-Z0-9]"); // Qualquer coisa que não seja letra ou número

            // Heurística simples para score de 0.0 a 1.0
            float score = 0f;

            // 1. Bônus por Comprimento (peso maior)
            if (length >= 12) score += 0.4f;
            else if (length >= 8) score += 0.25f;
            else score += 0.1f;

            // 2. Bônus por Variedade (pesos menores)
            if (hasUpper)  score += 0.15f;
            if (hasLower)  score += 0.15f; // Bônus por ter minúsculas
            if (hasDigit)  score += 0.15f;
            if (hasSymbol) score += 0.15f;

            // Garante que o score não passe de 1.0 (caso tenha todas as 4 variedades E +12 chars)
            if (score > 1f) score = 1f;

            // 3. Classificar e dar conselhos com base no score
            string classification;
            string advice;

            if (score < 0.4f)
            {
                classification = "fraca";
                advice = "Use pelo menos 12 caracteres e inclua maiúsculas, números e símbolos.";
            }
            else if (score < 0.75f)
            {
                classification = "média";
                advice = "Boa base. Para uma senha forte, aumente o tamanho (>12) e garanta variedade de símbolos.";
            }
            else
            {
                classification = "forte";
                advice = "Senha forte. Evite reutilizar essa senha em outros serviços.";
            }

            return new PasswordStrengthPrediction
            {
                Score = score,
                Classification = classification,
                Advice = advice
            };
        }
    }
}