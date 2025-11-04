using MotoSyncAuth.ML;
using Microsoft.Extensions.ML; // Importa o PredictionEnginePool

namespace MotoSyncAuth.Services
{
    public class PasswordStrengthService
    {
        private readonly PredictionEnginePool<PasswordInput, PasswordStrengthPrediction> _pool;
        private readonly string _modelName = "PasswordStrengthModel"; // Mesmo nome do Program.cs

        // 1. Injetar o Pool
        public PasswordStrengthService(PredictionEnginePool<PasswordInput, PasswordStrengthPrediction> pool)
        {
            _pool = pool;
        }

        public PasswordStrengthPrediction Evaluate(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                return new PasswordStrengthPrediction
                {
                    Classification = "inválida",
                    Advice = "Senha vazia ou nula."
                };
            }

            var input = new PasswordInput { Password = password };

            // 4. Usar o modelo para prever!
            var prediction = _pool.Predict(modelName: _modelName, example: input);
            
            // 5. TRADUZIR a saída numérica do modelo para texto
            prediction.Classification = prediction.PredictedLabel switch
            {
                0 => "fraca",
                1 => "média",
                2 => "forte",
                _ => "desconhecida"
            };
            
            // 6. Adicionar o "Advice" com base na classificação
            prediction.Advice = prediction.Classification switch
            {
                "fraca" => "Use pelo menos 12 caracteres e inclua maiúsculas, números e símbolos.",
                "média" => "Boa base. Para uma senha forte, aumente o tamanho (>12) e garanta variedade.",
                "forte" => "Senha forte. Evite reutilizar essa senha em outros serviços.",
                _ => "Não foi possível classificar."
            };

            return prediction;
        }
    }
}