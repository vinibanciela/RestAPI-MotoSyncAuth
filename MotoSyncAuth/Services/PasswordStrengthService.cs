// Importa os pacotes necessários
using Microsoft.Extensions.ML; // Para o PredictionEnginePool
using MotoSyncAuth.ML;      // Para as classes de modelo (PasswordModelInput, PasswordStrengthPrediction)

namespace MotoSyncAuth.Services
{
    // Serviço responsável por avaliar a força de uma senha.
    // Ele serve como um "tradutor" entre o endpoint da API e o modelo de ML.
    public class PasswordStrengthService
    {
        // O PredictionEnginePool é a forma otimizada de usar modelos ML.NET em APIs.
        // Ele evita ter que carregar o modelo .zip do disco a cada requisição.
        private readonly PredictionEnginePool<PasswordModelInput, PasswordStrengthPrediction> _pool;
        
        // O nome do modelo que registramos no Program.cs.
        private readonly string _modelName = "PasswordStrengthModel";

        // O Construtor recebe o Pool de Predição via Injeção de Dependência (DI).
        public PasswordStrengthService(PredictionEnginePool<PasswordModelInput, PasswordStrengthPrediction> pool)
        {
            _pool = pool;
        }

        // Método principal que executa a avaliação.
        public PasswordStrengthPrediction Evaluate(string password)
        {
            // 1. Validação de Entrada: Se a senha for vazia, retorna um erro amigável.
            if (string.IsNullOrWhiteSpace(password))
            {
                return new PasswordStrengthPrediction
                {
                    Classification = "inválida",
                    Advice = "Senha vazia ou nula."
                };
            }

            // 2. Mapeamento de Entrada: Prepara o objeto que o modelo de ML espera.
            // O modelo foi treinado com 2 colunas (Password, Strength),
            // então precisamos fornecer as duas.
            var input = new PasswordModelInput
            {
                Password = password,
                Strength = 0 // Usamos 0 como um "valor dummy" (fictício) para
                             // satisfazer o contrato do modelo e evitar erros.
            };

            // 3. Inferência (Predição): Executa o modelo de ML.
            // O _pool usa o modelo .zip carregado para analisar o 'input'.
            var prediction = _pool.Predict(_modelName, input);

            // 4. Pós-processamento (Tradução da Saída):
            
            // O modelo retorna 'PredictedLabel' como um 'float' (ex: 1.0).
            // Precisamos convertê-lo (fazer o "cast") para 'int' (ex: 1) 
            // para que o 'switch' funcione.
            var label = (int)prediction.PredictedLabel;

            // Traduz o número (0, 1, 2) para um texto amigável.
            prediction.Classification = label switch
            {
                0 => "fraca",
                1 => "média",
                2 => "forte",
                _ => "desconhecida" // Caso de segurança
            };

            // Adiciona o conselho (advice) correspondente à classificação.
            prediction.Advice = prediction.Classification switch
            {
                "fraca" => "Use pelo menos 12 caracteres e inclua maiúsculas, números e símbolos.",
                "média" => "Boa base. Para uma senha forte, aumente o tamanho (>12) e garanta variedade.",
                "forte" => "Senha forte. Evite reutilizar essa senha em outros serviços.",
                _ => "Não foi possível classificar."
            };

            // 5. Retorno: Envia o objeto 'prediction' completo de volta ao endpoint.
            return prediction;
        }
    }
}