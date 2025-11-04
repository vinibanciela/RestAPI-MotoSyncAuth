using Microsoft.ML.Data;
using System.Text.Json.Serialization;

namespace MotoSyncAuth.ML
{
    // Dados de entrada para o modelo
    // O [LoadColumn(0)] é usado para dizer ao ML.NET qual coluna do arquivo de dados ele deve ler.
    public class PasswordInput
    {
        [LoadColumn(0)]
        public string Password { get; set; } = string.Empty;
    }

    // Dados de saída do modelo
    public class PasswordStrengthPrediction
    {
        // O modelo vai cuspir o "Label" previsto (0, 1, ou 2)
        // O ML.NET usa "Key" (um tipo uint) para labels de classificação
        [ColumnName("PredictedLabel")]
        public uint PredictedLabel { get; set; } 

        // O modelo também nos dá as probabilidades de cada classe
        public float[] Score { get; set; } = Array.Empty<float>();

        // --- Campos que nosso serviço C# vai preencher ---
        // (Eles não vêm do modelo, por isso não têm atributos)

        public string Classification { get; set; } = string.Empty;
        public string Advice { get; set; } = string.Empty;

        // Propriedade "calculada" para o JSON de resposta
        public float Confidence => Score.Length > 0 ? Score.Max() : 0;

        // Vamos esconder o array de Scores do JSON final,
        // pois "Confidence" (a maior prob.) é mais amigável.
        [JsonIgnore]
        public float[] ScoresInternal => Score;
    }
}