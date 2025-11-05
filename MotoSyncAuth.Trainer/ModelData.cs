using Microsoft.ML.Data;

// O que lemos do CSV
public class PasswordData
{
    [LoadColumn(0)]
    public string Password { get; set; } = "";

    [LoadColumn(1)]
    public float Strength { get; set; } // 0, 1, 2
}

// O que o modelo cospe
public class PasswordPrediction
{
    // Apenas o Label previsto (0, 1, 2)
    [ColumnName("PredictedLabel")]
    public uint PredictedLabel { get; set; }

    // E os scores
    public float[] Score { get; set; } = Array.Empty<float>();
}