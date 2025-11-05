using Microsoft.ML;

// Define os caminhos

// Para os dados
var dataPath = "passwords.csv";
// Para o Modelo (salva diretamente na pasta do projeto da API)
var modelPath = "../MotoSyncAuth/PasswordStrengthModel.zip";

// 1. Inicializar o MLContext
var mlContext = new MLContext(seed: 0); // Seed para reprodutibilidade

// 2. Carregar os dados do CSV
Console.WriteLine("Carregando dados (passwords.csv)...");
IDataView data = mlContext.Data.LoadFromTextFile<PasswordData>(dataPath, separatorChar: ',', hasHeader: true);

// 3. Definir o Pipeline de Treinamento (SIMPLES)
Console.WriteLine("Definindo o pipeline...");
var pipeline = 
    // Passo 1: Converter a "Label" (0, 1, 2) para "Key"
    mlContext.Transforms.Conversion.MapValueToKey(outputColumnName: "Label", inputColumnName: "Strength")

    // Passo 2: Featurize (Transformar a senha de texto em um vetor de números)
    .Append(mlContext.Transforms.Text.FeaturizeText(outputColumnName: "Features", inputColumnName: "Password"))
    
    // Passo 3: Adicionar o algoritmo de classificação
    .Append(mlContext.MulticlassClassification.Trainers.SdcaMaximumEntropy("Label", "Features"))
    
    // Passo 4: Converter a "Key" prevista de volta para o valor original (0, 1, 2)
    .Append(mlContext.Transforms.Conversion.MapKeyToValue(outputColumnName: "PredictedLabel"));

// 4. Treinar o modelo
Console.WriteLine("Treinando o modelo...");
var model = pipeline.Fit(data);

// 5. Salvar o modelo
Console.WriteLine($"Salvando modelo em {modelPath}...");
// Salva o modelo na pasta raiz da solução, para fácil acesso pela API
mlContext.Model.Save(model, data.Schema, modelPath);

Console.WriteLine("Treinamento concluído!");