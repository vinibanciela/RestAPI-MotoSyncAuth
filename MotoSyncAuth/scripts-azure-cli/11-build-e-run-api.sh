#!/bin/bash

# Caminho para o diretório onde está o Dockerfile
cd ~/java-api-cloud

# Build da imagem Docker da API Java
sudo docker build -t java-api-crud .

# Sobe o container em segundo plano (detach), mapeando porta 8080
sudo docker run -d -p 8080:8080 java-api-crud
