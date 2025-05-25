#!/bin/bash

# Remove versões antigas
sudo apt-get remove docker docker-engine docker.io containerd runc -y

# Atualiza pacotes
sudo apt-get update -y

# Instala dependências
sudo apt-get install -y ca-certificates curl gnupg lsb-release

# Adiciona chave GPG oficial do Docker
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Adiciona repositório do Docker
echo \
  "deb [arch=$(dpkg --print-architecture) \
  signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Atualiza pacotes novamente e instala Docker
sudo apt-get update -y
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Verifica se Docker está funcionando
sudo docker --version
