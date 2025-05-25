#!/bin/bash

# Atualiza os pacotes do sistema
sudo apt-get update -y

# Instala o Git
sudo apt-get install -y git

# Verifica a versão instalada
git --version
