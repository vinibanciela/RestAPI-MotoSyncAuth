#!/bin/bash

# Lista os containers ativos
echo "🔍 Listando containers em execução:"
docker ps

# Solicita o ID ou nome do container para testar
echo ""
read -p "Digite o ID ou nome do container da API: " CONTAINER_ID

# Executa o comando 'whoami' dentro do container
echo ""
echo "👤 Usuário em execução dentro do container:"
docker exec -it $CONTAINER_ID whoami
