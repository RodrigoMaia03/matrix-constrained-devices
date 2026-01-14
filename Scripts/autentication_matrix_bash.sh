#!/bin/bash

# Configurações iniciais
BASE_URL="http://localhost:8008"
USER="tcc_user"
PASS="tcc12345"

echo "1. Tentando fazer login..."
LOGIN_JSON=$(printf '{"type":"m.login.password", "user":"%s", "password":"%s"}' "$USER" "$PASS")

# Requisição de Login
RESPONSE=$(curl -s -X POST -d "$LOGIN_JSON" "$BASE_URL/_matrix/client/r0/login")
TOKEN=$(echo $RESPONSE | grep -oP '(?<="access_token":")[^"]*')

if [ -z "$TOKEN" ]; then
    echo "ERRO NO LOGIN. Verifique as credenciais e o servidor."
    exit 1
fi

echo "Login realizado com SUCESSO!"

# Requisição de Criação de Sala
echo "2. Criando a sala 'Sensores'..."
ROOM_JSON='{"name":"Sensores", "preset":"public_chat"}'
ROOM_RESPONSE=$(curl -s -X POST -d "$ROOM_JSON" "$BASE_URL/_matrix/client/r0/createRoom?access_token=$TOKEN")
ROOM_ID=$(echo $ROOM_RESPONSE | grep -oP '(?<="room_id":")[^"]*')

# Exibição de Dados Finais
echo -e "\n========================================"
echo "DADOS PARA CONFIGURAÇÃO DO COMATRIX:"
echo "========================================"
echo "ACCESS TOKEN: $TOKEN"
echo "ROOM ID: $ROOM_ID"
echo "========================================"