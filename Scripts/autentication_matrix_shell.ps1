# 1. Configurações
$baseUrl = "http://localhost:8008"
$user = "tcc_user"
$pass = "tcc12345"

# 2. Fazer Login e obter o Token de Acesso
Write-Host "1. Tentando fazer login..." -ForegroundColor Cyan
$loginBody = @{
    type     = "m.login.password"
    user     = $user
    password = $pass
} | ConvertTo-Json

try {
    $loginResponse = Invoke-RestMethod -Uri "$baseUrl/_matrix/client/r0/login" -Method Post -Body $loginBody -ContentType "application/json"
    $token = $loginResponse.access_token
    Write-Host "Login realizado com SUCESSO!" -ForegroundColor Green
} catch {
    Write-Host "ERRO NO LOGIN. Verifique se o servidor Synapse está ativo." -ForegroundColor Red
    break
}

# 3. Criar a Sala 'Sensores'
Write-Host "2. Criando a sala 'Sensores'..." -ForegroundColor Cyan
$roomBody = @{
    name   = "Sensores"
    preset = "public_chat"
} | ConvertTo-Json

try {
    $roomResponse = Invoke-RestMethod -Uri "$baseUrl/_matrix/client/r0/createRoom?access_token=$token" -Method Post -Body $roomBody -ContentType "application/json"
    $roomId = $roomResponse.room_id
    Write-Host "Sala criada com SUCESSO!" -ForegroundColor Green
} catch {
    Write-Host "ERRO AO CRIAR SALA." -ForegroundColor Red
}

# 4. Exibir Resultados para Configuração
Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "ANOTE ESTES DADOS PARA O CONFIG DO COMATRIX:" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "ACCESS TOKEN: " -NoNewline; Write-Host $token -ForegroundColor White
Write-Host "ROOM ID: " -NoNewline; Write-Host $roomId -ForegroundColor White
Write-Host "========================================" -ForegroundColor Yellow