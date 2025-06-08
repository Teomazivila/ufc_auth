# Guia de Testes da API de Autenticação

Este documento fornece instruções abrangentes para testar a funcionalidade de autenticação da API UFC Auth.

## URL Base
```
http://localhost:3000/api/v1
```

## 1. Verificação de Saúde

### Verificar Saúde da API
```bash
curl -X GET http://localhost:3000/health
```

**Resposta Esperada:**
```json
{
  "status": "healthy",
  "timestamp": "2025-06-01T12:00:00.000Z",
  "services": {
    "database": "healthy",
    "redis": "healthy"
  }
}
```

## 2. Registo de Utilizador

### Registar Novo Utilizador
```bash
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test.user@example.com",
    "username": "testuser",
    "password": "SecurePassword123!",
    "confirmPassword": "SecurePassword123!",
    "firstName": "Test",
    "lastName": "User",
    "acceptTerms": true
  }'
```

**Resposta Esperada:**
```json
{
  "success": true,
  "data": {
    "message": "Registration successful",
    "user": {
      "id": 1,
      "email": "test.user@example.com",
      "username": "testuser",
      "first_name": "Test",
      "last_name": "User",
      "status": "pending_verification",
      "email_verified": false,
      "two_factor_enabled": false,
      "created_at": "2025-06-01T12:00:00.000Z"
    },
    "tokens": {
      "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expiresIn": "15m"
    }
  }
}
```

### Erros de Validação no Registo
```bash
# Campos obrigatórios em falta
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com"
  }'

# Palavras-passe não coincidem
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "username": "testuser",
    "password": "Password123!",
    "confirmPassword": "DifferentPassword123!",
    "firstName": "Test",
    "lastName": "User",
    "acceptTerms": true
  }'
```

## 3. Início de Sessão

### Início de Sessão Padrão
```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test.user@example.com",
    "password": "SecurePassword123!"
  }'
```

**Resposta Esperada:**
```json
{
  "success": true,
  "data": {
    "message": "Login successful",
    "user": {
      "id": 1,
      "email": "test.user@example.com",
      "username": "testuser",
      "first_name": "Test",
      "last_name": "User",
      "status": "active",
      "email_verified": true,
      "two_factor_enabled": false,
      "last_login": "2025-06-01T12:00:00.000Z"
    },
    "tokens": {
      "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expiresIn": "15m"
    }
  }
}
```

### Início de Sessão com "Lembrar-me"
```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test.user@example.com",
    "password": "SecurePassword123!",
    "rememberMe": true
  }'
```

### Credenciais Inválidas
```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test.user@example.com",
    "password": "WrongPassword"
  }'
```

**Resposta Esperada:**
```json
{
  "success": false,
  "error": {
    "message": "Invalid email or password",
    "code": "UNAUTHORIZED"
  }
}
```

## 4. Gestão de Tokens

### Obter Perfil do Utilizador Actual
```bash
# Substitua YOUR_ACCESS_TOKEN pelo token real da resposta de login
curl -X GET http://localhost:3000/api/v1/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Resposta Esperada:**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": 1,
      "email": "test.user@example.com",
      "username": "testuser",
      "first_name": "Test",
      "last_name": "User",
      "status": "active",
      "email_verified": true,
      "two_factor_enabled": false,
      "last_login": "2025-06-01T12:00:00.000Z"
    }
  }
}
```

### Renovar Token de Acesso
```bash
curl -X POST http://localhost:3000/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN"
  }'
```

**Resposta Esperada:**
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expiresIn": "15m"
  }
}
```

### Verificar Estado de Autenticação
```bash
curl -X GET http://localhost:3000/api/v1/auth/status \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## 5. Autenticação de Dois Factores (2FA)

### Configurar 2FA
```bash
curl -X POST http://localhost:3000/api/v1/auth/2fa/setup \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json"
```

**Resposta Esperada:**
```json
{
  "success": true,
  "data": {
    "message": "2FA setup initiated. Scan the QR code with your authenticator app.",
    "qrCode": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
    "manualEntryKey": "JBSWY3DPEHPK3PXP",
    "backupCodes": null
  }
}
```

### Verificar e Activar 2FA
```bash
# Substitua 123456 pelo código TOTP real da aplicação autenticadora
curl -X POST http://localhost:3000/api/v1/auth/2fa/verify-setup \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "twoFactorToken": "123456"
  }'
```

**Resposta Esperada:**
```json
{
  "success": true,
  "data": {
    "message": "2FA has been successfully enabled for your account",
    "backupCodes": [
      "A1B2C3D4",
      "E5F6G7H8",
      "I9J0K1L2",
      "M3N4O5P6",
      "Q7R8S9T0",
      "U1V2W3X4",
      "Y5Z6A7B8",
      "C9D0E1F2",
      "G3H4I5J6",
      "K7L8M9N0"
    ],
    "warning": "Save these backup codes in a secure location. They can only be used once each."
  }
}
```

### Início de Sessão com 2FA
```bash
# Primeira tentativa - irá requerer 2FA
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test.user@example.com",
    "password": "SecurePassword123!"
  }'
```

**Resposta Esperada (2FA Requerido):**
```json
{
  "success": true,
  "data": {
    "requiresTwoFactor": true,
    "message": "2FA verification required",
    "userId": 1
  }
}
```

```bash
# Segunda tentativa - com token 2FA
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test.user@example.com",
    "password": "SecurePassword123!",
    "twoFactorToken": "123456"
  }'
```

### Início de Sessão com Código de Backup
```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test.user@example.com",
    "password": "SecurePassword123!",
    "backupCode": "A1B2C3D4"
  }'
```

### Verificar 2FA para Sessão Actual
```bash
curl -X POST http://localhost:3000/api/v1/auth/2fa/verify \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "twoFactorToken": "123456"
  }'
```

### Desactivar 2FA
```bash
curl -X POST http://localhost:3000/api/v1/auth/2fa/disable \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json"
```

## 6. Gestão de Palavras-passe

### Alterar Palavra-passe
```bash
curl -X POST http://localhost:3000/api/v1/auth/change-password \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "currentPassword": "SecurePassword123!",
    "newPassword": "NewSecurePassword456!",
    "confirmPassword": "NewSecurePassword456!"
  }'
```

### Solicitar Redefinição de Palavra-passe
```bash
curl -X POST http://localhost:3000/api/v1/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test.user@example.com"
  }'
```

## 7. Terminar Sessão

### Terminar Sessão Padrão
```bash
curl -X POST http://localhost:3000/api/v1/auth/logout \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN"
  }'
```

### Terminar Sessão em Todos os Dispositivos
```bash
curl -X POST http://localhost:3000/api/v1/auth/logout-all \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json"
```

## 8. Cenários de Erro

### Token Expirado
```bash
curl -X GET http://localhost:3000/api/v1/auth/me \
  -H "Authorization: Bearer EXPIRED_TOKEN"
```

**Resposta Esperada:**
```json
{
  "success": false,
  "error": {
    "message": "Access token expired",
    "code": "UNAUTHORIZED"
  }
}
```

### Token Inválido
```bash
curl -X GET http://localhost:3000/api/v1/auth/me \
  -H "Authorization: Bearer INVALID_TOKEN"
```

### Cabeçalho de Autorização em Falta
```bash
curl -X GET http://localhost:3000/api/v1/auth/me
```

### Teste de Limitação de Taxa
```bash
# Execute este comando várias vezes rapidamente (>10 vezes em 15 minutos)
for i in {1..12}; do
  curl -X POST http://localhost:3000/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{
      "email": "nonexistent@example.com",
      "password": "wrongpassword"
    }'
  echo "Tentativa $i"
done
```

## 9. Fluxo de Testes Completo

### Passo 1: Registar um novo utilizador
```bash
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "workflow@example.com",
    "username": "workflowuser",
    "password": "WorkflowPassword123!",
    "confirmPassword": "WorkflowPassword123!",
    "firstName": "Workflow",
    "lastName": "User",
    "acceptTerms": true
  }'
```

### Passo 2: Actualizar estado do utilizador para activo (se necessário)
```bash
# Isto pode ser necessário se o estado do utilizador for "pending_verification"
# Pode actualizar directamente na base de dados ou implementar verificação de email
```

### Passo 3: Iniciar sessão e obter tokens
```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "workflow@example.com",
    "password": "WorkflowPassword123!"
  }'
```

### Passo 4: Testar endpoint protegido
```bash
curl -X GET http://localhost:3000/api/v1/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Passo 5: Configurar 2FA
```bash
curl -X POST http://localhost:3000/api/v1/auth/2fa/setup \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Passo 6: Verificar e activar 2FA
```bash
curl -X POST http://localhost:3000/api/v1/auth/2fa/verify-setup \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "twoFactorToken": "TOTP_CODE_FROM_APP"
  }'
```

### Passo 7: Testar início de sessão com 2FA
```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "workflow@example.com",
    "password": "WorkflowPassword123!",
    "twoFactorToken": "TOTP_CODE_FROM_APP"
  }'
```

### Passo 8: Testar renovação de token
```bash
curl -X POST http://localhost:3000/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN"
  }'
```

### Passo 9: Testar terminar sessão
```bash
curl -X POST http://localhost:3000/api/v1/auth/logout \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN"
  }'
```

## 10. Variáveis de Ambiente

Certifique-se de que estas variáveis de ambiente estão configuradas correctamente:

```bash
# Base de Dados
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_NAME=ufc_auth
DATABASE_USER=postgres
DATABASE_PASSWORD=postgres123

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# JWT
JWT_SECRET=your-super-secret-jwt-key-change-in-production
JWT_REFRESH_SECRET=your-super-secret-refresh-key-change-in-production
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# 2FA
TWO_FACTOR_SERVICE_NAME=UFC Auth API
TWO_FACTOR_ISSUER=UFC Auth
```

## 11. Problemas Comuns e Soluções

### Problema: "Invalid access token"
- **Solução**: Certifique-se de que está a usar o formato correcto do token: `Bearer YOUR_TOKEN`
- **Verificar**: Token não expirou (15 minutos por defeito)
- **Verificar**: Token não foi colocado na lista negra após terminar sessão

### Problema: "User not found" após registo
- **Solução**: Verificar se o estado do utilizador é "active" na base de dados
- **Corrigir**: Actualizar estado do utilizador: `UPDATE users SET status = 'active' WHERE email = 'your@email.com';`

### Problema: Configuração de 2FA falha
- **Solução**: Certificar-se de que o Redis está a funcionar e acessível
- **Verificar**: 2FA não está já activado para o utilizador

### Problema: Erros de limitação de taxa
- **Solução**: Aguardar 15 minutos ou limpar chaves de limitação de taxa do Redis
- **Limpar**: `redis-cli FLUSHDB` (apenas desenvolvimento)

## 12. Consultas de Base de Dados para Testes

### Verificar estado do utilizador
```sql
SELECT id, email, status, email_verified, two_factor_enabled, login_attempts, locked_until 
FROM users WHERE email = 'your@email.com';
```

### Activar conta de utilizador
```sql
UPDATE users SET status = 'active', email_verified = true WHERE email = 'your@email.com';
```

### Redefinir tentativas de início de sessão falhadas
```sql
UPDATE users SET login_attempts = 0, locked_until = NULL WHERE email = 'your@email.com';
```

### Desactivar 2FA para testes
```sql
UPDATE users SET two_factor_enabled = false, two_factor_secret = NULL, backup_codes = NULL 
WHERE email = 'your@email.com';
```

---

**Nota**: Substitua `YOUR_ACCESS_TOKEN`, `YOUR_REFRESH_TOKEN`, e `TOTP_CODE_FROM_APP` pelos valores reais das suas respostas da API e aplicação autenticadora. 