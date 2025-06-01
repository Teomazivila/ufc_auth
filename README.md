# UFC Auth API - Sistema de Gestão de Identidades

[![Node.js](https://img.shields.io/badge/Node.js-20+-green.svg)](https://nodejs.org/)
[![Express](https://img.shields.io/badge/Express-4.19+-blue.svg)](https://expressjs.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16+-blue.svg)](https://postgresql.org/)
[![Redis](https://img.shields.io/badge/Redis-7+-red.svg)](https://redis.io/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com/)

API REST robusta e segura para gestão de identidades digitais com autenticação forte, desenvolvida como projeto de mestrado em Ciência da Computação com especialização em Cibersegurança.

## 🚀 Características Principais

- **Autenticação Multifactor (2FA)** - TOTP, SMS e email backup
- **Controlo de Acesso Baseado em Funções (RBAC)** - Sistema hierárquico de permissões
- **Segurança Avançada** - Rate limiting, detecção de ataques, auditoria completa
- **JWT com Refresh Tokens** - Gestão segura de sessões
- **Infraestrutura Docker** - Deployment simplificado e escalável
- **Documentação OpenAPI** - API completamente documentada
- **Testes Automatizados** - Cobertura superior a 80%

## 🏗️ Arquitetura

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   API Gateway   │    │   Auth API      │
│   (Cliente)     │◄──►│   (Nginx)       │◄──►│   (Node.js)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
                       ┌─────────────────┐             │
                       │     Redis       │◄────────────┤
                       │    (Cache)      │             │
                       └─────────────────┘             │
                                                        │
                       ┌─────────────────┐             │
                       │   PostgreSQL    │◄────────────┘
                       │   (Database)    │
                       └─────────────────┘
```

## 🛠️ Stack Tecnológico

- **Backend**: Node.js 20+ com Express.js
- **Base de Dados**: PostgreSQL 16 com extensões UUID
- **Cache**: Redis 7 para sessões e rate limiting
- **Autenticação**: JWT + bcrypt + speakeasy (2FA)
- **Containerização**: Docker com multi-stage builds
- **Documentação**: Swagger/OpenAPI 3.0
- **Testes**: Jest com SuperTest
- **Linting**: ESLint + Prettier

## 📋 Pré-requisitos

- Docker 24.0+ e Docker Compose 2.0+
- Node.js 20+ (para desenvolvimento local)
- Git

## 🚀 Início Rápido

### 1. Clonar o Repositório

```bash
git clone <repository-url>
cd ufc_auth
```

### 2. Configurar Variáveis de Ambiente

```bash
cp env.example .env
# Editar .env com as suas configurações
```

### 3. Iniciar com Docker

```bash
# Desenvolvimento
docker-compose up -d

# Produção
docker-compose --profile production up -d
```

### 4. Verificar Serviços

```bash
docker-compose ps
```

## 🌐 Endpoints Disponíveis

| Serviço | URL | Descrição |
|---------|-----|-----------|
| API | http://localhost:3000 | API principal |
| Swagger | http://localhost:3000/api-docs | Documentação da API |
| pgAdmin | http://localhost:5050 | Gestão PostgreSQL |
| Redis Commander | http://localhost:8081 | Gestão Redis |
| MailHog | http://localhost:8025 | Interface de email |

## 📚 Documentação da API

### Autenticação

```bash
# Registar utilizador
POST /api/v1/auth/register
{
  "email": "user@example.com",
  "username": "username",
  "password": "SecurePass123!",
  "firstName": "João",
  "lastName": "Silva"
}

# Login
POST /api/v1/auth/login
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}

# Configurar 2FA
POST /api/v1/auth/2fa/setup
Authorization: Bearer <token>

# Verificar 2FA
POST /api/v1/auth/2fa/verify
{
  "token": "123456"
}
```

### Gestão de Utilizadores

```bash
# Obter perfil
GET /api/v1/users/profile
Authorization: Bearer <token>

# Atualizar perfil
PUT /api/v1/users/profile
Authorization: Bearer <token>
{
  "firstName": "João",
  "lastName": "Santos"
}
```

## 🔒 Funcionalidades de Segurança

### Rate Limiting
- **Global**: 100 requests/15min por IP
- **Login**: 5 tentativas/15min por IP
- **2FA**: 10 tentativas/15min por utilizador

### Proteções Implementadas
- ✅ OWASP Top 10 compliance
- ✅ Helmet.js security headers
- ✅ CORS configurado
- ✅ Input validation com Joi
- ✅ SQL injection prevention
- ✅ XSS protection
- ✅ Brute force protection

### Auditoria
- Todos os eventos de segurança são registados
- Logs estruturados com Winston
- Monitorização de sessões suspeitas
- Alertas automáticos por email

## 🧪 Testes

```bash
# Executar todos os testes
npm test

# Testes com coverage
npm run test:coverage

# Testes em modo watch
npm run test:watch
```

## 🔧 Desenvolvimento

### Estrutura do Projeto

```
src/
├── controllers/     # Controladores da API
├── middleware/      # Middleware personalizado
├── models/         # Modelos de dados
├── routes/         # Definição de rotas
├── services/       # Lógica de negócio
├── utils/          # Utilitários
├── config/         # Configurações
└── tests/          # Testes automatizados
```

### Scripts Disponíveis

```bash
npm run dev          # Desenvolvimento com nodemon
npm start           # Produção
npm test            # Executar testes
npm run lint        # Verificar código
npm run format      # Formatar código
npm run db:migrate  # Executar migrações
npm run db:seed     # Popular base de dados
```

## 📊 Monitorização

### Health Checks
- **API**: `GET /health`
- **Database**: Verificação de conectividade PostgreSQL
- **Cache**: Verificação de conectividade Redis

### Métricas
- Tempo de resposta da API
- Taxa de sucesso de autenticação
- Utilização de recursos
- Eventos de segurança

## 🚀 Deployment

### Desenvolvimento
```bash
docker compose up --build -d
```

### Produção
```bash
# Build da imagem de produção
docker build --target production -t ufc-auth-api:latest .

# Deploy com compose
docker compose --profile production up -d
```

### Variáveis de Ambiente Críticas

```bash
# Segurança (OBRIGATÓRIO alterar em produção)
JWT_SECRET=<strong-secret-key>
JWT_REFRESH_SECRET=<strong-refresh-key>
DB_PASSWORD=<secure-database-password>

# Base de dados
DB_HOST=postgres
DB_NAME=ufc_auth
DB_USER=postgres

# Redis
REDIS_HOST=redis
REDIS_PORT=6379
```

## 🔍 Troubleshooting

### Problemas Comuns

1. **Erro de conexão à base de dados**
   ```bash
   docker compose logs postgres
   ```

2. **API não responde**
   ```bash
   docker compose logs api
   ```

3. **Redis não conecta**
   ```bash
   docker compose logs redis
   ```

### Logs
```bash
# Ver logs de todos os serviços
docker compose logs -f

# Ver logs específicos
docker compose logs -f api
```

## 📈 Roadmap

- [ ] Implementação de OAuth2/OpenID Connect
- [ ] Integração com Active Directory
- [ ] Dashboard administrativo
- [ ] Métricas avançadas com Prometheus
- [ ] Notificações push
- [ ] API rate limiting por utilizador

## 🤝 Contribuição

1. Fork o projeto
2. Criar branch para feature (`git checkout -b feature/nova-funcionalidade`)
3. Commit das alterações (`git commit -am 'Adicionar nova funcionalidade'`)
4. Push para branch (`git push origin feature/nova-funcionalidade`)
5. Criar Pull Request

## 📄 Licença

Este projeto está licenciado sob a Licença MIT - ver o arquivo [LICENSE](LICENSE) para detalhes.

## 👥 Equipa

- **Desenvolvedor Principal**: UFC Auth Team
- **Orientador**: [Nome do Professor]
- **Instituição**: [Nome da Universidade]

## 📞 Suporte

- **Email**: support@ufcauth.com
- **Documentação**: [Link para documentação completa]
- **Issues**: [Link para GitHub Issues]

---

**Nota**: Este projeto foi desenvolvido como parte de um mestrado em Ciência da Computação com especialização em Cibersegurança. Todas as práticas de segurança implementadas seguem as melhores práticas da indústria e standards internacionais. 