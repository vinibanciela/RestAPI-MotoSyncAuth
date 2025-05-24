# 📚 MotoSyncAuth API - Documentação Inicial

Esta é a API de autenticação e gerenciamento de acesso do sistema MotoSyncAuth, desenvolvida em ASP.NET Core Minimal API.

## 🚀 Visão Geral
- **Tecnologias:** ASP.NET Core 8, Swagger, JWT, Rate Limiting
- **Funcionalidades:**
    - Autenticação via JWT
    - Gerenciamento de usuários e cargos
    - Redefinição de senha com token temporário
    - Proteção por roles (Administrador, Gerente, Funcionário)

## 📂 Estrutura de Endpoints
## 📂 Estrutura de Endpoints

### 🔐 Auth
| Método | Rota                  | Descrição                            | Respostas HTTP                                   | Tipo de Acesso |
| ------ | --------------------- | ------------------------------------ | ------------------------------------------------ | -------------- |
| POST   | /auth/login           | Autentica e gera JWT                 | 200 OK (AuthResponse), 401 Unauthorized          | Pública        |
| GET    | /auth/me              | Retorna dados do usuário autenticado | 200 OK (User), 401 Unauthorized                  | Privada        |
| POST   | /auth/forgot-password | Gera token para redefinição de senha | 200 OK (string), 404 Not Found                   | Pública        |
| POST   | /auth/reset-password  | Redefine senha com token             | 200 OK (string), 400 Bad Request                 | Pública        |

### 👥 Users
| Método | Rota            | Descrição                | Respostas HTTP                                                         | Tipo de Acesso |
| ------ | --------------- | ------------------------ | ---------------------------------------------------------------------- | -------------- |
| GET    | /users          | Lista todos os usuários  | 200 OK (IEnumerable<UserResponse>), 401 Unauthorized, 403 Forbidden    | Privada        |
| GET    | /users/{id}     | Busca usuário por ID     | 200 OK (UserResponse), 401 Unauthorized, 403 Forbidden, 404 Not Found  | Privada        |
| GET    | /users/by-email | Busca usuário por e-mail | 200 OK (UserResponse), 401 Unauthorized, 403 Forbidden, 404 Not Found  | Privada        |
| POST   | /users          | Cria um novo usuário     | 201 Created (UserResponse), 401 Unauthorized, 403 Forbidden, 400 Bad Request | Privada        |
| PUT    | /users/{id}     | Atualiza um usuário      | 200 OK (string), 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found | Privada |
| DELETE | /users/{id}     | Deleta um usuário        | 200 OK (string), 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found | Privada |

### 🏷️ Roles
| Método | Rota        | Descrição             | Respostas HTTP                                                         | Tipo de Acesso |
| ------ | ----------- | --------------------- | ---------------------------------------------------------------------- | -------------- |
| GET    | /roles      | Lista todos os cargos | 200 OK (IEnumerable<RoleResponse>), 401 Unauthorized, 403 Forbidden    | Privada        |
| GET    | /roles/{id} | Busca cargo por ID    | 200 OK (RoleResponse), 401 Unauthorized, 403 Forbidden, 404 Not Found  | Privada        |
| POST   | /roles      | Cria um novo cargo    | 201 Created (RoleResponse), 401 Unauthorized, 403 Forbidden            | Privada        |
| PUT    | /roles/{id} | Atualiza um cargo     | 200 OK (string), 401 Unauthorized, 403 Forbidden, 404 Not Found        | Privada        |
| DELETE | /roles/{id} | Exclui um cargo       | 200 OK (string), 401 Unauthorized, 403 Forbidden, 404 Not Found        | Privada        |

### 📝 Observações
- 🔒 **401 Unauthorized**: Quando a requisição não tem um token válido ou ausente.
- 🔒 **403 Forbidden**: Quando o token é válido, mas o usuário não tem permissão para aquela ação.
- 🚀 **201 Created**: Indica criação bem-sucedida (usado em POST de criação de usuários e cargos).
- 🗂️ **404 Not Found**: Recurso não encontrado (ex: ID inválido, e-mail não cadastrado).
- ❌ **400 Bad Request**: Erro de validação ou solicitação malformada.



## 🔒 Segurança
- Utiliza autenticação JWT com tokens válidos por 4 horas.
- Proteção de rotas por roles de acesso (Admin, Gerente, Funcionário).
- Rate limiting configurado para proteger contra flood de requisições.

### 🔐 Regras de Acesso por Cargo

| Ação / Recurso                                     | Administrador | Gerente¹ | Funcionário Administrativo |
| ------------------------------------------------- |:-------------:|:-------:|:--------------------------:|
| **🔑 Auth**                                       |               |         |                            |
| Login (`/auth/login`)                             | ✅            | ✅      | ✅                         |
| Ver perfil logado (`/auth/me`)                    | ✅            | ✅      | ✅                         |
| Resetar senha (`/auth/forgot-password`)           | ✅            | ✅      | ✅                         |
| Redefinir senha (`/auth/reset-password`)          | ✅            | ✅      | ✅                         |
| **👥 Users**                                      |               |         |                            |
| Criar usuários (`POST /users`)                    | ✅            | ✅¹     | ❌                         |
| Listar usuários (`GET /users`)                    | ✅            | ✅²     | ❌                         |
| Buscar usuário por ID (`GET /users/{id}`)         | ✅            | ✅²     | ❌                         |
| Buscar usuário por e-mail (`GET /users/by-email`) | ✅            | ✅²     | ❌                         |
| Atualizar usuários (`PUT /users/{id}`)            | ✅            | ✅¹     | ❌                         |
| Excluir usuários (`DELETE /users/{id}`)           | ✅            | ✅¹     | ❌                         |
| **🏷️ Roles**                                      |               |         |                            |
| Visualizar cargos (`GET /roles`)                  | ✅            | ❌      | ❌                         |
| Criar novo cargo (`POST /roles`)                  | ✅            | ❌      | ❌                         |
| Atualizar cargo (`PUT /roles/{id}`)               | ✅            | ❌      | ❌                         |
| Excluir cargo (`DELETE /roles/{id}`)              | ✅            | ❌      | ❌                         |

#### Observações:
- ¹ Gerente pode criar, atualizar e excluir **apenas usuários Funcionários**.
- ² Gerente pode visualizar **usuários do mesmo nível ou inferior (Gerente e Funcionário)**.


## 📘 Documentação Interativa
- Swagger disponível em `/swagger`
- Futuramente será integrado com **Redoc** para uma visualização mais amigável.


---

