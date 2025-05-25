## Faculdade de Informática e Administração Paulista - FIAP/SP

### Referência: Challenge 2025 - empresa _Mottu_

Alunos: 

- Guilherme Gonçalves - RM558475
- Thiago Mendes - RM555352 
- Vinicius Banciela - RM558117

Turma: 2TDSPW


# 📚 MotoSyncAuth API - Documentação Inicial

Esta é a API RESTful de autenticação e gerenciamento de acesso do sistema MotoSync, desenvolvida em ASP.NET Core Minimal API.

### 🚀 Visão Geral
- **Tecnologias:** ASP.NET Core 8, Entity Framework Core + Migration, Swagger, Redoc, BCrypt, JWT, Rate Limiting, Azure, Linux, Docker, Oracle SQL Developer
- **Funcionalidades:**
    - Hash de senha
    - Autenticação via JWT
    - Gerenciamento de usuários e cargos
    - Redefinição de senha com token temporário
    - Proteção por roles (Administrador, Gerente, Funcionário)

### Descrição do Projeto

Este projeto faz parte da entrega da SPRINT 1 dos módulos "Advanced Business Development with .NET" e "DevOps Tools & Cloud Computing" do curso de Tecnologia em Análise e Desenvolvimento de Sistemas da FIAP/SP, no contexto do Challenge 2025 proposto pela faculdade em parceria com a empresa MOTTU TECNOLOGIA LTDA. ("Mottu") -  que tem por objeto a locação de motos - a fim de atender a necessidade de mapeamento e gestão dos pátios da empresa.

Com uma abordagem modular decidimos dividir o back-end do sistema em duas partes: uma para focar na autenticação e gerenciamento de acesso pessoal, indispensável para um sistema interno que tem hierarquia e regras bem definidas e considerando que a organização da empresa e do sistema se dá em vários níveis; e outra para atender diretamente a dor da empresa, fazendo o gerenciamento do pátio, motos, sensores, e outras variáveis específicas, desenvolvida a partir de outro módulo, "Java Advanced".

Com isso, nós esperamos aumentar a nossa eficiência e aprofundar em cada um dos temas, de maneira modular - mas não independente. A ideia é que à partir das demais entregas ao decorrer do ano letivo possamos integrar todas as matérias de maneira inteligente.

Então, utilizando ferramentas modernas, como o framework ASP.NET Core (Minimal API) e banco de dados Oracle com Entity Framework Core (EF Core), a aplicação desenvolvida em C# foi concebida para gerenciar autenticação, autorização e CRUD de usuários e cargos, permitindo diferentes níveis de acesso, como Administrador, Gerente e Funcionário.

A API implementa autenticação segura via JWT (Json Web Token), com senhas armazenadas de forma segura utilizando hash com BCrypt. A integração com o banco de dados Oracle foi realizada com migrations, permitindo a criação e controle automático das tabelas do sistema. Além disso, a documentação completa da API foi elaborada com base no padrão OpenAPI, utilizando ferramentas como Swagger e ReDoc, proporcionando uma interface visual intuitiva para consulta das rotas, parâmetros e retornos.

Com um conjunto robusto de endpoints, o sistema cobre desde o login e recuperação de senha até a gestão completa de usuários e cargos, aplicando regras de autorização para garantir que cada nível de usuário possa acessar apenas os recursos permitidos. A implementação contempla ainda validação de dados, tratamento de erros e retornos HTTP padronizados (200 OK, 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found, entre outros).

A estrutura "Minimal" e a organização do código foram pensadas para garantir manutenibilidade, clareza e eficiência, facilitando a continuidade e expansão do projeto em etapas futuras.

A API teve seu deploy feito em uma Máquina Virtual de verdade disposta no serviço de computação na nuvem Azure, da Microsoft, foi posta em conteiner Docker e recebeu e respondeu requisições http externas a partir do ip público da máquina e as regras de segurança definidas.

Os scripts CLI Azure para criação da VM, abertura de portas (22 e 8080), outros comandos Linux, e o DockerFile, acompanham na raiz do projeto.


## 🚀 Guia de Instalação e Execução

### 📦 Pré-requisitos
- [.NET SDK 8.0](https://dotnet.microsoft.com/en-us/download) instalado na máquina
- Oracle database acesso com usuário, senha e servidor –(obs: já configurado no `appsettings.json` para testes)
- Acesso ao terminal ou shell para execução dos comandos
- (Opcional) Rider, VisualStudio ou outro editor para abrir o projeto

## 📥 Clone o repositório

```
git clone https://github.com/vinibanciela/RestAPI-MotoSyncAuth.git
```

Abre a pasta do projeto (atenção)
```
cd RestAPI-MotoSyncAuth-main\MotoSyncAuth\
```
 Restaura os pacotes Nuget
```
dotnet restore
```
Aplicar as migrations (criar as tabelas no banco)
```
dotnet ef database update
```
Rodar o projeto
```
dotnet run
```

## 📂 Estrutura de Endpoints

# 📘 Documentação Interativa
-  Disponível em `/swagger` (padrão ao rodar) ou `/redoc` caso preferir. 

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
- Criptografia de senha com BCrypt.
- Rate limiting configurado para proteger contra flood de requisições.
- Utiliza autenticação JWT com tokens válidos por 4 horas.
- Proteção de rotas por roles de acesso (Admin, Gerente, Funcionário).

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






