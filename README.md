## Faculdade de Informática e Administração Paulista - FIAP/SP

### Referência: Challenge 2025 - empresa _Mottu_

Alunos:

- Guilherme Gonçalves - RM558475
- Thiago Mendes - RM555352
- Vinicius Banciela - RM558117

Turma: 2TDSPW

# 📚 MotoSyncAuth API - Documentação Oficial

Esta é a API RESTful de autenticação e gerenciamento de acesso do sistema MotoSync, desenvolvida em ASP.NET Core Minimal API.

### 🚀 Visão Geral

- **Tecnologias:** ASP.NET Core 8, Entity Framework Core + Migration, JWT, BCrypt, Rate Limiting, Docker, Docker Compose, PostGreSQL, AzureDatabaseSQL, Azure Container Registry, Azure Web App for Containers, Swagger, Redoc
- **Funcionalidades:**
  - Hash de senha
  - Autenticação via JWT
  - Gerenciamento de usuários e cargos
  - Redefinição de senha com token temporário
  - Proteção por roles (Administrador, Gerente, Funcionário)
  - Paginação em rotas de listagem
  - HATEOAS para descoberta de ações
  - Migrations automáticas para múltiplos provedores de banco de dados (PostgreSQL e SQL Server)
  - Sistema de Log de Auditoria
  - Documentação OpenAPI com Swagger e ReDoc
  - Rate Limiting para proteção contra brute-force

### Introdução

Este projeto faz parte da entrega da SPRINT 2 do curso de Tecnologia em Análise e Desenvolvimento de Sistemas da FIAP/SP, no contexto do Challenge 2025 proposto pela faculdade em parceria com a empresa MOTTU TECNOLOGIA LTDA. ("Mottu") - que tem por objeto a locação de motos - a fim de atender a necessidade de mapeamento e gestão dos pátios da empresa.

Com uma abordagem modular decidimos dividir o back-end do sistema em duas partes: uma para focar na autenticação e gerenciamento de acesso pessoal, indispensável para um sistema interno que tem hierarquia e regras bem definidas, e considerando que a organização da empresa e do sistema se dá em vários níveis (ao cuidado do módulo "advanced Business Development with .NET") - a nossa API aqui; e outra para atender diretamente a dor da empresa, fazendo o gerenciamento do pátio e motos (e outras variáveis específicas), a partir do módulo "Java Advanced". Enquanto a construção dos sensores de presença se dá através do módulo "Disruptive Architetures - IOT, IOB and Generative I.A.", e o front-end para o cliente constrúido com auxílio do "Mobile Application Development".

Claro, não podemos esquecer que nossa AuthAPI pode ser disposta (deploy) na nuvem sob os ensinamentos de "Devops Tools and Cloud Computing".

Com isso, nós esperamos aumentar a nossa eficiência e aprofundar em cada um dos temas, de maneira modular - mas não independente. A ideia é que à partir das demais entregas até o final do ano letivo possamos integrar todas as matérias de maneira inteligente.

### Descrição do Projeto

Então, utilizando ferramentas modernas, como o framework ASP.NET Core (Minimal API), com Entity Framework Core (EF Core), a aplicação desenvolvida em C# foi concebida para gerenciar autenticação, autorização e CRUD de usuários e cargos, permitindo diferentes níveis de acesso, como Administrador, Gerente e Funcionário. Além disso, tem uma entidade específica criada para monitorar logs do sitema (como: dados de login, dados de criação ou exclusão de usuários), viabilizando a auditoria do sistema pelo Administrador.

A integração com os banco de dados foi realizada com migrations, permitindo a criação e controle automático das tabelas do sistema. Importante ressaltar, além do mais, que foi utilizado nas migrations SeedData´s para incluir um 'Administrador' inicial no banco (para que pudesse logar no sistema e de fato usar, a priori), e as 3 RoleIds principais (para caracterizar o Admim, que já viria caracterizado com sua roleId 1 - e os dois outros cargos principais RoleId 2 'Gerente', e RoleId 3 'Funcionário' - para facilitar as inserções de novos usuários).

Forçoso reconhecer, ainda, que existem arquivos de migrations para cada tipo de banco, que são lidos conforme o ambiente em que a aplicação está rodando: se está rodando no ambiente Development é feita a leitura dos arquivos do banco PostGreeSQL (em container, configurado no nosso Docker Compose); por sua vez se está rodando no ambiente Production, é feita a leitura dos arquivos do banco AzureSQL (PAAS). Isso não afeta em nada a compilação ou execução do código, por conta do DbContext configurado, que faz a leitura automática do ambiente e já redireciona esta e outras características de acordo com o ambiente de execuação.

Portanto, conforme explicado, a API pode ser rodada em dois ambientes, que vai ter comportamentos distintos em cada um, se preferir testar localmente basta subir os containers locais (api e banco de dados PostGreSQL) seguindo o Guia de Execução [Ambiente Local - Development] no Docker. Caso prefira rodar na nuvem, basta seguir o próximo Guia de Execução [Ambiente Production - Nuvem]: neste caso se utilizará dos serviços da Azure, da Microsoft, mais especificamente AzureContainerRegistry para armazenar a imagem docker da API, Azure App Service (Web App for Containers) para o deploy da imagem docker da API, e Azure Database SQL (Server + Database) para ser o banco gerenciado da API na nuvem.

A API implementa autenticação segura via JWT (Json Web Token), com senhas armazenadas de forma segura utilizando hash com BCrypt. Possibilita a redefinição de senha com token temporário, inlusive tendo este retorno referenciado (link) caso o usuário falhe no login (401). Além de possuir Rate Limiting para evitar flood de requisições.

Possui recurso de paginação para as listagens de usuários, cargos e logs de auditoria. Adicionalmente, utiliza HATEOAS (Hypermedia as the Engine of Application State) para tornar a API autodescritiva e navegável. Nas rotas de consulta por ID, a resposta inclui links dinâmicos para ações subsequentes, como atualizar ou deletar o recurso/ID, que são exibidos de acordo com as permissões do usuário autenticado. As respostas de listagem paginada também contêm links para navegação, como self, next-page e prev-page, facilitando a iteração sobre grandes conjuntos de dados.

Com um conjunto robusto de endpoints, o sistema cobre desde o login e recuperação de senha até a gestão completa de usuários e cargos, aplicando regras de autorização para garantir que cada nível de usuário possa acessar apenas os recursos permitidos. A implementação contempla ainda validação de dados, tratamento de erros e retornos HTTP padronizados (200 OK, 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found, entre outros).

A documentação completa da API foi elaborada com base no padrão OpenAPI, utilizando ferramentas como Swagger e ReDoc, proporcionando uma interface visual intuitiva para consulta das rotas, parâmetros e retornos. Para reforçar adicionamos comentários nas Models e DTOs exibivéis em OpenAPI (Swagger ou Redoc) com XML Documentation Comments.

A preferência pela estrutura "minimal" se deu pela modularidade que foi pensado o sistema, cuidando apenas de uma parte (autenticação e gerenciamento de acesso) a nossa API, sem interferir assim nas demais. Além disso, mas no mesmo sentido, a organização do código foi desenhada para garantir manutenibilidade, clareza e eficiência, facilitando a continuidade e expansão do projeto em etapas futuras.

## 🚀 Guia de Execução [Ambiente Development - Local]

### 📦 Pré-requisitos

- [Git](https://git-scm.com/) instalado na máquina.
- [.NET SDK 8.0](https://dotnet.microsoft.com/en-us/download) instalado na máquina.
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) instalado e em execução.
- (Opcional) Rider, VisualStudio ou outro editor para abrir o projeto.

1.  **Clone o repositório:**

    ```shell
    git clone [https://github.com/vinibanciela/RestAPI-MotoSyncAuth.git](https://github.com/vinibanciela/RestAPI-MotoSyncAuth.git)
    ```

2.  **Navegue até a pasta raiz do projeto:**

    ```shell
    cd RestAPI-MotoSyncAuth
    ```

3.  **Construa e inicie os contêineres:**
    Este único comando irá construir a imagem da API a partir do `Dockerfile`, baixar a imagem do PostgreSQL e iniciar ambos os serviços.

    ```shell
    docker compose up -d --build
    ```

4.  **Aguarde a inicialização:**
    Aguarde cerca de um minuto. Na primeira inicialização, a API aplicará as migrações do banco de dados automaticamente.

5.  **Acesse e teste em:**
    ```shell
    http://localhost:8080/swagger/index.html
    ```

## 🚀 Guia de Deploy (Ambiente na Nuvem - Production)

Este guia descreve o passo a passo para fazer o deploy completo da aplicação (Banco de Dados + API) no Azure utilizando o Azure CLI e Docker. Os comandos devem ser executados em sequência a partir do seu terminal local.

### 📦 Pré-requisitos

- [Git](https://git-scm.com/) instalado.
- [Azure CLI](https://docs.microsoft.com/pt-br/cli/azure/install-azure-cli) instalado e configurado.
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) instalado e em execução.

---

### Passo a Passo do Deploy

#### Fase 1: Preparação Inicial

1.  **Clone o repositório:**

    ```shell
    git clone [https://github.com/vinibanciela/RestAPI-MotoSyncAuth.git](https://github.com/vinibanciela/RestAPI-MotoSyncAuth.git)
    ```

2.  **Navegue até a pasta raiz do projeto:**

    ```shell
    cd RestAPI-MotoSyncAuth
    ```

3.  **Faça o login no Azure CLI:**
    ```shell
    az login
    ```

#### Fase 2: Azure Container Registry (ACR) e Imagem Docker

Primeiro, criamos o registro para nossa imagem e fazemos o upload.

1.  **Crie o Grupo de Recursos para o ACR:**

    ```shell
    az group create --name rg-motosync-acr --location brazilsouth
    ```

2.  **Crie o Azure Container Registry (ACR):**

    ```shell
    az acr create --resource-group rg-motosync-acr --name acrmotosync --sku Standard --admin-enabled true --public-network-enabled true
    ```

3.  **Faça o login do Docker no seu ACR:**

    ```shell
    az acr login --name acrmotosync
    ```

4.  **Construa, Etiquete (Tag) e Envie (Push) a imagem Docker:**

    ```shell
    # Constrói a imagem localmente
    docker build -t motosync-image -f ./MotoSyncAuth/Dockerfile ./MotoSyncAuth

    # Etiqueta a imagem com o endereço do ACR e o nome do repositório
    docker tag motosync-image acrmotosync.azurecr.io/repo-acr-motosync:v1

    # Envia a imagem para o ACR
    docker push acrmotosync.azurecr.io/repo-acr-motosync:v1
    ```

#### Fase 3: Azure SQL Database (PaaS)

Agora, criamos o banco de dados que a aplicação irá usar.

1.  **Crie o Grupo de Recursos para o Banco de Dados:**

    ```shell
    az group create --name rg-motosync-database --location brazilsouth
    ```

2.  **Crie o Servidor e o Banco de Dados SQL:**

    ```shell
    # Criar o Servidor SQL (substitua a senha)
    az sql server create -l brazilsouth -g rg-motosync-database -n sqlserver-motosync -u admsql -p <sua_senha_forte_aqui> --enable-public-network true

    # Criar o Banco de Dados
    az sql db create -g rg-motosync-database -s sqlserver-motosync -n motosyncdb-dev --service-objective Basic

    # Criar a Regra de Firewall (ATENÇÃO: Abre para todos os IPs)
    az sql server firewall-rule create -g rg-motosync-database -s sqlserver-motosync -n AllowAll --start-ip-address 0.0.0.0 --end-ip-address 255.255.255.255
    ```

    > ⚠️ **Alerta de Segurança:** O comando acima abre seu banco de dados para toda a internet. Para um ambiente de produção real, restrinja os IPs de acesso.

#### Fase 4: App Service (WebApp for Containers)

Finalmente, criamos o serviço que irá executar nossa API.

1.  **Crie o Grupo de Recursos para o Deploy:**
    ```shell
    az group create --name rg-motosync-deploy --location brazilsouth
    ```
2.  **Crie o Plano do App Service:**

    ```shell
    az appservice plan create --name plan-motosync --resource-group rg-motosync-deploy --location brazilsouth --is-linux --sku B1
    ```

3.  **Crie o Web App para Contêineres (com a configuração injetada):**
    ```powershell
    # Comando para criar o Web App, apontando para a imagem no ACR e injetando a string de conexão
    # O acento grave ` no final de cada linha é para quebra de linha no PowerShell
    az webapp create `
        --resource-group rg-motosync-deploy `
        --plan plan-motosync `
        --name webapp-motosync `
        --image acrmotosync.azurecr.io/repo-acr-motosync:v1 `
        --settings "ConnectionStrings__AzureSqlConnection=SUA_STRING_DE_CONEXAO_AQUI"
    ```
    > ✏️ **Nota:** Substitua `SUA_STRING_DE_CONEXAO_AQUI` pela string de conexão completa do seu Azure SQL. Você pode obtê-la com o comando `az sql db show-connection-string -s sqlserver-motosync -n motosyncdb-dev -c ado.net`.

#### Passo 5: Verificação

1.  **Aguarde alguns minutos** para o deploy e a execução das migrações automáticas.
2.  Acesse sua API pela URL do Swagger:
    `https://<seu_nome_de_app_unico>.azurewebsites.net/swagger`
3.  [Obs] Acesse sua API pela URL do Swagger: Se você usou os mesmos nomes do script, o link exato será:
    ```
    [https://webapp-motosync.azurewebsites.net/swagger/index.html](https://webapp-motosync.azurewebsites.net/swagger/index.html)
    ```
    > 💡 **Dica:** O nome do Web App (`webapp-motosync`) deve ser único globalmente. Se você precisou usar um nome diferente, ajuste a URL de acordo.

## 📂 Estrutura de Endpoints

# 📘 Documentação Interativa

- Disponível em `/swagger` (padrão ao rodar) ou `/redoc` caso preferir.
- Local com guia de Execução - Development: http://localhost:8080/swagger/index.html
- Nuvem com guia de Execução - Production: https://webapp-motosync.azurewebsites.net/swagger/index.html (ou a que você configurou/construiu)

### 🔐 Auth

| Método | Rota                  | Descrição                            | Respostas HTTP                          | Tipo de Acesso |
| ------ | --------------------- | ------------------------------------ | --------------------------------------- | -------------- |
| POST   | /auth/login           | Autentica e gera JWT                 | 200 OK (AuthResponse), 401 Unauthorized | Pública        |
| GET    | /auth/me              | Retorna dados do usuário autenticado | 200 OK (User), 401 Unauthorized         | Privada        |
| POST   | /auth/forgot-password | Gera token para redefinição de senha | 200 OK (string), 404 Not Found          | Pública        |
| POST   | /auth/reset-password  | Redefine senha com token             | 200 OK (string), 400 Bad Request        | Pública        |

### 👥 Users

| Método | Rota            | Descrição                | Respostas HTTP                                                                   | Tipo de Acesso |
| ------ | --------------- | ------------------------ | -------------------------------------------------------------------------------- | -------------- |
| GET    | /users          | Lista todos os usuários  | 200 OK (IEnumerable<UserResponse>), 401 Unauthorized, 403 Forbidden              | Privada        |
| GET    | /users/{id}     | Busca usuário por ID     | 200 OK (UserResponse), 401 Unauthorized, 403 Forbidden, 404 Not Found            | Privada        |
| GET    | /users/by-email | Busca usuário por e-mail | 200 OK (UserResponse), 401 Unauthorized, 403 Forbidden, 404 Not Found            | Privada        |
| POST   | /users          | Cria um novo usuário     | 201 Created (UserResponse), 401 Unauthorized, 403 Forbidden, 400 Bad Request     | Privada        |
| PUT    | /users/{id}     | Atualiza um usuário      | 200 OK (string), 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found | Privada        |
| DELETE | /users/{id}     | Deleta um usuário        | 200 OK (string), 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found | Privada        |

### 🏷️ Roles

| Método | Rota        | Descrição             | Respostas HTTP                                                        | Tipo de Acesso |
| ------ | ----------- | --------------------- | --------------------------------------------------------------------- | -------------- |
| GET    | /roles      | Lista todos os cargos | 200 OK (IEnumerable<RoleResponse>), 401 Unauthorized, 403 Forbidden   | Privada        |
| GET    | /roles/{id} | Busca cargo por ID    | 200 OK (RoleResponse), 401 Unauthorized, 403 Forbidden, 404 Not Found | Privada        |
| POST   | /roles      | Cria um novo cargo    | 201 Created (RoleResponse), 401 Unauthorized, 403 Forbidden           | Privada        |
| PUT    | /roles/{id} | Atualiza um cargo     | 200 OK (string), 401 Unauthorized, 403 Forbidden, 404 Not Found       | Privada        |
| DELETE | /roles/{id} | Exclui um cargo       | 200 OK (string), 401 Unauthorized, 403 Forbidden, 404 Not Found       | Privada        |

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

| Ação / Recurso                                    | Administrador | Gerente¹ | Funcionário Administrativo |
| ------------------------------------------------- | :-----------: | :------: | :------------------------: |
| **🔑 Auth**                                       |               |          |                            |
| Login (`/auth/login`)                             |      ✅       |    ✅    |             ✅             |
| Ver perfil logado (`/auth/me`)                    |      ✅       |    ✅    |             ✅             |
| Resetar senha (`/auth/forgot-password`)           |      ✅       |    ✅    |             ✅             |
| Redefinir senha (`/auth/reset-password`)          |      ✅       |    ✅    |             ✅             |
| **👥 Users**                                      |               |          |                            |
| Criar usuários (`POST /users`)                    |      ✅       |   ✅¹    |             ❌             |
| Listar usuários (`GET /users`)                    |      ✅       |   ✅²    |             ❌             |
| Buscar usuário por ID (`GET /users/{id}`)         |      ✅       |   ✅²    |             ❌             |
| Buscar usuário por e-mail (`GET /users/by-email`) |      ✅       |   ✅²    |             ❌             |
| Atualizar usuários (`PUT /users/{id}`)            |      ✅       |   ✅¹    |             ❌             |
| Excluir usuários (`DELETE /users/{id}`)           |      ✅       |   ✅¹    |             ❌             |
| **🏷️ Roles**                                      |               |          |                            |
| Visualizar cargos (`GET /roles`)                  |      ✅       |    ❌    |             ❌             |
| Criar novo cargo (`POST /roles`)                  |      ✅       |    ❌    |             ❌             |
| Atualizar cargo (`PUT /roles/{id}`)               |      ✅       |    ❌    |             ❌             |
| Excluir cargo (`DELETE /roles/{id}`)              |      ✅       |    ❌    |             ❌             |

#### Observações:

- ¹ Gerente pode criar, atualizar e excluir **apenas usuários Funcionários**.
- ² Gerente pode visualizar **usuários do mesmo nível ou inferior (Gerente e Funcionário)**.
