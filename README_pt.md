[English](README.md) | [简体中文](README_cn.md) | [Español](README_es.md) | [हिन्दी](README_hi.md) | [العربية](README_ar.md) | [Français](README_fr.md) | [Português](README_pt.md) | [Русский](README_ru.md) | [বাংলা](README_bn.md) | [اردو](README_ur.md) | [日本語](README_ja.md) | [Deutsch](README_de.md) | [Bahasa Indonesia](README_id.md) | [한국어](README_ko.md)


<div align="center">
 <img alt="SamWaf" width="100" src="./docs/images/logo.png"> 

Um firewall de aplicação web leve e de código aberto

[![Release](https://img.shields.io/github/release/samwafgo/SamWaf.svg)](https://github.com/samwafgo/SamWaf/releases)
[![Last commit](https://img.shields.io/github/last-commit/samwafgo/SamWaf?style=flat-square&color=blue&logo=github)](https://github.com/samwafgo/SamWaf/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/samwaf/samwaf?style=flat-square&color=blue&label=Docker+Image+Pulls)](https://hub.docker.com/r/samwaf/samwaf)
[![Release Downloads](https://img.shields.io/github/downloads/samwafgo/samwaf/total?style=flat-square&color=blue&label=Release+Downloads)](https://github.com/samwafgo/SamWaf/releases)
[![Gitee](https://img.shields.io/badge/Gitee-blue?style=flat-square&logo=Gitee)](https://gitee.com/samwaf/SamWaf)
[![GitHub stars](https://img.shields.io/github/stars/samwafgo/SamWaf?style=flat-square&logo=Github)](https://github.com/samwafgo/SamWaf)
[![Gitee star](https://gitee.com/samwaf/SamWaf/badge/star.svg?theme=gray)](https://gitee.com/samwaf/SamWaf)
[![Atomgit star](https://atomgit.com/SamSafe/SamWaf/star/badge.svg)](https://atomgit.com/SamSafe/SamWaf)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)](LICENSE)
</div>

  
## Motivação do Desenvolvimento:
- **Leveza**: No início, eu usava alguns produtos de segurança baseados em plugins para nginx, apache e iis como proteção, mas o formato de plugin tinha um alto grau de acoplamento.
- **Privatização**: Mais tarde, passaram a ser adotados principalmente serviços de proteção em nuvem, mas a implantação privada é acessível apenas para médias e grandes empresas, enquanto pequenas empresas e estúdios a consideram cara.
- **Privacidade e Criptografia**: Durante a proteção web, é preferível processar os dados localmente, sem enviá-los para a nuvem. O objetivo era criar uma ferramenta que criptografasse as informações locais e as comunicações de rede do painel de gerenciamento.
- **DIY**: Ao longo dos anos de manutenção e desenvolvimento de sites, havia funções específicas que eu queria adicionar, mas não conseguia implementar.
- **Visibilidade**: Se o administrador do site nunca usou um WAF semelhante, é inconveniente entender quem está acessando o site e quais requisições estão sendo feitas apenas a partir de logs ou do nginx, apache, IIS etc.

Em resumo, o objetivo era criar uma ferramenta eficaz de proteção para sites ou APIs, capaz de lidar com situações anormais e garantir o funcionamento normal de sites e aplicações.

# Apresentação do Software
O SamWaf é um firewall de aplicação web leve e de código aberto para pequenas empresas, estúdios e sites pessoais. Ele suporta implantação totalmente privada, criptografa os dados armazenados localmente, é fácil de iniciar e suporta Linux, Windows 64 bits e ARM64, com imagens Docker disponíveis. Por padrão, utiliza um banco de dados SQLite embutido e criptografado, sem nenhuma dependência externa, podendo opcionalmente ser trocado por MySQL.

## Arquitetura

![Arquitetura do SamWaf](./docs/images_en/tecDesign.svg)

## Interface
![Visão Geral do Firewall de Aplicação Web SamWaf](/docs/images_en/overview.png)

<table>
    <tr>
        <td align="center">Adicionar Host</td>
        <td align="center">Log de Ataques</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/add_host.png" alt="Adicionar Host"/></td>
        <td><img src="./docs/images_en/attacklog.png" alt="Log de Ataques"/></td>
    </tr>
    <tr>
        <td align="center">CC</td>
        <td align="center">Lista de Bloqueio de IP</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/cc.png" alt="CC"/></td>
        <td><img src="./docs/images_en/ipblock.png" alt="Lista de Bloqueio de IP"/></td>
    </tr>
    <tr>
        <td align="center">Lista de Permissão de IP</td>
        <td align="center">LDP</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/ipallow.png" alt="Lista de Permissão de IP"/></td>
        <td><img src="./docs/images_en/ldp.png" alt="LDP"/></td>
    </tr>
    <tr>
        <td align="center">Adicionar Script de Regra a partir do Log</td>
        <td align="center">Selecionar Log</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/log_add_rule_script.png" alt="Adicionar Script de Regra a partir do Log"/></td>
        <td><img src="./docs/images_en/log_select.png" alt="Selecionar Log"/></td>
    </tr>
    <tr>
        <td align="center">Detalhes do Log</td>
        <td align="center">Regra Manual</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/logdetail.png" alt="Detalhes do Log"/></td>
        <td><img src="./docs/images_en/manual_rule.png" alt="Regra Manual"/></td>
    </tr>
    <tr>
        <td align="center">Lista de Bloqueio de URL</td>
        <td align="center">Lista de Permissão de URL</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/urlblock.png" alt="Lista de Bloqueio de URL"/></td>
        <td><img src="./docs/images_en/urlallow.png" alt="Lista de Permissão de URL"/></td>
    </tr>
</table>

## Principais Funcionalidades

### Básico
- Código totalmente aberto (Apache 2.0)
- Implantação totalmente privada; os dados são criptografados e armazenados somente localmente
- Inicialização com um clique em arquivo único, leve e sem dependência de serviços de terceiros (MySQL/Redis são opcionais)
- Motor totalmente independente; a proteção não depende de IIS nem de Nginx
- Suporte a IPv6

### Entrada de Tráfego
- Suporte a HTTP/1.1, HTTP/2 e HTTP/3 (QUIC)
- Encaminhamento de WebSocket
- Proxy reverso com balanceamento de carga (round-robin ponderado, hash de IP, menor número de conexões); verificações de integridade removem automaticamente os backends com problemas
- Regras de caminho: proxy reverso por caminho, arquivos estáticos ou redirecionamento 301/302, com protocolo de backend e tempo limite de resposta configuráveis
- Hospedagem de sites estáticos
- Encaminhamento de túnel TCP/UDP na camada 4 (com controle de acesso por IP e controle por janela de tempo)
- Cache de páginas web
- HTTP Basic Auth para acesso ao site
- Página de bloqueio personalizável

### Proteção contra Ataques
- Detecção de injeção de SQL
- Detecção de XSS (cross-site scripting)
- Detecção de RCE (execução remota de comandos)
- Detecção de ferramentas de varredura (scanners)
- Detecção de path traversal
- Detecção de upload de arquivos (extensões perigosas, assinaturas de webshell, Content-Type falsificado)
- Proteção contra CC / limitação de taxa (rate limit)
- Detecção de crawlers/bots falsos (verificação por DNS reverso dos bots de mecanismos de busca)
- Proteção contra hotlink (anti-leech)
- Proteção contra CSRF (validação de Origin/Referer por site)
- Filtragem de palavras sensíveis
- Suporte ao conjunto de regras OWASP CRS (motor Coraza; as regras podem ser habilitadas/desabilitadas/sobrescritas)
- Regras de proteção personalizáveis, com edição por script e por interface gráfica
- Verificação humana: CAPTCHA de clique e prova de trabalho (proof-of-work) com Cap.js
- Modo somente registro: registra os ataques sem bloqueá-los, útil para observar e ajustar as regras

### Controle de Acesso
- Lista de permissão / lista de bloqueio de IP
- Lista de permissão / lista de bloqueio de URL
- Bloqueio geográfico (bancos de dados offline ip2region/GeoIP2 integrados, IPv4/IPv6)
- Banimento de IP vinculado ao firewall do sistema operacional
- Banimento automático quando o número de falhas de um IP atinge um limite
- Configuração global com um clique e estratégias de proteção por site

### Segurança de Dados
- Armazenamento de logs criptografado
- Logs de comunicação criptografados
- Mascaramento de dados (DLP) com saída designada para dados privados
- Antiadulteração de páginas web (aprendizado de linha de base + recuperação automática)
- Reforço de segurança de cookies (HttpOnly/Secure/SameSite)

### Certificados SSL
- Solicitação e renovação automáticas de certificado SSL (ACME, múltiplas CAs com suporte a EAB)
- Múltiplos certificados via SNI e HTTPS em múltiplas portas
- Verificação em lote da expiração de certificados SSL
- Carregamento automático de certificados

### Operações e Gerenciamento
- RBAC de contas, autenticação de dois fatores com OTP, logs de login/operações
- Relatórios estatísticos e monitoramento de sistema/hosts
- Política de retenção de dados com fragmentação (sharding) e arquivamento automáticos de logs
- SQLite (criptografado) por padrão, MySQL opcional, com ferramenta integrada de migração SQLite→MySQL
- Atualização online com um clique, reinício gradual sem tempo de inatividade e reversão de versão
- Tarefas em lote, tarefas agendadas e backup de dados
- API aberta

### Notificações
- Canais de entrega por e-mail, DingTalk, Feishu, WeCom (WeChat Work), ServerChan, Webhook, Kafka, RabbitMQ e arquivo de log

# Instruções de Uso
**Recomenda-se fortemente realizar testes completos em um ambiente de teste antes de implantar em produção. Se ocorrer algum problema, envie seu feedback prontamente.**
## Baixar a Versão Mais Recente
Gitee:  [https://gitee.com/samwaf/SamWaf/releases](https://gitee.com/samwaf/SamWaf/releases)

GitHub: [https://github.com/samwafgo/SamWaf/releases](https://github.com/samwafgo/SamWaf/releases)

AtomGit: [https://atomgit.com/SamSafe/SamWaf/releases](https://atomgit.com/SamSafe/SamWaf/releases)

## Início Rápido

### Windows
- Iniciar diretamente
```
SamWaf64.exe
```
- Executar como serviço (requer privilégios de Administrador)
```
//Install & Start
SamWaf64.exe install && SamWaf64.exe start

//Stop &  Uninstall 
SamWaf64.exe stop && SamWaf64.exe uninstall
``` 

### Linux
- instalar
```
curl -sSO https://update.samwaf.com/latest/install_samwaf.sh && bash install_samwaf.sh install 
``` 

- desinstalar
```
curl -sSO https://update.samwaf.com/latest/install_samwaf.sh && bash install_samwaf.sh uninstall 
```

### Docker
```
docker run -d --name=samwaf-instance \
           --restart always \
           -p 26666:26666 \
           -p 80:80 \
           -p 443:443 \
           -v /path/to/your/conf:/app/conf \
           -v /path/to/your/data:/app/data \
           -v /path/to/your/logs:/app/logs \
           -v /path/to/your/ssl:/app/ssl \
           samwaf/samwaf


```
Mais detalhes sobre o Docker: https://hub.docker.com/r/samwaf/samwaf

Tags:
- **latest**: A versão estável mais recente (recomendada para uso em produção).
- **beta**: A versão de teste mais recente (permite testar novas funcionalidades ou correções específicas de bugs).

### Ferramentas de Linha de Comando

| Command | Descrição |
|---------|-------------|
| `install` / `uninstall` | Instala / desinstala o serviço do sistema |
| `start` / `stop` / `restart` | Inicia / para / reinicia o serviço |
| `rolling-restart` | Reinício gradual sem tempo de inatividade (troca o worker sem interromper o tráfego) |
| `resetpwd` | Redefine a senha do administrador |
| `resetotp` | Redefine o código de segurança (OTP) |
| `repairdb` | Repara um banco de dados corrompido |
| `execsql` | Executa instruções SQL em um banco de dados selecionado |
| `migratedb` | Migração offline de banco de dados SQLite → MySQL (`--dry-run` para apenas estimar, `--force` para sobrescrever) |
| `rollback` | Reverte para uma versão de backup anterior |

Exemplo: `SamWaf64.exe resetpwd` (no Linux: `./SamWafLinux64 resetpwd`)

## Acesso Inicial

http://127.0.0.1:26666

Conta padrão: admin  Senha padrão: admin868 (Altere a senha padrão no primeiro login)


## Guia de Atualização

**Observação: o processo de atualização encerrará o serviço; realize a atualização fora dos horários de pico.**

### Atualização Automática
Se uma nova versão estiver disponível, um aviso de atualização será exibido para confirmação, permitindo que você inicie a atualização. A página será recarregada automaticamente após a conclusão da atualização.

### Atualização Manual
- Para inicialização direta:
    1. Feche a aplicação.
    2. Baixe o programa mais recente, substitua os arquivos existentes e, em seguida, inicie-o manualmente de novo.

- Para o modo de serviço:
```
1. First, pause the service.

  Windows: SamWaf64.exe stop
  Linux: ./SamWafLinux64 stop
  
2. Replace with the latest application files.

3. Start the service:
Windows: SamWaf64.exe start
Linux: ./SamWafLinux64 start
```

**Observação**: a atualização do serviço no Windows pode acionar regras de segurança do 360 ou do Huorong, impedindo que os novos arquivos sejam substituídos normalmente. Nesse caso, você pode substituir os arquivos manualmente. Quem tem familiaridade com essa área pode ajudar a determinar o método correto de tratamento.

## Documentação Online

[Documentação Online](https://doc.samwaf.com/)

# Informações sobre o Código
## Repositório de Código
- Gitee
[https://gitee.com/samwaf/SamWaf](https://gitee.com/samwaf/SamWaf)
- GitHub
[https://github.com/samwafgo/SamWaf](https://github.com/samwafgo/SamWaf)
- Atomgit
[https://atomgit.com/SamSafe/SamWaf](https://atomgit.com/SamSafe/SamWaf)

## Introdução e Compilação
Como compilar
[Instruções de Compilação](./docs/compile.md)

Manual Online de Compilação:
[https://doc.samwaf.com/en/dev/](https://doc.samwaf.com/en/dev/)

## Plataformas Testadas e Suportadas
[Plataformas Testadas e Suportadas](./docs/Tested_supported_systems.md)

## Outras Informações 

- [Atualizar o Banco de Dados de IP](./docs/ipmodify.md)

## Resultados de Testes
[Resultados de Testes](./test/attackTest.md)

# Política de Segurança
[Política de Segurança](./SECURITY.md)

# Feedback
O SamWaf está em iteração contínua. Feedback e sugestões são bem-vindos.

- [Gitee Issues](https://gitee.com/samwaf/SamWaf/issues)
- [GitHub Issues](https://github.com/samwafgo/SamWaf/issues)
- [Atomgit Issues](https://atomgit.com/SamSafe/SamWaf/issues)
- Feedback por e-mail: samwafgo@gmail.com

# Conta Oficial do WeChat

<img alt="SamWaf" width="400px"  src="./docs/images/mp_samwaf.png"> 

## Histórico de Stars

[![Gráfico de Histórico de Stars](https://api.star-history.com/svg?repos=samwafgo/samwaf&type=Date)](https://star-history.com/#samwafgo/samwaf&Date)


#  Licença
O SamWaf é licenciado sob a Apache License 2.0. Consulte [LICENSE](./LICENSE) para mais detalhes.

Para o aviso de uso de software de terceiros, consulte [ThirdLicense](./ThirdLicense)

# Contribuição
 Agradecimentos aos seguintes contribuidores!

<a href="https://github.com/samwafgo/SamWaf/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=samwafgo/SamWaf" />
</a>
