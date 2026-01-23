# Sistema Financeiro – Web App (Flask + Supabase + Docker + Caddy)

Aplicação web para **gestão financeira jurídica**, contemplando:

- Acordos
- Mandados
- Cadastros auxiliares
- Usuários e hierarquias
- Dashboard com KPIs
- Autenticação e autorização
- Deploy em Docker com Gunicorn
- Proxy reverso com Caddy (HTTPS)

---

## Arquitetura

Internet → Caddy (HTTPS) → Gunicorn (Docker) → Flask → Supabase (PostgreSQL)

---

## Estrutura do Projeto

app.py  
templates/  
static/  
Dockerfile  
docker-compose.yml  
Caddyfile  
.env  

---

## Autenticação e Segurança

- Senhas armazenadas com hash seguro (Werkzeug)
- Controle de sessão com Flask-Login
- Controle de acesso por hierarquia
- Variáveis sensíveis via `.env`
- Gunicorn em produção

---

## Usuários

Tabela: `fin_users`

Permissões:
- Admin / Gestor: gerenciam usuários
- Usuários: alteram seus próprios dados

---

## Acordos e Mandados

- CRUD completo
- Separação automática (ativos/finalizados)
- Datas no padrão brasileiro
- Regras automáticas de status

---

## Cadastros Auxiliares

Gerenciamento centralizado:
- Status
- UF
- Réu
- Tipo
- Local
- Prazo estimado

Com controle de ativo/inativo.

---

## Configuração (.env)

FLASK_PORT=5001  
SUPABASE_URL=...  
SUPABASE_KEY=...  

Nunca versionar o `.env`.

---

## Docker

Subir a aplicação:

docker compose up -d --build

Logs:

docker logs -f site-financeiro-web

---

## Caddy

Caddyfile:

financeiro.n8n-draconsumidor.com.br {
    encode gzip
    reverse_proxy site-financeiro-web:5001
}

---

## Deploy

1. Ajustar `.env`
2. Garantir rede Docker
3. Subir containers
4. Acessar via HTTPS

---

Sistema pronto para produção.



1 - Em mandados incluir um card que soma a coluna REPASSE e esse card entra no card total final também
2 - Na edição o campo "Correção" só pode ser preenchida quando VALOR DE DEPÓSITO tenha valor inserido, caso seu valor seja zero ou vazio novamente a correção tem seu valo não calculado automaticamente novamente
3 - anulada
4 - Ocultar do front as colunas 'mes pg', 'finalizado', 'id'
5 - todos cabeçalhos tem que ficar centralizados
6 - todas colunas de números tem que ficar centralizadas
7 - se a coluna Tipo = "CNPJ"
→ aplica ac-row-cnpj (magenta #ff00ff)
8 - Se a coluna Status = "A REPASSAR"
→ aplica ac-row-arepassar (amarelo #ffff00)
9 - Se a coluna Status = "REPASSADO"
→ aplica ac-row-repassado (rosa/roxo #c27ba0)
10 - Se a coluna Local = "ID DEPÓSITO" ou "ID DEPOSITO"
→ aplica ac-row-iddeposito (verde #00b050)
11 - Se a coluna Status = "AGUARDANDO AUTORIZAÇÃO PIX (BRADESCO)"
(ou sem acento: "AGUARDANDO AUTORIZACAO PIX (BRADESCO)")
→ aplica ac-row-aguardando-pix (azul #0070c0) e o texto vira branco
12 - Se a coluna  Status = "AGUARDANDO RETORNO DO CLIENTE"
→ aplica ac-row-aguardando-retorno (azul claro/cinza #a2c4c9)
13 - Na edição o parametro tipo, se eu escrever CNPJ e salvar, depois abrir de novo e apagar seu valor e salvar, o valor antigo não sai