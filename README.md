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
