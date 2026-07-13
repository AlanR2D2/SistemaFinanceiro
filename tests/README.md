# Bateria de Testes

Rode **sempre** após implementar qualquer nova feature ou correção.

```powershell
conda activate sistema_financeiro
python tests/run_all.py
```

> Ambiente conda correto: **`sistema_financeiro`**
> (`C:\Users\alan.chagas_vittude\miniconda3\envs\sistema_financeiro\python.exe`).

## O que é coberto

| # | Arquivo | Verifica |
|---|---------|----------|
| 1 | (runner) | `app.py` compila sem erro de sintaxe |
| 2 | (runner) | Todos os templates Jinja2 parseiam |
| 3 | `test_config_visibilidade.py` | Visibilidade/label de colunas por tenant; **isolamento entre tenants** (config de um não vaza para outro) — sem banco |
| 4 | `test_ordem_colunas_endpoint.py` | `PUT /api/ordem-colunas/<escopo>` persiste visível+label no escopo base; 400 em escopo inválido — mockado |
| 5 | `test_frontend_headers.js` | Renomear coluna **não destrói o botão de filtro** (node) |
| 6 | `test_smoke_http.py` | Telas autenticadas retornam **200**; filtro server-side responde ok; rota protegida sem login → 302 (Supabase real, precisa do `.env`) |

## Checklist obrigatório para toda nova feature

- [ ] Telas relevantes retornam **status 200** (sem 500).
- [ ] **Filtros** das tabelas continuam funcionando.
- [ ] Configurações personalizadas de um tenant **não interferem** em outro tenant.
- [ ] `python tests/run_all.py` termina com **RESUMO** todo `[OK ]`.

Ao criar uma feature nova, adicione aqui um teste que cubra o comportamento
dela e o caso de isolamento por tenant (quando aplicável).
