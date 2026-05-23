# Plano de Testes E2E — Sistema Financeiro

Suite de testes API-level em pytest+httpx que valida o comportamento do app
contra o Flask local + Supabase dev. Toda a suite roda **scopeda ao tenant
`Lara's Company`** — nunca toca em Dra Consumidor, Aeroline ou qualquer
outro tenant.

---

## Por que API-level e não Selenium/Playwright

- **Velocidade**: a suite completa roda em segundos, não minutos.
- **Cobertura**: ~90% do que importa (CRUD, regras de negócio,
  isolamento de tenant) está no backend, não no DOM.
- **Manutenção**: testes não quebram quando o HTML é refatorado.
- **Limitação aceita**: drag-drop visual e modais com preview não são
  cobertos. Se virarem regressões frequentes, dá pra adicionar Playwright
  numa segunda suite paralela depois.

---

## Camadas de segurança (multi-tenant safety)

Como rodamos contra o **Supabase de dev** compartilhado com Dra Consumidor
e Aeroline, há 5 camadas de proteção:

1. **`.env.test` separado** do `.env` de dev — credenciais do usuário do
   tenant `Lara's Company` ficam só lá. Não vai pro git.
2. **Bloqueio explícito**: `conftest.py` aborta a suite se
   `TEST_TENANT_NAME` for `Dra Consumidor` ou `Aeroline`.
3. **Filtro automático server-side**: todo endpoint do app só lê/escreve
   no tenant da sessão (lógica em `sb_select` / `_get_tenant`).
4. **Prefixo `__E2E__`** em tudo que os testes criam (campos, opções,
   nomes únicos por timestamp). O teardown só apaga itens com prefixo.
5. **`assert_tenant_safe()`**: helper que falha imediatamente se qualquer
   resposta vazar `tenant` diferente do alvo. Usado em todos os testes
   que listam dados.

Se um teste acidentalmente criar dados sem prefixo, ele falha o assert
`assert_prefixo()`. Se um endpoint retornar dado de outro tenant, o
guardrail `enforce_tenant_em_cada_teste` aborta a suite com `pytest.exit`.

---

## Preparação (uma vez por máquina)

### 1. Tenant e usuário

O tenant `Lara's Company` já deve existir em `fin_tenants`. Para o usuário
de teste, abra o painel staff e crie um usuário admin nele:

- Acesse [http://localhost:5001/staff/login](http://localhost:5001/staff/login)
- Em **Usuários** → "+ Adicionar usuário"
  - Login: ex.: `lara_e2e`
  - Senha: à sua escolha (mín. 6 caracteres)
  - Hierarquia: `admin`
  - Tenant: `Lara's Company`

### 2. Arquivo `.env.test`

```bash
cp .env.test.example .env.test
```

Edite `.env.test`:

```env
TEST_BASE_URL=http://localhost:5001
TEST_USER_LOGIN=lara_e2e
TEST_USER_PASSWORD=<a senha que você definiu>
TEST_TENANT_NAME=Lara's Company
TEST_RESOURCE_PREFIX=__E2E__
```

### 3. Dependências

```powershell
& "C:/Users/alan.chagas_vittude/miniconda3/envs/sistema_financeiro/python.exe" -m pip install -r requirements-test.txt
```

### 4. Subir o Flask

A suite assume `localhost:5001` rodando. Em outro terminal:

```powershell
& "C:/Users/alan.chagas_vittude/miniconda3/envs/sistema_financeiro/python.exe" app.py
```

---

## Como rodar

```powershell
# Suite completa
& "C:/Users/alan.chagas_vittude/miniconda3/envs/sistema_financeiro/python.exe" -m pytest

# Só smoke (rápido — antes de continuar)
& "C:/Users/alan.chagas_vittude/miniconda3/envs/sistema_financeiro/python.exe" -m pytest -m smoke

# Só isolamento de tenant
& "C:/Users/alan.chagas_vittude/miniconda3/envs/sistema_financeiro/python.exe" -m pytest -m isolation

# Um arquivo específico
& "C:/Users/alan.chagas_vittude/miniconda3/envs/sistema_financeiro/python.exe" -m pytest tests/e2e/test_opcoes_crud.py
```

Para uma run mais verbosa: `-vv -s` (sem captura de stdout).

---

## O que está coberto hoje

### `test_smoke.py` (5 testes) — marker `smoke`

| Teste | Valida |
|---|---|
| `test_login_estabeleceu_sessao` | Fixture de login funciona |
| `test_migration_05_aplicada` | `/api/campos` não retorna 503 |
| `test_sete_campos_sistema_estao_seedados` | 7 system_locked existem com chaves corretas |
| `test_coluna_fixa_dos_campos_sistema` | Mapeamento chave→coluna fixa correto |
| `test_limite_de_10_campos_exposto` | API retorna `limite: 10` |

### `test_campos_crud.py` (10 testes) — marker `crud`

| Teste | Valida |
|---|---|
| `test_criar_campo_texto` | POST campo texto livre |
| `test_criar_campo_select_e_apagar` | POST + DELETE de select |
| `test_editar_nome_de_campo_custom` | PUT nome |
| `test_nao_pode_excluir_campo_system_locked` | system_locked não dá DELETE |
| `test_nao_pode_mudar_tipo_de_campo_system_locked` | system_locked não muda `tipo` |
| `test_pode_renomear_campo_system_locked` | system_locked aceita renomear |
| `test_limite_de_10_campos_eh_respeitado` | 11º campo bloqueado |
| `test_tipo_invalido_eh_rejeitado` | Tipo fora do enum |
| `test_nome_vazio_eh_rejeitado` | Nome em branco |
| `test_escopo_padrao_inclui_ambos` | escopo_acordos / escopo_mandados defaults |
| `test_pode_desabilitar_escopo_de_acordos` | Criar só em mandados funciona |

### `test_opcoes_crud.py` (8 testes) — marker `crud`

| Teste | Valida |
|---|---|
| `test_criar_opcao_simples` | POST com cor + hierarquia |
| `test_opcao_em_campo_nao_select_eh_rejeitada` | Texto livre não aceita opções |
| `test_opcao_duplicada_case_insensitive_eh_rejeitada` | "PAGO" colide com "Pago" |
| `test_hierarquia_eh_clampada_entre_1_e_10` | 0→1, 99→10 |
| `test_editar_cor_e_hierarquia` | PUT campos individuais |
| `test_renomear_opcao` | PUT valor |
| `test_excluir_opcao` | DELETE opção |
| `test_apagar_campo_em_cascata_remove_opcoes` | FK ON DELETE CASCADE |

### `test_ordem_colunas.py` (4 testes) — marker `crud`

| Teste | Valida |
|---|---|
| `test_get_retorna_colunas_fixas_e_custom` (×2) | Estrutura do GET para ambos escopos |
| `test_escopo_invalido_retorna_400` | URL com escopo desconhecido |
| `test_persistir_e_reler_ordem` | PUT persiste; GET reflete |
| `test_reordenar_acordos_nao_altera_mandados` | Escopos independentes |

### `test_honorarios_default.py` (3 testes) — marker `crud`

| Teste | Valida |
|---|---|
| `test_salvar_e_recuperar` | PUT 27.5 vira value="27.5" na tela |
| `test_aceita_virgula_e_converte_para_ponto` | "12,5" → "12.5" |
| `test_vazio_zera_valor` | "" remove o setting |

### `test_tenant_isolation.py` (6 testes) — marker `isolation`

| Teste | Valida |
|---|---|
| `test_listagem_de_campos_nao_vaza_outros_tenants` | `/api/campos` só do alvo |
| `test_opcoes_nao_vazam_outros_tenants` | Opções aninhadas iguais |
| `test_ordem_colunas_nao_vaza_dados_de_outros_tenants` | Forma OK em ambos escopos |
| `test_nao_acessar_campo_de_outro_tenant_via_id` | PUT em field_id alheio falha |
| `test_row_colors_v2_so_traz_opcoes_do_tenant` | Mapa íntegro |
| `test_recursos_criados_aparecem_apenas_no_tenant` | Criar/recuperar = tenant correto |

---

## Como adicionar testes para novas features

A estrutura foi pensada para crescer sem ficar bagunçada. Receita:

### 1. Crie um arquivo `tests/e2e/test_<feature>.py`

```python
"""
<Feature> — descrição em uma linha.
"""

import pytest
from tests.conftest import assert_tenant_safe, assert_prefixo


pytestmark = pytest.mark.crud   # ou outro marker


def test_caso_feliz(client, nome_unico, tenant_alvo):
    # 1) criar com nome_unico('Foo') — garante prefixo + unicidade
    # 2) bater no endpoint
    # 3) assert_tenant_safe(resposta) sempre que ela trouxer dados
    # 4) cleanup no finally
    ...
```

### 2. Use os fixtures certos

| Fixture | Para que serve |
|---|---|
| `client` | httpx.Client autenticado, sessão pronta |
| `nome_unico` | gera nomes com prefixo `__E2E__<ts>_<label>` |
| `tenant_alvo` | string do tenant — passe para `assert_tenant_safe` |
| `prefixo_recurso` | só se precisar do prefixo cru |

### 3. Padrão para cada teste

```python
def test_algo(client, nome_unico, tenant_alvo):
    r = client.post("/api/algo", json={"nome": nome_unico("X")})
    assert r.status_code == 200
    recurso = r.json()["data"]
    try:
        assert_tenant_safe(recurso, tenant_alvo)
        # … asserts da feature
    finally:
        client.delete(f"/api/algo/{recurso['id']}")
```

### 4. Markers (opcional mas recomendado)

Adicione em `pytest.ini` se criar novos markers. Padrões existentes:
`smoke`, `crud`, `isolation`, `slow`.

### 5. Regras de ouro

- **Nunca crie nada sem prefixo** — use `nome_unico()`.
- **Sempre `try/finally` com cleanup** — testes ficam frágeis quando deixam
  lixo.
- **Sempre `assert_tenant_safe(...)` em listagens** — é cheap e pega
  vazamentos de tenant cedo.
- **Nada de hardcoded `tenant="Dra Consumidor"`** ou similar — use
  `tenant_alvo`.
- **Não teste idempotência via reusar nomes** — use timestamps. Senão dá
  conflito entre runs paralelos.

---

## O que ainda não está coberto

Para honestidade do plano, listo o que ficaria de fora:

- **Drag-drop visual** em `/admin/ordem-colunas` e no modal de opções:
  o backend do PUT é testado; a interação JS não. Se virar fonte de bug,
  adicionar Playwright.
- **Preview ao vivo de cor no modal**: idem.
- **Fase 4 (ainda não implementada)**: quando as tabelas Acordos/Mandados
  passarem a respeitar a ordem custom + campos personalizados, novos
  testes precisarão validar:
  - `/api/acordos` retorna `valores_custom` no payload
  - Coluna custom aparece na ordem certa
  - Pintura de linha usa o menor `hierarquia` dentre opções com cor
- **Login negativo**: senha errada, usuário inexistente. Cobertura média
  — pode ser adicionada quando relevante.

---

## Troubleshooting

| Sintoma | Causa provável | Como resolver |
|---|---|---|
| `RuntimeError: .env.test não encontrado` | Faltou copiar o exemplo | `cp .env.test.example .env.test` + preencher |
| `pytest.exit: Login falhou` | Credenciais erradas no `.env.test` | Conferir login/senha no painel staff |
| `pytest.exit: TEST_TENANT_NAME é tenant de produção` | Você apontou para Dra Consumidor/Aeroline | Mudar para `Lara's Company` |
| `503 Service Unavailable` em `/api/campos` | Migration 05 não rodou ou PostgREST cacheou | Aplicar SQL + `NOTIFY pgrst, 'reload schema';` |
| `assertion VAZAMENTO DE TENANT` | Bug real de isolamento. **Não ignorar.** | Investigar o endpoint que vazou |
| Suite passa mas deixou lixo | Algum teste crashou fora do finally | Rodar de novo — o `limpa_recursos_teste` autouse limpa no início |
