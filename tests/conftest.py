"""
Fixtures globais para a suite E2E.

Toda a suite roda contra o Flask local + Supabase dev, autenticada como
um usuário do tenant "Lara's Company". A barreira de segurança principal
é o filtro automático por tenant no app — todo endpoint só enxerga linhas
do tenant em sessão.

Camadas extras de segurança implementadas aqui:

  1) `_assert_tenant_safe()` — falha imediatamente se algum payload de
     resposta vazar `tenant != Lara's Company`. Usado pelos testes.
  2) `_assert_prefixo()` — recursos criados pelos testes SEMPRE recebem
     prefixo (default __E2E__). O teardown só apaga itens com esse prefixo.
  3) `enforce_tenant` (autouse) — antes de cada teste, valida que a sessão
     do client realmente está no tenant correto.
"""

from __future__ import annotations

import os
import time
from typing import Iterator

import httpx
import pytest
from dotenv import load_dotenv


# ---------------------------------------------------------------------------
# Configuração da suite — carregada de .env.test. As validações estritas
# rodam dentro de _config() (lazy) para permitir `pytest --collect-only`
# sem credenciais.
# ---------------------------------------------------------------------------

ENV_TEST_PATH = os.path.join(os.path.dirname(__file__), "..", ".env.test")

# Defaults — sobrescritos se .env.test existir.
BASE_URL = "http://localhost:5001"
LOGIN = ""
PASSWORD = ""
TENANT = "Lara's Company"
PREFIXO = "__E2E__"

if os.path.exists(ENV_TEST_PATH):
    load_dotenv(ENV_TEST_PATH, override=True)
    BASE_URL = os.getenv("TEST_BASE_URL", BASE_URL).rstrip("/")
    LOGIN    = os.getenv("TEST_USER_LOGIN", "").strip()
    PASSWORD = os.getenv("TEST_USER_PASSWORD", "").strip()
    TENANT   = os.getenv("TEST_TENANT_NAME", TENANT).strip()
    PREFIXO  = os.getenv("TEST_RESOURCE_PREFIX", PREFIXO).strip()


def _exigir_config_valida():
    """Lança RuntimeError se algo essencial estiver faltando. Chamado pelas
    fixtures que precisam de fato das credenciais — assim `--collect-only`
    não precisa de `.env.test`."""
    if not os.path.exists(ENV_TEST_PATH):
        raise RuntimeError(
            "Arquivo .env.test não encontrado. Copie .env.test.example e "
            "preencha as credenciais de um usuário do tenant 'Lara's Company'."
        )
    if not LOGIN or not PASSWORD:
        raise RuntimeError(
            "TEST_USER_LOGIN e TEST_USER_PASSWORD são obrigatórios no .env.test"
        )

    # Bloqueio: testes nunca rodam contra tenants conhecidos de produção.
    tenants_proibidos = {"Dra Consumidor", "Aeroline"}
    if TENANT in tenants_proibidos:
        raise RuntimeError(
            f"TEST_TENANT_NAME={TENANT!r} é um tenant de produção. "
            f"A suite recusa rodar para evitar contaminação. "
            f"Use 'Lara's Company' ou outro tenant dedicado a testes."
        )


# ---------------------------------------------------------------------------
# Fixture: HTTP client autenticado
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def client() -> Iterator[httpx.Client]:
    """httpx.Client com cookie de sessão Flask já autenticado."""
    _exigir_config_valida()
    c = httpx.Client(base_url=BASE_URL, timeout=15.0, follow_redirects=False)

    # 0) servidor está de pé?
    try:
        r = c.get("/login")
    except httpx.ConnectError as e:
        pytest.exit(
            f"Não consegui conectar em {BASE_URL}. Suba o Flask local antes: "
            f"`python app.py`. Erro: {e}",
            returncode=2,
        )
    assert r.status_code == 200, f"GET /login não retornou 200: {r.status_code}"

    # 1) login
    r = c.post("/login", data={"username": LOGIN, "password": PASSWORD})
    if r.status_code != 302:
        pytest.exit(
            f"Login falhou para usuário {LOGIN!r}. "
            f"Verifique credenciais no .env.test. status={r.status_code}",
            returncode=2,
        )

    # 2) confirma que a sessão pegou
    r = c.get("/")
    assert r.status_code == 200, f"GET / após login retornou {r.status_code}"

    yield c

    # teardown: logout cortês
    try:
        c.get("/logout")
    except Exception:
        pass
    c.close()


# ---------------------------------------------------------------------------
# Constantes e helpers exportados para os testes
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def tenant_alvo() -> str:
    return TENANT


@pytest.fixture(scope="session")
def prefixo_recurso() -> str:
    return PREFIXO


def _nome_unico(label: str) -> str:
    """Gera nome único com prefixo de segurança + timestamp."""
    return f"{PREFIXO}{int(time.time() * 1000)}_{label}"


@pytest.fixture
def nome_unico():
    return _nome_unico


# ---------------------------------------------------------------------------
# Guardrails (asserts reutilizáveis pelos testes)
# ---------------------------------------------------------------------------

def assert_tenant_safe(rows, expected_tenant=TENANT):
    """Falha se qualquer linha vazar tenant diferente do esperado.

    Usar SEMPRE após chamadas que retornam dados — é a linha de defesa
    final caso algum endpoint deixe escapar registros de outro tenant.
    """
    if rows is None:
        return
    if isinstance(rows, dict):
        rows = [rows]
    for r in rows:
        if not isinstance(r, dict):
            continue
        t = r.get("tenant")
        if t is not None and t != expected_tenant:
            raise AssertionError(
                f"VAZAMENTO DE TENANT: encontrei row com tenant={t!r}, "
                f"esperado {expected_tenant!r}. Row: {r}"
            )


def assert_prefixo(nome: str):
    """Garante que tudo que os testes criam tem o prefixo de segurança."""
    if not nome or not nome.startswith(PREFIXO):
        raise AssertionError(
            f"Recurso sem prefixo de teste: {nome!r}. "
            f"Use o fixture `nome_unico('...')` para gerar nomes."
        )


# ---------------------------------------------------------------------------
# Teardown global: limpa qualquer recurso de teste deixado para trás
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def limpa_recursos_teste(client):
    """Antes E depois da suite: deleta tudo que começa com PREFIXO no tenant.

    Roda como cinto de segurança — se um teste crashar sem limpar, o run
    seguinte limpa antes de começar.
    """
    def _purge():
        try:
            r = client.get("/api/campos")
            if r.status_code != 200:
                return
            data = r.json()
            campos = (data or {}).get("campos") or []
            for c in campos:
                nome = (c.get("nome") or "").strip()
                if not nome.startswith(PREFIXO):
                    continue
                # extra paranoia: nunca apaga system_locked
                if int(c.get("system_locked") or 0) == 1:
                    continue
                cid = c.get("id")
                if not cid:
                    continue
                try:
                    client.delete(f"/api/campos/{cid}")
                except Exception:
                    pass
        except Exception:
            pass

    _purge()
    yield
    _purge()


@pytest.fixture(autouse=True)
def enforce_tenant_em_cada_teste(client):
    """Antes de cada teste: confirma que a sessão está no tenant alvo.

    Se outro teste por engano logar como outro usuário (não deveria, mas…),
    isto pega no próximo teste.
    """
    # Não dá pra ler `session["tenant"]` do servidor direto via API.
    # Em vez disso, pedimos /api/campos e validamos que NADA vaza tenant ≠ alvo.
    r = client.get("/api/campos")
    if r.status_code == 200:
        data = r.json()
        for c in (data.get("campos") or []):
            if c.get("tenant") and c["tenant"] != TENANT:
                pytest.exit(
                    f"VAZAMENTO DETECTADO ANTES DE TESTE: campo de tenant {c['tenant']!r} "
                    f"chegou na sessão (esperado {TENANT!r}). Suite abortada.",
                    returncode=3,
                )
    yield
