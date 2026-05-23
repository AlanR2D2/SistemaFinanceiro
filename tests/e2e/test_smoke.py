"""
Smoke tests — rodam primeiro. Se algum falhar, parar a suite.

Objetivo: validar pré-requisitos antes de testar comportamento.
"""

import pytest
from tests.conftest import assert_tenant_safe


pytestmark = pytest.mark.smoke


def test_login_estabeleceu_sessao(client):
    """Dashboard responde 200 — fixture `client` já fez o login."""
    r = client.get("/")
    assert r.status_code == 200


def test_migration_05_aplicada(client):
    """/api/campos retorna 200 (não 503). Se 503, rode migrations/05_custom_fields.sql."""
    r = client.get("/api/campos")
    assert r.status_code != 503, (
        "Migration 05 não está aplicada. Rode migrations/05_custom_fields.sql "
        "no SQL Editor do Supabase e depois `NOTIFY pgrst, 'reload schema';`."
    )
    assert r.status_code == 200, f"GET /api/campos retornou {r.status_code}"


def test_sete_campos_sistema_estao_seedados(client, tenant_alvo):
    """Após o seed da migration 05, o tenant tem os 7 campos system_locked."""
    r = client.get("/api/campos")
    data = r.json()
    campos = data.get("campos") or []
    assert_tenant_safe(campos, tenant_alvo)

    sys_fields = [c for c in campos if int(c.get("system_locked") or 0) == 1]
    chaves = sorted(c["chave"] for c in sys_fields)
    esperado = sorted([
        "status", "local", "conta",
        "reu", "uf", "escritorio_reu", "prazo_estimado",
    ])
    assert chaves == esperado, f"Campos sistema seedados não batem: {chaves}"


def test_coluna_fixa_dos_campos_sistema(client):
    """Os 6 campos sistema com coluna fixa apontam para o nome correto.
    O campo `conta` é o único sem coluna fixa (vai pro JSONB)."""
    r = client.get("/api/campos")
    campos = r.json().get("campos") or []
    coluna_fixa_por_chave = {c["chave"]: c.get("coluna_fixa") for c in campos
                              if int(c.get("system_locked") or 0) == 1}

    esperado = {
        "status": "status",
        "local": "local",
        "reu": "reu",
        "uf": "uf",
        "escritorio_reu": "escritorio_reu",
        "prazo_estimado": "prazo_estimado",
        "conta": None,
    }
    for chave, col in esperado.items():
        assert coluna_fixa_por_chave.get(chave) == col, (
            f"Campo {chave!r}: coluna_fixa={coluna_fixa_por_chave.get(chave)!r}, "
            f"esperado {col!r}"
        )


def test_limite_de_10_campos_exposto(client):
    """API anuncia o limite — frontend usa para desabilitar botão Add."""
    data = client.get("/api/campos").json()
    assert data.get("limite") == 10
