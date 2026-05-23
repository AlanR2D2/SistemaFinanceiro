"""
CRUD de campos personalizados (fin_custom_fields).

Cobre /api/campos POST/PUT/DELETE.
"""

import pytest
from tests.conftest import assert_tenant_safe, assert_prefixo


pytestmark = pytest.mark.crud


# ---------- helpers locais ----------

def _criar_campo(client, nome, tipo="texto"):
    assert_prefixo(nome)
    r = client.post("/api/campos", json={"nome": nome, "tipo": tipo})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("ok") is True
    return body["campo"]


def _listar(client):
    r = client.get("/api/campos")
    assert r.status_code == 200
    return r.json().get("campos") or []


# ---------- testes ----------

def test_criar_campo_texto(client, nome_unico, tenant_alvo):
    nome = nome_unico("Etiqueta")
    campo = _criar_campo(client, nome, tipo="texto")
    assert campo["nome"] == nome
    assert campo["tipo"] == "texto"
    assert campo["tenant"] == tenant_alvo
    assert int(campo["system_locked"]) == 0

    # cleanup
    client.delete(f"/api/campos/{campo['id']}")


def test_criar_campo_select_e_apagar(client, nome_unico):
    nome = nome_unico("Categoria")
    campo = _criar_campo(client, nome, tipo="select_single")
    cid = campo["id"]

    r = client.delete(f"/api/campos/{cid}")
    assert r.status_code == 200
    assert r.json()["ok"] is True

    # confirma sumiu
    campos = _listar(client)
    assert not any(c["id"] == cid for c in campos)


def test_editar_nome_de_campo_custom(client, nome_unico):
    nome = nome_unico("Nome A")
    campo = _criar_campo(client, nome, tipo="texto")
    cid = campo["id"]

    novo = nome_unico("Nome B")
    r = client.put(f"/api/campos/{cid}", json={"nome": novo})
    assert r.status_code == 200, r.text

    campos = _listar(client)
    atual = next(c for c in campos if c["id"] == cid)
    assert atual["nome"] == novo

    client.delete(f"/api/campos/{cid}")


def test_nao_pode_excluir_campo_system_locked(client):
    campos = _listar(client)
    sys = next(c for c in campos if int(c.get("system_locked") or 0) == 1)
    r = client.delete(f"/api/campos/{sys['id']}")
    assert r.status_code == 400
    body = r.json()
    assert body.get("ok") is False
    assert "sistema" in (body.get("error") or "").lower()


def test_nao_pode_mudar_tipo_de_campo_system_locked(client):
    campos = _listar(client)
    sys = next(c for c in campos if c["chave"] == "status")
    r = client.put(f"/api/campos/{sys['id']}", json={"tipo": "texto"})
    assert r.status_code == 400
    assert "tipo" in (r.json().get("error") or "").lower()


def test_pode_renomear_campo_system_locked(client, nome_unico):
    """O nome (label) é editável mesmo em campos sistema."""
    campos = _listar(client)
    sys = next(c for c in campos if c["chave"] == "status")
    nome_original = sys["nome"]

    novo = nome_unico("Status_RENOMEADO")
    r = client.put(f"/api/campos/{sys['id']}", json={"nome": novo})
    assert r.status_code == 200, r.text

    # restaura para não poluir o tenant
    client.put(f"/api/campos/{sys['id']}", json={"nome": nome_original})


def test_limite_de_10_campos_eh_respeitado(client, nome_unico):
    """Cria N campos extras até o limite. O 11º deve ser bloqueado."""
    inicial = _listar(client)
    livre = 10 - len(inicial)

    criados = []
    try:
        # cria até o limite
        for i in range(livre):
            campo = _criar_campo(client, nome_unico(f"Slot{i}"))
            criados.append(campo["id"])

        # o próximo deve falhar
        r = client.post("/api/campos", json={
            "nome": nome_unico("Excedente"),
            "tipo": "texto",
        })
        assert r.status_code == 400
        assert "limite" in (r.json().get("error") or "").lower()
    finally:
        for cid in criados:
            client.delete(f"/api/campos/{cid}")


def test_tipo_invalido_eh_rejeitado(client, nome_unico):
    r = client.post("/api/campos", json={
        "nome": nome_unico("Inv"),
        "tipo": "tipo_inexistente",
    })
    assert r.status_code == 400
    assert "tipo" in (r.json().get("error") or "").lower()


def test_nome_vazio_eh_rejeitado(client):
    r = client.post("/api/campos", json={"nome": "", "tipo": "texto"})
    assert r.status_code == 400


def test_escopo_padrao_inclui_ambos(client, nome_unico):
    nome = nome_unico("EscopoTeste")
    campo = _criar_campo(client, nome, tipo="texto")
    assert int(campo["escopo_acordos"]) == 1
    assert int(campo["escopo_mandados"]) == 1
    client.delete(f"/api/campos/{campo['id']}")


def test_pode_desabilitar_escopo_de_acordos(client, nome_unico):
    nome = nome_unico("SoMandados")
    r = client.post("/api/campos", json={
        "nome": nome,
        "tipo": "texto",
        "escopo_acordos": 0,
        "escopo_mandados": 1,
    })
    assert r.status_code == 200, r.text
    cid = r.json()["campo"]["id"]
    try:
        campos = _listar(client)
        c = next(c for c in campos if c["id"] == cid)
        assert int(c["escopo_acordos"]) == 0
        assert int(c["escopo_mandados"]) == 1
    finally:
        client.delete(f"/api/campos/{cid}")
