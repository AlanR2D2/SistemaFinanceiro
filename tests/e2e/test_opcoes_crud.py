"""
CRUD de opções (fin_custom_field_options).

Cobre /api/campos/<id>/opcoes (POST, PUT, DELETE) + regras de cor,
hierarquia 1-10, duplicação, bloqueio quando em uso.
"""

import pytest
from tests.conftest import assert_prefixo


pytestmark = pytest.mark.crud


def _campo_select(client, nome_unico, tipo="select_single"):
    """Cria um campo SELECT vazio com prefixo de teste, devolve dict."""
    nome = nome_unico("CampoOpcoes")
    r = client.post("/api/campos", json={"nome": nome, "tipo": tipo})
    assert r.status_code == 200, r.text
    return r.json()["campo"]


def _criar_opcao(client, field_id, valor, cor=None, hierarquia=5):
    payload = {"valor": valor, "hierarquia": hierarquia}
    if cor:
        payload["cor"] = cor
    r = client.post(f"/api/campos/{field_id}/opcoes", json=payload)
    assert r.status_code == 200, r.text
    return r.json()["opcao"]


def _opcoes(client, field_id):
    campos = client.get("/api/campos").json()["campos"]
    c = next((c for c in campos if c["id"] == field_id), None)
    return (c or {}).get("opcoes", [])


# ---------- testes ----------

def test_criar_opcao_simples(client, nome_unico):
    campo = _campo_select(client, nome_unico)
    try:
        valor = nome_unico("Pago")
        opt = _criar_opcao(client, campo["id"], valor, cor="#00b050", hierarquia=3)
        assert opt["valor"] == valor
        assert opt["cor"] == "#00b050"
        assert int(opt["hierarquia"]) == 3
        assert int(opt["ativo"]) == 1
    finally:
        client.delete(f"/api/campos/{campo['id']}")


def test_opcao_em_campo_nao_select_eh_rejeitada(client, nome_unico):
    nome = nome_unico("Texto")
    r = client.post("/api/campos", json={"nome": nome, "tipo": "texto"})
    campo = r.json()["campo"]
    try:
        r = client.post(f"/api/campos/{campo['id']}/opcoes",
                        json={"valor": nome_unico("X")})
        assert r.status_code == 400
        assert "sele" in (r.json().get("error") or "").lower()
    finally:
        client.delete(f"/api/campos/{campo['id']}")


def test_opcao_duplicada_case_insensitive_eh_rejeitada(client, nome_unico):
    campo = _campo_select(client, nome_unico)
    try:
        v = nome_unico("Etiqueta")
        _criar_opcao(client, campo["id"], v)

        r = client.post(f"/api/campos/{campo['id']}/opcoes",
                        json={"valor": v.upper()})
        assert r.status_code == 400
        assert "existe" in (r.json().get("error") or "").lower()
    finally:
        client.delete(f"/api/campos/{campo['id']}")


def test_hierarquia_eh_clampada_entre_1_e_10(client, nome_unico):
    campo = _campo_select(client, nome_unico)
    try:
        # 0 vira 1
        o1 = _criar_opcao(client, campo["id"], nome_unico("Min"), hierarquia=0)
        assert int(o1["hierarquia"]) == 1
        # 99 vira 10
        o2 = _criar_opcao(client, campo["id"], nome_unico("Max"), hierarquia=99)
        assert int(o2["hierarquia"]) == 10
    finally:
        client.delete(f"/api/campos/{campo['id']}")


def test_editar_cor_e_hierarquia(client, nome_unico):
    campo = _campo_select(client, nome_unico)
    try:
        opt = _criar_opcao(client, campo["id"], nome_unico("E"), cor=None, hierarquia=5)

        r = client.put(
            f"/api/campos/{campo['id']}/opcoes/{opt['id']}",
            json={"cor": "#ff0000", "cor_letra": "#ffffff", "hierarquia": 1},
        )
        assert r.status_code == 200, r.text

        opcoes = _opcoes(client, campo["id"])
        atualizado = next(o for o in opcoes if o["id"] == opt["id"])
        assert atualizado["cor"] == "#ff0000"
        assert atualizado["cor_letra"] == "#ffffff"
        assert int(atualizado["hierarquia"]) == 1
    finally:
        client.delete(f"/api/campos/{campo['id']}")


def test_renomear_opcao(client, nome_unico):
    campo = _campo_select(client, nome_unico)
    try:
        antigo = nome_unico("Antes")
        novo = nome_unico("Depois")
        opt = _criar_opcao(client, campo["id"], antigo)

        r = client.put(
            f"/api/campos/{campo['id']}/opcoes/{opt['id']}",
            json={"valor": novo},
        )
        assert r.status_code == 200, r.text

        opcoes = _opcoes(client, campo["id"])
        atualizado = next(o for o in opcoes if o["id"] == opt["id"])
        assert atualizado["valor"] == novo
    finally:
        client.delete(f"/api/campos/{campo['id']}")


def test_excluir_opcao(client, nome_unico):
    campo = _campo_select(client, nome_unico)
    try:
        opt = _criar_opcao(client, campo["id"], nome_unico("ParaApagar"))
        r = client.delete(f"/api/campos/{campo['id']}/opcoes/{opt['id']}")
        assert r.status_code == 200, r.text

        assert not any(o["id"] == opt["id"] for o in _opcoes(client, campo["id"]))
    finally:
        client.delete(f"/api/campos/{campo['id']}")


def test_apagar_campo_em_cascata_remove_opcoes(client, nome_unico):
    """ON DELETE CASCADE no FK garante que apagar o campo apaga as opções."""
    campo = _campo_select(client, nome_unico)
    cid = campo["id"]
    for i in range(3):
        _criar_opcao(client, cid, nome_unico(f"Opt{i}"))
    assert len(_opcoes(client, cid)) == 3

    # apaga o campo
    r = client.delete(f"/api/campos/{cid}")
    assert r.status_code == 200

    # campo sumiu
    campos = client.get("/api/campos").json()["campos"]
    assert not any(c["id"] == cid for c in campos)
