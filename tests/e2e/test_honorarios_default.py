"""
% honorários padrão (PUT /api/config/honorarios-default).
"""

import pytest


pytestmark = pytest.mark.crud


def _ler_porc_default_via_html(client) -> str:
    """Lê a tela /admin/ordem-colunas e extrai o value do input.

    Não temos GET dedicado para o valor; é um setting global do tenant que
    o servidor injeta no template. Inspecionamos o HTML.
    """
    r = client.get("/admin/ordem-colunas")
    assert r.status_code == 200
    txt = r.text
    # busca id="hpInput" e captura value="..."
    import re
    m = re.search(r'id="hpInput"[^>]*value="([^"]*)"', txt)
    assert m, "Não encontrei o input #hpInput na página /admin/ordem-colunas"
    return m.group(1)


def test_salvar_e_recuperar(client):
    original = _ler_porc_default_via_html(client)

    try:
        r = client.put("/api/config/honorarios-default", json={"valor": "27.5"})
        assert r.status_code == 200, r.text

        assert _ler_porc_default_via_html(client) == "27.5"
    finally:
        # restaura
        client.put("/api/config/honorarios-default",
                   json={"valor": original or ""})


def test_aceita_virgula_e_converte_para_ponto(client):
    original = _ler_porc_default_via_html(client)
    try:
        client.put("/api/config/honorarios-default", json={"valor": "12,5"})
        atual = _ler_porc_default_via_html(client)
        assert atual == "12.5", f"Esperava 12.5, veio {atual!r}"
    finally:
        client.put("/api/config/honorarios-default",
                   json={"valor": original or ""})


def test_vazio_zera_valor(client):
    original = _ler_porc_default_via_html(client)
    try:
        client.put("/api/config/honorarios-default", json={"valor": "30"})
        assert _ler_porc_default_via_html(client) == "30"

        client.put("/api/config/honorarios-default", json={"valor": ""})
        assert _ler_porc_default_via_html(client) == ""
    finally:
        client.put("/api/config/honorarios-default",
                   json={"valor": original or ""})
