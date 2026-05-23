"""
Ordem das colunas — GET e PUT /api/ordem-colunas/<escopo>.

Cobre persistência e que muda ordem em um escopo não afeta o outro.
"""

import pytest


pytestmark = pytest.mark.crud


@pytest.mark.parametrize("escopo", ["acordos", "mandados"])
def test_get_retorna_colunas_fixas_e_custom(client, escopo):
    r = client.get(f"/api/ordem-colunas/{escopo}")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["ok"] is True
    assert data["escopo"] == escopo

    colunas = data["colunas"]
    assert len(colunas) > 0

    # Sempre tem pelo menos colunas fixas.
    origens = {c["origem"] for c in colunas}
    assert "fixa" in origens or "sistema" in origens

    # Cada item tem chave + label + ordem + visivel.
    for c in colunas:
        assert "chave" in c and c["chave"]
        assert "label" in c
        assert "origem" in c
        assert "ordem" in c
        assert "visivel" in c


def test_escopo_invalido_retorna_400(client):
    r = client.get("/api/ordem-colunas/foo")
    assert r.status_code == 400


def test_persistir_e_reler_ordem(client):
    """Reverte uma coluna para o topo e confirma persistência."""
    r = client.get("/api/ordem-colunas/acordos")
    colunas = r.json()["colunas"]
    assert len(colunas) >= 2

    # estado original (chaves na ordem)
    original = [c["chave"] for c in colunas]

    # gira: empurra a primeira para o final
    nova = original[1:] + [original[0]]
    payload = {"ordem": [{"chave": k} for k in nova]}

    try:
        r = client.put("/api/ordem-colunas/acordos", json=payload)
        assert r.status_code == 200, r.text

        rel = client.get("/api/ordem-colunas/acordos").json()["colunas"]
        chaves_atuais = [c["chave"] for c in rel]
        # Itens podem incluir novos campos no meio; checamos só a posição
        # relativa entre os que estavam no payload original.
        idx = {k: chaves_atuais.index(k) for k in nova if k in chaves_atuais}
        for i in range(len(nova) - 1):
            a, b = nova[i], nova[i + 1]
            if a in idx and b in idx:
                assert idx[a] < idx[b], (
                    f"Ordem não respeitada: {a!r} (pos {idx[a]}) deveria vir antes de {b!r} (pos {idx[b]})"
                )
    finally:
        # restaura ordem original
        client.put(
            "/api/ordem-colunas/acordos",
            json={"ordem": [{"chave": k} for k in original]},
        )


def test_reordenar_acordos_nao_altera_mandados(client):
    """Salvar nova ordem em acordos não pode mexer em mandados."""
    md_antes = [c["chave"] for c in client.get("/api/ordem-colunas/mandados").json()["colunas"]]

    ac = [c["chave"] for c in client.get("/api/ordem-colunas/acordos").json()["colunas"]]
    if len(ac) < 2:
        pytest.skip("Acordos com poucas colunas para reordenar")

    try:
        invertido = list(reversed(ac))
        client.put("/api/ordem-colunas/acordos",
                   json={"ordem": [{"chave": k} for k in invertido]})

        md_depois = [c["chave"] for c in client.get("/api/ordem-colunas/mandados").json()["colunas"]]
        assert md_antes == md_depois
    finally:
        client.put("/api/ordem-colunas/acordos",
                   json={"ordem": [{"chave": k} for k in ac]})
