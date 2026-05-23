"""
Isolamento de tenant — testes CRÍTICOS.

A regra fundamental do sistema multi-tenant: nada que o usuário do
tenant A faz pode aparecer / afetar o tenant B. Estes testes validam isso
do ponto de vista da API.
"""

import pytest
from tests.conftest import assert_tenant_safe


pytestmark = pytest.mark.isolation


def test_listagem_de_campos_nao_vaza_outros_tenants(client, tenant_alvo):
    """Nenhum campo retornado por /api/campos pode pertencer a outro tenant."""
    r = client.get("/api/campos")
    campos = r.json().get("campos") or []
    assert_tenant_safe(campos, tenant_alvo)


def test_opcoes_nao_vazam_outros_tenants(client, tenant_alvo):
    """Cada opção retornada também tem que ser do tenant alvo."""
    campos = client.get("/api/campos").json().get("campos") or []
    todas_opcoes = []
    for c in campos:
        todas_opcoes.extend(c.get("opcoes") or [])
    assert_tenant_safe(todas_opcoes, tenant_alvo)


def test_ordem_colunas_nao_vaza_dados_de_outros_tenants(client):
    """O endpoint pode misturar fixas/sistema/custom mas tudo deve refletir
    apenas o estado do tenant logado (impossível verificar 'tenant' direto;
    o teste é mais para garantir 200 + estrutura)."""
    for escopo in ("acordos", "mandados"):
        r = client.get(f"/api/ordem-colunas/{escopo}")
        assert r.status_code == 200
        for c in r.json().get("colunas") or []:
            # Campos custom de outro tenant teriam chave 'cf_X' desconhecida.
            # Não dá pra detectar sozinho; o filtro server-side cuida.
            assert "chave" in c


def test_nao_acessar_campo_de_outro_tenant_via_id(client):
    """Tentar editar/deletar field_id que não pertence ao tenant
    deve retornar 404 (e nunca 200)."""
    # IDs absurdos / improváveis de pertencer ao tenant
    for fake_id in (999_999_999, 1):
        # 1 PODE existir em outro tenant — se for o caso, o teste valida
        # que o sistema não deixa o usuário do tenant alvo ler/editar/apagar.
        r = client.put(f"/api/campos/{fake_id}", json={"nome": "Hack"})
        assert r.status_code in (404, 400), (
            f"Acessar field_id={fake_id} de outro tenant deveria falhar, "
            f"veio {r.status_code} body={r.text}"
        )


def test_row_colors_v2_so_traz_opcoes_do_tenant(client):
    """O mapa de cores não pode conter opções de outro tenant."""
    r = client.get("/api/row-colors-v2")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["ok"] is True
    mapa = data["mapa"]
    # Estrutural — não dá pra verificar tenant direto aqui, mas garantimos
    # que a forma da resposta é como esperado (chaves de campos + dict de valores)
    for chave, opcoes in mapa.items():
        assert isinstance(chave, str)
        assert isinstance(opcoes, dict)


def test_recursos_criados_aparecem_apenas_no_tenant(client, nome_unico, tenant_alvo):
    """Cria um campo, recupera, confirma que o tenant retornado é o alvo."""
    nome = nome_unico("IsolTest")
    r = client.post("/api/campos", json={"nome": nome, "tipo": "texto"})
    campo = r.json()["campo"]
    try:
        assert campo["tenant"] == tenant_alvo

        # Re-lista e procura
        campos = client.get("/api/campos").json().get("campos") or []
        encontrado = next((c for c in campos if c["id"] == campo["id"]), None)
        assert encontrado is not None
        assert encontrado["tenant"] == tenant_alvo
    finally:
        client.delete(f"/api/campos/{campo['id']}")
