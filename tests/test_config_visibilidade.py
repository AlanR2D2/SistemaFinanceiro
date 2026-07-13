# -*- coding: utf-8 -*-
"""
Lógica pura (sem banco) de visibilidade/label de colunas por tenant.
Faz monkeypatch dos helpers de dados. Verifica:
  - _config_campos_tabela: visibilidade lida do escopo base p/ qualquer coluna.
  - _build_ordem_colunas: escopo base é autoritativo na visibilidade.
  - Isolamento entre tenants: config de um tenant NÃO vaza para outro.
"""
import sys, io, os
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app

PASS = 0; FAIL = 0
def check(cond, msg):
    global PASS, FAIL
    if cond: PASS += 1; print("  ok  -", msg)
    else: FAIL += 1; print("  FAIL -", msg)

FAKE_ROWS = {
    ("empresa_a", "acordos"): [
        {"chave": "reu", "label": "PARTE RÉ", "visivel": 0, "valor": None, "ordem": None},
        {"chave": "valor_acordo", "label": "", "visivel": 0, "valor": None, "ordem": None},
        {"chave": "campo_x", "label": "", "visivel": 0, "valor": None, "ordem": None},
    ],
    ("empresa_a", "ordem_acordos"): [
        {"chave": "status", "label": None, "visivel": 1, "valor": None, "ordem": 1},
    ],
}
app._campos_config_rows = lambda tenant, escopo: list(FAKE_ROWS.get((tenant, escopo), []))
def _fake_cf(tenant):
    if tenant == "empresa_a":
        return [{"chave": "campo_x", "nome": "Campo X", "ativo": 1,
                 "escopo_acordos": 1, "escopo_mandados": 0, "ordem": 1}]
    return []
app._list_custom_fields = _fake_cf

print("\n[1] _config_campos_tabela — Tenant A (colunas ocultas)")
cfgA = app._config_campos_tabela("empresa_a", "acordos")
check(cfgA["visiveis"].get("reu") == 0, "'reu' oculto para A")
check(cfgA["visiveis"].get("valor_acordo") == 0, "'valor_acordo' oculto para A")
check(cfgA["visiveis"].get("campo_x") == 0, "campo personalizado oculto para A")
check(cfgA["visiveis"].get("status") == 1, "'status' visível para A")
check(cfgA["labels"].get("reu") == "PARTE RÉ", "label custom de 'reu' aplicado")

print("\n[2] Tenant B (sem config) NÃO herda A")
cfgB = app._config_campos_tabela("empresa_b", "acordos")
check(cfgB["visiveis"].get("reu") == 1, "'reu' visível para B (isolado)")
check("campo_x" not in cfgB["visiveis"], "campo_x de A ausente em B")
check(cfgB["labels"].get("reu") == "RÉU", "label padrão para B")

print("\n[3] _build_ordem_colunas — A: base autoritativo")
colsA = {c["chave"]: c for c in app._build_ordem_colunas("empresa_a", "acordos")}
check(colsA["reu"]["visivel"] == 0, "'reu' visivel=0")
check(colsA["status"]["visivel"] == 1, "'status' visivel=1")
check(colsA["campo_x"]["visivel"] == 0, "campo personalizado oculto")

print("\n[4] _build_ordem_colunas — B: tudo visível")
colsB = {c["chave"]: c for c in app._build_ordem_colunas("empresa_b", "acordos")}
check(all(c["visivel"] == 1 for c in colsB.values()), "todas visíveis para B")
check("campo_x" not in colsB, "campo_x de A ausente em B")

print("\n[5] Isolamento por escopo (mandados de A não herdam acordos)")
check(app._config_campos_tabela("empresa_a", "mandados")["visiveis"].get("reu") == 1,
      "'reu' visível em mandados")

print(f"\n=== {PASS} passaram, {FAIL} falharam ===")
sys.exit(1 if FAIL else 0)
