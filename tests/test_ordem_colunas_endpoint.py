# -*- coding: utf-8 -*-
"""
PUT /api/ordem-colunas/<escopo> — persiste visivel+label no escopo base,
grava ordem no escopo de ordem e responde 200/ok. Auth e banco mockados.
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

class _Q:
    def table(s,n): return s
    def select(s,*a,**k): return s
    def insert(s,*a,**k): return s
    def update(s,*a,**k): return s
    def eq(s,*a,**k): return s
    def neq(s,*a,**k): return s
    def limit(s,*a,**k): return s
    def order(s,*a,**k): return s
    def execute(s):
        class R: data=[]
        return R()
app.supabase = _Q()
app.require_admin = lambda: None
app._get_tenant = lambda: "empresa_a"

capturado = []
app._upsert_campo_config = lambda tenant, escopo, chave, label=None, valor=None, visivel=None: \
    capturado.append({"tenant":tenant,"escopo":escopo,"chave":chave,"label":label,"visivel":visivel})

app.app.config["LOGIN_DISABLED"] = True
client = app.app.test_client()

payload = {"ordem": [
    {"chave": "data_acordo", "label": "DATA", "visivel": 1},
    {"chave": "reu", "label": "PARTE RÉ", "visivel": 0},
    {"chave": "valor_acordo", "label": "", "visivel": 0},
    {"chave": "status", "label": "STATUS", "visivel": 1},
]}

print("\n[1] PUT /api/ordem-colunas/acordos")
r = client.put("/api/ordem-colunas/acordos", json=payload)
check(r.status_code == 200 and r.get_json().get("ok") is True, f"200/ok (foi {r.status_code})")

by = {c["chave"]: c for c in capturado}
print("\n[2] Visibilidade+label no escopo base")
check(all(c["escopo"] == "acordos" for c in capturado), "gravado no escopo base")
check(all(c["tenant"] == "empresa_a" for c in capturado), "tenant correto")
check(by["reu"]["visivel"] == 0 and by["valor_acordo"]["visivel"] == 0, "colunas marcadas ocultas")
check(by["data_acordo"]["visivel"] == 1 and by["status"]["visivel"] == 1, "colunas marcadas visíveis")
check(by["reu"]["label"] == "PARTE RÉ" and by["valor_acordo"]["label"] == "", "labels persistidos (inclui reset)")

print("\n[3] Escopo inválido -> 400")
check(client.put("/api/ordem-colunas/xpto", json=payload).status_code == 400, "400 em escopo inválido")

print(f"\n=== {PASS} passaram, {FAIL} falharam ===")
sys.exit(1 if FAIL else 0)
