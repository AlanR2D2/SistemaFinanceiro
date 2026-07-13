# -*- coding: utf-8 -*-
"""
Smoke test HTTP (Flask test client + Supabase real) com sessão admin mockada.
  - Telas autenticadas retornam 200 (sem 500).
  - API ordem-colunas expõe 'visivel' por coluna.
  - Filtro server-side (/api/acordos com filters) retorna 200/ok.
  - Rota protegida sem login redireciona (302), não 500.

Requer as variáveis do .env (conexão Supabase). Rode com o ambiente conda
'sistema_financeiro'. Tenant de teste: TENANT (default 'Dra Consumidor').
"""
import sys, io, os, base64, json
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app

TENANT = os.environ.get("TENANT_TESTE", "Dra Consumidor")
PASS = 0; FAIL = 0
def check(cond, msg):
    global PASS, FAIL
    if cond: PASS += 1; print("  ok  -", msg)
    else: FAIL += 1; print("  FAIL -", msg)

_orig = app._get_user_by_login
FAKE = {"login": "smoketest", "nome": "Smoke", "hierarquia": "admin",
        "tenant": TENANT, "email": "s@x.com"}
app._get_user_by_login = lambda login: dict(FAKE) if login == "smoketest" else _orig(login)

client = app.app.test_client()
with client.session_transaction() as sess:
    sess["_user_id"] = "smoketest"; sess["_fresh"] = True; sess["tenant"] = TENANT

PAGINAS = [
    ("/", "dashboard"), ("/acordos/ativos", "acordos ativos"),
    ("/acordos/finalizados", "acordos finalizados"),
    ("/mandados/ativos", "mandados ativos"),
    ("/mandados/finalizados", "mandados finalizados"),
    ("/cadastros", "cadastros"), ("/config", "config"),
    ("/users", "usuários"), ("/admin/ordem-colunas", "ordenar colunas"),
]
print("\n[1] Telas autenticadas -> 200")
for url, nome in PAGINAS:
    try:
        r = client.get(url)
        check(r.status_code == 200, f"{nome} ({url}) -> {r.status_code}")
    except Exception as e:
        check(False, f"{nome} ({url}) EXCEPTION: {e}")

print("\n[2] API ordem-colunas expõe 'visivel'")
for esc in ("acordos", "mandados"):
    r = client.get(f"/api/ordem-colunas/{esc}")
    j = r.get_json() if r.status_code == 200 else {}
    cols = (j or {}).get("colunas", [])
    check(r.status_code == 200 and j.get("ok"), f"/api/ordem-colunas/{esc} -> 200/ok")
    check(bool(cols) and all("visivel" in c for c in cols), f"colunas de {esc} têm 'visivel'")

print("\n[3] Filtro server-side (/api/acordos com filters)")
filtro = {"status": {"type": "set", "values": ["FINALIZADO"], "include_blank": False}}
raw = base64.urlsafe_b64encode(json.dumps(filtro).encode()).decode().rstrip("=")
r = client.get(f"/api/acordos?finalizado=1&page=1&page_size=20&totals=1&filters={raw}")
j = r.get_json() if r.status_code == 200 else {}
check(r.status_code == 200 and j.get("ok"), f"/api/acordos com filtro -> {r.status_code}")
if j.get("ok"):
    fc, tc = j.get("filtered_count"), j.get("total_count")
    check(isinstance(j.get("rows"), list), "retornou lista de rows")
    check(fc is None or tc is None or fc <= tc, f"filtered_count({fc}) <= total_count({tc})")

print("\n[4] Baseline sem filtro -> 200")
r = client.get("/api/mandados?finalizado=0&page=1&page_size=20")
check(r.status_code == 200 and (r.get_json() or {}).get("ok"), f"/api/mandados -> {r.status_code}")

print("\n[5] Rota protegida sem login -> 302")
check(app.app.test_client().get("/admin/ordem-colunas").status_code in (301, 302),
      "redirect p/ login sem sessão")

print(f"\n=== {PASS} passaram, {FAIL} falharam ===")
sys.exit(1 if FAIL else 0)
