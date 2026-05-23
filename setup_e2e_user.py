"""
Cria (ou repõe a senha de) um usuário admin descartável no tenant
'Lara's Company' para a suite E2E rodar, e grava o .env.test com as
credenciais.

USO:
    python setup_e2e_user.py

Idempotente: pode rodar várias vezes — sempre repõe a senha com um
valor novo e atualiza o .env.test.

Características intencionais:
  - Senha aleatória de 24 chars, escrita SÓ no .env.test (local, não-versionado).
  - Usuário pertence APENAS ao tenant Lara's Company.
  - Hierarquia = admin (necessário para usar /api/campos).
"""

import os
import secrets
import string
import sys

from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

from supabase_client import get_supabase_client


TENANT_ALVO = "Lara's Company"
LOGIN_E2E = "e2e_runner"
NOME_E2E = "E2E Runner (descartável)"
EMAIL_E2E = "e2e+runner@local.test"


def _senha_aleatoria(n: int = 24) -> str:
    alfa = string.ascii_letters + string.digits
    return "".join(secrets.choice(alfa) for _ in range(n))


def main() -> int:
    load_dotenv()  # lê .env (mesmas creds do app)
    sb = get_supabase_client()

    # 1) Confirma que o tenant existe
    r = sb.table("fin_tenants").select("nome,ativo").eq("nome", TENANT_ALVO).limit(1).execute()
    if not (getattr(r, "data", None) or []):
        print(f"[ERRO] Tenant '{TENANT_ALVO}' não existe em fin_tenants.", file=sys.stderr)
        return 1
    if int(r.data[0].get("ativo") or 0) != 1:
        print(f"[ERRO] Tenant '{TENANT_ALVO}' está inativo.", file=sys.stderr)
        return 1

    print(f"[ok] tenant '{TENANT_ALVO}' encontrado e ativo")

    # 2) Verifica se o usuário já existe
    senha = _senha_aleatoria()
    senha_hash = generate_password_hash(senha)
    agora = None  # supabase preenche updated_at

    r = sb.table("fin_users").select("*").eq("login", LOGIN_E2E).limit(1).execute()
    existente = (getattr(r, "data", None) or [])

    if existente:
        usr = existente[0]
        if (usr.get("tenant") or "").strip() != TENANT_ALVO:
            print(
                f"[ERRO] Usuário '{LOGIN_E2E}' existe mas pertence ao tenant "
                f"'{usr.get('tenant')}'. Recuso atualizar para não bagunçar.",
                file=sys.stderr,
            )
            return 2
        sb.table("fin_users").update({
            "senha": senha_hash,
            "hierarquia": "admin",
        }).eq("login", LOGIN_E2E).execute()
        print(f"[ok] senha do usuário existente '{LOGIN_E2E}' atualizada")
    else:
        sb.table("fin_users").insert({
            "login": LOGIN_E2E,
            "senha": senha_hash,
            "nome": NOME_E2E,
            "email": EMAIL_E2E,
            "hierarquia": "admin",
            "tenant": TENANT_ALVO,
        }).execute()
        print(f"[ok] usuário '{LOGIN_E2E}' criado em '{TENANT_ALVO}' (admin)")

    # 3) Grava .env.test
    env_test_path = os.path.join(os.path.dirname(__file__), ".env.test")
    contents = f"""# Gerado por setup_e2e_user.py — não versionar.
TEST_BASE_URL=http://localhost:5001
TEST_USER_LOGIN={LOGIN_E2E}
TEST_USER_PASSWORD={senha}
TEST_TENANT_NAME={TENANT_ALVO}
TEST_RESOURCE_PREFIX=__E2E__
"""
    with open(env_test_path, "w", encoding="utf-8") as f:
        f.write(contents)
    print(f"[ok] .env.test gravado em {env_test_path}")
    print(f"     login={LOGIN_E2E}  tenant={TENANT_ALVO}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
