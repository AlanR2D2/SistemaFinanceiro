"""
Backup das tabelas afetadas pela migration 05 (custom_fields).

USO:
    python backup_pre_migration_05.py

Saída:
    backups/pre_migration_05_<timestamp>/<tabela>.json   (uma por tabela)
    backups/pre_migration_05_<timestamp>/_resumo.json    (metadados)

Em caso de problema com a migration, dá para restaurar manualmente
re-inserindo as linhas via SQL Editor do Supabase ou via bulk_insert().

Tabelas incluídas no backup:
    - fin_acordos                (será alterada: nova coluna valores_custom)
    - fin_mandados               (será alterada: nova coluna valores_custom)
    - fin_campos_config          (será alterada: nova coluna ordem)
    - fin_status                 (origem do seed; não alterada)
    - fin_local                  (origem do seed; não alterada)
    - fin_conta                  (origem do seed; não alterada)
    - fin_reu                    (origem do seed; não alterada)
    - fin_uf                     (origem do seed; não alterada)
    - fin_patrono_reu            (origem do seed; não alterada)
    - fin_prazo_estimado         (origem do seed; não alterada)
    - fin_tenants                (referência para o seed)
    - fin_users                  (precaução)

Observação: a migration é 100% aditiva — não altera linhas existentes.
Este backup serve como rede de segurança caso algo dê errado.
"""

import json
import os
import sys
from datetime import datetime

from supabase_client import get_supabase_client, _sanitize_json


TABELAS_BACKUP = [
    "fin_acordos",
    "fin_mandados",
    "fin_campos_config",
    "fin_status",
    "fin_local",
    "fin_conta",
    "fin_reu",
    "fin_uf",
    "fin_patrono_reu",
    "fin_prazo_estimado",
    "fin_tenants",
    "fin_users",
]

# Limite por consulta (Supabase tem teto de 1000 por padrão; usamos paginação manual).
PAGE_SIZE = 1000


def _fetch_all(sb, table_name: str) -> list[dict]:
    """Lê TODAS as linhas da tabela paginando de PAGE_SIZE em PAGE_SIZE."""
    rows: list[dict] = []
    page = 0
    while True:
        start = page * PAGE_SIZE
        end = start + PAGE_SIZE - 1
        res = sb.table(table_name).select("*").range(start, end).execute()
        data = getattr(res, "data", None) or []
        if not data:
            break
        rows.extend(data)
        if len(data) < PAGE_SIZE:
            break
        page += 1
    return rows


def main() -> int:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join("backups", f"pre_migration_05_{ts}")
    os.makedirs(out_dir, exist_ok=True)

    print(f"[backup] destino: {out_dir}")

    try:
        sb = get_supabase_client()
    except Exception as e:
        print(f"[ERRO] Falha ao conectar no Supabase: {e}", file=sys.stderr)
        return 1

    resumo = {
        "timestamp": ts,
        "tabelas": {},
        "erros": [],
    }

    for tabela in TABELAS_BACKUP:
        try:
            print(f"[backup] {tabela} ...", end="", flush=True)
            rows = _fetch_all(sb, tabela)
            destino = os.path.join(out_dir, f"{tabela}.json")
            with open(destino, "w", encoding="utf-8") as fh:
                json.dump(_sanitize_json(rows), fh, ensure_ascii=False, indent=2)
            print(f" {len(rows)} linhas")
            resumo["tabelas"][tabela] = {"linhas": len(rows), "arquivo": destino}
        except Exception as e:
            msg = f"Falha ao exportar '{tabela}': {e}"
            print(f"\n[ERRO] {msg}", file=sys.stderr)
            resumo["erros"].append({"tabela": tabela, "erro": str(e)})

    resumo_path = os.path.join(out_dir, "_resumo.json")
    with open(resumo_path, "w", encoding="utf-8") as fh:
        json.dump(resumo, fh, ensure_ascii=False, indent=2)

    total = sum(t["linhas"] for t in resumo["tabelas"].values())
    print(f"\n[backup] concluído — {total} linhas em {len(resumo['tabelas'])} tabela(s).")
    print(f"[backup] resumo: {resumo_path}")

    if resumo["erros"]:
        print(f"[backup] ATENÇÃO: {len(resumo['erros'])} erro(s). Veja _resumo.json.")
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
