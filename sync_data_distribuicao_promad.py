"""
Sincroniza a coluna personalizada "Data da distribuição" (chave cf_1) do
tenant "Dra Consumidor" a partir do arquivo promad.xlsx (raiz do projeto).

- Lê a coluna "Número do Processo" e "Data Distribuição" do Excel.
- Normaliza o número do processo (apenas dígitos: remove pontos, traços, espaços).
- Para cada registro de fin_acordos e fin_mandados do tenant "Dra Consumidor",
  faz match por número normalizado. Em caso de match, grava a data em
  valores_custom["cf_1"] (mesclando com o JSONB existente — não sobrescreve
  outros campos personalizados).
- Datas vazias / inválidas no Excel são ignoradas (registro não atualizado).
- Duplicatas no Excel: mantém a primeira ocorrência e avisa.

Uso:
    # Dry run (padrão) — só mostra resumo, não altera o banco
    python sync_data_distribuicao_promad.py

    # Executa as atualizações
    python sync_data_distribuicao_promad.py --apply
"""

import argparse
import re
import sys
from pathlib import Path
from datetime import date, datetime

import pandas as pd

from supabase_client import get_supabase_client


# ===================== Configuração =====================

TENANT = "Dra Consumidor"
FIELD_CHAVE = "cf_1"  # campo "Data da distribuição"
XLSX_PATH = Path(__file__).parent / "promad.xlsx"

# Nomes "lógicos" das colunas que precisamos. A planilha vem com codificação
# Latin-1 (vimos chars como 'N�mero' por erro de leitura), então fazemos
# match tolerante por contém-substring, sem acentos.
NEEDED = {
    "numero_processo": ("numero", "processo"),       # "Número do Processo"
    "data_distribuicao": ("data", "distribui"),      # "Data Distribuição"
}

BATCH_PRINT = 500  # de quanto em quanto loga progresso


# ===================== Helpers =====================

def _norm_text(s: str) -> str:
    """Normaliza para match tolerante (lower, sem acentos/cedilha simples)."""
    s = (s or "").lower()
    repl = {
        "á": "a", "à": "a", "ã": "a", "â": "a",
        "é": "e", "ê": "e",
        "í": "i",
        "ó": "o", "ô": "o", "õ": "o",
        "ú": "u",
        "ç": "c",
        "�": "",  # placeholder de char ilegível
    }
    for k, v in repl.items():
        s = s.replace(k, v)
    return s


def _find_column(df_columns, needle_parts: tuple[str, ...]) -> str | None:
    """Encontra a primeira coluna cujo nome normalizado contém todas as partes."""
    for c in df_columns:
        cn = _norm_text(str(c))
        if all(p in cn for p in needle_parts):
            return c
    return None


def _only_digits(s) -> str:
    """Remove tudo que não é dígito. None/NaN → ''."""
    if s is None:
        return ""
    if isinstance(s, float) and pd.isna(s):
        return ""
    return re.sub(r"\D+", "", str(s))


def _to_iso_date(v) -> str | None:
    """
    Converte v (str, Timestamp, date, datetime, etc.) para 'YYYY-MM-DD'.
    Retorna None se vazio/ inválido.
    """
    if v is None:
        return None
    if isinstance(v, float) and pd.isna(v):
        return None
    if isinstance(v, (datetime, date)):
        return v.strftime("%Y-%m-%d")
    if isinstance(v, pd.Timestamp):
        if pd.isna(v):
            return None
        return v.strftime("%Y-%m-%d")

    s = str(v).strip()
    if not s or s.lower() in ("nan", "nat", "none"):
        return None

    # ISO já vem pronto
    m_iso = re.match(r"^(\d{4})-(\d{2})-(\d{2})", s)
    if m_iso:
        return f"{m_iso.group(1)}-{m_iso.group(2)}-{m_iso.group(3)}"

    # BR dd/mm/yyyy
    m_br = re.match(r"^(\d{2})/(\d{2})/(\d{4})", s)
    if m_br:
        return f"{m_br.group(3)}-{m_br.group(2)}-{m_br.group(1)}"

    # Fallback genérico via pandas
    try:
        ts = pd.to_datetime(s, dayfirst=True, errors="coerce")
        if pd.isna(ts):
            return None
        return ts.strftime("%Y-%m-%d")
    except Exception:
        return None


# ===================== Pipeline =====================

def load_xlsx() -> dict[str, str]:
    """
    Devolve {numero_processo_normalizado: data_iso}.
    Em caso de duplicata, mantém a primeira ocorrência e avisa.
    """
    if not XLSX_PATH.exists():
        print(f"ERRO: arquivo não encontrado: {XLSX_PATH}", file=sys.stderr)
        sys.exit(2)

    print(f"Lendo {XLSX_PATH} ...")
    df = pd.read_excel(XLSX_PATH)
    print(f"Linhas lidas: {len(df)}")

    col_num = _find_column(df.columns, NEEDED["numero_processo"])
    col_dt = _find_column(df.columns, NEEDED["data_distribuicao"])

    if not col_num:
        print(f"ERRO: coluna 'Número do Processo' não encontrada. Colunas: {list(df.columns)}", file=sys.stderr)
        sys.exit(2)
    if not col_dt:
        print(f"ERRO: coluna 'Data Distribuição' não encontrada. Colunas: {list(df.columns)}", file=sys.stderr)
        sys.exit(2)

    print(f"Coluna número: {col_num!r}")
    print(f"Coluna data:   {col_dt!r}")

    mapping: dict[str, str] = {}
    dups = 0
    vazios_data = 0
    vazios_num = 0
    invalidos_data = 0

    for _, row in df.iterrows():
        num = _only_digits(row[col_num])
        if not num:
            vazios_num += 1
            continue

        raw_dt = row[col_dt]
        if raw_dt is None or (isinstance(raw_dt, float) and pd.isna(raw_dt)):
            vazios_data += 1
            continue

        iso = _to_iso_date(raw_dt)
        if not iso:
            invalidos_data += 1
            continue

        if num in mapping:
            dups += 1
            # mantém o primeiro
            continue
        mapping[num] = iso

    print(f"Sem número de processo:        {vazios_num}")
    print(f"Sem data de distribuição:      {vazios_data}")
    print(f"Data inválida (não parseável): {invalidos_data}")
    print(f"Duplicatas no Excel:           {dups} (mantida a primeira)")
    print(f"Mapeamento util (num->data):   {len(mapping)}")
    return mapping


def fetch_tenant_rows(sb, table: str) -> list[dict]:
    """Carrega id, numero_processo e valores_custom do tenant em uma só leitura paginada."""
    rows: list[dict] = []
    page_size = 1000
    start = 0
    while True:
        end = start + page_size - 1
        res = (
            sb.table(table)
            .select("id,numero_processo,valores_custom")
            .eq("tenant", TENANT)
            .range(start, end)
            .execute()
        )
        chunk = res.data or []
        rows.extend(chunk)
        if len(chunk) < page_size:
            break
        start += page_size
    return rows


def plan_updates(rows: list[dict], mapping: dict[str, str]) -> tuple[list[dict], int, int]:
    """
    Devolve (updates, ja_iguais, sem_match) para uma tabela.
    Cada update = {"id":..., "valores_custom": <novo dict>}.
    Só inclui updates onde o valor atual difere do desejado.
    """
    updates: list[dict] = []
    ja_iguais = 0
    sem_match = 0
    for r in rows:
        num_norm = _only_digits(r.get("numero_processo"))
        if not num_norm:
            sem_match += 1
            continue
        iso = mapping.get(num_norm)
        if not iso:
            sem_match += 1
            continue

        vc = r.get("valores_custom") or {}
        if not isinstance(vc, dict):
            vc = {}
        atual = vc.get(FIELD_CHAVE)
        if atual == iso:
            ja_iguais += 1
            continue

        novo = dict(vc)
        novo[FIELD_CHAVE] = iso
        updates.append({"id": r["id"], "valores_custom": novo,
                        "_numero": r.get("numero_processo"),
                        "_de": atual, "_para": iso})
    return updates, ja_iguais, sem_match


def apply_updates(sb, table: str, updates: list[dict]) -> int:
    """Aplica updates um a um. Retorna quantos foram aplicados."""
    aplicados = 0
    for i, u in enumerate(updates, 1):
        payload = {"valores_custom": u["valores_custom"]}
        try:
            res = sb.table(table).update(payload).eq("id", u["id"]).execute()
            if getattr(res, "data", None) is not None:
                aplicados += 1
        except Exception as e:
            print(f"  ! erro id={u['id']} ({table}): {e}")
        if i % BATCH_PRINT == 0:
            print(f"  ... {i}/{len(updates)} aplicados em {table}")
    return aplicados


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--apply", action="store_true",
                    help="Aplica as atualizações no banco. Sem essa flag, só mostra resumo (dry-run).")
    ap.add_argument("--sample", type=int, default=10,
                    help="Quantos exemplos de update mostrar no dry-run (default: 10).")
    args = ap.parse_args()

    mapping = load_xlsx()
    if not mapping:
        print("Nada a sincronizar (mapeamento vazio).")
        return

    sb = get_supabase_client()

    print(f"\nBuscando registros do tenant {TENANT!r} ...")
    acordos = fetch_tenant_rows(sb, "fin_acordos")
    mandados = fetch_tenant_rows(sb, "fin_mandados")
    print(f"  fin_acordos:  {len(acordos)} registros")
    print(f"  fin_mandados: {len(mandados)} registros")

    upd_a, eq_a, miss_a = plan_updates(acordos, mapping)
    upd_m, eq_m, miss_m = plan_updates(mandados, mapping)

    print("\n========== RESUMO ==========")
    print(f"Tenant: {TENANT}")
    print(f"Campo:  {FIELD_CHAVE} (Data da distribuição)")
    print(f"--- fin_acordos ---")
    print(f"  atualizar:  {len(upd_a)}")
    print(f"  já iguais:  {eq_a}")
    print(f"  sem match:  {miss_a}")
    print(f"--- fin_mandados ---")
    print(f"  atualizar:  {len(upd_m)}")
    print(f"  já iguais:  {eq_m}")
    print(f"  sem match:  {miss_m}")

    if args.sample > 0 and (upd_a or upd_m):
        print(f"\nExemplos de updates (primeiros {args.sample}):")
        amostras = (upd_a + upd_m)[: args.sample]
        for u in amostras:
            print(f"  proc={u['_numero']!r:40s}  {u['_de']!r}  ->  {u['_para']!r}")

    if not args.apply:
        print("\n[DRY-RUN] Nada foi alterado. Use --apply para executar.")
        return

    if not (upd_a or upd_m):
        print("\nNada a aplicar.")
        return

    print("\nAplicando atualizações...")
    a = apply_updates(sb, "fin_acordos", upd_a)
    m = apply_updates(sb, "fin_mandados", upd_m)
    print(f"\nConcluído. fin_acordos: {a}/{len(upd_a)} | fin_mandados: {m}/{len(upd_m)}")


if __name__ == "__main__":
    main()
