# supabase_client.py
import os
import math
from typing import Any
from datetime import date, datetime

from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")


def get_supabase_client() -> Client:
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise RuntimeError(
            "Credenciais do Supabase não configuradas no .env "
            "(SUPABASE_URL / SUPABASE_KEY)."
        )
    return create_client(SUPABASE_URL, SUPABASE_KEY)


def _sanitize_json(obj: Any) -> Any:
    """
    Torna qualquer objeto JSON-serializável:
    - NaN / Inf -> None
    - date / datetime -> ISO string (YYYY-MM-DD / YYYY-MM-DDTHH:MM:SS)
    """
    if isinstance(obj, dict):
        return {k: _sanitize_json(v) for k, v in obj.items()}

    if isinstance(obj, list):
        return [_sanitize_json(v) for v in obj]

    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            return None
        return obj

    if isinstance(obj, (date, datetime)):
        return obj.isoformat()

    return obj


def delete_all(table_name: str, candidates: list[str] | None = None) -> None:
    """
    Deleta TODOS os registros da tabela.
    PostgREST exige WHERE, então usamos um filtro que pega todas as linhas:
    col != "__never__"
    """
    sb = get_supabase_client()
    candidates = candidates or ["id", "numero_processo", "created_at"]

    last_err = None
    for col in candidates:
        try:
            sb.table(table_name).delete().neq(col, "__never__").execute()
            return
        except Exception as e:
            last_err = e

    raise RuntimeError(
        f"Não consegui deletar tudo de '{table_name}'. "
        f"Nenhuma das colunas candidatas funcionou: {candidates}. "
        f"Erro: {last_err}"
    )


def bulk_insert(table_name: str, rows: list[dict], chunk_size: int = 300) -> None:
    """
    Inserção em chunks + sanitização total do payload.
    """
    if not rows:
        return

    sb = get_supabase_client()

    for i in range(0, len(rows), chunk_size):
        chunk = rows[i:i + chunk_size]
        chunk = _sanitize_json(chunk)
        sb.table(table_name).insert(chunk).execute()
