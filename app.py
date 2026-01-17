# app.py
import os
import re
from decimal import Decimal, InvalidOperation
from datetime import date, datetime
from collections import Counter

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, jsonify, abort, send_from_directory
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import check_password_hash, generate_password_hash
from supabase import create_client, Client

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip().strip("'").strip('"')
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "").strip().strip("'").strip('"')

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Configure SUPABASE_URL e SUPABASE_KEY no .env")

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

TABLE_USERS = "fin_users"
TABLE_ACORDOS = "fin_acordos"
TABLE_MANDADOS = "fin_mandados"

# ===================== AUTH =====================

class User(UserMixin):
    def __init__(self, data: dict):
        self.data = data or {}
        # Flask-Login usa self.id internamente
        self.id = str(self.data.get("login", ""))

    @property
    def login(self): return self.data.get("login")

    @property
    def nome(self): return self.data.get("nome")

    @property
    def hierarquia(self): return self.data.get("hierarquia")

    @property
    def email(self): return self.data.get("email")

    # ✅ COMPATIBILIDADE COM SEUS TEMPLATES:
    # Alguns templates estão verificando current_user.role == "admin".
    # No seu banco/código, o campo é "hierarquia".
    @property
    def role(self):
        return (self.data.get("hierarquia") or "").strip().lower()

    @property
    def is_admin(self):
        return self.role == "admin"


@app.context_processor
def inject_user_flags():
    """
    ✅ Disponibiliza no Jinja:
      - is_admin: bool
      - user_role: string
    Assim você pode usar tanto:
      {% if current_user.role == "admin" %}  (vai funcionar)
    quanto:
      {% if is_admin %}  (mais limpo)
    """
    try:
        if current_user and current_user.is_authenticated:
            return {"is_admin": bool(getattr(current_user, "is_admin", False)),
                    "user_role": getattr(current_user, "role", "")}
    except Exception:
        pass
    return {"is_admin": False, "user_role": ""}


def _get_user_by_login(login: str) -> dict | None:
    login = (login or "").strip()
    if not login:
        return None
    res = supabase.table(TABLE_USERS).select("*").eq("login", login).limit(1).execute()
    rows = getattr(res, "data", None) or []
    return rows[0] if rows else None


def _is_hash(stored_password: str) -> bool:
    s = (stored_password or "").strip()
    return s.startswith(("pbkdf2:", "scrypt:", "argon2:"))


def _password_ok(raw_password: str, stored_password: str) -> bool:
    """
    Padrão: HASH.
    Compat: se ainda tiver senha em texto simples no banco, valida e depois migra pra hash.
    """
    raw_password = (raw_password or "").strip()
    stored_password = (stored_password or "").strip()
    if not raw_password or not stored_password:
        return False

    if _is_hash(stored_password):
        try:
            return check_password_hash(stored_password, raw_password)
        except Exception:
            return False


    # legado (texto simples)
    return raw_password == stored_password


def _hash_password(raw_password: str) -> str:
    raw_password = (raw_password or "").strip()
    return generate_password_hash(raw_password)


def _maybe_migrate_plain_password_to_hash(user_row: dict, raw_password_ok: bool):
    if not user_row or not raw_password_ok:
        return
    stored = (user_row.get("senha") or "").strip()
    if not stored or _is_hash(stored):
        return
    try:
        new_hash = _hash_password(stored)  # stored == senha em texto simples
        supabase.table(TABLE_USERS).update({"senha": new_hash}).eq("login", user_row["login"]).execute()
    except Exception:
        pass


@login_manager.user_loader
def load_user(user_id: str):
    data = _get_user_by_login(user_id)
    return User(data) if data else None


@app.get("/login")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.post("/login")
def login_post():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()

    user_data = _get_user_by_login(username)
    if not user_data:
        return render_template("login.html", error="Usuário ou senha inválidos.")

    ok = _password_ok(password, user_data.get("senha", ""))
    if not ok:
        return render_template("login.html", error="Usuário ou senha inválidos.")

    _maybe_migrate_plain_password_to_hash(user_data, ok)
    login_user(User(user_data))
    return redirect(url_for("dashboard"))


@app.get("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ===================== HELPERS =====================

def _norm(x):
    return (x or "").strip()


def br_to_iso_date(s: str | None) -> str | None:
    """
    Converte dd/mm/aaaa -> yyyy-mm-dd.
    Se vier vazio/None, retorna None.
    Se já estiver yyyy-mm-dd ou outro formato, retorna original.
    """
    if s is None:
        return None
    s = str(s).strip()
    if not s:
        return None

    try:
        if len(s) >= 10 and s[2] == "/" and s[5] == "/":
            d = datetime.strptime(s[:10], "%d/%m/%Y").date()
            return d.strftime("%Y-%m-%d")
    except Exception:
        pass

    return s


def iso_to_br_date(s: str | None) -> str | None:
    if s is None:
        return None
    s = str(s).strip()
    if not s:
        return None
    try:
        if len(s) >= 10 and s[4] == "-" and s[7] == "-":
            d = datetime.strptime(s[:10], "%Y-%m-%d").date()
            return d.strftime("%d/%m/%Y")
    except Exception:
        pass
    return s


def parse_numeric(v):
    """
    Aceita:
      - None / "" -> None
      - "1.234,56" -> 1234.56
      - "1234,56"  -> 1234.56
      - "1,234.56" -> 1234.56 (também tenta)
      - números -> float
    """
    if v is None:
        return None

    if isinstance(v, (int, float, Decimal)):
        try:
            return float(v)
        except Exception:
            return None

    s = str(v).strip()
    if s == "":
        return None

    s = s.replace(" ", "")
    s = re.sub(r"[^0-9\-,.]", "", s)
    if s in ("", "-", ",", ".", "-.", "-,"):
        return None

    if "," in s and "." in s:
        if s.rfind(",") > s.rfind("."):
            s = s.replace(".", "").replace(",", ".")
        else:
            s = s.replace(",", "")
    elif "," in s and "." not in s:
        s = s.replace(".", "").replace(",", ".")
    else:
        pass

    try:
        return float(Decimal(s))
    except (InvalidOperation, ValueError):
        return None


NUMERIC_FIELDS_ACORDOS = {"valor_acordo", "honorarios", "repasse", "sucumbencia"}
NUMERIC_FIELDS_MANDADOS = {"deposito", "correcao", "honorarios", "repasse", "sucumbencia"}


def clean_payload(payload: dict, numeric_fields: set[str]):
    """
    - converte "" -> None
    - parseia campos numéricos
    - remove chaves com None (não sobrescreve com null)
      Obs: se você quiser permitir limpar campo (setar NULL), aí NÃO remova None.
    """
    out = {}
    for k, v in (payload or {}).items():
        if isinstance(v, str) and v.strip() == "":
            v = None

        if k in numeric_fields:
            v = parse_numeric(v)

        if v is None:
            continue
        out[k] = v
    return out


# ========= REGRA: finalizado = 1 somente quando status for "FINALIZADO..." =========

def _status_text_from_payload(data: dict) -> str:
    """
    Prioriza SEMPRE o campo 'status' (texto exibido no sistema).
    Só usa 'status_id' como fallback caso 'status' não venha.
    """
    s = (data.get("status") or "").strip()
    if s:
        return s
    return (data.get("status_id") or "").strip()


def _derive_finalizado_from_status(status: str) -> int:
    s = (status or "").strip().upper()
    return 1 if s.startswith("FINALIZADO") else 0


def sb_select(table: str, columns="*", limit=300, order_col=None, desc=True, filters=None):
    q = supabase.table(table).select(columns)

    if filters:
        for (col, op, val) in filters:
            if val is None or val == "" or val == []:
                continue
            if op == "eq":
                q = q.eq(col, val)
            elif op == "ilike":
                q = q.ilike(col, f"*{val}*")
            elif op == "gte":
                q = q.gte(col, val)
            elif op == "lte":
                q = q.lte(col, val)
            elif op == "in":
                q = q.in_(col, val)

    if order_col:
        q = q.order(order_col, desc=desc)

    q = q.limit(limit)
    res = q.execute()
    return getattr(res, "data", None) or []


def sb_select_or_like(table: str, columns="*", limit=300, order_col=None, desc=True,
                      or_ilike_cols=None, qtext=None, extra_filters=None):
    query = supabase.table(table).select(columns)

    if qtext and or_ilike_cols:
        qtext = (qtext or "").strip()
        if qtext:
            parts = [f"{c}.ilike.*{qtext}*" for c in or_ilike_cols]
            query = query.or_(",".join(parts))

    if extra_filters:
        for (col, op, val) in extra_filters:
            if val is None or val == "" or val == []:
                continue
            if op == "eq":
                query = query.eq(col, val)
            elif op == "ilike":
                query = query.ilike(col, f"*{val}*")
            elif op == "gte":
                query = query.gte(col, val)
            elif op == "lte":
                query = query.lte(col, val)
            elif op == "in":
                query = query.in_(col, val)

    if order_col:
        query = query.order(order_col, desc=desc)

    query = query.limit(limit)
    res = query.execute()
    return getattr(res, "data", None) or []

# ===================== STATIC FIX (logo case-sensitive) =====================

@app.get("/static/images/logo.png")
def static_logo_lowercase_fix():
    """
    Linux diferencia Images vs images.
    Se o HTML pedir /static/images/logo.png mas o arquivo estiver em static/Images/logo.png, isso corrige.
    """
    lower_dir = os.path.join(app.root_path, "static", "images")
    upper_dir = os.path.join(app.root_path, "static", "Images")

    if os.path.exists(os.path.join(lower_dir, "logo.png")):
        return send_from_directory(lower_dir, "logo.png")
    return send_from_directory(upper_dir, "logo.png")

# ===================== DASHBOARD =====================

_PT_MONTHS = ["jan", "fev", "mar", "abr", "mai", "jun", "jul", "ago", "set", "out", "nov", "dez"]


def _to_month_key(dt_val) -> str | None:
    if not dt_val:
        return None

    if isinstance(dt_val, (datetime, date)):
        return f"{dt_val.year:04d}-{dt_val.month:02d}"

    s = str(dt_val).strip()
    if not s:
        return None

    try:
        d = datetime.fromisoformat(s.replace("Z", "")[:19]).date()
        return f"{d.year:04d}-{d.month:02d}"
    except Exception:
        pass

    try:
        d = datetime.strptime(s[:10], "%d/%m/%Y").date()
        return f"{d.year:04d}-{d.month:02d}"
    except Exception:
        return None


def _fmt_mmm_aa(yyyy_mm: str) -> str:
    try:
        y, m = yyyy_mm.split("-")
        mi = int(m)
        return f"{_PT_MONTHS[mi-1]}/{str(y)[-2:]}"
    except Exception:
        return yyyy_mm


def _month_counter_by_data_pagamento(rows: list[dict]):
    c = Counter()
    for r in rows:
        mk = _to_month_key(r.get("data_pagamento"))
        if mk:
            c[mk] += 1
    labels = sorted(c.keys())
    values = [c[l] for l in labels]
    labels_fmt = [_fmt_mmm_aa(l) for l in labels]
    return labels_fmt, values


def _kpis(rows: list[dict]):
    total = len(rows)
    pagos = sum(1 for r in rows if _to_month_key(r.get("data_pagamento")) is not None)
    sem_pag = total - pagos

    finalizados = sum(1 for r in rows if int(r.get("finalizado") or 0) == 1)
    ativos = total - finalizados

    return {"total": total, "pagos": pagos, "sem_pag": sem_pag, "ativos": ativos, "finalizados": finalizados}


def _top_counter(rows: list[dict], field: str):
    c = Counter()
    for r in rows:
        v = _norm(r.get(field))
        if v:
            c[v] += 1
    items = c.most_common()
    return [k for k, _ in items], [v for _, v in items]


def _all_distinct(rows1: list[dict], rows2: list[dict], field: str) -> list[str]:
    s = set()
    for rows in (rows1, rows2):
        for r in rows:
            v = _norm(r.get(field))
            if v:
                s.add(v)
    return sorted(s)


def _apply_multi_filter(rows: list[dict], field: str, selected: list[str]) -> list[dict]:
    if not selected:
        return rows

    wanted = set([_norm(x) for x in selected if x and _norm(x) and x != "__BLANK__"])
    want_blank = "__BLANK__" in selected

    if not wanted and not want_blank:
        return rows

    out = []
    for r in rows:
        v = _norm(r.get(field))
        if v:
            if v in wanted:
                out.append(r)
        else:
            if want_blank:
                out.append(r)
    return out


@app.get("/")
@login_required
def dashboard():
    selected_statuses = request.args.getlist("status")
    selected_ufs = request.args.getlist("uf")
    selected_reus = request.args.getlist("reu")

    cols = "uf, reu, status, data_pagamento, finalizado"
    acordos_all = sb_select(TABLE_ACORDOS, columns=cols, limit=50000)
    mandados_all = sb_select(TABLE_MANDADOS, columns=cols, limit=50000)

    status_options = _all_distinct(acordos_all, mandados_all, "status")
    uf_options = _all_distinct(acordos_all, mandados_all, "uf")
    reu_options = _all_distinct(acordos_all, mandados_all, "reu")

    acordos = _apply_multi_filter(acordos_all, "status", selected_statuses)
    mandados = _apply_multi_filter(mandados_all, "status", selected_statuses)

    acordos = _apply_multi_filter(acordos, "uf", selected_ufs)
    mandados = _apply_multi_filter(mandados, "uf", selected_ufs)

    acordos = _apply_multi_filter(acordos, "reu", selected_reus)
    mandados = _apply_multi_filter(mandados, "reu", selected_reus)

    kpis = {"acordos": _kpis(acordos), "mandados": _kpis(mandados)}

    ac_m_labels, ac_m_values = _month_counter_by_data_pagamento(acordos)
    md_m_labels, md_m_values = _month_counter_by_data_pagamento(mandados)

    ac_uf_labels, ac_uf_values = _top_counter(acordos, "uf")
    ac_reu_labels, ac_reu_values = _top_counter(acordos, "reu")
    ac_st_labels, ac_st_values = _top_counter(acordos, "status")

    md_uf_labels, md_uf_values = _top_counter(mandados, "uf")
    md_reu_labels, md_reu_values = _top_counter(mandados, "reu")
    md_st_labels, md_st_values = _top_counter(mandados, "status")

    charts = {
        "acordos": {
            "mes_labels": ac_m_labels, "mes_values": ac_m_values,
            "uf_labels": ac_uf_labels, "uf_values": ac_uf_values,
            "reu_labels": ac_reu_labels, "reu_values": ac_reu_values,
            "status_labels": ac_st_labels, "status_values": ac_st_values,
        },
        "mandados": {
            "mes_labels": md_m_labels, "mes_values": md_m_values,
            "uf_labels": md_uf_labels, "uf_values": md_uf_values,
            "reu_labels": md_reu_labels, "reu_values": md_reu_values,
            "status_labels": md_st_labels, "status_values": md_st_values,
        }
    }

    return render_template(
        "dashboard.html",
        charts=charts,
        kpis=kpis,
        status_options=status_options,
        uf_options=uf_options,
        reu_options=reu_options,
        selected_statuses=selected_statuses,
        selected_ufs=selected_ufs,
        selected_reus=selected_reus,
    )

# ===================== ACORDOS (LIST PAGES) =====================

def acordos_list(finalizado_value: int):
    return sb_select(
        TABLE_ACORDOS,
        columns="*",
        limit=5000,
        order_col="data_acordo",
        desc=True,
        filters=[("finalizado", "eq", int(finalizado_value))]
    )


@app.get("/acordos/ativos")
@login_required
def acordos_ativos_page():
    rows = acordos_list(finalizado_value=0)
    return render_template("acordos_ativos.html", rows=rows)


@app.get("/acordos/finalizados")
@login_required
def acordos_finalizados_page():
    rows = acordos_list(finalizado_value=1)
    return render_template("acordos_finalizados.html", rows=rows)


@app.get("/acordos")
@login_required
def acordos_redirect_to_ativos():
    return redirect(url_for("acordos_ativos_page"))

# ===================== ACORDOS (CRUD) =====================

@app.post("/acordos")
@login_required
def acordos_create():
    data = request.get_json(force=True) or {}
    status_txt = _status_text_from_payload(data)

    payload = {
        "data_acordo": br_to_iso_date(data.get("data_acordo")),
        "numero_processo": data.get("numero_processo"),
        "uf": data.get("uf_id") or data.get("uf"),
        "reu": data.get("reu"),
        "autor": data.get("autor"),
        "tel": data.get("tel"),
        "escritorio_reu": data.get("escritorio_reu"),
        "valor_acordo": data.get("valor_acordo"),
        "status": status_txt,
        "prazo_estimado": data.get("prazo_estimado"),
        "prazo_real": br_to_iso_date(data.get("prazo_real")),
        "data_pagamento": br_to_iso_date(data.get("data_pagamento")),
        "local": data.get("local"),
        "tipo": data.get("tipo"),
        "honorarios": data.get("honorarios"),
        "audiencista": data.get("audiencista"),
        "repasse": data.get("repasse"),
        "chave_pix": data.get("chave_pix"),
        "sucumbencia": data.get("sucumbencia"),
        "observacoes": data.get("observacoes"),
        "mes_pg": data.get("mes_pg"),
        "finalizado": _derive_finalizado_from_status(status_txt),
    }

    payload = clean_payload(payload, NUMERIC_FIELDS_ACORDOS)

    res = supabase.table(TABLE_ACORDOS).insert(payload).execute()
    if getattr(res, "data", None) is None:
        return jsonify({"ok": False, "error": "Falha ao inserir"}), 400
    return jsonify({"ok": True})


@app.put("/acordos/<int:acordo_id>")
@login_required
def acordos_update(acordo_id: int):
    data = request.get_json(force=True) or {}
    status_txt = _status_text_from_payload(data)

    payload = {
        "data_acordo": br_to_iso_date(data.get("data_acordo")),
        "numero_processo": data.get("numero_processo"),
        "uf": data.get("uf_id") or data.get("uf"),
        "reu": data.get("reu"),
        "autor": data.get("autor"),
        "tel": data.get("tel"),
        "escritorio_reu": data.get("escritorio_reu"),
        "valor_acordo": data.get("valor_acordo"),
        "status": status_txt,
        "prazo_estimado": data.get("prazo_estimado"),
        "prazo_real": br_to_iso_date(data.get("prazo_real")),
        "data_pagamento": br_to_iso_date(data.get("data_pagamento")),
        "local": data.get("local"),
        "tipo": data.get("tipo"),
        "honorarios": data.get("honorarios"),
        "audiencista": data.get("audiencista"),
        "repasse": data.get("repasse"),
        "chave_pix": data.get("chave_pix"),
        "sucumbencia": data.get("sucumbencia"),
        "observacoes": data.get("observacoes"),
        "mes_pg": data.get("mes_pg"),
        "finalizado": _derive_finalizado_from_status(status_txt),
    }

    payload = clean_payload(payload, NUMERIC_FIELDS_ACORDOS)

    res = supabase.table(TABLE_ACORDOS).update(payload).eq("id", acordo_id).execute()
    if getattr(res, "data", None) is None:
        return jsonify({"ok": False, "error": "Falha ao atualizar"}), 400
    return jsonify({"ok": True})


@app.delete("/acordos/<int:acordo_id>")
@login_required
def acordos_delete(acordo_id: int):
    res = supabase.table(TABLE_ACORDOS).delete().eq("id", acordo_id).execute()
    if getattr(res, "data", None) is None:
        return jsonify({"ok": False, "error": "Falha ao excluir"}), 400
    return jsonify({"ok": True})

# ===================== MANDADOS (LIST PAGES) =====================

def mandados_list(finalizado_value: int):
    return sb_select(
        TABLE_MANDADOS,
        columns="*",
        limit=5000,
        order_col="data_quitacao",
        desc=True,
        filters=[("finalizado", "eq", int(finalizado_value))]
    )


@app.get("/mandados/ativos")
@login_required
def mandados_ativos_page():
    rows = mandados_list(finalizado_value=0)
    return render_template("mandados_ativos.html", rows=rows)


@app.get("/mandados/finalizados")
@login_required
def mandados_finalizados_page():
    rows = mandados_list(finalizado_value=1)
    return render_template("mandados_finalizados.html", rows=rows)


@app.get("/mandados")
@login_required
def mandados_redirect_to_ativos():
    return redirect(url_for("mandados_ativos_page"))

# ===================== MANDADOS (CRUD) =====================

@app.post("/mandados")
@login_required
def mandados_create():
    data = request.get_json(force=True) or {}
    status_txt = _status_text_from_payload(data)

    payload = {
        "numero_processo": data.get("numero_processo"),
        "data_quitacao": br_to_iso_date(data.get("data_quitacao")),
        "uf": data.get("uf_id") or data.get("uf"),
        "reu": data.get("reu"),
        "autor": data.get("autor"),
        "tel": data.get("tel"),

        "sentenca": data.get("sentenca"),
        "quitacao": data.get("quitacao"),
        "status": status_txt,
        "previsao": data.get("previsao"),
        "data_pagamento": br_to_iso_date(data.get("data_pagamento")),
        "local": data.get("local"),
        "tipo": data.get("tipo"),

        "deposito": data.get("deposito"),
        "correcao": data.get("correcao"),
        "honorarios": data.get("honorarios"),
        "audiencista": data.get("audiencista"),
        "repasse": data.get("repasse"),

        "chave_pix": data.get("chave_pix"),
        "sucumbencia": data.get("sucumbencia"),
        "observacoes": data.get("observacoes"),
        "mes_pg": data.get("mes_pg"),

        "finalizado": _derive_finalizado_from_status(status_txt),
    }

    payload = clean_payload(payload, NUMERIC_FIELDS_MANDADOS)

    res = supabase.table(TABLE_MANDADOS).insert(payload).execute()
    if getattr(res, "data", None) is None:
        return jsonify({"ok": False, "error": "Falha ao inserir"}), 400
    return jsonify({"ok": True})


@app.put("/mandados/<int:mandado_id>")
@login_required
def mandados_update(mandado_id: int):
    data = request.get_json(force=True) or {}
    status_txt = _status_text_from_payload(data)

    payload = {
        "numero_processo": data.get("numero_processo"),
        "data_quitacao": br_to_iso_date(data.get("data_quitacao")),
        "uf": data.get("uf_id") or data.get("uf"),
        "reu": data.get("reu"),
        "autor": data.get("autor"),
        "tel": data.get("tel"),

        "sentenca": data.get("sentenca"),
        "quitacao": data.get("quitacao"),
        "status": status_txt,
        "previsao": data.get("previsao"),
        "data_pagamento": br_to_iso_date(data.get("data_pagamento")),
        "local": data.get("local"),
        "tipo": data.get("tipo"),

        "deposito": data.get("deposito"),
        "correcao": data.get("correcao"),
        "honorarios": data.get("honorarios"),
        "audiencista": data.get("audiencista"),
        "repasse": data.get("repasse"),

        "chave_pix": data.get("chave_pix"),
        "sucumbencia": data.get("sucumbencia"),
        "observacoes": data.get("observacoes"),
        "mes_pg": data.get("mes_pg"),

        "finalizado": _derive_finalizado_from_status(status_txt),
    }

    payload = clean_payload(payload, NUMERIC_FIELDS_MANDADOS)

    res = supabase.table(TABLE_MANDADOS).update(payload).eq("id", mandado_id).execute()
    if getattr(res, "data", None) is None:
        return jsonify({"ok": False, "error": "Falha ao atualizar"}), 400
    return jsonify({"ok": True})


@app.delete("/mandados/<int:mandado_id>")
@login_required
def mandados_delete(mandado_id: int):
    res = supabase.table(TABLE_MANDADOS).delete().eq("id", mandado_id).execute()
    if getattr(res, "data", None) is None:
        return jsonify({"ok": False, "error": "Falha ao excluir"}), 400
    return jsonify({"ok": True})

# ===================== CADASTROS (ADMIN) =====================

def require_admin():
    """
    ✅ Regra atual:
      - admin, financeiro e gestor têm permissão
    OBS: Seus cards você quer APENAS admin -> isso fica no template usando is_admin/current_user.role.
    """
    h = (current_user.hierarquia or "").strip().lower()
    if h not in ("admin", "financeiro", "gestor"):
        abort(403)


CADASTRO_TABLES = {
    "fin_conta": {"label": "Conta", "value_col": "conta", "ativo_col": "ativo", "refs": []},
    "fin_local": {"label": "Local", "value_col": "local", "ativo_col": "ativo", "refs": [
        {"table": TABLE_ACORDOS, "col": "local"},
        {"table": TABLE_MANDADOS, "col": "local"},
    ]},
    "fin_patrono_reu": {"label": "Patrono do réu", "value_col": "patrono_reu", "ativo_col": "ativo", "refs": [
        {"table": TABLE_ACORDOS, "col": "escritorio_reu"},
    ]},
    "fin_prazo_estimado": {"label": "Prazo estimado", "value_col": "prazo_estimado", "ativo_col": "ativo", "refs": [
        {"table": TABLE_ACORDOS, "col": "prazo_estimado"},
    ]},
    "fin_reu": {"label": "Réu", "value_col": "reu", "ativo_col": "ativo", "refs": [
        {"table": TABLE_ACORDOS, "col": "reu"},
        {"table": TABLE_MANDADOS, "col": "reu"},
    ]},
    "fin_status": {"label": "Status", "value_col": "status", "ativo_col": "ativo", "refs": [
        {"table": TABLE_ACORDOS, "col": "status"},
        {"table": TABLE_MANDADOS, "col": "status"},
    ]},
    "fin_uf": {"label": "UF", "value_col": "uf", "ativo_col": "ativo", "refs": [
        {"table": TABLE_ACORDOS, "col": "uf"},
        {"table": TABLE_MANDADOS, "col": "uf"},
    ]},
}


def _cad_value_in_use(table_key: str, value: str) -> bool:
    cfg = CADASTRO_TABLES.get(table_key) or {}
    refs = cfg.get("refs") or []
    value = (value or "").strip()
    if not value or not refs:
        return False

    for ref in refs:
        t = ref["table"]
        c = ref["col"]
        try:
            r = supabase.table(t).select("id").eq(c, value).limit(1).execute()
            if getattr(r, "data", None):
                return True
        except Exception:
            pass

    return False


@app.get("/api/cadastro-options")
@login_required
def api_cadastro_options():
    options = {}
    for tname, cfg in CADASTRO_TABLES.items():
        value_col = cfg["value_col"]
        ativo_col = cfg["ativo_col"]

        rows = sb_select(
            tname,
            columns=f"{value_col},{ativo_col}",
            limit=5000,
            order_col=value_col,
            desc=False
        )
        options[tname] = [r[value_col] for r in rows if r.get(ativo_col) == 1]

    return jsonify(options)


@app.get("/cadastros")
@login_required
def cadastros():
    require_admin()

    table = (request.args.get("table") or "").strip()
    if table not in CADASTRO_TABLES:
        table = next(iter(CADASTRO_TABLES.keys()))

    cfg = CADASTRO_TABLES[table]
    value_col = cfg["value_col"]
    ativo_col = cfg["ativo_col"]

    rows = sb_select(
        table,
        columns=f"{value_col},{ativo_col}",
        limit=5000,
        order_col=value_col,
        desc=False
    )

    return render_template(
        "cadastros.html",
        cadastro_tables=CADASTRO_TABLES,
        table=table,
        cfg=cfg,
        value_col=value_col,
        ativo_col=ativo_col,
        rows=rows,
        error=request.args.get("error"),
        ok=request.args.get("ok"),
    )


@app.post("/cadastros/<table>/add")
@login_required
def cadastros_add(table):
    require_admin()
    if table not in CADASTRO_TABLES:
        abort(404)

    cfg = CADASTRO_TABLES[table]
    value_col = cfg["value_col"]
    ativo_col = cfg["ativo_col"]

    value = (request.form.get("value") or "").strip()
    ativo = request.form.get("ativo")
    ativo = 1 if ativo in (None, "", "1", "true", "on") else 0

    if not value:
        return redirect(url_for("cadastros", table=table, error="Informe um valor."))

    try:
        dup = supabase.table(table).select(value_col).ilike(value_col, value).limit(1).execute()
        if getattr(dup, "data", None):
            return redirect(url_for("cadastros", table=table, error="Valor já existe."))
    except Exception:
        pass

    supabase.table(table).insert({value_col: value, ativo_col: ativo}).execute()
    return redirect(url_for("cadastros", table=table, ok="Registro adicionado."))


@app.post("/cadastros/<table>/update")
@login_required
def cadastros_update(table):
    require_admin()
    if table not in CADASTRO_TABLES:
        abort(404)

    cfg = CADASTRO_TABLES[table]
    value_col = cfg["value_col"]
    ativo_col = cfg["ativo_col"]

    old_value = (request.form.get("old_value") or "").strip()
    new_value = (request.form.get("value") or "").strip()
    ativo = request.form.get("ativo")
    ativo = 1 if ativo in (None, "", "1", "true", "on") else 0

    if not old_value or not new_value:
        return redirect(url_for("cadastros", table=table, error="Valor inválido."))

    if _cad_value_in_use(table, old_value) and new_value != old_value:
        return redirect(url_for("cadastros", table=table, error="Este valor está em uso. Alteração do texto bloqueada; apenas 'Ativo' pode ser alterado."))

    if new_value != old_value:
        try:
            dup = supabase.table(table).select(value_col).ilike(value_col, new_value).limit(1).execute()
            if getattr(dup, "data", None):
                return redirect(url_for("cadastros", table=table, error="Já existe um registro com esse valor."))
        except Exception:
            pass

    supabase.table(table).update(
        {value_col: new_value, ativo_col: ativo}
    ).eq(value_col, old_value).execute()

    return redirect(url_for("cadastros", table=table, ok="Registro atualizado."))


@app.post("/cadastros/<table>/delete")
@login_required
def cadastros_delete(table):
    require_admin()
    if table not in CADASTRO_TABLES:
        abort(404)

    cfg = CADASTRO_TABLES[table]
    value_col = cfg["value_col"]

    value = (request.form.get("value") or "").strip()
    if not value:
        return redirect(url_for("cadastros", table=table, error="Valor inválido."))

    if _cad_value_in_use(table, value):
        return redirect(url_for("cadastros", table=table, error="Este valor está em uso em Acordos/Mandados. Exclusão bloqueada."))

    supabase.table(table).delete().eq(value_col, value).execute()
    return redirect(url_for("cadastros", table=table, ok="Registro excluído."))

# ===================== CONFIG (TODOS OS USUÁRIOS) =====================

@app.get("/config")
@login_required
def config_page():
    u = _get_user_by_login(current_user.login) or {}
    return render_template("config.html", user=u, error=request.args.get("error"), ok=request.args.get("ok"))


@app.post("/config")
@login_required
def config_post():
    nome = (request.form.get("nome") or "").strip()
    email = (request.form.get("email") or "").strip()

    senha_atual = (request.form.get("senha_atual") or "").strip()
    senha_nova = (request.form.get("senha_nova") or "").strip()
    senha_nova2 = (request.form.get("senha_nova2") or "").strip()

    user_row = _get_user_by_login(current_user.login)
    if not user_row:
        abort(403)

    payload = {}
    if nome != "":
        payload["nome"] = nome
    if email != "":
        payload["email"] = email

    wants_pw_change = any([senha_atual, senha_nova, senha_nova2])
    if wants_pw_change:
        if not (senha_atual and senha_nova and senha_nova2):
            return redirect(url_for("config_page", error="Para trocar a senha, preencha senha atual, nova e confirmação."))
        if senha_nova != senha_nova2:
            return redirect(url_for("config_page", error="A confirmação da nova senha não confere."))
        if len(senha_nova) < 6:
            return redirect(url_for("config_page", error="A nova senha deve ter pelo menos 6 caracteres."))
        if not _password_ok(senha_atual, user_row.get("senha", "")):
            return redirect(url_for("config_page", error="Senha atual incorreta."))

        payload["senha"] = _hash_password(senha_nova)

    if not payload:
        return redirect(url_for("config_page", ok="Nada para atualizar."))

    try:
        supabase.table(TABLE_USERS).update(payload).eq("login", current_user.login).execute()
    except Exception:
        return redirect(url_for("config_page", error="Falha ao atualizar. Tente novamente."))

    return redirect(url_for("config_page", ok="Dados atualizados com sucesso."))

# ===================== USERS ADMIN =====================

@app.get("/users")
@login_required
def users_admin():
    require_admin()
    s = (request.args.get("s") or "").strip()

    cols = "login,nome,email,hierarquia,created_at,updated_at"
    if s:
        rows = sb_select_or_like(
            TABLE_USERS,
            columns=cols,
            limit=2000,
            order_col="login",
            desc=False,
            or_ilike_cols=["login", "nome", "email", "hierarquia"],
            qtext=s
        )
    else:
        rows = sb_select(TABLE_USERS, columns=cols, limit=2000, order_col="login", desc=False)

    return render_template("users.html", rows=rows, error=request.args.get("error"), ok=request.args.get("ok"))


@app.post("/users/add")
@login_required
def users_add():
    require_admin()

    login = (request.form.get("login") or "").strip()
    nome = (request.form.get("nome") or "").strip()
    email = (request.form.get("email") or "").strip()
    hierarquia = (request.form.get("hierarquia") or "user").strip().lower()

    senha = (request.form.get("senha") or "").strip()
    senha2 = (request.form.get("senha2") or "").strip()

    if not login:
        return redirect(url_for("users_admin", error="Informe o login."))

    if senha != senha2:
        return redirect(url_for("users_admin", error="Senha e confirmação não conferem."))

    if len(senha) < 6:
        return redirect(url_for("users_admin", error="Senha deve ter pelo menos 6 caracteres."))

    if hierarquia not in ("user", "gestor", "financeiro", "admin"):
        hierarquia = "user"

    if _get_user_by_login(login):
        return redirect(url_for("users_admin", error="Login já existe."))

    payload = {
        "login": login,
        "nome": nome,
        "email": email,
        "hierarquia": hierarquia,
        "senha": _hash_password(senha),
    }

    try:
        supabase.table(TABLE_USERS).insert(payload).execute()
    except Exception:
        return redirect(url_for("users_admin", error="Falha ao criar usuário."))

    return redirect(url_for("users_admin", ok="Usuário criado com sucesso."))


@app.post("/users/update")
@login_required
def users_update():
    require_admin()

    mode = (request.form.get("mode") or "").strip()
    login = (request.form.get("login") or "").strip()

    if not login:
        return redirect(url_for("users_admin", error="Login inválido."))

    payload = {}

    if mode == "reset_password":
        senha = (request.form.get("senha") or "").strip()
        senha2 = (request.form.get("senha2") or "").strip()

        if senha != senha2:
            return redirect(url_for("users_admin", error="Senha e confirmação não conferem."))

        if len(senha) < 6:
            return redirect(url_for("users_admin", error="Senha deve ter pelo menos 6 caracteres."))

        payload["senha"] = _hash_password(senha)
    else:
        nome = (request.form.get("nome") or "").strip()
        email = (request.form.get("email") or "").strip()
        hierarquia = (request.form.get("hierarquia") or "user").strip().lower()

        if hierarquia not in ("user", "gestor", "financeiro", "admin"):
            hierarquia = "user"

        payload["nome"] = nome
        payload["email"] = email
        payload["hierarquia"] = hierarquia

    try:
        supabase.table(TABLE_USERS).update(payload).eq("login", login).execute()
    except Exception:
        return redirect(url_for("users_admin", error="Falha ao atualizar usuário."))

    return redirect(url_for("users_admin", ok="Usuário atualizado."))


@app.post("/users/delete")
@login_required
def users_delete():
    require_admin()

    login = (request.form.get("login") or "").strip()
    if not login:
        return redirect(url_for("users_admin", error="Login inválido."))

    if login == current_user.login:
        return redirect(url_for("users_admin", error="Você não pode excluir o próprio usuário logado."))

    try:
        supabase.table(TABLE_USERS).delete().eq("login", login).execute()
    except Exception:
        return redirect(url_for("users_admin", error="Falha ao excluir usuário."))

    return redirect(url_for("users_admin", ok="Usuário excluído."))

# ===================== RUN =====================

if __name__ == "__main__":
    app.run(
        host=os.getenv("FLASK_HOST", "0.0.0.0"),
        port=int(os.getenv("FLASK_PORT", "5001")),
        debug=os.getenv("FLASK_DEBUG", "true").lower() == "true"
    )
