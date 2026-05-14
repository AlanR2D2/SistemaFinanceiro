# app.py
import os
import re
from decimal import Decimal, InvalidOperation
from datetime import date, datetime
from collections import Counter

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, jsonify, abort, send_from_directory, session
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
TABLE_TENANTS = "fin_tenants"
TABLE_STAFF = "fin_staff"

# ===================== MULTI-TENANT =====================
# Tabelas que NÃO recebem filtro de tenant (são compartilhadas)
TABLES_SEM_TENANT = {"fin_uf"}

# Cache simples de tenants ativos (TTL em segundos)
_TENANTS_CACHE = {"ts": 0.0, "data": []}
_TENANTS_CACHE_TTL = 60.0


def _load_active_tenants() -> list[dict]:
    """Lê fin_tenants com cache em memória."""
    import time
    now = time.time()
    if (now - _TENANTS_CACHE["ts"]) < _TENANTS_CACHE_TTL and _TENANTS_CACHE["data"]:
        return _TENANTS_CACHE["data"]
    try:
        res = supabase.table(TABLE_TENANTS).select("nome,ativo").order("nome").execute()
        data = getattr(res, "data", None) or []
    except Exception:
        data = []
    _TENANTS_CACHE["ts"] = now
    _TENANTS_CACHE["data"] = data
    return data


def _tenant_existe_ativo(nome: str) -> bool:
    nome = (nome or "").strip()
    if not nome:
        return False
    for t in _load_active_tenants():
        if (t.get("nome") or "").strip() == nome and int(t.get("ativo") or 0) == 1:
            return True
    return False


def _invalidate_tenants_cache():
    _TENANTS_CACHE["ts"] = 0.0
    _TENANTS_CACHE["data"] = []


def _tenant_admin_count(tenant: str, exclude_login: str | None = None) -> int:
    """Conta usuários com hierarquia=admin no tenant. Usado para garantir que sempre exista ao menos 1 admin."""
    tenant = (tenant or "").strip()
    if not tenant:
        return 0
    try:
        q = supabase.table(TABLE_USERS).select("login").eq("tenant", tenant).eq("hierarquia", "admin")
        if exclude_login:
            q = q.neq("login", exclude_login)
        res = q.limit(5000).execute()
        rows = getattr(res, "data", None) or []
        return len(rows)
    except Exception:
        return 0

# ===================== AUTH =====================

class User(UserMixin):
    def __init__(self, data: dict):
        self.data = data or {}
        self.id = str(self.data.get("login", ""))

    @property
    def login(self): return self.data.get("login")

    @property
    def nome(self): return self.data.get("nome")

    @property
    def hierarquia(self): return self.data.get("hierarquia")

    @property
    def email(self): return self.data.get("email")

    # Compat com templates
    @property
    def role(self):
        return (self.data.get("hierarquia") or "").strip().lower()

    @property
    def is_admin(self):
        return self.role == "admin"


@app.context_processor
def inject_user_flags():
    try:
        if current_user and current_user.is_authenticated:
            return {
                "is_admin": bool(getattr(current_user, "is_admin", False)),
                "user_role": getattr(current_user, "role", ""),
                "tenant": session.get("tenant", ""),
                "onboarding_visto": bool(current_user.data.get("onboarding_visto_em")),
            }
    except Exception:
        pass
    return {"is_admin": False, "user_role": "", "tenant": "", "onboarding_visto": False}


def _get_tenant() -> str:
    """Retorna o tenant da sessão atual."""
    return session.get("tenant", "Dra Consumidor")


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
        new_hash = _hash_password(stored)
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

    tenant = (user_data.get("tenant") or "").strip()
    if not tenant:
        return render_template("login.html", error="Usuário sem empresa atribuída. Contate o staff.")

    if not _tenant_existe_ativo(tenant):
        return render_template("login.html", error="Empresa inativa. Contate o staff.")

    _maybe_migrate_plain_password_to_hash(user_data, ok)
    login_user(User(user_data))
    session["tenant"] = tenant
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


NUMERIC_FIELDS_ACORDOS = {"valor_acordo", "deposito", "correcao", "honorarios", "repasse", "sucumbencia", "porcentagem_honorarios"}
NUMERIC_FIELDS_MANDADOS = {"deposito", "correcao", "honorarios", "repasse", "sucumbencia", "porcentagem_honorarios"}


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


def sb_select(table: str, columns="*", limit=300, order_col=None, desc=True, filters=None, skip_tenant=False):
    q = supabase.table(table).select(columns)

    # Filtro de tenant automático
    if not skip_tenant and table not in TABLES_SEM_TENANT:
        q = q.eq("tenant", _get_tenant())

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
                      or_ilike_cols=None, qtext=None, extra_filters=None, skip_tenant=False):
    query = supabase.table(table).select(columns)

    # Filtro de tenant automático
    if not skip_tenant and table not in TABLES_SEM_TENANT:
        query = query.eq("tenant", _get_tenant())

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

    # ✅ adiciona tipo_reu também
    cols = "uf, reu, status, data_pagamento, finalizado, tipo_reu"
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

@app.get("/acordos/ativos")
@login_required
def acordos_ativos_page():
    # As linhas são carregadas via /api/acordos (paginação + scroll infinito).
    return render_template("acordos_ativos.html", rows=[], finalizado_value=0)


@app.get("/acordos/finalizados")
@login_required
def acordos_finalizados_page():
    return render_template("acordos_finalizados.html", rows=[], finalizado_value=1)


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

        # ✅ NOVO: tipo_reu
        "tipo_reu": data.get("tipo_reu"),

        "porcentagem_honorarios": data.get("porcentagem_honorarios"),
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
        "tenant": _get_tenant(),
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

        # ✅ NOVO: tipo_reu
        "tipo_reu": data.get("tipo_reu"),

        "porcentagem_honorarios": data.get("porcentagem_honorarios"),
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

@app.get("/mandados/ativos")
@login_required
def mandados_ativos_page():
    # As linhas são carregadas via /api/mandados (paginação + scroll infinito).
    return render_template("mandados_ativos.html", rows=[], finalizado_value=0)


@app.get("/mandados/finalizados")
@login_required
def mandados_finalizados_page():
    return render_template("mandados_finalizados.html", rows=[], finalizado_value=1)


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
        "previsao": br_to_iso_date(data.get("previsao")),
        "data_pagamento": br_to_iso_date(data.get("data_pagamento")),
        "local": data.get("local"),
        "tipo": data.get("tipo"),

        # ✅ NOVO: tipo_reu
        "tipo_reu": data.get("tipo_reu"),

        "porcentagem_honorarios": data.get("porcentagem_honorarios"),
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
        "tenant": _get_tenant(),
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
        "previsao": br_to_iso_date(data.get("previsao")),
        "data_pagamento": br_to_iso_date(data.get("data_pagamento")),
        "local": data.get("local"),
        "tipo": data.get("tipo"),

        # ✅ NOVO: tipo_reu
        "tipo_reu": data.get("tipo_reu"),

        "porcentagem_honorarios": data.get("porcentagem_honorarios"),
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

# ===================== API PAGINADA (ACORDOS / MANDADOS) =====================
# Endpoints usados pela listagem com scroll infinito.
# Princípios:
#   - Linhas: paginadas (limit/offset) — não carrega tudo no DOM.
#   - Totais: sempre somam TODOS os registros que casam com os filtros (independe da página).
#   - Facets: valores distintos por coluna respeitando os outros filtros ativos.

import base64
import json as _json

ACORDOS_LIST_COLUMNS = (
    "id,data_acordo,numero_processo,uf,reu,autor,tel,escritorio_reu,"
    "valor_acordo,status,prazo_estimado,prazo_real,data_pagamento,local,"
    "tipo,tipo_reu,porcentagem_honorarios,deposito,correcao,honorarios,"
    "audiencista,repasse,chave_pix,sucumbencia,observacoes,mes_pg,finalizado"
)

MANDADOS_LIST_COLUMNS = (
    "id,data_quitacao,numero_processo,uf,reu,autor,tel,sentenca,quitacao,"
    "status,previsao,data_pagamento,local,tipo,tipo_reu,"
    "porcentagem_honorarios,deposito,correcao,honorarios,audiencista,"
    "repasse,chave_pix,sucumbencia,observacoes,mes_pg,finalizado,"
    "created_at,updated_at"
)

ACORDOS_DATE_COLS = {"data_acordo", "prazo_real", "data_pagamento"}
MANDADOS_DATE_COLS = {"data_quitacao", "previsao", "data_pagamento", "created_at", "updated_at"}

ACORDOS_TOTAL_FIELDS = ("honorarios", "audiencista", "sucumbencia", "correcao")
MANDADOS_TOTAL_FIELDS = ("honorarios", "audiencista", "sucumbencia", "correcao", "deposito", "repasse")

# Whitelist de colunas válidas para ordenar/filtrar (evita injection no nome de coluna).
ACORDOS_VALID_COLS = {
    "data_acordo", "numero_processo", "uf", "reu", "autor", "tel", "escritorio_reu",
    "valor_acordo", "status", "prazo_estimado", "prazo_real", "data_pagamento",
    "local", "tipo", "tipo_reu", "porcentagem_honorarios", "deposito", "correcao",
    "honorarios", "audiencista", "repasse", "chave_pix", "sucumbencia",
    "observacoes", "mes_pg", "finalizado",
}
MANDADOS_VALID_COLS = {
    "data_quitacao", "numero_processo", "uf", "reu", "autor", "tel", "sentenca",
    "quitacao", "status", "previsao", "data_pagamento", "local", "tipo", "tipo_reu",
    "porcentagem_honorarios", "deposito", "correcao", "honorarios", "audiencista",
    "repasse", "chave_pix", "sucumbencia", "observacoes", "mes_pg", "finalizado",
    "created_at", "updated_at",
}


def _decode_filters_param(raw: str | None) -> dict:
    """
    O parâmetro `filters` chega como JSON base64-url-safe (mais simples que serializar
    todos os filtros como query string com listas).
    Forma esperada:
      {
        "<coluna>": {"type": "set", "values": [...], "include_blank": false},
        "<coluna>": {"type": "date_day"|"date_month", "values": [...], "include_blank": false},
      }
    """
    if not raw:
        return {}
    try:
        # base64 url-safe
        padded = raw + ("=" * (-len(raw) % 4))
        data = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        obj = _json.loads(data)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        # fallback: pode vir como JSON cru (URL-encoded)
        try:
            return _json.loads(raw)
        except Exception:
            return {}


def _quote_for_in(values):
    """
    PostgREST aceita listas em IN no formato: in.("v1","v2"). Caracteres especiais
    precisam ser envoltos em aspas duplas; aspas internas escapadas duplicando.
    """
    out = []
    for v in values:
        s = "" if v is None else str(v)
        s = s.replace("\\", "\\\\").replace('"', '""')
        out.append(f'"{s}"')
    return ",".join(out)


def _br_to_iso(s: str) -> str | None:
    """Converte dd/mm/yyyy → yyyy-mm-dd. Retorna None se inválido."""
    s = (s or "").strip()
    if not s or s == "-":
        return None
    try:
        if len(s) >= 10 and s[2] == "/" and s[5] == "/":
            return datetime.strptime(s[:10], "%d/%m/%Y").date().isoformat()
    except Exception:
        pass
    return None


def _month_range(mm_yyyy: str) -> tuple[str, str] | None:
    """Converte 'mm/yyyy' em par (inicio_iso, prox_mes_iso)."""
    try:
        mm, yyyy = (mm_yyyy or "").strip().split("/")
        mm_i = int(mm)
        yyyy_i = int(yyyy)
        if mm_i < 1 or mm_i > 12:
            return None
        nm = mm_i + 1
        ny = yyyy_i
        if nm > 12:
            nm = 1
            ny += 1
        return f"{yyyy_i:04d}-{mm_i:02d}-01", f"{ny:04d}-{nm:02d}-01"
    except Exception:
        return None


def _apply_list_filters(query, filters: dict, valid_cols: set, date_cols: set, skip_col: str | None = None):
    """
    Constrói WHERE no query do supabase a partir do dict de filtros.
    skip_col: ignora o filtro daquela coluna (usado em facets).
    """
    for col, f in (filters or {}).items():
        if not isinstance(f, dict):
            continue
        if col == skip_col:
            continue
        if col not in valid_cols:
            continue

        ftype = (f.get("type") or "").strip()
        values = f.get("values") or []
        include_blank = bool(f.get("include_blank"))

        if not values and not include_blank:
            continue

        if ftype == "set":
            if include_blank and not values:
                query = query.is_(col, "null")
            elif include_blank and values:
                escaped = _quote_for_in(values)
                query = query.or_(f"{col}.is.null,{col}.in.({escaped})")
            else:
                query = query.in_(col, values)

        elif ftype == "date_day" and col in date_cols:
            iso_vals = [_br_to_iso(v) for v in values]
            iso_vals = [v for v in iso_vals if v]
            if include_blank and not iso_vals:
                query = query.is_(col, "null")
            elif include_blank and iso_vals:
                escaped = _quote_for_in(iso_vals)
                query = query.or_(f"{col}.is.null,{col}.in.({escaped})")
            elif iso_vals:
                query = query.in_(col, iso_vals)

        elif ftype == "date_month" and col in date_cols:
            ranges = [_month_range(v) for v in values]
            ranges = [r for r in ranges if r]
            if include_blank and not ranges:
                query = query.is_(col, "null")
            elif ranges:
                or_parts = [f"and({col}.gte.{a},{col}.lt.{b})" for a, b in ranges]
                if include_blank:
                    or_parts.append(f"{col}.is.null")
                query = query.or_(",".join(or_parts))

        elif ftype == "date_range" and col in date_cols:
            # values = [start_iso | null, end_iso | null] — qualquer um pode ser omitido.
            start_v = values[0] if len(values) >= 1 else None
            end_v   = values[1] if len(values) >= 2 else None
            if not start_v and not end_v:
                continue
            if start_v:
                query = query.gte(col, start_v)
            if end_v:
                # Inclui o dia final: usamos col < (end + 1 dia) para funcionar
                # tanto em colunas DATE quanto em TIMESTAMP (created_at/updated_at).
                try:
                    from datetime import timedelta
                    d = datetime.strptime(str(end_v), "%Y-%m-%d").date()
                    query = query.lt(col, (d + timedelta(days=1)).isoformat())
                except Exception:
                    query = query.lte(col, end_v)

    return query


def _compute_totals(table_name: str, valid_cols: set, date_cols: set,
                    filters: dict, finalizado_value: int | None,
                    total_fields: tuple[str, ...]) -> dict:
    """
    Soma os campos numéricos para TODOS os registros que casam com os filtros.
    Estratégia: puxa apenas as colunas numéricas necessárias (payload mínimo) e soma em Python.
    Funciona em qualquer versão do PostgREST/Supabase.
    """
    cols = "id," + ",".join(total_fields)
    q = supabase.table(table_name).select(cols)
    q = q.eq("tenant", _get_tenant())
    if finalizado_value is not None:
        q = q.eq("finalizado", int(finalizado_value))
    q = _apply_list_filters(q, filters, valid_cols, date_cols)
    # Limite alto: cobre cenários reais. Se passar de 50k, idealmente RPC SQL.
    q = q.limit(50000)
    res = q.execute()
    rows = getattr(res, "data", None) or []

    sums = {f: 0.0 for f in total_fields}
    for r in rows:
        for f in total_fields:
            v = r.get(f)
            if v is None:
                continue
            try:
                sums[f] += float(v)
            except (TypeError, ValueError):
                pass
    return {"count": len(rows), "sums": sums}


def _normalize_sort(sort_col: str, sort_dir: str, valid_cols: set, default_col: str, default_dir: str = "desc"):
    col = (sort_col or "").strip()
    direction = (sort_dir or "").strip().lower()
    if col not in valid_cols:
        col = default_col
    if direction not in ("asc", "desc"):
        direction = default_dir
    return col, direction


def _page_args():
    try:
        page = max(1, int(request.args.get("page", "1")))
    except Exception:
        page = 1
    try:
        page_size = int(request.args.get("page_size", "100"))
    except Exception:
        page_size = 100
    page_size = max(20, min(500, page_size))
    return page, page_size


def _fetch_facets(table_name: str, col: str, valid_cols: set, date_cols: set,
                  filters: dict, finalizado_value: int | None,
                  date_mode: str | None = None) -> list[str]:
    """
    Retorna valores distintos de `col` respeitando os demais filtros.
    Para colunas de data, aplica formatação BR (dia ou mês) antes do distinct.
    """
    if col not in valid_cols:
        return []

    q = supabase.table(table_name).select(col)
    q = q.eq("tenant", _get_tenant())
    if finalizado_value is not None:
        q = q.eq("finalizado", int(finalizado_value))
    q = _apply_list_filters(q, filters, valid_cols, date_cols, skip_col=col)
    q = q.limit(50000)
    res = q.execute()
    rows = getattr(res, "data", None) or []

    seen = set()
    out = []
    is_date = col in date_cols

    for r in rows:
        v = r.get(col)
        if v is None or v == "":
            label = "-"
        elif is_date:
            iso = str(v)[:10]
            try:
                d = datetime.strptime(iso, "%Y-%m-%d").date()
            except Exception:
                d = None
            if d is None:
                label = "-"
            elif (date_mode or "day") == "month":
                label = f"{d.month:02d}/{d.year:04d}"
            else:
                label = f"{d.day:02d}/{d.month:02d}/{d.year:04d}"
        else:
            label = str(v)

        if label not in seen:
            seen.add(label)
            out.append(label)

    # Ordena: data por ordem cronológica, demais alfabética
    if is_date:
        def _date_key(lbl):
            if lbl == "-":
                return ""
            if (date_mode or "day") == "month":
                mm, yyyy = lbl.split("/")
                return f"{yyyy}-{mm}"
            dd, mm, yyyy = lbl.split("/")
            return f"{yyyy}-{mm}-{dd}"
        out.sort(key=_date_key)
    else:
        out.sort(key=lambda s: (s == "-", s.lower()))

    return out


def _list_paginated(table_name: str, list_columns: str, valid_cols: set, date_cols: set,
                    default_sort_col: str, total_fields: tuple[str, ...],
                    finalizado_value: int | None):
    """Lógica comum dos endpoints /api/acordos e /api/mandados."""
    filters = _decode_filters_param(request.args.get("filters"))
    sort_col, sort_dir = _normalize_sort(
        request.args.get("sort_col"), request.args.get("sort_dir"),
        valid_cols, default_sort_col, "desc"
    )
    page, page_size = _page_args()
    want_totals = (request.args.get("totals", "1") != "0")

    # Query principal: paginada
    q = supabase.table(table_name).select(list_columns, count="exact")
    q = q.eq("tenant", _get_tenant())
    if finalizado_value is not None:
        q = q.eq("finalizado", int(finalizado_value))
    q = _apply_list_filters(q, filters, valid_cols, date_cols)
    q = q.order(sort_col, desc=(sort_dir == "desc"))

    start = (page - 1) * page_size
    end = start + page_size - 1
    q = q.range(start, end)

    res = q.execute()
    rows = getattr(res, "data", None) or []
    total_count = getattr(res, "count", None)
    if total_count is None:
        total_count = len(rows) + start  # fallback aproximado

    payload = {
        "ok": True,
        "rows": rows,
        "page": page,
        "page_size": page_size,
        "total_count": total_count,
        "has_more": (start + len(rows)) < total_count,
        "sort_col": sort_col,
        "sort_dir": sort_dir,
    }

    if want_totals:
        totals = _compute_totals(
            table_name, valid_cols, date_cols, filters, finalizado_value, total_fields
        )
        payload["totals"] = totals["sums"]
        payload["filtered_count"] = totals["count"]

    return jsonify(payload)


# ----- ACORDOS API -----

@app.get("/api/acordos")
@login_required
def api_acordos_list():
    try:
        finalizado_value = int(request.args.get("finalizado", "0"))
    except Exception:
        finalizado_value = 0
    if finalizado_value not in (0, 1):
        finalizado_value = 0
    return _list_paginated(
        TABLE_ACORDOS, ACORDOS_LIST_COLUMNS,
        ACORDOS_VALID_COLS, ACORDOS_DATE_COLS,
        default_sort_col="data_acordo",
        total_fields=ACORDOS_TOTAL_FIELDS,
        finalizado_value=finalizado_value,
    )


@app.get("/api/acordos/<int:acordo_id>")
@login_required
def api_acordos_one(acordo_id: int):
    q = supabase.table(TABLE_ACORDOS).select("*").eq("id", acordo_id).eq("tenant", _get_tenant()).limit(1)
    res = q.execute()
    rows = getattr(res, "data", None) or []
    if not rows:
        return jsonify({"ok": False, "error": "Não encontrado"}), 404
    return jsonify({"ok": True, "row": rows[0]})


@app.get("/api/acordos/facets")
@login_required
def api_acordos_facets():
    col = (request.args.get("col") or "").strip()
    date_mode = (request.args.get("date_mode") or "day").strip()
    try:
        finalizado_value = int(request.args.get("finalizado", "0"))
    except Exception:
        finalizado_value = 0
    filters = _decode_filters_param(request.args.get("filters"))
    values = _fetch_facets(
        TABLE_ACORDOS, col, ACORDOS_VALID_COLS, ACORDOS_DATE_COLS,
        filters, finalizado_value, date_mode=date_mode,
    )
    return jsonify({"ok": True, "values": values})


# ----- MANDADOS API -----

@app.get("/api/mandados")
@login_required
def api_mandados_list():
    try:
        finalizado_value = int(request.args.get("finalizado", "0"))
    except Exception:
        finalizado_value = 0
    if finalizado_value not in (0, 1):
        finalizado_value = 0
    return _list_paginated(
        TABLE_MANDADOS, MANDADOS_LIST_COLUMNS,
        MANDADOS_VALID_COLS, MANDADOS_DATE_COLS,
        default_sort_col="data_quitacao",
        total_fields=MANDADOS_TOTAL_FIELDS,
        finalizado_value=finalizado_value,
    )


@app.get("/api/mandados/<int:mandado_id>")
@login_required
def api_mandados_one(mandado_id: int):
    q = supabase.table(TABLE_MANDADOS).select("*").eq("id", mandado_id).eq("tenant", _get_tenant()).limit(1)
    res = q.execute()
    rows = getattr(res, "data", None) or []
    if not rows:
        return jsonify({"ok": False, "error": "Não encontrado"}), 404
    return jsonify({"ok": True, "row": rows[0]})


@app.get("/api/mandados/facets")
@login_required
def api_mandados_facets():
    col = (request.args.get("col") or "").strip()
    date_mode = (request.args.get("date_mode") or "day").strip()
    try:
        finalizado_value = int(request.args.get("finalizado", "0"))
    except Exception:
        finalizado_value = 0
    filters = _decode_filters_param(request.args.get("filters"))
    values = _fetch_facets(
        TABLE_MANDADOS, col, MANDADOS_VALID_COLS, MANDADOS_DATE_COLS,
        filters, finalizado_value, date_mode=date_mode,
    )
    return jsonify({"ok": True, "values": values})


# ----- ONBOARDING -----

@app.post("/api/onboarding/marcar-visto")
@login_required
def api_onboarding_marcar_visto():
    """Marca o tour de boas-vindas como visto pelo usuário atual."""
    from datetime import timezone
    try:
        supabase.table(TABLE_USERS).update(
            {"onboarding_visto_em": datetime.now(timezone.utc).isoformat()}
        ).eq("login", current_user.login).execute()
        return jsonify({"ok": True})
    except Exception as e:
        # Se a coluna ainda não foi criada (migration 03 não rodou), respondemos
        # ok=False mas sem 500 — o tour já rodou na sessão, só não persiste.
        return jsonify({"ok": False, "error": str(e)}), 200


# ===================== CADASTROS (ADMIN) =====================

def require_admin():
    """
    Regra atual:
      - admin, financeiro e gestor têm permissão
    """
    h = (current_user.hierarquia or "").strip().lower()
    if h not in ("admin", "financeiro", "gestor"):
        abort(403)


CADASTRO_TABLES = {
    "fin_conta": {"label": "Conta", "value_col": "conta", "ativo_col": "ativo", "cor_col": "cor", "cor_letra_col": "cor_letra", "hierarquia_col": "hierarquia", "refs": []},
    "fin_local": {"label": "Local", "value_col": "local", "ativo_col": "ativo", "cor_col": "cor", "cor_letra_col": "cor_letra", "hierarquia_col": "hierarquia", "refs": [
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
    "fin_status": {"label": "Status", "value_col": "status", "ativo_col": "ativo", "cor_col": "cor", "cor_letra_col": "cor_letra", "hierarquia_col": "hierarquia", "refs": [
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

    tenant = _get_tenant()
    for ref in refs:
        t = ref["table"]
        c = ref["col"]
        try:
            q = supabase.table(t).select("id").eq(c, value)
            if t not in TABLES_SEM_TENANT:
                q = q.eq("tenant", tenant)
            r = q.limit(1).execute()
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


@app.get("/api/status-colors")
@app.get("/api/row-colors")
@login_required
def api_row_colors():
    """Retorna cores e hierarquia de status, local e conta para colorir linhas."""
    def _build_map(table_name, value_col):
        rows = sb_select(table_name, columns=f"{value_col},cor,cor_letra,hierarquia", limit=5000)
        m = {}
        for r in rows:
            v = (r.get(value_col) or "").strip()
            c = (r.get("cor") or "").strip()
            h = r.get("hierarquia")
            cl = (r.get("cor_letra") or "").strip()
            if v and c:
                m[v.upper()] = {"cor": c, "cor_letra": cl or "#000000", "hierarquia": h if h else 2}
        return m

    return jsonify({
        "status": _build_map("fin_status", "status"),
        "local": _build_map("fin_local", "local"),
        "conta": _build_map("fin_conta", "conta"),
    })


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
    cor_col = cfg.get("cor_col")
    cor_letra_col = cfg.get("cor_letra_col")
    hierarquia_col = cfg.get("hierarquia_col")

    columns = f"{value_col},{ativo_col}"
    if cor_col:
        columns += f",{cor_col}"
    if cor_letra_col:
        columns += f",{cor_letra_col}"
    if hierarquia_col:
        columns += f",{hierarquia_col}"

    rows = sb_select(
        table,
        columns=columns,
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
        cor_col=cor_col,
        cor_letra_col=cor_letra_col,
        hierarquia_col=hierarquia_col,
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
        dup_q = supabase.table(table).select(value_col).ilike(value_col, value)
        if table not in TABLES_SEM_TENANT:
            dup_q = dup_q.eq("tenant", _get_tenant())
        dup = dup_q.limit(1).execute()
        if getattr(dup, "data", None):
            return redirect(url_for("cadastros", table=table, error="Valor já existe."))
    except Exception:
        pass

    row_data = {value_col: value, ativo_col: ativo}
    # Tenant para cadastros (exceto fin_uf)
    if table not in TABLES_SEM_TENANT:
        row_data["tenant"] = _get_tenant()
    cor_col = cfg.get("cor_col")
    if cor_col:
        row_data[cor_col] = (request.form.get("cor") or "").strip() or None
    cor_letra_col = cfg.get("cor_letra_col")
    if cor_letra_col:
        row_data[cor_letra_col] = (request.form.get("cor_letra") or "#000000").strip()
    hierarquia_col = cfg.get("hierarquia_col")
    if hierarquia_col:
        h_val = (request.form.get("hierarquia") or "").strip()
        row_data[hierarquia_col] = int(h_val) if h_val in ("1", "2") else 2

    supabase.table(table).insert(row_data).execute()
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
        return redirect(url_for(
            "cadastros",
            table=table,
            error="Este valor está em uso. Alteração do texto bloqueada; apenas 'Ativo' pode ser alterado."
        ))

    if new_value != old_value:
        try:
            dup_q = supabase.table(table).select(value_col).ilike(value_col, new_value)
            if table not in TABLES_SEM_TENANT:
                dup_q = dup_q.eq("tenant", _get_tenant())
            dup = dup_q.limit(1).execute()
            if getattr(dup, "data", None):
                return redirect(url_for("cadastros", table=table, error="Já existe um registro com esse valor."))
        except Exception:
            pass

    update_data = {value_col: new_value, ativo_col: ativo}
    cor_col = cfg.get("cor_col")
    if cor_col:
        update_data[cor_col] = (request.form.get("cor") or "").strip() or None
    cor_letra_col = cfg.get("cor_letra_col")
    if cor_letra_col:
        update_data[cor_letra_col] = (request.form.get("cor_letra") or "#000000").strip()
    hierarquia_col = cfg.get("hierarquia_col")
    if hierarquia_col:
        h_val = (request.form.get("hierarquia") or "").strip()
        update_data[hierarquia_col] = int(h_val) if h_val in ("1", "2") else 2

    q_update = supabase.table(table).update(update_data).eq(value_col, old_value)
    if table not in TABLES_SEM_TENANT:
        q_update = q_update.eq("tenant", _get_tenant())
    q_update.execute()

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

    q_del = supabase.table(table).delete().eq(value_col, value)
    if table not in TABLES_SEM_TENANT:
        q_del = q_del.eq("tenant", _get_tenant())
    q_del.execute()
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

    cols = "login,nome,email,hierarquia,tenant,created_at,updated_at"
    if s:
        rows = sb_select_or_like(
            TABLE_USERS,
            columns=cols,
            limit=2000,
            order_col="login",
            desc=False,
            or_ilike_cols=["login", "nome", "email", "hierarquia"],
            qtext=s,
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

    if hierarquia not in ("user", "gestor", "financeiro", "admin"):
        hierarquia = "user"

    tenant = _get_tenant()

    existing = _get_user_by_login(login)
    if existing:
        return redirect(url_for("users_admin", error="Já existe um usuário com este login."))

    if senha != senha2:
        return redirect(url_for("users_admin", error="Senha e confirmação não conferem."))

    if len(senha) < 6:
        return redirect(url_for("users_admin", error="Senha deve ter pelo menos 6 caracteres."))

    # Se o tenant não tem nenhum admin, força o primeiro usuário criado a ser admin
    if _tenant_admin_count(tenant) == 0:
        hierarquia = "admin"

    payload = {
        "login": login,
        "nome": nome,
        "email": email,
        "hierarquia": hierarquia,
        "senha": _hash_password(senha),
        "tenant": tenant,
    }

    try:
        supabase.table(TABLE_USERS).insert(payload).execute()
    except Exception as e:
        app.logger.exception("Falha ao criar usuário (tenant)")
        return redirect(url_for("users_admin", error=f"Falha ao criar usuário: {e}"))

    return redirect(url_for("users_admin", ok="Usuário criado com sucesso."))


@app.post("/users/update")
@login_required
def users_update():
    require_admin()

    mode = (request.form.get("mode") or "").strip()
    login = (request.form.get("login") or "").strip()

    if not login:
        return redirect(url_for("users_admin", error="Login inválido."))

    alvo = _get_user_by_login(login)
    if not alvo or (alvo.get("tenant") or "") != _get_tenant():
        return redirect(url_for("users_admin", error="Usuário não encontrado neste tenant."))

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

        # Invariante: o tenant precisa ter ao menos 1 admin
        old_h = (alvo.get("hierarquia") or "").strip().lower()
        if old_h == "admin" and hierarquia != "admin":
            if _tenant_admin_count(_get_tenant(), exclude_login=login) < 1:
                return redirect(url_for("users_admin", error="Não é possível remover o último admin deste tenant."))

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

    alvo = _get_user_by_login(login)
    if not alvo or (alvo.get("tenant") or "") != _get_tenant():
        return redirect(url_for("users_admin", error="Usuário não encontrado neste tenant."))

    # Invariante: não pode deixar o tenant sem admin
    if (alvo.get("hierarquia") or "").strip().lower() == "admin":
        if _tenant_admin_count(_get_tenant(), exclude_login=login) < 1:
            return redirect(url_for("users_admin", error="Não é possível excluir o último admin deste tenant."))

    try:
        supabase.table(TABLE_USERS).delete().eq("login", login).execute()
    except Exception:
        return redirect(url_for("users_admin", error="Falha ao excluir usuário."))

    return redirect(url_for("users_admin", ok="Usuário excluído."))

# ===================== STAFF (CROSS-TENANT) =====================

import secrets
import string
from functools import wraps

# Tabelas que possuem coluna `tenant` (usadas para cascata de rename e validação de delete)
ALL_TENANT_TABLES = (
    TABLE_USERS,
    TABLE_ACORDOS,
    TABLE_MANDADOS,
    "fin_status",
    "fin_local",
    "fin_conta",
    "fin_patrono_reu",
    "fin_prazo_estimado",
    "fin_reu",
)


def _get_staff_by_login(login: str) -> dict | None:
    login = (login or "").strip()
    if not login:
        return None
    try:
        res = supabase.table(TABLE_STAFF).select("*").eq("login", login).limit(1).execute()
        rows = getattr(res, "data", None) or []
        return rows[0] if rows else None
    except Exception:
        return None


def _get_staff_by_email(email: str) -> dict | None:
    email = (email or "").strip().lower()
    if not email:
        return None
    try:
        res = supabase.table(TABLE_STAFF).select("*").ilike("email", email).limit(1).execute()
        rows = getattr(res, "data", None) or []
        return rows[0] if rows else None
    except Exception:
        return None


def _current_staff() -> dict | None:
    login = session.get("staff_login")
    if not login:
        return None
    return _get_staff_by_login(login)


def staff_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("staff_login"):
            return redirect(url_for("staff_login"))
        staff = _get_staff_by_login(session["staff_login"])
        if not staff:
            session.pop("staff_login", None)
            return redirect(url_for("staff_login"))
        return fn(*args, **kwargs)
    return wrapper


def _generate_temp_password(length: int = 12) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _pop_staff_flash_temp_password() -> dict | None:
    data = session.pop("staff_flash_temp_password", None)
    return data


def _pop_staff_flash_form() -> dict | None:
    return session.pop("staff_flash_form", None)


def _flash_staff_form_error(modal: str, error: str, form_data: dict | None = None):
    """Guarda erro + dados do form para reabrir o modal preservando inputs."""
    session["staff_flash_form"] = {
        "modal": modal,
        "error": error,
        "form_data": form_data or {},
    }


# ---------- AUTH STAFF ----------

@app.get("/staff/login")
def staff_login():
    if session.get("staff_login"):
        return redirect(url_for("staff_dashboard"))
    return render_template("staff/login.html", error=request.args.get("error"))


@app.post("/staff/login")
def staff_login_post():
    email = (request.form.get("email") or "").strip()
    password = (request.form.get("password") or "").strip()

    if not email or not password:
        return render_template("staff/login.html", error="Informe email e senha.")

    staff = _get_staff_by_email(email)
    if not staff:
        return render_template("staff/login.html", error="Credenciais inválidas.")

    if not _password_ok(password, staff.get("senha", "")):
        return render_template("staff/login.html", error="Credenciais inválidas.")

    # Encerra qualquer sessão de tenant em paralelo
    try:
        logout_user()
    except Exception:
        pass
    session.pop("tenant", None)

    session["staff_login"] = staff["login"]
    return redirect(url_for("staff_dashboard"))


@app.get("/staff/logout")
def staff_logout():
    session.pop("staff_login", None)
    session.pop("staff_flash_temp_password", None)
    return redirect(url_for("staff_login"))


# ---------- DASHBOARD STAFF ----------

@app.get("/staff")
@staff_required
def staff_dashboard():
    staff = _current_staff() or {}

    try:
        tenants = supabase.table(TABLE_TENANTS).select("nome,ativo").order("nome").execute()
        tenants = getattr(tenants, "data", None) or []
    except Exception:
        tenants = []

    # Contagens por tenant
    stats = []
    total_users = 0
    total_acordos = 0
    total_mandados = 0
    for t in tenants:
        nome = t.get("nome") or ""
        try:
            u = supabase.table(TABLE_USERS).select("login").eq("tenant", nome).limit(5000).execute()
            uc = len(getattr(u, "data", None) or [])
        except Exception:
            uc = 0
        try:
            a = supabase.table(TABLE_ACORDOS).select("id").eq("tenant", nome).limit(50000).execute()
            ac = len(getattr(a, "data", None) or [])
        except Exception:
            ac = 0
        try:
            m = supabase.table(TABLE_MANDADOS).select("id").eq("tenant", nome).limit(50000).execute()
            mc = len(getattr(m, "data", None) or [])
        except Exception:
            mc = 0

        total_users += uc
        total_acordos += ac
        total_mandados += mc

        stats.append({
            "nome": nome,
            "ativo": int(t.get("ativo") or 0),
            "users": uc,
            "acordos": ac,
            "mandados": mc,
        })

    return render_template(
        "staff/dashboard.html",
        staff=staff,
        stats=stats,
        total_tenants=len(tenants),
        total_users=total_users,
        total_acordos=total_acordos,
        total_mandados=total_mandados,
    )


# ---------- TENANTS ----------

@app.get("/staff/tenants")
@staff_required
def staff_tenants():
    staff = _current_staff() or {}
    try:
        res = supabase.table(TABLE_TENANTS).select("*").order("nome").execute()
        rows = getattr(res, "data", None) or []
    except Exception:
        rows = []
    return render_template(
        "staff/tenants.html",
        staff=staff,
        rows=rows,
        error=request.args.get("error"),
        ok=request.args.get("ok"),
    )


@app.post("/staff/tenants/add")
@staff_required
def staff_tenants_add():
    nome = (request.form.get("nome") or "").strip()
    if not nome:
        return redirect(url_for("staff_tenants", error="Informe o nome do tenant."))

    try:
        dup = supabase.table(TABLE_TENANTS).select("nome").ilike("nome", nome).limit(1).execute()
        if getattr(dup, "data", None):
            return redirect(url_for("staff_tenants", error="Já existe um tenant com este nome."))
    except Exception:
        pass

    try:
        supabase.table(TABLE_TENANTS).insert({"nome": nome, "ativo": 1}).execute()
    except Exception:
        return redirect(url_for("staff_tenants", error="Falha ao criar tenant."))

    _invalidate_tenants_cache()
    return redirect(url_for("staff_tenants", ok=f"Tenant '{nome}' criado."))


@app.post("/staff/tenants/rename")
@staff_required
def staff_tenants_rename():
    old_nome = (request.form.get("old_nome") or "").strip()
    new_nome = (request.form.get("nome") or "").strip()

    if not old_nome or not new_nome:
        return redirect(url_for("staff_tenants", error="Nome inválido."))

    if old_nome == new_nome:
        return redirect(url_for("staff_tenants", ok="Nome inalterado."))

    try:
        dup = supabase.table(TABLE_TENANTS).select("nome").ilike("nome", new_nome).limit(1).execute()
        if getattr(dup, "data", None):
            return redirect(url_for("staff_tenants", error="Já existe um tenant com este nome."))
    except Exception:
        pass

    # Cascata: renomeia em fin_tenants e em todas as tabelas com coluna tenant
    try:
        supabase.table(TABLE_TENANTS).update({"nome": new_nome}).eq("nome", old_nome).execute()
    except Exception:
        return redirect(url_for("staff_tenants", error="Falha ao renomear tenant."))

    falhas = []
    for tbl in ALL_TENANT_TABLES:
        try:
            supabase.table(tbl).update({"tenant": new_nome}).eq("tenant", old_nome).execute()
        except Exception:
            falhas.append(tbl)

    _invalidate_tenants_cache()

    if falhas:
        return redirect(url_for("staff_tenants", error=f"Renomeado, mas falhou em: {', '.join(falhas)}."))
    return redirect(url_for("staff_tenants", ok=f"Tenant renomeado para '{new_nome}'."))


@app.post("/staff/tenants/toggle")
@staff_required
def staff_tenants_toggle():
    nome = (request.form.get("nome") or "").strip()
    if not nome:
        return redirect(url_for("staff_tenants", error="Tenant inválido."))

    try:
        res = supabase.table(TABLE_TENANTS).select("ativo").eq("nome", nome).limit(1).execute()
        rows = getattr(res, "data", None) or []
        if not rows:
            return redirect(url_for("staff_tenants", error="Tenant não encontrado."))
        novo = 0 if int(rows[0].get("ativo") or 0) == 1 else 1
        supabase.table(TABLE_TENANTS).update({"ativo": novo}).eq("nome", nome).execute()
    except Exception:
        return redirect(url_for("staff_tenants", error="Falha ao alterar status."))

    _invalidate_tenants_cache()
    return redirect(url_for("staff_tenants", ok=f"Tenant '{nome}' agora está {'ativo' if novo == 1 else 'inativo'}."))


@app.post("/staff/tenants/delete")
@staff_required
def staff_tenants_delete():
    nome = (request.form.get("nome") or "").strip()
    if not nome:
        return redirect(url_for("staff_tenants", error="Tenant inválido."))

    # Bloqueia se houver qualquer registro associado
    bloqueios = []
    for tbl in ALL_TENANT_TABLES:
        try:
            r = supabase.table(tbl).select("tenant").eq("tenant", nome).limit(1).execute()
            if getattr(r, "data", None):
                bloqueios.append(tbl)
        except Exception:
            pass

    if bloqueios:
        return redirect(url_for(
            "staff_tenants",
            error=f"Tenant '{nome}' tem dados em: {', '.join(bloqueios)}. Exclusão bloqueada."
        ))

    try:
        supabase.table(TABLE_TENANTS).delete().eq("nome", nome).execute()
    except Exception:
        return redirect(url_for("staff_tenants", error="Falha ao excluir tenant."))

    _invalidate_tenants_cache()
    return redirect(url_for("staff_tenants", ok=f"Tenant '{nome}' excluído."))


# ---------- USERS (GLOBAL) ----------

@app.get("/staff/users")
@staff_required
def staff_users():
    staff = _current_staff() or {}
    s = (request.args.get("s") or "").strip()
    tenant_filter = (request.args.get("tenant") or "").strip()

    try:
        q = supabase.table(TABLE_USERS).select("login,nome,email,hierarquia,tenant,created_at,updated_at").order("login")
        if tenant_filter:
            q = q.eq("tenant", tenant_filter)
        if s:
            parts = [f"{c}.ilike.*{s}*" for c in ("login", "nome", "email", "hierarquia")]
            q = q.or_(",".join(parts))
        res = q.limit(5000).execute()
        rows = getattr(res, "data", None) or []
    except Exception:
        rows = []

    try:
        tens = supabase.table(TABLE_TENANTS).select("nome").order("nome").execute()
        tenants = [t["nome"] for t in (getattr(tens, "data", None) or [])]
    except Exception:
        tenants = []

    temp_flash = _pop_staff_flash_temp_password()
    form_flash = _pop_staff_flash_form()

    # Erro principal: flash > query param
    error_msg = (form_flash or {}).get("error") or request.args.get("error")

    return render_template(
        "staff/users.html",
        staff=staff,
        rows=rows,
        tenants=tenants,
        tenant_filter=tenant_filter,
        s=s,
        temp_flash=temp_flash,
        form_flash=form_flash,
        error=error_msg,
        ok=request.args.get("ok"),
    )


@app.post("/staff/users/add")
@staff_required
def staff_users_add():
    login = (request.form.get("login") or "").strip()
    nome = (request.form.get("nome") or "").strip()
    email = (request.form.get("email") or "").strip()
    hierarquia = (request.form.get("hierarquia") or "user").strip().lower()
    tenant = (request.form.get("tenant") or "").strip()
    senha = (request.form.get("senha") or "").strip()
    senha2 = (request.form.get("senha2") or "").strip()

    form_data = {"login": login, "nome": nome, "email": email, "hierarquia": hierarquia, "tenant": tenant}

    def fail(msg: str):
        _flash_staff_form_error("add_user", msg, form_data)
        return redirect(url_for("staff_users"))

    if not login or not tenant:
        return fail("Login e tenant são obrigatórios.")

    if hierarquia not in ("user", "gestor", "financeiro", "admin"):
        hierarquia = "user"
        form_data["hierarquia"] = hierarquia

    try:
        r = supabase.table(TABLE_TENANTS).select("nome").eq("nome", tenant).limit(1).execute()
        if not (getattr(r, "data", None) or []):
            return fail("Tenant inválido.")
    except Exception:
        return fail("Tenant inválido.")

    if _get_user_by_login(login):
        return fail("Já existe um usuário com este login.")

    if senha != senha2:
        return fail("Senha e confirmação não conferem.")

    if len(senha) < 6:
        return fail("Senha deve ter pelo menos 6 caracteres.")

    # Tenant precisa ter pelo menos 1 admin — força o primeiro usuário a ser admin
    if _tenant_admin_count(tenant) == 0:
        hierarquia = "admin"

    # Converte strings vazias em NULL para colunas opcionais (evita colisão de UNIQUE em email='')
    payload = {
        "login": login,
        "nome": nome or None,
        "email": email or None,
        "hierarquia": hierarquia,
        "senha": _hash_password(senha),
        "tenant": tenant,
    }
    try:
        supabase.table(TABLE_USERS).insert(payload).execute()
    except Exception as e:
        app.logger.exception("Falha ao criar usuário (staff)")
        msg = str(e)
        if "duplicate key" in msg.lower() and "email" in msg.lower():
            msg = "Já existe um usuário com este email."
        return fail(f"Falha ao criar usuário: {msg}")

    return redirect(url_for("staff_users", ok=f"Usuário '{login}' criado no tenant '{tenant}'."))


@app.post("/staff/users/update")
@staff_required
def staff_users_update():
    login = (request.form.get("login") or "").strip()
    nome = (request.form.get("nome") or "").strip()
    email = (request.form.get("email") or "").strip()
    hierarquia = (request.form.get("hierarquia") or "user").strip().lower()

    if not login:
        return redirect(url_for("staff_users", error="Login inválido."))

    alvo = _get_user_by_login(login)
    if not alvo:
        return redirect(url_for("staff_users", error="Usuário não encontrado."))

    if hierarquia not in ("user", "gestor", "financeiro", "admin"):
        hierarquia = "user"

    old_h = (alvo.get("hierarquia") or "").strip().lower()
    tenant = (alvo.get("tenant") or "").strip()

    if old_h == "admin" and hierarquia != "admin":
        if _tenant_admin_count(tenant, exclude_login=login) < 1:
            return redirect(url_for("staff_users", error=f"Não é possível remover o último admin do tenant '{tenant}'."))

    try:
        supabase.table(TABLE_USERS).update({
            "nome": nome,
            "email": email,
            "hierarquia": hierarquia,
        }).eq("login", login).execute()
    except Exception:
        return redirect(url_for("staff_users", error="Falha ao atualizar usuário."))

    return redirect(url_for("staff_users", ok=f"Usuário '{login}' atualizado."))


@app.post("/staff/users/move")
@staff_required
def staff_users_move():
    login = (request.form.get("login") or "").strip()
    novo_tenant = (request.form.get("tenant") or "").strip()

    if not login or not novo_tenant:
        return redirect(url_for("staff_users", error="Dados inválidos."))

    alvo = _get_user_by_login(login)
    if not alvo:
        return redirect(url_for("staff_users", error="Usuário não encontrado."))

    tenant_atual = (alvo.get("tenant") or "").strip()
    if tenant_atual == novo_tenant:
        return redirect(url_for("staff_users", ok="Usuário já está neste tenant."))

    try:
        r = supabase.table(TABLE_TENANTS).select("nome").eq("nome", novo_tenant).limit(1).execute()
        if not (getattr(r, "data", None) or []):
            return redirect(url_for("staff_users", error="Tenant destino inexistente."))
    except Exception:
        return redirect(url_for("staff_users", error="Tenant destino inválido."))

    # Invariante: não deixar o tenant de origem sem admin
    if (alvo.get("hierarquia") or "").strip().lower() == "admin":
        if _tenant_admin_count(tenant_atual, exclude_login=login) < 1:
            return redirect(url_for("staff_users", error=f"Mover este admin deixaria o tenant '{tenant_atual}' sem nenhum admin."))

    try:
        supabase.table(TABLE_USERS).update({"tenant": novo_tenant}).eq("login", login).execute()
    except Exception:
        return redirect(url_for("staff_users", error="Falha ao mover usuário."))

    return redirect(url_for("staff_users", ok=f"Usuário '{login}' movido para '{novo_tenant}'."))


@app.post("/staff/users/reset-password")
@staff_required
def staff_users_reset_password():
    login = (request.form.get("login") or "").strip()
    if not login:
        return redirect(url_for("staff_users", error="Login inválido."))

    if not _get_user_by_login(login):
        return redirect(url_for("staff_users", error="Usuário não encontrado."))

    temp = _generate_temp_password()
    try:
        supabase.table(TABLE_USERS).update({"senha": _hash_password(temp)}).eq("login", login).execute()
    except Exception:
        return redirect(url_for("staff_users", error="Falha ao resetar senha."))

    session["staff_flash_temp_password"] = {"login": login, "senha": temp}
    return redirect(url_for("staff_users", ok=f"Senha de '{login}' redefinida."))


@app.post("/staff/users/delete")
@staff_required
def staff_users_delete():
    login = (request.form.get("login") or "").strip()
    if not login:
        return redirect(url_for("staff_users", error="Login inválido."))

    alvo = _get_user_by_login(login)
    if not alvo:
        return redirect(url_for("staff_users", error="Usuário não encontrado."))

    tenant = (alvo.get("tenant") or "").strip()
    if (alvo.get("hierarquia") or "").strip().lower() == "admin":
        if _tenant_admin_count(tenant, exclude_login=login) < 1:
            return redirect(url_for("staff_users", error=f"Não é possível excluir o último admin do tenant '{tenant}'."))

    try:
        supabase.table(TABLE_USERS).delete().eq("login", login).execute()
    except Exception:
        return redirect(url_for("staff_users", error="Falha ao excluir usuário."))

    return redirect(url_for("staff_users", ok=f"Usuário '{login}' excluído."))


# ---------- MINHA CONTA (STAFF) ----------

@app.get("/staff/account")
@staff_required
def staff_account():
    staff = _current_staff() or {}
    return render_template(
        "staff/account.html",
        staff=staff,
        error=request.args.get("error"),
        ok=request.args.get("ok"),
    )


@app.post("/staff/account")
@staff_required
def staff_account_post():
    staff = _current_staff()
    if not staff:
        return redirect(url_for("staff_login"))

    nome = (request.form.get("nome") or "").strip()
    email = (request.form.get("email") or "").strip()
    senha_atual = (request.form.get("senha_atual") or "").strip()
    senha_nova = (request.form.get("senha_nova") or "").strip()
    senha_nova2 = (request.form.get("senha_nova2") or "").strip()

    payload = {}
    if nome:
        payload["nome"] = nome
    if email:
        payload["email"] = email

    if any([senha_atual, senha_nova, senha_nova2]):
        if not (senha_atual and senha_nova and senha_nova2):
            return redirect(url_for("staff_account", error="Preencha senha atual, nova e confirmação."))
        if senha_nova != senha_nova2:
            return redirect(url_for("staff_account", error="Confirmação da nova senha não confere."))
        if len(senha_nova) < 8:
            return redirect(url_for("staff_account", error="A nova senha deve ter pelo menos 8 caracteres."))
        if not _password_ok(senha_atual, staff.get("senha", "")):
            return redirect(url_for("staff_account", error="Senha atual incorreta."))
        payload["senha"] = _hash_password(senha_nova)

    if not payload:
        return redirect(url_for("staff_account", ok="Nada para atualizar."))

    try:
        supabase.table(TABLE_STAFF).update(payload).eq("login", staff["login"]).execute()
    except Exception:
        return redirect(url_for("staff_account", error="Falha ao atualizar."))

    return redirect(url_for("staff_account", ok="Dados atualizados."))


# ===================== RUN =====================

if __name__ == "__main__":
    app.run(
        host=os.getenv("FLASK_HOST", "0.0.0.0"),
        port=int(os.getenv("FLASK_PORT", "5001")),
        debug=os.getenv("FLASK_DEBUG", "true").lower() == "true"
    )
