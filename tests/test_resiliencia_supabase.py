# -*- coding: utf-8 -*-
"""
Resiliência a instabilidade do Supabase (sem banco — tudo mockado):
  - _is_transient_error: 504 do gateway / timeouts são transitórios; erros de
    dados/SQL não.
  - _exec_with_retry: repete só erro transitório e desiste após N tentativas.
  - _cached: memo por requisição, TTL, só em GET, invalidação após escrita e
    invalidação ENTRE PROCESSOS (workers do gunicorn) via arquivo-marcador.
  - _rpc_agregacao: função SQL ausente cai no fallback; erro transitório sobe.
  - _erro_email_liberado: 1 e-mail por janela por assinatura de erro.
"""
import sys, io, os, subprocess, tempfile
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)

_TMP = tempfile.mkdtemp(prefix="sf_resiliencia_")
os.environ["CACHE_MARKER_PATH"] = os.path.join(_TMP, "cache.gen")

import httpx
from postgrest.exceptions import APIError
import app

app._exec_with_retry.__globals__["time"].sleep = lambda s: None  # sem espera real nos testes

PASS = 0; FAIL = 0
def check(cond, msg):
    global PASS, FAIL
    if cond: PASS += 1; print("  ok  -", msg)
    else: FAIL += 1; print("  FAIL -", msg)


print("\n[1] _is_transient_error")
check(app._is_transient_error(APIError({"message": "Gateway Timeout"})), "504 'Gateway Timeout' (sem code) é transitório")
check(app._is_transient_error(APIError({"message": "x", "code": "57014"})), "57014 statement timeout é transitório")
check(app._is_transient_error(httpx.ReadTimeout("t")), "httpx.ReadTimeout é transitório")
check(not app._is_transient_error(APIError({"message": "duplicate key", "code": "23505"})), "23505 unique violation NÃO é transitório")
check(not app._is_transient_error(APIError({"message": "column x does not exist", "code": "42703"})), "42703 NÃO é transitório")
check(not app._is_transient_error(ValueError("x")), "ValueError NÃO é transitório")


print("\n[2] _exec_with_retry")
chamadas = {"n": 0}
def _falha_2x():
    chamadas["n"] += 1
    if chamadas["n"] <= 2:
        raise APIError({"message": "Gateway Timeout"})
    return "ok"
check(app._exec_with_retry(_falha_2x) == "ok" and chamadas["n"] == 3, "recupera após 2 falhas transitórias (3 tentativas)")

chamadas["n"] = 0
def _sempre_504():
    chamadas["n"] += 1
    raise APIError({"message": "Gateway Timeout"})
try:
    app._exec_with_retry(_sempre_504); check(False, "deveria propagar após esgotar tentativas")
except APIError:
    check(chamadas["n"] == 3, "propaga o erro após 3 tentativas")

chamadas["n"] = 0
def _erro_dados():
    chamadas["n"] += 1
    raise APIError({"message": "duplicate key", "code": "23505"})
try:
    app._exec_with_retry(_erro_dados); check(False, "deveria propagar")
except APIError:
    check(chamadas["n"] == 1, "erro de dados NÃO é repetido (1 tentativa)")


print("\n[3] _cached — memo, TTL e escopo GET")
app._cache_invalidate()
contador = {"n": 0}
def _produz():
    contador["n"] += 1
    return {"valor": contador["n"]}

with app.app.test_request_context("/", method="GET"):
    a = app._cached(("t", 1), _produz)
    b = app._cached(("t", 1), _produz)
    check(a is b and contador["n"] == 1, "mesma requisição: 1 execução")
with app.app.test_request_context("/", method="GET"):
    c = app._cached(("t", 1), _produz)
    check(contador["n"] == 1 and c["valor"] == 1, "requisição seguinte dentro do TTL: usa cache")
with app.app.test_request_context("/", method="GET"):
    app._cached(("t", 1), _produz, ttl=0)
    check(contador["n"] == 2, "ttl=0 não usa cache entre requisições")
with app.app.test_request_context("/", method="POST"):
    app._cached(("t", 1), _produz)
    app._cached(("t", 1), _produz)
    check(contador["n"] == 4, "POST nunca usa cache (validações leem dado fresco)")

def _explode():
    raise RuntimeError("banco fora")
with app.app.test_request_context("/", method="GET"):
    try:
        app._cached(("t", "erro"), _explode)
    except RuntimeError:
        pass
    check(app._cached(("t", "erro"), lambda: "recuperado") == "recuperado", "exceção do producer não é cacheada")


print("\n[4] invalidação após escrita (after_request)")
app._cache_invalidate()
contador["n"] = 0
with app.app.test_request_context("/", method="GET"):
    app._cached(("t", 2), _produz)
cliente = app.app.test_client()
cliente.post("/rota-que-nao-existe")  # 404 — ainda assim invalida (rota pode gravar e falhar depois)
with app.app.test_request_context("/", method="GET"):
    app._cached(("t", 2), _produz)
check(contador["n"] == 2, "POST (mesmo com erro) invalida o cache")


print("\n[5] invalidação ENTRE PROCESSOS (workers do gunicorn)")
app._cache_invalidate()
contador["n"] = 0
with app.app.test_request_context("/", method="GET"):
    app._cached(("t", 3), _produz)
with app.app.test_request_context("/", method="GET"):
    app._cached(("t", 3), _produz)
check(contador["n"] == 1, "antes: entrada válida no cache deste processo")
codigo = (
    "import sys, os, logging; sys.path.insert(0, %r); logging.disable(logging.CRITICAL);"
    "import app; app._cache_bump_generation()"
) % RAIZ
r = subprocess.run([sys.executable, "-c", codigo], env=dict(os.environ), cwd=RAIZ,
                   capture_output=True, text=True, timeout=120)
check(r.returncode == 0, "outro processo trocou o marcador" + ("" if r.returncode == 0 else f" (stderr: {r.stderr[-300:]})"))
with app.app.test_request_context("/", method="GET"):
    app._cached(("t", 3), _produz)
check(contador["n"] == 2, "depois: entrada deste processo foi descartada")


print("\n[6] _rpc_agregacao — fallback e erros")
class _RPC:
    def __init__(self, erro=None, dados=None): self.erro, self.dados, self.n = erro, dados, 0
    def rpc(self, nome, params): return self
    def execute(self):
        self.n += 1
        if self.erro: raise self.erro
        class R: pass
        r = R(); r.data = self.dados; return r
orig = app.supabase
try:
    app._RPC_INDISPONIVEL.clear()
    fake = _RPC(erro=APIError({"message": "Could not find the function", "code": "PGRST202"}))
    app.supabase = fake
    check(app._rpc_agregacao("fin_x", {}) is None, "função inexistente -> None (fallback)")
    check(app._rpc_agregacao("fin_x", {}) is None and fake.n == 1, "ausência memorizada: não reconsulta o banco")

    app._RPC_INDISPONIVEL.clear()
    app.supabase = _RPC(erro=APIError({"message": "division by zero", "code": "22012"}))
    check(app._rpc_agregacao("fin_y", {}) is None, "bug no SQL -> None (fallback), não derruba a tela")

    app._RPC_INDISPONIVEL.clear()
    app.supabase = _RPC(erro=APIError({"message": "Gateway Timeout"}))
    try:
        app._rpc_agregacao("fin_z", {}); check(False, "deveria propagar")
    except APIError:
        check(True, "504 propaga (fallback só dobraria a carga no banco fora)")

    app.supabase = _RPC(dados={"count": 3})
    check(app._rpc_agregacao("fin_w", {}) == {"count": 3}, "sucesso devolve o JSON da função")
finally:
    app.supabase = orig


print("\n[7] _erro_email_liberado — 1 e-mail por janela")
app._ERRO_EMAIL_DIR = os.path.join(_TMP, "erros")
with app.app.test_request_context("/api/mandados"):
    e = APIError({"message": "Gateway Timeout"})
    r1 = app._erro_email_liberado(e)
    r2 = app._erro_email_liberado(e)
    r3 = app._erro_email_liberado(e)
    check(r1 == (True, 0), "1ª ocorrência envia")
    check(r2[0] is False and r3[0] is False, "repetições na janela não enviam")
with app.app.test_request_context("/tenant-logo"):
    check(app._erro_email_liberado(APIError({"message": "Gateway Timeout"}))[0] is False,
          "falha de infraestrutura em OUTRA rota conta como o mesmo incidente")
with app.app.test_request_context("/api/mandados"):
    check(app._erro_email_liberado(KeyError("campo"))[0] is True, "erro diferente envia o seu próprio e-mail")
    app.ERROR_EMAIL_WINDOW_SECONDS = 0
    check(app._erro_email_liberado(e) == (True, 3), "após a janela: envia e informa 3 suprimidos")


print(f"\n{PASS} ok, {FAIL} falha(s)")
sys.exit(1 if FAIL else 0)
