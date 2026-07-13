# -*- coding: utf-8 -*-
"""
Runner da bateria de testes. Rode SEMPRE após qualquer nova feature.

Uso (ambiente conda 'sistema_financeiro'):
    python tests/run_all.py

Executa, em ordem:
  1. Compilação do app.py
  2. Parse de todos os templates Jinja2
  3. Testes de lógica de visibilidade/tenant (sem banco)
  4. Teste do endpoint de ordem/visibilidade (mockado)
  5. Teste JS de preservação do botão de filtro (node, se disponível)
  6. Smoke HTTP das telas + filtros (Supabase real — precisa do .env)
"""
import os, sys, subprocess, shutil, py_compile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = os.path.join(ROOT, "tests")
PY = sys.executable
resultados = []

def passo(nome, funcao):
    print("\n" + "=" * 70)
    print(">> " + nome)
    print("=" * 70)
    try:
        ok = funcao()
    except Exception as e:
        print("  ERRO:", e)
        ok = False
    resultados.append((nome, ok))

def run(cmd, cwd=ROOT):
    r = subprocess.run(cmd, cwd=cwd)
    return r.returncode == 0

def compila_app():
    py_compile.compile(os.path.join(ROOT, "app.py"), doraise=True)
    print("  app.py compila OK")
    return True

def parse_templates():
    from jinja2 import Environment, FileSystemLoader
    env = Environment(loader=FileSystemLoader(os.path.join(ROOT, "templates")))
    ok = True
    for base, _, files in os.walk(os.path.join(ROOT, "templates")):
        for f in files:
            if f.endswith(".html"):
                rel = os.path.relpath(os.path.join(base, f),
                                      os.path.join(ROOT, "templates")).replace("\\", "/")
                try:
                    env.get_template(rel)
                except Exception as e:
                    ok = False; print("  FAIL", rel, "->", e)
    if ok:
        print("  Todos os templates parseiam OK")
    return ok

passo("1) Compilação app.py", compila_app)
passo("2) Parse de templates Jinja2", parse_templates)
passo("3) Lógica visibilidade/tenant", lambda: run([PY, os.path.join(TESTS, "test_config_visibilidade.py")]))
passo("4) Endpoint ordem-colunas", lambda: run([PY, os.path.join(TESTS, "test_ordem_colunas_endpoint.py")]))

node = shutil.which("node")
if node:
    passo("5) JS — filtro preservado ao renomear",
          lambda: run([node, os.path.join(TESTS, "test_frontend_headers.js")]))
else:
    print("\n(!) node não encontrado — pulando teste JS de headers")
    resultados.append(("5) JS headers (pulado)", True))

passo("6) Smoke HTTP telas + filtros", lambda: run([PY, os.path.join(TESTS, "test_smoke_http.py")]))

print("\n" + "#" * 70)
print("RESUMO DA BATERIA")
print("#" * 70)
falhou = False
for nome, ok in resultados:
    print(f"  [{'OK ' if ok else 'FALHOU'}] {nome}")
    falhou = falhou or not ok
print("#" * 70)
sys.exit(1 if falhou else 0)
