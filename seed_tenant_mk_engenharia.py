"""
Cria o tenant 'MK Engenharia' clonando a configuração do tenant 'vpladvogados'
(campos personalizados, ordem/labels de colunas, % de honorários default) e
criando o usuário admin inicial.

USO:
    python seed_tenant_mk_engenharia.py            # cria (aborta se o tenant já tiver dados)
    python seed_tenant_mk_engenharia.py --reset    # apaga a config do tenant e recria
    python seed_tenant_mk_engenharia.py --dry-run  # só mostra o que faria

O QUE É CLONADO DE 'vpladvogados':
    fin_custom_fields          → 8 campos (7 sistema + cf_1 'Data Repasse')
    fin_custom_field_options   → SOMENTE os campos genéricos (uf, status).
                                 As opções de 'reu' (companhias aéreas) e
                                 'escritorio_reu' (escritórios de litígio aéreo)
                                 NÃO são clonadas: são específicas do vpladvogados
                                 e não fazem sentido para uma empresa de engenharia.
                                 A admin cadastra as dela em Cadastros.
    fin_campos_config          → labels (acordos/mandados), ordem das colunas
                                 (ordem_acordos/ordem_mandados) e setting
                                 porcentagem_honorarios_default.

NÃO É CRIADO:
    - Logo própria (o tenant cai no fallback da logo padrão do sistema).
      Para adicionar depois: static/Images/logos/<slug>.<png|jpg|svg>
    - Nenhum acordo ou mandado — o tenant nasce vazio de lançamentos.

As tabelas legadas (fin_status, fin_local, fin_conta, fin_reu, fin_patrono_reu,
fin_prazo_estimado) NÃO recebem nada: seu PK é a própria coluna de valor, então o
mesmo valor não pode existir em dois tenants. Desde a migration 05 o app lê as
opções e as cores de fin_custom_field_options. É assim que o próprio vpladvogados
existe: zero linhas nas legadas.
"""

import argparse
import sys

from werkzeug.security import generate_password_hash

from supabase_client import get_supabase_client, bulk_insert

# ===================== CONFIGURAÇÃO =====================

TENANT_ORIGEM = "vpladvogados"
TENANT_NOVO = "MK Engenharia"

LOGIN_ADMIN = "yasmim.pires@mkconstrueng.com.br"
SENHA_ADMIN = "yasmim.pires!@#123"
NOME_ADMIN = "Yasmim Pires"
EMAIL_ADMIN = "yasmim.pires@mkconstrueng.com.br"
HIERARQUIA_ADMIN = "admin"

# Chaves de campo cujas opções são genéricas e podem ser clonadas entre tenants.
# 'reu' e 'escritorio_reu' ficam de fora por serem específicos de litígio aéreo.
CHAVES_OPCOES_CLONAVEIS = {"uf", "status"}

# Colunas geradas pelo banco — nunca são copiadas.
COLUNAS_IGNORADAS = {"id", "created_at", "updated_at"}

# Tabelas legadas — não recebem cópia, mas são limpas no --reset por segurança.
TABELAS_CADASTRO_LEGADAS = [
    "fin_status",
    "fin_local",
    "fin_conta",
    "fin_reu",
    "fin_patrono_reu",
    "fin_prazo_estimado",
]


# ===================== HELPERS =====================

def _limpar(row: dict, tenant: str) -> dict:
    """Copia uma linha trocando o tenant e removendo colunas geradas pelo banco."""
    novo = {k: v for k, v in row.items() if k not in COLUNAS_IGNORADAS}
    novo["tenant"] = tenant
    return novo


# ===================== ETAPAS =====================

def garantir_tenant(sb, dry_run: bool) -> None:
    r = sb.table("fin_tenants").select("nome,ativo").eq("nome", TENANT_NOVO).limit(1).execute()
    if r.data:
        if int(r.data[0].get("ativo") or 0) != 1:
            if dry_run:
                print(f"[dry-run] reativaria tenant '{TENANT_NOVO}'")
            else:
                sb.table("fin_tenants").update({"ativo": 1}).eq("nome", TENANT_NOVO).execute()
                print(f"[ok] tenant '{TENANT_NOVO}' reativado")
        else:
            print(f"[ok] tenant '{TENANT_NOVO}' já existe e está ativo")
        return
    if dry_run:
        print(f"[dry-run] criaria tenant '{TENANT_NOVO}'")
        return
    sb.table("fin_tenants").insert({"nome": TENANT_NOVO, "ativo": 1}).execute()
    print(f"[ok] tenant '{TENANT_NOVO}' criado")


def contar_dados(sb, tenant: str) -> dict:
    contagens = {}
    tabelas = [
        "fin_acordos", "fin_mandados", "fin_custom_fields",
        "fin_custom_field_options", "fin_campos_config", *TABELAS_CADASTRO_LEGADAS,
    ]
    for tbl in tabelas:
        try:
            r = sb.table(tbl).select("tenant", count="exact").eq("tenant", tenant).limit(1).execute()
            contagens[tbl] = r.count or 0
        except Exception:
            contagens[tbl] = 0
    r = sb.table("fin_users").select("login", count="exact").eq("tenant", tenant).limit(1).execute()
    contagens["fin_users"] = r.count or 0
    return contagens


def resetar(sb) -> None:
    """Apaga TODOS os dados do tenant novo. Não toca em nenhum outro tenant."""
    print(f"[reset] apagando dados do tenant '{TENANT_NOVO}'...")

    for tbl in ["fin_acordos", "fin_mandados"]:
        sb.table(tbl).delete().eq("tenant", TENANT_NOVO).execute()
        print(f"  - {tbl} limpo")

    # As opções caem por CASCADE ao deletar os campos, mas apagamos explicitamente
    # para o caso de sobras órfãs.
    sb.table("fin_custom_field_options").delete().eq("tenant", TENANT_NOVO).execute()
    sb.table("fin_custom_fields").delete().eq("tenant", TENANT_NOVO).execute()
    print("  - fin_custom_fields / fin_custom_field_options limpos")

    sb.table("fin_campos_config").delete().eq("tenant", TENANT_NOVO).execute()
    print("  - fin_campos_config limpo")

    for tbl in TABELAS_CADASTRO_LEGADAS:
        sb.table(tbl).delete().eq("tenant", TENANT_NOVO).execute()
    print("  - cadastros legados limpos")

    sb.table("fin_users").delete().eq("tenant", TENANT_NOVO).execute()
    print("  - fin_users limpo")


def clonar_custom_fields(sb, dry_run: bool) -> None:
    """Clona fin_custom_fields + as opções genéricas, remapeando field_id."""
    r = (sb.table("fin_custom_fields").select("*")
         .eq("tenant", TENANT_ORIGEM).order("ordem").execute())
    campos_origem = r.data or []
    if not campos_origem:
        raise SystemExit(f"[ERRO] tenant '{TENANT_ORIGEM}' não tem campos personalizados.")

    r = (sb.table("fin_custom_field_options").select("*")
         .eq("tenant", TENANT_ORIGEM).limit(20000).execute())
    opcoes_origem = r.data or []

    # id antigo -> chave do campo
    mapa_antigo = {c["id"]: c["chave"] for c in campos_origem}

    # Só as opções dos campos genéricos.
    opcoes_filtradas = [
        op for op in opcoes_origem
        if mapa_antigo.get(op["field_id"]) in CHAVES_OPCOES_CLONAVEIS
    ]
    descartadas = len(opcoes_origem) - len(opcoes_filtradas)

    if dry_run:
        print(f"[dry-run] fin_custom_fields: clonaria {len(campos_origem)} campos "
              f"({', '.join(c['chave'] for c in campos_origem)})")
        print(f"[dry-run] fin_custom_field_options: clonaria {len(opcoes_filtradas)} opções "
              f"dos campos {sorted(CHAVES_OPCOES_CLONAVEIS)}; "
              f"descartaria {descartadas} de reu/escritorio_reu")
        return

    novos = [_limpar(c, TENANT_NOVO) for c in campos_origem]
    inseridos = sb.table("fin_custom_fields").insert(novos).execute().data or []
    mapa_novo = {c["chave"]: c["id"] for c in inseridos}
    print(f"[ok] fin_custom_fields: {len(inseridos)} campos clonados")

    opcoes = []
    for op in opcoes_filtradas:
        chave = mapa_antigo.get(op["field_id"])
        if not chave or chave not in mapa_novo:
            continue
        nova = _limpar(op, TENANT_NOVO)
        nova["field_id"] = mapa_novo[chave]
        opcoes.append(nova)
    if opcoes:
        bulk_insert("fin_custom_field_options", opcoes)
    print(f"[ok] fin_custom_field_options: {len(opcoes)} opções clonadas "
          f"({descartadas} de reu/escritorio_reu descartadas de propósito)")


def clonar_campos_config(sb, dry_run: bool) -> None:
    """Clona labels, ordem das colunas e settings (% honorários default)."""
    r = (sb.table("fin_campos_config").select("*")
         .eq("tenant", TENANT_ORIGEM).limit(5000).execute())
    origem = r.data or []
    linhas = [_limpar(x, TENANT_NOVO) for x in origem]

    por_escopo: dict[str, int] = {}
    for x in origem:
        esc = x.get("escopo") or "?"
        por_escopo[esc] = por_escopo.get(esc, 0) + 1

    if dry_run:
        print(f"[dry-run] fin_campos_config: copiaria {len(linhas)} linhas {por_escopo}")
        return
    if linhas:
        bulk_insert("fin_campos_config", linhas)
    print(f"[ok] fin_campos_config: {len(linhas)} linhas clonadas {por_escopo}")


def criar_usuario(sb, dry_run: bool) -> None:
    r = sb.table("fin_users").select("login,tenant").eq("login", LOGIN_ADMIN).limit(1).execute()
    payload = {
        "senha": generate_password_hash(SENHA_ADMIN),
        "nome": NOME_ADMIN,
        "email": EMAIL_ADMIN,
        "hierarquia": HIERARQUIA_ADMIN,
        "tenant": TENANT_NOVO,
    }
    if r.data:
        dono = (r.data[0].get("tenant") or "").strip()
        if dono != TENANT_NOVO:
            raise SystemExit(
                f"[ERRO] login '{LOGIN_ADMIN}' já existe no tenant '{dono}'. Abortando."
            )
        if dry_run:
            print(f"[dry-run] atualizaria senha de '{LOGIN_ADMIN}'")
            return
        sb.table("fin_users").update(payload).eq("login", LOGIN_ADMIN).execute()
        print(f"[ok] usuário '{LOGIN_ADMIN}' atualizado (senha reposta)")
        return

    if dry_run:
        print(f"[dry-run] criaria usuário '{LOGIN_ADMIN}' ({HIERARQUIA_ADMIN}) em '{TENANT_NOVO}'")
        return
    sb.table("fin_users").insert({"login": LOGIN_ADMIN, **payload}).execute()
    print(f"[ok] usuário '{LOGIN_ADMIN}' criado ({HIERARQUIA_ADMIN}) em '{TENANT_NOVO}'")


# ===================== MAIN =====================

def main() -> int:
    parser = argparse.ArgumentParser(
        description=f"Cria o tenant '{TENANT_NOVO}' clonando a config de '{TENANT_ORIGEM}'."
    )
    parser.add_argument("--reset", action="store_true",
                        help="apaga todos os dados do tenant novo antes de recriar")
    parser.add_argument("--dry-run", action="store_true",
                        help="mostra o que seria feito, sem escrever no banco")
    args = parser.parse_args()

    sb = get_supabase_client()

    # Guarda: o tenant de origem precisa existir.
    r = sb.table("fin_tenants").select("nome").eq("nome", TENANT_ORIGEM).limit(1).execute()
    if not r.data:
        print(f"[ERRO] tenant de origem '{TENANT_ORIGEM}' não encontrado.", file=sys.stderr)
        return 1

    # Guarda: não colidir com um tenant existente de nome parecido (case-insensitive),
    # que é a mesma checagem feita pelo painel de staff.
    r = sb.table("fin_tenants").select("nome").ilike("nome", TENANT_NOVO).limit(1).execute()
    homonimos = [t["nome"] for t in (r.data or []) if t.get("nome") != TENANT_NOVO]
    if homonimos:
        print(f"[ERRO] já existe tenant com nome equivalente: {homonimos}", file=sys.stderr)
        return 5

    existente = contar_dados(sb, TENANT_NOVO)
    total_existente = sum(existente.values())
    if total_existente and not args.reset and not args.dry_run:
        print(f"[ERRO] o tenant '{TENANT_NOVO}' já tem dados: {existente}", file=sys.stderr)
        print("       Rode com --reset para apagar e recriar.", file=sys.stderr)
        return 2

    if args.reset and not args.dry_run:
        if total_existente:
            resetar(sb)
        else:
            print(f"[reset] tenant '{TENANT_NOVO}' já estava vazio")

    garantir_tenant(sb, args.dry_run)
    clonar_custom_fields(sb, args.dry_run)
    clonar_campos_config(sb, args.dry_run)
    criar_usuario(sb, args.dry_run)

    if args.dry_run:
        print("\n[dry-run] nada foi gravado.")
        return 0

    print("\n===== RESUMO =====")
    for tbl, qtd in contar_dados(sb, TENANT_NOVO).items():
        print(f"  {tbl}: {qtd}")
    print(f"\nLogin: {LOGIN_ADMIN}")
    print(f"Senha: {SENHA_ADMIN}")
    print(f"Tenant: {TENANT_NOVO}")
    print("\nSem logo própria — o sistema usa a logo padrão. Para personalizar depois,")
    print("coloque o arquivo em static/Images/logos/ conforme o slug do tenant.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
