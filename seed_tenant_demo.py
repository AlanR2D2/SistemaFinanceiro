"""
Cria o tenant de demonstração 'Demo', clonando toda a configuração do tenant
'Dra Consumidor' (cadastros auxiliares, campos personalizados, ordem/labels
de colunas) e populando acordos e mandados com dados aleatórios de 2026.

USO:
    python seed_tenant_demo.py            # cria (aborta se o tenant já tiver dados)
    python seed_tenant_demo.py --reset    # apaga tudo do tenant Demo e recria
    python seed_tenant_demo.py --dry-run  # só mostra o que faria

O QUE É CLONADO DE 'Dra Consumidor':
    fin_custom_fields + fin_custom_field_options (7 campos sistema + cf_1)
    fin_campos_config (ordem_acordos, ordem_mandados, setting)

As tabelas legadas (fin_status, fin_local, fin_conta, fin_reu, fin_patrono_reu,
fin_prazo_estimado, fin_uf) NÃO são clonadas: seu PK é a própria coluna de valor,
então o mesmo valor não pode existir em dois tenants. Desde a migration 05 o app
lê as opções e as cores de fin_custom_field_options (as legadas só servem de
fallback caso a migration não tenha rodado). É assim que os tenants reais criados
depois da migration — Aeroline, vpladvogados — existem: zero linhas nas legadas.

VOLUME GERADO:
    Acordos ativos: 150      Acordos finalizados: 500
    Mandados ativos: 200     Mandados finalizados: 700

Todas as datas ficam dentro do ano de 2026.
"""

import argparse
import random
import sys
from datetime import date, timedelta

from werkzeug.security import generate_password_hash

from supabase_client import get_supabase_client, bulk_insert

# ===================== CONFIGURAÇÃO =====================

TENANT_ORIGEM = "Dra Consumidor"
TENANT_DEMO = "Demo"

LOGIN_DEMO = "usu_demo"
SENHA_DEMO = "La.260425"
NOME_DEMO = "Usuário Demonstração"
EMAIL_DEMO = "demo@demo.com.br"
HIERARQUIA_DEMO = "admin"

QTD_ACORDOS_ATIVOS = 150
QTD_ACORDOS_FINALIZADOS = 500
QTD_MANDADOS_ATIVOS = 200
QTD_MANDADOS_FINALIZADOS = 700

ANO = 2026
PRIMEIRO_DIA = date(ANO, 1, 1)
ULTIMO_DIA = date(ANO, 12, 31)

# Tabelas legadas — não recebem cópia, mas são limpas no --reset por segurança.
TABELAS_CADASTRO_LEGADAS = [
    "fin_status",
    "fin_local",
    "fin_conta",
    "fin_reu",
    "fin_patrono_reu",
    "fin_prazo_estimado",
]

# Colunas geradas pelo banco — nunca são copiadas.
COLUNAS_IGNORADAS = {"id", "created_at", "updated_at"}

MESES_ABREV = [
    "jan.", "fev.", "mar.", "abr.", "mai.", "jun.",
    "jul.", "ago.", "set.", "out.", "nov.", "dez.",
]

# Status finalizados são derivados por prefixo (mesma regra do app.py).
PREFIXO_FINALIZADO = "FINALIZADO"

PRIMEIROS_NOMES = [
    "ANA", "BRUNO", "CARLA", "DIEGO", "ELISA", "FÁBIO", "GABRIELA", "HENRIQUE",
    "ISABELA", "JOÃO", "KARINA", "LUCAS", "MARIANA", "NATÁLIA", "OTÁVIO",
    "PATRÍCIA", "RAFAEL", "SANDRA", "THIAGO", "VANESSA", "WAGNER", "YASMIN",
    "ANDRÉ", "BEATRIZ", "CAIO", "DANIELA", "EDUARDO", "FERNANDA", "GUSTAVO",
    "HELENA", "IGOR", "JULIANA", "LEONARDO", "MARCELA", "NICOLAS", "PAULA",
]
SOBRENOMES = [
    "SILVA", "SANTOS", "OLIVEIRA", "SOUZA", "RODRIGUES", "FERREIRA", "ALVES",
    "PEREIRA", "LIMA", "GOMES", "COSTA", "RIBEIRO", "MARTINS", "CARVALHO",
    "ALMEIDA", "LOPES", "SOARES", "FERNANDES", "VIEIRA", "BARBOSA", "ROCHA",
    "DIAS", "NUNES", "MOREIRA", "TEIXEIRA", "CORREIA", "MENDES", "CARDOSO",
]

TIPOS = ["CPF", "CNPJ", None, None, None]
TIPOS_REU = ["aereo"] * 9 + ["onibus"]
PORCENTAGENS = [30.0] * 6 + [35.0, 40.0, 40.0, 25.0]
AUDIENCISTAS = [None] * 7 + [100.0, 100.0, 0.0]

OBSERVACOES = [
    "Cliente informado por WhatsApp.",
    "Aguardando confirmação bancária do depósito.",
    "Repasse programado para o próximo ciclo.",
    "Comprovante anexado ao processo.",
    "Réu solicitou parcelamento — proposta recusada.",
    "Valor conferido com a planilha de controle.",
    "Cliente pediu transferência para conta de terceiro (autorizada).",
    "Processo migrado do sistema antigo.",
    "Honorários já descontados na origem.",
    "Contato do autor atualizado nesta data.",
    None,
    None,
    None,
]


# ===================== HELPERS =====================

def _limpar(row: dict, tenant: str) -> dict:
    """Copia uma linha trocando o tenant e removendo colunas geradas pelo banco."""
    novo = {k: v for k, v in row.items() if k not in COLUNAS_IGNORADAS}
    novo["tenant"] = tenant
    return novo


def _data_no_ano(inicio: date = PRIMEIRO_DIA, fim: date = ULTIMO_DIA) -> date:
    """Data aleatória entre inicio e fim (ambas inclusive)."""
    dias = (fim - inicio).days
    return inicio + timedelta(days=random.randint(0, max(dias, 0)))


def _somar_dias(base: date, minimo: int, maximo: int) -> date:
    """base + N dias, nunca ultrapassando 31/12 do ano."""
    d = base + timedelta(days=random.randint(minimo, maximo))
    return min(d, ULTIMO_DIA)


def _mes_pg(d: date | None) -> str | None:
    """Formata a data de pagamento como 'jan./26' (padrão usado pelo sistema)."""
    if not d:
        return None
    return f"{MESES_ABREV[d.month - 1]}/{d.strftime('%y')}"


def _telefone() -> str:
    ddd = random.choice([11, 21, 31, 41, 47, 48, 51, 61, 62, 71, 81, 85, 92])
    return f"({ddd}) 9{random.randint(1000, 9999)}-{random.randint(1000, 9999)}"


def _chave_pix() -> str:
    escolha = random.random()
    if escolha < 0.4:
        return f"{random.randint(10000000000, 99999999999)}"
    if escolha < 0.7:
        nome = random.choice(PRIMEIROS_NOMES).lower()
        return f"{nome}{random.randint(10, 99)}@email.com"
    return _telefone()


def _numero_processo() -> str:
    """Número CNJ plausível: NNNNNNN-DD.AAAA.8.TR.OOOO"""
    return (
        f"{random.randint(1000000, 9999999)}-{random.randint(10, 99)}."
        f"{random.choice([2024, 2025, 2026])}.8."
        f"{random.randint(1, 27):02d}.{random.randint(1, 9999):04d}"
    )


def _autor() -> str:
    return f"{random.choice(PRIMEIROS_NOMES)} {random.choice(SOBRENOMES)} {random.choice(SOBRENOMES)}"


def _financeiro(base: float, pct: float) -> dict:
    """Deriva depósito/correção/honorários/repasse de forma coerente."""
    correcao = round(base * random.uniform(0.0, 0.09), 2)
    deposito = round(base + correcao, 2)
    honorarios = round(deposito * pct / 100, 2)
    repasse = round(deposito - honorarios, 2)
    sucumbencia = round(random.uniform(100, 2000), 2) if random.random() < 0.15 else None
    return {
        "correcao": correcao,
        "deposito": deposito,
        "honorarios": honorarios,
        "repasse": repasse,
        "sucumbencia": sucumbencia,
    }


# ===================== ETAPAS =====================

def garantir_tenant(sb, dry_run: bool) -> None:
    r = sb.table("fin_tenants").select("nome,ativo").eq("nome", TENANT_DEMO).limit(1).execute()
    if r.data:
        if int(r.data[0].get("ativo") or 0) != 1 and not dry_run:
            sb.table("fin_tenants").update({"ativo": 1}).eq("nome", TENANT_DEMO).execute()
            print(f"[ok] tenant '{TENANT_DEMO}' reativado")
        else:
            print(f"[ok] tenant '{TENANT_DEMO}' já existe")
        return
    if dry_run:
        print(f"[dry-run] criaria tenant '{TENANT_DEMO}'")
        return
    sb.table("fin_tenants").insert({"nome": TENANT_DEMO, "ativo": 1}).execute()
    print(f"[ok] tenant '{TENANT_DEMO}' criado")


def contar_dados_demo(sb) -> dict:
    contagens = {}
    tabelas = [
        "fin_acordos", "fin_mandados", "fin_custom_fields",
        "fin_custom_field_options", "fin_campos_config", *TABELAS_CADASTRO_LEGADAS,
    ]
    for tbl in tabelas:
        try:
            r = sb.table(tbl).select("tenant", count="exact").eq("tenant", TENANT_DEMO).limit(1).execute()
            contagens[tbl] = r.count or 0
        except Exception:
            contagens[tbl] = 0
    r = sb.table("fin_users").select("login", count="exact").eq("tenant", TENANT_DEMO).limit(1).execute()
    contagens["fin_users"] = r.count or 0
    return contagens


def resetar_demo(sb) -> None:
    """Apaga TODOS os dados do tenant Demo. Não toca em nenhum outro tenant."""
    print(f"[reset] apagando dados do tenant '{TENANT_DEMO}'...")

    for tbl in ["fin_acordos", "fin_mandados"]:
        sb.table(tbl).delete().eq("tenant", TENANT_DEMO).execute()
        print(f"  - {tbl} limpo")

    # As opções caem por CASCADE ao deletar os campos, mas apagamos explicitamente
    # para o caso de sobras órfãs.
    sb.table("fin_custom_field_options").delete().eq("tenant", TENANT_DEMO).execute()
    sb.table("fin_custom_fields").delete().eq("tenant", TENANT_DEMO).execute()
    print("  - fin_custom_fields / fin_custom_field_options limpos")

    sb.table("fin_campos_config").delete().eq("tenant", TENANT_DEMO).execute()
    print("  - fin_campos_config limpo")

    # O seed não escreve nas legadas, mas limpa por segurança (execuções antigas).
    for tbl in TABELAS_CADASTRO_LEGADAS:
        sb.table(tbl).delete().eq("tenant", TENANT_DEMO).execute()
    print("  - cadastros legados limpos")

    sb.table("fin_users").delete().eq("tenant", TENANT_DEMO).execute()
    print("  - fin_users limpo")


def clonar_custom_fields(sb, dry_run: bool) -> dict:
    """Clona fin_custom_fields + fin_custom_field_options, remapeando field_id.

    Devolve { chave_do_campo: [valores ativos] } — é daqui que saem as opções
    usadas para gerar os lançamentos, já que é daqui que o app as lê.
    """
    r = sb.table("fin_custom_fields").select("*").eq("tenant", TENANT_ORIGEM).order("ordem").execute()
    campos_origem = r.data or []
    if not campos_origem:
        raise SystemExit(f"[ERRO] tenant '{TENANT_ORIGEM}' não tem campos personalizados.")

    r = (sb.table("fin_custom_field_options").select("*")
         .eq("tenant", TENANT_ORIGEM).limit(20000).execute())
    opcoes_origem = r.data or []

    # id antigo -> chave
    mapa_antigo = {c["id"]: c["chave"] for c in campos_origem}

    if dry_run:
        print(f"[dry-run] fin_custom_fields: clonaria {len(campos_origem)} campos")
        print(f"[dry-run] fin_custom_field_options: clonaria {len(opcoes_origem)} opções")
    else:
        novos = [_limpar(c, TENANT_DEMO) for c in campos_origem]
        inseridos = sb.table("fin_custom_fields").insert(novos).execute().data or []
        mapa_novo = {c["chave"]: c["id"] for c in inseridos}
        print(f"[ok] fin_custom_fields: {len(inseridos)} campos clonados")

        opcoes = []
        for op in opcoes_origem:
            chave = mapa_antigo.get(op["field_id"])
            if not chave or chave not in mapa_novo:
                continue
            nova = _limpar(op, TENANT_DEMO)
            nova["field_id"] = mapa_novo[chave]
            opcoes.append(nova)
        if opcoes:
            bulk_insert("fin_custom_field_options", opcoes)
        print(f"[ok] fin_custom_field_options: {len(opcoes)} opções clonadas")

    # Opções ativas agrupadas por chave de campo.
    por_chave: dict[str, list[str]] = {}
    for op in opcoes_origem:
        chave = mapa_antigo.get(op["field_id"])
        valor = (op.get("valor") or "").strip()
        if not chave or not valor or int(op.get("ativo") or 0) != 1:
            continue
        por_chave.setdefault(chave, []).append(valor)
    return por_chave


def clonar_campos_config(sb, dry_run: bool) -> None:
    """Clona ordem das colunas, labels customizados e settings (% honorários)."""
    r = sb.table("fin_campos_config").select("*").eq("tenant", TENANT_ORIGEM).limit(5000).execute()
    linhas = [_limpar(x, TENANT_DEMO) for x in (r.data or [])]
    if dry_run:
        print(f"[dry-run] fin_campos_config: copiaria {len(linhas)} linhas")
        return
    if linhas:
        bulk_insert("fin_campos_config", linhas)
    print(f"[ok] fin_campos_config: {len(linhas)} linhas clonadas")


def criar_usuario(sb, dry_run: bool) -> None:
    r = sb.table("fin_users").select("login,tenant").eq("login", LOGIN_DEMO).limit(1).execute()
    payload = {
        "senha": generate_password_hash(SENHA_DEMO),
        "nome": NOME_DEMO,
        "email": EMAIL_DEMO,
        "hierarquia": HIERARQUIA_DEMO,
        "tenant": TENANT_DEMO,
    }
    if r.data:
        dono = (r.data[0].get("tenant") or "").strip()
        if dono != TENANT_DEMO:
            raise SystemExit(
                f"[ERRO] login '{LOGIN_DEMO}' já existe no tenant '{dono}'. Abortando."
            )
        if dry_run:
            print(f"[dry-run] atualizaria senha de '{LOGIN_DEMO}'")
            return
        sb.table("fin_users").update(payload).eq("login", LOGIN_DEMO).execute()
        print(f"[ok] usuário '{LOGIN_DEMO}' atualizado (senha reposta)")
        return

    if dry_run:
        print(f"[dry-run] criaria usuário '{LOGIN_DEMO}' ({HIERARQUIA_DEMO}) em '{TENANT_DEMO}'")
        return
    sb.table("fin_users").insert({"login": LOGIN_DEMO, **payload}).execute()
    print(f"[ok] usuário '{LOGIN_DEMO}' criado ({HIERARQUIA_DEMO}) em '{TENANT_DEMO}'")


# ===================== GERAÇÃO DE LANÇAMENTOS =====================

def _opcoes(por_chave: dict) -> dict:
    """Mapeia as chaves dos campos sistema para os nomes usados no gerador."""
    return {
        "status": por_chave.get("status", []),
        "local": por_chave.get("local", []),
        "conta": por_chave.get("conta", []),
        "reu": por_chave.get("reu", []),
        "patrono": por_chave.get("escritorio_reu", []),
        "prazo": por_chave.get("prazo_estimado", []),
        "uf": por_chave.get("uf", []),
    }


def _split_status(lista: list[str]) -> tuple[list[str], list[str]]:
    """Separa status em (finalizados, ativos) pela mesma regra do app."""
    fin = [s for s in lista if s.strip().upper().startswith(PREFIXO_FINALIZADO)]
    ativos = [s for s in lista if not s.strip().upper().startswith(PREFIXO_FINALIZADO)]
    return fin, ativos


def _valores_custom(data_ref: date, conta: str | None) -> dict:
    """cf_1 = 'Data da distribuição' (sempre <= data de referência). conta = campo sistema sem coluna fixa."""
    distribuicao = _data_no_ano(PRIMEIRO_DIA, data_ref)
    vc = {"cf_1": distribuicao.isoformat()}
    if conta:
        vc["conta"] = conta
    return vc


def gerar_acordos(opts: dict, qtd: int, finalizado: bool) -> list[dict]:
    fin_status, ativos_status = _split_status(opts["status"])
    linhas = []
    for _ in range(qtd):
        status = random.choice(fin_status if finalizado else ativos_status)
        data_acordo = _data_no_ano(PRIMEIRO_DIA, date(ANO, 11, 30))

        # Finalizados sempre têm pagamento; ativos, às vezes (réu pagou, falta repassar).
        tem_pagamento = finalizado or random.random() < 0.35
        data_pagamento = _somar_dias(data_acordo, 5, 90) if tem_pagamento else None

        pct = random.choice(PORCENTAGENS)
        valor_acordo = round(random.uniform(800, 28000), 2)
        fin = _financeiro(valor_acordo, pct)
        conta = random.choice(opts["conta"]) if opts["conta"] else None

        linhas.append({
            "tenant": TENANT_DEMO,
            "data_acordo": data_acordo.isoformat(),
            "numero_processo": _numero_processo(),
            "uf": random.choice(opts["uf"]),
            "reu": random.choice(opts["reu"]),
            "autor": _autor(),
            "tel": _telefone(),
            "escritorio_reu": random.choice(opts["patrono"]),
            "valor_acordo": valor_acordo,
            "status": status,
            "prazo_estimado": random.choice(opts["prazo"]),
            "prazo_real": _somar_dias(data_acordo, 5, 60).isoformat() if random.random() < 0.7 else None,
            "data_pagamento": data_pagamento.isoformat() if data_pagamento else None,
            "local": random.choice(opts["local"]),
            "tipo": random.choice(TIPOS),
            "tipo_reu": random.choice(TIPOS_REU),
            "porcentagem_honorarios": pct,
            "audiencista": random.choice(AUDIENCISTAS),
            "chave_pix": _chave_pix(),
            "observacoes": random.choice(OBSERVACOES),
            "mes_pg": _mes_pg(data_pagamento),
            "finalizado": 1 if finalizado else 0,
            "extra_1": None,
            "extra_2": None,
            "valores_custom": _valores_custom(data_acordo, conta),
            **fin,
        })
    return linhas


def gerar_mandados(opts: dict, qtd: int, finalizado: bool) -> list[dict]:
    fin_status, ativos_status = _split_status(opts["status"])
    linhas = []
    for _ in range(qtd):
        status = random.choice(fin_status if finalizado else ativos_status)
        data_quitacao = _data_no_ano(PRIMEIRO_DIA, date(ANO, 11, 30))

        tem_pagamento = finalizado or random.random() < 0.35
        data_pagamento = _somar_dias(data_quitacao, 3, 75) if tem_pagamento else None

        pct = random.choice(PORCENTAGENS)
        sentenca = round(random.uniform(800, 28000), 2)
        fin = _financeiro(sentenca, pct)
        conta = random.choice(opts["conta"]) if opts["conta"] else None

        linhas.append({
            "tenant": TENANT_DEMO,
            "data_quitacao": data_quitacao.isoformat(),
            "numero_processo": _numero_processo(),
            "uf": random.choice(opts["uf"]),
            "reu": random.choice(opts["reu"]),
            "autor": _autor(),
            "tel": _telefone(),
            "sentenca": sentenca,
            "quitacao": fin["deposito"],
            "status": status,
            "previsao": _somar_dias(data_quitacao, 15, 45).isoformat(),
            "data_pagamento": data_pagamento.isoformat() if data_pagamento else None,
            "local": random.choice(opts["local"]),
            "tipo": random.choice(TIPOS),
            "tipo_reu": random.choice(TIPOS_REU),
            "porcentagem_honorarios": pct,
            "audiencista": random.choice(AUDIENCISTAS),
            "chave_pix": _chave_pix(),
            "observacoes": random.choice(OBSERVACOES),
            "mes_pg": _mes_pg(data_pagamento),
            "finalizado": 1 if finalizado else 0,
            "extra_1": None,
            "extra_2": None,
            "valores_custom": _valores_custom(data_quitacao, conta),
            **fin,
        })
    return linhas


# ===================== MAIN =====================

def main() -> int:
    parser = argparse.ArgumentParser(description="Cria o tenant de demonstração 'Demo'.")
    parser.add_argument("--reset", action="store_true",
                        help="apaga todos os dados do tenant Demo antes de recriar")
    parser.add_argument("--dry-run", action="store_true",
                        help="mostra o que seria feito, sem escrever no banco")
    parser.add_argument("--seed", type=int, default=None,
                        help="semente do gerador aleatório (reprodutibilidade)")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    sb = get_supabase_client()

    # Guarda: o tenant de origem precisa existir.
    r = sb.table("fin_tenants").select("nome").eq("nome", TENANT_ORIGEM).limit(1).execute()
    if not r.data:
        print(f"[ERRO] tenant de origem '{TENANT_ORIGEM}' não encontrado.", file=sys.stderr)
        return 1

    existente = contar_dados_demo(sb)
    total_existente = sum(existente.values())
    if total_existente and not args.reset and not args.dry_run:
        print(f"[ERRO] o tenant '{TENANT_DEMO}' já tem dados: {existente}", file=sys.stderr)
        print("       Rode com --reset para apagar e recriar.", file=sys.stderr)
        return 2

    if args.reset and not args.dry_run:
        if total_existente:
            resetar_demo(sb)
        else:
            print(f"[reset] tenant '{TENANT_DEMO}' já estava vazio")

    garantir_tenant(sb, args.dry_run)
    por_chave = clonar_custom_fields(sb, args.dry_run)
    clonar_campos_config(sb, args.dry_run)
    criar_usuario(sb, args.dry_run)

    opts = _opcoes(por_chave)
    faltando = [k for k, v in opts.items() if not v]
    if faltando:
        print(f"[ERRO] campos sem opções ativas no tenant origem: {faltando}", file=sys.stderr)
        return 3

    fin_status, ativos_status = _split_status(opts["status"])
    if not fin_status or not ativos_status:
        print("[ERRO] tenant origem não tem status finalizados E ativos.", file=sys.stderr)
        return 4

    lotes = [
        ("fin_acordos", gerar_acordos(opts, QTD_ACORDOS_FINALIZADOS, finalizado=True), "acordos finalizados"),
        ("fin_acordos", gerar_acordos(opts, QTD_ACORDOS_ATIVOS, finalizado=False), "acordos ativos"),
        ("fin_mandados", gerar_mandados(opts, QTD_MANDADOS_FINALIZADOS, finalizado=True), "mandados finalizados"),
        ("fin_mandados", gerar_mandados(opts, QTD_MANDADOS_ATIVOS, finalizado=False), "mandados ativos"),
    ]

    for tabela, linhas, rotulo in lotes:
        if args.dry_run:
            print(f"[dry-run] {tabela}: inseriria {len(linhas)} {rotulo}")
            continue
        bulk_insert(tabela, linhas)
        print(f"[ok] {tabela}: {len(linhas)} {rotulo} inseridos")

    if args.dry_run:
        print("\n[dry-run] nada foi gravado.")
        return 0

    print("\n===== RESUMO =====")
    for tbl, qtd in contar_dados_demo(sb).items():
        print(f"  {tbl}: {qtd}")
    print(f"\nLogin: {LOGIN_DEMO}   Senha: {SENHA_DEMO}   Tenant: {TENANT_DEMO}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
