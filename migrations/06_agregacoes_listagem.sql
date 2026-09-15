-- =====================================================================
-- Agregações no Postgres para listagens e dashboard.
--
-- COMO RODAR:
--   Cole este SQL no SQL Editor do Supabase e execute. É idempotente
--   (CREATE OR REPLACE), então rodar mais de uma vez é seguro.
--   Não altera nenhum dado nem estrutura de tabela: só cria funções.
--
-- POR QUÊ:
--   Antes o app puxava até 50.000 linhas por requisição e somava/contava em
--   Python:
--     - totais da listagem (rodapé de somatórios)  -> fin_listagem_totais
--     - valores distintos do filtro por coluna     -> fin_listagem_facets
--     - dashboard (KPIs e gráficos)                -> fin_dashboard
--   Agora o banco devolve só o resultado agregado.
--
-- COMPATIBILIDADE:
--   O app detecta se estas funções existem. Enquanto a migration não for
--   aplicada ele continua usando o cálculo antigo em Python — então tanto
--   faz a ordem entre subir o app.py e rodar este SQL.
--
-- FILTROS:
--   A semântica dos filtros NÃO é reimplementada aqui. O app normaliza os
--   filtros (_normalize_list_filters em app.py) numa lista de cláusulas:
--     [{"col": "status", "custom": false,
--       "any": [{"op": "null"}, {"op": "in", "v": ["PAGO"]}]}, ...]
--   Cláusulas são combinadas com AND; os átomos de "any" com OR.
--   Átomos: null | in (v: lista) | range (a, b: [a, b)) | gte | lt | lte (v).
--   O mesmo formato alimenta o PostgREST no app, então os dois caminhos
--   produzem o mesmo resultado.
--
-- SEGURANÇA:
--   SQL dinâmico com nomes de tabela em whitelist, colunas validadas no
--   catálogo e todo valor passado por format(%L). EXECUTE liberado apenas
--   para service_role (a chave usada pelo backend).
-- =====================================================================


-- ---------------------------------------------------------------------
-- Monta a condição WHERE (sem a palavra WHERE) de uma listagem.
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fin_listagem_where(
    p_tabela     text,
    p_tenant     text,
    p_finalizado integer,
    p_clausulas  jsonb
) RETURNS text
LANGUAGE plpgsql
STABLE
SET search_path = public
AS $$
DECLARE
    v_sql    text;
    v_cl     jsonb;
    v_at     jsonb;
    v_col    text;
    v_ref    text;
    v_partes text[];
    v_vals   text;
BEGIN
    IF p_tabela IS NULL OR p_tabela NOT IN ('fin_acordos', 'fin_mandados') THEN
        RAISE EXCEPTION 'fin_listagem_where: tabela inválida (%)', p_tabela
            USING ERRCODE = '22023';
    END IF;
    IF p_tenant IS NULL THEN
        RAISE EXCEPTION 'fin_listagem_where: tenant obrigatório' USING ERRCODE = '22023';
    END IF;

    v_sql := format('tenant = %L', p_tenant);
    IF p_finalizado IS NOT NULL THEN
        v_sql := v_sql || format(' AND finalizado = %s', p_finalizado);
    END IF;

    FOR v_cl IN SELECT value FROM jsonb_array_elements(COALESCE(p_clausulas, '[]'::jsonb)) LOOP
        v_col := v_cl->>'col';
        IF v_col IS NULL OR v_col = '' THEN
            RAISE EXCEPTION 'fin_listagem_where: cláusula sem coluna' USING ERRCODE = '22023';
        END IF;

        IF COALESCE((v_cl->>'custom')::boolean, false) THEN
            -- Campo personalizado: a chave é só um literal dentro do JSONB.
            v_ref := format('(valores_custom->>%L)', v_col);
        ELSE
            IF NOT EXISTS (
                SELECT 1 FROM pg_attribute
                 WHERE attrelid = format('public.%I', p_tabela)::regclass
                   AND attname = v_col AND attnum > 0 AND NOT attisdropped
            ) THEN
                RAISE EXCEPTION 'fin_listagem_where: coluna inexistente (%)', v_col
                    USING ERRCODE = '42703';
            END IF;
            v_ref := format('%I', v_col);
        END IF;

        v_partes := ARRAY[]::text[];
        FOR v_at IN SELECT value FROM jsonb_array_elements(COALESCE(v_cl->'any', '[]'::jsonb)) LOOP
            CASE v_at->>'op'
                WHEN 'null' THEN
                    v_partes := v_partes || format('%s IS NULL', v_ref);
                WHEN 'in' THEN
                    -- Literais sem tipo: o Postgres converte para o tipo da coluna,
                    -- igual ao PostgREST (numeric, date, char...). null vira ''.
                    SELECT string_agg(format('%L', COALESCE(x, '')), ',')
                      INTO v_vals
                      FROM jsonb_array_elements_text(COALESCE(v_at->'v', '[]'::jsonb)) AS x;
                    IF v_vals IS NOT NULL THEN
                        v_partes := v_partes || format('%s IN (%s)', v_ref, v_vals);
                    END IF;
                WHEN 'range' THEN
                    v_partes := v_partes || format('(%s >= %L AND %s < %L)',
                                                   v_ref, v_at->>'a', v_ref, v_at->>'b');
                WHEN 'gte' THEN
                    v_partes := v_partes || format('%s >= %L', v_ref, v_at->>'v');
                WHEN 'lt' THEN
                    v_partes := v_partes || format('%s < %L', v_ref, v_at->>'v');
                WHEN 'lte' THEN
                    v_partes := v_partes || format('%s <= %L', v_ref, v_at->>'v');
                ELSE
                    RAISE EXCEPTION 'fin_listagem_where: operador inválido (%)', v_at->>'op'
                        USING ERRCODE = '22023';
            END CASE;
        END LOOP;

        IF cardinality(v_partes) > 0 THEN
            v_sql := v_sql || ' AND (' || array_to_string(v_partes, ' OR ') || ')';
        END IF;
    END LOOP;

    RETURN v_sql;
END;
$$;


-- ---------------------------------------------------------------------
-- Totais da listagem: {"count": n, "sums": {"honorarios": 123.45, ...}}
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fin_listagem_totais(
    p_tabela     text,
    p_tenant     text,
    p_finalizado integer,
    p_clausulas  jsonb,
    p_campos     text[]
) RETURNS jsonb
LANGUAGE plpgsql
STABLE
SET search_path = public
AS $$
DECLARE
    v_where text;
    v_somas text;
    v_res   jsonb;
BEGIN
    v_where := public.fin_listagem_where(p_tabela, p_tenant, p_finalizado, p_clausulas);

    SELECT string_agg(format('%L, COALESCE(SUM(%I), 0)', c, c), ', ')
      INTO v_somas
      FROM unnest(COALESCE(p_campos, ARRAY[]::text[])) AS c;

    EXECUTE format(
        'SELECT jsonb_build_object(''count'', COUNT(*), ''sums'', jsonb_build_object(%s)) FROM %I WHERE %s',
        COALESCE(v_somas, ''), p_tabela, v_where
    ) INTO v_res;

    RETURN v_res;
END;
$$;


-- ---------------------------------------------------------------------
-- Valores distintos de uma coluna (filtro estilo Excel), como JSON cru.
-- Coluna fixa: to_jsonb(coluna). Campo personalizado: valores_custom->chave
-- (listas de select_multi voltam como listas; o app as expande).
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fin_listagem_facets(
    p_tabela     text,
    p_tenant     text,
    p_finalizado integer,
    p_clausulas  jsonb,
    p_col        text,
    p_custom     boolean
) RETURNS jsonb
LANGUAGE plpgsql
STABLE
SET search_path = public
AS $$
DECLARE
    v_where text;
    v_expr  text;
    v_res   jsonb;
BEGIN
    v_where := public.fin_listagem_where(p_tabela, p_tenant, p_finalizado, p_clausulas);

    IF COALESCE(p_custom, false) THEN
        v_expr := format('valores_custom->%L', p_col);
    ELSE
        IF NOT EXISTS (
            SELECT 1 FROM pg_attribute
             WHERE attrelid = format('public.%I', p_tabela)::regclass
               AND attname = p_col AND attnum > 0 AND NOT attisdropped
        ) THEN
            RAISE EXCEPTION 'fin_listagem_facets: coluna inexistente (%)', p_col
                USING ERRCODE = '42703';
        END IF;
        v_expr := format('to_jsonb(%I)', p_col);
    END IF;

    EXECUTE format(
        'SELECT COALESCE(jsonb_agg(v), ''[]''::jsonb) FROM (SELECT DISTINCT %s AS v FROM %I WHERE %s) s',
        v_expr, p_tabela, v_where
    ) INTO v_res;

    RETURN v_res;
END;
$$;


-- ---------------------------------------------------------------------
-- Remove espaços nas pontas como o str.strip() do Python (inclui espaços
-- Unicode como NBSP, comuns em dados colados de planilha). '' vira NULL.
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fin_trim_py(p text)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
    SELECT NULLIF(
        regexp_replace(
            COALESCE(p, ''),
            '^[\u0009\u000a\u000b\u000c\u000d\u001c\u001d\u001e\u001f\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+|[\u0009\u000a\u000b\u000c\u000d\u001c\u001d\u001e\u001f\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$',
            '', 'g'
        ),
        ''
    );
$$;


-- ---------------------------------------------------------------------
-- Dashboard: KPIs e contagens por mês/UF/réu/status, já filtrados.
--
-- p_filtros (só campos com filtro ativo; valores já sem espaços nas pontas):
--   {"status": {"vals": ["PAGO"], "blank": false}, "uf": {...}, "reu": {...}}
--
-- Retorno (ordenação é feita no app):
--   {"opcoes":   {"status": [...], "uf": [...], "reu": [...]},
--    "acordos":  {"kpis": {...}, "mes": [[yyyy-mm, n]], "uf": [[v, n]], ...},
--    "mandados": {...}}
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fin_dashboard(
    p_tenant  text,
    p_filtros jsonb DEFAULT '{}'::jsonb
) RETURNS jsonb
LANGUAGE plpgsql
STABLE
SET search_path = public
AS $$
DECLARE
    v_st_on  boolean := COALESCE(p_filtros ? 'status', false);
    v_uf_on  boolean := COALESCE(p_filtros ? 'uf', false);
    v_reu_on boolean := COALESCE(p_filtros ? 'reu', false);
    v_st_vals  text[] := ARRAY(SELECT jsonb_array_elements_text(COALESCE(p_filtros->'status'->'vals', '[]')));
    v_uf_vals  text[] := ARRAY(SELECT jsonb_array_elements_text(COALESCE(p_filtros->'uf'->'vals', '[]')));
    v_reu_vals text[] := ARRAY(SELECT jsonb_array_elements_text(COALESCE(p_filtros->'reu'->'vals', '[]')));
    v_st_blank  boolean := COALESCE((p_filtros->'status'->>'blank')::boolean, false);
    v_uf_blank  boolean := COALESCE((p_filtros->'uf'->>'blank')::boolean, false);
    v_reu_blank boolean := COALESCE((p_filtros->'reu'->>'blank')::boolean, false);
    v_res jsonb;
BEGIN
    IF p_tenant IS NULL THEN
        RAISE EXCEPTION 'fin_dashboard: tenant obrigatório' USING ERRCODE = '22023';
    END IF;

    WITH base AS (
        SELECT 'acordos'::text AS origem, finalizado, data_pagamento,
               public.fin_trim_py(status) AS status,
               public.fin_trim_py(uf::text) AS uf,
               public.fin_trim_py(reu) AS reu
          FROM public.fin_acordos
         WHERE tenant = p_tenant
        UNION ALL
        SELECT 'mandados'::text, finalizado, data_pagamento,
               public.fin_trim_py(status),
               public.fin_trim_py(uf::text),
               public.fin_trim_py(reu)
          FROM public.fin_mandados
         WHERE tenant = p_tenant
    ),
    filtrada AS (
        SELECT *
          FROM base
         WHERE (NOT v_st_on  OR CASE WHEN status IS NULL THEN v_st_blank  ELSE status = ANY (v_st_vals)  END)
           AND (NOT v_uf_on  OR CASE WHEN uf     IS NULL THEN v_uf_blank  ELSE uf     = ANY (v_uf_vals)  END)
           AND (NOT v_reu_on OR CASE WHEN reu    IS NULL THEN v_reu_blank ELSE reu    = ANY (v_reu_vals) END)
    ),
    origens AS (
        SELECT unnest(ARRAY['acordos', 'mandados']) AS origem
    ),
    blocos AS (
        SELECT o.origem,
               jsonb_build_object(
                   'kpis', (
                       SELECT jsonb_build_object(
                                  'total',       COUNT(*),
                                  'pagos',       COUNT(f.data_pagamento),
                                  'finalizados', COUNT(*) FILTER (WHERE COALESCE(f.finalizado, 0) = 1))
                         FROM filtrada f WHERE f.origem = o.origem),
                   'mes', (
                       SELECT COALESCE(jsonb_agg(jsonb_build_array(k, n)), '[]'::jsonb)
                         FROM (SELECT to_char(f.data_pagamento, 'YYYY-MM') AS k, COUNT(*) AS n
                                 FROM filtrada f
                                WHERE f.origem = o.origem AND f.data_pagamento IS NOT NULL
                                GROUP BY 1) t),
                   'uf', (
                       SELECT COALESCE(jsonb_agg(jsonb_build_array(k, n)), '[]'::jsonb)
                         FROM (SELECT f.uf AS k, COUNT(*) AS n FROM filtrada f
                                WHERE f.origem = o.origem AND f.uf IS NOT NULL GROUP BY 1) t),
                   'reu', (
                       SELECT COALESCE(jsonb_agg(jsonb_build_array(k, n)), '[]'::jsonb)
                         FROM (SELECT f.reu AS k, COUNT(*) AS n FROM filtrada f
                                WHERE f.origem = o.origem AND f.reu IS NOT NULL GROUP BY 1) t),
                   'status', (
                       SELECT COALESCE(jsonb_agg(jsonb_build_array(k, n)), '[]'::jsonb)
                         FROM (SELECT f.status AS k, COUNT(*) AS n FROM filtrada f
                                WHERE f.origem = o.origem AND f.status IS NOT NULL GROUP BY 1) t)
               ) AS bloco
          FROM origens o
    )
    SELECT jsonb_build_object(
               'opcoes', jsonb_build_object(
                   'status', (SELECT COALESCE(jsonb_agg(DISTINCT b.status), '[]'::jsonb) FROM base b WHERE b.status IS NOT NULL),
                   'uf',     (SELECT COALESCE(jsonb_agg(DISTINCT b.uf),     '[]'::jsonb) FROM base b WHERE b.uf     IS NOT NULL),
                   'reu',    (SELECT COALESCE(jsonb_agg(DISTINCT b.reu),    '[]'::jsonb) FROM base b WHERE b.reu    IS NOT NULL)
               ),
               'acordos',  (SELECT bloco FROM blocos WHERE origem = 'acordos'),
               'mandados', (SELECT bloco FROM blocos WHERE origem = 'mandados')
           )
      INTO v_res;

    RETURN v_res;
END;
$$;


-- ---------------------------------------------------------------------
-- Permissões: só o backend (service_role) executa. Por padrão o Supabase
-- concede EXECUTE a anon/authenticated em funções novas do schema public.
-- ---------------------------------------------------------------------
DO $$
DECLARE
    fn text;
    funcs text[] := ARRAY[
        'public.fin_listagem_where(text, text, integer, jsonb)',
        'public.fin_listagem_totais(text, text, integer, jsonb, text[])',
        'public.fin_listagem_facets(text, text, integer, jsonb, text, boolean)',
        'public.fin_dashboard(text, jsonb)'
    ];
BEGIN
    FOREACH fn IN ARRAY funcs LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', fn);
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM anon', fn);
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM authenticated', fn);
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
            EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role', fn);
        END IF;
    END LOOP;
END;
$$;

-- Faz o PostgREST enxergar as funções novas sem reiniciar.
NOTIFY pgrst, 'reload schema';
