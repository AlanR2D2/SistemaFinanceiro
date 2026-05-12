-- =====================================================================
-- MIGRAÇÃO MULTI-TENANT
-- =====================================================================
-- 1) Cria tabela fin_tenants (fonte da verdade dos tenants)
-- 2) Cria tabela fin_staff (usuários administrativos cross-tenant)
-- 3) Adiciona coluna fin_users.tenant e faz backfill
-- 4) Remove colunas legadas dra_consumidor e aeroline
-- 5) Cria índices em todas as tabelas com filtro por tenant
--
-- ATENÇÃO: rode bloco por bloco no Supabase SQL Editor.
-- Antes de rodar o bloco 4 (DROP COLUMN), VERIFIQUE o resultado do
-- SELECT de conferência logo abaixo do bloco 3.
-- =====================================================================


-- ============================ BLOCO 1 ============================
-- Tabela fin_tenants
CREATE TABLE IF NOT EXISTS public.fin_tenants (
    id          BIGSERIAL PRIMARY KEY,
    nome        TEXT NOT NULL UNIQUE,
    ativo       INTEGER NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed dos tenants existentes
INSERT INTO public.fin_tenants (nome, ativo) VALUES ('Dra Consumidor', 1)
    ON CONFLICT (nome) DO NOTHING;
INSERT INTO public.fin_tenants (nome, ativo) VALUES ('Aeroline', 1)
    ON CONFLICT (nome) DO NOTHING;


-- ============================ BLOCO 2 ============================
-- Tabela fin_staff (usuários administrativos)
CREATE TABLE IF NOT EXISTS public.fin_staff (
    login       TEXT PRIMARY KEY,
    email       TEXT NOT NULL UNIQUE,
    senha       TEXT NOT NULL,
    nome        TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed do staff inicial (senha: La.260425)
INSERT INTO public.fin_staff (login, email, senha, nome)
VALUES (
    'leadfabrix',
    'leadfabrix@gmail.com',
    'scrypt:32768:8:1$fGof7NOaj2SGJ1pn$f6f2b38961b52b1a65d61eb76d5ddaaf470fa7d8b31f3e0b3616805dea06fb1b927254c31ac0226632587f38fc3ae785f5878b86878683c64feaef80fd0fb1fd',
    'Staff Lead Fabrix'
)
ON CONFLICT (login) DO NOTHING;


-- ============================ BLOCO 3 ============================
-- Adiciona coluna tenant em fin_users e faz backfill
ALTER TABLE public.fin_users
    ADD COLUMN IF NOT EXISTS tenant TEXT;

-- Backfill: usuário específico fica em Aeroline, todo o resto vai para Dra Consumidor
UPDATE public.fin_users
   SET tenant = 'Aeroline'
 WHERE LOWER(COALESCE(email, '')) = 'alangcc.r2d2@gmail.com';

UPDATE public.fin_users
   SET tenant = 'Dra Consumidor'
 WHERE tenant IS NULL;

-- CONFERÊNCIA (rode antes do bloco 4):
-- SELECT tenant, COUNT(*) FROM public.fin_users GROUP BY tenant;
-- Esperado: nenhum tenant NULL e a soma bate com o total de usuários.


-- ============================ BLOCO 4 ============================
-- Após validar a conferência acima, tornar NOT NULL e dropar colunas legadas
ALTER TABLE public.fin_users
    ALTER COLUMN tenant SET NOT NULL;

ALTER TABLE public.fin_users
    DROP COLUMN IF EXISTS dra_consumidor;

ALTER TABLE public.fin_users
    DROP COLUMN IF EXISTS aeroline;


-- ============================ BLOCO 5 ============================
-- Índices para acelerar o filtro por tenant
CREATE INDEX IF NOT EXISTS idx_fin_users_tenant            ON public.fin_users (tenant);
CREATE INDEX IF NOT EXISTS idx_fin_acordos_tenant          ON public.fin_acordos (tenant);
CREATE INDEX IF NOT EXISTS idx_fin_mandados_tenant         ON public.fin_mandados (tenant);
CREATE INDEX IF NOT EXISTS idx_fin_status_tenant           ON public.fin_status (tenant);
CREATE INDEX IF NOT EXISTS idx_fin_local_tenant            ON public.fin_local (tenant);
CREATE INDEX IF NOT EXISTS idx_fin_conta_tenant            ON public.fin_conta (tenant);
CREATE INDEX IF NOT EXISTS idx_fin_patrono_reu_tenant      ON public.fin_patrono_reu (tenant);
CREATE INDEX IF NOT EXISTS idx_fin_prazo_estimado_tenant   ON public.fin_prazo_estimado (tenant);
CREATE INDEX IF NOT EXISTS idx_fin_reu_tenant              ON public.fin_reu (tenant);
