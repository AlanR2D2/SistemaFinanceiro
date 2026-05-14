-- =====================================================================
-- Índices para acelerar a listagem paginada (Acordos / Mandados).
--
-- COMO RODAR:
--   Cole este SQL no SQL Editor do Supabase (ou em qualquer cliente psql
--   conectado ao banco do projeto) e execute. Cada CREATE INDEX é idempotente
--   (IF NOT EXISTS), então rodar mais de uma vez é seguro.
--
-- Não altera nenhum dado. Só cria estruturas para o Postgres responder mais
-- rápido nas queries de:
--   - GET /acordos/ativos, /acordos/finalizados  (paginação + filtro)
--   - GET /mandados/ativos, /mandados/finalizados (paginação + filtro)
--   - GET /api/acordos, /api/mandados            (paginação + ordenação)
--   - GET /api/acordos/facets, /api/mandados/facets (valores distintos)
-- =====================================================================

-- ---------- ACORDOS ----------

-- Acesso principal por tenant + finalizado + ordenação default
CREATE INDEX IF NOT EXISTS idx_fin_acordos_tenant_finalizado_data_acordo
  ON fin_acordos (tenant, finalizado, data_acordo DESC);

-- Filtros comuns (status, uf, reu, local, escritorio_reu)
CREATE INDEX IF NOT EXISTS idx_fin_acordos_tenant_status
  ON fin_acordos (tenant, status);

CREATE INDEX IF NOT EXISTS idx_fin_acordos_tenant_uf
  ON fin_acordos (tenant, uf);

CREATE INDEX IF NOT EXISTS idx_fin_acordos_tenant_reu
  ON fin_acordos (tenant, reu);

CREATE INDEX IF NOT EXISTS idx_fin_acordos_tenant_local
  ON fin_acordos (tenant, local);

CREATE INDEX IF NOT EXISTS idx_fin_acordos_tenant_escritorio_reu
  ON fin_acordos (tenant, escritorio_reu);

CREATE INDEX IF NOT EXISTS idx_fin_acordos_tenant_data_pagamento
  ON fin_acordos (tenant, data_pagamento);

CREATE INDEX IF NOT EXISTS idx_fin_acordos_tenant_prazo_real
  ON fin_acordos (tenant, prazo_real);


-- ---------- MANDADOS ----------

CREATE INDEX IF NOT EXISTS idx_fin_mandados_tenant_finalizado_data_quitacao
  ON fin_mandados (tenant, finalizado, data_quitacao DESC);

CREATE INDEX IF NOT EXISTS idx_fin_mandados_tenant_status
  ON fin_mandados (tenant, status);

CREATE INDEX IF NOT EXISTS idx_fin_mandados_tenant_uf
  ON fin_mandados (tenant, uf);

CREATE INDEX IF NOT EXISTS idx_fin_mandados_tenant_reu
  ON fin_mandados (tenant, reu);

CREATE INDEX IF NOT EXISTS idx_fin_mandados_tenant_local
  ON fin_mandados (tenant, local);

CREATE INDEX IF NOT EXISTS idx_fin_mandados_tenant_data_pagamento
  ON fin_mandados (tenant, data_pagamento);

CREATE INDEX IF NOT EXISTS idx_fin_mandados_tenant_previsao
  ON fin_mandados (tenant, previsao);

CREATE INDEX IF NOT EXISTS idx_fin_mandados_tenant_created_at
  ON fin_mandados (tenant, created_at);
