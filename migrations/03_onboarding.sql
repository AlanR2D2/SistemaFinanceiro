-- =====================================================================
-- Onboarding: marca quando o usuário viu o tour de boas-vindas.
--
-- COMO RODAR:
--   Cole no SQL Editor do Supabase e execute. Idempotente (IF NOT EXISTS).
--
-- Não altera nenhum dado. Apenas adiciona uma coluna anulável a fin_users.
--   - NULL  → usuário ainda não viu o tour completo (será disparado no login).
--   - timestamp → usuário já viu; o tour só roda manualmente pelo botão "?".
-- =====================================================================

ALTER TABLE fin_users
  ADD COLUMN IF NOT EXISTS onboarding_visto_em timestamptz NULL;
