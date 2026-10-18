-- 03-rls.sql — RLS is ENABLED and policies are CORRECT.
-- It does nothing, because lendstack_app owns the tables (V-30).
-- We deliberately never run ALTER TABLE ... FORCE ROW LEVEL SECURITY.

CREATE OR REPLACE FUNCTION current_tenant() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT nullif(current_setting('app.tenant_id', true), '')::uuid
$$;

-- Direct tenant_id tables
ALTER TABLE users             ENABLE ROW LEVEL SECURITY;
ALTER TABLE accounts          ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices          ENABLE ROW LEVEL SECURITY;
ALTER TABLE loan_applications ENABLE ROW LEVEL SECURITY;
ALTER TABLE transfers         ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger_entries    ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhooks          ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log         ENABLE ROW LEVEL SECURITY;
ALTER TABLE support_messages  ENABLE ROW LEVEL SECURITY;

CREATE POLICY users_iso             ON users             USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant());
CREATE POLICY accounts_iso          ON accounts          USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant());
CREATE POLICY invoices_iso          ON invoices          USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant());
CREATE POLICY loan_apps_iso         ON loan_applications USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant());
CREATE POLICY transfers_iso         ON transfers         USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant());
CREATE POLICY ledger_entries_iso    ON ledger_entries    USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant());
CREATE POLICY webhooks_iso          ON webhooks          USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant());
CREATE POLICY audit_log_iso         ON audit_log         USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant());
CREATE POLICY support_messages_iso  ON support_messages  USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant());

-- Indirect (no tenant_id column) — scoped via parent
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY refresh_tokens_iso ON refresh_tokens
  USING (user_id IN (SELECT id FROM users WHERE tenant_id = current_tenant()));

-- V-31: files has no tenant_id. The policy can only join to invoices.
-- With owner-bypass in place, the download endpoint can fetch any file by id.
ALTER TABLE files ENABLE ROW LEVEL SECURITY;
CREATE POLICY files_iso ON files
  USING (invoice_id IN (SELECT id FROM invoices WHERE tenant_id = current_tenant()));
