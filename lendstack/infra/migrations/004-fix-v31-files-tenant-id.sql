-- 004-fix-v31-files-tenant-id.sql
-- Fixes V-31: files table has no tenant_id column.
--
-- Currently tenant association flows through invoice_id → invoices.tenant_id.
-- RLS policy on files is a join, not a direct column.
--
-- Fix: add tenant_id, backfill, NOT NULL, FK, index, replace RLS policy.

BEGIN;

ALTER TABLE files ADD COLUMN tenant_id uuid;

UPDATE files f
SET tenant_id = i.tenant_id
FROM invoices i
WHERE f.invoice_id = i.id;

ALTER TABLE files ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE files
  ADD CONSTRAINT files_tenant_id_fkey
  FOREIGN KEY (tenant_id) REFERENCES tenants(id);

CREATE INDEX files_tenant_id_idx ON files (tenant_id);

DROP POLICY files_iso ON files;

CREATE POLICY files_iso ON files
  USING (tenant_id = current_tenant())
  WITH CHECK (tenant_id = current_tenant());

COMMIT;
