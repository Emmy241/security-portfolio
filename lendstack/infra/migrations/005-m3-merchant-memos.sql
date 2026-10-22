-- 005-m3-merchant-memos.sql
-- Adds the merchant_memos table for V-13 (stored XSS in admin panel).
--
-- Memo content is user-controlled and rendered by the admin panel with
-- innerHTML — V-13. This migration is not the vulnerability; the admin
-- panel HTML is. The table just needs to store the content verbatim.
--
-- Follows the V-30 fix pattern: owner = lendstack_owner, FORCE RLS,
-- app role gets CRUD only.

BEGIN;

CREATE TABLE merchant_memos (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES tenants(id),
  merchant_id  text NOT NULL,
  content      text NOT NULL,
  created_by   uuid REFERENCES users(id),
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX merchant_memos_tenant_merchant_idx
  ON merchant_memos (tenant_id, merchant_id);

-- V-30 fix pattern: separate owner, FORCE RLS, app role gets CRUD
ALTER TABLE merchant_memos OWNER TO lendstack_owner;
ALTER TABLE merchant_memos ENABLE ROW LEVEL SECURITY;
ALTER TABLE merchant_memos FORCE ROW LEVEL SECURITY;

CREATE POLICY merchant_memos_iso ON merchant_memos
  USING (tenant_id = current_tenant())
  WITH CHECK (tenant_id = current_tenant());

GRANT SELECT, INSERT, UPDATE, DELETE ON merchant_memos TO lendstack_app;

COMMIT;
