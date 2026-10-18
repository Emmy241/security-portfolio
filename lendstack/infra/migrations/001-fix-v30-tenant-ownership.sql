-- 001-fix-v30-tenant-ownership.sql
-- Fixes V-30: RLS bypass via table ownership.
--
-- Before: the app role (lendstack_app) owns every tenant-scoped table, and
-- FORCE ROW LEVEL SECURITY is not set. Postgres bypasses RLS evaluation for
-- the table owner, so policies never fire. All tenants' rows are visible
-- to any authenticated query.
--
-- After: the app role does not own any tenant-scoped table. A separate
-- ownership role (lendstack_owner) owns them. FORCE ROW LEVEL SECURITY is
-- set on every tenant-scoped table. The app role retains CRUD privileges
-- via explicit GRANTs.
--
-- The middleware in tenancy/middleware.js becomes effective: setting
-- app.tenant_id per request now actually scopes queries.

BEGIN;

-- 1. Create the ownership role (owns tables, never used by the app)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'lendstack_owner') THEN
    CREATE ROLE lendstack_owner NOINHERIT;
  END IF;
END
$$;

GRANT CONNECT ON DATABASE lendstack TO lendstack_owner;
GRANT USAGE ON SCHEMA public TO lendstack_owner;

-- 2. Reassign ownership away from the app role
ALTER TABLE tenants           OWNER TO lendstack_owner;
ALTER TABLE users             OWNER TO lendstack_owner;
ALTER TABLE refresh_tokens    OWNER TO lendstack_owner;
ALTER TABLE accounts          OWNER TO lendstack_owner;
ALTER TABLE invoices          OWNER TO lendstack_owner;
ALTER TABLE loan_applications OWNER TO lendstack_owner;
ALTER TABLE transfers         OWNER TO lendstack_owner;
ALTER TABLE ledger_entries    OWNER TO lendstack_owner;
ALTER TABLE webhooks          OWNER TO lendstack_owner;
ALTER TABLE files             OWNER TO lendstack_owner;
ALTER TABLE audit_log         OWNER TO lendstack_owner;
ALTER TABLE support_messages  OWNER TO lendstack_owner;

-- 3. FORCE RLS — defense in depth against ownership drift
ALTER TABLE users             FORCE ROW LEVEL SECURITY;
ALTER TABLE accounts          FORCE ROW LEVEL SECURITY;
ALTER TABLE invoices          FORCE ROW LEVEL SECURITY;
ALTER TABLE loan_applications FORCE ROW LEVEL SECURITY;
ALTER TABLE transfers         FORCE ROW LEVEL SECURITY;
ALTER TABLE ledger_entries    FORCE ROW LEVEL SECURITY;
ALTER TABLE webhooks          FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_log         FORCE ROW LEVEL SECURITY;
ALTER TABLE support_messages  FORCE ROW LEVEL SECURITY;
ALTER TABLE files             FORCE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens    FORCE ROW LEVEL SECURITY;

-- 4. Grant CRUD to the app role (it no longer owns tables)
GRANT SELECT, INSERT, UPDATE, DELETE
  ON tenants, users, refresh_tokens, accounts, invoices,
     loan_applications, transfers, ledger_entries, webhooks,
     files, audit_log, support_messages
  TO lendstack_app;

-- 5. Defense in depth: app role must not have BYPASSRLS
ALTER ROLE lendstack_app NOBYPASSRLS;

COMMIT;
