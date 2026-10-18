-- 002-fix-login-rls.sql
-- Companion to 001-fix-v30-tenant-ownership.sql.
--
-- V-30's fix enforces RLS on `users`. That breaks login: the login route
-- must find a user by email BEFORE knowing their tenant, so the query runs
-- without app.tenant_id set and RLS returns 0 rows.
--
-- Fix: a second policy (policies OR together for SELECT) that allows
-- email-based lookup only while app.login_email is set. That setting is
-- transaction-local — it disappears at COMMIT/ROLLBACK — so it's only
-- effective during the login handler's transaction, never for any other
-- query on the same connection.
--
-- Documented as V-35 in findings/. This is the "fix exposed a second bug"
-- case, and the reason RLS migrations break production auth in real life.

BEGIN;

CREATE POLICY users_login_lookup ON users
  FOR SELECT
  USING (email = current_setting('app.login_email', true));

COMMIT;
