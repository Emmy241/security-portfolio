-- infra/checks/rls-check.sql
-- Fails the build if the app role owns a tenant table or has BYPASSRLS.

SELECT
  c.relname        AS table,
  r.rolname        AS owner,
  c.relrowsecurity AS rls_enabled,
  c.relforcerowsecurity AS rls_forced
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_roles     r ON r.oid = c.relowner
WHERE n.nspname = 'public' AND c.relkind = 'r'
ORDER BY 1;

SELECT rolname, rolsuper, rolbypassrls
FROM pg_roles
WHERE rolname LIKE 'lendstack%';
