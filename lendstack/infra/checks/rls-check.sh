#!/usr/bin/env bash
# infra/checks/rls-check.sh
# CI check: fails if tenant isolation invariants are violated.
#
# Checks three things on every tenant-scoped table:
#   1. The app role (lendstack_app) does NOT own the table.
#   2. FORCE ROW LEVEL SECURITY is set.
#   3. The app role does NOT have BYPASSRLS.
#
# Exit: 0 = pass, 1 = fail (with violation details on stderr).
#
# Run from the lendstack/ directory (uses docker compose exec).

set -euo pipefail

run_sql() {
  docker compose exec -T postgres psql -U postgres -d lendstack -tA -c "$1"
}

fail=0
failures=()

TENANT_TABLES="'tenants','users','refresh_tokens','accounts','invoices',
  'loan_applications','transfers','ledger_entries','webhooks',
  'files','audit_log','support_messages'"

# Check 1: no tenant-scoped table is owned by the app role
OWNED_BY_APP=$(run_sql "
  SELECT c.relname
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_roles r ON r.oid = c.relowner
  WHERE n.nspname = 'public' AND c.relkind = 'r'
    AND r.rolname = 'lendstack_app'
    AND c.relname IN ($TENANT_TABLES)
  ORDER BY 1;")

if [ -n "$OWNED_BY_APP" ]; then
  fail=1
  failures+=("Tables owned by lendstack_app (should be lendstack_owner):")
  while IFS= read -r t; do
    failures+=("  - $t")
  done <<< "$OWNED_BY_APP"
fi

# Check 2: FORCE RLS on every tenant-scoped table with RLS enabled
NOT_FORCED=$(run_sql "
  SELECT c.relname
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND c.relkind = 'r'
    AND c.relrowsecurity = true
    AND NOT c.relforcerowsecurity
    AND c.relname IN ($TENANT_TABLES)
  ORDER BY 1;")

if [ -n "$NOT_FORCED" ]; then
  fail=1
  failures+=("Tables with RLS but NOT FORCE (owner bypasses policies):")
  while IFS= read -r t; do
    failures+=("  - $t")
  done <<< "$NOT_FORCED"
fi

# Check 3: app role must not have BYPASSRLS
HAS_BYPASS=$(run_sql "
  SELECT rolname FROM pg_roles
  WHERE rolname = 'lendstack_app' AND rolbypassrls = true;")

if [ -n "$HAS_BYPASS" ]; then
  fail=1
  failures+=("Role lendstack_app has BYPASSRLS (should be off):")
  failures+=("  - lendstack_app")
fi

# Report
if [ "$fail" -eq 1 ]; then
  echo "FAIL: tenant isolation invariants violated" >&2
  for line in "${failures[@]}"; do
    echo "$line" >&2
  done
  echo "" >&2
  echo "Apply infra/migrations/001-fix-v30-tenant-ownership.sql to remediate." >&2
  exit 1
fi

echo "PASS: all tenant isolation invariants hold"
