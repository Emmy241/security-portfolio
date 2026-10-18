# V-30: Tenant Isolation Bypass via Table Ownership (Critical)

| Field | Value |
|---|---|
| **ID** | V-30 |
| **Title** | App role owns RLS-enabled tables → RLS silently bypassed |
| **Severity** | Critical |
| **CVSS 3.1** | 8.1 (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`) |
| **CWE** | CWE-284: Improper Access Control |
| **Component** | `infra/postgres/init/02-schema.sql`, `03-rls.sql` |
| **Status** | Confirmed. Every tenant-scoped table affected. |
| **Category** | Infrastructure / database-layer tenant isolation |

**Contents:** [Summary](#summary) · [Impact](#impact) · [Reproduction](#reproduction) · [Root cause](#root-cause) · [Fix](#fix) · [Verification test](#verification-test) · [Why this finding matters most](#why-this-finding-matters-more-than-the-sum-of-the-others) · [Evidence files](#evidence-files)

---

## Summary

Every tenant-scoped table in LendStack has RLS enabled and a policy of the form `USING (tenant_id = current_tenant())`. The policies are syntactically correct. They do not fire.

The application's database role (`lendstack_app`) is the **owner** of every table. Postgres bypasses RLS policy evaluation for the table owner unless `ALTER TABLE ... FORCE ROW LEVEL SECURITY` is set. LendStack never sets `FORCE`, so:

- RLS is "on" (`relrowsecurity = t`).
- The policy exists and is correct.
- Queries from the app role see **all tenants' rows**, always.

This is the single most consequential finding in the architecture review, because it silently undermines **every defense-in-depth claim** at higher layers: the middleware correctly sets `app.tenant_id` per request (see `tenancy/middleware.js`), the RLS policies are written by the book, and the result is still total cross-tenant data exposure.

---

## Impact

**Confidentiality:** an authenticated user from any tenant can read every row in `invoices`, `accounts`, `loan_applications`, `transfers`, `ledger_entries`, `files` (metadata), `webhooks`, `audit_log`, `support_messages`. `users` too, which is the full tenant roster with role assignments.

**Integrity:** writes and updates are equally unscoped. An analyst from tenant A can `UPDATE invoices` and mutate tenant B's rows, because the RLS `WITH CHECK` clause doesn't fire for the owner either.

**Downstream consequences**

| Finding | How V-30 affects it |
|---|---|
| **V-10 (IDOR)** | Exploitable because the app-level query lacks a tenant filter *and* the RLS layer doesn't catch it. Fixing V-10 alone leaves a system where the next forgotten filter becomes the next IDOR. Fixing V-30 makes every correctly written middleware layer effective again. |
| **V-31 (files)** | Exploitable because `files` has no `tenant_id`, and even the invoice-join policy is inert. |
| **V-32 (export)** | Demonstrates the middleware-bypass class of bug, but it is *amplified* by V-30: even routes that do use the middleware are exposed, so an inconsistency between routes is currently invisible. Every route leaks. |

---

## Reproduction

```bash
docker compose exec -T postgres psql -U lendstack_app -d lendstack <<'SQL'
SET app.tenant_id = 'a0000001-0000-4000-8000-000000000001';
SELECT tenant_id, count(*) FROM invoices GROUP BY tenant_id ORDER BY tenant_id;
SQL
```

| | Result |
|---|---|
| **Expected (secure)** | 1 row: the tenant in `app.tenant_id` |
| **Actual** | 3 rows: every tenant in the system |

---

## Root cause

`infra/postgres/init/02-schema.sql` ends with:

```sql
ALTER TABLE invoices           OWNER TO lendstack_app;
-- ...every other tenant table reassigned to lendstack_app
```

`infra/postgres/init/03-rls.sql` enables RLS and creates policies but never runs:

```sql
ALTER TABLE invoices FORCE ROW LEVEL SECURITY;
```

Without `FORCE`, the owner bypass is Postgres's documented behaviour. It is not a bug in Postgres; it is a configuration footgun that requires an explicit opt-out to be safe, and the default is "unsafe."

---

## Fix

Three changes, applied together.

### 1. Reassign ownership away from the app role

The app role should have `SELECT, INSERT, UPDATE, DELETE` privileges, not ownership.

```sql
CREATE ROLE lendstack_owner NOINHERIT;  -- owns tables, not used by app
ALTER TABLE invoices OWNER TO lendstack_owner;
-- ...all tenant-scoped tables
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO lendstack_app;
```

### 2. Add `FORCE` on every tenant-scoped table

This is defense in depth: even if a future migration accidentally regrants ownership to the app role, `FORCE` keeps RLS applying to owners.

```sql
ALTER TABLE invoices FORCE ROW LEVEL SECURITY;
-- ...all tenant tables
```

### 3. Enforce both in CI

Add a script that queries `pg_class.relowner`, `pg_roles.rolbypassrls`, and `pg_class.relforcerowsecurity`, and fails the build on any tenant table where owner = app role or force = false.

With all three in place, the middleware in `tenancy/middleware.js` (which correctly sets `app.tenant_id`) actually takes effect. No application code change is required. That is the point of the finding: the vulnerability is entirely in the DB layer, and the fix is entirely in the DB layer.

---

## Verification test

After the fix, the reproduction query must return **1 row**. Then, additionally:

```sql
-- Confirm FORCE is set
SELECT c.relname, r.rolname AS owner, c.relforcerowsecurity
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_roles r ON r.oid = c.relowner
WHERE n.nspname = 'public' AND c.relkind = 'r'
  AND c.relname IN ('invoices','users','transfers','files');
-- All rows: owner != lendstack_app, relforcerowsecurity = t
```

```sql
-- Confirm BYPASSRLS is not held by the app role
SELECT rolname, rolbypassrls FROM pg_roles WHERE rolname = 'lendstack_app';
-- Expected: f
```

The three checks together (one for RLS behaviour, one for `FORCE` state, one for role privileges) are the CI check. It is not enough to say "we have RLS"; the CI check is what makes the claim maintainable.

---

## Why this finding matters more than the sum of the others

Every other tenant-isolation finding in this review (V-10, V-31, V-32, V-33) is a route-level or query-level bug. They are each individually fixable. V-30 is a platform-level bug: it makes correct code incorrect.

A security review that reports V-10 (IDOR on `/invoices/:id`) as Critical and V-30 as a note has the priority backward. The right remediation order is:

1. **Fix V-30 first.** Every other tenant-isolation finding becomes easier to test, easier to verify, and easier to keep fixed once V-30 is closed.
2. **Fix V-10, V-31, V-32 next.** The app-layer filters are still needed even with RLS working, because of the middleware-bypass pattern in V-32.
3. **Add CI** so the configuration cannot drift.

Doing them in the opposite order (fixing every route and leaving V-30) is the exact failure mode that lets the bug come back. A single forgotten filter becomes a new IDOR, and the RLS layer that was supposed to catch it still isn't catching it.

---

## Evidence files

| File | Shows |
|---|---|
| `evidence/before/rls-bypass.png` | 3-row cross-tenant query, pre-fix |
| `evidence/before/rls-ownership.png` | Ownership table showing the app role owns all tables |
| `evidence/after/rls-bypass.png` | 1-row query, post-fix (on `secure-reference` branch) |
| `evidence/after/ci-check-fail.png` | CI check failing on `main` (as designed) |
| `evidence/after/ci-check-pass.png` | Same CI check passing on `secure-reference` |
