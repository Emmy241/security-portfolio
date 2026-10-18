# V-32: Admin Export Bypasses Tenant Middleware (High)

| Field | Value |
|---|---|
| **ID** | V-32 |
| **Title** | Bulk export endpoint returns all tenants' invoices: bypasses tenant middleware |
| **Severity** | High |
| **CVSS 3.1** | 6.5 (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`) |
| **CWE** | CWE-863: Incorrect Authorization |
| **OWASP** | A01:2021: Broken Access Control |
| **Component** | `target-app/src/admin/export.js` → `exportInvoices`; `GET /api/v1/admin/export` |
| **Status** | Confirmed exploitable |
| **Requires** | An authenticated session with `role='owner'` (any tenant) |

**Contents:** [Summary](#summary) · [Evidence](#evidence) · [Root cause](#root-cause) · [The V-32 pattern](#why-this-finding-is-the-v-32-pattern) · [Fix](#fix) · [Verification test](#verification-test) · [Distinction from V-10 and V-31](#distinction-from-v-10-and-v-31) · [Related findings](#related-findings) · [Evidence files](#evidence-files)

---

## Summary

`GET /api/v1/admin/export` is route-gated by `requireAuth` and `attachTenant`, and additionally checks `req.user.role === 'owner'`. The route handler **looks correctly protected**: it has all three expected controls in its middleware chain.

The repository behind it (`admin/export.js` → `exportInvoices`) calls `req.pool.query()` directly instead of `req.withTenant(...)`. That skips the per-request transaction that sets `app.tenant_id`. The query is:

```sql
SELECT id, tenant_id, number, amount_cents, status, due_date
FROM invoices
ORDER BY created_at DESC
```

There is no `WHERE tenant_id` filter and no use of `req.withTenant`. The middleware that ran earlier in the chain has no effect, because `attachTenant` only prepares `req.withTenant`; it does nothing until a repository calls it.

**Impact:** any tenant owner can export the complete invoice set across all tenants in the system. In LendStack (3 tenants, 15 invoices), that is 15 rows / ~3KB of cross-tenant financial records in a single authenticated GET. In a production lending platform, that is the entire customer and transaction book for the platform, in one request.

---

## Evidence

```bash
TOKEN_A=$(curl -s -X POST localhost:3000/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"owner@acme-lending.test","password":"Password123!"}' | jq -r .access_token)

curl -s -H "Authorization: Bearer $TOKEN_A" \
  localhost:3000/api/v1/admin/export \
  | jq '{count: (.invoices | length), tenants: (.invoices | map(.tenant_id) | unique)}'
```

**Response: HTTP 200**

```json
{
  "count": 15,
  "tenants": [
    "a0000001-0000-4000-8000-000000000001",
    "b0000001-0000-4000-8000-000000000001",
    "c0000001-0000-4000-8000-000000000001"
  ]
}
```

Response size: **2969 bytes** (captured in `v32-raw-response.json`).

An Acme-tenant owner (`tenant_id` `a0000001-...`) received 15 invoices spanning **all three tenants**. The `/admin/export` endpoint was designed for a specific business need, a per-tenant invoice export for month-end reconciliation. It returns the full platform dataset instead.

---

## Root cause

The route is correctly wired:

```js
app.get('/api/v1/admin/export', requireAuth, attachTenant, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ error: 'forbidden' });
  const rows = await exportInvoices(req);
  ...
});
```

`requireAuth` validates the JWT. `attachTenant` attaches `req.withTenant`, which, if called, sets `app.tenant_id` for the query. The role check confirms the caller is an owner.

The repository ignores the middleware:

```js
async function exportInvoices(req) {
  const { rows } = await req.pool.query(       // ← bypasses req.withTenant
    `SELECT id, tenant_id, number, amount_cents, status, due_date
     FROM invoices
     ORDER BY created_at DESC`
  );
  return rows;
}
```

Three things had to go wrong to reach the leak:

1. **`req.pool` used instead of `req.withTenant`.** The middleware prepared `req.withTenant` but the repository didn't call it. `attachTenant` has no effect on `req.pool`; it only sets `req.withTenant` as an available helper.

2. **No `WHERE tenant_id` filter.** Same class of missing-filter bug as V-10, but in a different route. Even if `req.withTenant` had been used, the RLS layer would have caught it, but the middleware wasn't called.

3. **RLS inert (V-30).** The final defense-in-depth layer, the RLS policy `invoices_iso USING (tenant_id = current_tenant())`, would have caught the query if it fired. It doesn't, because the app role owns the table. So even without `app.tenant_id` set on the connection, RLS returns all rows.

Any one of these three being present would have prevented the cross-tenant leak:

- If `req.withTenant` had been called → `app.tenant_id` set → RLS would filter (if it worked).
- If the query had `WHERE tenant_id = $2` → the application-layer filter applies regardless of RLS.
- If V-30 were fixed → RLS would filter even without `app.tenant_id` (though with an empty setting it would return 0 rows, which is itself the correct fail-closed behavior).

The fact that all three failed simultaneously is what makes this exploitable. **This is the exact reason defense-in-depth is described as a claim rather than a fact:** three layers existed, and all three had a hole.

---

## Why this finding is the "V-32 pattern"

V-32 is a distinct, specific pattern worth naming: **the middleware is present in the route chain but the repository bypasses it.** It's not a missing middleware, and it's not a missing authorization check. It's a correctly configured chain that fails at the last step.

This happens frequently because:

- `attachTenant` looks like it does scoping: a reviewer sees it in the route and assumes scoping is handled.
- The repository is a separate file: a reviewer checking the route doesn't necessarily open the repository.
- `req.pool` and `req.withTenant` are one typo apart, and `req.pool` is shorter to write.

The pattern is why a lint rule (below) is the right fix, not just patching this one route. A grep for `.pool.query` in repository files would catch every instance.

---

## Fix

Four changes, in order of leverage.

### 1. Use the middleware in the repository

```js
async function exportInvoices(req) {
  // withTenant sets app.tenant_id; the explicit WHERE is defense in depth.
  return req.withTenant(async (client) => {
    const { rows } = await client.query(
      `SELECT id, tenant_id, number, amount_cents, status, due_date
       FROM invoices
       WHERE tenant_id = $1
       ORDER BY created_at DESC`,
      [req.user.tenant_id]
    );
    return rows;
  });
}
```

Two fixes in one: it uses `req.withTenant` (so `app.tenant_id` is set) and adds the SQL filter (so even if the middleware breaks, the query is scoped).

### 2. Fix V-30

The RLS layer needs to actually fire (see V-30's fix). With V-30 fixed, `req.withTenant` becomes effective: the query above would return only Acme's rows even if someone removed the `WHERE tenant_id` clause.

### 3. Lint rule: no direct `pool.query` in repositories

Add to the repo's CI pipeline:

```bash
# Fail the build if any file under src/repositories/ or src/admin/ or
# src/money/ imports the pool directly or calls req.pool.query.
if grep -rn 'req\.pool\.query\|require(.*db.*).query' \
     target-app/src/repositories/ \
     target-app/src/admin/ \
     target-app/src/money/; then
  echo "ERROR: repositories must use req.withTenant, not req.pool"
  exit 1
fi
```

This is a short shell script that would have caught V-32, V-31, and every future variant of the same bug. **The lint rule is the actual remediation; the code change fixes this instance.**

### 4. Route-level test coverage

Add an integration test asserting that `GET /api/v1/admin/export` returns only the caller's tenant's invoices, regardless of how many tenants exist in the seed. This test would fail on the current code and pass after the fix. CI runs it on every push.

---

## Verification test

After the fix, the same request must return only Acme's invoices:

```bash
curl -s -H "Authorization: Bearer $TOKEN_A" \
  localhost:3000/api/v1/admin/export \
  | jq '{count: (.invoices | length), tenants: (.invoices | map(.tenant_id) | unique)}'
```

**Expected after fix:**

```json
{
  "count": 5,
  "tenants": [
    "a0000001-0000-4000-8000-000000000001"
  ]
}
```

5 invoices, 1 tenant. The cross-tenant export is closed.

Also confirm the positive case: Beta's owner can still export Beta's invoices.

```bash
TOKEN_B=$(curl -s -X POST localhost:3000/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"owner@beta-credit.test","password":"Password123!"}' | jq -r .access_token)

curl -s -H "Authorization: Bearer $TOKEN_B" \
  localhost:3000/api/v1/admin/export \
  | jq '{count: (.invoices | length), tenants: (.invoices | map(.tenant_id) | unique)}'
```

**Expected after fix:**

```json
{
  "count": 5,
  "tenants": [
    "b0000001-0000-4000-8000-000000000001"
  ]
}
```

Both tests are required: the negative (no cross-tenant) and the positive (own-tenant still works). A fix that returns 0 rows for everyone is a regression, not a fix.

---

## Distinction from V-10 and V-31

| Finding | Where the bypass lives | Fix |
|---|---|---|
| **V-10** | SQL missing `AND tenant_id = $2` in an otherwise-correct repository | Application layer (one-line SQL change) |
| **V-31** | Schema has no `tenant_id` **and** repository uses `req.pool` | Schema migration + query change |
| **V-32** | Repository uses `req.pool` in a route that otherwise correctly wires middleware | Query change + lint rule |

V-32 is the "purest" instance of the middleware-bypass pattern: no schema issue, no missing route wiring, just a repository that took the wrong connection object. That's why the **lint rule** is the load-bearing fix here. V-10-style bugs are caught by code review (someone sees the missing filter). V-32-style bugs are often missed by code review because the route *looks* correct; the bug is one level deeper.

The lint rule is the general control that survives future code changes, team turnover, and forgotten context.

---

## Related findings

- **V-30 (RLS bypass):** the amplifying cause. Without V-30, the RLS layer would have caught V-32's query at the database level. V-32 demonstrates what "defense in depth is broken" looks like in practice: three layers configured, all three non-functional, and the code that triggers all three failures looks perfectly reasonable.
- **V-31 (files no tenant isolation):** same `req.pool`-vs-`req.withTenant` pattern. The two findings share a lint-rule fix. Fixing V-32 without fixing V-31 leaves the same class of bug live on a different endpoint.
- **V-10 (IDOR on invoices):** different class (single-record cross-tenant read vs. bulk export), same underlying "tenant boundary not enforced" root cause.

Taken together, these three findings are the argument for the CI check and lint rule as the *primary* remediation. Patching each bug individually leaves the system vulnerable to the next one written, and given how mundane the code shape is, that next one is guaranteed to be written by someone, eventually.

---

## Evidence files

| File | Shows |
|---|---|
| `evidence/v32-cross-tenant-export.json` | The `jq` summary: `{"count": 15, "tenants": [a, b, c]}` |
| `evidence/v32-raw-response.json` | The full 2969-byte response (raw, unprocessed, for independent review) |
| `evidence/v32-fixed-export.json` | Post-fix: `{"count": 5, "tenants": [a]}` (captured on `secure-reference` branch) |
| `evidence/v32-lint-rule-fail.png` | CI failing on `main` (as designed: the lint rule catches the pattern) |
| `evidence/v32-lint-rule-pass.png` | CI passing on `secure-reference` (pattern removed) |
