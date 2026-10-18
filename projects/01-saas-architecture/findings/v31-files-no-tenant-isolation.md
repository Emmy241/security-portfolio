# V-31: Files Table Missing Tenant Isolation (High)

| Field | Value |
|---|---|
| **ID** | V-31 |
| **Title** | `files` table has no `tenant_id`: cross-tenant metadata and path disclosure |
| **Severity** | High |
| **CVSS 3.1** | 6.5 (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`) |
| **CWE** | CWE-284: Improper Access Control |
| **Component** | `infra/postgres/init/02-schema.sql` (`files` table), `target-app/src/repositories/files.js` |
| **Endpoint** | `GET /api/v1/files/:id` |
| **Status** | Confirmed exploitable |
| **Requires** | An authenticated session (any tenant, any role) |

**Contents:** [Summary](#summary) · [Evidence](#evidence) · [Root cause](#root-cause) · [Fix](#fix) · [Verification test](#verification-test) · [Why V-31 is distinct](#why-v-31-is-distinct-from-v-10-and-v-32) · [Related findings](#related-findings) · [Evidence files](#evidence-files)

---

## Summary

The `files` table has no `tenant_id` column. Tenant association is only available indirectly via `invoice_id → invoices.tenant_id`. Three failures combine to make file metadata readable across tenant boundaries:

1. **Schema-level:** `files` has no `tenant_id`. A first-class scoping column is missing. The only way to scope is a JOIN, and only if the query performs it.
2. **RLS-level:** the RLS policy on `files` uses the invoice join (`invoice_id IN (SELECT id FROM invoices WHERE tenant_id = current_tenant())`). Even if V-30 were fixed, this policy is weaker than a first-class column: the join is more expensive and easier to get wrong in a query.
3. **Query-level:** `downloadFile` in `repositories/files.js` uses `req.pool.query` directly instead of `req.withTenant`. It bypasses the tenant middleware entirely. Combined with V-30 (RLS inert), the query has **no tenant context at all** and returns any file by ID.

**Impact:** an authenticated user from any tenant can read file metadata for files belonging to other tenants, including the filename and full on-disk `storage_path`. In a system where the `storage_path` becomes a signed download URL (or is used to read the file directly from disk), this is a **full cross-tenant file read**, not just metadata disclosure.

---

## Evidence

```bash
TOKEN_A=$(curl -s -X POST localhost:3000/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"owner@acme-lending.test","password":"Password123!"}' | jq -r .access_token)

BETA_FILE="b0000001-0000-4000-8000-000000000801"

curl -s -H "Authorization: Bearer $TOKEN_A" \
  localhost:3000/api/v1/files/$BETA_FILE | jq .
```

**Response: HTTP 200**

```json
{
  "file": {
    "filename": "contract-2001.pdf",
    "content_type": "application/pdf",
    "storage_path": "/var/lendstack/files/b/2001.pdf"
  }
}
```

The caller is authenticated to **Acme** (`tenant_id` `a0000001-...`). The file belongs to **Beta Credit** (`tenant_id` `b0000001-...`).

### What leaks

| Field | Sensitivity |
|---|---|
| `filename` | Beta's contract identifier (`contract-2001.pdf`): reveals client naming and document lifecycle |
| `content_type` | `application/pdf`: minor on its own, but reveals document class |
| `storage_path` | **`/var/lendstack/files/b/2001.pdf`**: discloses on-disk layout, tenant directory structure (`/b/`), and the file's physical location |

The `storage_path` disclosure is the escalation vector. If the endpoint ever served the file by reading `storage_path` from disk (a common pattern), or if the caller can probe adjacent paths, the exposure becomes full file content, not metadata.

---

## Root cause

Three failures, in severity order.

### 1. Schema: no `tenant_id` on `files`

`infra/postgres/init/02-schema.sql`:

```sql
CREATE TABLE files (
  id            uuid PRIMARY KEY,
  invoice_id    uuid NOT NULL REFERENCES invoices(id),
  filename      text NOT NULL,
  content_type  text NOT NULL,
  storage_path  text NOT NULL,
  uploaded_by   uuid NOT NULL REFERENCES users(id),
  created_at    timestamptz NOT NULL DEFAULT now()
);
```

Tenant association is only reachable through `invoice_id`. Any query that doesn't join through `invoices` has no way to filter by tenant, and there is no column that RLS could target without a subquery.

### 2. RLS: policy is a join, not a column

`infra/postgres/init/03-rls.sql`:

```sql
CREATE POLICY files_iso ON files
  USING (invoice_id IN (SELECT id FROM invoices WHERE tenant_id = current_tenant()));
```

Correct as far as it goes, but it only fires if RLS fires at all (V-30), and only if the query runs in a session with `app.tenant_id` set. Both preconditions fail here.

### 3. Query: bypasses the middleware

`target-app/src/repositories/files.js`:

```js
async function downloadFile(req, fileId) {
  const { rows } = await req.pool.query(       // ← bypasses req.withTenant
    `SELECT id, invoice_id, filename, content_type, storage_path
     FROM files
     WHERE id = $1`,                            // ← no tenant filter
    [fileId]
  );
  ...
}
```

Using `req.pool` instead of `req.withTenant` means:

- No `BEGIN`, so there is no transaction to set `app.tenant_id` on.
- No `SET app.tenant_id`, so RLS has nothing to evaluate against even if it were enabled.
- The query runs on the pooled connection with whatever `app.tenant_id` the last request set (or none, if it is a fresh connection).

This is the **V-32 pattern**: the middleware exists, the route is wired to it, and the repository ignores it. V-31 is the same class of bug, with the schema-level absence of `tenant_id` making it structurally harder to fix.

---

## Fix

Four changes, applied together.

### 1. Schema: add `tenant_id` to `files`

```sql
ALTER TABLE files ADD COLUMN tenant_id uuid REFERENCES tenants(id);

-- Backfill from the invoice join
UPDATE files f
SET tenant_id = i.tenant_id
FROM invoices i
WHERE f.invoice_id = i.id;

-- Make it NOT NULL to prevent future inserts from forgetting it
ALTER TABLE files ALTER COLUMN tenant_id SET NOT NULL;

-- Index for tenant-scoped queries
CREATE INDEX files_tenant_id_idx ON files (tenant_id);
```

### 2. RLS: policy uses the column, not a join

```sql
DROP POLICY files_iso ON files;

CREATE POLICY files_iso ON files
  USING (tenant_id = current_tenant())
  WITH CHECK (tenant_id = current_tenant());
```

The policy is now a single column comparison: faster, and structurally impossible to bypass via a forgotten join.

### 3. Query: use the middleware

```js
async function downloadFile(req, fileId) {
  return req.withTenant(async (client) => {
    const { rows } = await client.query(
      `SELECT id, invoice_id, filename, content_type, storage_path
       FROM files
       WHERE id = $1 AND tenant_id = $2`,     // ← defense in depth
      [fileId, req.user.tenant_id]
    );
    if (rows.length === 0) return null;
    return { ... };
  });
}
```

Both layers are applied: the `AND tenant_id = $2` filter (application-level defense) and the now-functional RLS (infrastructure-level defense). If either layer is present, the other catches the failure.

### 4. CI check: enforce the schema shape

Add to the CI check (from V-30's fix) a rule: **every table whose name is in the tenant-scoped set must have a `tenant_id` column of type `uuid NOT NULL`.**

```sql
-- Fails if any table in the tenant-scoped set lacks tenant_id
SELECT c.relname
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind = 'r'
  AND c.relname IN ('files','invoices','users','accounts','transfers',
                    'ledger_entries','webhooks','audit_log','support_messages')
  AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = c.relname
      AND column_name = 'tenant_id'
      AND data_type = 'uuid'
      AND is_nullable = 'NO'
  );
-- Expected output: zero rows. Any row = CI failure.
```

This is what prevents the bug from recurring. V-31 is a schema-level finding, and the CI check enforces the schema shape at the layer where the finding lives.

---

## Verification test

After the fix, the same request must return **404**:

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer $TOKEN_A" \
  localhost:3000/api/v1/files/b0000001-0000-4000-8000-000000000801
# Expected: 404
```

And the positive case (Acme's own file) must still return **200**:

```bash
ACME_FILE="a0000001-0000-4000-8000-000000000801"
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer $TOKEN_A" \
  localhost:3000/api/v1/files/$ACME_FILE
# Expected: 200
```

The negative case proves the fix blocks the cross-tenant read. The positive case proves the fix doesn't over-block same-tenant access. Both are required: a fix that 404s everything is a regression.

---

## Why V-31 is distinct from V-10 and V-32

The findings overlap enough that the differences are worth stating explicitly:

| Finding | Root cause | Fix location |
|---|---|---|
| **V-10** | Missing `WHERE tenant_id` filter in an otherwise-correct route | Application layer (SQL) |
| **V-32** | Route uses `req.pool` instead of `req.withTenant`: same code shape as V-31's query bug | Application layer (middleware usage) |
| **V-31** | (a) Schema has no `tenant_id` column, **and** (b) route uses `req.pool`, **and** (c) RLS policy is a join not a column | Schema + application + RLS |

V-31 is the only one that requires a **schema migration**. V-10 and V-32 are fixable with code changes; V-31 requires `ALTER TABLE`, a backfill, and a new `NOT NULL` constraint. That makes it the hardest of the three, and the one where the CI check matters most: a schema-level absence is invisible to a code review that only looks at query syntax.

---

## Related findings

- **V-30 (RLS bypass):** the amplifying cause. V-31's query bug would be caught by RLS if V-30 were fixed. On its own (with V-30 fixed), V-31 would still be a scoping gap for any query that forgot the filter, but the blast radius would be one tenant, not all tenants.
- **V-32 (unscoped export):** same `req.pool`-vs-`req.withTenant` pattern. The two findings share a root cause (middleware exists, repository bypasses it) and share a systematic fix (lint rule: no direct `pool.query` from repositories).
- **V-10 (IDOR):** different endpoint, same class. V-10 is a missing filter; V-31 is a missing column. Both are "the tenant boundary wasn't enforced at this route."

---

## Evidence files

| File | Shows |
|---|---|
| `evidence/v31-cross-tenant-file.json` | 200 response with Beta's file metadata and storage path |
| `evidence/v31-own-tenant-file.json` | 200 response with Acme's file (positive case, for post-fix comparison) |
| `evidence/v31-fixed-cross-tenant.json` | 404 after fix (verification) |
| `evidence/v31-fixed-own-tenant.json` | 200 after fix (verification) |
| `evidence/v31-schema-before.txt` | `\d files` showing the missing `tenant_id` column |
| `evidence/v31-schema-after.txt` | `\d files` after the migration, showing the column present and indexed |
