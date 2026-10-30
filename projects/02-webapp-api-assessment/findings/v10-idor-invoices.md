# V-10 — IDOR on GET /api/v1/invoices/:id

| Field | Value |
|---|---|
| **Severity** | High (CVSS 7.1) |
| **CWE** | CWE-639 — Authorization Bypass Through User-Controlled Key |
| **Endpoint** | `GET /api/v1/invoices/:id` |
| **Component** | `target-app/src/repositories/invoices.js` |
| **Status** | Confirmed exploitable |

## Summary
The endpoint to retrieve an invoice by its UUID does not check if the requesting user belongs to the same tenant as the invoice. The SQL query filters only by `id` and omits the `tenant_id`. RLS was intended to catch this, but was inert due to V-30. An attacker authenticated to Tenant A can read Tenant B's invoices by iterating or guessing UUIDs.

## Evidence
1. Authenticate as Acme (Tenant A).
2. Request an invoice that belongs to Beta (Tenant B).

curl -s -H "Authorization: Bearer $TOKEN_A" localhost:3000/api/v1/invoices/b0000001-0000-4000-8000-000000000301 | jq .

Response is 200 OK with Beta's data:
{
  "invoice": {
    "id": "b0000001-0000-4000-8000-000000000301",
    "tenant_id": "b0000001-0000-4000-8000-000000000001",
    "number": "INV-B-2001",
    "amount_cents": "98000"
  }
}

## Root Cause
The invoices repository omits the tenant filter:
const { rows } = await client.query(
  `SELECT id, tenant_id, account_id, number, amount_cents FROM invoices WHERE id = $1`,
  [id]
);
App-layer authorization is missing, and the RLS backstop was bypassed.

## Fix
Add the tenant filter to the SQL query:
const { rows } = await client.query(
  `SELECT id, tenant_id, account_id, number, amount_cents FROM invoices WHERE id = $1 AND tenant_id = $2`,
  [id, req.user.tenant_id]
);
Also, fix V-30 (RLS bypass) so that the DB acts as a reliable backstop.
