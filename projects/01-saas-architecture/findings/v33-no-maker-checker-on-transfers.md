# V-33: No Maker-Checker on Money Movement (Critical)

| Field | Value |
|---|---|
| **ID** | V-33 |
| **Title** | Transfer approval has no maker-checker enforcement: self-approval permitted |
| **Severity** | Critical |
| **CVSS 3.1** | 8.1 (`AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`) |
| **CWE** | CWE-863: Incorrect Authorization |
| **OWASP** | A01:2021: Broken Access Control |
| **Component** | `target-app/src/money/transfers.js` → `approveTransfer`; `POST /api/v1/transfers/:id/approve` |
| **Status** | Confirmed exploitable |
| **Requires** | An authenticated session with transfer-approval permission (any tenant) |

**Contents:** [Summary](#summary) · [Evidence](#evidence) · [Root cause](#root-cause) · [Fix](#fix) · [Verification test](#verification-test) · [Why Critical](#why-v-33-is-critical-while-v-31v-32-are-high) · [Compliance implications](#compliance-implications) · [Related findings](#related-findings) · [Detection opportunity](#detection-opportunity) · [Evidence files](#evidence-files)

---

## Summary

The transfer workflow has a two-stage shape: `POST /transfers` creates a transfer in `status='pending'`, and `POST /transfers/:id/approve` moves it to `status='approved'`. The schema stores both `created_by` and `approved_by`, so the data model *looks* like it enforces segregation of duties.

It doesn't. There is no check that `approved_by != created_by`, at either the application layer or the database layer. A single authenticated user can create a transfer and immediately approve it, with no second party involved.

**Impact:** in a lending platform, this is the control that prevents a single insider from moving funds and stamping "approved" on the action. It's what turns one malicious actor into a two-person conspiracy. Without it, the person who wants to steal is the person who confirms that stealing is allowed.

In the seed data, transfers move between a tenant's own `operating` and `reserve` accounts, so the lab demo doesn't drain another tenant's money. But the **approval gate is the same code path** in a real transfer flow, where the money leaves the platform to an external account. The absence of a maker-checker check here is the absence of a maker-checker check everywhere.

---

## Evidence

```bash
TOKEN_A=$(curl -s -X POST localhost:3000/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"owner@acme-lending.test","password":"Password123!"}' | jq -r .access_token)

# Same user creates and approves a transfer
TRANSFER_ID=$(curl -s -X POST localhost:3000/api/v1/transfers \
  -H "Authorization: Bearer $TOKEN_A" -H 'content-type: application/json' \
  -d '{"from_account_id":"a0000001-0000-4000-8000-000000000201",
       "to_account_id":"a0000001-0000-4000-8000-000000000202",
       "amount_cents":100000}' \
  | jq -r .transfer.id)

echo "Created:  $TRANSFER_ID"

curl -s -o /dev/null -w "Approve: %{http_code}\n" -X POST \
  -H "Authorization: Bearer $TOKEN_A" \
  localhost:3000/api/v1/transfers/$TRANSFER_ID/approve
```

**Response**

```
Created: 8c94f81e-52ea-43dd-8119-24a7834ab304
Approve: 204
```

`204` on the approve call, with the **same token** that created the transfer. No second identity involved.

### Database-level confirmation

The `204` proves the endpoint accepted the request. It doesn't prove the DB recorded a self-approval. The next query does:

```sql
SELECT id, created_by, approved_by, created_by = approved_by AS self_approved
FROM transfers WHERE id = '8c94f81e-52ea-43dd-8119-24a7834ab304';
```

**Result**

```
                  id                  |              created_by              |             approved_by              | self_approved
--------------------------------------+--------------------------------------+--------------------------------------+---------------
 8c94f81e-52ea-43dd-8119-24a7834ab304 | a0000001-0000-4000-8000-000000000101 | a0000001-0000-4000-8000-000000000101 | t
```

`self_approved = t`. Two identical UUIDs. The transfer was created and approved by the same user, and the database recorded it without complaint.

---

## Root cause

`target-app/src/money/transfers.js`:

```js
async function approveTransfer(req, transferId) {
  return req.withTenant(async (client) => {
    const { rows: existing } = await client.query(
      `SELECT status, created_by FROM transfers WHERE id = $1`,
      [transferId]
    );
    if (existing.length === 0) return { error: 'not_found' };
    if (existing[0].status !== 'pending') return { error: 'not_pending' };

    // V-33: no maker-checker check. req.user.id may equal created_by.
    await client.query(
      `UPDATE transfers SET status = 'approved', approved_by = $1 WHERE id = $2`,
      [req.user.id, transferId]
    );

    return { ok: true };
  });
}
```

The repository fetches `created_by`: **it knows the value**, and then does nothing with it. `req.user.id` is written to `approved_by` without any comparison against `created_by`. The approval is a single UPDATE with no guard.

The schema has no constraint either:

```sql
CREATE TABLE transfers (
  ...
  created_by    uuid NOT NULL REFERENCES users(id),
  approved_by   uuid REFERENCES users(id),      -- no CHECK constraint
  ...
);
```

A `CHECK (approved_by IS NULL OR approved_by != created_by)` constraint would have prevented the UPDATE from succeeding even though the application allowed it. Both layers failed.

### Why this is more serious than a missing `if` statement

1. **The data model implies a control that doesn't exist.** `created_by` and `approved_by` are separate columns; a reviewer looking at the schema sees two columns and assumes the separation is enforced. It isn't. The columns describe the *intent* of maker-checker; they don't implement it. This is the same pattern as V-30 (RLS enabled but inert) and V-31 (RLS policy correct but query bypasses it): configuration that reads as protection but doesn't protect.

2. **The absence of the check is intentional-looking code.** The repository *fetches* `created_by` in its SELECT. It could compare against it in one line. The developer who wrote this wrote code that knows the creator, and then chose not to check it. That's not a "forgot to add a control" bug; it's a control that was implicitly designed away. A code reviewer looking for `if (existing[0].created_by === req.user.id)` would flag the omission; a reviewer asking "does this follow maker-checker?" and reading only the columns would not.

---

## Fix

Three changes, applied at different layers.

### 1. Application-level check: the visible control

```js
async function approveTransfer(req, transferId) {
  return req.withTenant(async (client) => {
    const { rows: existing } = await client.query(
      `SELECT status, created_by FROM transfers WHERE id = $1`,
      [transferId]
    );
    if (existing.length === 0) return { error: 'not_found' };
    if (existing[0].status !== 'pending') return { error: 'not_pending' };

    // V-33 FIX: maker-checker. Approver must be a different user.
    if (existing[0].created_by === req.user.id) {
      return { error: 'self_approval_denied' };
    }

    await client.query(
      `UPDATE transfers SET status = 'approved', approved_by = $1 WHERE id = $2`,
      [req.user.id, transferId]
    );

    return { ok: true };
  });
}
```

And the route handler returns `403` on `self_approval_denied`:

```js
if (result.error === 'self_approval_denied') {
  return res.status(403).json({ error: 'self_approval_denied' });
}
```

### 2. Database-level constraint: the defense-in-depth control

The application check can be bypassed by any future route that writes to `transfers` and forgets the comparison. The database constraint cannot:

```sql
ALTER TABLE transfers
  ADD CONSTRAINT transfers_no_self_approval
  CHECK (approved_by IS NULL OR approved_by != created_by);
```

Now an `UPDATE transfers SET approved_by = created_by` is rejected by Postgres with `ERROR: new row for relation "transfers" violates check constraint "transfers_no_self_approval"`.

The application check is the **business logic** (clear error message, proper 403 response). The DB constraint is the **invariant** (cannot be bypassed by any code path, including migrations, scripts, or a future developer's forgotten check).

Both are required. The application check without the constraint fails on any alternate write path. The constraint without the application check fails silently: the user sees a 500, not a 403, and the SOC doesn't know whether it was an attempted attack or a bug.

### 3. Add a `transfer.approval_denied` audit event

For SIEM visibility (this ties back to #3's detection work), the self-approval attempt should emit an audit event:

```js
if (existing[0].created_by === req.user.id) {
  log({
    sourcetype: 'lendstack:money',
    event: 'transfer.approval_denied',
    tenant_id: req.user.tenant_id,
    actor_id: req.user.id,
    transfer_id: transferId,
    reason: 'self_approval',
    outcome: 'fail',
  });
  return { error: 'self_approval_denied' };
}
```

A would-be insider attempting self-approval is a **signal worth detecting**, not a routine error. #3 can then add a rule (LDS-MONEY-001) that fires on `transfer.approval_denied reason='self_approval'`. The log of the *attempt* is more valuable than the log of the successful transfer.

---

## Verification test

After the fix, self-approval must be blocked:

```bash
TRANSFER_ID=$(curl -s -X POST localhost:3000/api/v1/transfers \
  -H "Authorization: Bearer $TOKEN_A" -H 'content-type: application/json' \
  -d '{"from_account_id":"a0000001-0000-4000-8000-000000000201",
       "to_account_id":"a0000001-0000-4000-8000-000000000202",
       "amount_cents":100000}' \
  | jq -r .transfer.id)

curl -s -o /dev/null -w "Self-approve: %{http_code}\n" -X POST \
  -H "Authorization: Bearer $TOKEN_A" \
  localhost:3000/api/v1/transfers/$TRANSFER_ID/approve
# Expected: 403
```

And a different user can still approve:

```bash
# Auditor can approve: role sufficient, different user
TOKEN_AUD=$(curl -s -X POST localhost:3000/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"auditor@acme-lending.test","password":"Password123!"}' | jq -r .access_token)

curl -s -o /dev/null -w "Other-approve: %{http_code}\n" -X POST \
  -H "Authorization: Bearer $TOKEN_AUD" \
  localhost:3000/api/v1/transfers/$TRANSFER_ID/approve
# Expected: 204
```

Both are required: self-approval blocked, alternate-user approval works. A fix that blocks everyone is a regression.

Additionally, verify the DB constraint is live:

```bash
docker compose exec -T postgres psql -U lendstack_app -d lendstack -c "
UPDATE transfers
SET approved_by = created_by
WHERE id = '$TRANSFER_ID';"
# Expected: ERROR: new row for relation "transfers" violates check constraint
#           "transfers_no_self_approval"
```

The DB constraint is the load-bearing control; the application check is the user-facing one. Both must be verified independently.

---

## Why V-33 is Critical while V-31/V-32 are High

The severity distinction comes from **impact class**, not exploitability:

| Finding | Exploitability | Impact |
|---|---|---|
| V-31 | Any authenticated user | Cross-tenant metadata disclosure |
| V-32 | Any tenant owner | Cross-tenant invoice export (bulk read) |
| **V-33** | Any authenticated user with transfer permission | **Fund movement without oversight** |

V-31 and V-32 are **confidentiality** findings: sensitive data leaks. Serious, but the damaged party can be notified, and the data doesn't change hands.

V-33 is an **integrity** finding on a financial control. A transfer that moves money to an attacker-controlled account, self-approved, is:

- A loss of funds (real, not virtual)
- A reputational incident (customers and regulators)
- Potentially a criminal matter (the insider committed fraud, and the platform failed to detect the control gap)
- A compliance failure (segregation of duties is table stakes for PCI DSS 6.4.2, GLBA 314.4(c), and SOX ITGC)

The CVSS score reflects this: `C:N/I:H/A:N`, with no confidentiality or availability impact but **High integrity impact**. That's the difference between "someone read what they shouldn't have" and "someone moved the money."

---

## Compliance implications

This finding is documented separately in #1's compliance mapping, but it is worth calling out here because it maps to specific external requirements:

| Standard | Requirement | How V-33 violates it |
|---|---|---|
| **PCI DSS 4.0, 6.4.2** | "Deploy an automated technical solution that detects and prevents web-based attacks" (controls on payment page scripts) | Indirect: self-approval permits any transfer, including those that move payment data to attacker-controlled accounts |
| **GLBA, 314.4(c)(3)** | "Encrypt all customer information in transit and at rest" (access controls to financial records) | Segregation of duties on financial actions is a required access control |
| **SOX ITGC, Change Management** | Segregation of duties for financial-authorization changes | Maker-checker on financial movements is the operative SOX control in a lending platform |
| **ISO 27001:2022, A.5.3** | Segregation of duties | Direct violation: the same role can be maker and checker |
| **ISO 27001:2022, A.5.5** | Contact with authorities | **Post-incident:** if an insider extracts funds via self-approval, this becomes the notification pathway |

The mapping matters for #1 because it converts an "architectural finding" into a "control gap with external consequences." A portfolio reader who is a security auditor sees V-33 and knows exactly why it's Critical without needing further explanation.

---

## Related findings

- **V-19 (planned, M4):** transfer endpoint has no negative-amount check and no idempotency key. Companion finding on the *creation* side of the same endpoint. V-33 fixes approval; V-19 fixes creation.
- **V-30 (RLS bypass):** not directly related, but co-occurring. A system where the RLS layer is inert would also allow cross-tenant transfers to be approved, since a malicious insider in tenant A could approve a pending transfer in tenant B. V-33's fix (application check on `created_by == user_id`) catches same-user self-approval but not cross-tenant approval; that's V-30's domain.
- **V-41 (audit gap):** the original finding was "role changes aren't audited." V-33's fix adds `transfer.approval_denied` audit events for the *attempt*, which is a related logging improvement. Both feed #3's detection rules.

---

## Detection opportunity

A self-approval attempt against a real system is a meaningful signal. After the fix, this generates a `lendstack:money` → `transfer.approval_denied` event with `reason='self_approval'`.

A #3 detection rule (**LDS-MONEY-001**, planned) would fire on:

| Condition | Severity | Meaning |
|---|---|---|
| `transfer.approval_denied` with `reason='self_approval'` from any user | **Medium** | Policy violation attempt, likely a mistaken UI, but worth knowing |
| Same user followed within 5 minutes by a `transfer.created` with a different `approved_by` | **High** | Attempt to circumvent maker-checker by creating a second transfer and having a different user approve it. This is the "collusion" pattern, and it's the one that matters. |

Detection of the *attempt* is often more valuable than detection of the *success*. V-33's fix creates the signal that #3 can use.

---

## Evidence files

| File | Shows |
|---|---|
| `evidence/v33-self-approval.txt` | The `204` response and transfer ID from the exploit |
| `evidence/v33-db-state.txt` | Database query showing `self_approved = t` |
| `evidence/v33-fixed-self-approval.json` | `403` after fix (verification) |
| `evidence/v33-fixed-other-approve.json` | `204` from a different user (positive case) |
| `evidence/v33-constraint-violation.txt` | The Postgres error from a direct `UPDATE transfers SET approved_by = created_by`, proving the DB constraint |
