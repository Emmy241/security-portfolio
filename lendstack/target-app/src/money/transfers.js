// V-33: money-movement approval has no maker-checker enforcement.
//
// The schema has approved_by, but nothing prevents approved_by == created_by.
// A single user with transfer:create permission can submit and approve their
// own transfer.

async function createTransfer(req, fromAccountId, toAccountId, amountCents) {
  return req.withTenant(async (client) => {
    const { rows } = await client.query(
      `INSERT INTO transfers
         (id, tenant_id, from_account_id, to_account_id, amount_cents,
          status, created_by)
       VALUES (gen_random_uuid(), $1, $2, $3, $4, 'pending', $5)
       RETURNING id, status`,
      [req.user.tenant_id, fromAccountId, toAccountId, amountCents, req.user.id]
    );
    return rows[0];
  });
}

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

module.exports = { createTransfer, approveTransfer };
