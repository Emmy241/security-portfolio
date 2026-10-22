// Invoice repository. Includes the V-10 fix pattern (tenant filter) but
// note getInvoiceById still has the original V-10 bug documented in #2 —
// that finding lives on `main` where migrations aren't applied. Once
// migrations are applied, RLS catches the missing filter.
//
// All queries use req.withTenant so RLS + tenant filter apply.

async function getInvoiceById(req, id) {
  return req.withTenant(async (client) => {
    const { rows } = await client.query(
      `SELECT id, tenant_id, account_id, number, amount_cents, currency,
              status, due_date
       FROM invoices
       WHERE id = $1 AND tenant_id = $2`,
      [id, req.user.tenant_id]
    );
    return rows[0] || null;
  });
}

async function listInvoices(req) {
  return req.withTenant(async (client) => {
    const { rows } = await client.query(
      `SELECT id, number, amount_cents, status, due_date
       FROM invoices
       ORDER BY created_at DESC
       LIMIT 50`
    );
    return rows;
  });
}

async function createInvoice(req, { account_id, number, amount_cents, currency, due_date }) {
  return req.withTenant(async (client) => {
    // Validate account belongs to this tenant
    const acct = await client.query(
      `SELECT id FROM accounts WHERE id = $1 AND tenant_id = $2`,
      [account_id, req.user.tenant_id]
    );
    if (acct.rows.length === 0) return { error: 'invalid_account' };

    const { rows } = await client.query(
      `INSERT INTO invoices
         (tenant_id, account_id, number, amount_cents, currency, due_date)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, number, amount_cents, currency, status, due_date`,
      [req.user.tenant_id, account_id, number, amount_cents,
       currency || 'USD', due_date || null]
    );
    return rows[0];
  });
}

async function updateInvoice(req, id, { amount_cents, status, due_date }) {
  return req.withTenant(async (client) => {
    const { rows } = await client.query(
      `UPDATE invoices
       SET amount_cents = COALESCE($1, amount_cents),
           status = COALESCE($2, status),
           due_date = COALESCE($3, due_date)
       WHERE id = $4 AND tenant_id = $5
       RETURNING id, number, amount_cents, status, due_date`,
      [amount_cents ?? null, status ?? null, due_date ?? null,
       id, req.user.tenant_id]
    );
    return rows[0] || null;
  });
}

async function deleteInvoice(req, id) {
  return req.withTenant(async (client) => {
    const { rowCount } = await client.query(
      `DELETE FROM invoices WHERE id = $1 AND tenant_id = $2`,
      [id, req.user.tenant_id]
    );
    return rowCount > 0;
  });
}

module.exports = { getInvoiceById, listInvoices, createInvoice, updateInvoice, deleteInvoice };
