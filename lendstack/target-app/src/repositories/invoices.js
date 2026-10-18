// Invoice repository.
//
// getInvoiceById is the SQL-level shape that produces V-10 (IDOR).
// Two failures combine to make it exploitable:
//
//   1. The SQL has no `AND tenant_id = $2` filter. Application-layer
//      authorization is missing — the classic IDOR bug.
//   2. RLS was supposed to be defense-in-depth but is inert (V-30).
//      So the "second layer" doesn't catch it either.

async function getInvoiceById(req, id) {
  return req.withTenant(async (client) => {
    // V-10: no tenant_id filter.
    const { rows } = await client.query(
      `SELECT id, tenant_id, account_id, number, amount_cents, currency,
              status, due_date
       FROM invoices
       WHERE id = $1`,
      [id]
    );
    return rows[0] || null;
  });
}

// The correct version — kept as documentation of the fix.
async function getInvoiceByIdSafe(req, id) {
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

module.exports = { getInvoiceById, getInvoiceByIdSafe, listInvoices };
