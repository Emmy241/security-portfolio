// V-32 fix: exportInvoices uses req.withTenant instead of req.pool directly.
// Both layers applied: RLS (app.tenant_id set) + query filter.

async function exportInvoices(req) {
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

module.exports = { exportInvoices };
