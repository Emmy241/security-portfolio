// V-32: bulk admin export uses req.pool directly instead of req.withTenant.
// The route looks authorized (requireRole('owner')) but the query returns
// every tenant's invoices — the tenant context middleware was never
// invoked on this path.

async function exportInvoices(req) {
  const { rows } = await req.pool.query(
    `SELECT id, tenant_id, number, amount_cents, status, due_date
     FROM invoices
     ORDER BY created_at DESC`
  );
  return rows;
}

module.exports = { exportInvoices };
