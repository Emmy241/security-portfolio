// V-31: the `files` table has no tenant_id column. Tenant association
// flows indirectly through invoice_id -> invoices.tenant_id.
//
// Consequences:
//   - The RLS policy on files must join through invoices to scope.
//   - `downloadFile` uses req.pool directly (no app.tenant_id set).
//   - Even if RLS were enforced via FORCE, this query would still run with
//     whatever app.tenant_id the pooled connection last held.

async function downloadFile(req, fileId) {
  // V-31: uses req.pool directly. No app.tenant_id set, no explicit
  // tenant filter.
  const { rows } = await req.pool.query(
    `SELECT id, invoice_id, filename, content_type, storage_path
     FROM files
     WHERE id = $1`,
    [fileId]
  );
  if (rows.length === 0) return null;
  return {
    filename: rows[0].filename,
    content_type: rows[0].content_type,
    storage_path: rows[0].storage_path,
  };
}

async function filesByInvoice(req, invoiceId) {
  // V-31 companion — same bypass, listing path.
  const { rows } = await req.pool.query(
    `SELECT id, filename, content_type FROM files WHERE invoice_id = $1`,
    [invoiceId]
  );
  return rows;
}

module.exports = { downloadFile, filesByInvoice };
