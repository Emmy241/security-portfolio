// V-31 fix: files now has tenant_id column (migration 004).
// Both layers applied: RLS via column policy + query filter via req.withTenant.

async function downloadFile(req, fileId) {
  return req.withTenant(async (client) => {
    const { rows } = await client.query(
      `SELECT id, invoice_id, filename, content_type, storage_path
       FROM files
       WHERE id = $1 AND tenant_id = $2`,
      [fileId, req.user.tenant_id]
    );
    if (rows.length === 0) return null;
    return {
      filename: rows[0].filename,
      content_type: rows[0].content_type,
      storage_path: rows[0].storage_path,
    };
  });
}

async function filesByInvoice(req, invoiceId) {
  return req.withTenant(async (client) => {
    const { rows } = await client.query(
      `SELECT id, filename, content_type
       FROM files
       WHERE invoice_id = $1 AND tenant_id = $2`,
      [invoiceId, req.user.tenant_id]
    );
    return rows;
  });
}

module.exports = { downloadFile, filesByInvoice };
