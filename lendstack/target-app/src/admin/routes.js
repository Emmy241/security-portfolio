// Admin routes: export (V-32 fix preserved), search (V-12 SQLi),
// merchant memos (V-13 stored XSS), and the admin panel HTML.

const express = require('express');
const { requireAuth } = require('../auth/middleware');
const { attachTenant } = require('../tenancy/middleware');
const { exportInvoices } = require('./export');
const { log } = require('../log');

const router = express.Router();

// --- Export (V-32 fixed pattern — req.withTenant + tenant filter) ---
router.get('/export', requireAuth, attachTenant, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'forbidden' });
    const rows = await exportInvoices(req);
    log({ sourcetype: 'lendstack:admin', event: 'export.requested',
          tenant_id: req.user.tenant_id, actor_id: req.user.id,
          row_count: rows.length, outcome: 'ok' });
    res.json({ invoices: rows });
  } catch (e) {
    log({ sourcetype: 'lendstack:http', event: 'handler.error',
          request_id: req.id, path: req.path, error: e.code || e.message });
    res.status(500).json({ error: 'internal_error' });
  }
});

// --- Search — V-12: SQLi via string concatenation ---
// Uses req.withTenant (so RLS scopes the base rows), but the WHERE clause
// is built by string concatenation. An attacker can break out of the LIKE
// and inject arbitrary SQL. Time-based blind injection is the cleanest
// demonstration (doesn't depend on what data RLS exposes).
router.get('/search', requireAuth, attachTenant, async (req, res) => {
  const q = req.query.q || '';
  try {
    const rows = await req.withTenant(async (client) => {
      // V-12: string concatenation — vulnerable to SQLi
      const sql = `SELECT id, number, amount_cents, status
                   FROM invoices
                   WHERE number LIKE '%${q}%'
                   ORDER BY created_at DESC
                   LIMIT 50`;
      const r = await client.query(sql);
      return r.rows;
    });
    res.json({ results: rows });
  } catch (e) {
    // V-15: error message leaked in response (adjacent finding)
    res.status(500).json({ error: 'search_failed', detail: e.message });
  }
});

// --- Merchant memos — V-13: stored XSS ---
// Content is stored verbatim and returned verbatim. The admin panel
// (GET /api/v1/admin/panel) renders it with innerHTML — stored XSS.
router.post('/merchants/:merchantId/memos', requireAuth, attachTenant, async (req, res) => {
  const { merchantId } = req.params;
  const { content } = req.body || {};
  if (!content) return res.status(400).json({ error: 'missing_content' });

  try {
    const memo = await req.withTenant(async (client) => {
      const { rows } = await client.query(
        `INSERT INTO merchant_memos (tenant_id, merchant_id, content, created_by)
         VALUES ($1, $2, $3, $4)
         RETURNING id, merchant_id, content, created_at`,
        [req.user.tenant_id, merchantId, content, req.user.id]
      );
      return rows[0];
    });
    res.status(201).json({ memo });
  } catch (e) {
    res.status(500).json({ error: 'internal_error' });
  }
});

router.get('/merchants/:merchantId/memos', requireAuth, attachTenant, async (req, res) => {
  const { merchantId } = req.params;
  try {
    const memos = await req.withTenant(async (client) => {
      const { rows } = await client.query(
        `SELECT id, merchant_id, content, created_at
         FROM merchant_memos
         WHERE merchant_id = $1
         ORDER BY created_at DESC`,
        [merchantId]
      );
      return rows;
    });
    res.json({ memos });
  } catch (e) {
    res.status(500).json({ error: 'internal_error' });
  }
});

// --- Admin panel HTML — V-13 sink ---
// Renders memo content with innerHTML. Any script tags or event handlers
// in the stored content execute in the admin's browser when the panel loads.
router.get('/panel', (req, res) => {
  res.type('html').send(`
<!DOCTYPE html>
<html>
<head>
  <title>LendStack Admin Panel</title>
  <style>
    body { font-family: -apple-system, sans-serif; max-width: 900px; margin: 2em auto; padding: 1em; color: #222; }
    input, button { padding: 0.5em; font-size: 1em; }
    input { width: 70%; }
    .memo { border: 1px solid #ddd; border-radius: 6px; padding: 1em; margin: 1em 0; background: #fafafa; }
    .memo strong { color: #0066cc; }
    .memo p { margin: 0.5em 0 0 0; }
    .hint { color: #666; font-size: 0.9em; }
  </style>
</head>
<body>
  <h1>Admin Panel — Merchant Memos</h1>
  <p class="hint">Paste an owner JWT to load memos for merchant <strong>acme</strong>.</p>
  <input id="token" placeholder="JWT">
  <button onclick="load()">Load Memos</button>
  <div id="memos"></div>
  <script>
    async function load() {
      const token = document.getElementById('token').value;
      const res = await fetch('/api/v1/admin/merchants/acme/memos', {
        headers: { 'Authorization': 'Bearer ' + token }
      });
      if (!res.ok) { document.getElementById('memos').textContent = 'Failed to load.'; return; }
      const data = await res.json();
      // V-13: innerHTML with untrusted content — stored XSS fires here
      document.getElementById('memos').innerHTML = data.memos.map(m =>
        '<div class="memo"><strong>' + m.merchant_id + '</strong><p>' + m.content + '</p></div>'
      ).join('');
    }
  </script>
</body>
</html>
  `);
});

module.exports = router;
