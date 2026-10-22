const express = require('express');
const crypto  = require('crypto');
const { log } = require('./log');
const authRoutes = require('./auth/routes');
const adminRoutes = require('./admin/routes');
const webhookRoutes = require('./webhooks/routes');
const { requireAuth } = require('./auth/middleware');
const { attachTenant } = require('./tenancy/middleware');
const { publicKey } = require('./keys');
const pool = require('./db');
const {
  getInvoiceById, listInvoices, createInvoice, updateInvoice, deleteInvoice
} = require('./repositories/invoices');
const { downloadFile } = require('./repositories/files');
const { createTransfer, approveTransfer } = require('./money/transfers');

const app = express();
app.use(express.json({ limit: '1mb' }));

app.use((req, res, next) => {
  req.id = crypto.randomUUID();
  res.set('X-Request-Id', req.id);
  const start = Date.now();
  res.on('finish', () => log({
    sourcetype: 'lendstack:http',
    event: 'http.request',
    request_id: req.id,
    method: req.method,
    path: req.path,
    status: res.statusCode,
    latency_ms: Date.now() - start,
    actor_ip: req.ip,
  }));
  next();
});

app.get('/healthz', (req, res) => res.json({ status: 'ok', service: 'lendstack-api' }));

app.get('/.well-known/public.pem', (req, res) => {
  res.type('application/x-pem-file').send(publicKey);
});

app.get('/.well-known/jwks.json', (req, res) => {
  const { createPublicKey } = require('crypto');
  const jwk = createPublicKey(publicKey).export({ format: 'jwk' });
  res.json({ keys: [{ ...jwk, kid: 'default', use: 'sig', alg: 'RS256' }] });
});

app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/admin', adminRoutes);
app.use('/api/v1/webhooks', webhookRoutes);

app.get('/api/v1/users/me', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, tenant_id, email, role FROM users WHERE id = $1', [req.user.id]
    );
    res.json({ user: rows[0] || null });
  } catch (e) {
    log({ sourcetype: 'lendstack:http', event: 'handler.error',
          request_id: req.id, path: req.path, error: e.code || e.message });
    res.status(500).json({ error: 'internal_error' });
  }
});

// --- Invoices CRUD ---
app.get('/api/v1/invoices', requireAuth, attachTenant, async (req, res) => {
  try {
    const rows = await listInvoices(req);
    res.json({ invoices: rows });
  } catch (e) {
    log({ sourcetype: 'lendstack:http', event: 'handler.error',
          request_id: req.id, path: req.path, error: e.code || e.message });
    res.status(500).json({ error: 'internal_error' });
  }
});

app.get('/api/v1/invoices/:id', requireAuth, attachTenant, async (req, res) => {
  try {
    const inv = await getInvoiceById(req, req.params.id);
    if (!inv) return res.status(404).json({ error: 'not_found' });
    res.json({ invoice: inv });
  } catch (e) {
    log({ sourcetype: 'lendstack:http', event: 'handler.error',
          request_id: req.id, path: req.path, error: e.code || e.message });
    res.status(500).json({ error: 'internal_error' });
  }
});

app.post('/api/v1/invoices', requireAuth, attachTenant, async (req, res) => {
  try {
    const result = await createInvoice(req, req.body || {});
    if (result.error) return res.status(400).json({ error: result.error });
    res.status(201).json({ invoice: result });
  } catch (e) {
    log({ sourcetype: 'lendstack:http', event: 'handler.error',
          request_id: req.id, path: req.path, error: e.code || e.message });
    res.status(500).json({ error: 'internal_error' });
  }
});

app.patch('/api/v1/invoices/:id', requireAuth, attachTenant, async (req, res) => {
  try {
    const inv = await updateInvoice(req, req.params.id, req.body || {});
    if (!inv) return res.status(404).json({ error: 'not_found' });
    res.json({ invoice: inv });
  } catch (e) {
    log({ sourcetype: 'lendstack:http', event: 'handler.error',
          request_id: req.id, path: req.path, error: e.code || e.message });
    res.status(500).json({ error: 'internal_error' });
  }
});

app.delete('/api/v1/invoices/:id', requireAuth, attachTenant, async (req, res) => {
  try {
    const deleted = await deleteInvoice(req, req.params.id);
    if (!deleted) return res.status(404).json({ error: 'not_found' });
    res.status(204).end();
  } catch (e) {
    log({ sourcetype: 'lendstack:http', event: 'handler.error',
          request_id: req.id, path: req.path, error: e.code || e.message });
    res.status(500).json({ error: 'internal_error' });
  }
});

// --- Files ---
app.get('/api/v1/files/:id', requireAuth, attachTenant, async (req, res) => {
  try {
    const f = await downloadFile(req, req.params.id);
    if (!f) return res.status(404).json({ error: 'not_found' });
    res.json({ file: f });
  } catch (e) {
    log({ sourcetype: 'lendstack:http', event: 'handler.error',
          request_id: req.id, path: req.path, error: e.code || e.message });
    res.status(500).json({ error: 'internal_error' });
  }
});

// --- Transfers ---
app.post('/api/v1/transfers', requireAuth, attachTenant, async (req, res) => {
  try {
    const { from_account_id, to_account_id, amount_cents } = req.body || {};
    if (!from_account_id || !to_account_id || typeof amount_cents !== 'number') {
      return res.status(400).json({ error: 'missing_fields' });
    }
    const t = await createTransfer(req, from_account_id, to_account_id, amount_cents);
    log({ sourcetype: 'lendstack:money', event: 'transfer.created',
          tenant_id: req.user.tenant_id, actor_id: req.user.id,
          transfer_id: t.id, amount_cents, outcome: 'ok' });
    res.status(201).json({ transfer: t });
  } catch (e) {
    log({ sourcetype: 'lendstack:http', event: 'handler.error',
          request_id: req.id, path: req.path, error: e.code || e.message });
    res.status(500).json({ error: 'internal_error' });
  }
});

app.post('/api/v1/transfers/:id/approve', requireAuth, attachTenant, async (req, res) => {
  try {
    const result = await approveTransfer(req, req.params.id);
    if (result.error === 'not_found') return res.status(404).json({ error: 'not_found' });
    if (result.error === 'not_pending') return res.status(409).json({ error: 'not_pending' });
    if (result.error === 'self_approval_denied') return res.status(403).json({ error: 'self_approval_denied' });
    log({ sourcetype: 'lendstack:money', event: 'transfer.approved',
          tenant_id: req.user.tenant_id, actor_id: req.user.id,
          transfer_id: req.params.id, outcome: 'ok' });
    res.status(204).end();
  } catch (e) {
    log({ sourcetype: 'lendstack:http', event: 'handler.error',
          request_id: req.id, path: req.path, error: e.code || e.message });
    res.status(500).json({ error: 'internal_error' });
  }
});

const port = Number(process.env.PORT) || 3000;
app.listen(port, '0.0.0.0', () =>
  log({ sourcetype: 'lendstack:http', event: 'server.start', port })
);
