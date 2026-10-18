const express = require('express');
const crypto  = require('crypto');
const { log } = require('./log');
const authRoutes = require('./auth/routes');
const { requireAuth } = require('./auth/middleware');
const { publicKey } = require('./keys');
const pool = require('./db');

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

// V-01 exploitation surface: raw PEM for the HS256-with-public-key trick.
app.get('/.well-known/public.pem', (req, res) => {
  res.type('application/x-pem-file').send(publicKey);
});

// Standards-compliant JWKS (equivalent information).
app.get('/.well-known/jwks.json', (req, res) => {
  const { createPublicKey } = require('crypto');
  const jwk = createPublicKey(publicKey).export({ format: 'jwk' });
  res.json({ keys: [{ ...jwk, kid: 'default', use: 'sig', alg: 'RS256' }] });
});

app.use('/api/v1/auth', authRoutes);

// Protected endpoint — target for V-01 / V-02 / V-08 exploits.
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

const port = Number(process.env.PORT) || 3000;
app.listen(port, '0.0.0.0', () =>
  log({ sourcetype: 'lendstack:http', event: 'server.start', port })
);
