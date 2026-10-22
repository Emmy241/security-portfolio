const express = require('express');
const bcrypt  = require('bcryptjs');
const crypto  = require('crypto');
const pool    = require('../db');
const { authLog } = require('../log');

const { signAccessToken } = require('../jwt');
const { generateResetToken } = require('./reset');

const router = express.Router();
const pendingResets = new Map();   // token -> { user_id, created_at }
const pendingOtps   = new Map();   // email -> { code, created_at }

function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

// POST /api/v1/auth/register
router.post('/register', async (req, res) => {
  const { tenant_id, email, password, role = 'analyst' } = req.body || {};
  if (!tenant_id || !email || !password) return res.status(400).json({ error: 'missing_fields' });

  // V-11: role taken from body without authorization check.
  // Also: caller picks tenant_id freely, no proof of membership.
  const hash = await bcrypt.hash(password, 10);

  // Transaction with app.tenant_id set so RLS INSERT policy is satisfied.
  // The attacker controls tenant_id (from body), so they control which
  // tenant's RLS policy is satisfied — cross-tenant registration.
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenant_id]);

    const { rows } = await client.query(
      `INSERT INTO users (id, tenant_id, email, password_hash, role)
       VALUES (gen_random_uuid(), $1, $2, $3, $4)
       RETURNING id, tenant_id, email, role`,
      [tenant_id, email, hash, role]
    );
    await client.query('COMMIT');

    authLog(req, 'register.success', { tenant_id, actor_id: rows[0].id,
      actor_email: email, outcome: 'ok', role });
    res.status(201).json({ user: rows[0] });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    authLog(req, 'register.failure', { tenant_id, actor_email: email, outcome: 'fail',
      reason: e.code === '23505' ? 'duplicate' : 'db_error' });
    res.status(409).json({ error: 'registration_failed' });
  } finally {
    client.release();
  }
});

// POST /api/v1/auth/login
router.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    authLog(req, 'login.failure', { actor_email: email || null, outcome: 'fail', reason: 'missing_fields' });
    return res.status(400).json({ error: 'missing_fields' });
  }

  // V-35: login must find a user by email before knowing their tenant.
  // Transactional lookup uses users_login_lookup policy (email match) to
  // read the user row, then sets app.tenant_id for the refresh-token INSERT
  // which is tenant-scoped by RLS.
  const client = await pool.connect();
  let user = null;
  let access = null;
  let refresh = null;
  try {
    await client.query('BEGIN');
    await client.query("SELECT set_config('app.login_email', $1, true)", [email]);

    const { rows } = await client.query(
      'SELECT id, tenant_id, email, password_hash, role FROM users WHERE email = $1',
      [email]
    );
    user = rows[0];

    if (user) {
      const ok = await bcrypt.compare(password, user.password_hash);
      if (ok) {
        // Now we know the tenant — set app.tenant_id for scoped writes
        await client.query("SELECT set_config('app.tenant_id', $1, true)", [user.tenant_id]);

        access  = signAccessToken({ user_id: user.id, tenant_id: user.tenant_id, role: user.role, email: user.email });
        refresh = crypto.randomBytes(32).toString('hex');

        await client.query(
          `INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at)
           VALUES (gen_random_uuid(), $1, $2, now() + interval '14 days')`,
          [user.id, sha256(refresh)]
        );
      }
    }

    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    client.release();
    throw e;
  }
  client.release();

  if (!user) {
    authLog(req, 'login.failure', { actor_email: email, outcome: 'fail', reason: 'no_such_user' });
    return res.status(401).json({ error: 'invalid_credentials' });
  }
  if (!access) {
    authLog(req, 'login.failure', { tenant_id: user.tenant_id, actor_id: user.id,
      actor_email: email, outcome: 'fail', reason: 'bad_password' });
    return res.status(401).json({ error: 'invalid_credentials' });
  }

  authLog(req, 'login.success', { tenant_id: user.tenant_id, actor_id: user.id,
    actor_email: email, outcome: 'ok', role: user.role });
  res.json({ access_token: access, refresh_token: refresh, token_type: 'Bearer', expires_in: 86400 });
});

// POST /api/v1/auth/refresh
router.post('/refresh', async (req, res) => {
  const { refresh_token } = req.body || {};
  if (!refresh_token) return res.status(400).json({ error: 'missing_refresh_token' });
  const { rows } = await pool.query(
    `SELECT rt.id AS token_id, u.id AS user_id, u.tenant_id, u.email, u.role
     FROM refresh_tokens rt JOIN users u ON u.id = rt.user_id
     WHERE rt.token_hash = $1 AND rt.revoked_at IS NULL AND rt.expires_at > now()`,
    [sha256(refresh_token)]
  );
  if (rows.length === 0) {
    authLog(req, 'refresh.failure', { outcome: 'fail', reason: 'invalid_or_expired' });
    return res.status(401).json({ error: 'invalid_refresh_token' });
  }
  const u = rows[0];
  // V-03: old refresh token is NOT revoked — reusable until expiry.
  const access = signAccessToken({ user_id: u.user_id, tenant_id: u.tenant_id, role: u.role, email: u.email });
  authLog(req, 'refresh.used', { tenant_id: u.tenant_id, actor_id: u.user_id,
    actor_email: u.email, outcome: 'ok', token_id: u.token_id });
  res.json({ access_token: access, token_type: 'Bearer', expires_in: 86400 });
});

// POST /api/v1/auth/password-reset
router.post('/password-reset', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'missing_email' });
  const { rows } = await pool.query('SELECT id, tenant_id FROM users WHERE email = $1', [email]);
  if (rows.length === 0) {
    authLog(req, 'password.reset.requested', { actor_email: email, outcome: 'no_such_user' });
    return res.status(204).end();
  }
  const user = rows[0];
  const token = generateResetToken();   // V-20
  pendingResets.set(token, { user_id: user.id, created_at: Date.now() });
  authLog(req, 'password.reset.requested', { tenant_id: user.tenant_id,
    actor_id: user.id, actor_email: email, outcome: 'ok' });
  // LAB SIMPLIFICATION: real app emails this. We return it for test convenience
  // so V-20 can be demonstrated without SMTP setup. Documented in docs/setup.md.
  res.json({ reset_token: token });
});

// POST /api/v1/auth/password-change
router.post('/password-change', async (req, res) => {
  const { token, new_password } = req.body || {};
  if (!token || !new_password) return res.status(400).json({ error: 'missing_fields' });
  const rec = pendingResets.get(token);
  if (!rec) {
    authLog(req, 'password.reset.used', { outcome: 'fail', reason: 'invalid_token' });
    return res.status(401).json({ error: 'invalid_token' });
  }
  // V-20: token never deleted — reusable. No expiry check.
  const hash = await bcrypt.hash(new_password, 10);
  await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, rec.user_id]);
  // V-03: refresh tokens for this user are NOT revoked after password change.
  authLog(req, 'password.reset.used', { actor_id: rec.user_id, outcome: 'ok' });
  res.status(204).end();
});

// POST /api/v1/auth/otp  (V-16: no rate limit)
router.post('/otp', async (req, res) => {
  const { email } = req.body || {};
  const code = String(Math.floor(100000 + Math.random() * 900000));
  pendingOtps.set(email, { code, created_at: Date.now() });
  authLog(req, 'otp.requested', { actor_email: email, outcome: 'ok' });
  res.json({ code });   // LAB: real app emails this
});

// POST /api/v1/auth/otp/verify
router.post('/otp/verify', async (req, res) => {
  const { email, code } = req.body || {};
  const rec = pendingOtps.get(email);
  if (!rec || rec.code !== code) {
    authLog(req, 'otp.failure', { actor_email: email, outcome: 'fail', reason: 'bad_code' });
    return res.status(401).json({ error: 'invalid_code' });
  }
  authLog(req, 'otp.success', { actor_email: email, outcome: 'ok' });
  pendingOtps.delete(email);
  res.status(204).end();
});

module.exports = router;
