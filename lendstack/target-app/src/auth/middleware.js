const jwt = require('jsonwebtoken');
const { authLog } = require('../log');

function requireAuth(req, res, next) {
  const h = req.get('authorization') || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) {
    authLog(req, 'auth.denied', { outcome: 'fail', reason: 'missing_token' });
    return res.status(401).json({ error: 'missing_token' });
  }

  // V-01: jwt.decode does NOT verify the signature. Any well-formed JWT is
  // accepted as long as the payload parses — the "safe" verifyAccessToken
  // helper exists in jwt.js but the middleware was never migrated to it.
  const payload = jwt.decode(m[1]);
  if (!payload) {
    authLog(req, 'auth.denied', { outcome: 'fail', reason: 'unparseable' });
    return res.status(401).json({ error: 'invalid_token' });
  }

  req.user = { id: payload.sub, tenant_id: payload.tenant_id,
               role: payload.role, email: payload.email };
  next();
}

module.exports = { requireAuth };
