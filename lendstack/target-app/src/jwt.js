const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const { privateKey, publicKey } = require('./keys');

function signAccessToken({ user_id, tenant_id, role, email }) {
  // V-04: 24h access token, no revocation path
  return jwt.sign(
    { sub: user_id, tenant_id, role, email },
    privateKey,
    {
      algorithm: 'RS256',
      expiresIn: '24h',
      issuer: 'lendstack-api',
      audience: 'lendstack-web',
    }
  );
}

function verifyAccessToken(token) {
  return jwt.verify(token, publicKey, { algorithms: ['RS256'] });   // secure helper
}

function resolveKey(kid) {
  // V-02: path.join does not prevent `..` escapes; no basename check.
  //       kid = "../malicious"  → /app/src/keys/../malicious.pem
  const keyPath = path.join(__dirname, 'keys', kid + '.pem');
  if (!fs.existsSync(keyPath)) return publicKey;   // silent fallback
  return fs.readFileSync(keyPath, 'utf8');
}

module.exports = { signAccessToken, verifyAccessToken };
