const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const KEY_DIR = path.join(__dirname, 'keys');
fs.mkdirSync(KEY_DIR, { recursive: true });
const privPath = path.join(KEY_DIR, 'private.pem');
const pubPath  = path.join(KEY_DIR, 'public.pem');

if (!fs.existsSync(privPath) || !fs.existsSync(pubPath)) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding:  { type: 'spki',  format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  fs.writeFileSync(privPath, privateKey, { mode: 0o600 });
  fs.writeFileSync(pubPath,  publicKey);
}

module.exports = {
  privateKey: fs.readFileSync(privPath, 'utf8'),
  publicKey:  fs.readFileSync(pubPath,  'utf8'),
};
