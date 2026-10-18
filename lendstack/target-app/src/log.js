const fs = require('fs');
const path = require('path');
const LOG_DIR = process.env.LOG_DIR || '/var/log/lendstack';
fs.mkdirSync(LOG_DIR, { recursive: true });
const stream = fs.createWriteStream(path.join(LOG_DIR, 'api.log'), { flags: 'a' });

function log(obj) {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...obj }) + '\n';
  process.stdout.write(line);
  stream.write(line);
}

function authLog(req, event, extra = {}) {
  log({
    sourcetype: 'lendstack:auth',
    event,
    actor_ip: req.ip || req.socket?.remoteAddress,
    user_agent: req.get('user-agent') || null,
    request_id: req.id,
    ...extra,
  });
}

module.exports = { log, authLog };
