const http = require('http');
const fs   = require('fs');
const path = require('path');

const LOG_DIR = process.env.LOG_DIR || '/var/log/lendstack';
fs.mkdirSync(LOG_DIR, { recursive: true });
const logStream = fs.createWriteStream(path.join(LOG_DIR, 'api.log'), { flags: 'a' });

function log(obj) {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...obj }) + '\n';
  process.stdout.write(line);
  logStream.write(line);
}

const server = http.createServer((req, res) => {
  log({
    event: 'http.request',
    sourcetype: 'lendstack:http',
    method: req.method,
    path: req.url,
    outcome: 'ok'
  });
  if (req.url === '/healthz') {
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ status: 'ok', service: 'lendstack-api' }));
  }
  res.writeHead(404, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ error: 'not_found' }));
});

server.listen(Number(process.env.PORT) || 3000, '0.0.0.0', () => {
  log({ event: 'server.start', port: Number(process.env.PORT) || 3000, sourcetype: 'lendstack:http' });
});
