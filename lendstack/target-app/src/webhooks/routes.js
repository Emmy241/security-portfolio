// Webhook routes — V-14: SSRF via server-side fetch on registration.
//
// POST /webhooks registers a callback URL and immediately fetches it to
// "verify" it's reachable. No allowlist, no scheme check, no private-IP
// blocklist. An attacker can register http://postgres:5432 or
// http://mock-llm:4000 and have the server make internal requests.

const express = require('express');
const { requireAuth } = require('../auth/middleware');
const { attachTenant } = require('../tenancy/middleware');
const { log } = require('../log');

const router = express.Router();

// POST /webhooks — register + verify by fetching
router.post('/', requireAuth, attachTenant, async (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'missing_url' });

  try {
    const webhook = await req.withTenant(async (client) => {
      const { rows } = await client.query(
        `INSERT INTO webhooks (tenant_id, url, secret)
         VALUES ($1, $2, gen_random_uuid()::text)
         RETURNING id, url, created_at`,
        [req.user.tenant_id, url]
      );
      return rows[0];
    });

    // V-14: server-side fetch of attacker-supplied URL
    // No validation of scheme, host, or resolved IP.
    let verifyResult;
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const r = await fetch(url, { signal: controller.signal });
      clearTimeout(timeout);
      const body = await r.text();
      verifyResult = {
        status: r.status,
        content_type: r.headers.get('content-type') || 'unknown',
        body_preview: body.slice(0, 500),
      };
    } catch (e) {
      verifyResult = { error: e.message };
    }

    log({ sourcetype: 'lendstack:webhook', event: 'webhook.registered',
          tenant_id: req.user.tenant_id, actor_id: req.user.id,
          webhook_id: webhook.id, url, outcome: 'ok' });

    res.status(201).json({ webhook, verify: verifyResult });
  } catch (e) {
    res.status(500).json({ error: 'internal_error' });
  }
});

// GET /webhooks — list tenant-scoped
router.get('/', requireAuth, attachTenant, async (req, res) => {
  try {
    const webhooks = await req.withTenant(async (client) => {
      const { rows } = await client.query(
        `SELECT id, url, active, created_at FROM webhooks ORDER BY created_at DESC`
      );
      return rows;
    });
    res.json({ webhooks });
  } catch (e) {
    res.status(500).json({ error: 'internal_error' });
  }
});

module.exports = router;
