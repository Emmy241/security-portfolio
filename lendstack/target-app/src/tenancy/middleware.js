// Attaches tenant context to every authenticated request.
//
// This middleware is CORRECT. It sets app.tenant_id inside a per-request
// transaction, which is exactly what Postgres RLS needs to enforce the
// policies created in infra/postgres/init/03-rls.sql.
//
// But V-30 means the RLS policies don't fire: the app role owns the tables
// and lacks FORCE ROW LEVEL SECURITY, so Postgres bypasses policy evaluation
// for the owner. The middleware has no effect on what queries return.
//
// In #1's secure-reference branch, fixing V-30 (adding FORCE RLS + moving
// ownership to a non-app role) makes this middleware immediately effective —
// no code change required.

const pool = require('../db');

function attachTenant(req, res, next) {
  req.pool = pool;

  if (!req.user || !req.user.tenant_id) {
    return next();
  }

  req.withTenant = async (work) => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        "SELECT set_config('app.tenant_id', $1, true)",
        [req.user.tenant_id]
      );
      const result = await work(client);
      await client.query('COMMIT');
      return result;
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      throw e;
    } finally {
      client.release();
    }
  };

  next();
}

module.exports = { attachTenant };
