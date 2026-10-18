# Environment setup notes

Running `docker compose up -d` for the first time uncovered a chain of
environment gotchas. Recorded here so a clone on a fresh machine doesn't
hit the same walls.

## Docker / BuildKit / Bake

- **Symptom:** `docker compose build` fails with
  `Error response from daemon: the Dockerfile (Dockerfile) cannot be empty`
  despite a valid ~200-byte Dockerfile.
- **Cause:** Compose v2.29+ builds via Bake by default; Bake requires
  `buildx`. When `buildx` is absent or broken, the error message is
  misleading.
- **Fix:** Install `docker-buildx-plugin` via package manager
  (`sudo apt install docker-buildx-plugin`). Verify with
  `docker buildx version`. Fallback: `DOCKER_BUILDKIT=0 docker compose up -d --build`
  (deprecated in Compose v2.39+; internal builder removed in v5).
- **Verification:** `docker build -t lendstack-api-test ./target-app`
  should succeed independently of Compose.

## YAML indentation

- **Symptom:** `validating docker-compose.yml: additional properties 'api' not allowed`.
- **Cause:** service name (`api:`, `postgres:`) dedented to column 0,
  read as a top-level key instead of a service under `services:`.
- **Fix:** indent each service two spaces under `services:`.
- **Preflight:** `docker compose config --quiet && echo VALID` after every edit.

## Port conflicts

- **Symptom:** `failed to bind host port 127.0.0.1:3000/tcp: address already in use`.
- **Cause:** another process or stale container holds port 3000.
- **Fix:** `sudo ss -tlnp | grep ':3000'` → kill the holder, or remap
  the host side in `docker-compose.yml` (e.g. `127.0.0.1:3100:3000`).

## fluent-bit

- **`Format` on the `file` output** does NOT accept `json` or `json_lines`.
  Valid values: `out_file`, `plain`, `csv`, `ltsv`, `template`.
  Use `plain` for NDJSON without the `time`/`tag` wrapper.
- **Container exits with no visible error:** Compose `ps` may show `Up`
  but the process aborted within a second. Check
  `docker compose logs fluent-bit` or `docker compose ps -a` for the
  true state.
- **No `cat`, `sh`, or coreutils in the image:** read the output volume via
  `docker run --rm -v lendstack_fluent-out:/data alpine cat /data/out`.
- **Cold start misses existing log content:** `tail` reads from EOF like
  `tail -f`. Set `Read_from_Head On` in `fluent-bit.conf` so a fresh
  container ingests the full `api.log`.

## Postgres / RLS

- **`relrowsecurity = t` but RLS is inert:** the app role is the table
  owner. Without `ALTER TABLE ... FORCE ROW LEVEL SECURITY`, policies do
  not apply to the owner. This is the planted V-30 condition.
- **Row counts across tenants:** `SELECT tenant_id, count(*) FROM invoices GROUP BY 1`
  as `lendstack_app` returns 3 rows (one per tenant). That proves owner
  bypass. If it returns 1 row, RLS is enforced and V-30 did not take.
