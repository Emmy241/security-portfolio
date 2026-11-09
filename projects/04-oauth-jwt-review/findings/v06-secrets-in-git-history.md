# V-06 — Database Credentials Committed to Git

| Field | Value |
|---|---|
| **ID** | V-06 |
| **Severity** | Critical (business impact). CVSS 3.1 7.5 for reference: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **CWE** | CWE-540: Inclusion of Sensitive Information in Source Code |
| **OWASP** | A07:2021: Identification and Authentication Failures |
| **Component** | `lendstack/.env` |
| **Status** | Confirmed exploitable |
| **Introduced** | Commit `c6625f9` (M0, the first working stack). Still tracked today. |

## Summary

The `.env` file holding LendStack's real configuration is committed to the repository. It contains the Postgres superuser password, the application and read-only role passwords, a full `DATABASE_URL` and a `JWT_SECRET`. Anyone who can read the repository can read them.

The leaked application credentials were used to connect directly to Postgres as `lendstack_app`, bypassing the API, its authentication and its logging.

**Severity note:** this is rated Critical on business impact. The credentials reach the database that holds every tenant's lending data, and a database password can't be revoked as easily as a session. The CVSS vector scores only what was demonstrated: a successful connection with read access, over a network path that exists in the lab. Write access with the same role was not tested, and would raise the score.

## Evidence

### 1. The file is tracked

```bash
git ls-files | grep '\.env$'
# lendstack/.env

git log --oneline -- lendstack/.env
# c6625f9 chore: M0 — LendStack stack green (5 services, seed, RLS planted, log pipeline verified)
```

### 2. It holds live secrets (values redacted here)

```text
POSTGRES_USER=<redacted>
POSTGRES_PASSWORD=<redacted>
APP_DB_USER=lendstack_app
APP_DB_PASSWORD=LendStack_App_****
RO_DB_USER=<redacted>
RO_DB_PASSWORD=<redacted>
DATABASE_URL=postgres://lendstack_app:****@...
JWT_SECRET=<redacted>
```

### 3. The credentials work

Connecting with the committed application password, outside the API:

```text
 current_user  | current_database
---------------+------------------
 lendstack_app | lendstack
(1 row)
```

Full output: [`evidence/v06-live-credential-proof.txt`](../evidence/v06-live-credential-proof.txt).

## Root cause

- `.env` was never added to `.gitignore`. The repository relies on people remembering not to commit it.
- There is no pre-commit or CI secret scan, so nothing stopped it.
- The same credentials are used across environments, so a leak from development is a leak from production.

## Impact

- **Direct database access** as the application role, skipping authentication, rate limits and the `lendstack:auth` audit trail.
- **Chains with other findings:** combined with V-30 (RLS bypass), a direct connection can read across tenants. See [#1](../../01-saas-architecture/).
- **Persistence:** the secrets stay in Git history even after the file is deleted, and in every clone and fork made before that.

## Fix

Order matters: rotate first, because removing the file doesn't un-leak anything.

1. **Rotate every secret in the file:** the three database passwords and `JWT_SECRET`. Treat the old values as public.
2. **Stop tracking the file:** `git rm --cached lendstack/.env`, add `.env` to `.gitignore`, and keep only `.env.example` with placeholder values.
3. **Purge history** with `git filter-repo --path lendstack/.env --invert-paths`, then force-push and ask collaborators to re-clone. This reduces exposure but doesn't replace step 1.
4. **Use separate credentials per environment,** so a development leak can't reach production.

## Prevention

- Add a secret scan to CI (for example `gitleaks detect`) and fail the build on any hit.
- Add the same scan as a pre-commit hook, so secrets are caught before they leave the laptop.
- Enable GitHub secret scanning and push protection on the repository.

## Retest

1. `git ls-files | grep '\.env$'` returns nothing.
2. `gitleaks detect --log-opts="--all"` reports no secrets in history.
3. Connecting with the old `lendstack_app` password fails with `password authentication failed`.
4. The application still starts with the rotated credentials supplied from the environment.

## Note on this lab

LendStack is a deliberately vulnerable reference build, and these credentials exist only in the lab. The file is left in place on purpose so the finding can be reproduced. In a real engagement, step 1 would happen the same day the finding was reported.
