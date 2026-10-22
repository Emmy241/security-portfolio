# Threat Model — LendStack Trust Boundaries

| Field | Value |
|---|---|
| **Project** | [#1 — Secure Multi-Tenant SaaS Architecture](README.md) |
| **Target** | [LendStack](../../lendstack/) — multi-tenant fintech/lending SaaS |
| **Method** | Six trust boundaries identified; STRIDE analysis per boundary |
| **Status** | Boundaries + STRIDE complete; per-boundary mitigations cross-referenced to findings and migrations |
| **Last updated** | 2026-10-22 |

---

## What a trust boundary is, and why this matters

A trust boundary is any place where data, identity, or privilege crosses from a zone of one trust level into another. On one side, a piece of data is (relatively) trusted; on the other, it must be verified. **Controls live at trust boundaries** — authentication where the internet meets the application, authorization where one role meets another role's data, encryption where the app meets storage.

A threat model that lists "SQL injection" and "XSS" as findings is a vulnerability catalog, not a threat model. **A threat model asks: what crosses this boundary, what could go wrong, and what layer catches it?** The findings then become the specific instances of the answers.

LendStack has six boundaries. Three of them — tenant isolation, application-to-database, and maker-checker — failed on **multiple layers simultaneously**, which is why they account for all four of the project's Critical/High findings. The other three boundaries are less burdened by findings but complete the model.

---

## The six boundaries

| # | Boundary | What crosses | Zone A → Zone B |
|---|---|---|---|
| 1 | Client ↔ API | HTTP requests, JWTs, user input | Internet (untrusted) → Application (partially trusted) |
| 2 | Tenant ↔ Tenant | Data ownership, row visibility | Tenant A context → Tenant B context (both within app zone) |
| 3 | Application ↔ Database | SQL queries, connection identity | Application (partially trusted) → Data store (trusted) |
| 4 | User ↔ Role (within tenant) | Privilege level, approval authority | Same-tenant user (analyst) → same-tenant user (owner) |
| 5 | Application ↔ External Services | Outbound HTTP, secrets, user data in payloads | Application → Third-party endpoints |
| 6 | Operator ↔ Production | Config, migrations, secrets, deployment | CI/human operator → Production runtime |

Not a numbered boundary, but crossing all of them: **authentication**. Which identity is making the request, and how do we know? Every boundary below assumes authentication has resolved `req.user` — the question is *whether that assumption is safe* (see boundary 1).

---

## Boundary 1 — Client ↔ API

**What crosses:** Every HTTP request into LendStack: JWTs in the `Authorization` header, JSON bodies, path parameters, cookies, `X-Forwarded-For` headers.

**Zone transition:** Internet (attacker-controlled) → Application (trusted enough to execute code, not trusted enough to make authorization decisions).

**Controls present:**
- JWT signature verification (`jwt.verify` in `auth/middleware.js`)
- `express.json({ limit: '1mb' })` — request body size limit
- Password hashing (bcrypt, cost 10)

**Controls absent or insufficient:**
- Rate limiting on `/auth/login`, `/auth/otp`, `/auth/password-reset`
- Token revocation path (`refresh_tokens.revoked_at` exists but unused)
- Audience/issuer validation in JWT verify
- CSRF protection (not applicable — bearer-token API, but worth noting the API relies on `Authorization` header only, not cookies)

### STRIDE analysis

| Threat | Description | Finding | Severity | Mitigation status |
|---|---|---|---|---|
| **S**poofing | Forge a JWT to impersonate any user | **V-01** — signature not verified in middleware (used `jwt.decode` instead of `jwt.verify`); also **V-08** — no `aud`/`iss` check allows cross-service token reuse | Critical / Medium | V-01 documented; **V-01-R** (alg confusion) blocked by jsonwebtoken v9 but version-dependent — noted as residual risk |
| **T**ampering | Modify user data via registration payload | **V-11** — `role` field accepted from `POST /auth/register` body without authorization check | High | Present on `main`; not yet exercised in demo |
| **R**epudiation | Deny a login attempt happened | **V-40** — auth failure events log `actor_email` but not always `actor_id` or `tenant_id` | Medium | Present; affects #3's T1110.001 detection accuracy |
| **I**nformation Disclosure | Learn a user exists via timing / error differences | Login returns generic `invalid_credentials` — good. But **V-20** — password reset returns the token in the response (lab simplification, would be emailed in prod) | Medium | V-20 documented; lab simplification noted |
| **D**enial of Service | Flood login endpoint to lock out legit users or exhaust resources | **V-16** — no rate limiting on `/auth/login`, `/auth/otp`, `/auth/password-reset` | High | Present; 30× 401 in <1s reproduces |
| **E**levation of Privilege | Escalate role via mass assignment | **V-11** — same as Tampering | High | Present |

**Findings on this boundary:** V-01, V-03, V-04, V-08, V-11, V-16, V-20
**Fixes applied:** none on this boundary (V-01 fix is documented in #4, not #1's remediation scope; V-03/V-04/V-16/V-20 are #2/#4 findings)

**Why this boundary didn't get a "fix" in the architecture review:** The findings here are *application-layer* security issues, and they're documented under the relevant projects (#2, #4). The architecture review's scope is *structural* — trust boundaries between zones, not every application finding. But the model is complete only if it names what crosses each boundary and what's absent. Hence the list.

---

## Boundary 2 — Tenant ↔ Tenant (the isolation boundary)

**What crosses:** Data ownership and visibility. Tenant A's user requests a row that belongs to Tenant B. In a correctly-isolated multi-tenant system, this crossing should be **impossible** — the response should be `404 Not Found` regardless of whether the row exists.

**Zone transition:** Tenant A context → Tenant B context. Both are *within* the application zone, but they are **not supposed to be able to see each other**. This is the boundary that multi-tenancy is fundamentally about.

**Controls present:**
- RLS enabled (`ENABLE ROW LEVEL SECURITY`) on every tenant-scoped table
- RLS policies correctly written (`USING (tenant_id = current_tenant())`)
- Tenant middleware (`attachTenant` in `tenancy/middleware.js`) — correctly sets `app.tenant_id` per request
- Repository layer that *should* use `req.withTenant` for all tenant-scoped queries

**Controls absent or broken:**
- `FORCE ROW LEVEL SECURITY` not set on any table
- App role (`lendstack_app`) owns every table — RLS bypassed
- Some repositories bypass `req.withTenant` and use `req.pool` directly (V-32 pattern)
- One table (`files`) has no `tenant_id` column at all

### STRIDE analysis

| Threat | Description | Finding | Severity | Mitigation status |
|---|---|---|---|---|
| **S**poofing | Assume another tenant's identity via stolen token | V-01 (Client↔API) makes this trivial — but even with valid token, cross-tenant read is the actual exploit | Critical | V-01 documented under #4 |
| **T**ampering | Modify another tenant's rows | **V-30** — RLS bypass permits `UPDATE invoices` on any tenant's rows | Critical | ✅ Fixed via migration 001 |
| **R**epudiation | Cross-tenant actions not attributed | **V-41** — role changes not audited; cross-tenant writes not distinguishable from legit reads in logs | High | Planned (M4) |
| **I**nformation Disclosure | Read another tenant's invoices, files, loan applications | **V-10**, **V-30**, **V-31**, **V-32** — every tenant-scoped table leaks | Critical (V-30), High (V-10/V-31/V-32) | ✅ All four fixed via migrations 001 + 004 + code |
| **D**enial of Service | Not directly a cross-tenant issue; same-tenant DoS via V-16 | — | — | — |
| **E**levation of Privilege | Use cross-tenant read to impersonate another tenant's owner | Implied by V-30 — if you can read all rows, you can read every tenant's `users` table, then forge a JWT for any of them | Critical | ✅ Fixed via migration 001 |

**Findings on this boundary:** V-10, V-30, V-31, V-32
**Fixes applied (migrations 001–004):**
- **V-30** — ownership reassigned to `lendstack_owner`, `FORCE RLS` set, app role gets CRUD only (migration 001)
- **V-31** — `files.tenant_id` added, backfilled, NOT NULL, column-based RLS policy (migration 004)
- **V-32** — `exportInvoices` rewritten to use `req.withTenant` + `WHERE tenant_id = $1` (code change, no migration needed)
- **V-10** — closed *behaviorally* by V-30's fix; the SQL-level fix (adding `WHERE tenant_id = $2` to `getInvoiceById`) is documented in #2's V-10 finding, applied there

**Why this boundary is the flagship of the review:** It's the one that every developer thinks is covered. RLS is on, middleware is wired, policies are correct — and it still leaked. The distance between "looks isolated" and "is isolated" is exactly what an architecture review exists to measure.

---

## Boundary 3 — Application ↔ Database

**What crosses:** SQL queries, connection identity, transaction state. The application connects to Postgres as `lendstack_app`; the DB evaluates RLS policies against `app.tenant_id` and `current_user`.

**Zone transition:** Application (partially trusted) → Data store (fully trusted). The database is the last line of defense — if it's configured right, it catches what the application misses.

**Controls present:**
- RLS policies on every tenant-scoped table
- Postgres 16 (mature RLS implementation)
- Per-request transaction pattern (`req.withTenant`) correctly written

**Controls absent or broken:**
- App role owns the tables (V-30) — RLS bypassed
- `FORCE ROW LEVEL SECURITY` not set
- `log_connections` off (V-42) — failed DB connections not logged, so failed auth at the DB layer is invisible
- Postgres credentials in git history (V-06)

### STRIDE analysis

| Threat | Description | Finding | Severity | Mitigation status |
|---|---|---|---|---|
| **S**poofing | Connect as a different DB role | V-06 — credentials in git history (see boundary 6) | Critical | Documented under #4 |
| **T**ampering | Modify rows outside the application's intended scope | **V-30** — no table-owner bypass protection means the app role can write to any row | Critical | ✅ Fixed via migration 001 |
| **R**epudiation | Database-level actions untraceable | **V-42** — `log_connections` off, so connection identity is invisible; **V-41** — table-level audit trail absent | Medium | Planned |
| **I**nformation Disclosure | Query returns rows the tenant shouldn't see | **V-30**, **V-31** — RLS policy inert; schema missing `tenant_id` column | Critical / High | ✅ Fixed |
| **D**enial of Service | Exhaust connection pool | `pool` has default max connections; not configured; not currently a finding but worth noting | — | — |
| **E**levation of Privilege | Elevate DB privileges (superuser, BYPASSRLS) | `ALTER ROLE lendstack_app NOBYPASSRLS` applied on migration 001; `rolsuper` was never granted (checked at setup) | High | ✅ Enforced via migration 001 + `rls-check.sh` CI |

**Findings on this boundary:** V-30, V-31, V-42
**Fixes applied:** V-30 and V-31 fixed via migrations; V-42 planned

**Why this boundary required its own CI check:** The application layer can be reviewed with code review. The database layer cannot — it depends on configuration state (`FORCE`, ownership, `BYPASSRLS`) that isn't visible in SQL files. Hence `rls-check.sh` — a CI-level query that asserts the invariants hold after every migration. **Without the CI check, "we fixed V-30" is a claim; with it, it's an enforced property.**

---

## Boundary 4 — User ↔ Role (privilege escalation within a tenant)

**What crosses:** Privilege level and approval authority. A user with `role='analyst'` attempts an action reserved for `role='owner'`. Or: a user tries to approve their own action (maker-checker). Or: a user grants themselves elevated privileges.

**Zone transition:** Same-tenant user (lower privilege) → same-tenant user (higher privilege). This boundary is entirely *internal* to a tenant — unlike boundary 2, both sides are legitimately authorized to the tenant, but not to the same actions within it.

**Controls present:**
- `role` column with CHECK constraint (`owner`, `analyst`, `auditor`, `service`)
- `requireRole` pattern available (used on `/admin/export`)
- `created_by` and `approved_by` columns on `transfers`

**Controls absent or broken:**
- **V-11** — `POST /auth/register` accepts `role` from request body
- **V-33** — self-approval on transfers: `created_by` and `approved_by` can be the same user
- **V-41** — role changes not audited (when role-change endpoint is built in M4, it should emit an event)
- No maker-checker enforcement for any transfer type beyond the schema columns

### STRIDE analysis

| Threat | Description | Finding | Severity | Mitigation status |
|---|---|---|---|---|
| **S**poofing | Claim another role via mass assignment | **V-11** — `role` from request body at registration | High | Present; fix documented in V-11's finding file |
| **T**ampering | Modify own or others' role without authorization | **V-11** (above); role-change route planned for M4 with V-41 logging requirement | High | Present |
| **R**epudiation | Role change with no audit trail | **V-41** — `role.changed` event not emitted (route not built; requirement documented as #3's prerequisite) | High | Planned |
| **I**nformation Disclosure | See another role's data (e.g., analyst sees owner-only exports) | Export is `requireRole('owner')` — correct at the gate, but **V-32** bypasses the *tenant* check; role gate itself works | — | ✅ (gate is correct; tenant check is boundary 2) |
| **D**enial of Service | — | Not applicable | — | — |
| **E**levation of Privilege | Approve own financial transfers | **V-33** — no maker-checker; `created_by == approved_by` succeeds | Critical | ✅ Fixed via migration 003 + app check |

**Findings on this boundary:** V-11, V-33, V-41
**Fixes applied:** V-33 fixed (migration 003 + `approveTransfer` code + audit event). V-11 and V-41 documented; fixes scoped to #2 and #3 respectively.

**Why this boundary matters as much as boundary 2:** Cross-tenant leaks are external; maker-checker failures are internal. In a lending platform, the internal threat — a single insider moving money — is at least as serious as a cross-tenant read. It's the failure mode that regulators care about most (segregation of duties), and it's the finding that most directly maps to compliance requirements in the eventual compliance overlay.

---

## Boundary 5 — Application ↔ External Services

**What crosses:** Outbound HTTP from LendStack to: mock-LLM (support chatbot), MailHog (password reset emails), customer-registered webhook URLs. Also: any user-supplied data (support messages, webhook payloads) that the app forwards.

**Zone transition:** Application → Third parties. The application is sending data that may include PII (or worse, PAN) to systems outside its control, and receiving data that may contain attacker-controlled content.

**Controls present:**
- `mock-llm` runs in the internal Docker network (`lendstack-net`) — not internet-accessible
- `mailhog` similarly isolated
- Webhook URLs validated as HTTP/HTTPS (planned)

**Controls absent or broken:**
- **V-14** (planned M6) — webhook registration allows any URL → SSRF
- **V-34** (planned M6) — support chatbot forwards full transcript to mock-LLM including any PAN the user typed
- No outbound-request audit trail (which requests went to which external endpoint, with what payload)

### STRIDE analysis

| Threat | Description | Finding | Severity | Mitigation status |
|---|---|---|---|---|
| **S**poofing | App talks to attacker-controlled endpoint pretending to be legit service | No defense currently; depends on TLS pinning which isn't implemented | — | Planned (M6) |
| **T**ampering | Attacker modifies webhook response to influence app state | No integrity check on webhook callbacks | — | Planned (M6) |
| **R**epudiation | Outbound request to external service with no log | No outbound request log; V-34's log-any-forwarding will partially address | Medium | Planned |
| **I**nformation Disclosure | PAN forwarded to LLM provider | **V-34** — support messages forwarded verbatim to mock-LLM; no scrubbing layer | High | Planned (M6) |
| **D**enial of Service | App DoS'd by slow external endpoint | No timeout on outbound requests | — | Planned (M6) |
| **E**levation of Privilege | SSRF — attacker uses webhook URL to reach internal services | **V-14** — webhook URL unrestricted | High | Planned (M6) |

**Findings on this boundary:** V-14 (planned), V-34 (planned)
**Fixes applied:** none yet — the modules (webhooks, LLM chatbot) aren't built. This boundary is documented now because the threat exists before the code does, and knowing it constrains the design.

**Why it's included despite having no current findings:** The findings are the specific instances; the boundary is the structural concern. An architecture review that omits boundaries with "no current findings" isn't reviewing architecture — it's documenting what happened to be tested. Boundary 5 will have findings in M6; the model is honest about what's coming.

---

## Boundary 6 — Operator ↔ Production

**What crosses:** Configuration, secrets, migrations, deploys. A CI pipeline pushes code; a migration script modifies production schema; a developer's `.env` contains production credentials.

**Zone transition:** CI / human operator → production runtime. The transition happens rarely (deployments) but each transition has high impact — mistakes here affect everything at once.

**Controls present:**
- Migrations are versioned and idempotent-ish (single-transaction)
- `.env.example` documented
- CI check `rls-check.sh` enforces DB invariants at deploy time
- Lint check `no-pool-in-repos.sh` enforces code invariants at deploy time

**Controls absent or broken:**
- **V-06** — `LendStack_App_Pr0d_2024!` in git history (committed at M0, "removed" in a later commit, still in history)
- No secret rotation policy documented
- No `log_connections` (V-42) — connection-time audit trail absent
- Deployment to production not documented as a pipeline (this is a lab; but the *controls* required are named)

### STRIDE analysis

| Threat | Description | Finding | Severity | Mitigation status |
|---|---|---|---|---|
| **S**poofing | Attacker connects to prod using committed credentials | **V-06** — DB credential in git history; verified retrievable via `git log -p -- .env` | Critical | Documented under #4; not remediated in #1's scope |
| **T**ampering | Unauthorized config change bypasses CI | `rls-check.sh` catches DB config drift; lint catches code-pattern drift; both require CI integration to matter | High | ✅ Checked in CI (manual in lab, automated on real deploys) |
| **R**epudiation | Config change with no audit trail | Postgres has `pg_stat_activity` but `log_connections` off (V-42); migrations not audit-logged | Medium | Planned |
| **I**nformation Disclosure | Secrets committed to git | **V-06** — same as above | Critical | Documented |
| **D**enial of Service | Malformed migration breaks prod | Migrations run in transaction; failure rolls back | ✅ mitigated | Single-transaction pattern applied |
| **E**levation of Privilege | CI role grants itself more DB privilege than needed | `lendstack_owner` created by migration 001 — but the CI role creating it isn't documented | — | Planned |

**Findings on this boundary:** V-06, V-30 (config drift), V-35 (audit gaps), V-42
**Fixes applied:** V-30 fix is *enforced* by boundary 6's CI check — the fix on boundary 3 is guaranteed by controls on boundary 6.

**Why this boundary is the one auditors care most about:** Boundaries 1–5 are runtime threats. Boundary 6 is *how the runtime is kept honest*. The CI check on this boundary is what keeps the fixes on boundaries 2 and 3 from drifting back. A fix without a boundary-6 control is a temporary state; a fix with one is a durable property.

---

## Cross-reference — findings to boundaries

| Finding | Primary boundary | Also crosses | Severity |
|---|---|---|---|
| V-01 | 1 (Client ↔ API) | — | Critical |
| V-03 | 1 | — | High |
| V-04 | 1 | — | Medium |
| V-06 | 6 (Operator ↔ Prod) | 5 (blast radius) | Critical |
| V-08 | 1 | — | Medium |
| V-10 | 2 (Tenant ↔ Tenant) | — | High |
| V-11 | 1, 4 | — | High |
| V-14 | 5 (App ↔ External) | — | High |
| V-16 | 1 | — | High |
| V-19 | 4 (User ↔ Role) | — | Critical |
| V-20 | 1 | — | High |
| V-30 | 2, 3 (App ↔ DB), 6 | — | Critical |
| V-31 | 2, 3 | — | High |
| V-32 | 2 | — | High |
| V-33 | 4 | — | Critical |
| V-34 | 5 | — | High |
| V-40 | 1, 3 | — | Medium |
| V-41 | 3, 4 | — | High |
| V-42 | 3, 6 | — | Medium |

---

## What the boundaries reveal

Three patterns emerge when findings are grouped by boundary rather than by severity or type:

**1. Multi-layer failures cluster.** V-30, V-31, and V-32 all live at boundary 2, and all three represent *the same failure mode*: a defense that looks present but doesn't fire. This isn't a coincidence — boundaries with redundant controls (RLS + middleware + query filters) are exactly the ones where all three controls can be silently broken because each assumes the others work. **Redundant defense is a risk if the redundancy is unverified.**

**2. Boundary 6 is the multiplier.** A finding at boundary 2 (like V-30) is severe. But the *reason* V-30 stays severe after the fix is that boundary 6 has no enforcement. Adding `rls-check.sh` turns boundary 6 from a threat into a control — and it's the check that makes boundary 2's fixes durable. In production terms: the CI check is worth more than the fix it enforces, because the check catches every future recurrence.

**3. Boundaries 1 and 5 have the most findings but the lowest structural weight.** These are the boundaries closest to "the internet" — they accumulate the typical web-app findings (auth bypass, rate limits, SSRF). They're important, but they're the categories security teams know how to handle. Boundaries 2, 3, 4, and 6 are the ones that reveal the *architecture*: are trust zones actually isolated, is the data layer actually defensive, is authority actually separated, is production actually guarded? Those four questions are what an architecture review is *for*.

**The finding pattern across LendStack maps this precisely:** the highest-severity findings are not on boundary 1 (the "obvious" attack surface). They're on boundaries 2, 3, and 4 — where the controls looked correct but weren't. That's what a STRIDE-driven, boundary-based threat model surfaces that a vulnerability scan doesn't.

---

## How to use this document

- **For finding files:** each finding cross-references its boundary. When #2, #3, #4 add findings, they reference this model rather than re-deriving where the boundary is.
- **For the compliance overlay:** each compliance requirement (PCI DSS, GLBA, SOX, ISO) will be mapped to one or more boundaries — e.g., segregation of duties ↔ boundary 4. See `compliance-overlay.md` (in progress).
- **For the next remediation cycle:** boundaries with the most planned-but-unbuilt findings (boundary 5, boundary 6's V-42) are where the next review cycle should focus.
