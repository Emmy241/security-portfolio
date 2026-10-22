# #1 — Secure Multi-Tenant SaaS Architecture & Access Control

| Field | Value |
|---|---|
| **Status** | 4 findings (2C/2H) documented and **all fixed via migrations 001–004** with CI-enforced prevention (`rls-check.sh` + `no-pool-in-repos.sh`). Trust-boundary + STRIDE + compliance-overlay docs: in progress. |
| **Worked example** | [LendStack](../../lendstack/) — a multi-tenant fintech/lending SaaS built for this portfolio |
| **Findings** | 2 Critical (V-30, V-33), 2 High (V-31, V-32) |
| **Related** | [V-10 (IDOR)](../02-webapp-api-assessment/findings/v10-idor-invoices.md) documented under #2 — same system, different view |
| **Compliance overlay** | PCI DSS 4.0, GLBA 314.4, AML/KYC, Fair Lending (mapped per finding, full overlay in progress) |

---

## TL;DR

A multi-tenant SaaS platform that **looks** like it has tenant isolation and financial controls. It doesn't have either. Four findings — two Critical, two High — demonstrate this end to end, all with reproducible evidence against a real, running system.

The story isn't "here are some bugs." The story is: **defense in depth is a claim, and the platform failed on every layer simultaneously.** RLS was enabled but inert (V-30). The tenant middleware was correctly written but bypassed by repositories (V-32). Files had no tenant column at all (V-31). Money-movement approval had a `created_by` and `approved_by` column but never compared them (V-33).

Each finding is individually fixable. The **architecture** problem is that the system was designed as though defense in depth worked, and no single layer did. That's the review this project delivers — and it delivers it with the fix, not just the finding: all four are remediated via versioned migrations with CI-enforced prevention. See `evidence/main-vs-secure-reference.txt` for the before/after diff.

---

## Problem

Multi-tenant SaaS platforms fail in a specific, well-documented pattern: the tenant boundary exists at the application layer, the database layer, and the query layer — and **each layer assumes the others work**. When one layer's defense silently fails, the others don't catch it. The system continues to look isolated while leaking everything.

In a fintech/lending platform, the consequences extend beyond confidentiality:

- **Cross-tenant reads** (V-30, V-31, V-32) leak another tenant's customers, invoices, and — via `storage_path` disclosure — the layout of the on-disk file store.
- **Self-approved money movements** (V-33) violate segregation of duties, a control that PCI DSS 6.4.2, GLBA 314.4(c), SOX ITGC, and ISO 27001:2022 A.5.3 all require. In a lending platform, this isn't a compliance formality — it's the control that turns a single malicious insider into a two-person conspiracy.

The problem this project addresses: **can I demonstrate that a platform claiming tenant isolation and financial controls doesn't actually have them, and prove it with the same rigor that would be expected of an architecture review — threat model, STRIDE per boundary, compliance overlay, and CI enforcement — rather than a list of bugs?**

LendStack is the worked example. It's a small enough system to reason about end to end, and real enough that the failures are the same shape they'd be at scale.

---

## Approach

The methodology follows five principles. Each is a choice, and each is defensible:

1. **Findings are the evidence; the architecture narrative is the deliverable.** The four findings aren't the review — they're what the review *produced*. The trust boundaries, STRIDE analysis, and compliance overlay (all in progress) are what turn the findings into an architecture review rather than a pentest report.

2. **Name the layer that failed, and the layer that should have caught it.** Every finding explicitly states: (a) the bug, (b) the defense-in-depth layer that was supposed to catch it, (c) why that layer didn't. V-30 states "the app role owns RLS-enabled tables, so RLS doesn't fire." V-32 states "the route correctly wires the tenant middleware, and the repository bypasses it." This layering is the entire point.

3. **Remediate at the layer where the finding lives, and enforce it in CI.** V-31 is a schema problem — the fix is an `ALTER TABLE`, not a code change. V-32 is a code-pattern problem — the fix is a lint rule that fails the build on `req.pool.query` in repositories, not just a one-line patch. Every finding names its CI-level remediation, not just its code-level fix.

4. **Compliance mapping is a control check, not a checklist.** Each finding maps to specific compliance requirements — not "this relates to PCI" but "this violates PCI DSS 6.4.2, which requires X, and here's the specific control gap." The full overlay is in progress, but the finding files each carry their own compliance annotation.

5. **Migrations demonstrate the fix without breaking the vulnerable version.** The app starts vulnerable after `docker compose up`. Each migration applies one fix. After all four are applied, the CI checks pass. The before/after story is one command: apply migrations or don't.

---

## What I built — findings

| Finding | Severity | Impact | Layer that failed |
|---|---|---|---|
| [**V-30** — RLS bypass via table ownership](findings/v30-tenant-isolation-bypass.md) | **Critical** | Every tenant-scoped table returns all tenants' rows to any authenticated user | Database (RLS policy inert because app role owns tables, no FORCE) |
| [**V-31** — Files table has no tenant isolation](findings/v31-files-no-tenant-isolation.md) | High | Cross-tenant file metadata + `storage_path` disclosure | Schema (no `tenant_id` column) + application (repo bypasses middleware) + RLS (policy is a join) |
| [**V-32** — Admin export bypasses tenant middleware](findings/v32-admin-export-bypasses-tenant-middleware.md) | High | Cross-tenant invoice export via a single authenticated GET (2969 bytes = all tenants' records) | Application (repository uses `req.pool` instead of `req.withTenant`) |
| [**V-33** — No maker-checker on transfers](findings/v33-no-maker-checker-on-transfers.md) | **Critical** | Transfer created and self-approved by the same user; DB records `self_approved = t` | Application (approval route doesn't compare `created_by` vs `req.user.id`) + database (no `CHECK` constraint) |

**Companion finding (documented under #2):**

- [**V-10** — IDOR on `/invoices/:id`](../02-webapp-api-assessment/findings/v10-idor-invoices.md) — same "tenant boundary not enforced" pattern, documented in the web/API assessment project because the exploitation path is a direct HTTP request.

### The coherent story across the four findings

V-30, V-31, and V-32 all demonstrate the same root cause — **the tenant boundary is enforced in some layers and assumed in others, and the assumed layers don't work.** V-33 demonstrates the *same failure mode applied to a different control*: segregation of duties has data-model support (`created_by` vs `approved_by` columns) and no enforcement.

The narrative that connects them: **the codebase reads as a system with tenant isolation and financial controls. It is a system with neither.** Every layer that looks like a control — RLS policies, tenant middleware, `created_by`/`approved_by` columns, role-based route guards — is present and non-functional in a specific, verifiable way.

This is what a reviewer needs to see: not "you have four bugs" but "you have a systematic gap between what the code looks like it enforces and what it actually enforces, and here are four examples of the pattern."

---

## The CI check — least-privilege as a technical control

V-30's remediation introduces the artifact that makes the architecture review *actionable* rather than advisory: a CI check that fails the build if the database configuration drifts back to the vulnerable state.

The check queries `pg_class`, `pg_roles`, and `pg_class.relforcerowsecurity` for three conditions:

1. Any tenant-scoped table owned by the app role (`lendstack_app`)
2. Any tenant-scoped table without `FORCE ROW LEVEL SECURITY` set
3. The app role holding `BYPASSRLS`

If any condition is met, the build fails. Before migrations: fails (by design — the vulnerable configuration is live). After migrations: passes (the fix is applied).

**Why this is the centerpiece of the project, not an afterthought:** every other finding can be described as "here's a bug and here's the fix." That's a pentest. The CI check is what converts "we fixed it" into "we can't un-fix it accidentally." Every finding in this review has a corresponding CI-level enforcement — the check is the mechanism that keeps the fix from drifting back after the next six months of code changes.

**Status:** ✅ **Complete.** `infra/checks/rls-check.sh` exists at `lendstack/infra/checks/rls-check.sh`, fails before migrations are applied (exit 1, listing every table where the app role owns it or `FORCE RLS` is unset), and passes after all four migrations. Verified in `evidence/before/ci-check-fail.txt` and `evidence/after/ci-check-pass.txt`.

---

## The maker-checker gate — defense at the data layer, not just the route

V-33's remediation introduces the second load-bearing artifact: a database-level `CHECK` constraint that prevents self-approval even if a future route handler forgets to check.

```sql
ALTER TABLE transfers
  ADD CONSTRAINT transfers_no_self_approval
  CHECK (approved_by IS NULL OR approved_by != created_by);
```

The application-level check (in `approveTransfer`) is the user-facing control — it returns a proper `403` with a clear error message. The database constraint is the **invariant** — it cannot be bypassed by any code path, including a future route handler, an administrative script, or a migration. Both are required:

- Application check without the constraint fails silently on any alternate write path.
- Constraint without the application check fails with a `500` instead of a `403` — the user doesn't get a clear message, and the SOC can't distinguish attempted attack from bug.

Together, they enforce maker-checker as an architectural property, not a convention.

**Status:** ✅ **Complete.** Applied via migration `003-fix-v33-maker-checker.sql`. The migration includes a data-remediation step (historical self-approved transfers reverted to `pending`, fact preserved in `audit_log` with action `self_approval_remediated`) before adding the `CHECK` constraint — the production gotcha that this kind of migration always hits. Verified: self-approval returns 403, alternate-user approval returns 204, direct SQL `UPDATE approved_by = created_by` hits the constraint. Evidence in `evidence/after/v33-fix-verification.txt`.

---

## Evidence

| File | What it proves |
|---|---|
| [`evidence/main-vs-secure-reference.txt`](evidence/main-vs-secure-reference.txt) | The before/after diff — all four findings closed |
| [`evidence/before/v30-query.txt`](evidence/before/v30-query.txt) | Before migrations: RLS returns 3 rows (all tenants) |
| [`evidence/before/v30-ownership.txt`](evidence/before/v30-ownership.txt) | Before migrations: every table owned by `lendstack_app`, `relforcerowsecurity=f` |
| [`evidence/before/ci-check-fail.txt`](evidence/before/ci-check-fail.txt) | Before migrations: `rls-check.sh` exits 1, lists every violated table |
| [`evidence/after/v30-query.txt`](evidence/after/v30-query.txt) | After migrations: RLS returns 1 row (correct tenant) |
| [`evidence/after/v30-ownership.txt`](evidence/after/v30-ownership.txt) | After migrations: every table owned by `lendstack_owner`, `relforcerowsecurity=t` |
| [`evidence/after/ci-check-pass.txt`](evidence/after/ci-check-pass.txt) | After migrations: `rls-check.sh` exits 0 |
| [`evidence/v31-cross-tenant-file.json`](evidence/v31-cross-tenant-file.json) | Pre-fix: Acme's token returns Beta's file + `storage_path` |
| [`evidence/v31-schema-before.txt`](evidence/v31-schema-before.txt) | Pre-fix: `\d files` missing `tenant_id` |
| [`evidence/after/v31-schema-after.txt`](evidence/after/v31-schema-after.txt) | Post-fix: `\d files` shows `tenant_id`, `NOT NULL`, FK |
| [`evidence/v32-cross-tenant-export.json`](evidence/v32-cross-tenant-export.json) | Pre-fix: 15 invoices, 3 tenants returned |
| [`evidence/v32-raw-response.json`](evidence/v32-raw-response.json) | Full 2969-byte raw response |
| [`evidence/after/v31-v32-fixes.txt`](evidence/after/v31-v32-fixes.txt) | V-31 and V-32 verification summary (404s, 5-row export, lint PASS) |
| [`evidence/v33-self-approval.txt`](evidence/v33-self-approval.txt) | Pre-fix: 204 on self-approval |
| [`evidence/v33-db-state.txt`](evidence/v33-db-state.txt) | Pre-fix: `self_approved = t` in DB |
| [`evidence/after/v33-fix-verification.txt`](evidence/after/v33-fix-verification.txt) | Post-fix: 403 + DB constraint + audit event |
| [`evidence/after/v33-constraint-violation.txt`](evidence/after/v33-constraint-violation.txt) | Post-fix: direct UPDATE rejected by CHECK |
| [`evidence/after/v33-denial-audit-event.json`](evidence/after/v33-denial-audit-event.json) | Post-fix: `transfer.approval_denied` event |

**Not yet captured:** PNG screenshots of the CI check and query outputs. The current evidence is the terminal output and query results, which is stronger than screenshots because it's independently reproducible. PNGs are optional.

Every finding's evidence is reproducible from the running system — see each finding's "Verification test" section. No proprietary tooling, no paid tier, no cloud account. Everything runs locally via `docker compose up`.

---

## Architecture design principles applied

These are the meta-observations the finding set demonstrates. They're worth stating explicitly because they're the actual transferable skill — the findings are specific, but the pattern is general:

1. **"Defense in depth" is a claim that requires verification, not a fact that comes from layering.** V-30/31/32 all demonstrate three-layer controls where all three layers failed. A reviewer who asks "do you have RLS?" gets a "yes." A reviewer who asks "does RLS actually filter?" gets a "no." The architecture review is the difference between those two questions.

2. **Configuration that looks secure is a specific attack surface.** RLS enabled + policy present = the appearance of isolation. The actual protection depends on `FORCE`, ownership, `BYPASSRLS`, and whether queries run in a session with `app.tenant_id` set. Four conditions, any of which can silently fail. The architecture review is the practice of enumerating those conditions and verifying each one.

3. **Schema absence is harder to catch than code bugs.** V-31 (files has no `tenant_id`) is invisible to a code review that reads SQL. The query has no missing filter — it has a missing *column* to filter on. Schema-level tenant isolation has to be a CI check, not a convention, because "remember to add `tenant_id` to every new table" is a rule that gets forgotten.

4. **Financial controls are integrity controls, and they need data-layer enforcement.** V-33's `self_approved = t` is a database record, not an API error — which means the control gap is verifiable from the data, not just from the code. The maker-checker constraint at the DB layer is the enforcement that survives refactors, library swaps, and developer turnover. Application-layer checks alone are conventions; constraints are properties.

5. **The fix is a CI check, and the CI check is the deliverable.** Every finding in this set has a code fix and a CI check. The code fix closes the specific instance. The CI check prevents the class. Reviewers evaluating an architecture review should look for the CI checks as the actual remediation — "here's a fix" is a patch; "here's a fix and here's how we catch the next instance" is engineering.

6. **Adversarial review needs a working exploit, not just a code walk.** All four findings were demonstrated against a running system, not inferred from code reading. This is what separates a pentest from a code review — the running system confirms the vulnerability is *actually exploitable*, not just theoretically present. Code review says "this looks wrong." Verification says "the token returns Beta's invoice."

---

## What's in progress (honest scope)

The portfolio description for this project includes the six-trust-boundary diagram, STRIDE threat model per boundary, and full compliance overlay. **They are not yet written.** Current status:

| Deliverable | Status | Notes |
|---|---|---|
| 4 findings with reproducible evidence | ✅ Complete | V-30 (Critical), V-31 (High), V-32 (High), V-33 (Critical) |
| Companion finding V-10 (IDOR) | ✅ Complete | Documented under #2, cross-referenced here |
| **V-30 fix** (migrations 001+002) | ✅ Complete | Ownership reassigned to `lendstack_owner`, `FORCE RLS`, login-lookup policy |
| **V-31 fix** (migration 004) | ✅ Complete | `files.tenant_id` backfilled + NOT NULL + FK + column-based RLS policy |
| **V-32 fix** (code + lint) | ✅ Complete | `exportInvoices` uses `req.withTenant`; lint rule `no-pool-in-repos.sh` prevents regression |
| **V-33 fix** (migration 003) | ✅ Complete | DB constraint `transfers_no_self_approval`, self-approval returns 403 + audit event |
| **CI check** `infra/checks/rls-check.sh` | ✅ Complete | Fails before migrations, passes after |
| **Lint rule** `infra/checks/no-pool-in-repos.sh` | ✅ Complete | Catches `req.pool.query` in repositories |
| **Before/after diff evidence** | ✅ Complete | `evidence/main-vs-secure-reference.txt` |
| Six-trust-boundary diagram | 🚧 In progress | Boundaries identified; diagram + narrative to write |
| STRIDE threat model per boundary | 🚧 In progress | Analysis per boundary to write |
| Compliance overlay document | 🚧 In progress | Per-finding annotations exist; full overlay to write |
| V-34 — Cardholder data in LLM path | 🚧 Planned | Depends on M6 (support module) |

This README will be updated as each is completed. **Four findings and their fixes are complete** — findings documented, exploited, remediated via migrations, verified, and CI-enforced. The remaining "in progress" items are the architecture-review framing (trust boundaries, STRIDE, compliance overlay) — they complete the review's presentation, not its substance.

**Why be explicit about this?** A portfolio that presents "in progress" as "complete" fails the first serious interview question. A portfolio that says "here's what's done, here's the story it tells, and here's what's next" demonstrates the judgment that gets hired.

---

## How to reproduce

LendStack runs in two states: **vulnerable** (after `docker compose up`, before migrations) and **fixed** (after applying migrations 001–004). The migrations tell the fix story; each one closes one finding.

Setup:

```bash
cd lendstack
docker build -t lendstack-api-test ./target-app
docker compose up -d
sleep 3
curl -s localhost:3000/healthz
# → {"status":"ok","service":"lendstack-api"}
# → VULNERABLE state: demos below all exploitable

# Apply all four migrations (each closes one finding)
for m in infra/migrations/00*.sql; do
  docker compose exec -T postgres psql -U postgres -d lendstack -f /dev/stdin < "$m"
done
# → FIXED state: same demos return safe responses

# Verify CI checks
./infra/checks/rls-check.sh            # exit 0 after fix
./infra/checks/no-pool-in-repos.sh     # exit 0 always (code is fixed)
```

### V-30 — RLS bypass

```bash
docker compose exec -T postgres psql -U lendstack_app -d lendstack <<'SQL'
SET app.tenant_id = 'a0000001-0000-4000-8000-000000000001';
SELECT tenant_id, count(*) FROM invoices GROUP BY tenant_id ORDER BY tenant_id;
SQL
```

Before migrations: **3 rows** (Acme, Beta, Gamma). After migrations: **1 row** (Acme only). That's the fix, verifiable in one query.

### V-31, V-32, V-33 — authenticated exploits

```bash
TOKEN_A=$(curl -s -X POST localhost:3000/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"owner@acme-lending.test","password":"Password123!"}' | jq -r .access_token)

# V-31: cross-tenant file metadata
# before migrations: 200 with Beta's file + storage_path.  after: 404
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer $TOKEN_A" \
  localhost:3000/api/v1/files/b0000001-0000-4000-8000-000000000801

# V-32: cross-tenant export
# before: 15 invoices, 3 tenants.  after: 5 invoices, 1 tenant
curl -s -H "Authorization: Bearer $TOKEN_A" \
  localhost:3000/api/v1/admin/export \
  | jq '{count: (.invoices | length), tenants: (.invoices | map(.tenant_id) | unique)}'

# V-33: self-approval
# before: 204.  after: 403
TRANSFER_ID=$(curl -s -X POST localhost:3000/api/v1/transfers \
  -H "Authorization: Bearer $TOKEN_A" -H 'content-type: application/json' \
  -d '{"from_account_id":"a0000001-0000-4000-8000-000000000201",
       "to_account_id":"a0000001-0000-4000-8000-000000000202",
       "amount_cents":100000}' | jq -r .transfer.id)

curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  -H "Authorization: Bearer $TOKEN_A" \
  localhost:3000/api/v1/transfers/$TRANSFER_ID/approve
```

Each finding file contains its own "Verification test" section with the full before/after commands.

---

## Related projects

- **[#2 — Web Application & API Security Assessment](../02-webapp-api-assessment/)** — Same LendStack target, offensive-review lens. V-10 (IDOR) is documented here rather than under #1 because the exploitation path is direct HTTP; the architecture-level cause (missing tenant filter + inert RLS) is the same V-30 finding.

- **[#3 — SIEM Detection Engineering](../03-siem-detection/)** — LendStack's auth + admin + money logs feed #3's detection rules. V-33's fix (add `transfer.approval_denied` audit event on self-approval attempt) creates the log signal that #3's planned LDS-MONEY-001 rule detects.

- **[#4 — OAuth & JWT Security Review](../04-oauth-jwt-review/)** — LendStack's auth layer is #4's target. V-01 (JWT signature not verified) is documented under #4; V-30's remediation adds the tenant context that a correct JWT signature would scope.

- **[#5 — Enterprise SOC Simulation Lab](../05-soc-lab/)** — LendStack is one of two log sources in the SOC lab (alongside Windows Event Logs / Sysmon / packet capture).

---

## What I'd do differently

Three things, in order of how much they'd have changed the review:

1. **Write the trust-boundary diagram and STRIDE first, findings second.** I found the vulnerabilities, then started drafting the architecture narrative. But the natural flow is the opposite: draw the six boundaries, run STRIDE per boundary, and *then* the findings fall out as "the specific instances of each threat." Next time: draw the boundary diagram in the first hour of the review.

2. **Make the fixed state a first-class artifact, not a follow-on.** The vulnerable version and the fixed version should be visible side by side from day one, with the migrations numbered in the same commit as the finding they close.

3. **The compliance overlay should drive the finding severity, not the other way around.** I rated V-30 and V-33 as Critical based on technical impact, then mapped them to PCI/GLBA/SOX/ISO requirements. The stronger approach is to start from the standard's requirements, ask "does this control work?", and let the finding emerge from the compliance gap.

None of these are "the review failed." They're the gap between "good architecture review" and "real production engagement." Naming the gap is what makes the review credible rather than inflated.
