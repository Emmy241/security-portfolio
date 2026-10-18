# #1: Secure Multi-Tenant SaaS Architecture & Access Control

| Field | Value |
|---|---|
| **Status** | Findings: 4/4 documented with evidence. Trust-boundary + STRIDE + compliance-overlay docs: in progress. CI check + `secure-reference` branch: in progress. |
| **Worked example** | [LendStack](../../lendstack/): a multi-tenant fintech/lending SaaS built for this portfolio |
| **Findings** | 2 Critical (V-30, V-33), 2 High (V-31, V-32) |
| **Related** | [V-10 (IDOR)](../02-webapp-api-assessment/findings/v10-idor-invoices.md) documented under #2: same system, different view |
| **Compliance overlay** | PCI DSS 4.0, GLBA 314.4, AML/KYC, Fair Lending (mapped per finding, full overlay in progress) |

**Contents:** [TL;DR](#tldr) · [Problem](#problem) · [Approach](#approach) · [Findings](#what-i-built-findings) · [CI check](#the-ci-check-least-privilege-as-a-technical-control) · [Maker-checker gate](#the-maker-checker-gate-defense-at-the-data-layer-not-just-the-route) · [Evidence](#evidence) · [Design principles](#architecture-design-principles-applied) · [What's in progress](#whats-in-progress-honest-scope) · [How to reproduce](#how-to-reproduce) · [Related projects](#related-projects) · [What I'd do differently](#what-id-do-differently)

---

## TL;DR

A multi-tenant SaaS platform that **looks** like it has tenant isolation and financial controls. It doesn't have either. Four findings (two Critical, two High) demonstrate this end to end, all with reproducible evidence against a real, running system.

The story isn't "here are some bugs." The story is: **defense in depth is a claim, and the platform failed on every layer simultaneously.** RLS was enabled but inert (V-30). The tenant middleware was correctly written but bypassed by repositories (V-32). Files had no tenant column at all (V-31). Money-movement approval had a `created_by` and `approved_by` column but never compared them (V-33).

Each finding is individually fixable. The **architecture** problem is that the system was designed as though defense in depth worked, and no single layer did. That's the review this project delivers.

---

## Problem

Multi-tenant SaaS platforms fail in a specific, well-documented pattern: the tenant boundary exists at the application layer, the database layer, and the query layer, and **each layer assumes the others work**. When one layer's defense silently fails, the others don't catch it. The system continues to look isolated while leaking everything.

In a fintech/lending platform, the consequences extend beyond confidentiality:

- **Cross-tenant reads** (V-30, V-31, V-32) leak another tenant's customers, invoices, and (via `storage_path` disclosure) the layout of the on-disk file store.
- **Self-approved money movements** (V-33) violate segregation of duties, a control that PCI DSS 6.4.2, GLBA 314.4(c), SOX ITGC, and ISO 27001:2022 A.5.3 all require. In a lending platform, this isn't a compliance formality: it's the control that turns a single malicious insider into a two-person conspiracy.

The problem this project addresses: **can I demonstrate that a platform claiming tenant isolation and financial controls doesn't actually have them, and prove it with the same rigor that would be expected of an architecture review (threat model, STRIDE per boundary, compliance overlay, and CI enforcement) rather than a list of bugs?**

LendStack is the worked example. It's a small enough system to reason about end to end, and real enough that the failures are the same shape they'd be at scale.

---

## Approach

The methodology follows five principles. Each is a choice, and each is defensible.

1. **Findings are the evidence; the architecture narrative is the deliverable.** The four findings aren't the review; they're what the review *produced*. The trust boundaries, STRIDE analysis, and compliance overlay (all in progress) are what turn the findings into an architecture review rather than a pentest report.

2. **Name the layer that failed, and the layer that should have caught it.** Every finding explicitly states: (a) the bug, (b) the defense-in-depth layer that was supposed to catch it, (c) why that layer didn't. V-30 states "the app role owns RLS-enabled tables, so RLS doesn't fire." V-32 states "the route correctly wires the tenant middleware, and the repository bypasses it." This layering is the entire point.

3. **Remediate at the layer where the finding lives, and enforce it in CI.** V-31 is a schema problem: the fix is an `ALTER TABLE`, not a code change. V-32 is a code-pattern problem: the fix is a lint rule that fails the build on `req.pool.query` in repositories, not just a one-line patch. Every finding names its CI-level remediation, not just its code-level fix.

4. **Compliance mapping is a control check, not a checklist.** Each finding maps to specific compliance requirements: not "this relates to PCI" but "this violates PCI DSS 6.4.2, which requires X, and here's the specific control gap." The full overlay is in progress, but the finding files each carry their own compliance annotation.

5. **The `secure-reference` branch demonstrates the fix without breaking the vulnerable version.** The vulnerable `main` branch stays exploitable (that's the demo). The `secure-reference` branch applies each fix and passes the CI check. Reviewers can diff the two, run the CI check on both, and see the before/after as a code artifact rather than a claim.

---

## What I built: findings

| Finding | Severity | Impact | Layer that failed |
|---|---|---|---|
| [**V-30**: RLS bypass via table ownership](findings/v30-tenant-isolation-bypass.md) | **Critical** | Every tenant-scoped table returns all tenants' rows to any authenticated user | Database (RLS policy inert because app role owns tables, no `FORCE`) |
| [**V-31**: Files table has no tenant isolation](findings/v31-files-no-tenant-isolation.md) | High | Cross-tenant file metadata + `storage_path` disclosure | Schema (no `tenant_id` column) + application (repo bypasses middleware) + RLS (policy is a join) |
| [**V-32**: Admin export bypasses tenant middleware](findings/v32-admin-export-bypasses-tenant-middleware.md) | High | Cross-tenant invoice export via a single authenticated GET (2969 bytes = all tenants' records) | Application (repository uses `req.pool` instead of `req.withTenant`) |
| [**V-33**: No maker-checker on transfers](findings/v33-no-maker-checker-on-transfers.md) | **Critical** | Transfer created and self-approved by the same user; DB records `self_approved = t` | Application (approval route doesn't compare `created_by` vs `req.user.id`) + database (no `CHECK` constraint) |

**Companion finding (documented under #2):** [**V-10**: IDOR on `/invoices/:id`](../02-webapp-api-assessment/findings/v10-idor-invoices.md). Same "tenant boundary not enforced" pattern, documented in the web/API assessment project because the exploitation path is a direct HTTP request.

### The coherent story across the four findings

V-30, V-31, and V-32 all demonstrate the same root cause: **the tenant boundary is enforced in some layers and assumed in others, and the assumed layers don't work.** V-33 demonstrates the *same failure mode applied to a different control*: segregation of duties has data-model support (`created_by` vs `approved_by` columns) and no enforcement.

The narrative that connects them: **the codebase reads as a system with tenant isolation and financial controls. It is a system with neither.** Every layer that looks like a control (RLS policies, tenant middleware, `created_by`/`approved_by` columns, role-based route guards) is present and non-functional in a specific, verifiable way.

This is what a reviewer needs to see: not "you have four bugs" but "you have a systematic gap between what the code looks like it enforces and what it actually enforces, and here are four examples of the pattern."

---

## The CI check: least-privilege as a technical control

V-30's remediation introduces the artifact that makes the architecture review *actionable* rather than advisory: a CI check that fails the build if the database configuration drifts back to the vulnerable state.

The check queries `pg_class`, `pg_roles`, and `pg_class.relforcerowsecurity` for three conditions:

1. Any tenant-scoped table owned by the app role (`lendstack_app`)
2. Any tenant-scoped table without `FORCE ROW LEVEL SECURITY` set
3. The app role holding `BYPASSRLS`

If any condition is met, the build fails. On `main`, it fails (by design: the vulnerable configuration is live). On `secure-reference`, it passes (the fix is applied).

**Why this is the centerpiece of the project, not an afterthought:** every other finding can be described as "here's a bug and here's the fix." That's a pentest. The CI check is what converts "we fixed it" into "we can't un-fix it accidentally." Every finding in this review has a corresponding CI-level enforcement: the check is the mechanism that keeps the fix from drifting back after the next six months of code changes.

**Status:** the query logic is written and documented in V-30's fix section. The CI script (`infra/checks/rls-check.sh`) that wraps it as a build-failing check is **in progress**; see [What's in progress](#whats-in-progress-honest-scope).

---

## The maker-checker gate: defense at the data layer, not just the route

V-33's remediation introduces the second load-bearing artifact: a database-level `CHECK` constraint that prevents self-approval even if a future route handler forgets to check.

```sql
ALTER TABLE transfers
  ADD CONSTRAINT transfers_no_self_approval
  CHECK (approved_by IS NULL OR approved_by != created_by);
```

The application-level check (in `approveTransfer`) is the user-facing control: it returns a proper `403` with a clear error message. The database constraint is the **invariant**: it cannot be bypassed by any code path, including a future route handler, an administrative script, or a migration. Both are required:

- Application check without the constraint fails silently on any alternate write path.
- Constraint without the application check fails with a `500` instead of a `403`: the user doesn't get a clear message, and the SOC can't distinguish attempted attack from bug.

Together, they enforce maker-checker as an architectural property, not a convention.

**Status:** the constraint is documented in V-33's fix section. The `secure-reference` branch applying it is **in progress**; see [What's in progress](#whats-in-progress-honest-scope).

---

## Evidence

| File | What it proves |
|---|---|
| [`evidence/before/rls-bypass.png`](evidence/before/rls-bypass.png) | Cross-tenant query returns 3 rows (V-30) |
| [`evidence/before/rls-ownership.png`](evidence/before/rls-ownership.png) | Every table owned by `lendstack_app`, `relforcerowsecurity=f` (V-30) |
| [`evidence/v31-cross-tenant-file.json`](evidence/v31-cross-tenant-file.json) | Acme's token returns Beta's file metadata + `storage_path` (V-31) |
| [`evidence/v31-schema-before.txt`](evidence/v31-schema-before.txt) | `\d files` showing missing `tenant_id` column (V-31) |
| [`evidence/v32-cross-tenant-export.json`](evidence/v32-cross-tenant-export.json) | Export returns 15 rows across 3 tenants (V-32) |
| [`evidence/v32-raw-response.json`](evidence/v32-raw-response.json) | Full 2969-byte raw response (V-32) |
| [`evidence/v33-self-approval.txt`](evidence/v33-self-approval.txt) | 204 response for self-approval (V-33) |
| [`evidence/v33-db-state.txt`](evidence/v33-db-state.txt) | DB query: `self_approved = t` (V-33) |

Every finding's evidence is reproducible from the running system; see each finding's "Verification test" section. No proprietary tooling, no paid tier, no cloud account. Everything runs locally via `docker compose up`.

**Not yet captured:** `secure-reference` branch evidence (the fixes applied, CI check passing). This is a known gap; see [What's in progress](#whats-in-progress-honest-scope).

---

## Architecture design principles applied

These are the meta-observations the finding set demonstrates. They are worth stating explicitly because they're the actual transferable skill: the findings are specific, but the pattern is general.

1. **"Defense in depth" is a claim that requires verification, not a fact that comes from layering.** V-30/31/32 all demonstrate three-layer controls where all three layers failed. A reviewer who asks "do you have RLS?" gets a "yes." A reviewer who asks "does RLS actually filter?" gets a "no." The architecture review is the difference between those two questions.

2. **Configuration that looks secure is a specific attack surface.** RLS enabled + policy present = the appearance of isolation. The actual protection depends on `FORCE`, ownership, `BYPASSRLS`, and whether queries run in a session with `app.tenant_id` set. Four conditions, any of which can silently fail. The architecture review is the practice of enumerating those conditions and verifying each one.

3. **Schema absence is harder to catch than code bugs.** V-31 (`files` has no `tenant_id`) is invisible to a code review that reads SQL. The query has no missing filter; it has a missing *column* to filter on. Schema-level tenant isolation has to be a CI check, not a convention, because "remember to add `tenant_id` to every new table" is a rule that gets forgotten.

4. **Financial controls are integrity controls, and they need data-layer enforcement.** V-33's `self_approved = t` is a database record, not an API error, which means the control gap is verifiable from the data, not just from the code. The maker-checker constraint at the DB layer is the enforcement that survives refactors, library swaps, and developer turnover. Application-layer checks alone are conventions; constraints are properties.

5. **The fix is a CI check, and the CI check is the deliverable.** Every finding in this set has a code fix and a CI check. The code fix closes the specific instance. The CI check prevents the class. Reviewers evaluating an architecture review should look for the CI checks as the actual remediation: "here's a fix" is a patch; "here's a fix and here's how we catch the next instance" is engineering.

6. **Adversarial review needs a working exploit, not just a code walk.** All four findings were demonstrated against a running system, not inferred from code reading. This is what separates a pentest from a code review: the running system confirms the vulnerability is *actually exploitable*, not just theoretically present. Code review says "this looks wrong." Verification says "the token returns Beta's invoice."

---

## What's in progress (honest scope)

The portfolio description for this project includes the six-trust-boundary diagram, STRIDE threat model per boundary, and full compliance overlay. **They are not yet written.** Current status:

| Deliverable | Status | Notes |
|---|---|---|
| 4 findings with reproducible evidence | ✅ Complete | V-30 (Critical), V-31 (High), V-32 (High), V-33 (Critical) |
| Companion finding V-10 (IDOR) | ✅ Complete | Documented under #2, cross-referenced here |
| Six-trust-boundary diagram | 🚧 In progress | Concept exists (browser/app, app/db, tenant/tenant, tenant/platform, customer/support, admin/operator); diagram + narrative not yet written |
| STRIDE threat model per boundary | 🚧 In progress | Per-boundary analysis to be written. The four findings map to specific boundaries (V-30/31/32 to tenant/tenant; V-33 to admin/operator) |
| Compliance overlay | 🚧 In progress | Per-finding compliance annotations are in each finding file; the full overlay document (PCI DSS 4.0, GLBA 314.4, AML/KYC, Fair Lending → controls → findings) is not yet written |
| CI check script (`infra/checks/rls-check.sh`) | 🚧 In progress | Query logic written in V-30's fix section; wrapper script + GitHub Actions integration not yet coded |
| `secure-reference` branch with applied fixes | 🚧 In progress | Fixes documented per finding; branch not yet created. This is where the CI check passes and the "after" screenshots come from |
| V-34: Cardholder data in LLM path | 🚧 Planned | Support chatbot forwards full transcript (incl. PAN) to `mock-llm`. Requires M6 (support module) to build first |

This README will be updated as each is completed. The current deliverable, four findings with reproducible evidence and per-finding compliance annotations, is substantial on its own; the "in progress" items complete the architecture-review framing rather than establish it.

**Why be explicit about this?** Same reason as #3: a portfolio that presents "in progress" as "complete" fails the first serious interview question. A portfolio that says "here's what's done, here's the story it tells, and here's what's next" demonstrates the judgment that gets hired.

---

## How to reproduce

Full setup (from the LendStack repo root):

```bash
cd lendstack
docker build -t lendstack-api-test ./target-app
docker compose up -d
sleep 3
curl -s localhost:3000/healthz
# → {"status":"ok","service":"lendstack-api"}
```

### V-30: RLS bypass

```bash
docker compose exec -T postgres psql -U lendstack_app -d lendstack <<'SQL'
SET app.tenant_id = 'a0000001-0000-4000-8000-000000000001';
SELECT tenant_id, count(*) FROM invoices GROUP BY tenant_id ORDER BY tenant_id;
SQL
```

**Expected:** **3 rows** (Acme, Beta, Gamma; 5 invoices each). Not 1 row. That's the bypass.

### V-31, V-32, V-33: authenticated exploits

```bash
TOKEN_A=$(curl -s -X POST localhost:3000/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"owner@acme-lending.test","password":"Password123!"}' | jq -r .access_token)

# V-31: cross-tenant file metadata
curl -s -H "Authorization: Bearer $TOKEN_A" \
  localhost:3000/api/v1/files/b0000001-0000-4000-8000-000000000801 | jq .

# V-32: cross-tenant export
curl -s -H "Authorization: Bearer $TOKEN_A" \
  localhost:3000/api/v1/admin/export \
  | jq '{count: (.invoices | length), tenants: (.invoices | map(.tenant_id) | unique)}'

# V-33: self-approval
TRANSFER_ID=$(curl -s -X POST localhost:3000/api/v1/transfers \
  -H "Authorization: Bearer $TOKEN_A" -H 'content-type: application/json' \
  -d '{"from_account_id":"a0000001-0000-4000-8000-000000000201",
       "to_account_id":"a0000001-0000-4000-8000-000000000202",
       "amount_cents":100000}' | jq -r .transfer.id)

curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  -H "Authorization: Bearer $TOKEN_A" \
  localhost:3000/api/v1/transfers/$TRANSFER_ID/approve
# Expected: 204
```

Each finding file contains its own "Verification test" section with the full before/after commands.

---

## Related projects

- **[#2: Web Application & API Security Assessment](../02-webapp-api-assessment/):** same LendStack target, offensive-review lens. V-10 (IDOR) is documented there rather than under #1 because the exploitation path is direct HTTP; the architecture-level cause (missing tenant filter + inert RLS) is the same V-30 finding. The two projects are cross-referenced by design: a single system reviewed from two angles.

- **[#3: SIEM Detection Engineering](../03-siem-detection/):** LendStack's auth + admin + money logs feed #3's detection rules. V-33's fix (add a `transfer.approval_denied` audit event on a self-approval attempt) creates the log signal that #3's planned LDS-MONEY-001 rule detects. V-41 (role changes not audited) is documented as #3's prerequisite: the same finding viewed from the architecture side.

- **[#4: OAuth & JWT Security Review](../04-oauth-jwt-review/):** LendStack's auth layer is #4's target. V-01 (JWT signature not verified) is documented under #4; V-30's remediation adds the tenant context that a correct JWT signature would scope. Both findings operate on the same authentication boundary.

- **[#5: Enterprise SOC Simulation Lab](../05-soc-lab/):** LendStack is one of two log sources in the SOC lab (alongside Windows Event Logs / Sysmon / packet capture). #1's architectural findings become #5's detection targets.

---

## What I'd do differently

Three things, in order of how much they would have changed the review.

1. **Write the trust-boundary diagram and STRIDE first, findings second.** I found the vulnerabilities, then started drafting the architecture narrative. But the natural flow is the opposite: draw the six boundaries, run STRIDE per boundary, and *then* the findings fall out as "the specific instances of each threat." Doing it in the reverse order means the findings came first and the architecture is retrofitted, which is honest, but less elegant than the ideal. Next time: draw the boundary diagram in the first hour of the review, before opening the codebase.

2. **Make `secure-reference` a first-class deliverable, not a follow-on.** The vulnerable `main` branch and the secure `secure-reference` branch should be created at the same time, with the fixes applied in parallel with the findings, not after. This makes the review look like what it actually is: a remediation lifecycle, not a vulnerability report. It also means the CI check has a green target from day one, rather than a future branch that needs building.

3. **The compliance overlay should drive the finding severity, not the other way around.** I rated V-30 and V-33 as Critical based on technical impact (tenant isolation bypass, fund movement). Then I mapped them to PCI/GLBA/SOX/ISO requirements. The stronger approach, and the one that reflects how a compliance-driven review actually works, is to start from the standard's requirements, ask "does this control work?", and let the finding emerge from the compliance gap. V-33's "segregation of duties" finding would have been found in half the time if I had started from ISO 27001 A.5.3 rather than reading the transfer route. Next time: run the compliance checklist first, then verify each control technically.

None of these are "the review failed." They are the gap between "good architecture review" and "real production engagement." Naming the gap is what makes the review credible rather than inflated.
