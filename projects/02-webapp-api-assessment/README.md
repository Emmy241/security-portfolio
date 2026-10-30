# #2 — Web Application & API Security Assessment

| Field | Value |
|---|---|
| **Status** | 6 findings (2 Critical, 4 High) documented with reproducible evidence. |
| **Worked example** | [LendStack](../../lendstack/) — the same fintech/lending SaaS used in #1 |
| **Findings** | Critical: V-12 (SQLi), V-19 (Business Logic) · High: V-10 (IDOR), V-11 (Mass Assignment), V-13 (XSS), V-14 (SSRF) |
| **Related** | [V-30/31/32/33](../01-saas-architecture/) documented under #1 (architecture lens) |

---

## TL;DR

LendStack is a multi-tenant fintech platform. Project #1 reviewed it from the database and architecture layer, finding that defense-in-depth had collapsed. Project #2 reviews it from the **application and API layer** — the exact surface a black-box or grey-box penetration tester would attack.

The result is six findings, ranging from a Critical SQL injection to business logic flaws that allow self-approval and negative-value money movement. The story isn't just "here are some bugs" — it's that **every layer of the application trusted the layer above it**, allowing trivial privilege escalation once an attacker was inside.

## Problem

In a web application, the frontend is not a security boundary. Every authorization check, every data filter, and every business rule must be enforced by the backend API. When the API trusts the client to provide its own tenant ID, role, or transfer amount, the system is compromised.

LendStack makes a perfect case study because the vulnerabilities chain together:

1. **V-11 (Mass Assignment)** lets an unauthenticated attacker become an owner on any tenant.
2. **V-13 (Stored XSS)** allows an attacker to steal an admin's JWT.
3. **V-10 (IDOR)** allows reading cross-tenant invoices.
4. **V-12 (SQLi)** allows arbitrary database reads, writes, and DoS.
5. **V-19 (Business Logic)** allows double-spending and reverse transfers.

These aren't isolated bugs. They represent a systemic failure to enforce authorization and validation at the API boundary.

## Approach

This assessment followed a standard grey-box API methodology:

- **Authorization Testing:** Attempted cross-tenant reads (V-10) and role escalation (V-11).
- **Injection Testing:** Tested all user-controlled inputs for SQLi, using error-based, time-based, and UNION techniques (V-12).
- **Client-Side Injection:** Stored payloads in the database and verified execution in the admin context (V-13).
- **Server-Side Request Forgery:** Forced the API to fetch internal services using webhooks (V-14).
- **Business Logic Analysis:** Examined the transfer flow for race conditions, negative values, and missing idempotency (V-19).

Every finding was proven against a live, running instance of LendStack, with reproducible command-line evidence captured in the `evidence/` directory.

## What I built — findings

| Finding | Severity | Impact | Root Cause |
|---|---|---|---|
| [**V-10** — IDOR on `/invoices/:id`](findings/v10-idor-invoices.md) | High | Cross-tenant invoice read | Missing tenant filter in SQL + inert RLS |
| [**V-11** — Mass Assignment](findings/v11-mass-assignment.md) | High | Privilege escalation via `role` field | API trusts client-supplied authorization |
| [**V-12** — SQL Injection](findings/v12-sqli.md) | **Critical** | Arbitrary DB execution | String concatenation in `admin/search` |
| [**V-13** — Stored XSS](findings/v13-stored-xss.md) | High | Admin JWT theft | Unsanitized `innerHTML` rendering |
| [**V-14** — SSRF](findings/v14-ssrf.md) | High | Internal network access | Unvalidated server-side `fetch` |
| [**V-19** — Business Logic](findings/v19-business-logic.md) | **Critical** | Double-spend / reverse ledger | No idempotency, no negative amount check |

## The Attack Chain

The most powerful aspect of this assessment is how the findings chain:

1. An attacker exploits **V-11** to create an account with `role: "owner"`.
2. With that account, they exploit **V-12** to run SQL, reading arbitrary data.
3. They plant a **V-13** payload in a merchant memo.
4. A real administrator logs in, views the panel, and has their JWT stolen.
5. The attacker uses the admin JWT to access `/admin/export` and exfiltrate the entire platform's data.

This chain demonstrates that fixing one vulnerability is insufficient — the system needs a fundamental shift toward backend-enforced authorization.

## Fixes (M8)

The fixes for these findings are documented in each finding file. In summary:

- **V-10:** Add `AND tenant_id = $2` to the query, and fix the RLS layer (V-30).
- **V-11:** Never accept `role` or `tenant_id` from the client. Use invitations.
- **V-12:** Use parameterized queries. Remove error details from responses.
- **V-13:** Use `textContent` instead of `innerHTML`. Add a CSP.
- **V-14:** Block private IPs and metadata endpoints. Use an egress proxy.
- **V-19:** Add `CHECK (amount_cents > 0)`. Require an idempotency key. Use row-level locking.

All fixes are applied on the `secure-reference` migrations (except V-13 and V-14, which are mitigated in code).

## Related projects

- **[#1 — Secure Multi-Tenant SaaS Architecture](../01-saas-architecture/):** The architecture lens. V-30, V-31, V-32, and V-33 are documented there. They explain why V-10 is possible, and they are fixed via database migrations.
- **[#3 — SIEM Detection Engineering](../03-siem-detection/):** The detection rules that would alert on V-12 (SQLi) and V-11 (privilege escalation).
- **[#4 — OAuth & JWT Review](../04-oauth-jwt-review/):** The auth-layer findings (V-01, V-03, V-06) that made V-13's session hijacking possible.
