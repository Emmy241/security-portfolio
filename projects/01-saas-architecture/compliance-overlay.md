# Compliance Overlay — Regulatory Controls Mapped to LendStack

| Field | Value |
|---|---|
| **Project** | [#1 — Secure Multi-Tenant SaaS Architecture](README.md) |
| **Target** | [LendStack](../../lendstack/) — multi-tenant fintech/lending SaaS |
| **Standards covered** | PCI DSS 4.0, GLBA Safeguards Rule (16 CFR 314), SOX ITGC, ISO 27001:2022 |
| **Status** | Technical control mappings complete for 4 findings + 15 adjacent findings; organizational controls explicitly out of scope |
| **Last updated** | 2026-10-22 |

---

## What this document is (and isn't)

**It is:** a control-by-control mapping showing which regulatory requirements touch LendStack, which ones the four architecture findings violate, and which ones are addressed by the fixes. The purpose is to demonstrate that the technical findings aren't just bugs — they're **compliance gaps**, with specific regulatory citations.

**It isn't:** a compliance audit. A full compliance assessment would require evidence of organizational controls — policies, training, vendor management, incident response plans, Qualified Individual designations — that are outside the scope of a technical review of a lab environment. This document marks those items as **out of technical scope** rather than pretending they're covered.

**Why this framing matters for a portfolio:** the difference between a pentest report and a compliance review is that the pentest says "here's a vulnerability" and the compliance review says "here's a regulatory requirement, here's the control that satisfies it, here's why this system doesn't." The architecture review is stronger when it does both.

---

## Why these four standards

LendStack is a **multi-tenant fintech/lending SaaS**. That's the profile of a system that would be in scope for:

| Standard | Applies because |
|---|---|
| **PCI DSS 4.0** | The platform handles payment card data in the transfer and invoice flows (even if the current lab uses test data, the architecture assumes it will hold real card data in production) |
| **GLBA Safeguards Rule** | LendStack is a "financial institution" under GLBA — a non-bank lender, which the FTC regulates under 16 CFR Part 314 |
| **SOX ITGC** | If the platform is operated by a public company (or its customers are), IT general controls on access, change, and operations apply |
| **ISO 27001:2022** | The most commonly adopted international ISMS standard — the controls in Annex A form a superset that overlaps with the other three |

Plus two more that appear briefly in the finding files but aren't a primary focus here:

- **AML/KYC** (Bank Secrecy Act, 31 CFR 1020) — customer identification, transaction monitoring, SAR reporting. Mostly organizational; touches this system at the audit-trail layer.
- **Fair Lending** (ECOA, Regulation B; HMDA, Regulation C) — loan decision data collection and non-discrimination. Relevant to the loan application model (V-35, planned).

---

## The compliance view of LendStack's findings

The four Critical/High findings in #1 all map to specific regulatory controls. This table is the cross-reference:

| Finding | Severity | PCI DSS 4.0 | GLBA 314.4 | SOX ITGC | ISO 27001:2022 |
|---|---|---|---|---|---|
| **V-30** — RLS bypass | Critical | 7.2.1, 7.3.1 | (c)(1) access controls | Access management | A.5.15, A.5.18, A.8.3 |
| **V-31** — Files no tenant_id | High | 7.2.1, 7.3.1 | (c)(1) access controls | Access management | A.8.3, A.8.12 |
| **V-32** — Export bypasses middleware | High | 7.2.1 | (c)(1) access controls | Access management | A.8.3 |
| **V-33** — No maker-checker | Critical | 6.4.2 (control on financial transactions), 7.2.1 | (c)(1), (c)(7) | **Change management segregation of duties** | **A.5.3 segregation of duties** |

The **V-33 / SOX ITGC** alignment is the strongest compliance story in the project: SOX requires segregation of duties for financial control changes, and V-33 is the *absence* of that control in code. A SOX auditor looking at the transfer approval flow would flag it immediately.

---

## Control-by-control mapping

### PCI DSS 4.0

| Requirement | Control | LendStack status | Findings | Evidence / fix |
|---|---|---|---|---|
| 7.2.1 | Access control model defined and assigned | ❌ Failed (pre-fix) | V-30, V-31, V-32 | The model exists (tenant isolation, role-based access) but doesn't enforce. Fixed by migration 001 (V-30), migration 004 (V-31), and code change (V-32). |
| 7.3.1 | Access to system components restricted by role | ❌ Failed (pre-fix) | V-30, V-31 | Same as 7.2.1 — role gate exists on `/admin/export` (`requireRole('owner')`) but tenant gate was missing. |
| 8.2 | Unique IDs for all users | ✅ Pass | — | Users table has UUID primary key, no shared accounts. |
| 8.3 | Strong authentication for users | ⚠️ Partial | V-01, V-03, V-04, V-08 | Password hashing is correct (bcrypt cost 10), but JWT verification has signature gap (V-01), no revocation (V-03, V-04), no audience/issuer (V-08). Fixes documented in #4. |
| 8.4 | MFA for all access into CDE | ⚠️ Partial | — | OTP endpoint exists but no MFA enforcement. In scope for M5 (admin panel) work. |
| 8.6 | Application and system accounts | ⚠️ Partial | V-33 | Service accounts exist (`svc@<tenant>.test`) with `role='service'`; but no separate privilege model for them. V-33's fix requires maker-checker which service accounts should also be bound by. |
| 10.2 | Audit logs generated for access to system components | ⚠️ Partial | V-41, V-42 | Auth events logged (good). But role changes not logged (V-41) and DB connections not logged (V-42). Fix planned in M4. |
| 10.4 | Audit logs reviewed | ⚠️ Out of technical scope | — | Requires SOC process; #3 documents the detection rules that would enable review. |
| 10.5.1 | Audit log retention for at least 12 months | ⚠️ Out of technical scope | — | `audit_log` table exists but no retention policy or archival. |
| 6.4.2 | Automated technical solution detecting web attacks | ⚠️ Partial | V-33 (adjacent) | WAF/IPS outside scope. Maker-checker constraint on financial transactions is the closest relevant control and is now enforced (migration 003). |

### GLBA Safeguards Rule (16 CFR 314.4)

| Requirement | Control | LendStack status | Findings | Evidence / fix |
|---|---|---|---|---|
| 314.4(a) | Designate a Qualified Individual | ⚠️ Out of technical scope | — | Organizational; not a code/system property. |
| 314.4(b) | Risk assessment | ⚠️ Partial | — | `threat-model.md` is a technical risk assessment, not the organizational one required by the Rule. |
| 314.4(c)(1) | Access controls | ❌ Failed (pre-fix) | V-30, V-31, V-32, V-33 | The core finding set. Fixed by migrations 001, 003, 004 + code. |
| 314.4(c)(2) | Identification and authentication | ⚠️ Partial | V-01, V-08 | Auth layer exists; JWT signature verification gap (V-01) documented under #4. |
| 314.4(c)(3) | Encryption of customer information | ✅ Pass (at rest); ⚠️ Partial (in transit) | — | Postgres encryption at rest depends on deployment (out of scope for lab); TLS termination configured at reverse proxy (not documented in this repo). |
| 314.4(c)(5) | MFA | ⚠️ Partial | — | Same as PCI 8.4. |
| 314.4(c)(7) | Change management | ✅ Pass | V-30, V-31, V-32, V-33 | The migration-based remediation *is* the change management story. Versioned, reviewed, CI-enforced. |
| 314.4(c)(8) | Monitoring and auditing | ⚠️ Partial | V-41, V-42 | Same as PCI 10.2. |
| 314.4(f) | Service provider oversight | ⚠️ Out of technical scope | V-14 (planned) | `mock-llm` is a stand-in; V-14 (SSRF via webhooks) is the technical manifestation, but the *program* requirement is organizational. |
| 314.4(g) | Incident response plan | ⚠️ Out of technical scope | — | #3's detection rules + playbooks are the technical component. |
| 314.4(i) | Periodic assessment | ⚠️ Out of technical scope | — | This document is one assessment; the *periodic* requirement is organizational. |

### SOX ITGC

| Control area | Requirement | LendStack status | Findings | Evidence / fix |
|---|---|---|---|---|
| Access management | User provisioning / deprovisioning / periodic review | ⚠️ Partial | V-11, V-41 | `role` field accepted from request body at registration (V-11); role changes not audited (V-41). Both documented; V-11 in #2 scope, V-41 in #3 scope. |
| Access management | Segregation of duties for financial controls | ❌ Failed (pre-fix) | **V-33** | **The strongest SOX finding.** A single user can create and approve a financial transfer. Fixed via migration 003 (app check + DB constraint + audit event). |
| Change management | SDLC with segregation of duties | ✅ Pass | V-30 through V-33 | The migration-based remediation demonstrates change management — every fix is a reviewed, versioned migration. |
| Change management | Testing of changes before production | ✅ Pass | V-30 through V-33 | Each finding has a "Verification test" section. Each fix has before/after evidence in `evidence/`. |
| IT operations | Job scheduling and monitoring | ⚠️ Out of technical scope | — | No scheduled jobs implemented in the lab; monitoring is via `fluent-bit` → SIEM (documented in #3). |
| IT operations | Incident management | ⚠️ Partial | — | Detection exists (#3); response playbooks are in progress (#3). |

### ISO 27001:2022 Annex A

| Control | Requirement | LendStack status | Findings | Evidence / fix |
|---|---|---|---|---|
| A.5.3 | **Segregation of duties** | ❌ Failed (pre-fix) | **V-33** | Same finding as SOX. Fixed via migration 003. |
| A.5.15 | Access control | ❌ Failed (pre-fix) | V-30, V-31, V-32 | Fixed via migrations 001 and 004 + code change. |
| A.5.16 | Identity management | ✅ Pass | — | Users have UUID identities; no shared accounts. |
| A.5.17 | Authentication information | ⚠️ Partial | V-03, V-06 | Refresh tokens not revoked on password change (V-03); DB credentials in git history (V-06). Both documented. |
| A.5.18 | Access rights | ❌ Failed (pre-fix) | V-30, V-33 | Fixed by migrations 001 and 003. |
| A.5.19 | Information security in supplier relationships | ⚠️ Partial | V-14 (planned) | Webhook SSRF (V-14) is the technical manifestation; the *program* is organizational. |
| A.8.2 | Privileged access rights | ⚠️ Partial | V-33, V-41 | Fixed for V-33; V-41 (role-change audit) planned. |
| A.8.3 | Information access restriction | ❌ Failed (pre-fix) | V-30, V-31, V-32 | The core finding set. Fixed via migrations. |
| A.8.5 | Secure authentication | ⚠️ Partial | V-01, V-08 | JWT signature gap documented under #4. |
| A.8.11 | Data masking | ⚠️ Planned | V-34 (planned) | PAN in support-chatbot transcript; scrubbing layer planned for M6. |
| A.8.12 | Data leakage prevention | ⚠️ Partial | V-31, V-34 | V-31 (cross-tenant file metadata + storage_path) fixed. V-34 (PAN to LLM) planned. |
| A.8.15 | Logging | ⚠️ Partial | V-41, V-42 | Auth events logged; role changes and DB connections not. |
| A.8.16 | Monitoring activities | ⚠️ Partial | — | #3's detection rules cover the auth and admin layers; expansion to other layers planned. |
| A.8.24 | Use of cryptography | ⚠️ Partial | V-01, V-06 | JWT uses RS256 (correct); signature verification gap (V-01); DB credentials in git (V-06). |
| A.8.25 | Secure development life cycle | ✅ Pass | V-30 through V-33 | The migration + evidence + CI-check pattern demonstrates SDLC discipline. |
| A.8.28 | Secure coding | ⚠️ Partial | V-10, V-11, V-12, V-14 | Several findings are secure-coding failures documented in #2's scope. |
| A.8.32 | Change management | ✅ Pass | V-30 through V-33 | Every fix is a versioned migration; every migration is a reviewable change. |

---

## Findings-to-standards matrix

Full cross-reference of every LendStack finding to the four standards:

| Finding | Severity | PCI | GLBA | SOX | ISO | Fix status |
|---|---|---|---|---|---|---|
| **V-01** | Critical | 8.3 | (c)(2) | — | A.8.5, A.8.24 | Documented (#4) |
| **V-03** | High | 8.3 | (c)(2) | — | A.5.17, A.8.5 | Documented (#4) |
| **V-04** | Medium | 8.3 | (c)(2) | — | A.5.17 | Documented (#4) |
| **V-06** | Critical | 8.6 | (c)(1), (c)(3) | Access mgmt | A.5.17, A.8.24 | Documented (#4) |
| **V-08** | Medium | 8.3 | (c)(2) | — | A.8.5 | Documented (#4) |
| **V-10** | High | 7.2.1 | (c)(1) | Access mgmt | A.5.15, A.8.3 | Documented (#2); closed behaviorally by V-30 fix |
| **V-11** | High | 7.2.1 | (c)(1) | Access mgmt | A.5.15, A.5.18 | Documented (#2) |
| **V-14** | High | 7.2.1 | (c)(1), (f) | — | A.5.19 | Planned (M6) |
| **V-16** | High | 8.2, 8.3 | (c)(2) | — | A.8.5 | Documented (#2, #4) |
| **V-19** | Critical | 6.4.2 | (c)(1) | Access mgmt | A.5.3 | Planned (M4) |
| **V-20** | High | 8.3 | (c)(2) | — | A.5.17 | Documented (#4) |
| **V-30** | Critical | 7.2.1, 7.3.1 | (c)(1) | Access mgmt | A.5.15, A.5.18, A.8.3 | ✅ Fixed (migration 001) |
| **V-31** | High | 7.2.1, 7.3.1 | (c)(1) | Access mgmt | A.8.3, A.8.12 | ✅ Fixed (migration 004) |
| **V-32** | High | 7.2.1 | (c)(1) | Access mgmt | A.8.3 | ✅ Fixed (code + lint) |
| **V-33** | Critical | 6.4.2, 7.2.1 | (c)(1), (c)(7) | **Segregation of duties** | **A.5.3**, A.8.2 | ✅ Fixed (migration 003) |
| **V-34** | High | 3.2.1, 3.3.1 | (c)(3) | — | A.8.11, A.8.12 | Planned (M6) |
| **V-40** | Medium | 10.2 | (c)(8) | IT ops | A.8.15 | Planned (#3 expansion) |
| **V-41** | High | 10.2 | (c)(8) | Access mgmt | A.8.15 | Planned (M4) |
| **V-42** | Medium | 10.2 | (c)(8) | IT ops | A.8.15 | Planned (#3 expansion) |

---

## What a compliance auditor would still flag after all current fixes

The four findings are fixed. Six more are documented (in #2, #4). But a real compliance assessment would still find gaps. **This is the honest picture of where the system stands**, not just what the current finding set covers:

| Gap | Standard | Why it matters | Fix path |
|---|---|---|---|
| No MFA enforcement | PCI 8.4, GLBA (c)(5) | Mandatory for CDE access in PCI 4.0 | M5 (admin panel) + MFA at auth layer |
| No audit log retention policy | PCI 10.5.1 | PCI requires 12 months retention | Deployment policy, not code |
| No log review process | PCI 10.4 | Detection exists (#3) but process is organizational | Document in `docs/operations.md` |
| PAN in LLM path (V-34) | PCI 3.2, 3.3; GLBA (c)(3) | Cardholder data must not leave CDE | M6 (support module) + scrubbing layer |
| Webhook SSRF (V-14) | GLBA (f), ISO A.5.19 | Service provider / external integration control | M6 (webhooks module) |
| Fair lending model features | ECOA Reg B, HMDA | Zip code and income as model features can proxy for protected classes | M6 (loan applications) + model audit |
| AML transaction monitoring | BSA / 31 CFR 1020 | Threshold monitoring for SAR generation | Not in scope; would be a separate system |
| No incident response plan | GLBA (g), ISO A.5.24 | Documented playbooks exist per rule (#3) but no organizational plan | Organizational |
| Qualified Individual not designated | GLBA 314.4(a) | Required organizational role | Organizational |

**The framing that matters:** the technical control gaps that *can* be closed in code are closed (V-30, V-31, V-32, V-33). The gaps that remain fall into two categories — **(a) not yet built** (V-14, V-34, V-19, etc.) or **(b) organizational, not technical** (Qualified Individual, IR plan, audit review process). Naming which is which is the compliance discipline. A reviewer or auditor reading this document should be able to see exactly which gaps are in scope for the project and which are outside it.

---

## The strongest compliance story in this project

Of the four fixed findings, **V-33 is the one a compliance auditor would care most about**, and it's worth stating why explicitly:

**V-33 violates ISO 27001 A.5.3 (segregation of duties) directly and unambiguously.** The control is not subtle — ISO 27002:2022 states segregation of duties "should be used to reduce the risk of fraud and error by requiring two people to complete a task." LendStack's transfer flow has this exact task (approve a money movement) and the exact gap (one person can do both).

The finding:
- **Is a technical gap** — the fix is code + a DB constraint
- **Is a compliance gap** — the fix directly satisfies the ISO control
- **Is a business risk** — a self-approved transfer in a lending platform is the "internal fraud" scenario regulators care most about
- **Has a durable fix** — the DB constraint survives refactors, library swaps, and developer turnover

That combination — technical + compliance + business + durable — is what a good compliance overlay is for. It's not a checklist; it's a demonstration that closing a specific bug closes a specific regulatory requirement in a way that's verifiable.

**V-30 is the second-strongest story**, for a different reason: it demonstrates that multi-tenant isolation controls, when they look present but aren't, are a control-failure class. PCI 7.2.1 doesn't say "have RLS" — it says "restrict access to system components and cardholder data by business need to know." RLS enabled but inert means the *control* is present but the *restriction* isn't. That distinction is exactly what the finding documents.

---

## What this document is for

Four audiences, four different uses:

**For a hiring manager or technical reviewer:** the finding set demonstrates whether the candidate understands that technical bugs map to regulatory requirements — not as an afterthought, but as the frame. Every finding here has a regulatory control behind it. Every fix closes a compliance gap in a verifiable way.

**For a compliance auditor reviewing LendStack:** this document is the bridge between the technical findings and the audit checklist. An auditor doesn't need to read every finding file — they read this one and know which findings affect which controls. Then they spot-check specific findings to verify the claim.

**For a security engineer joining the team:** the compliance overlay is the "why does any of this matter" document. A junior engineer who doesn't understand why maker-checker matters can read V-33's ISO A.5.3 citation and understand the *purpose* of the finding, not just the mechanism.

**For the eventual SOC 2 or ISO 27001 audit:** the control mapping is the skeleton of the "systems description" section. It needs to be expanded (with evidence artifacts for organizational controls) before it's audit-ready, but it's the right structure.

---

## Honest scope boundaries

Three things I want to state explicitly, so the document doesn't overclaim:

**1. This is a compliance control mapping, not a compliance audit.** A real audit would require evidence of *operating effectiveness* — proof the controls work not just at test time but continuously. The technical controls here have evidence (CI checks, query results), but the organizational ones don't exist yet. Marking them "out of technical scope" is honest; claiming the system is compliant would not be.

**2. Regulatory requirements are paraphrased, not quoted.** I've cited requirement numbers accurately (PCI 7.2.1, GLBA 314.4(c)(1), ISO A.5.3, etc.) but the descriptions are summaries, not quotes. For a real audit, the exact regulatory text would need to be cited per finding. This is intentional — quoting PCI DSS from memory risks subtle inaccuracies, and the numbered citations are sufficient for the mapping.

**3. The four fixed findings do not make the platform compliant.** They close four specific control gaps. Compliance also requires the organizational controls, the MFA rollout, the audit retention policy, the incident response plan, and the many technical findings still open (V-14, V-34, V-19, etc.). The document says this, the README says this, and the finding files say this. The honest scope is part of the credibility — a portfolio that claims "PCI DSS compliant" because four Critical findings are fixed is less credible than one that says "these four are fixed, here's the compliance picture, here's what's still open."

**4. AML/KYC and Fair Lending are named but not deeply mapped.** Both are largely organizational (customer identification, SAR reporting, model governance). The technical touches — audit trails for AML, data collection for fair lending — are noted where relevant (V-41, V-35 planned). A full AML/KYC control mapping would require the platform to have a customer onboarding flow, which LendStack doesn't yet. Naming that gap is more honest than a thin mapping that pretends it's covered.

---

## Related documents

- **[README](README.md)** — the project overview, findings, and remediation
- **[threat-model.md](threat-model.md)** — six trust boundaries + STRIDE per boundary
- **[findings/](findings/)** — the individual finding files with evidence and verification tests
- **[evidence/](evidence/)** — before/after evidence for each fix
