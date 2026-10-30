# ISO 27001:2022 — 12-Month Implementation Roadmap

| Field | Value |
|---|---|
| **Owner** | CTO / Head of Security |
| **Review Cycle** | Quarterly |
| **Target** | Stage 2 Certification Audit (Month 12) |
| **Context** | LendStack (Series A Fintech SaaS) |

## Executive Summary

Implementing ISO 27001 from scratch takes 9 to 12 months for a lean team. Attempting to implement all 93 controls in Annex A simultaneously will paralyze the engineering team. 

This roadmap takes a **phased approach**, prioritizing foundational governance and high-risk technical controls first. It is designed to balance engineering velocity with the compliance requirements needed to pass an external audit.

---

## Phase 1: Foundation & Scope (Months 1–3)
**Goal:** Define what we are protecting, how we make decisions, and what the baseline is.

| Month | Milestone | Key Deliverables | Owner |
|---|---|---|---|
| 1 | **ISMS Scope** | Define which systems, people, and locations are in scope (e.g., LendStack Prod, AWS, HQ). | CTO |
| 1 | **Risk Methodology** | Approve the CIA scoring matrix and risk acceptance criteria. | Security Lead |
| 2 | **Asset Inventory** | Complete the 43-asset Information Asset Register. | IT Ops |
| 2 | **Gap Assessment** | Map current state against ISO 27001 Annex A. Identify major gaps. | Security Lead |
| 3 | **Statement of Applicability (SoA)** | Document which of the 93 controls apply to us and why. | Security Lead |

*Phase 1 Output:* Leadership agrees on scope, risk methodology, and knows exactly what is missing.

---

## Phase 2: Governance & HR Controls (Months 4–6)
**Goal:** Secure the human element and establish the policy framework.

| Month | Milestone | Key Deliverables | Owner |
|---|---|---|---|
| 4 | **Policy Rollout** | Approve and publish Access Control, Acceptable Use, and Data Classification policies. | HR / CTO |
| 4 | **HR Security** | Implement background checks for new hires and security awareness training. | HR |
| 5 | **Risk Register v1** | Complete the initial 24-entry risk register and assign risk owners. | Security Lead |
| 5 | **Supplier Security** | Define vendor due-diligence process; review critical vendors (e.g., AWS, LLM provider). | Legal / Security |
| 6 | **Physical Security** | Define office access controls (badges) and remote work rules. | IT Ops |

*Phase 2 Output:* Policies are enforced, employees are trained, and the risk register is live.

---

## Phase 3: Technical & Operational Controls (Months 7–9)
**Goal:** Harden the technical environment and prove we can detect/respond to incidents.

| Month | Milestone | Key Deliverables | Owner |
|---|---|---|---|
| 7 | **Access Control** | Enforce MFA, implement maker-checker (V-33), and RLS fixes (V-30). | Engineering |
| 7 | **Logging & Monitoring** | Deploy SIEM, finalize the 3 detection rules (T1110, T1078, T1110.003). | Security Eng |
| 8 | **Incident Response** | Publish the IR Procedure. Run a tabletop exercise (phishing scenario). | Security Lead |
| 8 | **Vulnerability Mgmt** | Deploy automated container scanning and establish a 30-day patch SLA for Critical CVEs. | Engineering |
| 9 | **Business Continuity** | Document backup/restore procedures. Test a restore from scratch. | IT Ops |
| 9 | **Cryptography** | Define encryption standards (TLS 1.3 in transit, AES-256 at rest). | Engineering |

*Phase 3 Output:* The security controls are actually running. The technical team can detect and respond to threats.

---

## Phase 4: Audit & Certification (Months 10–12)
**Goal:** Prove to the auditor that the ISMS works.

| Month | Milestone | Key Deliverables | Owner |
|---|---|---|---|
| 10 | **Internal Audit** | Hire an internal auditor (or use a consultant). Audit our own ISMS against Annex A. | Internal Auditor |
| 10 | **Remediation** | Fix the findings from the internal audit. | Security Lead |
| 11 | **Management Review** | CTO reviews the ISMS, risk register, and audit findings. Signs off. | CTO |
| 11 | **Stage 1 Audit** | External auditor reviews documentation (SoA, Policies, Risk Register). | CTO / Security |
| 12 | **Stage 2 Audit** | External auditor tests controls (interviews, log reviews, system checks). | All Teams |
| 12 | **Certification!** | Receive ISO 27001 certificate (valid for 3 years). | CTO |

*Phase 4 Output:* Certification achieved. The company can confidently respond to enterprise security questionnaires.

---

## Resource Requirements

| Role | Allocation | Purpose |
|---|---|---|
| **Security Lead** | 60% | Owns the ISMS, writes policies, manages the audit. |
| **Engineering** | 15% | Implementing technical controls (MFA, logging, patching). |
| **HR / Legal** | 10% | HR security, vendor contracts, privacy (ROPA). |
| **External Auditor** | $15k - $25k | Stage 1 & Stage 2 certification audits. |

## Critical Success Factors

1. **Executive Buy-in:** The CTO must enforce the roadmap. If engineering ignores policies, the audit will fail.
2. **Don't Over-Scope:** Only put LendStack and AWS in scope. Do not include the HR payroll system or the physical office servers in Phase 1.
3. **Automate Evidence:** The best way to pass an audit is to automate the evidence. (e.g., CI checks in #1 prove code changes are tested; SIEM logs in #3 prove monitoring is active).
