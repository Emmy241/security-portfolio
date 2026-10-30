# #6 — ISO 27001:2022 Implementation & Gap Assessment Toolkit

| Field | Value |
|---|---|
| **Status** | 6 deliverables (Roadmap, Risk Register, Asset Register, ROPA, IR Procedure, Policy Set) complete. |
| **Context** | A fictional implementation for LendStack — a multi-tenant fintech SaaS platform. |
| **Standard** | ISO/IEC 27001:2022 (Information Security Management Systems) |
| **Related** | [#1 (Architecture)](../01-saas-architecture/) (Technical controls) · [#3 (SIEM)](../03-siem-detection/) (Detection controls) |

---

## TL;DR

A startup building a fintech platform (like LendStack) needs ISO 27001 certification to win enterprise deals and prove their security posture. However, building an Information Security Management System (ISMS) from scratch usually results in one of two failures:
1. Spending $50k on consultants who deliver a 400-page "binder" that nobody in engineering reads.
2. Copy-pasting templates from the internet that don't actually reflect how the business operates.

**This toolkit takes a third approach.** It is a complete, audit-ready ISMS package built from a blank page, specifically designed to be *usable by engineers and founders*, not just impressive to auditors. Every document features clear ownership, review dates, and plain-language procedures that a non-security team can actually follow day-to-day.

## Methodology: Usable, Not Just Compliant

The philosophy of this toolkit is **"Living Documentation."**

- **Formula-Driven Risk:** The risk register uses an automated CIA (Confidentiality, Integrity, Availability) scoring matrix, rather than arbitrary subjective ratings.
- **Clear Ownership:** Every risk, asset, and policy has a named owner (e.g., "Head of Engineering", "CTO"), not just a department.
- **Mapped to Reality:** The controls map directly to the technical findings discovered in [#1](../01-saas-architecture/) (e.g., V-30, V-33) and the detection rules in [#3](../03-siem-detection/). 

## What's in the Toolkit?

This project contains 6 core deliverables, organized into four directories:

### 1. The Roadmap (`/roadmap`)
- **12-Month ISMS Implementation Plan:** A realistic, phased rollout plan. You cannot implement all 93 controls in Annex A on day one. This roadmap explains what to build in Q1 (foundations), Q2 (technical controls), Q3 (vendor/HR), and Q4 (audit prep).

### 2. The Registers (`/registers`)
- **Risk Register (24 entries):** The heart of the ISMS. A comprehensive risk assessment using a formula-driven CIA scoring model.
- **Information Asset Register (43 assets):** A detailed inventory of every data store, system, cloud service, and physical asset.
- **Article 30 ROPA:** A GDPR-compliant Record of Processing Activities, mapping data subjects, legal bases, and retention periods.

### 3. The Procedures (`/procedures`)
- **Incident Response Procedure:** Aligned with ISO 27035, detailing the lifecycle of an incident from detection (tying back to #3's SIEM) to post-mortem.
- **Gap Assessment Matrix:** A sample assessment showing how LendStack measures against Annex A today.

### 4. The Policies (`/policies`)
- **Access Control Policy:** Tied to the maker-checker (V-33) and RLS (V-30) fixes from #1.
- **Acceptable Use Policy:** Clear, plain-English rules for employees.
- **Data Classification Policy:** Defining what is Public, Internal, Confidential, and Restricted.

## Why this matters for LendStack

LendStack handles financial data (invoices, loans) and is subject to PCI DSS, GLBA, and SOC 2. ISO 27001 is the umbrella ISMS framework that satisfies the governance requirements for all of them. 

By building this toolkit, a startup goes from "we think we're secure" to "we can prove to an auditor, a customer, and a regulator exactly how we manage risk, access, and incidents."

## Author's Note

*This toolkit represents how I would build an ISMS for a seed-to-Series-A startup. It prioritizes velocity and practicality without sacrificing the rigor required to pass a Stage 2 certification audit.*
