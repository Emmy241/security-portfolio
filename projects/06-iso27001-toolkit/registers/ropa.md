# GDPR Article 30 — Record of Processing Activities (ROPA)

| Field | Value |
|---|---|
| **Owner** | Data Protection Officer (DPO) / Legal |
| **Review Cycle** | Annually |
| **Regulation** | GDPR Article 30 |
| **Context** | LendStack SaaS Platform |

## Purpose
This ROPA documents all processing activities involving personal data. It maps the data subjects, the categories of data, the legal basis for processing, the recipients, and the retention periods. This is a mandatory legal requirement for companies operating in the EU/UK.

---

## 1. Customer Identity & Access Management
- **Purpose:** To authenticate users and provide secure access to the platform.
- **Data Subjects:** Customer employees (Owners, Analysts, Auditors).
- **Data Categories:** Name, email address, hashed password, role, IP address, device user-agent.
- **Legal Basis:** Contractual Necessity (Art. 6(1)(b)).
- **Recipients:** AWS (Hosting), Vanta (Compliance).
- **International Transfers:** AWS us-east-1 (Standard Contractual Clauses in place).
- **Retention:** Duration of contract + 30 days.
- **Security Measures:** Bcrypt hashing, JWT RS256, Row-Level Security (RLS), TLS 1.3.

## 2. Loan Application Processing
- **Purpose:** To assess creditworthiness and make lending decisions.
- **Data Subjects:** End-customers of LendStack tenants (Applicants).
- **Data Categories:** Name, Income, Zip Code, Loan Amount, Decision (Approved/Denied).
- **Legal Basis:** Contractual Necessity (Art. 6(1)(b)), Legal Obligation (Fair Lending/AML).
- **Recipients:** AWS (Hosting), Credit Bureaus (via tenant integrations).
- **International Transfers:** None outside the US.
- **Retention:** 5 years post-decision (Regulatory requirement).
- **Security Measures:** Encryption at rest (AES-256), RLS (Tenant isolation), Maker-Checker (V-33 fix).

## 3. Money Movement & Transfers
- **Purpose:** To execute and record financial transactions.
- **Data Subjects:** Tenant employees (Initiators/Approvers), Account holders.
- **Data Categories:** Account numbers, Transfer amounts, Timestamps, IP addresses.
- **Legal Basis:** Contractual Necessity (Art. 6(1)(b)).
- **Recipients:** AWS (Hosting), Banking Partners (via webhooks).
- **International Transfers:** None.
- **Retention:** 7 years (Financial record-keeping laws).
- **Security Measures:** Maker-Checker authorization, Audit logging, RLS.

## 4. Customer Support Chatbot (LLM)
- **Purpose:** To provide automated support to tenants and resolve issues.
- **Data Subjects:** Tenant employees.
- **Data Categories:** Chat transcripts (often containing names, emails, or invoice details).
- **Legal Basis:** Legitimate Interest (Art. 6(1)(f)).
- **Recipients:** OpenAI/Anthropic (via API).
- **International Transfers:** US (Standard Contractual Clauses in place).
- **Retention:** 90 days.
- **Security Measures:** PAN redaction (V-34 fix), TLS 1.3 in transit.

## 5. Webhook Event Delivery
- **Purpose:** To notify tenant systems of platform events.
- **Data Subjects:** Tenant system data (invoice IDs, status changes).
- **Data Categories:** Event IDs, tenant IDs, status payloads.
- **Legal Basis:** Contractual Necessity (Art. 6(1)(b)).
- **Recipients:** Tenant-configured endpoints.
- **International Transfers:** Determined by tenant.
- **Retention:** 30 days (in logs).
- **Security Measures:** HMAC signatures on payloads, HTTPS only (V-14 fix).

## 6. Employee HR & Payroll
- **Purpose:** To manage employment, payroll, and benefits.
- **Data Subjects:** LendStack employees.
- **Data Categories:** National Insurance Number, Bank Account, Home Address, Emergency Contacts.
- **Legal Basis:** Contractual Necessity (Art. 6(1)(b)), Legal Obligation (Tax).
- **Recipients:** Gusto (Payroll), 1Password (Access).
- **International Transfers:** None outside the US.
- **Retention:** 6 years post-employment.
- **Security Measures:** MFA, strict Access Control Policies.

## 7. Security Monitoring & Incident Response
- **Purpose:** To detect and respond to cyber attacks.
- **Data Subjects:** Employees, Customers (system users).
- **Data Categories:** IP addresses, User-agents, Failed login attempts, Audit logs.
- **Legal Basis:** Legitimate Interest (Art. 6(1)(f) - Security).
- **Recipients:** AWS CloudWatch, Datadog.
- **International Transfers:** US.
- **Retention:** 12 months (PCI DSS requirement).
- **Security Measures:** Encrypted in transit, strict internal access controls.
