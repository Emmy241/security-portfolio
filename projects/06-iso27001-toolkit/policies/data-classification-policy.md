# Data Classification Policy

| Field | Value |
|---|---|
| **Document Owner** | Security Lead |
| **Version** | 1.0 |
| **Review Cycle** | Annually |
| **ISO 27001 Reference** | Annex A.8.2 (Information Classification) |

## 1. Purpose
This policy establishes a framework for classifying LendStack data based on its sensitivity. It ensures that all employees understand how to handle data appropriately, reducing the risk of unauthorized disclosure, modification, or destruction.

## 2. Scope
This policy applies to all data created, processed, stored, or transmitted by LendStack, regardless of format (digital, physical, verbal).

## 3. Data Classification Levels

LendStack uses four classification levels:

### Level 1: Public
- **Definition:** Data intended for public consumption. Unauthorized disclosure has no impact on the company or its customers.
- **Examples:** Marketing materials, public documentation, open-source code, job postings.
- **Handling:** No special handling required. Can be shared freely.

### Level 2: Internal
- **Definition:** Data intended for internal use only. Unauthorized disclosure could cause minor embarrassment or operational inconvenience.
- **Examples:** Internal memos, org charts, non-sensitive meeting notes, system architecture diagrams (redacted).
- **Handling:** Do not share externally. Access restricted to employees and trusted contractors.

### Level 3: Confidential
- **Definition:** Sensitive data. Unauthorized disclosure could cause significant financial or reputational damage to the company or its tenants.
- **Examples:** Source code, support chat transcripts, webhook event logs, internal audit reports.
- **Handling:** Access is granted on a need-to-know basis. Must be encrypted in transit (TLS 1.3) and at rest (AES-256). Do not store on personal devices.

### Level 4: Restricted
- **Definition:** Highly sensitive data. Unauthorized disclosure could result in severe legal, financial, or regulatory consequences (GDPR fines, PCI DSS penalties, loss of customer trust).
- **Examples:** Customer PII (Names, SSNs), financial ledgers, loan application data, JWT private keys, database backups.
- **Handling:** Strict access controls (least privilege). Encrypted at rest and in transit. Requires explicit authorization for storage or transfer. Subject to audit logging. Must never be sent to external LLMs or unapproved third parties.

## 4. Labeling

- **Digital Data:** Databases and S3 buckets containing Confidential or Restricted data must be tagged in AWS with the corresponding classification level.
- **Documents:** Internal, Confidential, and Restricted documents should have a header or footer indicating their classification (e.g., `[CONFIDENTIAL]`).
- **Emails:** If sending Confidential or Restricted data, the email subject must include `[CONFIDENTIAL]`.

## 5. Handling Rules

| Activity | Public | Internal | Confidential | Restricted |
|---|---|---|---|---|
| **Storage** | Any | Company-approved tools | Company-approved tools + Encryption | Company-approved tools + Encryption + Strict Access Control |
| **Transmission** | Any | Secure Email | TLS 1.3 required | TLS 1.3 + End-to-End Encryption |
| **Access** | Anyone | Employees | Need-to-know | Need-to-know + MFA |
| **Destruction** | Any | Standard deletion | Secure deletion | Certified crypto-shredding |

## 6. Data Retention and Destruction
Data must not be kept longer than necessary (see the ROPA for specific retention periods).
- **Digital Destruction:** Restricted data must be cryptographically shredded (deleting the encryption keys).
- **Physical Destruction:** Paper documents containing Confidential or Restricted data must be cross-cut shredded.

## 7. Violations
Failure to follow this policy may result in disciplinary action. If you accidentally leak Confidential or Restricted data, report it to the Security Lead immediately.
