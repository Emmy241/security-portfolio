# ISO 27001:2022 — Information Asset Register

| Field | Value |
|---|---|
| **Owner** | IT Operations / Security Lead |
| **Review Cycle** | Semi-Annually |
| **Total Assets** | 43 |
| **Classification Scheme** | Public, Internal, Confidential, Restricted (see Data Classification Policy) |

## Purpose
You cannot protect what you don't know you have. The Information Asset Register (IAR) is the foundational inventory for the ISMS. It identifies every system, data store, and physical asset that supports LendStack, assigns a named owner to each, and determines the required level of protection based on the CIA (Confidentiality, Integrity, Availability) triad.

---

## Asset Inventory

| ID | Asset Name | Category | Owner | Location / Host | C | I | A | Classification |
|---|---|---|---|---|---|---|---|---|
| D-01 | Customer PII (Names, Emails, SSNs) | Data | CTO | AWS RDS (Postgres) | High | High | High | Restricted |
| D-02 | Financial Ledgers (Invoices, Transfers) | Data | CFO | AWS RDS (Postgres) | High | High | High | Restricted |
| D-03 | Loan Applications & Decision Data | Data | Risk Officer | AWS RDS (Postgres) | High | High | Med | Restricted |
| D-04 | Support Chat Transcripts | Data | Support Lead | AWS RDS (Postgres) | Med | Med | Low | Confidential |
| D-05 | System Audit Logs | Data | Security Lead | AWS CloudWatch | Med | High | Med | Confidential |
| D-06 | Application Source Code | Data | Eng Lead | GitHub (Private) | High | High | High | Confidential |
| D-07 | Secrets & API Keys (JWT Private Key) | Data | Sec Lead | AWS Secrets Manager | High | High | High | Restricted |
| D-08 | Database Backups | Data | IT Ops | AWS S3 (Glacier) | High | High | High | Restricted |
| D-09 | Webhook Event Logs | Data | Eng Lead | AWS RDS (Postgres) | Med | High | Low | Internal |
| D-10 | Infrastructure as Code (Terraform) | Data | IT Ops | GitHub (Private) | Low | High | Med | Internal |
| S-01 | LendStack API Server | Application | Eng Lead | AWS ECS (Docker) | High | High | High | Restricted |
| S-02 | Admin Panel Frontend | Application | Eng Lead | AWS S3 + CloudFront | High | High | Med | Confidential |
| S-03 | PostgreSQL Database Engine | Application | IT Ops | AWS RDS | High | High | High | Restricted |
| S-04 | Fluent Bit Log Shipper | Application | IT Ops | AWS ECS (Docker) | Med | Med | Med | Internal |
| S-05 | Mock LLM Service | Application | Eng Lead | AWS ECS (Docker) | Low | Low | Low | Public |
| S-06 | GitHub Organization | Software | CTO | GitHub Cloud | High | High | High | Confidential |
| S-07 | CI/CD Pipeline (GitHub Actions) | Software | Eng Lead | GitHub Cloud | High | High | High | Restricted |
| S-08 | AWS WAF & Shield | Software | IT Ops | AWS Cloud | High | High | High | Restricted |
| S-09 | Password Manager (1Password) | Software | Sec Lead | Cloud | High | High | Med | Restricted |
| S-10 | Slack Workspace | Software | HR Lead | Cloud | Med | Low | Med | Internal |
| H-01 | AWS ECS Compute Nodes | Hardware | IT Ops | AWS us-east-1 | N/A | High | High | N/A |
| H-02 | AWS RDS Storage | Hardware | IT Ops | AWS us-east-1 | High | High | High | Restricted |
| H-03 | AWS S3 Storage Buckets | Hardware | IT Ops | AWS us-east-1 | High | High | High | Restricted |
| H-04 | Employee Laptops (MacBook Pro) | Hardware | HR Lead | Remote | Med | Med | Med | Confidential |
| H-05 | HQ Office Network Router | Hardware | IT Ops | HQ | Med | Med | Med | Internal |
| H-06 | YubiKeys (Hardware MFA) | Hardware | Sec Lead | Distributed | High | High | High | Restricted |
| H-07 | External Backup Hard Drives | Hardware | IT Ops | Safe (HQ) | High | High | Med | Restricted |
| V-01 | AWS Cloud Provider | Service | CTO | AWS | High | High | High | Restricted |
| V-02 | GitHub (Source Control) | Service | CTO | GitHub | High | High | High | Confidential |
| V-03 | Twilio (SMS OTP Provider) | Service | Eng Lead | Twilio | Med | High | Med | Confidential |
| V-04 | SendGrid (Email Provider) | Service | Eng Lead | SendGrid | Med | High | Med | Confidential |
| V-05 | Vanta (Compliance Automation) | Service | Sec Lead | Vanta | Med | High | Med | Confidential |
| V-06 | Slack (Communications) | Service | HR Lead | Slack | Med | Low | Med | Internal |
| V-07 | VirusTotal / AbuseIPDB | Service | Sec Lead | Cloud API | Low | Med | Low | Public |
| V-08 | Cloudflare (DNS Provider) | Service | IT Ops | Cloudflare | Low | High | High | Internal |
| P-01 | Engineering Team (12 Staff) | People | Eng Lead | Hybrid | N/A | N/A | N/A | N/A |
| P-02 | CTO / Security Lead | People | CEO | Hybrid | N/A | N/A | N/A | N/A |
| P-03 | External Auditor (ISO/PCI) | People | CTO | Remote | N/A | N/A | N/A | N/A |
| P-04 | AWS Support (Enterprise) | People | IT Ops | AWS Portal | N/A | N/A | N/A | N/A |
| F-01 | HQ Office Space | Facility | HR Lead | London, UK | Med | Med | Med | Internal |
| F-02 | Server Room / Network Closet | Facility | IT Ops | HQ | High | High | High | Restricted |
| F-03 | Co-working Space Desks | Facility | HR Lead | NYC, US | Low | Low | Low | Public |
| F-04 | Remote Worker Home Offices | Facility | HR Lead | Distributed | Med | Med | Med | Internal |

## CIA Definitions
- **Confidentiality (C):** How much damage if this asset is leaked to the public?
- **Integrity (I):** How much damage if this asset is modified or corrupted?
- **Availability (A):** How much damage if this asset is offline for 24 hours?
