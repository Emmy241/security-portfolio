# ISO 27001:2022 — Risk Register

| Field | Value |
|---|---|
| **Owner** | Security Lead |
| **Review Cycle** | Quarterly |
| **Methodology** | Likelihood (1-5) × Impact (1-5) = Risk Score (1-25) |
| **Risk Appetite** | Maximum acceptable risk score is 9 (Medium). |

## Scoring Matrix

- **Likelihood:** 1 (Rare), 2 (Unlikely), 3 (Possible), 4 (Likely), 5 (Almost Certain)
- **Impact:** 1 (Insignificant), 2 (Minor), 3 (Moderate), 4 (Major), 5 (Severe/Critical)
- **Rating:** Low (1-4), Medium (5-9), High (10-16), Critical (17-25)

---

## Active Risk Register

| ID | Risk Description | Category | Owner | C | I | A | L | Impact | Score | Rating | Treatment Plan | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| R-01 | **Authentication Bypass:** Attacker forges a JWT using `alg:none` or missing signature verification (V-01). | Technical | Sec Lead | 5 | 5 | 5 | 4 | 5 | **20** | **Critical** | Replace `jwt.decode` with `jwt.verify`. Enforce RS256 algorithm. | Mitigated |
| R-02 | **Credential Leak:** Database passwords committed to Git history (V-06). | Technical | Eng Lead | 5 | 5 | 5 | 3 | 5 | **15** | **High** | Rotate credentials immediately. Purge history via `git-filter-repo`. | Mitigated |
| R-03 | **Tenant Data Leak:** RLS bypass allows cross-tenant reads (V-30). | Technical | Eng Lead | 5 | 5 | 5 | 3 | 5 | **15** | **High** | Force RLS. Separate app role from table owner. Add CI check. | Mitigated |
| R-04 | **Financial Fraud:** Insider creates and approves their own transfer (V-33). | Technical | Sec Lead | 1 | 5 | 1 | 3 | 5 | **15** | **High** | Implement maker-checker DB constraint and application logic. | Mitigated |
| R-05 | **Data Exfiltration:** Stored XSS in admin panel steals admin JWTs (V-13). | Technical | Eng Lead | 5 | 5 | 1 | 3 | 5 | **15** | **High** | Use `textContent` instead of `innerHTML`. Enforce strict CSP. | Mitigated |
| R-06 | **Database Compromise:** SQL injection in admin search endpoint (V-12). | Technical | Eng Lead | 5 | 5 | 5 | 3 | 5 | **15** | **High** | Use parameterized queries. | Mitigated |
| R-07 | **Phishing:** Employee clicks malicious link, compromising credentials. | Human | HR Lead | 4 | 4 | 4 | 4 | 4 | **16** | **High** | Mandatory security awareness training. Implement FIDO2/WebAuthn MFA. | In Progress |
| R-08 | **Cloud Outage:** AWS region outage takes LendStack offline. | Availability | IT Ops | 1 | 1 | 5 | 2 | 5 | **10** | **High** | Implement multi-region failover for critical services. RTO: 4 hours. | In Progress |
| R-09 | **Supply Chain:** LLM provider goes down or is breached. | Supply Chain | CTO | 4 | 4 | 2 | 3 | 4 | **12** | **High** | Ensure no PII is sent to LLM. Implement fallback LLM provider. | In Progress |
| R-10 | **Insider Threat:** Disgruntled employee deletes production databases. | Human | CTO | 1 | 3 | 5 | 2 | 5 | **10** | **High** | Enforce least privilege. Require approvals for destructive actions. | In Progress |
| R-11 | **Ransomware:** Malware encrypts core systems. | Technical | IT Ops | 4 | 4 | 4 | 2 | 4 | **8** | **Medium** | Deploy EDR. Maintain off-site immutable backups. | In Progress |
| R-12 | **DDoS:** Attacker floods the API with garbage traffic. | Availability | IT Ops | 1 | 1 | 5 | 3 | 5 | **15** | **High** | Deploy AWS WAF and Shield Advanced. | Open |
| R-13 | **Laptop Theft:** Employee laptop stolen from coffee shop. | Physical | HR Lead | 3 | 3 | 3 | 3 | 3 | **9** | **Medium** | Enforce Full Disk Encryption (FileVault/BitLocker). | Mitigated |
| R-14 | **Vulnerable Dependencies:** Unpatched npm packages exploited. | Technical | Eng Lead | 4 | 4 | 4 | 4 | 4 | **16** | **High** | Automate Dependabot scanning. 30-day SLA for patches. | In Progress |
| R-15 | **Data Loss:** Accidental deletion or corruption of DB. | Availability | IT Ops | 2 | 4 | 5 | 2 | 5 | **10** | **High** | Daily automated backups. Test restore every quarter. | Mitigated |
| R-16 | **GDPR Breach:** Customer PII leaked to unauthorized party. | Legal | DPO | 5 | 5 | 2 | 3 | 5 | **15** | **High** | Data Classification Policy. Data processing agreements (DPA). | Open |
| R-17 | **Social Engineering:** Attacker calls helpdesk to reset admin password. | Human | HR Lead | 4 | 4 | 4 | 3 | 4 | **12** | **High** | Implement strict identity verification protocol for helpdesk. | Open |
| R-18 | **Weak Passwords:** Users reuse passwords from breached sites. | Technical | Sec Lead | 4 | 4 | 4 | 4 | 4 | **16** | **High** | Enforce MFA. Check against HaveIBeenPwned API on registration. | In Progress |
| R-19 | **Lack of Awareness:** Employees do not know how to report an incident. | Human | HR Lead | 2 | 3 | 3 | 3 | 3 | **9** | **Medium** | Publish IR procedure. Annual tabletop exercise. | In Progress |
| R-20 | **API Abuse:** No rate limits on auth endpoints (V-16). | Technical | Eng Lead | 4 | 4 | 4 | 4 | 4 | **16** | **High** | Implement AWS API Gateway rate limiting. | Mitigated |
| R-21 | **Library Exploit:** Zero-day in JSON Web Token library. | Technical | Eng Lead | 4 | 4 | 4 | 2 | 4 | **8** | **Medium** | Subscribe to GitHub Security Advisories. | Open |
| R-22 | **Cloud Misconfig:** S3 bucket accidentally made public. | Technical | IT Ops | 5 | 5 | 1 | 2 | 5 | **10** | **High** | Enable AWS Config and GuardDuty. Block public S3. | Mitigated |
| R-23 | **Regulatory Fine:** PCI DSS non-compliance leads to fines. | Compliance | CTO | 3 | 3 | 1 | 2 | 3 | **6** | **Medium** | Annual PCI scan and ASV certification. | Open |
| R-24 | **Key Person Risk:** Only one engineer knows how the RLS works. | Operational | CTO | 3 | 3 | 3 | 3 | 3 | **9** | **Medium** | Conduct cross-training. Document architectural decisions (like #1). | Mitigated |
