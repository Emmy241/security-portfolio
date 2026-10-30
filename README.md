# Security Engineering Portfolio

Welcome to my security engineering portfolio. This repository contains six end-to-end projects that demonstrate my ability to design, build, attack, defend, and govern secure systems.

## The Worked Example: LendStack
To provide a realistic and cohesive narrative, projects #1 through #4 are built around **LendStack**, a deliberately vulnerable multi-tenant fintech/lending SaaS platform. 

- I built the platform from scratch (Node.js, Postgres, Docker).
- I **attacked** it (SQLi, XSS, SSRF, IDOR, JWT forgery).
- I **defended** it (Row-Level Security, Maker-Checker, CI checks).
- I **detected** the attacks (SIEM rules, IR playbooks).

## The Projects

### [1. Secure Multi-Tenant SaaS Architecture & Access Control](./projects/01-saas-architecture/)
*Architecture & Remediation* 
Documented 4 Critical/High findings (RLS bypass, missing maker-checker). Fixed them via versioned database migrations and enforced prevention using CI pipelines (`rls-check.sh`). Includes a complete STRIDE threat model and a PCI/GLBA/SOX compliance overlay.

### [2. Web Application & API Security Assessment](./projects/02-webapp-api-assessment/)
*Offensive Security*
Conducted a grey-box penetration test against LendStack. Found 6 vulnerabilities including SQL Injection, Stored XSS, Mass Assignment, and Business Logic flaws (double-spending). Includes full proof-of-concept exploits and a documented attack chain.

### [3. SIEM Detection Engineering & Incident Response](./projects/03-siem-detection/)
*Defensive Security*
Built dual-platform detection rules (Splunk SPL and Sentinel KQL) mapped to MITRE ATT&CK. Reduced false positives by 40% through iterative tuning. Includes incident response playbooks and a Python IOC enrichment script.

### [4. OAuth & JWT Security Review](./projects/04-oauth-jwt-review/)
*Authentication Security*
Audited LendStack's auth layer. Found 5 vulnerabilities including secrets committed to Git history, missing JWT signature verification, and lack of token revocation. Documented the full token lifecycle attack surface.

### [5. Enterprise SOC Simulation & Threat Detection Lab](./projects/05-soc-lab/)
*SOC Operations & DFIR*
Architected a simulated corporate network (Sysmon, Windows Event Logs, Auditd). Wrote detection rules for lateral movement (T1049), performed forensic analysis on a malicious PCAP (DNS tunneling), and documented a 42-alert triage log.

### [6. ISO 27001:2022 Implementation Toolkit](./projects/06-iso27001-toolkit/)
*Governance, Risk & Compliance*
Built a complete ISMS package from a blank page. Includes a 12-month roadmap, a 24-entry risk register, a 43-asset register, a GDPR Article 30 ROPA, an Incident Response procedure, and a foundational policy set.

## Technical Stack Used
- **Offensive:** Burp Suite, SQLMap, Nmap, Kali Linux, Python.
- **Defensive:** Splunk, Microsoft Sentinel, Sysmon, Wireshark, Fluent Bit.
- **AppSec/Dev:** Node.js, Postgres (RLS), Docker, GitHub Actions, Bash.
- **GRC:** ISO 27001, PCI DSS, GLBA, SOX.

## Contact
- **LinkedIn:** [Your Link]
- **Email:** [Your Email]
