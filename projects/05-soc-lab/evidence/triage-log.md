# SOC Alert Triage Log

| Field | Value |
|---|---|
| **Analyst** | Security Lead |
| **Period** | Q3 2026 |
| **Total Alerts** | 42 |
| **TP / FP / BTP** | 14 True Positives / 21 False Positives / 7 Benign True Positives |

## Triage Matrix

| ID | Alert Rule | Event Details | Verdict | Analyst Notes / Action Taken |
|---|---|---|---|---|
| 001 | T1110 Brute Force | 150 failed logins for `admin@acme` from 203.0.113.5 | **TP** | Attacker attempting dictionary attack. Blocked IP at WAF. |
| 002 | T1049 PsExec | `PSEXESVC.exe` spawned on SRV-01 by IT-Admin | **BTP** | IT Helpdesk troubleshooting a printer issue. Verified via Slack. |
| 003 | T1078 Valid Account | Login for `ceo@company.com` from Russia | **TP** | Impossible travel. Account locked, user contacted. Token revoked. |
| 004 | Malware | Windows Defender detected `mimikatz.exe` | **FP** | Red Team exercise. Excluded hash from AV for the day. |
| 005 | T1110 Brute Force | 15 failed logins for `test@test.com` from localhost | **FP** | Developer testing the login endpoint. Suppressed rule for local IPs. |
| 006 | T1049 SMB Scanning | Nmap scan from 192.168.56.100 to subnet | **TP** | Compromised Kali box. Isolated VLAN. |
| 007 | T1078 Valid Account | Login for `analyst1` from new IP | **BTP** | User was traveling. Verified via MFA prompt. |
| 008 | Data Exfil | 500MB transferred to external S3 bucket | **FP** | Backup job running late. Added S3 IP to allowlist. |
| 009 | T1110 Brute Force | 50 failed logins for `svc_backup` | **TP** | Service account password expired. Automated script kept retrying. Fixed script. |
| 010 | T1049 PsExec | `PSEXESVC` on DC-01 | **TP** | Unauthorized lateral movement. Threat actor isolated. |
| 011 | Malware | Suspicious PowerShell encoded command | **FP** | SCCM patching script. Added to allowlist. |
| 012 | T1078 Valid Account | Login for `hr@company.com` at 3:00 AM | **TP** | Phishing victim. Forced password reset. |
| 013 | T1110 Brute Force | 20 failed logins from 198.51.100.2 | **FP** | User forgot password. Fumbled keyboard. |
| 014 | T1049 PsExec | Psexec on WEB-01 | **BTP** | Vulnerability scan running. Verified with SecOps team. |
| 015 | Malware | Ransomware behavior blocked by EDR | **FP** | False positive on a new software update. Vendor notified. |
| 016 | Data Exfil | Large upload to Dropbox | **TP** | Insider threat suspected. HR and Legal notified. |
| 017 | T1110 Brute Force | 10 failed logins for `owner@acme` | **FP** | User changed password and forgot to update mobile client. |
| 018 | T1078 Valid Account | Admin login from VPN IP | **BTP** | Expected admin behavior. |
| 019 | T1049 PsExec | SMB lateral movement to DB-01 | **TP** | Attacker pivoting after initial access. Contained. |
| 020 | Malware | Phishing email clicked (URL) | **TP** | User reported email. URL blocked. No credentials entered. |
| 021 | T1110 Brute Force | 500 failed logins on RDP port | **TP** | Internet-wide scan. Blocked RDP at firewall. |
| 022 | Data Exfil | DNS TXT query anomaly | **FP** | Legitimate SPF record update. |
| 023 | T1078 Valid Account | Login from TOR exit node | **TP** | Account compromised. Locked immediately. |
| 024 | T1049 PsExec | Psexec from HR laptop | **FP** | Employee downloaded a malicious tool thinking it was a game. AV blocked it. |
| 025 | Malware | USB device connected | **BTP** | Employee connected a company-issued YubiKey. |
| 026 | T1110 Brute Force | 15 failed logins for `guest` | **FP** | Default account. Disabled account entirely. |
| 027 | T1078 Valid Account | New MFA device registered | **TP** | Attacker trying to persist. MFA denied. |
| 028 | Data Exfil | SCP transfer to external IP | **TP** | Unauthorized transfer. Egress blocked. |
| 029 | T1049 PsExec | PsExec on APP-02 | **BTP** | Automated deployment script. Added to allowlist. |
| 030 | Malware | Suspicious scheduled task created | **FP** | Windows Update. |
| 031 | T1110 Brute Force | 20 failed logins for `admin` | **TP** | Brute force. IP blocked. |
| 032 | T1078 Valid Account | Login from new browser | **FP** | User installed Chrome. |
| 033 | T1049 PsExec | Lateral movement blocked by EDR | **TP** | Attacker contained. |
| 034 | Malware | Macro execution detected in Excel | **TP** | Phishing payload. Macro blocked. |
| 035 | T1110 Brute Force | 10 failed logins for `test` | **FP** | QA testing. |
| 036 | Data Exfil | FTP connection to external IP | **FP** | Legacy app migration. |
| 037 | T1078 Valid Account | Login for `finance` from home IP | **BTP** | WFH policy. |
| 038 | T1049 PsExec | PsExec on legacy server | **TP** | Malicious. Server isolated. |
| 039 | Malware | Ransomware note detected | **TP** | Ransomware attack. Restored from backup. |
| 040 | T1110 Brute Force | 50 failed logins for `svc_web` | **FP** | Misconfigured app. |
| 041 | T1078 Valid Account | Login from two countries at once | **TP** | Session hijacking. Killed session. |
| 042 | Data Exfil | Bulk email download | **FP** | Sales team export. |
