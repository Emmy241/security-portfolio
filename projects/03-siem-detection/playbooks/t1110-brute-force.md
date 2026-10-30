# Incident Response Playbook: Brute Force (T1110.001)

| Field | Value |
|---|---|
| **Detection Rule** | LDS-AUTH-001 (`T1110.001`) |
| **Severity** | Medium |
| **Trigger** | ≥ 10 `login.failure` events for the same email from the same IP in 5 minutes. |
| **Data Source** | `lendstack:auth` |

## 1. Triage
- **Verify the Alert:** Does the alert show a successful login *after* the failures? If yes, this is a successful compromise; escalate to "Valid Accounts" (T1078). If no, proceed.
- **Check for False Positives:**
  - Is the `actor_email` a service account (e.g., `svc@acme-lending.test`)? If yes, check if the account eventually succeeded. Service accounts often retry vaulted credentials during a refresh window (mitigated in rule tuning).
  - Is it a user with an expired password who is retrying repeatedly? Contact the user.
- **Identify the Target:** Which account is being targeted? Is it a high-privilege account (`owner` or `admin`)?

## 2. Investigation
- **Source IP Enrichment:** Look up the `actor_ip` in threat intelligence (VirusTotal, AbuseIPDB). Is it a known malicious IP, a VPN, or a TOR exit node?
- **Geographic Location:** Does the IP geolocate to a country where the organization does not operate?
- **Target Scope:** Search the SIEM for the same `actor_ip` attempting to log into *other* accounts. This distinguishes a targeted brute force from a password spray.

## 3. Containment
- **Block the IP:** Add the `actor_ip` to the WAF or firewall blocklist.
- **Lock the Account:** If the targeted account is confirmed to be under active attack, temporarily lock it (`UPDATE users SET status = 'locked'`).

## 4. Eradication & Recovery
- **Password Reset:** Force a password reset for the targeted user. (Ensure the reset process is secure and uses MFA).
- **MFA Enforcement:** If not already enabled, enforce MFA for the targeted account.

## 5. Post-Incident
- Document the source IP, target account, and duration of the attack.
- Review the rule thresholds. Were there false negatives? Did the attacker switch IPs?
