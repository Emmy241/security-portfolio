# Incident Response Playbook: Password Spraying (T1110.003)

| Field | Value |
|---|---|
| **Detection Rule** | LDS-AUTH-003 (`T1110.003`) |
| **Severity** | High |
| **Trigger** | ≥ 15 distinct `actor_email` values from the same `actor_ip` within 10 minutes. |
| **Data Source** | `lendstack:auth` |

## 1. Triage
- **Check for Outages:** Was there a recent SSO outage or shared-office network change? (Check `avg_per_email`. If it's high, it might be a broken SSO loop).
- **Confirm the Spray:** Does the alert show 1 attempt per email? This is the classic spray signature.
- **Look for Success:** **CRITICAL:** Check if *any* of the targeted emails show a `login.success` immediately after the spray. If yes, this has escalated to a compromise.

## 2. Investigation
- **Determine Scope:** How many emails were targeted? What is the pattern (e.g., `firstname.lastname@company.com`)?
- **Source IP Enrichment:** Is the IP from a known bulletproof hosting provider or TOR exit node?
- **Check Other Tenants:** Did the same IP hit multiple tenants? (This is a cross-tenant spray).

## 3. Containment
- **Block the IP:** Drop all traffic from `actor_ip` at the edge firewall/WAF.
- **Force Password Resets:** If the attacker successfully guessed a password, force a reset for that account.
- **Global MFA prompt:** If the spray is ongoing and broad, trigger a forced re-authentication for the affected tenant.

## 4. Eradication & Recovery
- **Identify the Password:** What password was sprayed? (e.g., `Spring2024!`). If it's a season/year pattern, all users with similar passwords are at risk.
- **Remediate the Successful Account:** Treat any successful login as a T1078 compromise.

## 5. Post-Incident
- Review password policies. Are users choosing predictable patterns?
- Implement a breached-password check in the registration/login flow.
