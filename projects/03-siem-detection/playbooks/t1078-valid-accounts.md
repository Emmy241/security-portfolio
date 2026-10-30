# Incident Response Playbook: Valid Accounts (T1078)

| Field | Value |
|---|---|
| **Detection Rule** | LDS-AUTH-002 (`T1078`) |
| **Severity** | High |
| **Trigger** | Successful login from a new IP, followed within 15m by a privileged action (role change, export, transfer). |
| **Data Source** | `lendstack:auth`, `lendstack:admin`, `lendstack:money` |

## 1. Triage
- **Verify the Alert:** Check the `actor_email` and `actor_ip`.
- **Check for False Positives:**
  - Is the user traveling? (Compare geo-IP to recent history).
  - Did an on-call engineer legitimately export data from home at 2 AM?
- **Identify the Action:** What did the user do? Did they change a role? Export invoices? Approve a transfer? This dictates urgency.

## 2. Investigation
- **Session Review:** Pull all `lendstack:http` logs for the `request_id` associated with the alert. What else did this user do during this session?
- **Account History:** When was the last time this user logged in from this IP?
- **Role Changes:** If the user granted a role, to whom? (e.g., did they make an attacker an owner?).
- **Out-of-Band Verification:** Call the user directly (using their known phone number, not a number from the suspicious session) to confirm if they performed the action.

## 3. Containment
- **Terminate Sessions:** Invalidate all access and refresh tokens for the compromised user. (See V-04 in project #4 — this must be implemented to be effective!).
- **Lock Account:** Lock the user account immediately.
- **Revert Actions:** If the user changed a role or approved a fraudulent transfer, revert it immediately in the database.

## 4. Eradication & Recovery
- **Password Reset & MFA:** Reset the user's password and enforce MFA.
- **Credential Rotation:** If the password was reused elsewhere, notify the user.

## 5. Post-Incident
- Was this a phishing victim or an insider threat?
- Review the V-41 fix (audit logging on role changes) — this is critical for investigating future T1078s.
