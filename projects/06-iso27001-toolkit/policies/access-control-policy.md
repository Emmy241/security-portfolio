# Access Control Policy

| Field | Value |
|---|---|
| **Document Owner** | CTO |
| **Version** | 1.0 |
| **Review Cycle** | Annually |
| **ISO 27001 Reference** | Annex A.9 (Access Control) |

## 1. Purpose
This policy defines the rules for accessing LendStack systems, applications, and data. It ensures that access is granted based on business needs, follows the principle of least privilege, and prevents unauthorized access.

## 2. Scope
This policy applies to all LendStack employees, contractors, and systems that access the production environment or handle customer data.

## 3. Role-Based Access Control (RBAC)
- **Roles:** Users are assigned one of four roles: `Owner`, `Analyst`, `Auditor`, or `Service`.
- **Least Privilege:** Users are granted the minimum level of access necessary to perform their job functions.
- **Separation of Duties:** 
  - **Maker-Checker:** No single user may both create and approve a financial transfer (V-33). The database enforces a constraint rejecting self-approval.
  - **Code Review:** No single engineer may push code to `main` without a second engineer's approval.

## 4. Authentication Requirements
- **MFA:** Multi-Factor Authentication (MFA) is mandatory for all administrative access (AWS Console, GitHub, Slack, LendStack Admin Panel). Hardware keys (FIDO2/YubiKey) are required for Admin roles.
- **Passwords:** Passwords must be at least 12 characters, checked against breached password databases (e.g., HaveIBeenPwned), and never shared or reused.
- **Tokens:** Access tokens (JWTs) must expire in 15 minutes. Refresh tokens must be rotated on every use and revoked immediately upon password change or logout (V-04).

## 5. Tenant Isolation
- **Application Layer:** All database queries must explicitly filter by `tenant_id`. Application-layer authorization is mandatory.
- **Database Layer:** Row-Level Security (RLS) must be enabled and `FORCE ROW LEVEL SECURITY` must be set on all tenant tables to prevent app-role bypass (V-30).
- **Enforcement:** CI pipelines must run the `rls-check.sh` script and fail the build if RLS is improperly configured.

## 6. Access Reviews
- **Quarterly Reviews:** The Security Lead will review all user access lists every quarter to ensure roles are still appropriate.
- **Offboarding:** HR must notify IT immediately upon employee termination. All access must be revoked within 1 hour of departure.

## 7. Third-Party and Vendor Access
- Vendors (e.g., AWS Support) are granted access via temporary, time-bound credentials with MFA required.
- Vendor access is logged and reviewed by the Security Lead.
