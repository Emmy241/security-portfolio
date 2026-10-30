# V-03 — Refresh Tokens Are Not Rotated or Revoked

| Field | Value |
|---|---|
| **Severity** | High (CVSS 7.4) |
| **CWE** | CWE-613 — Insufficient Session Expiration |
| **Endpoint** | `POST /api/v1/auth/refresh` |
| **Component** | `target-app/src/auth/routes.js` |
| **Status** | Confirmed exploitable |

## Summary
When a client uses a refresh token to generate a new access token, the server does not rotate (invalidate and replace) the refresh token. The same refresh token can be reused indefinitely until its 14-day expiration. 

Furthermore, changing a user's password does not revoke active refresh tokens. If an attacker steals a refresh token, they can maintain persistent access to the account even after the victim resets their password.

## Evidence
During the a2 phase demonstration, the same refresh token was submitted twice in a row:

1. First call:
   curl -s -X POST localhost:3000/api/v1/auth/refresh -H 'content-type: application/json' -d '{"refresh_token":"<TOKEN>"}'
   Response: 200 OK with a new access_token.

2. Second call (identical payload):
   curl -s -X POST localhost:3000/api/v1/auth/refresh -H 'content-type: application/json' -d '{"refresh_token":"<TOKEN>"}'
   Response: 200 OK with another new access_token.

The server did not mark the original token as `revoked_at` in the database after the first use.

## Root Cause
The refresh endpoint selects the token where `revoked_at IS NULL` but never sets `revoked_at` after generating the new access token. 

Additionally, the `POST /auth/password-change` route updates the password hash but does not execute `UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1`.

## Fix
1. **Implement Refresh Token Rotation:**
   When a refresh token is used:
   - Set `revoked_at = now()` on the old token.
   - Generate a new refresh token and return it to the client.
   - If a revoked token is reused, revoke the entire token family (assume theft).
2. **Revoke on Password Change:**
   Add a query to the password-change handler to revoke all active refresh tokens for the user.
