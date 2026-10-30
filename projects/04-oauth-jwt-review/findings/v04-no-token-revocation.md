# V-04 — Access Tokens Cannot Be Revoked Before Expiration

| Field | Value |
|---|---|
| **Severity** | Medium (CVSS 6.5) |
| **CWE** | CWE-613 — Insufficient Session Expiration |
| **Endpoint** | `POST /api/v1/auth/login` |
| **Component** | `target-app/src/jwt.js` |
| **Status** | Confirmed exploitable |

## Summary

The API issues JSON Web Tokens (JWTs) with a 24-hour expiration (`expiresIn: '24h'`). Because JWTs are stateless and the application does not maintain a token denylist, there is no way to revoke an access token once it has been issued.

If an attacker steals a token (e.g., via the Stored XSS vulnerability in V-13), the victim cannot log them out. The attacker maintains full access to the account for up to 24 hours, even if the victim uses a "logout" endpoint or resets their password.

## Evidence

1. Log in and decode the issued token's payload to inspect the `exp` and `iat` (issued at) claims.

TOKEN=$(curl -s -X POST localhost:3000/api/v1/auth/login -H 'content-type: application/json' -d '{"email":"owner@acme-lending.test","password":"Password123!"}' | jq -r .access_token)
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq .

Response: The difference between `exp` and `iat` is exactly 86,400 seconds (24 hours).

2. There is no `/logout` endpoint, and no logic in the middleware to check against a revoked tokens list. The API blindly trusts the cryptographic signature until the `exp` time passes.

## Root Cause

The `jwt.js` file issues long-lived tokens, and the middleware `verifyAccessToken` has no mechanism to check if a token is still valid server-side:

return jwt.sign(payload, privateKey, {
  algorithm: 'RS256',
  expiresIn: '24h', // Too long
});

## Fix

1. **Shorten the Access Token lifespan:** Reduce `expiresIn` to `15m` (15 minutes). Clients should use the refresh token to get a new access token when it expires.
2. **Implement a Denylist (Optional but recommended for high security):** If immediate revocation is required, maintain a Redis denylist of JWTs that have been explicitly logged out or invalidated. The middleware must check this list on every request.
3. **Token Versioning:** Include a `token_version` claim in the JWT. When a user logs out or changes their password, increment their `token_version` in the database. Reject any JWT with an older version.
