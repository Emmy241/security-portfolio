# V-08 — Missing Audience and Issuer Validation

| Field | Value |
|---|---|
| **Severity** | Medium (CVSS 5.3) |
| **CWE** | CWE-345 — Insufficient Verification of Data Authenticity |
| **Endpoint** | All authenticated routes (via `requireAuth` middleware) |
| **Component** | `target-app/src/jwt.js` |
| **Status** | Confirmed exploitable |

## Summary

The API verifies the cryptographic signature of a JWT but does not check the `aud` (audience) or `iss` (issuer) claims. This means a valid token issued by any application using the same private key (e.g., a staging environment, a sibling service, or a partner integration) will be accepted by LendStack.

In a microservices architecture, this is a cross-service token replay vulnerability.

## Evidence

1. The token issued by the LendStack API contains `aud: "lendstack-web"` and `iss: "lendstack-api"`. 

2. However, the `verifyAccessToken` function does not enforce either claim. Because `jsonwebtoken` does not validate `aud` or `iss` unless explicitly configured to do so in the `verify` options, any token signed by the matching private key is accepted, regardless of its intended audience.

## Root Cause

In `jwt.js`, the `jwt.verify` call lacks the `audience` and `issuer` options:

return jwt.verify(token, publicKey, {
  algorithms: ['RS256']
  // Missing: audience: 'lendstack-web',
  // Missing: issuer: 'lendstack-api'
});

## Fix

Add the required claims to the verification options:

return jwt.verify(token, publicKey, {
  algorithms: ['RS256'],
  audience: 'lendstack-web',
  issuer: 'lendstack-api'
});
