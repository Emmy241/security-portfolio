# #4 — OAuth & JWT Security Review

| Field | Value |
|---|---|
| **Status** | 5 findings (1 Critical, 2 High, 2 Medium) documented with reproducible evidence. |
| **Worked example** | [LendStack](../../lendstack/) — the same fintech/lending SaaS used in #1 and #2 |
| **Findings** | Critical: V-06 (Secrets in Git) · High: V-01 (Signature Bypass), V-03 (Refresh Not Rotated) · Medium: V-04 (No Revocation), V-08 (Missing Aud/Iss) |
| **Related** | [#2 (Web/API)](../02-webapp-api-assessment/) (V-11, V-13 rely on this auth layer) |

---

## TL;DR

LendStack uses JSON Web Tokens (JWTs) and OAuth-style refresh tokens to authenticate API requests. This review audited the entire authentication and secrets lifecycle. 

The result is a chain of findings that allow an unauthenticated attacker to completely bypass authentication. It starts with **V-06** (live database credentials committed to Git), moves to **V-01** (the API accepts forged tokens without verifying signatures), and continues with **V-03** and **V-04** (stolen tokens cannot be revoked, and refresh tokens never expire).

The story is not "you forgot to check a claim." It is that **the system trusted the token itself more than it trusted its own servers**.

## Problem

In a modern API, the JWT is the keys to the kingdom. If the token verification logic is flawed, or if the secrets protecting the token issuance are leaked, the entire access control model collapses. 

The goal of this review was to test three specific boundaries:
1. **The Secret Boundary:** Are the credentials used to sign tokens and access the database kept secret?
2. **The Verification Boundary:** Does the server actually verify that a token was issued by the legitimate authority, or does it trust the client's claims?
3. **The Lifecycle Boundary:** When a token is compromised or a session ends, can the server invalidate it?

LendStack failed all three.

## Approach

This review followed a standard methodology for authentication testing:

- **Secrets Enumeration:** Checked Git history and configuration files for exposed signing keys and database credentials (V-06).
- **Cryptographic Testing:** Attempted to forge tokens by exploiting algorithm confusion and signature verification gaps (V-01).
- **Lifecycle Testing:** Attempted to reuse refresh tokens, tested password-change token invalidation, and decoded access token lifespans (V-03, V-04).
- **Claim Validation:** Stripped the `aud` and `iss` claims to test for cross-service token replay (V-08).

Every finding was proven against a live LendStack instance. V-06 is particularly notable because the leaked database credentials were used to directly connect to Postgres.

## What I built — findings

| Finding | Severity | Impact | Root Cause |
|---|---|---|---|
| [**V-01** — Missing Signature Verification](findings/v01-signature-not-verified.md) | High | Authentication Bypass (forge any user) | `jwt.decode` used instead of `jwt.verify` in middleware |
| [**V-03** — Refresh Tokens Not Rotated](findings/v03-refresh-tokens-not-rotated.md) | High | Persistent access after password reset | Tokens never revoked on reuse or password change |
| [**V-04** — No Revocation Path](findings/v04-no-token-revocation.md) | Medium | 24-hour attacker persistence | 24h expiry, no denylist, no `/logout` |
| [**V-06** — Secrets in Git](findings/v06-secrets-in-git-history.md) | **Critical** | Full database access | `.env` committed to repo since initial commit |
| [**V-08** — Missing Aud/Iss Checks](findings/v08-missing-aud-iss.md) | Medium | Cross-service token replay | `jwt.verify` lacks `audience` and `issuer` options |

### The Attack Chain

These findings compose into a complete authentication bypass:

1. **V-06** lets an attacker pull the production database password from the public GitHub repository.
2. **V-01** lets an attacker bypass login entirely by forging an `alg: none` token. 
3. **V-03** and **V-04** mean that even if a legitimate admin discovers the attack, they cannot terminate the attacker's session by changing their password.

## The Most Valuable Lesson: Library Defaults Change

The most interesting technical detail in this review is how **V-01 (Algorithm Confusion)** evolved. 

Historically, passing a public key to `jwt.verify()` without specifying `algorithms` allowed an attacker to sign an `HS256` token using the public key as the HMAC secret. 

However, `jsonwebtoken` v9 (used by LendStack) introduced a key-type check. If the header says `HS256`, the key must be a symmetric string, not a PEM file. This blocked the classic algorithm confusion attack.

But the application was still vulnerable via a different path: **`jwt.decode()` vs `jwt.verify()`**. The middleware was decoding the token without verifying the signature at all. This demonstrates a critical audit principle: **do not assume a vulnerability is patched just because the library version was updated.** Always test the actual code path.

## Fixes (M8)

The fixes for these findings are documented in each finding file. In summary:

- **V-01:** Replace `jwt.decode` with `jwt.verify`, and strictly allowlist `['RS256']`.
- **V-03:** Implement refresh token rotation. Revoke all tokens on password change.
- **V-04:** Reduce access token lifespan to 15m. Implement a logout endpoint and Redis denylist.
- **V-06:** Rotate the database password, remove `.env` from tracking (`git rm --cached`), and purge history with `git-filter-repo`. 
- **V-08:** Add `audience: 'lendstack-web'` and `issuer: 'lendstack-api'` to the `jwt.verify` options.

## Related projects

- **[#1 — Secure Multi-Tenant SaaS Architecture](../01-saas-architecture/):** The architecture lens. V-30 (RLS bypass) matters here because even if V-01 is fixed and a user is authenticated correctly, the DB still allows cross-tenant reads.
- **[#2 — Web Application & API Security Assessment](../02-webapp-api-assessment/):** The exploitation lens. V-13 (Stored XSS) exfiltrates the JWT that this review found cannot be revoked. V-11 (Mass Assignment) bypasses the auth check differently, but achieves the same result.
- **[#3 — SIEM Detection Engineering](../03-siem-detection/):** The detection lens. V-01 and V-11 are both detectable via `lendstack:auth` event anomalies (e.g., `login.success` for a user that doesn't exist).
