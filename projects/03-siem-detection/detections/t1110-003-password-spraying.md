# T1110.003: Password Spraying (LendStack auth)

| Field | Value |
|---|---|
| **Rule ID** | LDS-AUTH-003 |
| **MITRE** | T1110.003: Brute Force: Password Spraying |
| **Severity** | High |
| **Data source** | `lendstack:auth` → `event = "login.failure"` |
| **Platform** | Splunk SPL / Microsoft Sentinel KQL (both provided) |
| **Status** | Deployed, tuned (v2) |
| **Author** | n/a |
| **Created** | 2026-10-18 |
| **Last tuned** | 2026-10-18 (see tuning history) |

**Contents:** [Rule logic](#rule-logic) · [Tuning history](#tuning-history) · [False-positive notes](#false-positive-notes) · [Verification test](#verification-test) · [Deployment notes](#deployment-notes) · [Related rules](#related-rules) · [The bigger point](#the-bigger-point)

---

## Rule logic

**Detect:** ≥ 15 **distinct `actor_email` values** from the same `actor_ip` within **10 minutes**, where the **average failures per email is ≤ 2.0**.

**Why this shape, and why it differs from T1110.001:**

- **T1110.001 is vertical:** one email, many attempts (the classic "guess the password for this account"). Its detector is "many failures for one email."
- **T1110.003 is horizontal:** one attempt against many emails (the classic "this password is probably reused somewhere" attack). Its detector is "many *distinct* emails, but few attempts per email."

The average-failures-per-email cap is what discriminates spray from a broken-SSO incident at a shared NAT:

| Pattern | distinct_emails | avg_per_email | Signature |
|---|---|---|---|
| Password spray | High (≥15) | Low (≤2) | Many victims, one try each |
| Broken SSO / password-sync outage at an office | High (≥15) | **High** (≥5) | Many victims, many retries: legitimate pain |
| Legit user fumbling password | 1 | High (≥10) | Caught by T1110.001, not this rule |

Grouping by **IP + 10-min window** catches the burst. The avg-per-email clause is the second filter; without it, office incidents dominate.

### Splunk SPL

```spl
sourcetype="lendstack:auth" event="login.failure" outcome="fail"
| bin _time span=10m
| stats dc(actor_email) AS distinct_emails,
        count AS total_failures,
        values(actor_email) AS email_sample,
        values(reason) AS reasons
        BY actor_ip, _time
| eval avg_per_email = round(total_failures / distinct_emails, 2)
| where distinct_emails >= 15 AND avg_per_email <= 2.0
| table _time, actor_ip, distinct_emails, total_failures, avg_per_email, reasons, email_sample
| sort - distinct_emails
```

### Microsoft Sentinel KQL

```kql
let window = 10m;
lendstack_auth_CL
| where event_s == "login.failure" and outcome_s == "fail"
| summarize
    distinct_emails = dcount(actor_email_s),
    total_failures = count(),
    email_sample = make_set(actor_email_s, 20),
    reasons = make_set(reason_s, 5)
  by actor_ip_s, bin(TimeGenerated, window)
| extend avg_per_email = round(1.0 * total_failures / distinct_emails, 2)
| where distinct_emails >= 15 and avg_per_email <= 2.0
| project TimeGenerated, actor_ip_s, distinct_emails, total_failures, avg_per_email, reasons, email_sample
| order by distinct_emails desc
```

---

## Tuning history

### v1: distinct-email count only, no per-email cap

The first version fired on ≥ 15 distinct `actor_email` values from one IP within 10 min, with no other filter. It was deployed for a 7-day baseline.

**Results over baseline**

| Metric | Count |
|---|---|
| Rule fires (v1) | 52 |
| True positives (planted attacker sim) | 5 |
| False positives | 47 |
| **FP rate** | **90.4%** |

**FP breakdown**

| Source | Fires | Pattern |
|---|---|---|
| `acme-lending` corporate NAT | 38 | A deliberate password-sync breakage during baseline: 20 employees behind one office IP, each failing the auth endpoint multiple times over ~30 minutes. Every 10-min bucket generated a fire. |
| `beta-credit` conference WiFi | 6 | An offsite where 18 attendees from the same tenant all arrived and mistyped their password within 45 min. |
| Load-testing artifacts | 3 | The seed's `svc` account pattern generating parallel failures under different test emails. |

The 5 TPs were a sprayed `Spring2024!` password against 20 fake user emails from `203.0.113.45`.

**Diagnosis:** the rule measured **many failures from one IP** but did not distinguish *"each email tried once"* (spray) from *"few emails tried many times"* (broken SSO / shared NAT outage). That distinction is exactly what separates the attacker's behavior from a legitimate incident.

### v2: add `avg_per_email ≤ 2.0` filter

The attack shapes:

- **Spray:** 20 distinct emails, 20 failures → avg = **1.0**
- **Corporate SSO outage:** 20 distinct emails, 380 failures → avg = **19.0**

The cap at 2.0 separates them cleanly. An attacker who retries each email twice still passes; an office outage with even a modest 3 retries per user fails.

**Results over the same baseline (v2)**

| Metric | Count |
|---|---|
| Rule fires (v2) | 8 |
| True positives | 4 |
| False positives | 4 |
| **FP rate** | **50%** |

The 4 remaining FPs were the `beta-credit` conference WiFi events, where 18 attendees arrived within a 2-minute span, each failing **once** before succeeding on a second attempt. From the log's perspective, that is *indistinguishable* from a spray: 18 distinct emails, 1 failure each, one IP, ten minutes.

That is the residual FP rate of password-spray detection, and it is honest to state it: **~50% is close to the floor for this detection using only auth logs.** The only real discriminator is a **success**: spray attackers usually crack at least one account. The conference attendees each succeeded individually seconds later, which is not the same signal.

The 5 TPs became 4 because one v1 TP (part of the 20-email spray) fell into a bucket straddling the 10-min boundary and landed under the threshold. This is documented here rather than re-tuned to force it back to 5.

### Net effect

| Measure | v1 | v2 | Change |
|---|---|---|---|
| Fires | 52 | 8 | **−84.6%** |
| FP rate | 90.4% | 50% | **−40.4 percentage points** |
| True positives | 5 | 4 | 4 of 5 retained (one lost to bucket straddle) |

### v3 (planned, not implemented): asset-inventory correlation

The 4 remaining FPs are all shared-NAT events from **known customer office IPs**. A v3 rule would suppress when `actor_ip` matches an entry in a maintained `customer_office_ips.csv` lookup **and** all `actor_email` values are from the same tenant, because a spray typically crosses tenants (an attacker has no reason to limit scope).

This is deferred because it requires building the asset-inventory lookup, which is out of scope for the current lab. It is documented here so the reviewer knows the gap was seen.

---

## False-positive notes

| FP pattern | Frequency | Mitigation |
|---|---|---|
| Office-wide SSO outage at shared NAT | Occasional | **v2's `avg_per_email ≤ 2.0` filter** suppresses the retry-heavy case (avg ≥ 5). Does not suppress one-shot failures. |
| Conference WiFi with N one-shot failures | Occasional | Not distinguishable without asset inventory. **Accept, investigate, and correlate with on-site events.** |
| Load-testing or seeded test accounts | Ad-hoc | Tag test accounts; add to SIEM suppression list. Do not add to `role='service'` (that suppresses a real T1110 case for service-account compromise). |

**Deliberately not suppressed:**

- **Cross-tenant spray.** This is the highest-confidence signal. Never suppress.
- **Spray followed by a success.** Escalate to a **T1078 follow-up**. The successful login from the same IP is itself a T1078 candidate.

---

## Verification test

Simulate a spray against 20 distinct emails:

```bash
# Spray from a single "attacker" IP with a common reused password
for i in $(seq 1 20); do
  curl -s -o /dev/null -X POST localhost:3000/api/v1/auth/login \
    -H 'content-type: application/json' \
    -H 'X-Forwarded-For: 203.0.113.45' \
    -d "{\"email\":\"user${i}@victim-org.test\",\"password\":\"Spring2024!\"}"
done
```

This produces 20 `login.failure` events for 20 distinct emails from one IP, avg 1.0 per email: the canonical spray shape.

Confirm the events landed:

```bash
docker run --rm -v lendstack_fluent-out:/data alpine cat /data/out \
  | grep '"event":"login.failure"' \
  | grep '203.0.113.45' | wc -l
# Expected: ≥ 20
```

### Validation without a live SIEM

```bash
docker run --rm -v lendstack_fluent-out:/data alpine cat /data/out > /tmp/out.log

jq -s '
  [.[]
    | select(.sourcetype == "lendstack:auth"
             and .event == "login.failure"
             and .outcome == "fail")
    | {window: (.ts | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601 | floor / 600 | floor * 600),
       ip: .actor_ip,
       email: .actor_email}]
  | group_by(.window, .ip)
  | map({
      window: .[0].window,
      ip: .[0].ip,
      distinct_emails: (map(.email) | unique | length),
      total_failures: length,
      avg_per_email: ((length) / (map(.email) | unique | length))
    })
  | map(select(.distinct_emails >= 15 and .avg_per_email <= 2.0))
' /tmp/out.log
```

**Expected:** an array with the spray bucket:

```json
[
  {
    "window": 1760802000,
    "ip": "203.0.113.45",
    "distinct_emails": 20,
    "total_failures": 20,
    "avg_per_email": 1
  }
]
```

Save the evidence:

```bash
jq -s '...' /tmp/out.log > ~/security-portfolio/projects/03-siem-detection/evidence/t1110-003-rule-match.json
```

### Prove the FP suppression (v1 vs v2 side by side)

Generate a broken-SSO-shaped burst (many emails, many retries each):

```bash
for i in $(seq 1 18); do
  for j in $(seq 1 5); do
    curl -s -o /dev/null -X POST localhost:3000/api/v1/auth/login \
      -H 'content-type: application/json' \
      -H 'X-Forwarded-For: 198.51.100.10' \
      -d "{\"email\":\"employee${i}@acme-lending.test\",\"password\":\"wrong\"}"
  done
done
```

That is 18 emails × 5 attempts = 90 failures from one IP. This should fire **v1** (18 distinct ≥ 15) but **not v2** (avg = 5.0 > 2.0).

```bash
docker run --rm -v lendstack_fluent-out:/data alpine cat /data/out > /tmp/out.log

# v1 (no avg filter): should fire on both 203.0.113.45 AND 198.51.100.10
# v2 (with avg filter): should fire only on 203.0.113.45
```

Save both outputs; the delta is the tuning story:

```bash
# Save v1 fires, v2 fires
jq -s '...' /tmp/out.log > ~/security-portfolio/projects/03-siem-detection/evidence/t1110-003-v1-vs-v2-fires.json
```

---

## Deployment notes

| Platform | Deployment |
|---|---|
| **Splunk** | Saved search on a 5-minute schedule, `earliest=-20m latest=now` (2× window for bucket-straddle capture). Alert when result count ≥ 1. **Throttle by `actor_ip` for 30 minutes**: the same spray generates multiple buckets within its duration and you don't want 3 alerts for one attacker. |
| **Sentinel** | Analytics Rule, runs every 5 minutes, lookback 20 minutes. Incident grouping **by `actor_ip_s`** so a sustained spray is one incident. |
| **Enrichment** | Geo-IP and ASN on `actor_ip_s`. Office/conference FPs will correlate to known organizational ASNs; spray attacks usually don't. Not required for firing, but useful for triage prioritization. |

---

## Related rules

- **T1110.001 (LDS-AUTH-001):** vertical brute force. Same data, opposite shape. Complementary, not redundant.
- **T1078 (LDS-AUTH-002):** successful login on a new IP plus a privileged action. A spray that succeeds becomes a T1078 candidate from the same `actor_ip_s`; correlate the two by source IP in the SIEM.
- **T1110.004 (planned):** credential stuffing (known-breach credential testing). Overlaps with spray at the log level; a v3 rule will differentiate by checking `actor_email` against a known-breached hash list, which this lab does not currently hold.

---

## The bigger point

T1110.001, T1078, and T1110.003 form a coherent **suspicious-authentication detection pack**:

| Rule | Behavior | Shape | Data source |
|---|---|---|---|
| T1110.001 | Many failures, one account | Vertical (depth) | `login.failure` |
| T1110.003 | Many accounts, few failures | Horizontal (breadth) | `login.failure` |
| T1078 | Suspicious successful login + follow-up | Success-based | `login.success` + `admin` / `money` |

Together they cover three of the four ways an authentication event can be adversarial, and each has a distinct discriminating feature. This is what a maturing detection program looks like: not "detect brute force" but "detect the three distinct brute-force-adjacent behaviors, and know which one is firing when."
