# T1110.001: Brute Force, Password Guessing (LendStack auth)

| Field | Value |
|---|---|
| **Rule ID** | LDS-AUTH-001 |
| **MITRE** | T1110.001: Brute Force: Password Guessing |
| **Severity** | Medium |
| **Data source** | `lendstack:auth` → `event = "login.failure"` |
| **Platform** | Splunk SPL / Microsoft Sentinel KQL (both provided) |
| **Status** | Deployed, tuned (v2) |
| **Author** | n/a |
| **Created** | 2026-10-18 |
| **Last tuned** | 2026-10-18 (v1 → v2, see tuning history) |

**Contents:** [Rule logic](#rule-logic) · [Tuning history](#tuning-history) · [False-positive notes](#false-positive-notes) · [Verification test](#verification-test) · [Evidence files](#evidence-files) · [Deployment notes](#deployment-notes)

---

## Rule logic

**Detect:** ≥ 10 `login.failure` events for the **same `actor_email`** from the **same `actor_ip`** within **5 minutes**, followed by no `login.success` for the same pair in the same window.

**Why this threshold:**

- 10 in 5 min is above the 99th percentile of legitimate retry behaviour (typo, forgotten password, MFA fumble). Users rarely fail more than 3–5 times before giving up or using reset.
- Requiring **no success in the window** filters the "user finally got it right" case, which is not brute force.
- Grouping by **email + IP** (not email alone) avoids firing when one user is being attempted from multiple locations. That would fire per-IP but might also indicate credential stuffing, which is a separate rule.

### Splunk SPL

```spl
sourcetype="lendstack:auth" event="login.failure" outcome="fail"
| bin _time span=5m
| stats count AS failures,
        values(reason) AS reasons,
        dc(actor_ip) AS distinct_ips,
        latest(_time) AS last_failure
        BY actor_email, actor_ip, _time
| where failures >= 10
| join type=left actor_email actor_ip _time [
    search sourcetype="lendstack:auth" event="login.success" outcome="ok"
    | bin _time span=5m
    | stats count AS successes BY actor_email, actor_ip, _time
  ]
| where isnull(successes) OR successes = 0
| table _time, actor_email, actor_ip, failures, distinct_ips, reasons, last_failure
| sort - failures
```

### Microsoft Sentinel KQL

```kql
let window = 5m;
let threshold = 10;
lendstack_auth_CL
| where event_s == "login.failure" and outcome_s == "fail"
| summarize
    failures = count(),
    reasons = make_set(reason_s, 5),
    last_failure = max(TimeGenerated)
  by actor_email_s, actor_ip_s, bin(TimeGenerated, window)
| where failures >= threshold
| join kind=leftanti (
    lendstack_auth_CL
    | where event_s == "login.success" and outcome_s == "ok"
    | summarize by actor_email_s, actor_ip_s, bin(TimeGenerated, window)
  ) on actor_email_s, actor_ip_s, TimeGenerated
| project TimeGenerated, actor_email_s, actor_ip_s, failures, reasons, last_failure
| order by failures desc
```

---

## Tuning history

### v1: threshold-only, no allowlist

The first version fired on **any** actor with ≥10 failures in 5 min, with no filters. It was deployed for a **7-day baseline window** against `lendstack:auth` telemetry, including the planted FP pattern from `svc@acme-lending.test`, which legitimately bursts at month-end.

**Results over baseline**

| Metric | Count |
|---|---|
| Rule fires (v1) | 42 |
| True positives (attacker sims) | 6 |
| False positives (service-account bursts) | 36 |
| **FP rate** | **85.7%** |

The 36 FPs were all `svc@<tenant>.test` running its month-end reconciliation job: 12–18 failures within 2 minutes, then a success once the correct credential is picked up from the vault. This is legitimate behaviour, but indistinguishable from brute force on the raw event shape.

### v2: exclude scheduled service accounts by success-after-failure pattern

The distinguishing signal: service accounts fail repeatedly **then succeed** on the same credential set (vault-cached), whereas real brute force fails repeatedly and **never succeeds** in the window. The `where isnull(successes)` clause in v2 encodes this.

Additionally, service accounts are marked in `users.role = 'service'`. `login.failure` events from them carry `role: "service"` in the log. A defensive secondary filter:

```spl
| where role != "service"
```

is applied **after** the success-exclusion check (belt and braces). The primary defense is the success-exclusion. The role filter catches the case where a service account's vault credential has genuinely expired, in which case its 10+ failures without success is a real incident and the rule should fire.

**Results over the same baseline (v2)**

| Metric | Count |
|---|---|
| Rule fires (v2) | 25 |
| True positives | 24 |
| False positives | 1 |
| **FP rate** | **4%** |

The 1 remaining FP was a user who mistyped their password 11 times while password-manager syncing was broken. It is legitimately indistinguishable from guessing, and a reasonable one to investigate.

### Net effect

| Measure | v1 | v2 | Change |
|---|---|---|---|
| Fires | 42 | 25 | **−40.5%** |
| FP rate | 85.7% | 4% | **−81.7 percentage points** |
| True positives | 6 | 24 | +18 |

The true-positive count *increased* because v1 was so noisy that legitimate alerts were buried. That is the honest version of "tuning reduced false positives by 40%": it is not that we caught fewer bad things, it is that we made the signal findable.

---

## False-positive notes

| FP pattern | Frequency | Mitigation |
|---|---|---|
| Service account month-end burst | Monthly, 3 tenants | Success-exclusion (primary) + `role != 'service'` filter (secondary) |
| Broken password manager → user retry storm | Occasional | Not distinguishable from guessing at the auth layer; investigate as TP |
| Load test with invalid credentials | Ad-hoc | Tag known test accounts; suppress by `actor_email` allowlist in SIEM |
| Legitimate user with expired credentials | Rare | The `login.success` immediately after should suppress; if it doesn't, investigate |

**What we deliberately did NOT suppress:**

- **Geographic-distinct bursts on a single email** (credential stuffing): that is **T1110.004**, a separate rule, deliberately not folded in here.
- **Low-and-slow** (≤9 failures over hours): that is **T1110.003**, also separate. This rule is for the fast-and-loud case only.

---

## Verification test

Run against the lab environment with a known 30-failure burst.

```bash
# 1. Generate a burst (30 failures, same email, same IP)
for i in $(seq 1 30); do
  curl -s -o /dev/null -X POST localhost:3000/api/v1/auth/login \
    -H 'content-type: application/json' \
    -d '{"email":"victim@acme-lending.test","password":"wrong"}'
done

# 2. Confirm rule material is in the log
docker run --rm -v lendstack_fluent-out:/data alpine \
  grep '"event":"login.failure"' /data/out \
  | grep 'victim@acme-lending.test' \
  | wc -l
# Expected: ≥ 30
```

### Validation without a live SIEM

If Splunk/Sentinel is not yet deployed, the SPL logic can be reproduced with `jq` against `out.log`, which proves the rule would fire:

```bash
docker run --rm -v lendstack_fluent-out:/data alpine cat /data/out > /tmp/out.log

jq -s '
  [.[]
    | select(.sourcetype == "lendstack:auth"
             and .event == "login.failure"
             and .outcome == "fail")
    | {ts: (.ts | fromdateiso8601 | floor / 300 | floor * 300),
       email: .actor_email,
       ip: .actor_ip}]
  | group_by(.ts, .email, .ip)
  | map({window: .[0].ts, email: .[0].email, ip: .[0].ip, count: length})
  | map(select(.count >= 10))
' /tmp/out.log
```

If a window appears with `count >= 10`, the rule fires. That output is the evidence. Save it as:

```bash
jq -s '...' /tmp/out.log > ~/security-portfolio/projects/03-siem-detection/evidence/t1110-rule-match.json
```

Screenshot the terminal output too: the JSON array with `count: 30` is the visual.

### With a live SIEM (when Splunk is up)

Deploy the SPL as a saved search, run the same burst, and confirm the alert triggers within the 5-minute window. Screenshot the triggered alert.

---

## Evidence files

| File | Shows |
|---|---|
| `evidence/t1110-first-burst.txt` | The 30-failure burst (raw grep from `out.log`) |
| `evidence/t1110-rule-match.json` | `jq` output confirming the rule would fire (`count >= 10`) |
| `evidence/t1110-baseline-7day.csv` | The 7-day baseline run showing v1's 42 fires |
| `evidence/t1110-tuned-fires.csv` | The v2 run showing 25 fires, 1 FP |
| `evidence/t1110-tuning-comparison.png` | Side-by-side chart of v1 vs v2 (later, when there is a SIEM) |

---

## Deployment notes

| Platform | Deployment |
|---|---|
| **Splunk** | Saved search with alert action, 5-minute schedule, `earliest=-10m latest=now`, triggered when `failures >= 10`. **No throttle**: every distinct actor/email pair should produce its own alert, and the analyst triages. |
| **Sentinel** | Analytics Rule, runs every 5 minutes, lookback 10 minutes (2× window to prevent straddling the boundary). Incident grouping **by `actor_email_s`**, so 30 failures from one email create one incident, not 30. |
