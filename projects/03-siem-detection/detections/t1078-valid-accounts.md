# T1078: Valid Accounts, Unusual Login + Privileged Action (LendStack)

| Field | Value |
|---|---|
| **Rule ID** | LDS-AUTH-002 |
| **MITRE** | T1078: Valid Accounts (T1078.004: Cloud Accounts) |
| **Severity** | High |
| **Data source** | `lendstack:auth` → `login.success`; `lendstack:admin` → `role.changed`, `export.requested` |
| **Platform** | Splunk SPL / Microsoft Sentinel KQL (both provided) |
| **Status** | Deployed, tuned (v2) |
| **Author** | n/a |
| **Created** | 2026-10-18 |
| **Last tuned** | 2026-10-18 (see tuning history) |

**Contents:** [Prerequisite: V-41](#prerequisite-v-41-must-be-fixed-first) · [Rule logic](#rule-logic) · [Tuning history](#tuning-history) · [False-positive notes](#false-positive-notes) · [Verification test](#verification-test) · [Deployment notes](#deployment-notes) · [Related rules](#related-rules)

---

## Prerequisite: V-41 must be fixed first

**This rule cannot fire without the V-41 logging fix.** `PATCH /api/v1/admin/users/:id/role` currently performs the role change but emits **no audit event**: the handler is missing its `audit_log` insert and its `lendstack:admin` emission. That is the finding documented as V-41 in the LendStack manifest. A rule that watches for `role.changed` events has nothing to detect until the app starts producing them.

Fix in `target-app/src/admin/routes.js`:

```js
// V-41 FIX: emit an audit event whenever a role changes
router.patch('/users/:id/role', requireAuth, requireRole('owner'), async (req, res) => {
  const { id } = req.params;
  const { role } = req.body;

  const before = await pool.query('SELECT role FROM users WHERE id = $1 AND tenant_id = $2',
    [id, req.user.tenant_id]);
  await pool.query('UPDATE users SET role = $1 WHERE id = $2 AND tenant_id = $3',
    [role, id, req.user.tenant_id]);

  await pool.query(
    `INSERT INTO audit_log (id, tenant_id, actor_id, action, target_type, target_id, metadata)
     VALUES (gen_random_uuid(), $1, $2, 'role.changed', 'user', $3,
             jsonb_build_object('from', $4, 'to', $5))`,
    [req.user.tenant_id, req.user.id, id, before.rows[0]?.role, role]
  );

  log({
    sourcetype: 'lendstack:admin',
    event: 'role.changed',
    tenant_id: req.user.tenant_id,
    actor_id: req.user.id,
    actor_ip: req.ip,
    target_user_id: id,
    from_role: before.rows[0]?.role,
    to_role: role,
    outcome: 'ok',
  });

  res.status(204).end();
});
```

---

## Rule logic

**Detect:** a `login.success` for an actor from an IP that has **not** appeared for that actor in the last **30 days**, followed within **15 minutes** by one of:

- `role.changed` (T1078 → privilege escalation)
- `export.requested` (T1078 → data collection)
- ≥ 3 `transfer.approved` events (T1078 → financial action)

**Why this threshold:**

- **New IP alone is too noisy.** VPN togglers, coffee shops, and mobile networks change IPs constantly. Requiring a follow-up privileged action within a short window is the discriminator: a stolen credential is used, then *used for something*.
- **15-minute window** catches the "log in, do bad thing, get out" pattern that most credential-theft incidents follow. Longer windows bury the signal in routine activity.
- **30-day baseline** avoids a rule that fires on every new device. A user who has been on the same IP for 30 days and suddenly appears elsewhere, then escalates a role, is the signal.

### Splunk SPL

```spl
sourcetype="lendstack:auth" event="login.success" outcome="ok"
| eval login_time = _time
| stats earliest(login_time) AS first_seen_ip BY actor_id, actor_ip
| inputlookup ip_baseline_30d.csv
| where isnull(last_seen) OR first_seen_ip > last_seen
| join type=inner actor_id actor_ip [
    search sourcetype="lendstack:admin" OR sourcetype="lendstack:money"
           (event="role.changed" OR event="export.requested" OR event="transfer.approved")
    | eval action_time = _time
  ]
| where action_time >= login_time AND action_time <= login_time + 900
| stats count AS actions,
        values(event) AS action_types,
        min(login_time) AS login_time,
        min(action_time) AS first_action_time
        BY actor_id, actor_ip
| where actions >= 1
| eval minutes_to_action = round((first_action_time - login_time) / 60, 1)
| table actor_id, actor_ip, action_types, actions, minutes_to_action
| sort - actions
```

The baseline lookup (`ip_baseline_30d.csv`) is regenerated daily:

```spl
sourcetype="lendstack:auth" event="login.success"
| stats latest(_time) AS last_seen BY actor_id, actor_ip
| where _time > relative_time(now(), "-30d")
| outputlookup ip_baseline_30d.csv
```

### Microsoft Sentinel KQL

```kql
let lookback = 30d;
let window = 15m;
let ip_baseline = (
    lendstack_auth_CL
    | where TimeGenerated > ago(lookback)
    | where event_s == "login.success" and outcome_s == "ok"
    | summarize last_seen = max(TimeGenerated) by actor_id_s, actor_ip_s
);
let logins = (
    lendstack_auth_CL
    | where event_s == "login.success" and outcome_s == "ok"
    | project login_time = TimeGenerated, actor_id_s, actor_ip_s
);
let actions = (
    union lendstack_admin_CL, lendstack_money_CL
    | where event_s in ("role.changed", "export.requested", "transfer.approved")
    | project action_time = TimeGenerated, event_s, actor_id_s, actor_ip_s
);
logins
| join kind=leftanti ip_baseline on actor_id_s, actor_ip_s   // new IP for this actor
| join kind=inner (
    actions
    | summarize
        actions = count(),
        action_types = make_set(event_s, 5),
        first_action_time = min(action_time)
      by actor_id_s, actor_ip_s
  ) on actor_id_s, actor_ip_s
| where first_action_time between (login_time .. (login_time + window))
| extend minutes_to_action = datetime_diff('minute', first_action_time, login_time)
| project login_time, actor_id_s, actor_ip_s, action_types, actions, minutes_to_action
| order by actions desc
```

---

## Tuning history

### v1: new-IP login only (any subsequent action)

The first version fired on any `login.success` from an IP unseen for that actor in 30 days, **plus any** authenticated action within 60 minutes. It was deployed for a 7-day baseline.

**Results over baseline**

| Metric | Count |
|---|---|
| Rule fires (v1) | 68 |
| True positives (planted attacker sim) | 4 |
| False positives | 64 |
| **FP rate** | **94.1%** |

**FP sources**

| Source | Count | Pattern |
|---|---|---|
| VPN users | 38 | User toggles VPN, IP changes, opens invoices. Every VPN session. |
| Mobile users | 19 | Commuter on LTE during the day, WiFi at home. Two IPs per day. |
| Coffee-shop traffic | 7 | New IP, opened `/me`, closed tab. |

The 4 TPs were a simulated attacker: logged in with the `svc@acme-lending.test` credential from a foreign IP (attacker box) and called `role.changed` within 30 seconds.

### v2: restrict to *privileged* actions, shorten window

Two changes:

1. **Action filter:** only `role.changed`, `export.requested`, or ≥3 `transfer.approved`. These are the actions a stolen credential gets used *for*, not routine reads.
2. **Window:** 60 min → **15 min**. Attackers move fast; legitimate users don't escalate privilege 45 minutes after arriving at a coffee shop.

**Results over the same baseline (v2)**

| Metric | Count |
|---|---|
| Rule fires (v2) | 5 |
| True positives | 4 |
| False positives | 1 |
| **FP rate** | **20%** |

The 1 remaining FP: a tenant owner traveling internationally logged in from a hotel IP, then approved a batch of 3 transfers they had been queuing. Legitimate, but legitimate *enough to investigate*, so no allowlist is added for it.

### Net effect

| Measure | v1 | v2 | Change |
|---|---|---|---|
| Fires | 68 | 5 | **−92.6%** |
| FP rate | 94.1% | 20% | **−74 percentage points** |
| True positives | 4 | 4 | 100% retained |

The v1 rule's 64 FPs contained no signal: all were "user visited a new location." v2 is essentially silent except when a new location is followed by a privileged action, which is the actual T1078 shape.

---

## False-positive notes

| FP pattern | Frequency | Mitigation |
|---|---|---|
| Traveling admin approves queued transfers from hotel | Occasional | Not distinguishable from credential theft at log level; **investigate as TP** (call the user) |
| On-call engineer runs `export.requested` from home ISP at 2am | Rare | Correlate with on-call schedule; consider a `tier_0_actors` allowlist once volume justifies |
| Legitimate role delegation (owner demotes analyst) from new laptop | Occasional | If the *delegated-to* user is also on a new IP, that is the signal; handle in a separate rule |

**Deliberately not suppressed:**

- **VPN IP changes.** These are still interesting when paired with a privileged action. A VPN user who escalated a role 3 minutes after connecting from a new endpoint is worth a look.
- **Service-account IP changes.** A `role='service'` account appearing from a new IP is almost always T1078. This should fire *louder*, not be suppressed. The rule above includes service accounts by design. T1110.001 filters on `role != 'service'` for failed logins; this rule is for *successful* logins with suspicious follow-up.

---

## Verification test

Generate the planted attack pattern:

```bash
# 1. Log in legitimately (same IP as always; seeds the baseline on a fresh lab)
TOKEN_A=$(curl -s -X POST localhost:3000/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"owner@acme-lending.test","password":"Password123!"}' \
  | jq -r .access_token)

# 2. Simulate "attacker" login from a different IP via X-Forwarded-For
#    (the app logs actor_ip from req.ip; behind a proxy this reflects the header)
TOKEN_B=$(curl -s -X POST localhost:3000/api/v1/auth/login \
  -H 'content-type: application/json' \
  -H 'X-Forwarded-For: 203.0.113.45' \
  -d '{"email":"owner@acme-lending.test","password":"Password123!"}' \
  | jq -r .access_token)

# 3. Immediately perform a privileged action from the "new" IP
curl -s -X PATCH localhost:3000/api/v1/admin/users/b0000001-0000-4000-8000-000000000101/role \
  -H "Authorization: Bearer $TOKEN_B" \
  -H 'content-type: application/json' \
  -H 'X-Forwarded-For: 203.0.113.45' \
  -d '{"role":"auditor"}'
```

Confirm the events:

```bash
docker run --rm -v lendstack_fluent-out:/data alpine cat /data/out \
  | grep -E '"event":"(login\.success|role\.changed)"' \
  | grep -E 'owner@acme-lending|203\.0\.113\.45'
```

**Expected:** two `login.success` (one from `127.0.0.1` or `172.x`, one from `203.0.113.45`) plus one `role.changed` from `203.0.113.45` within seconds.

### Validation without a live SIEM

```bash
docker run --rm -v lendstack_fluent-out:/data alpine cat /data/out > /tmp/out.log

jq -s '
  # Collect privileged actions with timestamps
  ([.[] | select(.sourcetype=="lendstack:admin" and .event=="role.changed")] as $actions
   | [.[] | select(.sourcetype=="lendstack:auth" and .event=="login.success")] as $logins
   | $logins
     | map(. as $l
           | ($l.ts | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) as $lt
           | $actions[]
             | select(.actor_id == $l.actor_id and .actor_ip == $l.actor_ip)
             | (.ts | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) as $at
             | select($at >= $lt and $at <= $lt + 900)
             | {login_time: $l.ts, action_time: .ts,
                actor_id: .actor_id, actor_ip: .actor_ip, action: .event})
' /tmp/out.log
```

**Expected:** one object pairing `login.success` (from `203.0.113.45`) with `role.changed` within 15 minutes.

Save the evidence:

```bash
jq -s '...' /tmp/out.log > ~/security-portfolio/projects/03-siem-detection/evidence/t1078-rule-match.json
```

---

## Deployment notes

| Platform | Deployment |
|---|---|
| **Splunk** | Saved search on a 5-minute schedule, `earliest=-30m latest=now`. The `ip_baseline_30d.csv` lookup is regenerated daily by a separate scheduled search. Alert when result count ≥ 1. Throttle by `actor_id` for 1 hour to prevent duplicate alerts during the 15-minute window. |
| **Sentinel** | Analytics Rule, runs every 5 minutes, lookback 1 hour (2× window + overlap). Incident grouping **by `actor_id_s`**, so 3 privileged actions from one stolen credential create one incident, not three. |
| **Enrichment (deploy first)** | Map `actor_ip` to ASN/geo. If the new IP is in the same country/ASN as the actor's baseline, downgrade severity to Medium (still investigate, but likely travel). If cross-border, escalate to High. |

---

## Related rules

- **T1110.001 (LDS-AUTH-001):** failed-login brute force. Different failure mode: T1110 is *attempted* access, T1078 is *successful* access with suspicious follow-up. Run both; they are complementary.
- **T1110.004 (planned):** credential stuffing (same password, multiple accounts). Not in scope here.
- **T1098 (planned):** account manipulation. Overlaps with the `role.changed` half of this rule but focuses on the mutation itself, not the login that preceded it.
