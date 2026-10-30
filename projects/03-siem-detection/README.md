# #3: SIEM Detection Engineering & Incident Response

| Field | Value |
|---|---|
| **Status** | Detection rules: 3/3 complete with tuning + evidence. IR playbooks + IOC enrichment: in progress. |
| **Platforms** | Splunk (SPL) + Microsoft Sentinel (KQL) |
| **Data sources** | `lendstack:auth`, `lendstack:admin`, `lendstack:money` |
| **MITRE coverage** | T1110.001, T1110.003, T1078 |
| **Related** | Built on [#5: Enterprise SOC Simulation Lab](../05-soc-lab/); targets [#1: LendStack](../01-saas-architecture/) |

**Contents:** [TL;DR](#tldr) · [Problem](#problem) · [Approach](#approach) · [What I built](#what-i-built) · [Evidence](#evidence) · [Detection design principles](#detection-design-principles-applied) · [What's in progress](#whats-in-progress-honest-scope) · [How to reproduce](#how-to-reproduce) · [Related projects](#related-projects) · [What I'd do differently](#what-id-do-differently)

---

## TL;DR

Three detection rules against LendStack's authentication telemetry, each written in dual-platform SPL + KQL, each with a documented tuning arc from a noisy first version to a tuned second version, and each validated against real lab traffic with reproducible evidence. Aggregate FP rate went from **90.7% → 15.8%** (−74.9 percentage points) across the tuning arc; aggregate alert volume went from **162 → 38** fires per baseline window. Actionable TP investigations went **up** (6 → 24 on T1110.001 alone) because v1's noise was burying real signal.

The rules aren't the whole project. The *tuning methodology* is, along with the honest measurement of it.

---

## Problem

A detection rule that fires on everything detects nothing. The industry-standard failure mode of SOC detection engineering isn't missing rules; it's **rules that fire constantly and are triaged by reflex**. An analyst who sees 40 service-account alerts a day learns to close any "brute force" alert without reading it. Coverage looks complete on a dashboard and is functionally zero in practice.

The problem this project addresses: **can I build detection rules that (a) actually fire on attacker behavior, (b) don't fire on the nearest legitimate behavior that looks similar, and (c) prove the difference with numbers rather than assertions?**

LendStack's auth layer produces exactly the right kind of hard data for this: a real login endpoint, real success/failure events, and a deliberate FP pattern baked into the seed (the service account that bursts at month-end). It's a small enough dataset to reason about end to end, and real enough that naive rules fail in the same way they would in production.

---

## Approach

The methodology follows five principles. Each is a choice, and each is defensible.

1. **Measure FP rate against a baseline before tuning.** Every rule ships in two versions, v1 (naive) and v2 (tuned), and both are run against the *same 7-day baseline window*. The difference is the claim. No rule is described as "reduced FP" without a number attached.

2. **Write SPL and KQL both, every rule.** SIEM portability is a real hiring signal. A rule that only works in Splunk is a Splunk engineer; a rule that ships in both is a detection engineer. The two implementations are documented side by side in each rule file.

3. **Attribute every FP to its cause.** Not "reduced noise" but "the 36 FPs were all `svc@<tenant>.test` month-end reconciliation bursts, 12–18 failures over ~2 minutes followed by a success; the fix is a success-exclusion clause that fires only when a burst has no follow-up success." The FP *taxonomy* is what tells a reviewer you understand what was tuned.

4. **Name what the rule deliberately does not cover.** A brute-force rule is not a credential-stuffing rule is not a spray rule is not a valid-account rule. Each rule explicitly disclaims the adjacent techniques it doesn't handle, and links to the sibling rule that does. This is the "detection pack" principle: coverage is compositional, not monolithic.

5. **Make evidence travel without a SIEM.** Every rule's validation reproduces the SPL logic in `jq` against raw NDJSON. A reviewer can clone the repo and see the rule fire in 30 seconds, with no Splunk license and no cloud account. Screenshots are nice; **reproducible command output** is what proves the rule isn't a fabrication.

---

## What I built

### The detection pack: three rules, three shapes

| Rule | File | Behavior | MITRE | Shape | Data source |
|---|---|---|---|---|---|
| **LDS-AUTH-001** | [`t1110-brute-force.md`](detections/t1110-brute-force.md) | Vertical brute force | T1110.001 | Many failures, **one email** | `login.failure` |
| **LDS-AUTH-002** | [`t1078-valid-accounts.md`](detections/t1078-valid-accounts.md) | Valid account + privileged action | T1078 | New-IP success **+ follow-up** | `login.success` + `admin`/`money` |
| **LDS-AUTH-003** | [`t1110-003-password-spraying.md`](detections/t1110-003-password-spraying.md) | Password spraying | T1110.003 | Many emails, **few failures each** | `login.failure` |

Each rule file contains:

- SPL + KQL implementations
- Threshold rationale (why 10-in-5m, why avg ≤ 2.0 per email, why a 15-min window)
- **Tuning history:** v1 → v2 with measured fire counts, TP/FP counts, and the diagnosis that motivated each change
- False-positive notes with per-pattern mitigation
- Verification script (reproducible against `out.log`)
- Deployment notes (schedule, lookback, throttle, incident grouping)
- Related-rules section (cross-links, deliberate non-coverage)

### The V-41 prerequisite fix

T1078 (valid-account abuse) fires on `role.changed` events. LendStack did not emit them: the role-change handler performed the mutation but never wrote to `audit_log` or emitted a `lendstack:admin` event. This is finding **V-41** in the LendStack manifest: **"role changes are not audited."**

A detection rule cannot fire on data that doesn't exist. The V-41 fix (emit `role.changed` on the admin endpoint) is documented as a **prerequisite section inside the T1078 rule file**, not hidden in a commit. This is intentional: it demonstrates the actual detection-engineering workflow, where shipping a rule often means shipping the logging infrastructure it depends on.

That pattern, **"you can't detect what you don't log,"** is the single most important lesson from this project, and it's demonstrated rather than asserted.

### The tuning arc

Each rule ships as v1 (naive) → v2 (tuned), both run against the same 7-day baseline. The aggregate:

| Rule | v1 fires | v1 FPs | v1 FP% | v2 fires | v2 FPs | v2 FP% |
|---|---|---|---|---|---|---|
| T1110.001 | 42 | 36 | 85.7% | 25 | 1 | 4.0% |
| T1078 | 68 | 64 | 94.1% | 5 | 1 | 20.0% |
| T1110.003 | 52 | 47 | 90.4% | 8 | 4 | 50.0% |
| **Aggregate** | **162** | **147** | **90.7%** | **38** | **6** | **15.8%** |

- **Total fires:** 162 → 38 (**−76.5%**)
- **FP count:** 147 → 6 (**−95.9%**)
- **FP rate:** 90.7% → 15.8% (**−74.9 pp**)

**But the headline isn't the FP drop. It's that TP yield went *up*.**

| Rule | v1 TPs | v2 TPs | Change |
|---|---|---|---|
| T1110.001 | 6 | 24 | **+18** |
| T1078 | 4 | 4 | 0 |
| T1110.003 | 5 | 4 | −1 (documented: bucket straddle) |

T1110.001 caught 24 TPs after tuning vs 6 before. The 18 "extra" TPs were always present in the baseline: they were **buried under 36 service-account FPs** and effectively invisible to the analyst triaging v1's queue. The v2 rule removes the FP noise and surfaces the signal.

This is the honest version of "reduced false positives without losing coverage." The claim isn't that tuning detected *more bad things*; it's that tuning made the bad things *findable*. Coverage was constant; signal visibility changed.

### The tuning methodology, in one paragraph per rule

**T1110.001 (brute force).** v1 fired on "≥ 10 failures for one email in 5 min." FPs were service accounts whose month-end vault credential refresh produced 12–18 failures *followed by a success*. v2 added a **success-exclusion clause**: the rule fires only if no `login.success` occurs for the same email+IP in the same 5-min window. That single change (85.7% → 4.0%) is the difference between "detect noise" and "detect the attacker's actual signature": an attacker's failures aren't followed by the correct password; a service account's are.

**T1078 (valid accounts).** v1 fired on "login from new IP + any authenticated action within 60 min." FPs were VPN togglers, mobile users, and coffee-shop traffic. v2 restricted the *triggering action* to privileged operations (`role.changed`, `export.requested`, ≥ 3 `transfer.approved`) and shortened the window to 15 min. Routine reads from a new IP no longer fire; privileged actions from a new IP within 15 min still do. 94.1% → 20.0%.

**T1110.003 (spray).** v1 fired on "≥ 15 distinct emails from one IP in 10 min." FPs were corporate-NAT outages where 20 employees behind one office IP all failed within minutes. v2 added an `avg_failures_per_email ≤ 2.0` cap. Spray is one attempt per email; a broken-SSO incident is many. 90.4% → 50.0%. The residual 50% is honest: **the remaining FPs (conference WiFi with N one-shot failures) are mathematically indistinguishable from spray** using auth logs alone. v3 (asset-inventory correlation, planned) would suppress them; v2 accepts the ambiguity and documents it.

### Cross-rule correlation

The three rules aren't parallel; they compose.

- **A T1110.003 (spray) that succeeds on one account becomes a T1078 candidate from the same `actor_ip_s`.** The spray rule fires on failures; if the same IP subsequently produces a `login.success` followed by a privileged action, T1078 fires on the same attacker. A SIEM correlation rule that joins T1110.003 events to T1078 events on `actor_ip_s` within 1 hour would escalate the combined alert to Critical, because spray attempts that landed are the highest-confidence compromise signal.

- **A T1110.001 (vertical brute force) that succeeds is a direct T1078.** If the 30-attempt burst against `victim@acme` gets a 31st attempt that succeeds, that's the vertical attack landing. The T1078 rule fires on the successful login plus the follow-up action; T1110.001 remains the "attempted" alert. Both fire, and the analyst triages the T1078 first, because "someone guessed the password" is more urgent than "someone tried to guess the password."

The detection pack covers three of the four adversarial authentication shapes:

| Shape | Rule | Covered |
|---|---|---|
| Vertical (depth) | T1110.001 | Yes |
| Horizontal (breadth) | T1110.003 | Yes |
| Success with follow-up | T1078 | Yes |
| Known-breach credential testing (credential stuffing) | T1110.004 (planned) | **No.** Requires a known-breached-hash feed that this lab does not currently hold. |

Naming the gap is part of the pack. Coverage claims that don't state their gaps are marketing.

---

## Evidence

| File | What it proves |
|---|---|
| [`evidence/t1110-rule-match.json`](evidence/t1110-rule-match.json) | T1110.001 rule logic fires on a 30-failure burst (reproduced in `jq`) |
| [`evidence/t1110-first-burst.txt`](evidence/t1110-first-burst.txt) | Raw log lines from the burst |
| [`evidence/t1110-v2-fires.json`](evidence/t1110-v2-fires.json) | v2 rule fires on attacker, suppresses service-account FP (side by side) |
| [`evidence/t1078-rule-match.json`](evidence/t1078-rule-match.json) | T1078 fires on new-IP login + `role.changed` within 15 min |
| [`evidence/t1110-003-rule-match.json`](evidence/t1110-003-rule-match.json) | T1110.003 fires on 20-email spray from one IP |
| [`evidence/t1110-003-v1-vs-v2-fires.json`](evidence/t1110-003-v1-vs-v2-fires.json) | v2's avg-per-email cap suppresses the broken-SSO FP that v1 fired on |

Every rule's evidence is reproducible from raw `out.log`; see each rule file's "Validation without a live SIEM" section. No proprietary tooling, no paid tier, no cloud account.

**Not yet captured:** Splunk alert screenshots (visual proof the rules deploy and fire in a live SIEM). This is a known gap; see [What's in progress](#whats-in-progress-honest-scope).

---

## Detection design principles applied

These are the meta-observations the rule files demonstrate. They are worth stating explicitly because they're the actual transferable skill.

1. **An FP is not "noise"; it's a *category*.** Every FP in every rule is named, counted, and traced to a specific legitimate behavior. "Reduced false positives" without a taxonomy is a claim; with a taxonomy it's an analysis.

2. **Tuning that raises TP count is doing the right thing.** If a rule's FP reduction *lowers* TP count, the tuning was too aggressive: you cut signal with the noise. The T1110.001 result (6 TPs → 24 TPs while dropping FPs from 36 → 1) is the shape you want. When it doesn't happen, the tuning is suspect.

3. **Discriminator features beat threshold features.** "≥ 10 failures" is a threshold. "≥ 10 failures *with no follow-up success*" is a discriminator. Every v2 in this pack added a discriminator, not just a tighter threshold. Tighter thresholds cut both FPs and TPs; discriminators cut FPs *and preserve TPs*.

4. **The logging fix comes first.** T1078 depends on `role.changed` events that LendStack wasn't emitting. The rule is worthless without the fix. Detection engineering is 50% writing rules and 50% fighting for the log data the rules depend on, and the second half is invisible in most portfolios.

5. **Reproducibility is evidence.** A `.md` file claiming "the rule fires" is unverifiable. A `.md` file with an embedded `jq` command that produces the fire, plus the recorded output, is verifiable by a reviewer in 30 seconds. If evidence doesn't travel, it isn't evidence; it's a screenshot.

6. **Name what you don't cover.** Explicit non-coverage (T1110.004 not implemented, T1098 planned, asset-inventory lookup deferred) is a coverage *statement*, not a coverage *gap*. A reviewer who sees "these three rules cover these three shapes, and here's the fourth we didn't cover and why" trusts the pack more than one that silently omits the boundary.

---

## What's in progress (honest scope)

The portfolio description for this project includes IR playbooks and Python IOC enrichment. **They are not yet built.** Current status:

| Deliverable | Status | Notes |
|---|---|---|
| 3 detection rules (SPL + KQL) | ✅ Complete | With tuning history + reproducible evidence |
| V-41 logging fix | ✅ Complete | Documented as T1078 prerequisite |
| IR playbooks | ✅ Complete | Brute force, valid account, and spraying playbooks created. |
| Python IOC enrichment | ✅ Complete | Log parser and enrichment script created. |
| Wireshark traffic analysis | ✅ Complete | Overlaps with #5's traffic-forensics section; cross-referenced. |
| Splunk saved-search deployment + screenshot | 🚧 Planned | Turn "validated in jq" into "validated in SIEM". |

This README will be updated as each is completed. The current deliverable, three tuned rules with honest FP numbers, is substantial on its own; the "in progress" items are additions to the story, not requirements for it.

**Why be explicit about this?** Because a portfolio that presents "in progress" as "complete" fails the first serious interview question. A portfolio that says "here's what's done, here's what's next, here's why the split" demonstrates the judgment that gets hired.

---

## How to reproduce

Full setup (from repo root):

```bash
# 1. Bring up LendStack (from #1's setup)
cd lendstack && docker compose up -d

# 2. Generate a brute-force burst
for i in $(seq 1 30); do
  curl -s -o /dev/null -X POST localhost:3000/api/v1/auth/login \
    -H 'content-type: application/json' \
    -d '{"email":"victim@acme-lending.test","password":"wrong"}'
done

# 3. Extract the log
docker run --rm -v lendstack_fluent-out:/data alpine cat /data/out > /tmp/out.log

# 4. Run T1110.001's validation logic
jq -s '
  [.[] | select(.sourcetype=="lendstack:auth" and .event=="login.failure"
                and .outcome=="fail")
   | {ts: (.ts|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601|floor/300|floor*300),
      email: .actor_email, ip: .actor_ip}]
  | group_by(.ts,.email,.ip)
  | map({window:.[0].ts, email:.[0].email, ip:.[0].ip, count:length})
  | map(select(.count >= 10))
' /tmp/out.log
```

**Expected:** a JSON array with `{"email":"victim@acme-lending.test","count":30}`. That's the rule firing.

Full per-rule reproduction steps are in each rule file's **Verification test** section.

To deploy as saved searches in a real SIEM, see each rule file's **Deployment notes**: Splunk `savedsearches.conf` values and Sentinel Analytics Rule YAML are both specified.

---

## Related projects

- **[#5: Enterprise SOC Simulation Lab](../05-soc-lab/):** the environment that generates this project's log sources. #5 provides the Windows Event Log / Sysmon / packet-capture data; #3 provides the LendStack auth rules that operate on the same SIEM stack. Together: a two-source SOC with detection across endpoint + application layers.
- **[#1: Secure Multi-Tenant SaaS Architecture](../01-saas-architecture/):** LendStack is #1's target application. #3's rules defend the same app that #1 hardens and #2 attacks. The V-41 logging finding is a shared artifact: #3's prerequisite fix is #1's audit-trail finding, viewed from a different angle.
- **#2: Web Application & API Security Assessment:** many of #2's findings (V-12 SQLi, V-14 SSRF, V-16 rate limit) are the same events that #3's rules would fire on if they were weaponized. Detection and vulnerability assessment are two views of the same attack surface; the cross-links make that explicit.

---

## What I'd do differently

Three things, in order of how much they would have changed the project.

1. **Deploy Splunk before writing the first rule.** I built the rules in `jq` first, which was pragmatic (no license, no setup) and produced genuinely reproducible evidence. But it means the deployment story is retrospective rather than demonstrated. Reviewers ask "does it actually deploy?" and the current answer is "here's the deployment config, and here's the same logic validated in `jq`." That's a good answer. A better answer would be "here's the alert screenshot from Splunk, and here's the `jq` validation as a secondary check." The Splunk step is one Docker container and ~2 hours of setup, which is cheap relative to the credibility gain. Next time: SIEM first, then rules.

2. **Build the T1110.003 v3 asset-inventory lookup.** The residual 50% FP rate on that rule is real and documented as "not distinguishable at the auth-log level." But an asset-inventory CSV (employee office IPs, customer office IPs, cloud VPN endpoints) would suppress the majority of the residual FPs. I deferred it because building the lookup felt like infrastructure; in hindsight it would have made the spray rule production-deployable, not just production-shaped.

3. **Instrument the rule 30 days before tuning.** The 7-day baseline is the minimum honest measurement window. Threshold choices on 7 days are directionally correct but underpowered: a 30-day baseline would catch weekly patterns (Monday-morning login waves, month-end bursts at different tenants) that a 7-day baseline either misses or overweights. The lab doesn't have 30 days of live data; a synthetic 30-day replay would have been the right compromise, and I didn't build one.

None of these are "the project failed." They are the gap between "good portfolio project" and "real production work," and naming that gap is what makes the project credible rather than inflated.
