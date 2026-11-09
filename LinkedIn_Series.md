# LinkedIn 8-Post Series: LendStack Security Portfolio

## Post 1: The Hook / The RLS Bypass (Project #1)
*Status: Already Posted.*

**Visual:** The Carbon screenshot of the database query returning 3 tenants' data.
**The Text:** (Your original post)

---

## Post 2: The Engineering Fix (Project #1)

**Visual:** Carbon screenshot of your terminal showing `rls-check.sh` returning a **red FAIL** output.

**The Text:**
In my last post, I showed how a fintech platform I built (LendStack) leaked 15 invoices across 3 different tenants because the database role owned the tables, silently bypassing Row-Level Security (RLS).

The naive fix is to change the database role, verify it works, and move on. But as a security engineer, that’s not enough. 

If a fix relies on human memory during a deployment, it’s not a control. It’s a hope.

In a multi-tenant SaaS platform, a single routine database migration could accidentally reassign ownership. If that happens, the data is exposed again.

So I built a guardrail. 

I wrote a custom CI/CD pipeline check (`rls-check.sh`). It queries the PostgreSQL system catalogs (`pg_class` and `pg_roles`). If the application role owns a table, or if `FORCE RLS` is not enabled, the build fails. 

The visual below is that check doing its job. It catches the exact misconfiguration that caused the leak.

This changed my perspective on SaaS security:
• A policy on paper means nothing.
• A one-time manual fix is a temporary patch.
• Automated, CI-enforced checks are the true security boundary.

Next up, we’ll look at what happens when the data *is* secure, but the business logic isn’t. 👇

---

## Post 3: The Business Logic Flaw (Project #1)

**Visual:** A SQL query output showing `approved_by = created_by` (the `self_approved = t` finding).

**The Text:**
Data isolation is critical. But in fintech, you also have to worry about what an authorized user does with the data they *are* allowed to see.

While building LendStack, I audited the money-movement logic. 

The platform had a maker-checker workflow. A user creates a transfer, and it sits in a `pending` state until someone else approves it. The schema even had `created_by` and `approved_by` columns.

But the code never actually compared them.

An authenticated user could create a $10,000 transfer and immediately approve it themselves. From a business perspective, this violates the fundamental Segregation of Duties principle (and violates ISO 27001 A.5.3 and PCI DSS). It's the exact mechanism that enables internal fraud.

How do you fix this at the engineering level?

You don't just add an `if` statement in the API. If a future developer forgets to check it, the flaw returns. 

You push the rule down to the database. I wrote a migration that added a hard `CHECK` constraint: `approved_by != created_by`. 

Now, even if the API is compromised or a developer makes a mistake, the database will physically reject the self-approval.

In SaaS, technical bugs are business risks. Engineering the guardrail is how you protect the bottom line.

Tomorrow, I’ll switch sides and show what happens when I put on the attacker hat against this same API. 👇

---

## Post 4: The Attacker's Perspective (Project #2)

**Visual:** Your screenshot of the Admin Panel with the `alert("localhost")` popup.

**The Text:**
Over the last few posts, I’ve focused on defending the database. Now, let’s switch to the offensive side.

If you’re securing a SaaS platform, you have to know how an attacker will try to get inside.

I conducted a full penetration test against my own application (LendStack). One of the most impactful findings was a Stored Cross-Site Scripting (XSS) vulnerability.

The admin panel rendered merchant memos using `innerHTML` without escaping the input. 

I planted a payload in a memo: `<img src=x onerror="...">`. 

When an admin logged in and clicked on their dashboard, the JavaScript executed in their browser. The payload grabbed their JWT session token from the DOM and silently exfiltrated it to an attacker-controlled server.

The impact? Complete account takeover. 

In a real SaaS environment, an attacker could use that stolen admin token to export the entire database, change permissions, or approve fraudulent transactions.

The engineering fix isn't just "sanitize input." It's about context-aware output encoding (using `textContent` instead of `innerHTML`) and enforcing a strict Content Security Policy (CSP) that blocks inline event handlers.

Image below: The exact moment the XSS payload fires in the admin's browser. 👇

---

## Post 5: The Auth & Secrets Failure (Project #4)

**Visual:** Carbon screenshot of the terminal running `git log -p -- .env` and exposing the password (`+APP_DB_PASSWORD=LendStack_App_Pr0d_2024!`).

**The Text:**
How do you break into a system when the front door is locked? You look for the keys under the mat.

In this phase of the LendStack project, I audited the authentication layer and secrets lifecycle. I found two critical issues that would destroy a real fintech platform.

**1. Secrets in Git History:**
The `.env` file was deleted from the repository, but it was committed in the past. I used `git log -p -- .env` to extract the live database credentials from the commit history. I proved they were active by connecting directly to the production database from my terminal.

**2. JWT Signature Bypass:**
The API used `jwt.decode()` instead of `jwt.verify()` in its middleware. This meant the server trusted the client's claims without checking the cryptographic signature. I forged an `alg:none` token and authenticated as the platform owner without ever knowing a password.

The fix for this requires purging Git history (with `git-filter-repo`), rotating all credentials, and enforcing strict RS256 signature validation.

A lot of developers think "we removed the .env file, so we're safe." This proves why that assumption is dangerous. 👇

---

## Post 6: The SOC Analyst / DFIR (Project #5)

**Visual:** Carbon screenshot showing the decoded DNS Tunneling payload (Base64) or Sysmon logs showing `PSEXESVC.exe`.

**The Text:**
What does an attacker do once they are inside the network?

I built an enterprise SOC Simulation Lab to answer this. I set up a Windows endpoint with Sysmon and an attacker box (Kali Linux), then simulated a lateral movement attack.

Using `impacket-psexec`, I moved from the attacker box to the Windows victim. Sysmon immediately caught the signature: `services.exe` spawning `PSEXESVC.exe`.

But my favorite part of this project was the network forensics.

I analyzed a PCAP (packet capture) of a DNS Tunneling attack. The attacker was bypassing the firewall by sending Base64-encoded data out through DNS queries (Port 53) to an external domain. 

To the firewall, it looked like normal web traffic. To a forensic analyst, the huge, high-entropy subdomains were a screaming red flag. 

I wrote a Python script to parse the PCAP, extract the DNS queries, decode them, and reveal the stolen data.

Image below: The exact moment the exfiltration reveals itself in the logs. 👇

---

## Post 7: The Detection Engineer (Project #3)

**Visual:** A screenshot of your markdown table showing the "Tuning History" (v1 85% FP vs v2 4% FP).

**The Text:**
It’s one thing to secure an application. It’s another to know when someone is actively attacking it.

A secure platform still needs a SOC (Security Operations Center) watching the logs. 

For this phase, I built detection rules in Splunk (SPL) and Microsoft Sentinel (KQL) mapped to the MITRE ATT&CK framework.

One of the rules I wrote was for Brute Force attacks (T1110). 

The naive version flagged any IP with more than 10 failed logins in 5 minutes. The problem? It was incredibly noisy. False positives from service accounts drowning the analysts. 

So I tuned it. I added a discriminator: *the rule only fires if there are 10 failures AND no successful login occurs afterward.*

Why? Because an attacker guessing passwords will keep failing. A service account eventually authenticates. 

That single change reduced the false positive rate from 85% to 4%, while actually improving true-positive detection.

Detection engineering isn't just about writing queries. It's about understanding the difference between an anomaly and a threat. 👇

---

## Post 8: The GRC Close-out (Project #6)

**Visual:** The Risk Register screenshot from GitHub showing the Critical risk ratings.

**The Text:**
Finding the vulnerability is one thing. Exploiting it is another. Fixing it is engineering.

But in SaaS, none of that matters if you can't prove to a customer or an auditor that your systems are secure.

For the final part of my portfolio, I built a complete ISO 27001:2022 implementation toolkit from scratch. 

I mapped all the technical findings I discovered (the RLS bypass, the maker-checker flaw, the JWT exposure) directly into a 24-entry Risk Register with formula-driven CIA scoring.

I built the 12-month roadmap, the 43-asset Information Asset Register, and the Article 30 GDPR ROPA. 

This is where security engineering meets the business. A startup doesn't just need secure code; they need to prove to enterprise clients that their data is safe.

So, what did this whole portfolio demonstrate?

That the security lifecycle is circular. Architecture sets the boundary. Offensive testing proves the boundary. Detection monitors the boundary. Governance documents the boundary.

I’m actively looking for my next role in Security Engineering, AppSec, or Cloud Security. If your team needs someone who understands both the code and the business risk, let’s talk. 

My full repository (code, migrations, detections, and GRC docs) is here: [Link to GitHub]

#SecurityEngineering #ISO27001 #AppSec #OpenToWork
