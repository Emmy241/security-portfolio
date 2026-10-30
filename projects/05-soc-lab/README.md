# #5 — Enterprise SOC Simulation & Threat Detection Lab

| Field | Value |
|---|---|
| **Status** | Architecture, T1049 detection rule, PCAP forensics, and triage log complete. |
| **Role** | Independent researcher — built, attacked, and defended the lab solo. |
| **Context** | A simulated enterprise environment to test detection engineering and DFIR. |
| **Related** | [#3 (SIEM)](../03-siem-detection/) (Application logs) |

---

## TL;DR

A Security Operations Center (SOC) is only as good as its ability to detect and investigate threats across multiple data sources. Testing detection rules against real telemetry requires a lab environment where you can safely attack, break, and defend systems without worrying about production impact.

I built this lab from scratch, ingesting Windows Event Logs, Sysmon telemetry, and network data into Microsoft Sentinel and Splunk. I authored and validated detection rules for brute-force (T1110), valid-account abuse (T1078), and lateral movement (T1049), then triaged 40+ simulated alerts with structured documentation. 

Paired with forensic traffic analysis — extracting IOCs from phishing samples and spotting DNS tunnelling and beaconing in packet captures — this represents the exact detect-and-investigate loop I run for clients, built end to end on my own infrastructure.

## The Lab Architecture

The lab simulates a small corporate network with a mix of Windows and Linux endpoints, a SIEM, and an attacker box. It uses a Host-Only network (192.168.56.0/24) to isolate malicious traffic from the host machine.

### Data Sources & Telemetry
1. **Windows 11 (Sysmon):** Configured with the SwiftOnSecurity baseline. Forwards Event ID 1 (Process Creation), 3 (Network Connection), and 10 (Process Access) to the SIEM.
2. **Ubuntu Server (Auditd):** Logs execve (command execution) and connect (outbound network) syscalls.
3. **Kali Linux:** Used to simulate adversarial tactics (Nmap, Impacket, Hydra).
4. **SIEM (Splunk/Sentinel):** Aggregates the logs and runs KQL/SPL detection rules.
5. **Network (PCAP):** Packet capture running on the victim network for post-incident forensics.

## What I Built — Deliverables

### 1. Detection Engineering (/detections)
- T1049 — Lateral Movement: Detection of SMB/PsExec lateral movement using Sysmon and Windows Security logs.
- (Note: T1110 and T1078 rules were built against LendStack app logs in Project #3. These rules cover the network and endpoint layer).

### 2. Forensic Traffic Analysis (/forensics)
- DNS Tunneling Analysis: Analyzing a PCAP to identify data exfiltration over DNS. Includes the PCAP file and the analysis writeup.
- Beaconing Analysis: Identifying C2 beaconing patterns (jitter, sleep, periodic connections).

### 3. Triage & Incident Response (/evidence)
- Alert Triage Log: 40+ simulated alerts triaged, categorized as True Positive (TP), False Positive (FP), or Benign True Positive (BTP).
- Structured Documentation: Each alert includes the raw log snippet, the analyst's notes, and the escalation decision.

## Why this matters

In Project #3, I built detection rules against application logs (LendStack). In Project #1, I built the application. In this project, I built the environment to test them both against the network and endpoint layer. 

A SOC analyst doesn't just look at a dashboard; they look at a Windows Event Log, correlate it with a packet capture, and determine if a user clicked a phishing link or if an attacker is moving laterally. This lab proves I can build, attack, and defend that environment.
