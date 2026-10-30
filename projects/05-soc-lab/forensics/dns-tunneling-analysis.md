# Forensic Analysis: DNS Tunneling (C2 Exfiltration)

| Field | Value |
|---|---|
| **Artifact** | dns-exfil.pcap |
| **Analyst** | Security Lead |
| **Tools** | Wireshark, tshark, Python (scapy) |
| **Verdict** | Confirmed Data Exfiltration |

## 1. Executive Summary

A packet capture (PCAP) was taken from the DMZ firewall during a suspected incident. Analysis revealed a compromised Linux server (192.168.56.102) communicating with an attacker-controlled domain (exfil.evil-c2.com). The attacker bypassed traditional DLP and firewall blocks by tunneling data out through DNS queries (Port 53 UDP), which is almost always allowed outbound.

## 2. Initial Triage (Wireshark Statistics)

- **Protocol Hierarchy:** 94% of the traffic is DNS.
- **DNS Stats:** 
  - Total DNS Queries: 14,532 over 10 minutes.
  - NXDOMAIN Responses: 14,530. (The attacker's authoritative DNS server is returning NXDOMAIN because it only needs to read the request; it doesn't need to respond with an A record).
- **Top Talkers:** 192.168.56.102 generating traffic to 8.8.8.8 (Google DNS) resolving *.exfil.evil-c2.com.

## 3. Packet-Level Analysis (IOCs)

Filtering for the malicious domain reveals the exfiltration technique:

tshark -r dns-exfil.pcap -Y "dns.qry.name contains evil-c2.com" -T fields -e frame.time -e ip.src -e dns.qry.name

**Sample Output:**
2026-10-30 14:00:01  192.168.56.102  aGVsbG8gd29ybGQ.exfil.evil-c2.com
2026-10-30 14:00:02  192.168.56.102  c2VjcmV0IGRhdGE.exfil.evil-c2.com
2026-10-30 14:00:03  192.168.56.102  aW52b2ljZSBudW1iZXM.exfil.evil-c2.com

### Decoding the Payload

The subdomains are Base64 encoded. Decoding them reveals:
- aGVsbG8gd29ybGQ -> hello world
- c2VjcmV0IGRhdGE -> secret data
- aW52b2ljZSBudW1iZXM -> invoice numbers

The attacker is chunking a database dump into Base64 strings and prepending them to the C2 domain. 

## 4. Detection & Mitigation

- **Rule:** Detect DNS queries where the subdomain length is > 50 characters, or entropy is high, or the volume of queries to a single domain exceeds 100/min.
- **Mitigation:** 
  1. Block *.evil-c2.com at the DNS sinkhole.
  2. Isolate 192.168.56.102 from the network.
  3. Force internal DNS to use a proxy that logs all queries (like Cisco Umbrella or Pi-hole).
