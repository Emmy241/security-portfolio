#!/usr/bin/env python3
"""
LendStack IOC Enrichment Tool
Parses a JSON log file, extracts failed login IPs, and enriches them.
Usage: python3 ioc-enrichment.py < path_to_log.json
"""
import sys
import json
import ipaddress
from collections import Counter

# MOCK: In a real environment, you would use the 'requests' library
# to call AbuseIPDB or VirusTotal APIs here.
def mock_threat_intel(ip):
    if ip.startswith("203.0.113."):
        return "MALICIOUS (Known Scanner)"
    return "CLEAN"

def get_ip_type(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private:
            return "Private IP (Internal)"
        if ip.is_loopback:
            return "Loopback"
        return "Public IP"
    except ValueError:
        return "Unknown/Invalid"

def main():
    failed_logins = Counter()
    
    # Read from stdin
    for line in sys.stdin:
        try:
            log = json.loads(line.strip())
            if log.get("sourcetype") == "lendstack:auth" and log.get("event") == "login.failure":
                ip = log.get("actor_ip", "unknown")
                failed_logins[ip] += 1
        except json.JSONDecodeError:
            continue
            
    print(f"{'IP ADDRESS':<18} | {'FAILS':<5} | {'TYPE':<20} | {'THREAT INTEL'}")
    print("-" * 75)
    
    for ip, count in failed_logins.most_common():
        ip_type = get_ip_type(ip)
        intel = mock_threat_intel(ip)
        print(f"{ip:<18} | {count:<5} | {ip_type:<20} | {intel}")

if __name__ == "__main__":
    main()
