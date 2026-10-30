# T1049 — Lateral Movement (SMB / PsExec)

| Field | Value |
|---|---|
| **Rule ID** | SOC-ENDPOINT-001 |
| **MITRE** | T1049 — System Network Connections Discovery |
| **Severity** | High |
| **Data Source** | Sysmon (Event ID 1, 3, 11) + Windows Security Event 4624 |
| **Platform** | Splunk SPL / Microsoft Sentinel KQL |
| **Status** | Deployed, tuned (v2) |

## Rule Logic

Detect lateral movement via SMB by correlating three signals within a 10-minute window on a destination host:
1. Windows Security Event 4624 (Logon Type 3 - Network) from a workstation IP.
2. Sysmon Event 1 (Process Creation) showing services.exe spawning PSEXESVC.exe.
3. Sysmon Event 11 (FileCreate) creating C:\Windows\PSEXESVC.exe.

This is the exact signature of PsExec and Impacket's psexec.py tool.

### Splunk SPL
index=windows (EventCode=4624 Logon_Type=3) OR (EventCode=1 Image="*\\PSEXESVC.exe") OR (EventCode=11 TargetFilename="*\\PSEXESVC.exe")
| eval signal=case(EventCode=4624, "network_logon", EventCode=1, "psexesvc_proc", EventCode=11, "psexesvc_file")
| stats values(signal) as signals dc(signal) as signal_count by ComputerName, Source_Network_Address
| where signal_count >= 2
| table ComputerName, Source_Network_Address, signals

### Microsoft Sentinel KQL
let window = 10m;
SecurityEvent
| where EventID == 4624 and LogonType == 3
| project Computer, IpAddress, TimeGenerated, Signal = "network_logon"
| join kind=inner (
    SysmonEvent
    | where EventID == 1 and Image endswith "\\PSEXESVC.exe"
    | project Computer, TimeGenerated, Signal = "psexesvc_proc"
) on Computer
| where TimeGenerated between (TimeGenerated - window .. TimeGenerated + window)
| summarize Signals = make_set(Signal), Count = dcount(Signal) by Computer, IpAddress
| where Count >= 2

## False Positives
- Legitimate IT administration: Help-desk technicians using PsExec to troubleshoot. Mitigation: exclude known admin jump hosts by hostname/IP.
- SCCM / MDM tools: Some endpoint management tools use SMB and spawn temporary services. Mitigation: allowlist the specific service binary names.

## Verification
On Kali Linux, execute:
impacket-psexec Administrator:Password123!@192.168.56.101
Expect three correlated events within seconds on 192.168.56.101: 4624 (network logon from Kali), Sysmon 1 (PSEXESVC spawned), Sysmon 11 (PSEXESVC.exe created).
