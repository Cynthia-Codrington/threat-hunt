# CorpHealth Threat Hunt Report 

**Investigation Date:** November–December 2025  
**Analyst:** Cynthia Codrington  

---

## Executive Summary

During the investigation of **CH-OPS-WKS02**, suspicious activity was observed involving **privilege escalation, lateral movement, persistence, and external exfiltration attempts**. The attacker leveraged a combination of PowerShell, remote sessions, and staged binaries to maintain control.

**Key Findings:**

- Initial access via `chadmin` account from Vietnam IP `104.164.168.17`.
- Execution of encoded PowerShell commands for staging and persistence.
- Creation of staging files (`inventory_6ECFD4DF.csv`) and duplicate artifacts.
- Reverse shell delivered via ngrok tunnel (`revshell.exe`).
- Persistence established via Startup folder.
- Lateral pivot to internal IPs: `10.168.0.6` and `10.168.0.7`.
- MITRE ATT&CK techniques identified include: **T1078, T1059, T1086, T1105, T1547**.

---

## Scenario Overview

- **Affected System:** CH-OPS-WKS02  
- **Suspicious Activity Window:** Nov 9 – Dec 13, 2025  
- **Initial Access Account:** `chadmin`  
- **Remote Session Device Name:** `对手`  
- **Remote IP:** `104.164.168.17`  
- **Internal Pivot Hosts:** `10.168.0.6`, `10.168.0.7`  

---

## Flag-by-Flag Findings

### Flag 1 – Unique Maintenance File
**Finding:** Discovery of a suspicious maintenance script.

**KQL Query:**  
```kql
DeviceFileEvents
| where DeviceName contains "ch-ops-wks02"
| where FileName contains "maintenance"
| order by TimeGenerated desc
| project TimeGenerated, InitiatingProcessCreationTime, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, RequestAccountName, InitiatingProcessRemoteSessionIP
```

**Artifact:** MaintenanceRunner_Distributed.ps1

**Screenshot:**

---
### Flag 2 – Outbound Beacon Indicator

**Finding:** Script initiated outbound connection on 2025-11-23T03:46:08.400686Z.

**KQL Query:**
```kql
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine contains "MaintenanceRunner_Distributed.ps1"
```
**Screenshot:**

### Flag 3 – Beacon Destination

**Finding:** Initial connection attempt to 127.0.0.1:8080 (loopback).

KQL Query:

