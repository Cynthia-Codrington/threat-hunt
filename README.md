 # 🕵️‍♀️CorpHealth Threat Hunt Report 

**Date:** 01/17/25  
**Analyst:** Cynthia Codrington
**Affected System(s):** CH-OPS-WKS02  
**Scope / Environment:** Operations Department  
**Incident Type:** Operations Activity Review / Suspicious Automation Activity  
**Status:** Investigation Complete / Findings Summary  
**Priority / Severity:** Medium  
**Detection Methods:**  
- Microsoft Defender for Endpoint (Endpoint telemetry, Process & Network events)  
- Azure Diagnostic & Device Logs  
- DeviceFileEvents, DeviceNetworkEvents, DeviceLogonEvents, DeviceRegistryEvents  
---

 ## 🎯Executive Summary

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

 ## 🧠Scenario Overview

Following the phased deployment of **CorpHealth**, anomalous activity was identified on an operations workstation involving a privileged automation account intended strictly for non-interactive use.

Telemetry indicates execution outside approved maintenance windows, deviations from established automation baselines, and evidence of manual process activity under the privileged account.

Historical Microsoft Defender for Endpoint and device logs are being analyzed to determine scope, timeline, and whether the activity represents authorized operations or potential credential misuse.


- **Affected System:** CH-OPS-WKS02  
- **Suspicious Activity Window:** Nov 9 – Dec 13, 2025  
- **Initial Access Account:** `chadmin`  
- **Remote Session Device Name:** `对手`  
- **Remote IP:** `104.164.168.17`  
- **Internal Pivot Hosts:** `10.168.0.6`, `10.168.0.7`  

---

## 🚩Flag-by-Flag Findings

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
<img width="940" height="165" alt="image" src="https://github.com/user-attachments/assets/71bd45fb-82fb-42a3-9cf2-65908beeea50" />

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
<img width="940" height="309" alt="image" src="https://github.com/user-attachments/assets/ca4d04f3-d110-4232-86e9-068bd612753a" />

---
### Flag 3 – Beacon Destination

**Finding:** Initial connection attempt to 127.0.0.1:8080 (loopback).

**KQL Query:**
```kql
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed.ps1"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessCommandLine, RemoteIP, RemotePort
```
**Screenshot:**
<img width="940" height="121" alt="image" src="https://github.com/user-attachments/assets/634af2a2-0820-452e-b0ec-74ca944ad563" />

---
### Flag 4 – Confirm the Successful Beacon Timestamp

**Finding:** First successful outbound connection: 2025-11-25T04:14:41.281891Z
**Last successful connection:** 2025-11-30T01:03:17.6985973Z

**KQL Query:**
```kql
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed.ps1"
| where ActionType == "ConnectionSuccess"
| sort by TimeGenerated desc
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessCommandLine, RemoteIP, RemotePort
```
**Screenshot:**
<img width="940" height="141" alt="image" src="https://github.com/user-attachments/assets/56920ecd-ae71-4ef2-9cfe-50a950b175c1" />

---
### Flag 5 – Unexpected Staging Activity Detected

**Finding:** Creation of inventory_6ECFD4DF.csv in staging folder.

**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where ActionType == "FileCreated"
| where Timestamp <= datetime(2025-11-30T01:03:17.6985973Z)
| where FolderPath contains "CorpHealth"
| sort by TimeGenerated desc
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath
```
**Screenshot:**
<img width="940" height="168" alt="image" src="https://github.com/user-attachments/assets/5dff6ffb-9eec-4f2f-a9b7-02709028b597" />

---
### Flag 6 – Confirm the Staged File’s Integrity

**Finding:** SHA-256 hash: 7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8.

**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where ActionType == "FileCreated"
| where Timestamp <= datetime(2025-11-30T01:03:17.6985973Z)
| where FileName contains "inventory_6ECFD4DF.csv"
| sort by Timestamp desc
| project Timestamp, ActionType, DeviceName, FileName, FolderPath, SHA256
```
**Screenshot:**
<img width="940" height="91" alt="image" src="https://github.com/user-attachments/assets/a382f211-5186-4216-b36e-d029340556fd" />

---
### Flag 7 – Duplicate Staged Artifact

**Finding:** inventory_tmp_6ECFD4DF.csv created as intermediate artifact.

**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where Timestamp <= datetime(2025-11-30T01:03:17.6985973Z)
| where ActionType == "FileCreated"
| where FileName contains_cs "inventory"
| sort by Timestamp desc
| project Timestamp, ActionType, DeviceName, FileName, FolderPath, SHA256
```
**Screenshot:**
<img width="940" height="229" alt="image" src="https://github.com/user-attachments/assets/3a6b28eb-0ce8-44e2-a865-71390abe4794" />

---

### Flag 8 – Suspicious Registry Activity

**Finding:** Registry key created for credential harvesting simulation.

**KQL Query:**
```kql
let pivotTime = datetime(2025-11-25T04:15:02.4914978Z);
DeviceRegistryEvents
| where DeviceName == "ch-ops-wks02"
| where Timestamp between ((pivotTime - 12h) .. (pivotTime + 12h))
| where ActionType in ("RegistryKeyCreated", "RegistryValueSet")
| where InitiatingProcessCommandLine contains "powershell"
| extend Period = iff(Timestamp < pivotTime, "Before", "After")
| sort by Timestamp desc
| project Timestamp, DeviceName, Period, ActionType, RegistryKey, RegistryValueName, RegistryValueData
```
**Screenshot:**
<img width="940" height="168" alt="image" src="https://github.com/user-attachments/assets/8df7dc34-8049-426d-a0fe-a3220a6a61da" />

---
### Flag 9 – Scheduled Task Persistence

**Finding:** Scheduled task CorpHealth_A65E64 created for persistence.

**KQL Query:**
```kql
DeviceRegistryEvents
|where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (todatetime('2025-11-20T00:00:00Z') .. todatetime('2025-12-30T23:59:59Z') )
| where ActionType in ("RegistryKeyCreated", "RegistryValueSet")
|where RegistryKey contains "sch"
|project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RegistryKey, RegistryValueName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**Screenshot:**
<img width="940" height="165" alt="image" src="https://github.com/user-attachments/assets/9c6bf006-6c35-4cfd-ac79-d41407130acd" />

---
### Flag 10 – Registry-based Ephemeral Persistence

**Finding:** Run key added then deleted; value MaintenanceRunner.

**KQL Query:**
```kql
DeviceRegistryEvents
|where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (todatetime('2025-11-20T00:00:00Z') .. todatetime('2025-12-30T23:59:59Z') )
| where ActionType in ("RegistryKeyCreated", "RegistryValueSet", "RegistryKeyDeleted")
|where InitiatingProcessFileName == "powershell.exe"
|project DeviceName, InitiatingProcessAccountName, ActionType, RegistryKey, RegistryValueName, InitiatingProcessFileName, InitiatingProcessCommandLine
```
**Screenshot:**
<img width="940" height="311" alt="image" src="https://github.com/user-attachments/assets/2d7e2ff7-508e-4366-87a5-68aa28f2fe19" />

---
### Flag 11 – Privilege Escalation Event Timestamp

**Finding:** ConfigAdjust event by PowerShell at 2025-11-23T03:47:21.8529749Z.

**KQL Query:**
```kql
DeviceEvents
| where DeviceName == "ch-ops-wks02"
| where Timestamp between (datetime(2025-11-20T00:00:00Z) .. datetime(2025-12-30T23:59:59Z))
| where AdditionalFields contains "configadjust"
| sort by Timestamp desc
```
**Screenshot:**
<img width="940" height="302" alt="image" src="https://github.com/user-attachments/assets/f9efab24-2772-4021-ac67-1bb4d0305eeb" />

---
### Flag 12 – AV Exclusion Attempt

**Finding:** Attacker attempted to exclude staging folder from Windows Defender real-time scanning:
C:\ProgramData\Corp\Ops\staging
**KQL Query:**
```kql

DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where ProcessCommandLine has "ExclusionPath"
| sort by Timestamp desc
| project Timestamp, ProcessCommandLine, AccountName, FolderPath
```

**Screenshot / Output:** Attempted Defender exclusion logged.
<img width="940" height="114" alt="image" src="https://github.com/user-attachments/assets/5fc688b0-fced-49f9-a148-1f693786550c" />

---

### Flag 13 – PowerShell Encoded Command Execution

**Finding:** Encoded PowerShell executed to write diagnostic artifact to CorpHealth folder.
**KQL Query:**
```kql

DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where Timestamp between (datetime(2025-11-22T00:00:00Z) .. datetime(2025-12-30T23:59:59Z))
| where ProcessCommandLine has "powershell"
| where ProcessCommandLine has_any ("-EncodedCommand", "-enc")
| extend Encoded = extract(@"(?i)-(?:encodedcommand|enc)\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| where isnotempty(Encoded)
| extend Decoded = base64_decode_tostring(Encoded)
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine, Decoded
| sort by Timestamp desc
```

**Screenshot / Output:** Decoded command confirms malicious script execution.
<img width="940" height="131" alt="image" src="https://github.com/user-attachments/assets/72879210-e179-44af-a239-ac33b9b76656" />

---

### Flag 14 – Privilege Token Modification

**Finding:** Process with InitiatingProcessId 4888 modified token privileges to escalate access.
**KQL Query:**
```kql

DeviceEvents
| where DeviceName == "ch-ops-wks02"
| where Timestamp between (datetime(2025-11-23) .. datetime(2025-12-01))
| where AdditionalFields has_all ("tokenChangeDescription", "Privileges were added")
| where InitiatingProcessCommandLine contains ".ps1"
| sort by Timestamp desc
| project Timestamp, ActionType, AccountName, AdditionalFields, InitiatingProcessCommandLine, InitiatingProcessId
```

**Screenshot / Output:** Token privilege modification event logged.
<img width="940" height="171" alt="image" src="https://github.com/user-attachments/assets/14a76e57-7a31-4723-92da-7a0fcb2a87a8" />

---

### Flag 15 – Token User SID

**Finding:** Modified token belonged to S-1-5-21-1605642021-30596605-784192815-1000.

KQL Query: Same as Flag 14, inspect AdditionalFields.
**Screenshot / Output:** Confirms targeted user token affected.
<img width="940" height="135" alt="image" src="https://github.com/user-attachments/assets/03420449-5a55-4960-a8f2-3a2061d889ad" />

---

### Flag 16 – Ingress Tool Transfer (External Tunnel)

**Finding:** File revshell.exe written to disk after download via external tunnel (ngrok).
**KQL Query:**
```kql

DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where ActionType in ("FileCreated", "FileModified")
| where FileName endswith ".exe"
| where InitiatingProcessCommandLine contains "curl.exe"
| sort by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
```

**Screenshot / Output:** Confirms staged reverse shell.
<img width="940" height="64" alt="image" src="https://github.com/user-attachments/assets/fd6ed347-b0cc-4152-8256-cbc6a10eecd3" />
<img width="940" height="309" alt="image" src="https://github.com/user-attachments/assets/4d2e1686-ad15-4f64-bc09-2a22ee1a42ad" />

---

## Flag 17 – External Download Source

**Finding:** URL used to retrieve file: unresuscitating-donnette-smothery.ngrok-free.dev
**KQL Query:**
```kql

DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessFileName in~ ("curl.exe", "powershell.exe", "pwsh.exe")
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168." and RemoteIP !startswith "172."
| project TimeGenerated, InitiatingProcessFileName, RemoteIP, RemotePort, Protocol, InitiatingProcessAccountName, RemoteUrl
| order by TimeGenerated desc
```

*Screenshot / Output:* Download URL confirmed.
<img width="940" height="230" alt="image" src="https://github.com/user-attachments/assets/71e5aa73-e265-4571-9c33-96e78b560a8e" />

---
### Flag 18 – Execution of Staged Unsigned Binary

**Finding:** Binary executed by explorer.exe from user profile directory.
**KQL Query:**
```kql

DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where FileName endswith ".exe"
| where FolderPath has "C:\\Users"
| sort by Timestamp desc
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessAccountName, ProcessCommandLine
```

**Screenshot / Output:** Execution confirmed.
<img width="940" height="141" alt="image" src="https://github.com/user-attachments/assets/22150769-51c6-4d89-914f-ae55dd795b1e" />

---

### Flag 19 – External IP Contacted by Executable

**Finding:** Outbound connection attempted to 13.228.171.119:11746.
**KQL Query:**
```kql

DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where ActionType in~ ("ConnectionFailed", "ConnectionAttempt")
| where RemotePort == 11746
| sort by Timestamp desc
| project Timestamp, DeviceName, ActionType, RemotePort, RemoteIP, InitiatingProcessFileName
```

**Screenshot / Output:** External C2 contact logged.
<img width="940" height="184" alt="image" src="https://github.com/user-attachments/assets/4a451ef2-de23-45b6-bda2-883e49c6110f" />

---
### Flag 20 – Persistence via Startup Folder

**Finding:** revshell.exe copied to:
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe

**KQL Query:**
```kql

DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where Timestamp between (datetime(2025-11-15) .. datetime(2025-12-15))
| where FileName == "revshell.exe"
| where FolderPath contains "C:\\ProgramData\\"
| sort by Timestamp desc
| project Timestamp, DeviceName, FolderPath, FileName
```

**Screenshot / Output:** Startup persistence observed.
<img width="940" height="230" alt="image" src="https://github.com/user-attachments/assets/3da4f36e-b3b5-434d-9c3a-e4f8fbb03bfc" />

---

### Flag 21 – Remote Session Source Device

**Finding:** Remote session device: 对手.

**KQL Query:**
```kql:

DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where Timestamp between (datetime(2025-11-15) .. datetime(2025-12-15))
| where InitiatingProcessRemoteSessionDeviceName != ""
| distinct InitiatingProcessRemoteSessionDeviceName
```

**Screenshot / Output:** Remote device identified.
<img width="745" height="227" alt="image" src="https://github.com/user-attachments/assets/33564ad5-9693-40dd-812b-b22ec225d6ba" />

---

## Flag 22 – Remote Session IP Address

**Finding:** Source IP of remote session: 100.64.100.6
**KQL Query:**
```kql

DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where Timestamp between (datetime(2025-11-15) .. datetime(2025-12-15))
| where InitiatingProcessRemoteSessionDeviceName == "对手"
| sort by Timestamp desc
| project Timestamp, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP
```

**Screenshot / Output:** Confirms network origin.
<img width="925" height="484" alt="image" src="https://github.com/user-attachments/assets/499f3961-72a0-4f46-a7c1-034eb60f0a9e" />

---

### Flag 23 – Internal Pivot Host

**Finding:** Internal pivot IPs: 10.168.0.7 and 10.168.0.6
**KQL Query:**
```kql

DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where Timestamp between (datetime(2025-11-15) .. datetime(2025-12-15))
| where InitiatingProcessRemoteSessionDeviceName == "对手"
| where not(ipv4_is_in_range(InitiatingProcessRemoteSessionIP, "100.64.0.0/10"))
| distinct InitiatingProcessRemoteSessionIP
```

Screenshot / Output: Internal pivot hosts confirmed.
<img width="747" height="245" alt="image" src="https://github.com/user-attachments/assets/63ffea31-ca20-4fa1-a746-d042e122b3e9" />

---
### Flag 24 – First Suspicious Logon

**Finding:** Earliest suspicious logon: 2025-11-23T03:08:31.1849379Z, RemoteIP: 104.164.168.17
**KQL Query:**
```kql

DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| where RemoteDeviceName == "对手"
| where LogonType in~ ("RemoteInteractive", "Network")
| sort by Timestamp asc
| project Timestamp, DeviceName, RemoteDeviceName, AccountName, LogonType, InitiatingProcessFileName
```

**Screenshot / Output:** Initial logon identified.
<img width="940" height="263" alt="image" src="https://github.com/user-attachments/assets/2cf9a1e6-952e-4cb8-8612-10a76dad5cbf" />

---

### Flag 25 – IP Address of First Logon

**Finding:** IP associated: 104.164.168.17
KQL Query: Same as Flag 24, project RemoteIP.
**Screenshot / Output:** Confirms initial network entry point.
<img width="838" height="436" alt="image" src="https://github.com/user-attachments/assets/3a42638e-5532-4e36-bfd0-f95c57d00def" />

---

### Flag 26 – Account Used in First Logon

**Finding:** Account: chadmin
**KQL Query:**
```kql

DeviceLogonEvents
| where Timestamp between (datetime(2025-11-01T03:08:31.1849379Z) .. datetime(2025-11-23T03:08:31.1849379Z))
| where RemoteIP == "104.164.168.17"
| project Timestamp, AccountName, RemoteIP, ActionType
```

Screenshot / Output: Confirms compromised account.
<img width="940" height="229" alt="image" src="https://github.com/user-attachments/assets/a55024e8-5c27-4d78-ae69-c98972bb8d9e" />

---
### Flag 27 – Attacker Geographic Region

**Finding:** Attacker originates from Vietnam
**KQL Query:**
```kql

DeviceLogonEvents
| where TimeGenerated between (datetime('2025-11-01T03:08:31.1849379Z') .. datetime('2025-11-23T03:08:31.1849379Z'))
| where RemoteIP == "104.164.168.17"
| extend GeoInfo = geo_info_from_ip_address("104.164.168.17")
| project DeviceName, AccountName, RemoteIP, GeoInfo, LogonType
```

**Screenshot / Output:** Geolocation enrichment confirms region.
<img width="940" height="217" alt="image" src="https://github.com/user-attachments/assets/169d04c2-27b4-4c8c-9d70-f7a550f2785d" />

---

### Flag 28 – First Process Launched After Logon

**Finding:** Explorer.exe
**KQL Query:**
```kql

DeviceProcessEvents
| where Timestamp between (datetime(2025-11-23T03:08:31.1849379Z) .. datetime(2025-11-24T03:08:31.1849379Z))
| where AccountName == "chadmin"
| where InitiatingProcessAccountName == "chadmin"
| sort by Timestamp asc
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName, InitiatingProcessAccountName, InitiatingProcessFileName
```

**Screenshot / Output:** First action post-logon verified.
<img width="759" height="384" alt="image" src="https://github.com/user-attachments/assets/36a71778-3a47-4ca5-8138-dd48c82df5dc" />

---
### Flag 29 – First File Accessed

**Finding:** CH-OPS-WKS02 user-pass.txt
**KQL Query:**
```kql

DeviceProcessEvents
| where AccountName == "chadmin"
| where InitiatingProcessFolderPath has "explorer.exe"
| where ProcessCommandLine contains "chadmin"
| distinct ProcessCommandLine
```

Screenshot / Output: First file accessed identified.
<img width="940" height="104" alt="image" src="https://github.com/user-attachments/assets/12c28cb9-9880-436e-b1c1-6e2ccbd993c7" />

---

### Flag 30 – Next Action After Reading File

**Finding**: Ran ipconfig.exe for reconnaissance.
**KQL Query:**
```kql

DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where AccountName == "chadmin"
| where Timestamp > datetime(2025-11-23T03:11:00.6981995Z)
| sort by Timestamp asc
| take 2
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, ProcessCommandLine, AccountName
```

**Screenshot / Output:** Confirms post-file reconnaissance activity.
<img width="940" height="334" alt="image" src="https://github.com/user-attachments/assets/3c6fca21-aa2b-4e6d-9e2a-79bf4d6654ad" />

---
### Flag 31 – Identify the Next Account Accessed After Recon

**Finding:** Following the attacker’s initial reconnaissance, the first successful logon to a user account was detected. The attacker accessed the ops.maintenance account immediately after the enumeration activity, indicating a shift from information gathering to account-level interaction and possible privilege escalation.

**KQL Query:**
```kql

// Timestamp reference point set to end of enumeration window
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| where Timestamp > datetime(2025-11-23T03:11:00.6981995Z)
| where ActionType == "LogonSuccess"
| sort by Timestamp asc
| take 1
| project Timestamp,
          DeviceName,
          AccountName,
          LogonType,
          RemoteIP,
          InitiatingProcessFileName
```
**Screenshot:** This confirms the attacker moved from reconnaissance to active account access by using the ops.maintenance account.
<img width="940" height="264" alt="image" src="https://github.com/user-attachments/assets/1d4ae3f1-87c5-40eb-8f64-e850294392dd" />

---
## 🔍 Timeline of Events
| Time (UTC)             | Stage                              | Event / Action                                            | Details                                                                       |
| ---------------------- | ---------------------------------- | --------------------------------------------------------- | ----------------------------------------------------------------------------- |
| 2025-11-23T03:08       | Initial Access                     | Suspicious logon                                          | Account: `chadmin`, RemoteIP: 104.164.168.17, RemoteDevice: 对手                |
| 2025-11-23T03:08–03:11 | Recon                              | First process                                             | `explorer.exe` launched                                                       |
| 2025-11-23T03:11       | File Access                        | First file read                                           | `user-pass.txt`                                                               |
| 2025-11-23T03:11+      | Recon                              | Local enumeration                                         | `ipconfig.exe` executed; account accessed: `ops.maintenance`                  |
| 2025-11-23T03:46       | C2 Attempt                         | Outbound beacon                                           | `MaintenanceRunner_Distributed.ps1` attempted connection (loopback initially) |
| 2025-11-25T04:14       | C2 Success                         | Successful beacon                                         | Remote endpoint reached                                                       |
| 2025-11-25T04:15       | Staging                            | File staging                                              | `inventory_6ECFD4DF.csv` created; duplicate working file in Temp              |
| 2025-11-25T04:15–04:24 | Persistence & Privilege Escalation | Registry modifications, scheduled task, ephemeral Run key | PowerShell scripts executed; token privileges modified                        |
| 2025-12-02T12:56       | Ingress Tool Transfer              | Download `revshell.exe`                                   | From ngrok tunnel via `curl.exe`                                              |
| 2025-12-02T12:57       | Execution                          | Run `revshell.exe`                                        | Executed by `explorer.exe` from user profile                                  |
| 2025-12-02T12:57+      | C2 Communication                   | External IP contact                                       | 13.228.171.119, port 11746                                                    |
| Nov–Dec window         | Persistence                        | Startup folder placement                                  | `revshell.exe` copied to Startup directory                                    |
| Nov–Dec window         | Lateral / Pivot                    | Remote session via internal IPs                           | 10.168.0.7, 10.168.0.6, remote device: 对手, internal hops identified           |

---
## 🧩 MITRE ATT&CK Mapping

| Phase                | Technique                     | Tactic               | Related Flags | Notes                                                   |
| -------------------- | ----------------------------- | -------------------- | ------------- | ------------------------------------------------------- |
| Initial Access       | T1078 – Valid Accounts        | Initial Access       | 24–26         | Compromised chadmin account                             |
| Execution            | T1059.001 – PowerShell        | Execution            | 13, 14        | Encoded PowerShell commands executed                    |
| Persistence          | T1547.001 – Startup Items     | Persistence          | 20            | `revshell.exe` placed in Startup folder                 |
| Privilege Escalation | T1068 – Exploitation          | Privilege Escalation | 11, 14, 15    | ConfigAdjust token modification                         |
| Defense Evasion      | T1089 – AV/Defender Bypass    | Defense Evasion      | 12            | Attempted exclusion from Defender                       |
| Lateral Movement     | T1021.001 – Remote Services   | Lateral Movement     | 21–23         | Remote session from Vietnam IP to internal hosts        |
| Command & Control    | T1105 – Ingress Tool Transfer | C2                   | 16, 17, 19    | Reverse shell binary download via ngrok and external IP |
| Discovery            | T1082 – System Information    | Discovery            | 30            | Running `ipconfig.exe` post-file access                 |
| Credential Access    | T1003 – Credential Dumping    | Credential Access    | 29            | Accessed `user-pass.txt`                                |

---

## ⚠️Conclusion

CH-OPS-WKS02 showed unauthorized use of a privileged account, file staging, registry tampering, and reverse shell deployment — indicating deliberate intrusion; remediate, monitor, and enforce least-privilege policies.

---

## 🧠Lessons Learned 

- Privileged automation accounts must be restricted to non-interactive use only.  
- Scheduled tasks and scripts should be monitored for anomalous execution patterns.  
- Endpoint telemetry is critical to detect early lateral movement and staging activity.  
- Network egress to unknown IPs should trigger immediate alerting.  
- File integrity monitoring can reveal staged artifacts and unauthorized modifications.  
- Registry and startup persistence attempts are strong indicators of post-compromise activity.  

---
## 🛡 After-Action Recommendations

1. Reset compromised accounts (chadmin) and enforce MFA.

2. Harden endpoint defenses: block script-based AV exclusions, monitor PowerShell commands.

3. Segment networks to limit lateral movement.

4. Remove malicious artifacts (revshell.exe, staging files).

5. Block malicious IPs (104.164.168.17, 13.228.171.119).

6. Conduct red/blue team review and update response playbooks.
