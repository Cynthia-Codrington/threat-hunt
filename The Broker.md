<img width="683" height="1024" alt="image" src="https://github.com/user-attachments/assets/ea894e95-708d-4eeb-beef-0ebed475c824" />

 
 # 🕵️‍♀️The Broker Threat Hunt Report 

**Date:** 01/15/26 
**Analyst:** Cynthia Codrington
**Affected System(s):** AS-PC1 > AS-PC2 > AS-SRV 
**Scope / Environment:** Operations Department  
**Incident Type:** Malicious Endpoint Compromise 
**Status:** Investigation Complete / Findings Summary  
**Priority / Severity:** High 
**Detection Methods:**  
- Microsoft Defender for Endpoint (Endpoint telemetry, Process & Network events)  
- Azure Diagnostic & Device Logs  
---

 ## 🎯Executive Summary

On January 14, 2026, a malicious resume file executed by Sophie Turner on AS-PC1 triggered a multi-stage intrusion. The attacker established C2 with cdn.cloud-endpoint.net, harvested credentials, deployed AnyDesk for persistent access, and later pivoted via RDP to access sensitive financial data (BACS_Payments_Dec2025.ods), staging it in Shares.7z. Logs were cleared and in-memory credential theft tools executed to evade detection, reflecting a hands-on-keyboard intrusion targeting financial records.

**Key Findings:**
- Initial infection via user executing Daniel_Richardson_CV.pdf.exe on AS-PC1.
- Outbound communication to attacker C2 domain cdn.cloud-endpoint.net.
- SAM and SYSTEM registry hives accessed; SharpChrome injected into notepad.exe.
- AnyDesk installed with unattended password intrud3r!; svc_backup account created; scheduled task MicrosoftEdgeUpdateCheck deployed.
- Lateral pivot via RDP from AS-PC1 > AS-PC2 > AS-SRV; failed WMIC and PsExec attempts.
- Sensitive financial document BACS_Payments_Dec2025.ods accessed and staged into archive Shares.7z.
- Security and Application logs cleared; malware disguised as legitimate binaries; memory-based tooling loaded.
- MITRE ATT&CK techniques identified include: **T1204, T1071, T1003.002, T1555, T1219, T1136.001, T1053.005, T1047, T1569.002, T1021.001, T1078.003, T1560.001, T1036.005, T1070.001, T1620**

---

 ## 🧠Scenario Overview

The compromise began when a user executed a malicious resume executable, which connected to attacker-controlled infrastructure and deployed persistence tools. The attacker performed reconnaissance, harvested credentials from SAM and SYSTEM hives, and escalated privileges to move laterally.

AnyDesk was installed for persistent remote access, and after failed attempts with WMIC and PsExec, the attacker successfully pivoted via RDP. From the secondary workstation, sensitive financial documents were accessed and staged into a compressed archive.

Before leaving, the attacker cleared logs and loaded credential-harvesting tools in memory to evade detection.


- **Affected System:** AS-PC1 
- **Suspicious Activity Window:** 2026-01-14T23:31 → 2026-01-16T11:09
- **Initial Access Account:** Sophie.Turner
- **Initial Vector:** Daniel_Richardson_CV.pdf.exe  
- **Remote Session Host:** AS-PC1  
- **Remote IP:** `168.63.129.16`  
- **Pivot Hosts:** `AS-PC1 > AS-PC2 > AS-SRV`
- **Remote Access Tool:** AnyDesk
- **Exfiltrated Data:** 'BACS_Payments_Dec2025.ods → Shares.7z' 

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
| 2026-01-14T23:31      | Initial Access                     | Initial alert                                         | MDE detected suspicious file execution
|
| 2026-01-14T23:48 | Initial Access                              | Inbound connection                                            | Remote IP 168.63.129.16:80 connected to local 10.1.0.154:54554                                                      |
| 2026-01-14T23:47       | Command & Control                       | Outbound C2 connection                               | daniel_richardson_cv.pdf.exe connected to cdn.cloud-endpoint.net                                                              |
| 2026-01-15T00:11     | Persistence                             | Remote access tool installed                                       | AnyDesk installed, unattended access password intrud3r! configured                  |
| 2026-01-15T05:09      | Persistence                        | Suspicious child process                                         | notepad.exe spawned by malware |
| 2026-01-15T04:55      | Data Access                        | Sensitive document access                                        | BACS_Payments_Dec2025.ods opened from host as-pc2                                                     |
| 2026-01-15T04:59      | Data Access                           | Data archived                                            |Sensitive files saved into Shares.7z              |
| 2026-01-15T05:00 | Defense Evasion | Memory-based credential theft| SharpChrome loaded in notepad.exe memory                      |
| 2026-01-15T05:10       | Defense Evasion             | Reflective code loading                                  | Malicious assembly loaded in memory                                             |
| 2026-01-15T05:15       | Discovery                         | Registry & group enumeration                                      | SAM/SYSTEM queried; Administrators group enumerated                                  |
| 2026-01-15T06:00      | Lateral Movement                   | Remote execution attempts                                       | WMIC and PsExec failed on host as-pc2                                                 |
| 2026-01-15T06:10        |Lateral Movement                      | Successful pivot                                 | RDP session from as-pc1 → as-pc2 → as-srv using david.mitchell                                  |
|2026-01-15T06:30        | Persistence                    | Scheduled task created                          | MicrosoftEdgeUpdateCheck runs RuntimeBroker.exe           |
| 2026-01-16T11:09      | Privilege Escalation                    | Admin account added                         | svc_backup added as Administrator           |

---
## 🧩 MITRE ATT&CK Mapping

| Phase                | Technique                     | Related Flags  | Notes                                                   |
| -------------------- | ----------------------------- | -------------- | ------------------------------------------------------- |
| Initial Access       | T1204 – User Execution        |  1-3           | User executed malicious resume file                     |
| Command & Control    | T1071 – Application Protocol  |  4-5           | Malware connected to attacker C2 domain                 |
| Persistence          | T1219 – Remote Access         |  6-8           | AnyDesk installed for persistent access                 |
| Persistence          | T1136.001 – Account Creation  |  9-10          | svc_backup account created                              |
| Persistence          | T1053.005 – Scheduled Task    |  11-12         | Scheduled task maintained persistence                   |
| Credential Access    | T1003.002 – SAM Dumping       |  13-14         | SAM credentials accessed and staged                     |
| Credential Access    | T1555 – Credential Theft      |  15-16         | SharpChrome harvested browser credentials               |
| Defense Evasion      | T1036.005 – File Masquerading |  12,17         | Malware disguised as legitimate binaries                |
| Defense Evasion      | T1070.001 – Log Clearing      |  18            | Security and Application logs cleared                   |
| Defense Evasion      | T1620 – Reflective Loading    |  19            | Malicious code loaded in memory                         |
| Discovery            | T1012 – Registry Query        |  13            | Registry queried for system data                        |
| Discovery            | T1069.002 – Group Enumeration |  20            | Administrator group enumerated                          |
| Lateral Movement     | T1047 – WMI Execution         |  21            | WMIC attempted remote execution                         |
| Lateral Movement     | T1569.002 – PsExec Execution  |  22            | PsExec attempt observed                                 |
| Lateral Movement     | T1021.001 – RDP Movement      |  23            | RDP used to pivot between hosts                         |
| Exfiltration         | T1560.001 – Data Archiving    |  24-25         | Data archived into Shares.7z                            |

---

## ⚠️Conclusion

The investigation confirmed a multi-stage intrusion initiated through social engineering, where malware disguised as a resume was executed by a recruitment staff member. The attacker established persistence using a legitimate remote access tool, harvested credentials, and moved laterally across systems.

Sensitive financial data was accessed and staged for potential exfiltration, indicating a probable data theft objective. Despite attempts to evade detection through memory-based tools and log clearing, endpoint telemetry allowed investigators to reconstruct the full attack chain. 

---

## 🧠Lessons Learned 

- Executable files disguised as documents remain a highly effective phishing technique.
- Remote administration tools can easily be abused for persistence.
- Credential harvesting enables rapid lateral movement within enterprise environments.
- Monitoring of administrative tools and log clearing activity is critical for early detection.


---
## 🛡 After-Action Recommendations

1. Implement application control policies: Block execution of unknown binaries from user directories.

2. Restrict remote administration tools: Block unauthorized use of tools such as AnyDesk.

3. Enforce Multi-Factor Authentication: Required for RDP and privileged accounts.

4. Improve endpoint detection rules
Monitor for:

- certutil downloads

- scheduled task creation

- event log clearing

- reflective .NET assembly loading

5. Conduct security awareness training: Focus on phishing attempts targeting HR and recruitment teams.
