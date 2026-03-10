<img width="683" height="1024" alt="image" src="https://github.com/user-attachments/assets/ea894e95-708d-4eeb-beef-0ebed475c824" />

 
 # 🕵️‍♀️The Broker Threat Hunt Report 

**Date:** 01/15/26<br>
**Analyst:** Cynthia Codrington<br>
**Affected System(s):** AS-PC1 > AS-PC2 > AS-SRV <br>
**Scope / Environment:** Operations Department <br>
**Incident Type:** Malicious Endpoint Compromise <br>
**Status:** Investigation Complete / Findings Summary<br> 
**Priority / Severity:** High<br>
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

### Flag 1 – Initial Vector
**Finding:** User executed malicious resume file to initiate compromise.

**KQL Query:**  
```kql
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where InitiatingProcessAccountName == "sophie.turner"
| where FileName == "Daniel_Richardson_CV.pdf.exe"
| order by Timestamp desc
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName
```

**Artifact:** Daniel_Richardson_CV.pdf.exe

**Screenshot:**
<img width="595" height="766" alt="image" src="https://github.com/user-attachments/assets/f52a4de5-7370-46ae-8f4d-c92aeb71bd5c" />


---
### Flag 2 – Payload hash

**Finding:** SHA256 of initial payload. <br>
SHA256: 48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5

**KQL Query:**
```kql
DeviceFileEvents
| where FileName == "Daniel_Richardson_CV.pdf.exe"
| project Timestamp, DeviceName, FileName, SHA256
```
---
### Flag 3 – User Interaction

**Finding:** How payload was initially launched.

**KQL Query:**
```kql
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where FileName == "Daniel_Richardson_CV.pdf.exe"
| project Timestamp, FileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine
```
**Artifact:** Parent process Explorer.EXE
---
### Flag 4 – Suspicious Child Process

**Finding:** First successful outbound connection: 2025-11-25T04:14:41.281891Z
**Last successful connection:** 2025-11-30T01:03:17.6985973Z

**KQL Query:**
```kql
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where InitiatingProcessAccountName == "sophie.turner"
| where InitiatingProcessParentFileName contains ".exe"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```
**Artifact:** notepad.exe

---
### Flag 5 – Process Arguments

**Finding:** Child process executed with unusual arguments.

---
### Flag 6 – C2 Domain

**Finding:** Outbound command-and-control connections observed.

**KQL Query:**
```kql
DeviceNetworkEvents
| where DeviceName contains "as-pc1"
| where InitiatingProcessFileName == "Daniel_Richardson_CV.pdf.exe"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```
**Screenshot:**
<img width="940" height="91" alt="image" src="https://github.com/user-attachments/assets/a382f211-5186-4216-b36e-d029340556fd" />

---
### Flag 7 – C2 Process

**Finding:** Process responsible for C2 traffic
**Artifact:** notepad.exe

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

### Flag 8 – Staging Infrastructure

**Finding:** External payload hosted for staging.

**KQL Query:**
```kql
DeviceNetworkEvents
| where RemoteIP == "104.21.30.237"
| project TimeGenerated, DeviceName, RemoteUrl, InitiatingProcessFileName
```
**Screenshot:**
<img width="940" height="168" alt="image" src="https://github.com/user-attachments/assets/8df7dc34-8049-426d-a0fe-a3220a6a61da" />

---
### Flag 9 – Registry Targets

**Finding:** Targeted local credential stores.

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
### Flag 10 – Local Staging

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
### Flag 11 – User Context

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
### Flag 12 – Network Enumeration

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

### Flag 13 – Local Admins

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

### Flag 14 – Remote Tool

**Finding:** AnyDesk installed for persistence.
**KQL Query:**
```kql

DeviceFileEvents
| where FileName in ("AnyDesk.exe","AnyDesk64.exe")
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| sort by DeviceName asc, TimeGenerated desc
```

**Screenshot / Output:** Token privilege modification event logged.
<img width="940" height="171" alt="image" src="https://github.com/user-attachments/assets/14a76e57-7a31-4723-92da-7a0fcb2a87a8" />

---
### Flag 16 – Failed Execution

**Finding:** Attempted lateral movement failed.
**KQL Query:**
```kql

DeviceProcessEvents
| where DeviceName in ("as-pc1","as-pc2")
| where ProcessCommandLine has_any ("\\\\","/node:","-ComputerName","/S ")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| sort by TimeGenerated asc
```

**Screenshot / Output:** Confirms staged reverse shell.
<img width="940" height="64" alt="image" src="https://github.com/user-attachments/assets/fd6ed347-b0cc-4152-8256-cbc6a10eecd3" />
<img width="940" height="309" alt="image" src="https://github.com/user-attachments/assets/4d2e1686-ad15-4f64-bc09-2a22ee1a42ad" />

---

## Flag 17 – Successful Pivot

**Finding:** Successful lateral movement.
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
### Flag 18 – Scheduled Persistence

**Finding:** Scheduled task added for persistence.
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

### Flag 19 – Backdoor Account

**Finding:** New local account created for access..
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
### Flag 20 – Sensitive Document

**Finding:** Financial data accessed and staged.

**KQL Query:**
```kql

DeviceFileEvents
| where DeviceName == "as-srv"
| where ActionType in ("FileRead","FileModified","FileCreated")
| project TimeGenerated, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, SHA256
```

**Screenshot / Output:** Startup persistence observed.
<img width="940" height="230" alt="image" src="https://github.com/user-attachments/assets/3da4f36e-b3b5-434d-9c3a-e4f8fbb03bfc" />

---

### Flag 21 – Log Clearing

**Finding:** Anti-forensics activity; logs cleared.

**KQL Query:**
```kql:

DeviceProcessEvents
| where FileName in ("wevtutil.exe","eventvwr.exe","powershell.exe")
| where ProcessCommandLine has_any ("cl","Clear-EventLog","/c")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by TimeGenerated desc
```

**Screenshot / Output:** Remote device identified.
<img width="745" height="227" alt="image" src="https://github.com/user-attachments/assets/33564ad5-9693-40dd-812b-b22ec225d6ba" />

---

## Flag 22 – Reflective Loading

**Finding:** Memory injection observed.
**KQL Query:**
```kql

DeviceEvents
| where DeviceName == "as-pc1"
| where Timestamp between (datetime(2026-01-15 05:00) .. datetime(2026-01-15 06:00))
| where InitiatingProcessFileName == "notepad.exe"
| project Timestamp, ActionType, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Screenshot / Output:** Confirms network origin.
<img width="925" height="484" alt="image" src="https://github.com/user-attachments/assets/499f3961-72a0-4f46-a7c1-034eb60f0a9e" />

---



---
## 🔍 Timeline of Events
| Time (UTC)            | Stage                     | Event / Action                          | Details                                                       |
| --------------------- | ------------------------- | --------------------------------------- | -------------------------------------------------------------- |
| 2026-01-14T23:31      | Initial Access            | Initial alert                           | MDE detected suspicious file execution                        |
| 2026-01-14T23:48      | Initial Access            | Inbound connection                      | Remote IP 168.63.129.16:80 connected to local 10.1.0.154:54554 |
| 2026-01-14T23:47      | Command & Control         | Outbound C2 connection                  | daniel_richardson_cv.pdf.exe connected to cdn.cloud-endpoint.net  |
| 2026-01-15T00:11      | Persistence               | Remote access tool installed            | AnyDesk installed, unattended access password intrud3r! configured  |
| 2026-01-15T05:09      | Persistence               | Suspicious child process                | notepad.exe spawned by malware |
| 2026-01-15T04:55      | Data Access               | Sensitive document access               | BACS_Payments_Dec2025.ods opened from host as-pc2          |
| 2026-01-15T04:59      | Data Access               | Data archived                           | Sensitive files saved into Shares.7z              |
| 2026-01-15T05:00      | Defense Evasion           | Memory-based credential theft           | SharpChrome loaded in notepad.exe memory                      |
| 2026-01-15T05:10      | Defense Evasion           | Reflective code loading                 | Malicious assembly loaded in memory          |
| 2026-01-15T05:15      | Discovery                 | Registry & group enumeration            | SAM/SYSTEM queried; Administrators group enumerated    |
| 2026-01-15T06:00      | Lateral Movement          | Remote execution attempts               | WMIC and PsExec failed on host as-pc2  |
| 2026-01-15T06:10      | Lateral Movement          | Successful pivot                        | RDP session from as-pc1 → as-pc2 → as-srv using david.mitchell   |
| 2026-01-15T06:30      | Persistence               | Scheduled task created                  | MicrosoftEdgeUpdateCheck runs RuntimeBroker.exe           |
| 2026-01-16T11:09      | Privilege Escalation      | Admin account added                     | svc_backup added as Administrator           |

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

4. Improve endpoint detection rules by monitoring for: certutil downloads, scheduled task creations, event log clearing and reflective .NET assembly loading

5. Conduct security awareness training: Focus on phishing attempts targeting HR and recruitment teams.
