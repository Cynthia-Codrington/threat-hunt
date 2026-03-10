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

**Finding:** 
**Last successful connection:** 

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
<img width="940" height="135" alt="image" src="https://github.com/user-attachments/assets/d4e13ecb-7ed2-476b-924c-1d0e4b2ee684" />

---
### Flag 5 – Process Arguments

**Finding:** Child process executed with unusual arguments.<br>

<img width="695" height="366" alt="image" src="https://github.com/user-attachments/assets/b3b1e322-c8ef-48f6-9d98-7004cc2823f6" />

---
### Flag 6 – C2 Domain

**Finding:** Outbound command-and-control connections observed.

**KQL Query:**
```kql
DeviceNetworkEvents
|where DeviceName contains "as-pc1"
| where InitiatingProcessAccountName == "sophie.turner"
|where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc

```
**Screenshot:**
<img width="880" height="295" alt="image" src="https://github.com/user-attachments/assets/1955bce7-5883-44ec-b6b8-250e2094bec0" />


---
### Flag 7 – C2 Process

**Finding:** daniel_richardson_cv.pdf.exe is the process that initiated the outbound connections

**Screenshot:**
<img width="823" height="1091" alt="image" src="https://github.com/user-attachments/assets/795192f7-d074-4e0d-a789-58c7c66b31ec" />

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
<img width="940" height="349" alt="image" src="https://github.com/user-attachments/assets/9368ecea-5500-46e2-b930-da4fb9d4a5e4" />


---
### Flag 9 – Registry Targets

**Finding:** Targeted local credential stores.

**Screenshot:**
<img width="940" height="166" alt="image" src="https://github.com/user-attachments/assets/aa7d7864-789a-40a8-9a33-e9fbf0dd67b6" />


---
### Flag 10 – Local Staging

**Finding:** Extracted data was saved locally before exfiltration

**Screenshot:**
<img width="856" height="1039" alt="image" src="https://github.com/user-attachments/assets/77d48c53-31c2-442e-b537-36fc1a6d5023" />

---
### Flag 11 – User Context

**Finding:** The attacker confirmed their identity after initial access.

---
### Flag 12 – Network Enumeration

**Finding:** The attacker enumerated network resources. Net view was used to view available shares.
---

### Flag 13 – Local Admins

**Finding:** The attacker enumerated privileged local group membership.

**Screenshot / Output:** Decoded command confirms malicious script execution.
<img width="783" height="1214" alt="image" src="https://github.com/user-attachments/assets/f56db95a-da79-4add-8bfe-162badd1460d" />

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
---
### Flag 15 – Remote Tool Hash

**Finding:** SHA256 hash of the remote access tool Anydesk.exe
**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName == "as-pc1"
|where FileName contains "anydesk"

```
<img width="940" height="214" alt="image" src="https://github.com/user-attachments/assets/5d482b0f-1ae6-4ae6-9d48-de023e2087ac" />

---
### Flag 16 – Download Method

**Finding:** The tool was downloaded using a native Windows binary.

```
<img width="940" height="214" alt="image" src="https://github.com/user-attachments/assets/5d482b0f-1ae6-4ae6-9d48-de023e2087ac" />

---
### Flag 16 – Configuration Access

**Finding:** After installation, a configuration file was accessed.

<img width="564" height="1050" alt="image" src="https://github.com/user-attachments/assets/7a634383-1d43-4e92-8612-ac2f655d7c45" />

---
### Flag 17 – Access Credentials

**Finding:** Unattended access was configured for the remote tool.

<img width="605" height="619" alt="image" src="https://github.com/user-attachments/assets/1e9d5f8b-b57f-4af9-b8c9-1a8c4a497022" />
---
### Flag 18 – Deployment Footprint

**Finding:** The remote tool was installed across the environment.
**KQL Query:**
```kql

DeviceFileEvents
| where FileName in ("AnyDesk.exe", "AnyDesk64.exe")    // AnyDesk binaries
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by DeviceName asc, TimeGenerated desc

```
<img width="940" height="142" alt="image" src="https://github.com/user-attachments/assets/85fcd5ca-2fa6-4e45-982a-0adebae044e8" />
---

### Flag 19 – Failed Execution

**Finding:** The attacker attempted remote execution methods that failed.
**KQL Query:**
```kql

DeviceProcessEvents
| where DeviceName in ("as-pc1","as-pc2")
| where ProcessCommandLine has_any ("\\\\","/node:","-ComputerName","/S ")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| sort by TimeGenerated asc

```
**Screenshot / Output:**
<img width="940" height="198" alt="image" src="https://github.com/user-attachments/assets/ab0ae817-172a-4dc4-870a-24a21d01efba" />

---

## Flag 20 – Target Host

**Finding:** Remote execution was attempted against a specific system.
---
### Flag 21 – Sucessful Pivot

**Finding:** After failed attempts, a different method achieved lateral movement.

- mstsc.exe execution	DeviceProcessEvents
- RemoteInteractive logon	DeviceLogonEvents
- Port 3389 traffic	DeviceNetworkEvents

---
### Flag 22 – Movement Path

**Finding:** The attacker moved through the environment in a specific sequence: as-pc1>as-pc2>as-srv
---
---
### Flag 23 – Compromised Account

**Finding:** A valid account (david.mitchell) was used for successful lateral movement.
---
---
### Flag 24 – Account Activation

**Finding:** A disabled account was enabled for further access. The net.exe parameter used to activate the account:active:yes

---
### Flag 25 – Activation Context

**Finding:** The account activation was performed by a specific user: david.mitchell
---

### Flag 26 – Scheduled Persistence

**Finding:** Scheduled tasks and new accounts extend their access even if one mechanism is discovered and removed.

**KQL Query:**
```kql
 DeviceProcessEvents
|where DeviceName contains "as-"
| where ProcessCommandLine contains "/create"  // Only task creation commands

```
**Screenshot / Output:**
<img width="940" height="345" alt="image" src="https://github.com/user-attachments/assets/c2d48189-462e-44b6-993f-53ab577d9793" />

---

### Flag 27 – Renamed Binary

**Finding:** The persistence payload was renamed to avoid detection.

---

### Flag 28 – Persistence Hash

**Finding:** The persistence payload shares a hash with another file in the investigation.
**KQL Query:**
```kql
 DeviceProcessEvents
|where SHA256 == "48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5"

```
**Screenshot / Output:** 
<img width="940" height="551" alt="image" src="https://github.com/user-attachments/assets/379849af-74a3-49d9-a36c-12f9954f317d" />

---
### Flag 27 – Renamed Binary

**Finding:** The persistence payload was renamed to avoid detection.
---

### Flag 29 – Sensitive Document

**Finding:** A new local account was created for future access: svc_backup

**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName == "as-srv"
| where InitiatingProcessAccountName != ""
| where FileName contains "PAY"
|project ActionType, FileName, FolderPath

```
**Screenshot / Output:** 
<img width="940" height="373" alt="image" src="https://github.com/user-attachments/assets/715846e0-d590-4d83-ae54-16b12f47f7cc" />
---

### Flag 30 – Modification Evidence

**Finding:** The document was opened for editing, not just viewing

**Screenshot / Output:** 
<img width="940" height="373" alt="image" src="https://github.com/user-attachments/assets/e186761c-cf90-423d-a313-cb380570ab34" />

---

### Flag 31 – Access Origin

**Finding:** The document was accessed from a specific workstation

---
### Flag 32 – Exfil Archive

**Finding:** Data was archived before potential exfiltration

**Screenshot / Output:** 
<img width="940" height="238" alt="image" src="https://github.com/user-attachments/assets/2a5d04a8-522e-44ec-bdd4-ccdc8f27f392" />
---
### Flag 33 – Archive Hash

**Finding:** The SHA256 hash of the staged archive was identified.

**KQL Query:**
```kql:
let fileAccesses = DeviceFileEvents
| where DeviceName == "as-srv"                     // the file server
| where ActionType in ("FileRead", "FileRead", "FileModified", "FileCreated")
| project FileTime = TimeGenerated,
          FileName,
          FolderPath,
          InitiatingProcessAccountName,
          InitiatingProcessFileName,
          InitiatingProcessSHA256,
          SHA256;

let userSessions = DeviceLogonEvents
| where DeviceName == "as-pc2"                    // client machine
| project LogonTime = TimeGenerated,
          AccountName,
          LogonType;

fileAccesses
| join kind=inner userSessions on $left.InitiatingProcessAccountName == $right.AccountName
| where FileTime between (LogonTime .. LogonTime + 12h)   // assume user session duration

```

**Screenshot / Output:** 
<img width="940" height="322" alt="image" src="https://github.com/user-attachments/assets/7df7eac6-ab70-4ab0-991e-46e55bdd8b3a" />

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

**Screenshot / Output:** 
<img width="940" height="111" alt="image" src="https://github.com/user-attachments/assets/27964f46-b1e6-4bc4-b854-5aa9722538a7" />

---
## Flag 22 – Reflective Loading

**Finding:** Evidence of reflective code loading was captured.
---
## Flag 22 – Memory Tool

**Finding:** A credential theft tool was loaded directly into memory.
### Flag 21 – Host Process

**Finding:** The credential theft tool was injected into a legitimate process.

**KQL Query:**
DeviceEvents
| where DeviceName == "as-pc1"
| where Timestamp between (datetime(2026-01-15 05:00) .. datetime(2026-01-15 06:00))
| where InitiatingProcessFileName == "notepad.exe"
| project Timestamp, ActionType, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine

```
**Screenshot / Output:** 
<img width="940" height="178" alt="image" src="https://github.com/user-attachments/assets/8b24a00f-4220-4e2e-b4d0-d0306e7a0789" />

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
