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

## 🚩Investigation Findings

### Initial Access
User sophie.turner executed a malicious resume file that initiated the compromise.

**Artifacts:**
- File: Daniel_Richardson_CV.pdf.exe
- Hash: 48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5
- Parent Process: Explorer.exe
- Spawned Process: notepad.exe
  
---

### Command & Control
Outbound communications were established with attacker infrastructure.

**Domain** ```cdn.cloud-endpoint.net```

**Responsible Process** ```Daniel_Richardson_CV.pdf.exe ```

**Additional Infrastructure** ```sync.cloud-endpoint.net ```

---

### Credential Access
The attacker attempted to extract credentials from local system stores.

**Registry Targets** ```SAM``` ```SYSTEM ```

**Local Staging Directory** ```C:\Users\Public\ ```

**Memory Credential Theft Tool** ``` SharpChrome ```

**Injected Process** ``` notepad.exe ```

---

### Discovery Activity

The attacker performed reconnaissance to understand the environment.

Commands Observed ``` whoami.exe``` ```net view ```

Local Privileged Group Queried ```Administrators ```

---
### Persistence – Remote Access Tool

The attacker deployed a legitimate remote administration tool.

**Remote Tool** ```AnyDesk```

**SHA256** ```f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532 ```

**Download Method** ```certutil.exe ```

**Configuration File** ```C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf ```

**Unattended Access Password** ```intrud3r!```

**Deployment Hosts** ```as-pc1``` ```as-pc2``` ```as-srv ```

---
### Lateral Movement
The attacker attempted several remote execution techniques before successfully pivoting.

**Failed Methods** ```wmic.exe``` ```psexec.exe ```

**Successful Method** ```mstsc.exe (Remote Desktop) ```

**Movement Path** ``` as-pc1 > as-pc2 > as-srv ```

**Compromised Account** ``` david.mitchell ```

**Account Activation** ```net.exe active:yes ```

---

### Persistence – Scheduled Task 

Additional persistence mechanisms were deployed.

**Scheduled Task** ```MicrosoftEdgeUpdateCheck ```

**Renamed Payload** ```RuntimeBroker.exe ```

**Backdoor Account** ``` svc_backup ```

---

### Data Access & Staging

Sensitive financial records were accessed and staged for exfiltration.

**Target File** ``` BACS_Payments_Dec2025.ods ```

**Modification Artifact** ``` .~lock.BACS_Payments_Dec2025.ods# ```

**Access Origin** ``` as-pc2 ```

**Archive Created** ``` Shares.7z ```

**Archive Hash** ``` 6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048 ```

---
### Defense Evasion

The attacker attempted to conceal activity before exiting the environment.

**Logs Cleared** ```Security``` ```Application ```

**Reflective Code Loading** ```ClrUnbackedModuleLoaded ```

---
### Indicators of Compromise (IOC)

**Malicious Files**
| File	                 |SHA256  |
| --------------------- | ------------------------- |
| Daniel_Richardson_CV.pdf.exe	|48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5
|RuntimeBroker.exe	|48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5
|AnyDesk.exe	|f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532
|Shares.7z	|6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048

---
**Malicious Domains**

```cdn.cloud-endpoint.net```
```sync.cloud-endpoint.net ```

---
**Suspicious IP Addresses**

``` 37.59.29.33```
```64.31.23.30```
```88.97.164.155```
```104.21.30.237 ```

---
**Compromised Accounts**

``` sophie.turner```
```david.mitchell```
```svc_backup ```

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

6. # Appendix – Investigation Queries

 ---

## 🧾 Appendix – Investigation Queries
**Query 1 – Malware Execution**

```kql
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where FileName == "Daniel_Richardson_CV.pdf.exe" ```

**Query 2 – C2 Communication**
```kql
DeviceNetworkEvents
| where DeviceName contains "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe" ```

**Query 3 – AnyDesk Installation**
```kql
DeviceFileEvents
| where FileName in ("AnyDesk.exe","AnyDesk64.exe") ```

