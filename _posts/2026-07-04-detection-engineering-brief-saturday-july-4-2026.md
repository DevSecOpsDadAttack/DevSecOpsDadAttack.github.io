---
layout: post
title: "Detection Engineering Brief - Saturday, July 4, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-04
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Armored Likho
  - BusySnake Stealer
  - Windows
  - Linux
  - ScreenConnect
  - AsyncRAT
  - T1021.002
  - T1055
  - SMB
  - Meterpreter
  - Metasploit
  - PsExec
  - Peyara Remote Mouse
  - T1059
  - T1204.002
  - T1105
  - T1204
  - T1059.003
  - T1059.001
  - T1071
  - T1071.001
  - T1203
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

2 production candidates, 2 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Armored Likho, BusySnake Stealer, Windows, Linux, ScreenConnect, AsyncRAT, T1021.002, T1055, SMB, Meterpreter, Metasploit, PsExec, Peyara Remote Mouse, T1059, T1204.002, T1105, T1204, T1059.003, T1059.001, T1071, ....

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: BusySnake Stealer - Python Stealer Execution with Suspicious Parent or Network Activity; PsExec SMB Lateral Movement Followed by Meterpreter Service Creation; Peyara Remote Mouse RCE - Unexpected Child Process Spawned by Remote Mouse Application.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: BusySnake Stealer - Python Stealer Execution with Suspicious Parent or Network Activity

### Detection Opportunity

Python-based BusySnake Stealer executed on endpoint with unusual parent process or outbound network connections indicative of credential theft

### Intelligence Context

- Securelist: Armored Likho digging a snake pit: inside the covert BusySnake Stealer campaign — [https://securelist.com/tr/armored-likho-apt-with-busysnake-stealer/120292/](https://securelist.com/tr/armored-likho-apt-with-busysnake-stealer/120292/)
  - Context: Armored Likho deployed BusySnake Stealer, a Python-based tool, via spear-phishing with AI-generated loaders. The stealer executes as a Python process and is expected to make outbound connections for data exfiltration.

### Search Metadata

- CVEs: Not specified
- Threat actors: Armored Likho
- ATT&CK tags: T1059, T1204.002, T1105, T1204
- Products: Not specified
- Platforms: Windows, Linux
- Malware: BusySnake Stealer
- Tools: Not specified
- Search tags: Armored Likho, BusySnake Stealer, Windows, Linux, T1059, T1204.002, T1105, T1204

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (high); Execution: T1204 User Execution/ T1204.002 Malicious File (medium); Ingress Tool Transfer: T1105 Ingress Tool Transfer (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let SuspiciousParents = dynamic(["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "chrome.exe", "msedge.exe", "firefox.exe", "7zfm.exe", "winrar.exe", "wscript.exe", "cscript.exe", "mshta.exe"]);
let PythonNames = dynamic(["python.exe", "python3.exe", "pythonw.exe"]);
// Branch 1: Suspicious parent spawning Python
let SuspiciousParentSpawn = DeviceProcessEvents
| where FileName in~ (PythonNames)
| where InitiatingProcessFileName in~ (SuspiciousParents)
| project DeviceId, DeviceName, AccountName, PythonPid = ProcessId, PythonTime = Timestamp,
    ProcessCommandLine, InitiatingProcessFileName, FileName, SHA256,
    DetectionBranch = "SuspiciousParentSpawn";
// Branch 2: Python with suspicious command-line keywords
let SuspiciousCmdLine = DeviceProcessEvents
| where FileName in~ (PythonNames)
| where ProcessCommandLine has_any ("-c ", "base64", "urllib", "requests", "socket", "subprocess", "os.system")
| where InitiatingProcessFileName !in~ (SuspiciousParents)
| project DeviceId, DeviceName, AccountName, PythonPid = ProcessId, PythonTime = Timestamp,
    ProcessCommandLine, InitiatingProcessFileName, FileName, SHA256,
    DetectionBranch = "SuspiciousCmdLine";
let PythonProcs = SuspiciousParentSpawn
| union SuspiciousCmdLine;
let NetEvents = DeviceNetworkEvents
| where InitiatingProcessFileName in~ (PythonNames)
| where RemoteIPType == "Public"
| project DeviceId, InitiatingProcessId, NetTime = Timestamp, RemoteIP, RemoteUrl, RemotePort;
PythonProcs
| join kind=inner NetEvents on DeviceId
| where InitiatingProcessId == PythonPid
| where NetTime between (PythonTime .. (PythonTime + 5m))
| project DeviceName, AccountName, PythonTime, InitiatingProcessFileName, FileName,
    ProcessCommandLine, SHA256, RemoteIP, RemoteUrl, RemotePort, DetectionBranch
| order by PythonTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Developer workstations running Python scripts that import requests, urllib, or socket for legitimate purposes.
- Automated build or CI/CD pipelines that invoke Python from script hosts.
- Browser-integrated Python tooling or Jupyter notebooks making outbound connections.

**Tuning notes:**
- Expand or restrict SuspiciousParents based on observed legitimate Python parent processes in the environment.
- Consider adding a SHA256 allowlist for known-good Python scripts to reduce recurring false positives.
- If scheduling as a rule, consider requiring both branches (parent AND network) rather than union to increase precision.

**Risks / caveats:**
- RemoteIPType field availability in DeviceNetworkEvents should be confirmed; it is present in Defender for Endpoint telemetry but may not be populated for all network events depending on MDE sensor version.
- Linux endpoints are listed as a target platform but DeviceProcessEvents and DeviceNetworkEvents coverage for Linux via MDE must be confirmed for the specific OS versions in the environment.
- The 5-minute correlation window between process creation and network connection may miss stealers that delay exfiltration; analysts should extend the window during active hunting.
- Command-line keyword matching on strings like 'requests' or 'socket' will generate noise in developer-heavy environments; baseline Python usage before scheduling.

### Triage Runbook

**First 15 minutes:**
- Confirm the parent process, command line, and account context for the Python process; prioritize Office, browser, archive, or script-host parents and any command lines containing base64, urllib, requests, socket, subprocess, or os.system.
- Validate whether the outbound connection is to a public IP or URL and whether it occurred within minutes of the Python process start on the same device and process ID.
- Check whether the host is a developer workstation, CI/CD runner, or notebook environment where Python network activity is expected.
- Look for signs of credential access or staging such as access to browser profile paths, password stores, temp directories, or recent file creation around the same timestamp.

**Evidence to collect:**
- DeviceName, AccountName, PythonTime, InitiatingProcessFileName, ProcessCommandLine, SHA256, RemoteIP, RemoteUrl, RemotePort, DetectionBranch.
- Process tree for the Python process and any preceding Office/email/browser activity.
- Network destination reputation, ASN, and whether the URL/IP is newly seen in the environment.
- Any nearby file creation or archive extraction activity on the same host within the prior 10 minutes.

**Pivot points:**
- DeviceProcessEvents for the same DeviceId and AccountName to review parent/child process chains around PythonTime.
- DeviceNetworkEvents filtered to the same InitiatingProcessId and DeviceId to confirm the exact process making the connection.
- DeviceFileEvents for recent file creation in Temp, AppData, Downloads, or user profile paths.
- DeviceLogonEvents to determine whether the account was interactive, remote, or service-based at the time.

**Benign explanations:**
- Legitimate Python automation or developer activity using requests, urllib, or socket.
- CI/CD or build pipeline scripts that execute Python and reach external services.
- Jupyter or browser-integrated Python tooling making normal outbound connections.

**Escalation criteria:**
- The Python process is spawned by an Office app, browser, archive utility, or script host and connects to a public IP/URL not previously associated with the host.
- The command line shows suspicious download, decode, or execution behavior and the same process ID is tied to outbound traffic.
- Evidence of credential access, browser data theft, or staged payloads is found on the host.
- The account or host is not a known developer or automation asset and the activity is unexplained.

**Containment actions:**
- If the process is confirmed malicious or strongly suspicious, isolate the endpoint from the network.
- Terminate the Python process and any obvious child processes only after preserving evidence.
- Reset credentials for the affected user if browser, token, or password theft is suspected.
- Block the destination IP/URL if it is confirmed malicious and not required for business use.

**Closure criteria:**
- The Python activity is validated as a known-good script or approved automation job.
- The network destination is a sanctioned service and the process tree matches baseline behavior.
- No evidence of credential theft, payload staging, or suspicious parent process is found.
- A documented allowlist or tuning note is created for the legitimate pattern.

<br/>
---
<br/>

## Detection 2: BusySnake Stealer - Office Application Spawning Script Interpreter After Email Delivery

### Detection Opportunity

Office application or email client spawning a script interpreter or dropping an executable following spear-phishing delivery, consistent with BusySnake Stealer initial access chain

### Intelligence Context

- Securelist: Armored Likho digging a snake pit: inside the covert BusySnake Stealer campaign — [https://securelist.com/tr/armored-likho-apt-with-busysnake-stealer/120292/](https://securelist.com/tr/armored-likho-apt-with-busysnake-stealer/120292/)
  - Context: Armored Likho used spear-phishing with AI-generated loaders to deliver BusySnake Stealer. The delivery chain involves Office or email applications spawning script interpreters or dropping executables to temporary paths.

### Search Metadata

- CVEs: Not specified
- Threat actors: Armored Likho
- ATT&CK tags: T1059, T1204.002, T1105, T1204
- Products: Not specified
- Platforms: Windows
- Malware: BusySnake Stealer
- Tools: Not specified
- Search tags: Armored Likho, BusySnake Stealer, Windows, T1059, T1204.002, T1105, T1204

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (high); Execution: T1204 User Execution/ T1204.002 Malicious File (medium); Ingress Tool Transfer: T1105 Ingress Tool Transfer (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let OfficeApps = dynamic(["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"]);
let ScriptInterpreters = dynamic(["python.exe", "python3.exe", "pythonw.exe", "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"]);
let SuspiciousExtensions = dynamic(["exe", "dll", "ps1", "vbs", "js", "py", "bat", "hta"]);
let SpawnedInterpreters = DeviceProcessEvents
| where InitiatingProcessFileName in~ (OfficeApps)
| where FileName in~ (ScriptInterpreters)
| project DeviceId, DeviceName, AccountName,
    EventTime = Timestamp,
    EventType = "ChildProcessSpawn",
    ParentProcess = InitiatingProcessFileName,
    ChildProcessOrFile = FileName,
    ProcessCommandLine,
    FolderPath = "",
    FileExtension = "",
    SHA256 = SHA256;
let DroppedFiles = DeviceFileEvents
| where InitiatingProcessFileName in~ (OfficeApps)
| where ActionType == "FileCreated"
| where FileExtension in~ (SuspiciousExtensions)
| where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\Downloads\\")
| project DeviceId, DeviceName, AccountName,
    EventTime = Timestamp,
    EventType = "SuspiciousFileDrop",
    ParentProcess = InitiatingProcessFileName,
    ChildProcessOrFile = FileName,
    ProcessCommandLine = InitiatingProcessCommandLine,
    FolderPath,
    FileExtension,
    SHA256;
SpawnedInterpreters
| union DroppedFiles
| order by EventTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate Office macros or add-ins that invoke PowerShell or cmd for automation tasks.
- IT-managed Office templates that drop scripts to AppData for configuration purposes.
- PDF or document converters that write executables to Temp as part of normal operation.

**Tuning notes:**
- Add known legitimate macro automation account names or device names to an exclusion filter on AccountName or DeviceName.
- Consider restricting ScriptInterpreters to python.exe, python3.exe, and pythonw.exe only for a higher-precision variant targeting BusySnake specifically.
- If FileExtension is unpopulated, add a fallback: extract extension from FileName using extract(@'\.([^.]+)$', 1, FileName).

**Risks / caveats:**
- FileExtension field in DeviceFileEvents must be confirmed as populated in the environment; some MDE configurations may leave this field empty for certain file types, requiring fallback to parsing FolderPath or FileName.
- Legitimate Office macro automation environments will generate false positives; an AccountName or DeviceName allowlist should be built from baseline observations before promoting alert volume.
- The FolderPath filter uses has_any with partial path strings; deeply nested or non-standard user profile paths may be missed if they do not contain the listed substrings.
- onenote.exe is included in OfficeApps; OneNote-based delivery chains are valid but may generate noise if OneNote is used for legitimate scripting integrations.

### Triage Runbook

**First 15 minutes:**
- Identify the parent Office or email process, the child interpreter or dropped file, and the user account that opened the document or email.
- Review the document name, attachment origin, and whether the file was opened from email, Downloads, or a temp path.
- Check whether the child process is PowerShell, cmd, wscript, cscript, mshta, or Python, and inspect the full command line for download or execution behavior.
- Determine whether the file drop is a new executable or script in Temp, AppData, or Downloads and whether it has a hash available for reputation checks.

**Evidence to collect:**
- DeviceName, AccountName, EventTime, EventType, ParentProcess, ChildProcessOrFile, ProcessCommandLine, FolderPath, FileExtension, SHA256.
- Email metadata for the delivery chain if available, including sender, subject, and attachment name.
- Process tree from the Office/email application through the spawned interpreter or dropped file.
- Any related file creation, archive extraction, or subsequent network activity on the same host.

**Pivot points:**
- DeviceProcessEvents for the same DeviceId and AccountName to reconstruct the full process tree.
- DeviceFileEvents to identify additional files created by the same parent process in the same time window.
- DeviceNetworkEvents for the spawned interpreter or dropped file to see whether it reached out externally.
- Email-related telemetry or message trace data to confirm spear-phishing delivery if available in the environment.

**Benign explanations:**
- Legitimate Office macro automation or IT-managed scripts launched from Office documents.
- Approved add-ins or document converters that spawn interpreters for business workflows.
- Known software installers or converters that temporarily write executables or scripts to Temp or AppData.

**Escalation criteria:**
- An Office or email process spawns a script interpreter and the command line shows download, decode, or execution behavior.
- A suspicious executable or script is created in Temp, AppData, or Downloads and is followed by outbound network activity.
- The user reports opening a suspicious attachment or link shortly before the alert.
- The file hash, sender, or destination is unknown and not explainable by a sanctioned workflow.

**Containment actions:**
- Isolate the endpoint if the spawned interpreter or dropped file appears malicious.
- Quarantine the email or attachment source if the delivery path is confirmed.
- Terminate the suspicious child process and remove the dropped file after evidence capture.
- Reset the user’s credentials if the payload appears to target browser or session data.

**Closure criteria:**
- The parent Office/email activity is confirmed as a sanctioned automation or approved add-in.
- The dropped file is a known-good installer, script, or document converter artifact.
- No suspicious network activity or secondary payload execution is observed.
- The event is documented as a benign macro or IT workflow and tuned if recurring.

<br/>
---
<br/>

## Detection 3: AsyncRAT Dropped and Executed via Compromised ScreenConnect Process

### Detection Opportunity

ScreenConnect process spawning cmd, PowerShell, or dropping executables to temp or appdata paths, followed by outbound network connections consistent with AsyncRAT C2 activity

### Intelligence Context

- Securelist: The SOC Files: ScreenConnect masked as freeware. An inside look at a large-scale campaign — [https://securelist.com/tr/the-soc-files-screenconnect-campaign-with-asyncrat/120472/](https://securelist.com/tr/the-soc-files-screenconnect-campaign-with-asyncrat/120472/)
  - Context: AsyncRAT was dropped via compromised ScreenConnect software masquerading as freeware. The ScreenConnect process served as the delivery mechanism, spawning child processes or dropping payloads that established C2 connections.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.003, T1059.001, T1105, T1071, T1071.001
- Products: ScreenConnect
- Platforms: Windows
- Malware: AsyncRAT
- Tools: Not specified
- Search tags: ScreenConnect, AsyncRAT, Windows, T1059, T1059.003, T1059.001, T1105, T1071, T1071.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.003 Windows Command Shell (high); Execution: T1059 Command and Scripting Interpreter/ T1059.001 PowerShell (high); Ingress Tool Transfer: T1105 Ingress Tool Transfer (medium); Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents

### KQL

```kql
let ScreenConnectProcs = dynamic(["ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe", "ScreenConnect.WindowsBackstageShell.exe", "ScreenConnect.Service.exe"]);
let HighRiskChildren = dynamic(["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"]);
let SuspiciousExtensions = dynamic(["exe", "dll", "ps1", "bat", "vbs"]);
// Branch 1: ScreenConnect spawning high-risk child processes
let SpawnEvents = DeviceProcessEvents
| where InitiatingProcessFileName in~ (ScreenConnectProcs)
| where FileName in~ (HighRiskChildren)
| project DeviceId, DeviceName, AccountName,
    EventTime = Timestamp,
    DetectionBranch = "ChildProcessSpawn",
    ParentProcess = InitiatingProcessFileName,
    ChildProcessOrFile = FileName,
    ProcessCommandLine,
    FolderPath = "",
    SHA256 = SHA256,
    RemoteIP = "",
    RemotePort = int(null);
// Branch 2: ScreenConnect dropping suspicious files
let DropEvents = DeviceFileEvents
| where InitiatingProcessFileName in~ (ScreenConnectProcs)
| where ActionType == "FileCreated"
| where FileExtension in~ (SuspiciousExtensions)
| where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\ProgramData\\")
| project DeviceId, DeviceName, AccountName,
    EventTime = Timestamp,
    DetectionBranch = "SuspiciousFileDrop",
    ParentProcess = InitiatingProcessFileName,
    ChildProcessOrFile = FileName,
    ProcessCommandLine = InitiatingProcessCommandLine,
    FolderPath,
    SHA256,
    RemoteIP = "",
    RemotePort = int(null);
// Branch 3: High-risk child processes making outbound connections
let NetEvents = DeviceNetworkEvents
| where InitiatingProcessFileName in~ (HighRiskChildren)
| where RemoteIPType == "Public"
| project DeviceId, DeviceName, AccountName = "",
    EventTime = Timestamp,
    DetectionBranch = "OutboundC2Connection",
    ParentProcess = "",
    ChildProcessOrFile = InitiatingProcessFileName,
    ProcessCommandLine = InitiatingProcessCommandLine,
    FolderPath = "",
    SHA256 = "",
    RemoteIP,
    RemotePort;
SpawnEvents
| union DropEvents
| union NetEvents
| order by EventTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Authorized IT remote support sessions where a ScreenConnect technician opens cmd.exe or PowerShell on the remote host for legitimate administration.
- ScreenConnect-managed software deployment scripts that write executables to ProgramData as part of patch management.

**Tuning notes:**
- To tighten Branch 3, join NetEvents back to SpawnEvents on DeviceId with a time window to confirm the outbound connection originated from a ScreenConnect-spawned process.
- Add known IT support AccountName values to an exclusion filter to suppress authorized remote support activity.
- Validate ScreenConnect executable names in the environment by querying DeviceProcessEvents for ScreenConnect-related process names before deployment.

**Risks / caveats:**
- Custom-branded ScreenConnect deployments may use different executable names than the four listed; if the environment uses a rebranded ScreenConnect client, the ScreenConnectProcs list will not match and the detection will produce no results for those hosts.
- RemoteIPType field availability in DeviceNetworkEvents should be confirmed for the MDE sensor version deployed.
- Branch 3 (network events from HighRiskChildren) is not scoped to only those child processes spawned by ScreenConnect; it will surface any cmd.exe or PowerShell making outbound connections, not just those in the ScreenConnect chain. Analysts should correlate Branch 1 and Branch 3 events by DeviceId and time proximity during triage.
- Custom-branded ScreenConnect deployments require updating ScreenConnectProcs with the actual executable names before the detection is meaningful.

### Triage Runbook

**First 15 minutes:**
- Identify the ScreenConnect process name, the child process or dropped file, and the account or technician context associated with the session.
- Check whether the child process is cmd, PowerShell, wscript, cscript, mshta, rundll32, or regsvr32, and inspect the command line for download or execution behavior.
- Review the file drop path and hash for Temp, AppData, or ProgramData writes and determine whether the file is a new executable or script.
- Validate whether the outbound connection is to a public IP and whether it aligns with a known ScreenConnect support session or a suspicious post-execution connection.

**Evidence to collect:**
- DeviceName, AccountName, EventTime, DetectionBranch, ParentProcess, ChildProcessOrFile, ProcessCommandLine, FolderPath, SHA256, RemoteIP, RemotePort.
- ScreenConnect session details, technician account, and ticket/change reference if available.
- Process tree and any subsequent child processes from the ScreenConnect host.
- Network destination reputation and whether the connection was initiated by the dropped payload or the remote support tool.

**Pivot points:**
- DeviceProcessEvents for ScreenConnect-related processes on the same DeviceId to reconstruct the session chain.
- DeviceFileEvents for files created by the ScreenConnect process in Temp, AppData, or ProgramData.
- DeviceNetworkEvents for the same DeviceId and time window to identify outbound C2-like traffic.
- DeviceLogonEvents or remote access logs to confirm whether the session was authorized.

**Benign explanations:**
- Authorized IT remote support or software deployment using ScreenConnect.
- Managed patching or remote administration that legitimately opens cmd or PowerShell.
- Known ScreenConnect-based deployment scripts that write installers or scripts to ProgramData.

**Escalation criteria:**
- ScreenConnect spawns shell or scripting processes without a valid support ticket or approved maintenance window.
- A new executable or script is dropped and followed by public outbound connections consistent with RAT C2.
- The ScreenConnect process is present on a host where it is not expected or the executable name is unfamiliar.
- The technician or account cannot be validated as authorized.

**Containment actions:**
- Isolate the endpoint if unauthorized ScreenConnect activity or RAT behavior is confirmed.
- Disable or suspend the ScreenConnect account or service if compromise is suspected.
- Terminate the suspicious child process and quarantine the dropped file after evidence capture.
- Block the remote IP if it is confirmed malicious and not part of a sanctioned relay or support infrastructure.

**Closure criteria:**
- The activity is matched to a valid support ticket, approved technician, and expected process behavior.
- The dropped file is a known-good deployment artifact and no suspicious network activity is present.
- The ScreenConnect executable and child process behavior align with baseline authorized administration.
- A tuning exception is documented for the approved support pattern.

<br/>
---
<br/>

## Detection 4: PsExec SMB Lateral Movement Followed by Meterpreter Service Creation

### Detection Opportunity

PsExec used over SMB to deploy a service on a remote host, followed by process injection or Meterpreter-associated activity consistent with T1021.002 and T1055 exploitation chain

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Modules for SMB-to-Meterpreter, Peyara Remote Mouse RCE exploit, and more — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-07-03-2026/](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-07-03-2026/)
  - Context: A new Metasploit module uses PsExec over SMB to upgrade existing SMB sessions to Meterpreter, creating a remote service on the target host as part of the lateral movement and payload delivery chain.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1021.002, T1055, T1203, T1071, T1071.001
- Products: SMB
- Platforms: Windows
- Malware: Meterpreter
- Tools: Metasploit, PsExec
- Search tags: T1021.002, T1055, SMB, Windows, Meterpreter, Metasploit, PsExec, T1203, T1071, T1071.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Both
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1203 Exploitation for Client Execution (medium); Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- Defender for Endpoint file-event coverage must be confirmed on the target host population.
- RemotePort and Protocol fields are not standard columns on DeviceLogonEvents in Defender XDR; the SMB logon filter using RemotePort == 445 or Protocol == 'SMB' may fail or return no results depending on schema version. DeviceLogonEvents does not expose RemotePort natively.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents, DeviceLogonEvents, DeviceEvents

### KQL

```kql
let PsExecActivity = DeviceProcessEvents
| where FileName =~ "psexec.exe"
    or FileName =~ "psexec64.exe"
    or ProcessCommandLine has "PSEXESVC"
    or (InitiatingProcessFileName =~ "services.exe" and FileName =~ "PSEXESVC.exe")
| project DeviceId, DeviceName, AccountName, PsExecTime = Timestamp, FileName, ProcessCommandLine;
let SmbLogons = DeviceLogonEvents
| where LogonType == "Network"
| project DeviceId, LogonTime = Timestamp, RemoteIP, AccountName;
let InjectionEvents = DeviceEvents
| where ActionType in ("CreateRemoteThreadApiCall", "OpenProcessApiCall", "WriteProcessMemoryApiCall")
| where InitiatingProcessFileName !in~ ("MsMpEng.exe", "svchost.exe", "lsass.exe", "csrss.exe")
| project DeviceId, InjectionTime = Timestamp, InjectionActionType = ActionType, InjectionInitiatingProcess = InitiatingProcessFileName;
PsExecActivity
| join kind=inner SmbLogons on DeviceId
| where LogonTime between ((PsExecTime - 2m) .. (PsExecTime + 5m))
| join kind=leftouter InjectionEvents on DeviceId
| where isempty(InjectionTime) or InjectionTime between (PsExecTime .. (PsExecTime + 15m))
| project DeviceName, AccountName, PsExecTime, FileName, ProcessCommandLine,
    RemoteIP, LogonTime, InjectionActionType, InjectionTime, InjectionInitiatingProcess
| order by PsExecTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Authorized IT administrators using PsExec for remote management over SMB.
- Security tools and EDR agents that use cross-process memory access as part of normal operation and appear in DeviceEvents injection telemetry.
- Jump hosts or bastion servers that routinely authenticate over SMB to managed endpoints.

**Tuning notes:**
- Confirm injection ActionType values are present by running: DeviceEvents → where ActionType in ('CreateRemoteThreadApiCall','OpenProcessApiCall','WriteProcessMemoryApiCall') → summarize count() by ActionType.
- Add known IT admin AccountName values to an exclusion filter on PsExecActivity to suppress authorized usage.
- Consider splitting into two separate hunting queries: one for PsExec+SMB logon correlation and one for injection events, to allow independent tuning.

**Risks / caveats:**
- CreateRemoteThreadApiCall, OpenProcessApiCall, and WriteProcessMemoryApiCall ActionType values in DeviceEvents require MDE advanced telemetry (process injection telemetry) to be enabled; these events are not collected by default in all MDE configurations and must be confirmed present before the injection correlation branch produces results.
- RemotePort and Protocol fields are not standard columns on DeviceLogonEvents in Defender XDR; the SMB logon filter using RemotePort == 445 or Protocol == 'SMB' may fail or return no results depending on schema version. DeviceLogonEvents does not expose RemotePort natively.
- CreateRemoteThreadApiCall, OpenProcessApiCall, and WriteProcessMemoryApiCall must be confirmed present in DeviceEvents before the injection correlation branch is meaningful; run a count of these ActionType values before relying on the injection join.
- The SMB logon correlation uses LogonType == Network without port filtering; this will match any network logon on the device within the time window, not exclusively SMB port 445 connections, potentially broadening the match.

### Triage Runbook

**First 15 minutes:**
- Identify the source account, target host, and timing of the PsExec activity relative to the network logon and any injection telemetry.
- Check whether the process is psexec.exe, psexec64.exe, or PSEXESVC service creation and whether the account is an approved admin account.
- Review the target host for follow-on injection events, suspicious child processes, or new services created shortly after the PsExec event.
- Determine whether the source IP and account correspond to a jump host, admin workstation, or known IT management workflow.

**Evidence to collect:**
- DeviceName, AccountName, PsExecTime, FileName, ProcessCommandLine, RemoteIP, LogonTime, InjectionActionType, InjectionTime, InjectionInitiatingProcess.
- Service creation details and any command line arguments used by PsExec.
- DeviceEvents injection telemetry and the associated initiating process names.
- Any remote administration ticket, change record, or maintenance window associated with the activity.

**Pivot points:**
- DeviceProcessEvents for psexec.exe, psexec64.exe, and PSEXESVC on the same DeviceId and nearby hosts.
- DeviceLogonEvents to identify network logons from the same account or source IP around the event time.
- DeviceEvents for CreateRemoteThreadApiCall, OpenProcessApiCall, and WriteProcessMemoryApiCall on the target host.
- DeviceNetworkEvents for outbound connections from the target host after the PsExec event.

**Benign explanations:**
- Authorized IT administrators using PsExec for remote software deployment or troubleshooting.
- Managed service accounts or jump hosts performing routine remote administration.
- Security tooling that legitimately performs cross-process memory operations and service management.

**Escalation criteria:**
- PsExec is used by a non-admin or unexpected account and is followed by injection telemetry or Meterpreter-like behavior.
- The target host shows new service creation, suspicious child processes, or outbound connections shortly after the PsExec event.
- The source host or account is not recognized as part of approved administration.
- There is evidence of lateral movement beyond a single managed endpoint.

**Containment actions:**
- Isolate the target host if unauthorized lateral movement or injection is confirmed.
- Disable or reset the source account if it is not an approved admin identity.
- Block the source host or jump box from further SMB access if active movement is ongoing.
- Preserve memory and process artifacts before remediation if Meterpreter or injection is suspected.

**Closure criteria:**
- The activity is validated as approved remote administration with a matching ticket and known admin account.
- No injection telemetry, suspicious services, or post-exploitation behavior is found on the target host.
- The source and target hosts are both in the expected management scope.
- A documented allowlist or exception is created for the approved PsExec pattern.

<br/>
---
<br/>

## Detection 5: Peyara Remote Mouse RCE - Unexpected Child Process Spawned by Remote Mouse Application

### Detection Opportunity

Peyara Remote Mouse application spawning unexpected child processes or making outbound connections following inbound network activity, consistent with unauthenticated RCE exploitation

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Modules for SMB-to-Meterpreter, Peyara Remote Mouse RCE exploit, and more — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-07-03-2026/](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-07-03-2026/)
  - Context: A Metasploit exploit module was added for Peyara Remote Mouse v1.0.1 unauthenticated RCE. Successful exploitation would result in the Peyara process spawning attacker-controlled child processes or establishing outbound connections to a Metasploit listener.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1021.002, T1203, T1071, T1071.001
- Products: Peyara Remote Mouse
- Platforms: Windows
- Malware: Meterpreter
- Tools: Metasploit
- Search tags: T1021.002, Peyara Remote Mouse, Windows, Meterpreter, Metasploit, T1203, T1071, T1071.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1203 Exploitation for Client Execution (medium); Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents, DeviceNetworkEvents before scheduling.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let PeyaraProcessNames = dynamic(["RemoteMouse.exe", "PeyaraRemoteMouse.exe", "Remote Mouse.exe"]);
let SuspiciousChildren = dynamic(["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "python.exe"]);
// Branch 1: Peyara spawning suspicious child processes
let ChildSpawn = DeviceProcessEvents
| where InitiatingProcessFileName in~ (PeyaraProcessNames)
| where FileName in~ (SuspiciousChildren)
| project DeviceId, DeviceName, AccountName,
    EventTime = Timestamp,
    DetectionBranch = "ChildProcessSpawn",
    ParentProcess = InitiatingProcessFileName,
    ChildProcessOrFile = FileName,
    ProcessCommandLine,
    SHA256,
    RemoteIP = "",
    RemotePort = int(null);
// Branch 2: Peyara making outbound connections to public IPs
let OutboundNet = DeviceNetworkEvents
| where InitiatingProcessFileName in~ (PeyaraProcessNames)
| where RemoteIPType == "Public"
| project DeviceId, DeviceName, AccountName = "",
    EventTime = Timestamp,
    DetectionBranch = "OutboundConnection",
    ParentProcess = "",
    ChildProcessOrFile = InitiatingProcessFileName,
    ProcessCommandLine = InitiatingProcessCommandLine,
    SHA256 = "",
    RemoteIP,
    RemotePort;
ChildSpawn
| union OutboundNet
| order by EventTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate outbound connections from the Remote Mouse application to the paired mobile controller device if the controller has a public IP or routes through a cloud relay.
- Remote Mouse application updates or telemetry connections to vendor infrastructure.

**Tuning notes:**
- Before scheduling, run the discovery query to confirm the installed executable name and update PeyaraProcessNames accordingly.
- If the application makes routine outbound connections to a fixed set of controller IPs or a vendor relay service, add those IPs to a RemoteIP exclusion in Branch 2.
- Consider promoting to scheduled_rule after executable name is confirmed and a baseline of normal outbound connection behavior is established.

**Risks / caveats:**
- The Peyara Remote Mouse executable name is unconfirmed. PeyaraProcessNames contains candidate names that must be validated against DeviceProcessEvents on hosts where the software is installed before the detection produces any results. If none of the listed names match the installed binary, the query returns nothing.
- The PeyaraProcessNames list must be validated against DeviceProcessEvents on hosts where Peyara Remote Mouse is installed before this detection is meaningful. Run: DeviceProcessEvents → where FileName has_any ('Mouse', 'Peyara', 'RemoteMouse') → summarize count() by FileName to discover the actual process name.
- Legitimate outbound connections from the Remote Mouse application to its paired controller may generate false positives in Branch 2; known controller IPs should be added to a RemoteIP exclusion once identified.
- If Peyara Remote Mouse is not present in the monitored device population, this query will return no results and should not be scheduled.

### Triage Runbook

**First 15 minutes:**
- Confirm the actual Remote Mouse executable name on the host and whether it matches one of the detected process names.
- Review the child process or outbound connection details and determine whether they are consistent with normal Remote Mouse behavior.
- Check whether the host is running the software in a user-facing context or on a server where it should not be present.
- Inspect the command line, parent process, and any nearby network activity for signs of exploitation or payload launch.

**Evidence to collect:**
- DeviceName, AccountName, EventTime, DetectionBranch, ParentProcess, ChildProcessOrFile, ProcessCommandLine, SHA256, RemoteIP, RemotePort.
- Installed application inventory or process list confirming the Remote Mouse binary name.
- Process tree and any subsequent child processes spawned by the Remote Mouse application.
- Network destination reputation and whether the connection is to a known vendor relay or an unknown public IP.

**Pivot points:**
- DeviceProcessEvents filtered to RemoteMouse-related names on the same DeviceId to confirm the installed binary and child process chain.
- DeviceNetworkEvents for the same DeviceId and time window to identify outbound connections from the application or spawned child.
- DeviceLogonEvents to determine which user was active when the event occurred.
- DeviceFileEvents for any dropped files or executables created near the alert time.

**Benign explanations:**
- Legitimate Remote Mouse controller traffic to a paired device or vendor relay.
- Normal application update or telemetry behavior.
- A misidentified process name if the installed binary differs from the candidate names and the alert is based on partial matching.

**Escalation criteria:**
- The Remote Mouse process spawns cmd, PowerShell, or another LOLBin without a valid user action or support context.
- The application makes unexplained public outbound connections and the host is not expected to run this software.
- The executable name is confirmed and the behavior is clearly outside normal product operation.
- There is evidence of a dropped payload or follow-on execution on the host.

**Containment actions:**
- Isolate the host if exploitation is confirmed or strongly suspected.
- Terminate the suspicious child process and preserve the parent process evidence.
- Block the destination IP if it is not a sanctioned relay or controller endpoint.
- Remove or disable the vulnerable application if it is not required for business use.

**Closure criteria:**
- The executable name is validated and the observed behavior matches approved product use.
- The outbound connection is to a known controller or vendor service and no suspicious child process exists.
- No evidence of exploitation, payload drop, or post-exploitation activity is found.
- The detection is tuned or suppressed for the confirmed benign application pattern.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- BusySnake Stealer - Python Stealer Execution with Suspicious Parent or Network Activity: Do not schedule yet; validate as an analyst-led hunt first.
- PsExec SMB Lateral Movement Followed by Meterpreter Service Creation: Do not schedule yet; validate as an analyst-led hunt first.
- PsExec SMB Lateral Movement Followed by Meterpreter Service Creation: RemotePort and Protocol fields are not standard columns on DeviceLogonEvents in Defender XDR; the SMB logon filter using RemotePort == 445 or Protocol == 'SMB' may fail or return no results depending on schema version. DeviceLogonEvents does not expose RemotePort natively.

**Other deployment dependency:**
- PsExec SMB Lateral Movement Followed by Meterpreter Service Creation: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Telemetry availability:**
- Peyara Remote Mouse RCE - Unexpected Child Process Spawned by Remote Mouse Application: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents, DeviceNetworkEvents before scheduling.

**Shared-table notes:**
- DeviceProcessEvents: shared by BusySnake Stealer - Python Stealer Execution with Suspicious Parent or Network Activity; BusySnake Stealer - Office Application Spawning Script Interpreter After Email Delivery; AsyncRAT Dropped and Executed via Compromised ScreenConnect Process; PsExec SMB Lateral Movement Followed by Meterpreter Service Creation; Peyara Remote Mouse RCE - Unexpected Child Process Spawned by Remote Mouse Application
- DeviceNetworkEvents: shared by BusySnake Stealer - Python Stealer Execution with Suspicious Parent or Network Activity; AsyncRAT Dropped and Executed via Compromised ScreenConnect Process; PsExec SMB Lateral Movement Followed by Meterpreter Service Creation; Peyara Remote Mouse RCE - Unexpected Child Process Spawned by Remote Mouse Application
- DeviceFileEvents: shared by BusySnake Stealer - Office Application Spawning Script Interpreter After Email Delivery; AsyncRAT Dropped and Executed via Compromised ScreenConnect Process

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: BusySnake Stealer - Office Application Spawning Script Interpreter After Email Delivery; AsyncRAT Dropped and Executed via Compromised ScreenConnect Process.
2. Resolve environment-mapping detections next: Peyara Remote Mouse RCE - Unexpected Child Process Spawned by Remote Mouse Application.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: BusySnake Stealer - Python Stealer Execution with Suspicious Parent or Network Activity; PsExec SMB Lateral Movement Followed by Meterpreter Service Creation.

### Hunting Agenda and Promotion Criteria

- BusySnake Stealer - Python Stealer Execution with Suspicious Parent or Network Activity: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- PsExec SMB Lateral Movement Followed by Meterpreter Service Creation: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- Peyara Remote Mouse RCE - Unexpected Child Process Spawned by Remote Mouse Application: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents, DeviceNetworkEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
