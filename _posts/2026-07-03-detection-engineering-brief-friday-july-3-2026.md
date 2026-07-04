---
layout: post
title: "Detection Engineering Brief - Friday, July 3, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-03
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Metasploit
  - PsExec
  - Meterpreter
  - SMB
  - Windows
  - T1021.002
  - T1210
  - ScreenConnect
  - AsyncRAT
  - Armored Likho
  - BusySnake Stealer
  - Python
  - T1566
  - T1059
  - T1218
  - T1218.011
  - T1219
  - T1059.006
  - T1204
  - T1204.002
---

## Detection Engineering Summary

This brief produced 3 detection candidates.

1 production candidate, 2 hunting-only, 0 require environment mapping, and 0 rejected.

3 detections include KQL. 3 include ATT&CK mappings. 3 include triage guidance.

Search metadata extracted for this run includes: Metasploit, PsExec, Meterpreter, SMB, Windows, T1021.002, T1210, ScreenConnect, AsyncRAT, Armored Likho, BusySnake Stealer, Python, T1566, T1059, T1218, T1218.011, T1219, T1059.006, T1204, T1204.002.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: ScreenConnect Agent Spawning Suspicious Child Process Consistent with AsyncRAT Delivery; Python Stealer Execution from Unusual Parent or User-Writable Path Consistent with BusySnake Campaign.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: PsExec Spawning Interactive Shell via SMB Session Upgrade

### Detection Opportunity

PsExec used to upgrade an authenticated SMB session to a Meterpreter shell by spawning cmd.exe or powershell.exe as a child process over a remote SMB logon context.

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Modules for SMB-to-Meterpreter, Peyara Remote Mouse RCE exploit, and more — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-07-03-2026/](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-07-03-2026/)
  - Context: Rapid7 documented a new Metasploit module that uses PsExec to upgrade an existing SMB session to a Meterpreter shell. The module authenticates over SMB and leverages PsExec to spawn an interactive shell process on the remote host, enabling post-exploitation access.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1021.002, T1210
- Products: SMB, Meterpreter, PsExec
- Platforms: Windows
- Malware: Not specified
- Tools: Metasploit, PsExec
- Search tags: Metasploit, PsExec, Meterpreter, SMB, Windows, T1021.002, T1210

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1021.002 SMB/Windows Admin Shares/ T1021.002 SMB/Windows Admin Shares (high); Lateral Movement: T1210 Exploitation of Remote Services (medium)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceProcessEvents, DeviceLogonEvents

### KQL

```kql
let lookbackSeconds = 900;
let psexec_shells = DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("psexec.exe", "psexesvc.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe")
| project
    ShellTime = Timestamp,
    DeviceName,
    AccountName,
    AccountDomain,
    ProcessCommandLine,
    FileName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    ProcessId;
let smb_logons = DeviceLogonEvents
| where Timestamp > ago(1d)
| where LogonType == 3
| where isnotempty(RemoteIP)
| where RemoteIP != "127.0.0.1"
| project LogonTime = Timestamp, DeviceName, AccountName, AccountDomain, RemoteIP;
psexec_shells
| join kind=inner smb_logons on DeviceName, AccountName
| where abs(datetime_diff('second', ShellTime, LogonTime)) <= lookbackSeconds
| project
    ShellTime,
    LogonTime,
    DeviceName,
    AccountName,
    AccountDomain,
    RemoteIP,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    ProcessId
| order by ShellTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate IT administrators using PsExec to remotely manage endpoints over SMB will match this detection; allowlisting known admin source IPs or service accounts in RemoteIP or AccountName is recommended.
- Automated deployment tools that invoke PsExec to run cmd.exe or powershell.exe as part of software installation over SMB will generate matches.
- Monitoring or patch management agents that authenticate via SMB and then invoke shells may trigger this rule.

**Tuning notes:**
- Increase lookbackSeconds to 1800 (30 minutes) if ingestion latency is observed causing missed correlations in your environment.
- Add an AccountName exclusion list for known administrative service accounts to reduce noise from legitimate IT operations.
- Consider adding a RemoteIP allowlist for known jump-host or bastion IP ranges used by your IT team.
- If psexesvc.exe is renamed in your environment, supplement with a SHA256 hash filter or FolderPath check against the Windows system32 path.

**Risks / caveats:**
- DeviceLogonEvents.RemoteIP may be empty for logons originating from the local loopback or from domain controllers acting as authentication proxies; such events will be filtered out by the isnotempty(RemoteIP) clause, potentially missing some lateral-movement patterns.
- DeviceLogonEvents requires Microsoft Defender for Endpoint Plan 2 or Microsoft 365 Defender licensing with endpoint onboarding; environments without MDE onboarding will return no results from this table.
- The 15-minute (900-second) correlation window is a starting point; environments with slow SMB authentication or delayed process telemetry ingestion may require widening this window.
- AccountName-based join may produce cross-account false matches if multiple accounts share the same name across different devices in the same time window; adding AccountDomain to the join key reduces this risk.

### Triage Runbook

**First 15 minutes:**
- Confirm whether the source RemoteIP and AccountName belong to an approved admin jump host, IT support account, or automation system.
- Review the process tree on the target host to verify psexec.exe or psexesvc.exe spawned cmd.exe, powershell.exe, or pwsh.exe and note the exact command line.
- Check whether the logon was LogonType 3 from the same RemoteIP and whether there are other recent remote logons or service creations on the host.
- Look for follow-on activity from the same account or source IP such as remote service creation, scheduled task creation, credential access, or additional lateral movement.

**Evidence to collect:**
- ShellTime, LogonTime, DeviceName, AccountName, AccountDomain, RemoteIP, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, ProcessId.
- Any matching DeviceLogonEvents for the same account and device in the prior and subsequent 24 hours.
- Any DeviceProcessEvents showing psexec.exe, psexesvc.exe, cmd.exe, powershell.exe, or pwsh.exe on the target and the initiating host.
- Endpoint owner, business justification, and whether the source IP is a known admin workstation or bastion host.

**Pivot points:**
- DeviceProcessEvents for the target host and source host to reconstruct the process tree around the shell spawn.
- DeviceLogonEvents for the same AccountName and DeviceName to identify other remote logons and source IPs.
- DeviceNetworkEvents to identify outbound connections from the target immediately after the shell spawn.
- DeviceRegistryEvents and DeviceServiceEvents, if available, to check for service-based persistence or PsExec service artifacts.

**Benign explanations:**
- Planned remote administration by IT using PsExec from a known management host.
- Software deployment or patch tooling that uses PsExec to run maintenance commands over SMB.
- Monitoring or support agents that legitimately invoke cmd.exe or powershell.exe during remote troubleshooting.

**Escalation criteria:**
- The RemoteIP is unknown, external, or not associated with an approved admin host.
- The account is a standard user, newly created, disabled, or otherwise not expected to perform remote administration.
- The command line shows suspicious actions such as downloading payloads, disabling security tools, dumping credentials, or creating persistence.
- There are additional signs of compromise on the host or adjacent systems, including multiple lateral movement attempts or unusual service creation.

**Containment actions:**
- If the activity is not an approved admin action, isolate the target host from the network.
- Disable or reset the implicated account if credential misuse is suspected and coordinate with identity teams.
- Block the source IP or jump host if it is confirmed malicious or unauthorized.
- Preserve volatile evidence and avoid rebooting the host until process and log data are collected.

**Closure criteria:**
- Confirmed with the business owner as authorized remote administration from a known source and the command line matches expected maintenance activity.
- No additional suspicious activity is found on the target or source host after review of adjacent telemetry.
- The account, source IP, and command pattern are added to an approved allowlist or suppression list with documented justification.

<br/>
---
<br/>

## Detection 2: ScreenConnect Agent Spawning Suspicious Child Process Consistent with AsyncRAT Delivery

### Detection Opportunity

Compromised ScreenConnect software spawning unexpected child processes such as script interpreters or RAT-like binaries, consistent with AsyncRAT being dropped and executed through the RMM agent.

### Intelligence Context

- Securelist: The SOC Files: ScreenConnect masked as freeware. An inside look at a large-scale campaign — [https://securelist.com/tr/the-soc-files-screenconnect-campaign-with-asyncrat/120472/](https://securelist.com/tr/the-soc-files-screenconnect-campaign-with-asyncrat/120472/)
  - Context: Kaspersky researchers documented a large-scale campaign distributing trojanized ScreenConnect software that drops and executes AsyncRAT on victim hosts. The delivery mechanism relies on the ScreenConnect agent process spawning malicious child processes to stage the RAT payload.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1218, T1218.011, T1219
- Products: ScreenConnect
- Platforms: Windows
- Malware: AsyncRAT
- Tools: Not specified
- Search tags: ScreenConnect, AsyncRAT, Windows, T1059, T1218, T1218.011, T1219

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (medium); Execution: T1218 System Binary Proxy Execution/ T1218.011 Rundll32 (medium); Command and Control: T1219 Remote Access Software (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let lookbackSeconds = 600;
let screenconnect_parents = dynamic(["ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe", "ScreenConnect.WindowsBackstageShell.exe"]);
let suspicious_children = dynamic(["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"]);
let child_procs = DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ (screenconnect_parents)
| where FileName in~ (suspicious_children)
| project
    ChildTime = Timestamp,
    DeviceName,
    AccountName,
    ChildProcess = FileName,
    ChildFolderPath = FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessId,
    ChildSHA256 = SHA256;
let dropped_files = DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ (screenconnect_parents)
| where FolderPath matches regex @"(?i)(\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\)"
| project
    FileTime = Timestamp,
    DeviceName,
    DroppedFile = FileName,
    DroppedPath = FolderPath;
let high_fidelity = child_procs
| join kind=inner dropped_files on DeviceName
| where abs(datetime_diff('second', ChildTime, FileTime)) <= lookbackSeconds
| summarize
    ChildProcesses = make_set(ChildProcess),
    ChildPaths = make_set(ChildFolderPath),
    DroppedFiles = make_set(DroppedFile),
    DroppedPaths = make_set(DroppedPath),
    Commands = make_set(ProcessCommandLine),
    Hashes = make_set(ChildSHA256)
    by DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessId, EventTime = bin(ChildTime, 1h)
| extend SignalType = "ChildSpawnWithFileDrop";
let broad_hunt = child_procs
| summarize
    ChildProcesses = make_set(ChildProcess),
    ChildPaths = make_set(ChildFolderPath),
    DroppedFiles = make_set(""),
    DroppedPaths = make_set(""),
    Commands = make_set(ProcessCommandLine),
    Hashes = make_set(ChildSHA256)
    by DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessId, EventTime = bin(ChildTime, 1h)
| extend SignalType = "ChildSpawnOnly";
union high_fidelity, broad_hunt
| project SignalType, EventTime, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessId, ChildProcesses, ChildPaths, Commands, Hashes, DroppedFiles, DroppedPaths
| order by EventTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate ScreenConnect remote support sessions where a technician opens a command prompt or PowerShell window on the remote host will match the child-process-only path.
- Automated software deployment or patch management performed through ScreenConnect that invokes certutil.exe, bitsadmin.exe, or rundll32.exe will generate matches.
- ScreenConnect-managed endpoint configuration scripts that use wscript.exe or cscript.exe for legitimate automation will appear in results.

**Tuning notes:**
- After baselining, add known-legitimate child process names invoked by ScreenConnect in your environment to an exclusion filter on ChildProcess to reduce noise in the broad_hunt path.
- Reduce the bin size from 1h to 15m if granular session-level triage is needed.
- If custom-branded ScreenConnect is deployed, update screenconnect_parents with the actual executable names used in your environment.
- Consider promoting only the high_fidelity path (SignalType == 'ChildSpawnWithFileDrop') to a scheduled rule after baselining, while retaining the broad_hunt path for periodic hunting queries.

**Risks / caveats:**
- DeviceFileEvents requires Microsoft Defender for Endpoint with file activity telemetry enabled; environments where file monitoring is not configured for the relevant endpoints will return no results from this table.
- has_any() with a dynamic array containing full process names performs a substring match, not an exact match; InitiatingProcessFileName has_any (screenconnect_parents) will match any process whose name contains the substring 'ScreenConnect.ClientService.exe' as a substring, which is the intended behaviour but could match unexpected process names in edge cases. The improved query uses in~ for exact matching.
- The broad_hunt path (ChildSpawnOnly) will generate significant noise in environments where ScreenConnect is actively used for remote support; analyst triage is required to distinguish malicious from legitimate sessions.
- Custom-branded or renamed ScreenConnect deployments will not match the screenconnect_parents list; the list must be updated to reflect the actual process names in the environment.

### Triage Runbook

**First 15 minutes:**
- Identify whether the ScreenConnect parent process and host are managed by your IT or MSP team and whether a support session was active at the alert time.
- Review the child process name, command line, and folder path to see whether it is a common support action or a suspicious interpreter/proxy binary.
- Check whether a file was dropped in a user-writable path near the same time and whether the dropped file name or hash is known or suspicious.
- Look for evidence of interactive operator behavior such as encoded PowerShell, script execution, archive extraction, or additional payload launches.

**Evidence to collect:**
- SignalType, EventTime, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessId, ChildProcess, ChildFolderPath, ProcessCommandLine, ChildSHA256, DroppedFiles, DroppedPaths, Commands.
- DeviceProcessEvents for the ScreenConnect parent and all child processes on the host during the session window.
- DeviceFileEvents for dropped files in Users, AppData, Temp, ProgramData, or Public paths.
- Any ScreenConnect session logs or remote support ticket references that explain the activity.

**Pivot points:**
- DeviceProcessEvents to enumerate all children of ScreenConnect.ClientService.exe, ScreenConnect.WindowsClient.exe, or ScreenConnect.WindowsBackstageShell.exe on the same host.
- DeviceFileEvents to find recent drops in user-writable directories and correlate them to the child process time.
- DeviceNetworkEvents to identify outbound connections from the child process or ScreenConnect parent to suspicious infrastructure.
- DeviceImageLoadEvents or DeviceFileEvents, if available, to check for DLL side-loading or staged payload execution.

**Benign explanations:**
- A legitimate remote support technician opening cmd.exe or PowerShell during a helpdesk session.
- Automated software deployment or configuration scripts run through ScreenConnect by IT.
- Endpoint management tasks that use certutil.exe, rundll32.exe, wscript.exe, or cscript.exe for approved administration.

**Escalation criteria:**
- The child process is a known malware loader, script interpreter with suspicious arguments, or proxy execution binary used outside approved support workflows.
- A dropped file appears in a user-writable path and is not attributable to a documented support action.
- The ScreenConnect host is unmanaged, the session is unexpected, or the parent process path/hash does not match the approved ScreenConnect deployment.
- There is evidence of post-execution behavior such as persistence, credential theft, or outbound command-and-control traffic.

**Containment actions:**
- If the session is unauthorized or clearly malicious, terminate the ScreenConnect session and isolate the affected endpoint.
- Disable or revoke the ScreenConnect account or access token used for the session if compromise is suspected.
- Quarantine suspicious dropped files and block associated hashes or domains if identified.
- Coordinate with IT to suspend remote support access until the legitimacy of the session is confirmed.

**Closure criteria:**
- The activity is confirmed as a documented support or deployment action and the child process behavior matches known-good baselines.
- No malicious file drops, suspicious command lines, or follow-on compromise indicators are found.
- The parent/child pattern is documented for future allowlisting or tuning, with the specific support workflow recorded.

<br/>
---
<br/>

## Detection 3: Python Stealer Execution from Unusual Parent or User-Writable Path Consistent with BusySnake Campaign

### Detection Opportunity

Python interpreter spawned from a non-standard parent process or executed from a user-writable directory, consistent with the BusySnake Stealer deployment pattern used by Armored Likho.

### Intelligence Context

- Securelist: Armored Likho digging a snake pit: inside the covert BusySnake Stealer campaign — [https://securelist.com/tr/armored-likho-apt-with-busysnake-stealer/120292/](https://securelist.com/tr/armored-likho-apt-with-busysnake-stealer/120292/)
  - Context: Armored Likho deployed BusySnake Stealer, a Python-based credential and data theft tool, as part of a spear-phishing campaign. The stealer is executed via the Python interpreter and is delivered through phishing lures, meaning the Python process is likely spawned from an email client, browser, or document handler rather than a legitimate development environment.

### Search Metadata

- CVEs: Not specified
- Threat actors: Armored Likho
- ATT&CK tags: T1566, T1059, T1059.006, T1204, T1204.002
- Products: Not specified
- Platforms: Windows, Python
- Malware: BusySnake Stealer
- Tools: Not specified
- Search tags: Armored Likho, BusySnake Stealer, Windows, Python, T1566, T1059, T1059.006, T1204, T1204.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.006 Python (high); Execution: T1204 User Execution/ T1204.002 Malicious File (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let writable_paths = dynamic(["\\AppData\\", "\\Temp\\", "\\Downloads\\", "\\ProgramData\\", "\\Users\\Public\\"]);
let phishing_parents = dynamic(["outlook.exe", "thunderbird.exe", "winword.exe", "excel.exe", "powerpnt.exe", "msedge.exe", "chrome.exe", "firefox.exe", "explorer.exe", "wscript.exe", "mshta.exe"]);
let python_procs = DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("python.exe", "pythonw.exe")
| extend FromPhishingParent = InitiatingProcessFileName in~ (phishing_parents)
| extend FromWritablePath = FolderPath has_any (writable_paths) or ProcessCommandLine has_any (writable_paths)
| where FromPhishingParent or FromWritablePath
| extend SignalType = case(
    FromPhishingParent and FromWritablePath, "PhishingParentAndWritablePath",
    FromPhishingParent, "PhishingParent",
    "WritablePath"
  )
| project
    Timestamp,
    DeviceName,
    AccountName,
    AccountDomain,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ProcessCommandLine,
    SHA256,
    InitiatingProcessSHA256,
    SignalType;
let dropped_py_files = DeviceFileEvents
| where Timestamp > ago(1d)
| where FileName endswith ".py" or FileName endswith ".pyc"
| where FolderPath has_any (writable_paths)
| project FileTime = Timestamp, DeviceName, DroppedFile = FileName, DroppedPath = FolderPath;
python_procs
| join kind=leftouter dropped_py_files on DeviceName
| where isempty(FileTime) or abs(datetime_diff('minute', Timestamp, FileTime)) <= 30
| project
    SignalType,
    Timestamp,
    DeviceName,
    AccountName,
    AccountDomain,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ProcessCommandLine,
    SHA256,
    InitiatingProcessSHA256,
    DroppedFile,
    DroppedPath,
    FileTime
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Developers or data analysts who run Python scripts from Downloads or AppData directories will match the writable-path path.
- Automated testing frameworks or CI/CD agents that invoke Python from Office or browser processes in sandboxed environments will match the phishing-parent path.
- Python-based productivity tools (e.g., Jupyter notebooks launched from a browser) will match if the browser is in the phishing_parents list.
- Portable Python distributions installed in AppData by end users for legitimate purposes will match the writable-path path.

**Tuning notes:**
- Add an AccountName or device-group exclusion for known developer accounts or developer workstation groups to reduce noise in engineering environments.
- Prioritise triage of SignalType == 'PhishingParentAndWritablePath' and 'PhishingParent' rows, as these have the strongest behavioural alignment with the BusySnake campaign delivery pattern.
- After baselining, consider promoting only the PhishingParent signal path to a scheduled rule with a tighter 1-day lookback.
- If portable Python distributions are common in your environment (python.exe in AppData), add a SHA256 allowlist for known-good Python interpreter hashes to reduce writable-path FPs.

**Risks / caveats:**
- DeviceFileEvents requires Microsoft Defender for Endpoint with file activity telemetry enabled; environments where file monitoring is not configured will return no results from this table for the .py file correlation.
- FolderPath in DeviceProcessEvents reflects the folder of the executed binary (python.exe), not the script argument path; the writable_paths filter on FolderPath will only match if python.exe itself is installed in a user-writable location, which is the intended signal but may not match all delivery patterns where python.exe is in Program Files but the script is in AppData.
- The leftouter join with isempty(FileTime) means the query fires on Python execution from a phishing parent or writable path even without a correlated .py file drop; this is intentional to catch cases where the script was pre-staged, but it increases FP volume.
- The 1-day lookback reduces result volume for scheduled use but may miss delayed execution of pre-staged scripts; extend to 7 days for ad-hoc hunting.

### Triage Runbook

**First 15 minutes:**
- Check the initiating parent process and user context to see whether python.exe or pythonw.exe was launched from Outlook, Word, Excel, browser, or script host activity.
- Review the command line and folder path for user-writable locations such as AppData, Temp, Downloads, ProgramData, or Public.
- Confirm whether the device belongs to a developer, data science, or automation user who routinely runs Python from nonstandard locations.
- Look for immediate signs of credential theft or staging, including archive extraction, browser data access, suspicious child processes, or outbound connections.

**Evidence to collect:**
- SignalType, Timestamp, DeviceName, AccountName, AccountDomain, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessCommandLine, SHA256, InitiatingProcessSHA256, DroppedFile, DroppedPath, FileTime.
- DeviceProcessEvents for the parent process, python.exe/pythonw.exe, and any child processes spawned shortly after execution.
- DeviceFileEvents for .py or .pyc files and any other files created in user-writable paths around the alert time.
- Email, browser, or document activity that explains how the Python process was launched, if available in your environment.

**Pivot points:**
- DeviceProcessEvents to enumerate all Python executions by the same account and host over the prior 7 days.
- DeviceFileEvents to identify recently dropped scripts, archives, or executables in writable directories.
- DeviceNetworkEvents to identify suspicious outbound connections from python.exe or pythonw.exe.
- DeviceLogonEvents and DeviceImageLoadEvents, if available, to correlate user logon context and loaded libraries during execution.

**Benign explanations:**
- A developer or analyst running Python from Downloads, AppData, or a portable distribution for legitimate work.
- A browser-based notebook, automation tool, or internal utility that launches Python as part of normal use.
- A sanctioned script or test harness executed from a user-writable directory in a lab or sandbox environment.

**Escalation criteria:**
- Python was launched from an email client, browser, Office app, or script host on a non-developer endpoint and the command line is suspicious.
- The process or dropped files access browser credentials, mail data, or other sensitive user artifacts.
- The host shows additional compromise indicators such as persistence, encoded commands, or suspicious network beacons.
- The account or device is not expected to run Python and the activity cannot be tied to an approved business purpose.

**Containment actions:**
- If the execution is not attributable to legitimate work, isolate the host to prevent further theft or staging.
- Reset credentials for the affected user if browser, mail, or token theft is suspected.
- Quarantine suspicious scripts or archives and block known malicious hashes or outbound destinations.
- Preserve the user profile and relevant files for forensic review before remediation.

**Closure criteria:**
- The Python execution is confirmed as approved development, automation, or testing activity with supporting evidence.
- No malicious script, payload, or suspicious network behavior is found after reviewing adjacent telemetry.
- The account, device group, or known-good hash is documented for tuning or suppression.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Other deployment dependency:**
- PsExec Spawning Interactive Shell via SMB Session Upgrade: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Schema / correlation keys:**
- ScreenConnect Agent Spawning Suspicious Child Process Consistent with AsyncRAT Delivery: Do not schedule yet; validate as an analyst-led hunt first.
- Python Stealer Execution from Unusual Parent or User-Writable Path Consistent with BusySnake Campaign: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- DeviceProcessEvents: shared by PsExec Spawning Interactive Shell via SMB Session Upgrade; ScreenConnect Agent Spawning Suspicious Child Process Consistent with AsyncRAT Delivery; Python Stealer Execution from Unusual Parent or User-Writable Path Consistent with BusySnake Campaign
- DeviceFileEvents: shared by ScreenConnect Agent Spawning Suspicious Child Process Consistent with AsyncRAT Delivery; Python Stealer Execution from Unusual Parent or User-Writable Path Consistent with BusySnake Campaign

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: PsExec Spawning Interactive Shell via SMB Session Upgrade.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: ScreenConnect Agent Spawning Suspicious Child Process Consistent with AsyncRAT Delivery; Python Stealer Execution from Unusual Parent or User-Writable Path Consistent with BusySnake Campaign.

### Hunting Agenda and Promotion Criteria

- ScreenConnect Agent Spawning Suspicious Child Process Consistent with AsyncRAT Delivery: Do not schedule yet; validate as an analyst-led hunt first..
- Python Stealer Execution from Unusual Parent or User-Writable Path Consistent with BusySnake Campaign: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
