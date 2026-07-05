---
layout: post
title: "Detection Engineering Brief - Sunday, July 5, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-05
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Metasploit
  - PsExec
  - Meterpreter
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
  - T1059.001
  - T1059.003
  - T1218
  - T1218.011
  - T1059.006
---

## Detection Engineering Summary

This brief produced 3 detection candidates.

1 production candidate, 2 hunting-only, 0 require environment mapping, and 0 rejected.

3 detections include KQL. 3 include ATT&CK mappings. 3 include triage guidance.

Search metadata extracted for this run includes: Metasploit, PsExec, Meterpreter, Windows, T1021.002, T1210, ScreenConnect, AsyncRAT, Armored Likho, BusySnake Stealer, Python, T1566, T1059, T1059.001, T1059.003, T1218, T1218.011, T1059.006.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: PsExec SMB Session Upgrade to Meterpreter Shell; BusySnake Python Stealer Execution from Suspicious Path.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: PsExec SMB Session Upgrade to Meterpreter Shell

### Detection Opportunity

PsExec used to upgrade an SMB session to a Meterpreter shell by spawning cmd.exe or powershell.exe following a remote SMB logon

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Modules for SMB-to-Meterpreter, Peyara Remote Mouse RCE exploit, and more — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-07-03-2026/](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-07-03-2026/)
  - Context: A new Metasploit module uses PsExec to upgrade an existing SMB session to a Meterpreter shell. The module spawns a shell process via PsExec after authenticating over SMB, enabling post-exploitation capability from an existing credential or session.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1021.002, T1210
- Products: Metasploit, PsExec
- Platforms: Windows
- Malware: Not specified
- Tools: Metasploit, PsExec, Meterpreter
- Search tags: Metasploit, PsExec, Meterpreter, Windows, T1021.002, T1210

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1021.002 SMB/Windows Admin Shares/ T1021.002 SMB/Windows Admin Shares (high); Lateral Movement: T1210 Exploitation of Remote Services (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceLogonEvents

### KQL

```kql
let psexec_shells = DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("psexec.exe", "psexec64.exe")
| where FileName in~ ("cmd.exe", "powershell.exe")
| project ShellTime = Timestamp, DeviceName, AccountName, AccountDomain,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessParentFileName, ChildProcess = FileName, ProcessCommandLine;
let smb_logons = DeviceLogonEvents
| where Timestamp > ago(7d)
| where LogonType == 3
| where isnotempty(RemoteIP)
| where RemoteIP !in ("127.0.0.1", "::1")
| project LogonTime = Timestamp, DeviceName, AccountName, AccountDomain, RemoteIP;
smb_logons
| join kind=inner psexec_shells on DeviceName, AccountName, AccountDomain
| where ShellTime >= LogonTime and datetime_diff('second', ShellTime, LogonTime) <= 120
| project ShellTime, LogonTime, DeviceName, AccountName, AccountDomain,
    RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessParentFileName, ChildProcess, ProcessCommandLine
| order by ShellTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- IT administrators using PsExec for legitimate remote management will generate hits when they also have a concurrent SMB logon on the target device.
- Automated deployment or patch management tools that invoke PsExec may correlate with background SMB authentication events.

**Tuning notes:**
- Scope DeviceName to server device groups or high-value endpoint tags to reduce volume from workstations where PsExec is used routinely by IT.
- Add an AccountName exclusion list for known IT admin accounts after baselining to suppress recurring legitimate hits.
- Consider extending the lookback to 14 days during initial hunting to establish a baseline before scheduling.

**Risks / caveats:**
- The 120-second correlation window may need widening in environments where SMB authentication and PsExec execution are separated by longer delays due to network latency or tooling behavior.
- Exfiltration or post-exploitation activity occurring after the shell spawn is not covered by this query.
- AccountDomain may be empty for local accounts; the join on AccountDomain should be validated against the environment's logon telemetry to confirm it does not over-restrict results.

### Triage Runbook

**First 15 minutes:**
- Confirm the target device, account, RemoteIP, and exact ShellTime/LogonTime pairing to verify the SMB logon preceded the shell spawn within the expected window.
- Check whether the AccountName and AccountDomain belong to a known admin or automation account and whether the source RemoteIP maps to a management subnet or jump host.
- Review the parent and initiating process command lines for PsExec usage patterns, especially remote service creation, encoded commands, or execution of cmd.exe/powershell.exe for post-exploitation.
- Look for nearby signs of compromise on the target host such as new services, scheduled tasks, suspicious logons, or additional remote process creation from the same account.

**Evidence to collect:**
- DeviceProcessEvents for the target host covering the PsExec launch, child shell, and any follow-on processes.
- DeviceLogonEvents for the same account and device to confirm the SMB logon source and timing.
- Process ancestry including InitiatingProcessParentFileName and InitiatingProcessCommandLine to identify the operator or tool that launched PsExec.
- Any recent security logs showing service creation, remote admin activity, or additional lateral movement from the same account or RemoteIP.

**Pivot points:**
- DeviceProcessEvents filtered on the same DeviceName and AccountName to find additional cmd.exe, powershell.exe, or service-related activity around the alert time.
- DeviceLogonEvents filtered on the same AccountName, AccountDomain, and RemoteIP to determine whether the source host is a known admin workstation or jump box.
- DeviceNetworkEvents on the target host for the same time window to identify outbound connections or beaconing after the shell spawn.
- If available, endpoint or identity telemetry for the account to check for recent password resets, MFA prompts, or unusual sign-in locations.

**Benign explanations:**
- IT administrators may legitimately use PsExec for remote software deployment, troubleshooting, or service management.
- Automated patching or orchestration tools may create a matching SMB logon and spawn cmd.exe or powershell.exe on managed servers.
- Some remote support workflows use PsExec-like behavior during maintenance windows, especially on server fleets.

**Escalation criteria:**
- The account is not a known admin or automation account, or the RemoteIP is not associated with a trusted management host.
- The shell command line shows suspicious post-exploitation activity such as encoded PowerShell, credential dumping, or disabling security tools.
- There are additional signs of compromise on the target host, including new services, persistence, or multiple lateral movement attempts.
- The same source account or RemoteIP is seen touching multiple hosts in a short period without an approved change window.

**Containment actions:**
- If unauthorized activity is confirmed, isolate the target host from the network to stop further lateral movement.
- Disable or reset the involved account if it is not a sanctioned admin account or if compromise is suspected.
- Block the source RemoteIP or quarantine the source management host if it is not trusted and appears to be the operator system.

**Closure criteria:**
- The activity is confirmed as approved remote administration or automated management from a trusted account and source host.
- The command line and process ancestry match documented maintenance behavior with no additional suspicious follow-on activity.
- No other hosts, accounts, or network indicators show related lateral movement or post-exploitation behavior.

<br/>
---
<br/>

## Detection 2: AsyncRAT Dropped via ScreenConnect Agent Child Process

### Detection Opportunity

ScreenConnect agent spawning suspicious child processes consistent with AsyncRAT delivery, including scripting engines or dropped executables in user-writable paths

### Intelligence Context

- Securelist: The SOC Files: ScreenConnect masked as freeware. An inside look at a large-scale campaign — [https://securelist.com/tr/the-soc-files-screenconnect-campaign-with-asyncrat/120472/](https://securelist.com/tr/the-soc-files-screenconnect-campaign-with-asyncrat/120472/)
  - Context: Attackers distributed trojanized ScreenConnect software masquerading as freeware. Once installed, the compromised ScreenConnect agent dropped AsyncRAT onto victim systems. Detection focuses on the ScreenConnect process spawning scripting engines or writing executables to user-writable directories.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.001, T1059.003, T1218, T1218.011
- Products: ScreenConnect
- Platforms: Windows
- Malware: AsyncRAT
- Tools: Not specified
- Search tags: ScreenConnect, AsyncRAT, Windows, T1059, T1059.001, T1059.003, T1218, T1218.011

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.001 PowerShell (high); Execution: T1059 Command and Scripting Interpreter/ T1059.003 Windows Command Shell (high); Defense Evasion: T1218 System Binary Proxy Execution/ T1218.011 Rundll32 (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let sc_suspicious_children = DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (
    "ScreenConnect.ClientService.exe",
    "ScreenConnect.WindowsClient.exe"
  )
| where FileName in~ (
    "powershell.exe", "cmd.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"
  )
| project EventTime = Timestamp, DeviceName, AccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    ChildProcessOrFile = FileName, FolderPath = "",
    ProcessCommandLine,
    DetectionBranch = "ProcessSpawn";
let sc_dropped_files = DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where InitiatingProcessFileName in~ (
    "ScreenConnect.ClientService.exe",
    "ScreenConnect.WindowsClient.exe"
  )
| where FolderPath has_any ("\\AppData\\", "\\Temp\\", "\\ProgramData\\")
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".ps1"
| project EventTime = Timestamp, DeviceName, AccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine = "",
    InitiatingProcessParentFileName = "",
    ChildProcessOrFile = FileName, FolderPath,
    ProcessCommandLine = "",
    DetectionBranch = "FileDrop";
sc_suspicious_children
| union sc_dropped_files
| order by EventTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate ScreenConnect remote support sessions may spawn cmd.exe when an IT administrator opens a remote shell; the process spawn branch will generate these hits.
- ScreenConnect auto-update mechanisms may write executables to ProgramData; analysts should verify FolderPath does not correspond to the ScreenConnect installation or update directory.

**Tuning notes:**
- After baselining, add an AccountName exclusion for known IT administrator accounts to suppress legitimate remote support shell spawns in the process spawn branch.
- If the environment uses a non-default ScreenConnect installation path, verify that file drop hits in ProgramData are not from the ScreenConnect update mechanism by checking the full FolderPath.
- Consider splitting the union into two separate scheduled rules with different severities: FileDrop as High and ProcessSpawn as Medium, to allow independent tuning.

**Risks / caveats:**
- Custom-renamed ScreenConnect deployments using non-default process names will not be detected.
- ScreenConnect update processes writing legitimate binaries to ProgramData may generate file drop hits; analysts should correlate FolderPath against the known ScreenConnect installation directory.
- The process spawn branch will produce hits for legitimate IT remote support sessions; volume will depend on how frequently administrators use ScreenConnect to open shells.

### Triage Runbook

**First 15 minutes:**
- Identify whether the hit is a ProcessSpawn or FileDrop branch and prioritize FileDrop hits in user-writable paths as higher risk.
- Review the ScreenConnect parent process command line, child process name, and FolderPath to see whether the activity matches normal remote support or suspicious payload staging.
- Check whether the affected user and device are expected to use ScreenConnect and whether the timing aligns with a known support session or maintenance ticket.
- Look for immediate follow-on activity such as PowerShell execution, script launchers, proxy execution binaries, or new executables appearing in AppData, Temp, or ProgramData.

**Evidence to collect:**
- DeviceProcessEvents for the ScreenConnect process tree, including InitiatingProcessParentFileName and InitiatingProcessCommandLine.
- DeviceFileEvents for FileCreated activity from ScreenConnect, especially in AppData, Temp, and ProgramData.
- Any ScreenConnect session logs or remote support records that identify the operator, ticket, or approved maintenance window.
- DeviceNetworkEvents for the same host and time window to identify outbound connections after the suspicious child process or file drop.

**Pivot points:**
- DeviceProcessEvents filtered on ScreenConnect.ClientService.exe and ScreenConnect.WindowsClient.exe to find additional child processes on the same host.
- DeviceFileEvents filtered on the same DeviceName and FolderPath to identify other dropped executables, DLLs, or scripts.
- DeviceNetworkEvents for the same DeviceName and time window to identify C2-like connections or unusual outbound destinations.
- If available, ScreenConnect audit or admin logs to verify whether the session was initiated by a trusted support user.

**Benign explanations:**
- Legitimate remote support sessions may spawn cmd.exe or PowerShell when an administrator opens a shell during troubleshooting.
- ScreenConnect update or installation activity may write files to ProgramData and can resemble a dropper pattern if the path is not validated.
- Some IT workflows use scripting or proxy execution binaries during approved remote maintenance.

**Escalation criteria:**
- The child process is a scripting engine or proxy execution binary and there is no approved support activity or ticket.
- A FileDrop hit places an executable, DLL, or script in a user-writable directory outside the known ScreenConnect installation or update path.
- The host shows additional suspicious behavior such as persistence creation, credential access, or outbound connections consistent with malware execution.
- Multiple endpoints show the same ScreenConnect-related suspicious behavior, suggesting a broader campaign.

**Containment actions:**
- If malicious activity is confirmed, terminate the suspicious ScreenConnect session and isolate the affected host.
- Disable or revoke the ScreenConnect account or access path used for the suspicious session if it is unauthorized.
- Quarantine or remove the dropped payloads and block any confirmed malicious outbound destinations if identified.

**Closure criteria:**
- The activity is tied to a documented, approved ScreenConnect support session with expected child processes or file writes.
- The dropped files are validated as legitimate ScreenConnect components or update artifacts in the expected installation path.
- No additional suspicious processes, persistence, or network activity are observed on the host.

<br/>
---
<br/>

## Detection 3: BusySnake Python Stealer Execution from Suspicious Path

### Detection Opportunity

Python interpreter executing from an unusual or user-writable path, consistent with the BusySnake Python-based stealer deployed by Armored Likho following spear-phishing delivery

### Intelligence Context

- Securelist: Armored Likho digging a snake pit: inside the covert BusySnake Stealer campaign — [https://securelist.com/tr/armored-likho-apt-with-busysnake-stealer/120292/](https://securelist.com/tr/armored-likho-apt-with-busysnake-stealer/120292/)
  - Context: Armored Likho delivered BusySnake, a Python-based credential stealer, via spear-phishing with AI-generated loaders. The stealer runs as a Python process and exfiltrates data. Detection targets python.exe or pythonw.exe spawned from user-writable or non-standard paths, particularly when the parent process is an Office application or a loader dropped in AppData or Temp.

### Search Metadata

- CVEs: Not specified
- Threat actors: Armored Likho
- ATT&CK tags: T1566, T1059, T1059.006
- Products: Not specified
- Platforms: Windows, Python
- Malware: BusySnake Stealer
- Tools: Not specified
- Search tags: Armored Likho, BusySnake Stealer, Windows, Python, T1566, T1059, T1059.006

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1566 Phishing (high); Execution: T1059 Command and Scripting Interpreter/ T1059.006 Python (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let suspicious_python = DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("python.exe", "pythonw.exe")
| where
    FolderPath has_any ("\\AppData\\", "\\Temp\\", "\\Downloads\\", "\\ProgramData\\")
    or InitiatingProcessFileName in~ (
        "winword.exe", "excel.exe", "outlook.exe",
        "powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe"
    )
| project PythonTime = Timestamp, DeviceName, AccountName,
    FolderPath, ProcessCommandLine, ProcessId,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessParentFileName;
let python_network = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe", "pythonw.exe")
| where RemotePort !in (80, 443)
| where isnotempty(RemoteIP)
| project NetTime = Timestamp, DeviceName, InitiatingProcessId,
    RemoteIP, RemotePort, RemoteUrl;
suspicious_python
| join kind=leftouter (
    python_network
  ) on DeviceName, $left.ProcessId == $right.InitiatingProcessId
| where NetTime >= PythonTime and datetime_diff('minute', NetTime, PythonTime) <= 10
    or isnull(NetTime)
| project PythonTime, NetTime, DeviceName, AccountName,
    FolderPath, ProcessCommandLine, ProcessId,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    RemoteIP, RemotePort, RemoteUrl
| order by PythonTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Developer workstations with Python installed in AppData via tools such as pyenv, conda, or pipx will generate process branch hits.
- Data science or ML tooling that runs Python scripts via Office macros or automation scripts will match the parent process filter.
- IT automation tools that invoke Python via cmd.exe or powershell.exe will match the scripting parent filter.
- Python-based monitoring or endpoint agents installed in ProgramData will generate file path hits.

**Tuning notes:**
- Add known Python installation FolderPath prefixes for sanctioned developer tools to an exclusion filter after baselining to suppress legitimate developer activity.
- Restrict DeviceName to device groups where Python is not an expected workload to improve signal quality before broader rollout.
- Consider splitting into two separate queries: one for the high-fidelity Office-parent spawn signal and one for the path-based signal, to allow independent severity and volume management.
- Extend the network time window beyond 10 minutes if the threat intelligence indicates delayed exfiltration behavior.

**Risks / caveats:**
- Python processes that exfiltrate over ports 80 or 443 will not appear in the network branch; analysts should separately review DeviceNetworkEvents for Python processes making HTTPS connections to non-categorized destinations.
- The leftouter join will return Python process hits with no network activity, which may be high volume in developer environments; analysts should prioritize rows where RemoteIP is populated.
- ProcessId reuse within the 7-day lookback window is theoretically possible but unlikely to cause meaningful false correlations in practice.
- Python embedded in compiled loaders or renamed to a different binary name will not be detected by filename matching alone.

### Triage Runbook

**First 15 minutes:**
- Confirm the Python binary path, parent process, and command line to determine whether execution came from AppData, Temp, Downloads, ProgramData, or an Office/scripting parent.
- Check whether the device is a developer workstation, data science system, or automation host where Python from non-standard paths is expected.
- Review the associated network activity for the same ProcessId to see whether the Python process made outbound connections shortly after launch.
- Look for signs of phishing or user interaction such as recent email attachments, Office macro activity, or a suspicious loader dropped before Python execution.

**Evidence to collect:**
- DeviceProcessEvents for the Python process tree, including the parent and grandparent process chain.
- DeviceNetworkEvents tied to the same ProcessId to identify remote IPs, ports, and URLs contacted by the Python process.
- Any recent email, attachment, or browser download evidence that could explain how the Python payload arrived on the host.
- File system evidence for the Python script or package in the suspicious folder path, including file names and timestamps.

**Pivot points:**
- DeviceProcessEvents filtered on the same DeviceName and AccountName to find other script interpreters, Office child processes, or loader activity.
- DeviceNetworkEvents for the same ProcessId or DeviceName to identify repeated outbound connections, especially to unusual ports or URLs.
- DeviceFileEvents on the same host to locate recently created Python scripts, archives, or dropped executables in user-writable paths.
- Email and browser telemetry, if available, to identify the likely phishing source or download origin.

**Benign explanations:**
- Developer, data science, or automation environments may legitimately run Python from AppData, Temp, or ProgramData.
- Some sanctioned tools such as pyenv, conda, or pipx can place Python-related files in user-writable locations.
- IT automation or scripting workflows may launch Python from cmd.exe or powershell.exe as part of normal operations.

**Escalation criteria:**
- The Python process is launched from a suspicious path and the parent chain includes Office, a script host, or a loader with no approved business purpose.
- The same process instance makes outbound connections to unusual IPs, ports, or URLs shortly after launch.
- The host shows evidence of credential theft, browser data access, or other post-execution behavior consistent with a stealer.
- The user reports a suspicious attachment, phishing email, or unexpected prompt that preceded the execution.

**Containment actions:**
- If malicious execution is confirmed, isolate the host to prevent data theft and further command-and-control activity.
- Disable or reset the affected user account if there is evidence of credential compromise or active theft.
- Block confirmed malicious remote IPs, URLs, or domains if they are identified during triage.

**Closure criteria:**
- The Python execution is validated as a sanctioned developer or automation workflow with an expected path and parent process.
- No suspicious network activity, data access, or persistence is associated with the Python process instance.
- The file path, command line, and user context match a documented benign use case and no phishing indicators are present.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- PsExec SMB Session Upgrade to Meterpreter Shell: Do not schedule yet; validate as an analyst-led hunt first.
- BusySnake Python Stealer Execution from Suspicious Path: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- DeviceProcessEvents: shared by PsExec SMB Session Upgrade to Meterpreter Shell; AsyncRAT Dropped via ScreenConnect Agent Child Process; BusySnake Python Stealer Execution from Suspicious Path

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: AsyncRAT Dropped via ScreenConnect Agent Child Process.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: PsExec SMB Session Upgrade to Meterpreter Shell; BusySnake Python Stealer Execution from Suspicious Path.

### Hunting Agenda and Promotion Criteria

- PsExec SMB Session Upgrade to Meterpreter Shell: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- BusySnake Python Stealer Execution from Suspicious Path: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
