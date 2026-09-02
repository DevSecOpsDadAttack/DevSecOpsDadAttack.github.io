---
layout: post
title: "Detection Engineering Brief - Wednesday, September 2, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-02
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Microsoft Defender
  - Defender XDR
  - Windows
  - Microsoft Teams
  - ValleyRAT
  - Mirage Kitten
  - Node.js
  - JavaScript
  - NodeRabbit
  - PollCat
  - T1204
  - T1059
  - T1071
  - T1547
  - T1059.007
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 3 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Microsoft Defender, Defender XDR, Windows, Microsoft Teams, ValleyRAT, Mirage Kitten, Node.js, JavaScript, NodeRabbit, PollCat, T1204, T1059, T1071, T1547, T1059.007.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Counterfeit Installer Archive Spawning Child Processes from Browser Download; Suspicious Process Execution on Domain Controllers Following Microsoft Teams Activity; ValleyRAT Installer Dropping Executable Payload to Non-Standard Path; NodeRabbit Backdoor: Node.js Spawned from Unusual Parent with Outbound Network Connection.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Counterfeit Installer Archive Spawning Child Processes from Browser Download

### Detection Opportunity

Malware distributed through regenerated installer archives delivered via look-alike download pages, resulting in browser-downloaded installers spawning unexpected child processes.

### Intelligence Context

- Microsoft Security Blog: Counterfeit installers to system compromise: Tracking a deceptive software download campaign — [https://www.microsoft.com/en-us/security/blog/2026/09/01/counterfeit-installers-system-compromise-tracking-deceptive-software-download-campaign/](https://www.microsoft.com/en-us/security/blog/2026/09/01/counterfeit-installers-system-compromise-tracking-deceptive-software-download-campaign/)
  - Context: The campaign delivers malware through look-alike software vendor download pages using regenerated installer archives. Browser-downloaded installer executables spawn child processes inconsistent with legitimate software installation behavior.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1204, T1059
- Products: Microsoft Defender, Defender XDR
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Microsoft Defender, Defender XDR, Windows, T1204, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: execution: T1204 User Execution (medium); execution: T1059 Command and Scripting Interpreter (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let BrowserProcesses = dynamic(["chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe"]);
let SuspiciousPaths = dynamic(["\\AppData\\Local\\Temp\\", "\\Downloads\\", "\\Users\\Public\\"]);
let KnownInstallerChildren = dynamic(["msiexec.exe", "setup.exe", "install.exe", "uninst.exe", "vcredist_x64.exe", "vcredist_x86.exe", "dotnetfx.exe"]);
let TimeWindow = 10min;
let BrowserDownloadedInstallers =
    DeviceFileEvents
    | where Timestamp > ago(7d)
    | where ActionType == "FileCreated"
    | where InitiatingProcessFileName has_any (BrowserProcesses)
    | where FileName endswith ".exe" or FileName endswith ".msi"
    | where FolderPath has_any (SuspiciousPaths)
    | where isnotempty(FileOriginUrl)
    | project DownloadTime = Timestamp, DeviceId, DeviceName, InstallerFile = FileName, InstallerPath = FolderPath, FileOriginUrl, SHA256, InitiatingBrowser = InitiatingProcessFileName;
BrowserDownloadedInstallers
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName endswith ".exe" or InitiatingProcessFileName endswith ".msi"
    | where InitiatingProcessFolderPath has_any (SuspiciousPaths)
    | where FileName !in~ (KnownInstallerChildren)
    | project SpawnTime = Timestamp, DeviceId, ChildProcess = FileName, ChildCommandLine = ProcessCommandLine, ParentInstaller = InitiatingProcessFileName
) on DeviceId
| where SpawnTime between (DownloadTime .. (DownloadTime + TimeWindow))
| where ParentInstaller =~ InstallerFile
| project DownloadTime, SpawnTime, DeviceName, InstallerFile, InstallerPath, FileOriginUrl, SHA256, InitiatingBrowser, ChildProcess, ChildCommandLine
| order by DownloadTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate software installers downloaded via browser that spawn setup helpers not in the exclusion list (e.g., vcredist.exe, dotnetfx.exe, 7z.exe).
- Software update mechanisms that use browser-like process names as download agents.
- Environments where FileOriginUrl is sparsely populated will see reduced coverage rather than false positives.

**Tuning notes:**
- Extend KnownInstallerChildren with additional legitimate child process names observed in the environment during baseline review.
- Adjust TimeWindow from 10 minutes if users in the environment typically delay execution after download.
- Consider adding a FileOriginUrl domain allowlist exclusion for known-good software vendors to reduce noise from legitimate downloads.

**Risks / caveats:**
- FileOriginUrl is not guaranteed to be populated in DeviceFileEvents for all browser download scenarios; environments where MDE advanced features or network protection are not fully enabled may see this field empty, causing the query to return no results for the browser-download filter.
- The DeviceId-only join anchor means multiple installers downloaded on the same device within the time window may produce cross-matched results; analyst review of InstallerFile and ParentInstaller alignment is required.
- The 10-minute time window may miss installers that are executed by the user significantly after download.
- FileOriginUrl population depends on MDE configuration; sparse population reduces detection coverage.

### Triage Runbook

**First 15 minutes:**
- Confirm the installer source: review FileOriginUrl, browser process, download time, and whether the URL/domain matches an approved vendor or software distribution channel.
- Check the child process name and command line against normal installer behavior; prioritize anything that launches cmd.exe, powershell.exe, script interpreters, LOLBins, or unexpected secondary executables.
- Validate the installer hash and filename against known-good software versions or vendor signatures if available; look for mismatched names, odd paths, or recently created files in temp/download locations.
- Assess whether the same device has multiple installer downloads in the same window that could be cross-matched by the hunt logic; verify the parent installer and child process are causally linked.

**Evidence to collect:**
- InstallerFile, InstallerPath, SHA256, FileOriginUrl, and InitiatingBrowser from the download event.
- ChildProcess and ChildCommandLine from the spawned process event, including the exact parent installer filename.
- DeviceName, DownloadTime, and SpawnTime to confirm the sequence and timing.
- Any related file creation or process events on the same device around the same time that show payload extraction or follow-on execution.

**Pivot points:**
- DeviceFileEvents for the same DeviceId and SHA256 to find other downloads or file creations from the same source.
- DeviceProcessEvents for the same DeviceId and time window to identify additional child processes from the installer or related payloads.
- Defender XDR device timeline on the host to review adjacent process, file, and network activity.
- If available, pivot on FileOriginUrl domain to identify other endpoints that downloaded from the same source.

**Benign explanations:**
- Legitimate software installers downloaded from a vendor site that spawn helper executables not included in the exclusion list.
- Enterprise software updates or self-extracting installers that run from temp or Downloads folders.
- Browser-based downloaders or software portals that use nonstandard helper processes during installation.

**Escalation criteria:**
- The installer source is untrusted, look-alike, newly registered, or not an approved vendor domain.
- The child process is a script interpreter, LOLBin, or command shell not expected for the software being installed.
- The installer hash, filename, or path does not match the claimed software, or additional suspicious files are dropped nearby.
- The host shows any follow-on persistence, credential access, or outbound network activity after the installer runs.

**Containment actions:**
- Isolate the endpoint if the installer is confirmed malicious or if follow-on suspicious execution is observed.
- Block the installer hash and source URL/domain in Defender and web controls if validated as malicious.
- Terminate the suspicious child process and any related payload processes if they are still running.
- Quarantine the downloaded file and any dropped executables associated with the alert.

**Closure criteria:**
- The installer is verified as a legitimate vendor package and the child process behavior matches expected installation activity.
- The FileOriginUrl, hash, and filename align with approved software distribution records.
- No additional suspicious processes, file drops, or network connections are found on the host.
- Document the benign installer pattern and tune exclusions only after confirming it is recurring and approved.

<br/>
---
<br/>

## Detection 2: Suspicious Process Execution on Domain Controllers Following Microsoft Teams Activity

### Detection Opportunity

Malware deployed via Teams-based voice phishing targeting enterprise domain controllers, resulting in unusual process execution on DC-classified devices.

### Intelligence Context

- Unit 42: Spring Ring: An Inside Look at Voice Phishing Campaigns in Microsoft Teams — [https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/](https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/)
  - Context: The Spring Ring campaign abuses Microsoft Teams voice calls to socially engineer users into deploying malware, with the ultimate objective of compromising enterprise domain controllers. Detection focuses on the high-value post-exploitation phase: unusual process execution on domain controller devices.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1204, T1059, T1071
- Products: Microsoft Teams
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Microsoft Teams, Windows, T1204, T1059, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: execution: T1204 User Execution (medium); execution: T1059 Command and Scripting Interpreter (medium); command-and-control: T1071 Application Layer Protocol (low)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceInfo, DeviceProcessEvents, DeviceLogonEvents

### KQL

```kql
let DCDevices =
    DeviceInfo
    | where Timestamp > ago(1d)
    | where DeviceType == "DomainController"
    | summarize arg_max(Timestamp, *) by DeviceId
    | project DeviceId, DeviceName;
let SuspiciousParents = dynamic(["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"]);
let CorrelationWindow = 30min;
let InteractiveLogons =
    DeviceLogonEvents
    | where Timestamp > ago(7d)
    | where LogonType in ("Interactive", "RemoteInteractive", "Network")
    | where ActionType == "LogonSuccess"
    | join kind=inner DCDevices on DeviceId
    | project LogonTime = Timestamp, DeviceId, DeviceName, AccountName, LogonType;
InteractiveLogons
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName has_any (SuspiciousParents)
    | join kind=inner DCDevices on DeviceId
    | project ProcTime = Timestamp, DeviceId, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
) on DeviceId, AccountName
| where ProcTime between (LogonTime .. (LogonTime + CorrelationWindow))
| project LogonTime, ProcTime, DeviceName, AccountName, LogonType, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by ProcTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrative sessions on domain controllers by IT staff using PowerShell or cmd.exe for routine management.
- Automated monitoring or backup agents that spawn cmd.exe or PowerShell under interactive-equivalent logon contexts.
- Remote management tools (e.g., SCCM, Ansible) that initiate Network logons followed by scripting activity.

**Tuning notes:**
- Add AccountName exclusions for known administrative service accounts that legitimately run PowerShell or cmd.exe on DCs.
- Reduce CorrelationWindow from 30 minutes if the environment has high-frequency legitimate interactive DC logons.
- If DeviceType classification is unavailable, replace the DCDevices subquery with a static list of DC DeviceId or DeviceName values maintained as a watchlist.

**Risks / caveats:**
- DeviceInfo.DeviceType == 'DomainController' requires MDE device classification to be correctly applied; if DCs are not onboarded to MDE or DeviceType is not populated, the DCDevices subquery returns no rows and the entire detection produces no results.
- DeviceLogonEvents.LogonType uses string values ('Interactive', 'RemoteInteractive', 'Network') in Defender XDR Advanced Hunting; confirm these string values are correct for the schema version in use as some schema versions use numeric LogonType.
- If DeviceType classification is not applied to DC assets in MDE, the DCDevices subquery returns no rows and the detection produces no output; operators must verify DC classification before relying on this query.
- The AccountName join between logon and process events may miss cases where the process runs under a different account than the logon account (e.g., token impersonation or runas).

### Triage Runbook

**First 15 minutes:**
- Confirm the device is truly a domain controller using DeviceInfo classification or your authoritative DC inventory; do not rely on naming alone.
- Review the logon type, account name, and process command line to determine whether the execution was interactive, remote interactive, or network-based administrative activity.
- Identify the suspicious parent process and child process; prioritize cmd.exe, powershell.exe, wscript.exe, cscript.exe, mshta.exe, rundll32.exe, regsvr32.exe, certutil.exe, or bitsadmin.exe.
- Check whether the account is a privileged admin, service account, or a normal user account and whether the activity occurred shortly after a Teams-related user interaction or support call.

**Evidence to collect:**
- DeviceName, DeviceId, DeviceType, AccountName, AccountDomain, LogonType, and LogonTime for the DC session.
- FileName, ProcessCommandLine, InitiatingProcessFileName, and ProcTime for the suspicious process execution.
- Any related DeviceLogonEvents and DeviceProcessEvents on the same DC within the 30-minute window.
- Recent administrative activity on the DC, including remote management tools, scheduled tasks, and service changes.

**Pivot points:**
- DeviceLogonEvents on the same DeviceId to find other logons by the same account or from the same source.
- DeviceProcessEvents on the same DC for additional scripting, LOLBin, or remote administration activity.
- DeviceInfo to confirm DC classification and identify other domain controllers in scope.
- If available, Microsoft Teams audit or user activity logs to correlate the suspected social engineering window.

**Benign explanations:**
- Legitimate domain controller administration by IT staff using PowerShell or cmd.exe.
- Remote management, backup, or monitoring tools that create network or remote interactive logons followed by scripting.
- Planned maintenance or troubleshooting on a DC by a privileged administrator.

**Escalation criteria:**
- The account is not an approved admin or service account and the process is clearly suspicious.
- The DC shows multiple suspicious processes, lateral movement indicators, or evidence of payload staging.
- There are signs of credential theft, new services, scheduled tasks, or unauthorized remote access on the DC.
- The activity aligns with a recent Teams voice phishing report or user complaint involving the same account or device.

**Containment actions:**
- Isolate the domain controller if malicious execution is confirmed or if there is evidence of active compromise.
- Disable or reset the involved account if it is not a trusted admin account or if credential theft is suspected.
- Terminate suspicious processes and remove any dropped files or scheduled tasks associated with the activity.
- Engage incident response immediately because DC compromise can affect the entire domain.

**Closure criteria:**
- The process execution is validated as approved administrative activity with a matching change ticket or maintenance record.
- The account and logon type are expected for the DC and no additional suspicious activity is present.
- No evidence of payload staging, persistence, or lateral movement is found on the domain controller.
- Document the approved admin pattern and, if needed, add known service accounts or management tools to tuning.

<br/>
---
<br/>

## Detection 3: Microsoft Teams Process Spawning Suspicious Child Executables Post-Call

### Detection Opportunity

Microsoft Teams abused via voice phishing to socially engineer users into executing malware, resulting in Teams spawning or indirectly initiating suspicious child processes.

### Intelligence Context

- Unit 42: Spring Ring: An Inside Look at Voice Phishing Campaigns in Microsoft Teams — [https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/](https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/)
  - Context: Attackers use Teams voice calls to convince users to run malicious payloads. The malware deployment step follows the social engineering call, making Teams process lineage or temporally proximate process execution a viable detection signal.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1204, T1059, T1071
- Products: Microsoft Teams
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Microsoft Teams, Windows, T1204, T1059, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: execution: T1204 User Execution (medium); execution: T1059 Command and Scripting Interpreter (medium); command-and-control: T1071 Application Layer Protocol (low)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let TeamsProcesses = dynamic(["teams.exe", "ms-teams.exe"]);
let SuspiciousChildren = dynamic(["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe"]);
let SensitivePaths = dynamic(["\\AppData\\Local\\Temp\\", "\\Users\\Public\\", "\\ProgramData\\"]);
let SuspiciousExtensions = dynamic([".exe", ".dll", ".ps1", ".js", ".vbs", ".bat", ".cmd"]);
let TeamsSpawnedProcs =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName has_any (TeamsProcesses)
    | where FileName has_any (SuspiciousChildren)
    | project SignalType = "TeamsSpawnedProcess", EventTime = Timestamp, DeviceId, DeviceName, AccountName,
              ParentProcess = InitiatingProcessFileName, ChildProcess = FileName, ChildCommandLine = ProcessCommandLine,
              DroppedFile = "", DropPath = "", SHA256 = "";
let TeamsFileDrop =
    DeviceFileEvents
    | where Timestamp > ago(7d)
    | where ActionType == "FileCreated"
    | where InitiatingProcessFileName has_any (TeamsProcesses)
    | where FolderPath has_any (SensitivePaths)
    | where FileName has_any (SuspiciousExtensions)
    | project SignalType = "TeamsFileDrop", EventTime = Timestamp, DeviceId, DeviceName, AccountName = "",
              ParentProcess = InitiatingProcessFileName, ChildProcess = "", ChildCommandLine = "",
              DroppedFile = FileName, DropPath = FolderPath, SHA256;
TeamsSpawnedProcs
| union TeamsFileDrop
| project SignalType, EventTime, DeviceName, AccountName, ParentProcess, ChildProcess, ChildCommandLine, DroppedFile, DropPath, SHA256
| order by EventTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate Teams integrations or bots that invoke PowerShell or cmd.exe for workflow automation.
- IT-managed Teams add-ins that drop configuration scripts to temp directories during installation or update.
- Developer environments where Teams is used alongside scripting tools.

**Tuning notes:**
- Add AccountName or DeviceName exclusions for developer or IT admin devices where Teams-spawned scripting is expected.
- Restrict SensitivePaths to the most sensitive subset if the broader temp directory scope generates excessive noise.
- Review legitimate Teams integrations in the environment and add their child process names to an exclusion list.

**Risks / caveats:**
- Teams may be deployed under a process name other than 'teams.exe' or 'ms-teams.exe' in some enterprise packaging configurations (e.g., MSI-deployed Teams using a wrapper); verify the Teams process name in DeviceProcessEvents before relying on this detection.
- Teams process name variants in enterprise deployments may not match 'teams.exe' or 'ms-teams.exe'; verify process names in DeviceProcessEvents before scheduling.
- Indirect execution chains where the user manually runs a payload after a Teams call are not captured by direct parent-child attribution.
- AccountName is not available in DeviceFileEvents and will be empty for file drop signals, limiting account-based correlation for that signal type.

### Triage Runbook

**First 15 minutes:**
- Identify whether the alert is a Teams-spawned process or a Teams file drop; treat both as potentially malicious until proven otherwise.
- Review the parent process, child process, and command line for suspicious execution such as cmd.exe, powershell.exe, script interpreters, or LOLBins.
- Check the dropped file path and filename for temp, Public, or ProgramData locations and confirm whether the file extension is executable or script-like.
- Correlate the event time with user reports of a Teams voice call, screen share, or support request that may have preceded the execution.

**Evidence to collect:**
- SignalType, EventTime, DeviceName, AccountName, ParentProcess, ChildProcess, ChildCommandLine, DroppedFile, DropPath, and SHA256.
- Any related DeviceProcessEvents showing follow-on execution from the same parent or child process.
- Any related DeviceFileEvents showing additional file drops, especially in temp or user-writable paths.
- User identity and recent Teams activity context for the affected account or device.

**Pivot points:**
- DeviceProcessEvents for the same DeviceId and AccountName to find additional suspicious child processes or repeated Teams lineage.
- DeviceFileEvents for the same DeviceId to identify other dropped executables, scripts, or archives.
- Defender XDR device timeline to review adjacent network connections and persistence artifacts.
- If available, Teams audit or call logs to validate whether a suspicious call or chat occurred near the alert time.

**Benign explanations:**
- Legitimate Teams integrations, bots, or add-ins that invoke scripting tools for automation.
- IT-managed Teams updates or installation routines that temporarily drop scripts or helper files.
- Developer or admin workstations where Teams is used alongside scripting and build tools.
- Known enterprise packaging variants where Teams process names differ and the lineage is expected.

**Escalation criteria:**
- The child process is not expected for the user, device role, or approved Teams integration.
- The dropped file is a new executable or script in a sensitive path and is followed by additional execution or network activity.
- The user reports a suspicious Teams call, support impersonation, or instructions to run software.
- The host shows persistence, credential access, or outbound connections from the spawned process.

**Containment actions:**
- Isolate the endpoint if the child process or dropped file is confirmed malicious or if follow-on activity is observed.
- Quarantine the dropped file and terminate the suspicious child process if still active.
- Disable or reset the user account if the event is tied to a successful social engineering compromise.
- Block the file hash and any associated URLs or domains if they are identified during triage.

**Closure criteria:**
- The Teams activity is verified as legitimate automation, update behavior, or approved admin tooling.
- The child process and dropped file are consistent with documented Teams integrations or software deployment.
- No additional suspicious execution, file drops, or network activity is found on the endpoint.
- The event is documented with the approved Teams process name and any environment-specific exclusions needed.

<br/>
---
<br/>

## Detection 4: ValleyRAT Installer Dropping Executable Payload to Non-Standard Path

### Detection Opportunity

Malicious installer masquerading as adware delivers ValleyRAT backdoor by spawning unexpected child processes or dropping executables to non-standard filesystem locations.

### Intelligence Context

- Securelist: ValleyRAT masquerading as adware — [https://securelist.com/valleyrat-backdoor-adware/121175/](https://securelist.com/valleyrat-backdoor-adware/121175/)
  - Context: ValleyRAT is delivered via a malicious installer that disguises itself as adware. The installer drops a backdoor payload to the filesystem and spawns child processes inconsistent with legitimate adware installation, providing a behavioral detection opportunity via process and file telemetry.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1204, T1547, T1071
- Products: Not specified
- Platforms: Windows
- Malware: ValleyRAT
- Tools: Not specified
- Search tags: Windows, ValleyRAT, T1204, T1547, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: execution: T1204 User Execution (medium); persistence: T1547 Boot or Logon Autostart Execution (low); command-and-control: T1071 Application Layer Protocol (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let SuspiciousDirs = dynamic(["\\AppData\\Local\\Temp\\", "\\Users\\Public\\", "\\ProgramData\\", "\\AppData\\Roaming\\"]);
let KnownLegitDroppers = dynamic(["msiexec.exe", "svchost.exe", "trustedinstaller.exe"]);
let StageWindow = 10min;
let InstallerDrops =
    DeviceFileEvents
    | where Timestamp > ago(7d)
    | where ActionType == "FileCreated"
    | where FolderPath has_any (SuspiciousDirs)
    | where FileName endswith ".exe" or FileName endswith ".dll"
    | where InitiatingProcessFileName endswith ".exe"
    | where InitiatingProcessFileName !in~ (KnownLegitDroppers)
    | project DropTime = Timestamp, DeviceId, DeviceName, DroppedFile = FileName, DropPath = FolderPath, InstallerProcess = InitiatingProcessFileName, SHA256;
let DropsWithSpawn =
    InstallerDrops
    | join kind=inner (
        DeviceProcessEvents
        | where Timestamp > ago(7d)
        | where FolderPath has_any (SuspiciousDirs)
        | project ProcTime = Timestamp, DeviceId, SpawnedProcess = FileName, CommandLine = ProcessCommandLine, ParentProcess = InitiatingProcessFileName
    ) on DeviceId
    | where ProcTime between (DropTime .. (DropTime + StageWindow))
    | where SpawnedProcess =~ DroppedFile
    | project DropTime, ProcTime, DeviceId, DeviceName, InstallerProcess, DroppedFile, DropPath, SHA256, SpawnedProcess, CommandLine;
DropsWithSpawn
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where ActionType == "ConnectionSuccess"
    | where isnotempty(RemoteIP)
    | project NetTime = Timestamp, DeviceId, RemoteIP, RemotePort, RemoteUrl, ConnProcess = InitiatingProcessFileName
) on DeviceId
| where NetTime between (ProcTime .. (ProcTime + StageWindow))
| where ConnProcess =~ SpawnedProcess
| project DropTime, ProcTime, NetTime, DeviceName, InstallerProcess, DroppedFile, DropPath, SHA256, SpawnedProcess, CommandLine, RemoteIP, RemotePort, RemoteUrl
| order by DropTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate software installers that drop executables to temp directories, spawn them, and those executables make outbound connections for license validation or update checks.
- Software deployment tools (e.g., SCCM, Chocolatey) that follow the same drop-spawn-connect pattern.
- Security tools that drop and execute scanning agents with outbound telemetry connections.

**Tuning notes:**
- Extend StageWindow if the ValleyRAT delivery chain in observed incidents shows longer delays between stages.
- Add InstallerProcess exclusions for known legitimate software deployment tools that generate false positives.
- Consider adding a RemotePort filter to exclude common legitimate ports (80, 443) if the environment's legitimate software update traffic generates noise, while noting that ValleyRAT C2 may use standard ports.

**Risks / caveats:**
- DeviceNetworkEvents.ActionType == 'ConnectionSuccess' may not be populated in all MDE configurations or for all network event types; verify that ConnectionSuccess events are present in the environment for the endpoint population before relying on this filter.
- The DeviceId-only join anchor across three stages means causally unrelated events on busy endpoints may be correlated; analyst review of each result is required to confirm the three events share a causal chain.
- Staggered execution where the dropped payload is not run immediately after the drop, or where C2 beaconing is delayed, will cause the detection to miss the event chain.
- The SpawnedProcess =~ DroppedFile equality check requires the spawned process filename to exactly match the dropped file name; renamed or relocated payloads will evade this check.

### Triage Runbook

**First 15 minutes:**
- Treat the alert as likely malicious until proven otherwise because it combines file drop, execution, and network activity.
- Verify the installer filename, path, and hash against known software; look for adware-like branding, unusual packaging, or mismatched signatures.
- Inspect the dropped file and spawned process to confirm whether the payload executed from a temp, Public, ProgramData, or roaming path.
- Review the outbound connection details, including RemoteIP, RemoteUrl, and RemotePort, for signs of C2 or post-install telemetry.

**Evidence to collect:**
- DropTime, ProcTime, NetTime, DeviceName, InstallerProcess, DroppedFile, DropPath, SHA256, SpawnedProcess, CommandLine, RemoteIP, RemotePort, and RemoteUrl.
- The exact file creation event and the process event that executed the dropped payload.
- Any additional DeviceNetworkEvents from the same host around the same time, especially repeated connections to the same destination.
- Any persistence-related artifacts such as new services, scheduled tasks, startup entries, or registry run keys.

**Pivot points:**
- DeviceFileEvents for the same DeviceId and SHA256 to find other dropped files or repeated installer activity.
- DeviceProcessEvents for the same DeviceId to identify child processes, script execution, or persistence creation.
- DeviceNetworkEvents to review all outbound connections from the dropped payload and related processes.
- Defender XDR device timeline to inspect for registry, service, or scheduled task changes after the installer ran.

**Benign explanations:**
- Legitimate software installers that drop helper executables into temp or ProgramData before launching them.
- Software deployment tools such as SCCM or Chocolatey that follow a drop-spawn-connect pattern.
- Security or update tools that stage executables in user-writable paths and make outbound validation connections.

**Escalation criteria:**
- The installer is not from an approved vendor or the hash is unknown and the dropped payload executes.
- The spawned process or network destination is suspicious, especially if it repeats or persists.
- Any persistence artifact, credential theft indicator, or lateral movement is observed after execution.
- The host is a high-value system or the same installer appears on multiple endpoints.

**Containment actions:**
- Isolate the endpoint if the payload executed or if outbound connections indicate active compromise.
- Quarantine the installer and dropped payload, and block the hash and destination if confirmed malicious.
- Terminate the spawned process and remove any persistence artifacts discovered during triage.
- If the installer was delivered broadly, initiate enterprise-wide hunt for the same hash, filename, or destination.

**Closure criteria:**
- The installer is verified as legitimate and the drop-spawn-connect sequence matches approved software behavior.
- The outbound destination is a known vendor or internal service and no persistence is found.
- No additional suspicious files, processes, or network activity are present on the host.
- The detection is documented with any environment-specific exclusions for approved deployment tools.

<br/>
---
<br/>

## Detection 5: NodeRabbit Backdoor: Node.js Spawned from Unusual Parent with Outbound Network Connection

### Detection Opportunity

Mirage Kitten deploys NodeRabbit, a Node.js-based backdoor, by executing node.exe from an unusual parent process context with outbound C2 network connections.

### Intelligence Context

- Securelist: Mirage Kitten targeting aviation and FinTech sectors across the Middle East and Africa with a new malware set — [https://securelist.com/mirage-kitten-new-backdoors-noderabbit-pollcat/121244/](https://securelist.com/mirage-kitten-new-backdoors-noderabbit-pollcat/121244/)
  - Context: Mirage Kitten deploys NodeRabbit, a previously undocumented Node.js-based backdoor, as part of intrusion activity targeting aviation and FinTech sectors. Detection focuses on node.exe executing from non-developer parent processes and establishing outbound network connections consistent with C2 beaconing behavior.

### Search Metadata

- CVEs: Not specified
- Threat actors: Mirage Kitten
- ATT&CK tags: T1059.007, T1071, T1059
- Products: Not specified
- Platforms: Node.js, JavaScript
- Malware: NodeRabbit
- Tools: Not specified
- Search tags: Mirage Kitten, Node.js, JavaScript, NodeRabbit, PollCat, T1059.007, T1071, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: execution: T1059 Command and Scripting Interpreter/ T1059.007 JavaScript (high); command-and-control: T1071 Application Layer Protocol (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let SuspiciousParents = dynamic(["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "winword.exe", "excel.exe", "outlook.exe"]);
let SuspiciousPaths = dynamic(["\\AppData\\Local\\Temp\\", "\\Users\\Public\\", "\\ProgramData\\", "\\AppData\\Roaming\\"]);
let TimeWindow = 5min;
let SuspiciousNodeProcs =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "node.exe"
    | where InitiatingProcessFileName has_any (SuspiciousParents)
        or FolderPath has_any (SuspiciousPaths)
    | project NodeTime = Timestamp, DeviceId, DeviceName, AccountName, NodeCommandLine = ProcessCommandLine, ParentProcess = InitiatingProcessFileName, NodePath = FolderPath;
SuspiciousNodeProcs
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName =~ "node.exe"
    | where ActionType == "ConnectionSuccess"
    | where RemotePort !in (80, 443)
    | where isnotempty(RemoteIP)
    | project NetTime = Timestamp, DeviceId, RemoteIP, RemotePort, RemoteUrl
) on DeviceId
| where NetTime between (NodeTime .. (NodeTime + TimeWindow))
| project NodeTime, NetTime, DeviceName, AccountName, NodeCommandLine, ParentProcess, NodePath, RemoteIP, RemotePort, RemoteUrl
| order by NodeTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Developer workstations where Node.js is invoked from cmd.exe or PowerShell as part of build or test workflows.
- CI/CD agents that run Node.js scripts from shell parents with outbound connections to artifact repositories on non-standard ports.
- Legitimate Node.js applications installed in AppData or ProgramData that make outbound connections on non-standard ports.

**Tuning notes:**
- Baseline node.exe execution patterns in the environment over 30 days before scheduling to identify legitimate parent processes and paths to exclude.
- Add AccountName exclusions for developer and build agent accounts to reduce noise on developer workstations.
- Add RemotePort exclusions for known legitimate Node.js application ports used in the environment.
- Consider restricting to non-developer device populations using a device group or DeviceName filter if developer workstations dominate false positives.

**Risks / caveats:**
- DeviceNetworkEvents.ActionType == 'ConnectionSuccess' may not be populated for all network events in all MDE configurations; verify that this ActionType value is present in the environment before relying on it as a filter.
- The DeviceId-only join anchor means any node.exe network connection on a device within 5 minutes of any suspicious node.exe process start will match, even if they are unrelated node.exe instances.
- Non-standard port heuristic is a weak C2 signal; NodeRabbit or similar malware using ports 80 or 443 for C2 will evade this filter.
- Developer and CI/CD environments with legitimate Node.js usage from shell parents will generate significant noise without AccountName or DeviceName exclusions.

### Triage Runbook

**First 15 minutes:**
- Confirm whether node.exe is expected on the device; if the host is not a developer, build, or application server, treat the alert as highly suspicious.
- Review the parent process, command line, and path for node.exe; prioritize shell, script interpreter, Office, or LOLBin parents and execution from temp, Public, ProgramData, or roaming paths.
- Inspect the outbound connection details, especially RemoteIP, RemoteUrl, and RemotePort, and determine whether the destination is known, internal, or unusual for the host.
- Check whether the node.exe process is part of a legitimate application stack, CI/CD job, or packaged enterprise app before assuming compromise.

**Evidence to collect:**
- NodeTime, NetTime, DeviceName, AccountName, NodeCommandLine, ParentProcess, NodePath, RemoteIP, RemotePort, and RemoteUrl.
- The exact DeviceProcessEvents record for node.exe, including the initiating process and command line.
- The corresponding DeviceNetworkEvents record showing the connection success and destination details.
- Any nearby file creation or script execution events that indicate staging, unpacking, or persistence.

**Pivot points:**
- DeviceProcessEvents on the same DeviceId to find other node.exe instances, child processes, or script activity.
- DeviceNetworkEvents for the same DeviceId and AccountName to identify repeated connections or other suspicious destinations.
- DeviceFileEvents to look for dropped JavaScript, batch, or executable files in user-writable paths.
- If available, endpoint inventory or software catalog to confirm whether Node.js is installed and approved on the host.

**Benign explanations:**
- Developer workstations running legitimate Node.js applications, build scripts, or test harnesses.
- CI/CD agents or automation hosts that launch node.exe from shell parents and connect to artifact or package repositories.
- Legitimate enterprise applications that bundle Node.js in ProgramData or AppData and make outbound connections.
- Internal admin scripts or packaged tools that use node.exe for automation.

**Escalation criteria:**
- The host is not a known developer, build, or application server and node.exe is running from a suspicious path.
- The parent process is unexpected and the outbound destination is unknown, newly observed, or associated with malicious infrastructure.
- There are additional signs of persistence, credential theft, or follow-on payload execution.
- Multiple endpoints show the same suspicious node.exe pattern or the activity aligns with a broader intrusion.

**Containment actions:**
- Isolate the endpoint if node.exe is confirmed malicious or if the outbound connection appears to be active C2.
- Terminate the suspicious node.exe process and quarantine any related files or scripts.
- Block the destination IP, URL, or domain if confirmed malicious and not required for business use.
- Disable or reset the user account if the execution appears tied to a compromised user session.

**Closure criteria:**
- Node.exe is verified as part of an approved application, developer workflow, or automation job.
- The parent process, path, and network destination match documented legitimate behavior.
- No additional suspicious child processes, file drops, or repeated outbound connections are found.
- The alert is documented with any approved Node.js parent/process/path exceptions for the environment.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- Counterfeit Installer Archive Spawning Child Processes from Browser Download: Do not schedule yet; validate as an analyst-led hunt first.
- ValleyRAT Installer Dropping Executable Payload to Non-Standard Path: Do not schedule yet; validate as an analyst-led hunt first.
- NodeRabbit Backdoor: Node.js Spawned from Unusual Parent with Outbound Network Connection: Do not schedule yet; validate as an analyst-led hunt first.

**Other deployment dependency:**
- Suspicious Process Execution on Domain Controllers Following Microsoft Teams Activity: Defender for Endpoint file-event coverage must be confirmed on the target host population.
- Microsoft Teams Process Spawning Suspicious Child Executables Post-Call: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Shared-table notes:**
- DeviceFileEvents: shared by Counterfeit Installer Archive Spawning Child Processes from Browser Download; Microsoft Teams Process Spawning Suspicious Child Executables Post-Call; ValleyRAT Installer Dropping Executable Payload to Non-Standard Path
- DeviceProcessEvents: shared by Counterfeit Installer Archive Spawning Child Processes from Browser Download; Suspicious Process Execution on Domain Controllers Following Microsoft Teams Activity; Microsoft Teams Process Spawning Suspicious Child Executables Post-Call; ValleyRAT Installer Dropping Executable Payload to Non-Standard Path; NodeRabbit Backdoor: Node.js Spawned from Unusual Parent with Outbound Network Connection
- DeviceNetworkEvents: shared by ValleyRAT Installer Dropping Executable Payload to Non-Standard Path; NodeRabbit Backdoor: Node.js Spawned from Unusual Parent with Outbound Network Connection

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Microsoft Teams Process Spawning Suspicious Child Executables Post-Call.
2. Resolve environment-mapping detections next: Suspicious Process Execution on Domain Controllers Following Microsoft Teams Activity.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Counterfeit Installer Archive Spawning Child Processes from Browser Download; ValleyRAT Installer Dropping Executable Payload to Non-Standard Path; NodeRabbit Backdoor: Node.js Spawned from Unusual Parent with Outbound Network Connection.

### Hunting Agenda and Promotion Criteria

- Counterfeit Installer Archive Spawning Child Processes from Browser Download: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- ValleyRAT Installer Dropping Executable Payload to Non-Standard Path: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- NodeRabbit Backdoor: Node.js Spawned from Unusual Parent with Outbound Network Connection: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Suspicious Process Execution on Domain Controllers Following Microsoft Teams Activity: Defender for Endpoint file-event coverage must be confirmed on the target host population.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
