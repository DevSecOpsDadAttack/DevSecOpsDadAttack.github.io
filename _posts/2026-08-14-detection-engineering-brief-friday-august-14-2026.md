---
layout: post
title: "Detection Engineering Brief - Friday, August 14, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-08-14
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-63520
  - CVE-2026-55040
  - T1190
  - Microsoft SharePoint
  - Windows
  - HoneyMyte
  - CoolClient
  - Armored Likho
  - Still Toolkit
  - Telegram
  - T1059
  - T1547.006
  - T1014
  - T1547
  - T1213
---

## Detection Engineering Summary

This brief produced 4 detection candidates.

1 production candidate, 2 hunting-only, 1 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-63520, CVE-2026-55040, T1190, Microsoft SharePoint, Windows, HoneyMyte, CoolClient, Armored Likho, Still Toolkit, Telegram, T1059, T1547.006, T1014, T1547, T1213.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: SharePoint OfficeActivity Anomalous Operation Correlated with w3wp Child Process Execution; CoolClient Rootkit - Unsigned Kernel Driver Load on Windows Endpoint; Armored Likho Still Toolkit - Non-Telegram Process Accessing Telegram Local Storage.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: SharePoint IIS Worker Process Spawning Suspicious Child Process

### Detection Opportunity

Chained unauthenticated RCE via CVE-2026-63520 and CVE-2026-55040 resulting in arbitrary code execution on SharePoint server via w3wp.exe child process spawning.

### Intelligence Context

- Rapid7: CVE-2026-63520: Microsoft SharePoint Remote Code Execution (FIXED) — [https://www.rapid7.com/blog/post/etr-cve-2026-63520-microsoft-sharepoint-remote-code-execution-fixed](https://www.rapid7.com/blog/post/etr-cve-2026-63520-microsoft-sharepoint-remote-code-execution-fixed)
  - Context: Rapid7 reported two chained vulnerabilities (CVE-2026-63520 and CVE-2026-55040) enabling unauthenticated RCE on SharePoint. Exploitation results in arbitrary code execution via the SharePoint IIS worker process (w3wp.exe), making anomalous child process spawning from w3wp.exe the primary detection surface.

### Search Metadata

- CVEs: CVE-2026-63520, CVE-2026-55040
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Microsoft SharePoint
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-63520, CVE-2026-55040, T1190, Microsoft SharePoint, Windows, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where InitiatingProcessFolderPath has @"\Windows\System32\inetsrv"
| where FileName in~ (
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "certutil.exe",
    "bitsadmin.exe"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    SHA256
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate SharePoint administrative scripts or health-check automation that invoke cmd.exe or powershell.exe via the IIS worker process.
- Third-party SharePoint add-ins or monitoring agents that spawn interpreter processes under w3wp.exe.
- IIS-hosted applications other than SharePoint on the same server that spawn child processes.

**Tuning notes:**
- Prepend a let statement defining known SharePoint server hostnames and add '| where DeviceName in (SharePointServers)' to scope the rule precisely.
- After baselining, add a '| where ProcessCommandLine !has "<known_legitimate_pattern>"' exclusion for any recurring benign invocations identified.
- Consider reducing the lookback to 1d once the rule is scheduled to run every hour.

**Risks / caveats:**
- Without scoping DeviceName to known SharePoint server hostnames, the rule will fire on any IIS-hosted application that spawns these child processes, not only SharePoint.
- certutil.exe and bitsadmin.exe may generate false positives from legitimate administrative tasks on IIS servers; baseline before alerting.
- The 7-day lookback window is appropriate for scheduled rules but should be reduced to 1 day once the rule is running continuously to avoid duplicate alerts.

### Triage Runbook

**First 15 minutes:**
- Confirm the alert is on a known SharePoint server and not another IIS-hosted application.
- Review the child process name, command line, parent w3wp.exe command line, and account context for signs of webshell or post-exploitation activity.
- Check whether the child process is one of the high-risk interpreters or LOLBins and whether it launched from the standard IIS worker path.
- Look for multiple child process spawns from the same w3wp.exe instance or repeated alerts on the same host in a short window.
- If the process is still running, preserve volatile details before any restart or remediation action.

**Evidence to collect:**
- DeviceName, Timestamp, AccountName, AccountDomain, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName, FileName, FolderPath, ProcessCommandLine, SHA256
- Any related DeviceProcessEvents on the same host for the prior and subsequent 24 hours
- SharePoint/IIS application pool name from the w3wp.exe command line
- Recent authentication, admin, or service-account activity on the host if available
- Any file drops, script files, or secondary payload hashes associated with the child process

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and w3wp.exe parent chain
- DeviceFileEvents for recent file creation or modification on the SharePoint server
- DeviceNetworkEvents for outbound connections from the same host around the alert time
- OfficeActivity for SharePoint operations around the same time window if available
- DeviceLogonEvents or equivalent sign-in telemetry to identify suspicious account activity

**Benign explanations:**
- Legitimate SharePoint administrative scripts or health checks launched through the IIS worker process.
- Third-party SharePoint add-ins or monitoring agents that invoke cmd.exe or powershell.exe under w3wp.exe.
- Other IIS applications on the same server spawning interpreters for normal maintenance tasks.
- Known scheduled jobs or backup utilities that run during the same time window.

**Escalation criteria:**
- The child process is not tied to a documented maintenance, monitoring, or add-in workflow.
- The command line shows encoded PowerShell, download activity, script execution, or other post-exploitation behavior.
- There are multiple suspicious child processes, file drops, or outbound connections from the same SharePoint server.
- The host is internet-facing and the activity aligns with the reported SharePoint RCE behavior.

**Containment actions:**
- Isolate the SharePoint server from the network if suspicious execution is confirmed or strongly suspected.
- Preserve memory, process, and file evidence before rebooting or reimaging.
- Disable or restrict external access to the affected SharePoint service until patching and validation are complete.
- Block any confirmed malicious child process hashes or related outbound destinations if identified.

**Closure criteria:**
- The child process is confirmed as a documented benign SharePoint or IIS administrative action.
- No additional suspicious process, file, or network activity is found on the host during the investigation window.
- The server is patched or otherwise remediated and no further alerts recur after baseline review.
- A clear business owner confirms the activity matches an approved maintenance or monitoring workflow.

<br/>
---
<br/>

## Detection 2: SharePoint OfficeActivity Anomalous Operation Correlated with w3wp Child Process Execution

### Detection Opportunity

Unauthenticated RCE chain on SharePoint producing both anomalous OfficeActivity operations and suspicious process execution from the IIS worker process.

### Intelligence Context

- Rapid7: CVE-2026-63520: Microsoft SharePoint Remote Code Execution (FIXED) — [https://www.rapid7.com/blog/post/etr-cve-2026-63520-microsoft-sharepoint-remote-code-execution-fixed](https://www.rapid7.com/blog/post/etr-cve-2026-63520-microsoft-sharepoint-remote-code-execution-fixed)
  - Context: Rapid7 described chained CVEs enabling unauthenticated RCE on SharePoint. The attack surface spans both SharePoint application-layer activity visible in OfficeActivity and OS-level code execution visible in DeviceProcessEvents, making a correlated detection across both telemetry sources higher fidelity than either alone.

### Search Metadata

- CVEs: CVE-2026-63520, CVE-2026-55040
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Microsoft SharePoint
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-63520, CVE-2026-55040, T1190, Microsoft SharePoint, Windows, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- OfficeActivity, DeviceProcessEvents

### KQL

```kql
let LookbackWindow = 1d;
let BucketSize = 30m;
let SuspiciousSharePointOps = OfficeActivity
| where TimeGenerated > ago(LookbackWindow)
| where OfficeWorkload == "SharePoint"
| where Operation in ("FileUploaded", "FileAccessed", "PageViewed", "FileCheckedOut", "FileSyncDownloadedFull")
| summarize
    OpsCount = count(),
    ClientIP = take_any(ClientIP),
    Operation = take_any(Operation)
    by UserId, TimeBucket = bin(TimeGenerated, BucketSize);
let SuspiciousW3WPChildren = DeviceProcessEvents
| where Timestamp > ago(LookbackWindow)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where InitiatingProcessFolderPath has @"\Windows\System32\inetsrv"
| where FileName in~ (
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe"
)
| extend TimeBucket = bin(Timestamp, BucketSize)
| project
    ProcessTimestamp = Timestamp,
    DeviceName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    SHA256,
    TimeBucket;
SuspiciousW3WPChildren
| join kind=inner SuspiciousSharePointOps on TimeBucket
| project
    ProcessTimestamp,
    DeviceName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    SHA256,
    UserId,
    ClientIP,
    SharePointTimeGenerated = TimeBucket,
    Operation,
    OpsCount
| order by ProcessTimestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate SharePoint file upload or access activity coinciding in time with any IIS child process spawn on the same server will produce a match.
- High-volume SharePoint environments will generate frequent time-bucket matches even without exploitation.
- Administrative PowerShell tasks on SharePoint servers running during periods of normal user activity will correlate.

**Tuning notes:**
- To improve join fidelity, enrich DeviceProcessEvents with the server's public or NAT IP using a DeviceNetworkInfo lookup and join on ClientIP to DevicePublicIP.
- Reduce BucketSize to 10m in lower-activity environments to tighten the correlation window and reduce false positives.
- Scope SuspiciousW3WPChildren to known SharePoint server DeviceNames using a let statement to eliminate noise from other IIS applications.

**Risks / caveats:**
- OfficeActivity requires the Microsoft 365 (Office 365) data connector to be enabled in Sentinel and SharePoint audit logging to be active in the Microsoft 365 compliance portal. If either is absent, the OfficeActivity table will be empty or missing SharePoint records.
- DeviceProcessEvents requires the Microsoft Defender for Endpoint connector to be enabled in Sentinel and MDE agents deployed on SharePoint servers. If absent, the table will have no relevant records.
- KQL does not support 'between' with a non-equi join key in a standard join operator. The original query's join on a time range is syntactically invalid and will not execute. The improved query rewrites this using a time-bucketed equi-join.
- The time-bucket join correlates on a 30-minute window globally, not per SharePoint server. Without an IP-to-host mapping, there is no guarantee the OfficeActivity ClientIP corresponds to the same server where the w3wp.exe child process was observed.

### Triage Runbook

**First 15 minutes:**
- Confirm the alert involves a known SharePoint server and that the OfficeActivity event is plausibly related to the same time window as the process execution.
- Review the SharePoint operation, UserId, ClientIP, and process command line for signs of reconnaissance, staging, or exploitation.
- Check whether the process activity is a high-risk interpreter or LOLBin spawned by w3wp.exe from the IIS system path.
- Look for repeated SharePoint operations or multiple suspicious child processes in the same 30-minute window.
- Determine whether the activity is isolated to one server or appears across multiple SharePoint hosts.

**Evidence to collect:**
- ProcessTimestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, SHA256
- UserId, ClientIP, Operation, OpsCount, and SharePointTimeGenerated from the correlated OfficeActivity event
- Any additional OfficeActivity records for the same UserId or ClientIP around the alert time
- Any DeviceProcessEvents on the same host showing follow-on execution, file drops, or script activity
- Any relevant SharePoint audit or admin logs that explain the operation

**Pivot points:**
- OfficeActivity for the same UserId, ClientIP, and nearby time buckets
- DeviceProcessEvents for the same DeviceName and parent w3wp.exe chain
- DeviceFileEvents for file creation or modification on the SharePoint host
- DeviceNetworkEvents for outbound connections from the SharePoint server
- DeviceLogonEvents or sign-in telemetry to identify suspicious access patterns

**Benign explanations:**
- Normal SharePoint user activity that happened to coincide with a legitimate IIS child process spawn.
- Administrative PowerShell or scripting activity on the SharePoint server during routine maintenance.
- High-volume SharePoint environments where routine file operations overlap with benign process execution.
- Backup, sync, or monitoring activity that creates correlated telemetry without exploitation.

**Escalation criteria:**
- The OfficeActivity operation is unusual for the user or environment and aligns with exploitation precursors.
- The w3wp.exe child process is an interpreter or LOLBin with suspicious command-line content.
- There are multiple correlated events across the same host, user, or time window suggesting active exploitation.
- The server is externally exposed and the activity matches the reported unauthenticated RCE pattern.

**Containment actions:**
- Isolate the SharePoint server if the correlation strongly indicates exploitation.
- Preserve process, file, and audit evidence before any service restart.
- Temporarily restrict external access to the SharePoint application if compromise is likely.
- Block confirmed malicious hashes or destinations if the investigation identifies them.

**Closure criteria:**
- The OfficeActivity event is explained by approved user or administrative activity and the process execution is benign.
- No additional suspicious SharePoint or process activity is found on the host or tenant.
- The server is patched and monitored with no recurrence during the observation period.
- The correlation is determined to be a timing coincidence rather than a true exploitation chain.

<br/>
---
<br/>

## Detection 3: CoolClient Rootkit - Unsigned Kernel Driver Load on Windows Endpoint

### Detection Opportunity

HoneyMyte CoolClient backdoor variant loads a kernel-mode rootkit driver to hide malicious processes, files, and network connections from security tooling.

### Intelligence Context

- Securelist: APT group HoneyMyte upgrades CoolClient: the backdoor gets a kernel-level Windows rootkit — [https://securelist.com/honeymyte-coolclient-driver-rootkit/121028/](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028/)
  - Context: Securelist reported that HoneyMyte upgraded the CoolClient backdoor with a kernel-mode rootkit driver that hides malicious processes, files, and network connections. Loading an unsigned or anomalously signed kernel driver is the earliest detectable action before the rootkit suppresses further telemetry.

### Search Metadata

- CVEs: Not specified
- Threat actors: HoneyMyte
- ATT&CK tags: T1547.006, T1014, T1547
- Products: Not specified
- Platforms: Windows
- Malware: CoolClient
- Tools: Not specified
- Search tags: HoneyMyte, CoolClient, Windows, T1547.006, T1014, T1547

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1547 Boot or Logon Autostart Execution/ T1547.006 Kernel Modules and Extensions (medium); Defense Evasion: T1014 Rootkit (high)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceEvents

### KQL

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "DriverLoad"
| extend ParsedFields = parse_json(AdditionalFields)
| extend ParsedSigner = tostring(ParsedFields.Signer)
| extend ParsedIsSigned = tobool(ParsedFields.IsSigned)
| where (isempty(ParsedSigner) or ParsedIsSigned == false or isnull(ParsedIsSigned))
| where FolderPath matches regex @"(?i)(\\Users\\|\\Temp\\|\\AppData\\|\\ProgramData\\)"
| project
    Timestamp,
    DeviceName,
    FileName,
    FolderPath,
    SHA1,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    ParsedSigner,
    ParsedIsSigned,
    AdditionalFields
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate third-party software that installs unsigned drivers to user-writable paths during installation or update processes.
- Security research or penetration testing tools that load unsigned kernel drivers.
- Enterprise software with drivers staged to ProgramData before installation.

**Tuning notes:**
- Before scheduling, run 'DeviceEvents → where ActionType == "DriverLoad" → take 100 → project AdditionalFields' to confirm Signer and IsSigned subfield availability in the tenant.
- If IsSigned is consistently null, consider removing the isnull fallback and relying solely on the FolderPath signal to reduce noise.
- Build a SHA1 allowlist of known legitimate unsigned drivers in the environment and add a '| where SHA1 !in (AllowlistedHashes)' filter.

**Risks / caveats:**
- AdditionalFields.Signer and AdditionalFields.IsSigned are dynamic subfields that are not guaranteed to be present or consistently populated for DriverLoad events across all MDE sensor versions. The query will silently return no results or incorrect results if these subfields are absent.
- DriverLoad as an ActionType in DeviceEvents must be confirmed present in the tenant by running a count query before scheduling. Some MDE configurations or licensing tiers may not surface this ActionType.
- If AdditionalFields does not contain Signer or IsSigned for DriverLoad events in the target tenant, the isnull(ParsedIsSigned) fallback will match all DriverLoad events from suspicious paths, increasing false positive volume significantly.
- The FolderPath regex may miss rootkit drivers staged to non-standard writable paths not covered by the current pattern.

### Triage Runbook

**First 15 minutes:**
- Confirm the driver load occurred from a user-writable or temporary path and not a known system driver location.
- Review the initiating process, command line, and signer information to identify what installed or loaded the driver.
- Check whether the endpoint is already showing signs of tampering, missing telemetry, or unusual process/network behavior.
- Look for recent installer activity, archive extraction, or privilege escalation preceding the driver load.
- If the driver is still present, preserve the file path and hash before any cleanup action.

**Evidence to collect:**
- Timestamp, DeviceName, FileName, FolderPath, SHA1, ParsedSigner, ParsedIsSigned, AdditionalFields
- InitiatingProcessFileName, InitiatingProcessFolderPath, and InitiatingProcessCommandLine
- Any related DeviceEvents showing driver installation, service creation, or security setting changes
- Recent DeviceProcessEvents and DeviceFileEvents on the same host around the load time
- Any evidence of hidden processes, network connections, or missing telemetry after the driver load

**Pivot points:**
- DeviceEvents for other DriverLoad or service-related actions on the same DeviceName
- DeviceProcessEvents for the initiating process and any installer chain
- DeviceFileEvents for the driver file path and related dropped files
- DeviceNetworkEvents for suspicious outbound connections from the endpoint
- DeviceRegistryEvents if available for service or driver persistence artifacts

**Benign explanations:**
- Legitimate third-party software installation or update that stages a driver in a writable location.
- Security research, testing, or administrative tooling that intentionally loads a driver.
- Enterprise software that temporarily stages drivers before moving them into a standard system path.
- A vendor installer that is unsigned but approved in the environment.

**Escalation criteria:**
- The driver is unsigned or untrusted and loaded from a user-writable or temporary path without a clear business justification.
- The initiating process is suspicious, unknown, or associated with malware staging behavior.
- The endpoint shows signs of defense evasion, hidden activity, or telemetry suppression after the load.
- The same host has other suspicious process, file, or network events indicating active compromise.

**Containment actions:**
- Isolate the endpoint if the driver load is not clearly authorized or if rootkit behavior is suspected.
- Preserve the driver file, memory, and relevant logs before rebooting or remediation.
- Disable the affected endpoint from sensitive network segments until validated.
- Block the driver hash or associated installer if confirmed malicious.

**Closure criteria:**
- The driver is verified as a legitimate, approved component from a trusted vendor or internal software package.
- The file hash and signer are matched to an authorized installation record.
- No additional suspicious persistence, hiding, or network behavior is found on the endpoint.
- The endpoint is restored to a trusted state and monitored without recurrence.

<br/>
---
<br/>

## Detection 4: Armored Likho Still Toolkit - Non-Telegram Process Accessing Telegram Local Storage

### Detection Opportunity

Armored Likho Still Toolkit accesses Telegram local storage paths to steal session data and credentials from victim machines.

### Intelligence Context

- Securelist: Armored Likho expands its cyber-espionage toolkit — [https://securelist.com/armored-likho-still-toolkit/121033/](https://securelist.com/armored-likho-still-toolkit/121033/)
  - Context: Securelist reported that the Armored Likho Still Toolkit targets Telegram data on Windows victims. The toolkit accesses Telegram's local storage directory to steal session tokens and eavesdrop on communications. Unauthorized file access to Telegram AppData paths by non-Telegram processes is the primary detection signal.

### Search Metadata

- CVEs: Not specified
- Threat actors: Armored Likho
- ATT&CK tags: T1213
- Products: Telegram
- Platforms: Windows
- Malware: Not specified
- Tools: Still Toolkit
- Search tags: Armored Likho, Still Toolkit, Telegram, Windows, T1213

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Collection: T1213 Data from Information Repositories (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- File-read style telemetry must be confirmed before scheduling detections that depend on FileRead, FileAccessed, or SensitiveFileRead-style events.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_cs @"AppData\Roaming\Telegram Desktop"
| where ActionType in ("FileCopied", "FileCreated", "FileModified")
| where InitiatingProcessFileName !in~ (
    "Telegram.exe",
    "Updater.exe"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    ActionType,
    FileName,
    FolderPath,
    SHA256
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Enterprise backup agents or file sync tools (e.g., OneDrive, Dropbox) that back up the entire AppData\Roaming directory including Telegram Desktop.
- Antivirus or EDR products performing file scanning that touch Telegram storage paths.
- User-initiated file copy or archive operations that include the Telegram Desktop directory.

**Tuning notes:**
- Add known backup agent and sync tool process names to the exclusion list after reviewing baseline results.
- If FileCopied generates excessive noise from legitimate backup operations, narrow ActionType to FileCreated only, which is more indicative of a tool staging exfiltration output.
- Consider adding a second condition requiring InitiatingProcessFolderPath to not contain standard system or program files paths to further reduce noise from security tooling.

**Risks / caveats:**
- FileRead and FileAccessed are not standard ActionType values in DeviceFileEvents for Defender XDR. Including them in the ActionType filter will not cause a syntax error but will silently return zero results for those values. The improved query uses only confirmed ActionType values (FileCopied, FileCreated, FileModified) and notes that FileRead telemetry is not available in this table.
- FileRead telemetry is not available in DeviceFileEvents, so read-only access to Telegram session files without a copy or write operation will not be detected by this query.
- The Still Toolkit may use a renamed executable that does not match Telegram.exe or Updater.exe, which would be caught by this query, but legitimate tools with unexpected names may also match.
- Backup and sync agents that access AppData\Roaming broadly will generate false positives and require exclusion tuning.

### Triage Runbook

**First 15 minutes:**
- Confirm the process is not Telegram.exe or Updater.exe and review the initiating command line and parent process.
- Check whether the access is a copy, create, or modify operation against the Telegram Desktop AppData path.
- Identify the user context and whether the activity occurred during normal user work or from an unexpected process tree.
- Look for nearby archive creation, exfiltration staging, or other file access to messaging or browser data.
- Determine whether the process is a known backup, sync, or security tool before escalating.

**Evidence to collect:**
- Timestamp, DeviceName, AccountName, AccountDomain, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName
- ActionType, FileName, FolderPath, and SHA256 for the accessed Telegram-related files
- Any related DeviceFileEvents showing archive creation, copying, or modification of nearby user data
- Any DeviceProcessEvents for the same initiating process before and after the alert
- Any sign-in or session activity that suggests Telegram account abuse or credential theft

**Pivot points:**
- DeviceFileEvents for the same DeviceName and Telegram Desktop path
- DeviceProcessEvents for the initiating process tree and any child processes
- DeviceNetworkEvents for outbound connections from the same process or host
- DeviceLogonEvents or user activity telemetry to confirm whether the user was active
- Other DeviceFileEvents for access to browser profiles, password stores, or messaging app data

**Benign explanations:**
- Backup, sync, or endpoint protection software scanning or copying user profile data.
- A user manually copying Telegram Desktop data for migration or troubleshooting.
- Legitimate enterprise software that inventories or backs up AppData content.
- Antivirus or EDR file scanning that touches Telegram storage paths.

**Escalation criteria:**
- The process is unknown, unsigned, or clearly unrelated to approved software and is accessing Telegram storage.
- The activity is accompanied by archive creation, credential-store access, or other collection behavior.
- There is evidence of exfiltration staging, suspicious network traffic, or additional data theft from the same host.
- The user reports no legitimate reason for the access and the process tree is suspicious.

**Containment actions:**
- Isolate the endpoint if the process is confirmed or strongly suspected to be credential theft tooling.
- Preserve the process tree, file artifacts, and relevant user profile data before cleanup.
- Reset or protect the affected Telegram account if session theft is likely.
- Block the suspicious process hash or parent executable if identified.

**Closure criteria:**
- The process is verified as a legitimate backup, sync, or administrative tool.
- The Telegram access is explained by an approved user action and no other suspicious collection is found.
- No evidence of exfiltration, credential theft, or additional sensitive file access is present.
- The host remains stable with no recurrence after baseline review and monitoring.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- SharePoint OfficeActivity Anomalous Operation Correlated with w3wp Child Process Execution: Do not schedule yet; validate as an analyst-led hunt first.
- Armored Likho Still Toolkit - Non-Telegram Process Accessing Telegram Local Storage: Do not schedule yet; validate as an analyst-led hunt first.

**Other deployment dependency:**
- CoolClient Rootkit - Unsigned Kernel Driver Load on Windows Endpoint: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Telemetry availability:**
- File-read style telemetry must be confirmed before scheduling detections that depend on FileRead, FileAccessed, or SensitiveFileRead-style events.

**Shared-table notes:**
- DeviceProcessEvents: shared by SharePoint IIS Worker Process Spawning Suspicious Child Process; SharePoint OfficeActivity Anomalous Operation Correlated with w3wp Child Process Execution

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: SharePoint IIS Worker Process Spawning Suspicious Child Process.
2. Resolve environment-mapping detections next: CoolClient Rootkit - Unsigned Kernel Driver Load on Windows Endpoint.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: SharePoint OfficeActivity Anomalous Operation Correlated with w3wp Child Process Execution; Armored Likho Still Toolkit - Non-Telegram Process Accessing Telegram Local Storage.

### Hunting Agenda and Promotion Criteria

- SharePoint OfficeActivity Anomalous Operation Correlated with w3wp Child Process Execution: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Armored Likho Still Toolkit - Non-Telegram Process Accessing Telegram Local Storage: Do not schedule yet; validate as an analyst-led hunt first.; confirm required file-access telemetry exists and produces representative events; baseline expected benign activity and define an alert-volume threshold.
- CoolClient Rootkit - Unsigned Kernel Driver Load on Windows Endpoint: Defender for Endpoint file-event coverage must be confirmed on the target host population.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

This run exposes a file-access telemetry blind spot: browser cookie theft and resource-file loader behaviors depend on file-read style events that may not be emitted in every Defender deployment. Validate that coverage before treating these as scheduled analytics.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
