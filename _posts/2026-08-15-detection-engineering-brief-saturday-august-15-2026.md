---
layout: post
title: "Detection Engineering Brief - Saturday, August 15, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-08-15
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Armored Likho
  - Telegram
  - Windows
  - Still Toolkit
  - HoneyMyte
  - CoolClient
  - Microsoft SharePoint
  - Microsoft products
  - CVE-2026-46300
  - T1190
  - Metasploit
  - Linux
  - T1204.002
  - T1059
  - T1059.001
  - T1204
  - T1547.006
  - T1014
  - T1547
  - T1068
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 3 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Armored Likho, Telegram, Windows, Still Toolkit, HoneyMyte, CoolClient, Microsoft SharePoint, Microsoft products, CVE-2026-46300, T1190, Metasploit, Linux, T1204.002, T1059, T1059.001, T1204, T1547.006, T1014, T1547, T1068.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: CoolClient Rootkit - Unsigned or Low-Prevalence Kernel Driver Load on Windows; SharePoint RCE Chain - Worker Process Spawning Unexpected Shell; Armored Likho - Office or Script Interpreter Spawning Suspicious Child Process After Document Open; Metasploit Linux LPE - Non-Root Process Spawning Root Child Process (CVE-2026-46300).

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Still Toolkit - Non-Telegram Process Accessing Telegram tdata Directory

### Detection Opportunity

Still Toolkit accesses Telegram session data files stored in the tdata directory to steal credentials and session tokens on Windows endpoints.

### Intelligence Context

- Securelist: Armored Likho expands its cyber-espionage toolkit — [https://securelist.com/armored-likho-still-toolkit/121033/](https://securelist.com/armored-likho-still-toolkit/121033/)
  - Context: The Still Toolkit, attributed to Armored Likho, targets Telegram session data stored in the tdata directory on Windows to steal credentials and session tokens as part of a cyber-espionage campaign using fundraising lures.

### Search Metadata

- CVEs: Not specified
- Threat actors: Armored Likho
- ATT&CK tags: T1204.002, T1059, T1059.001, T1204
- Products: Telegram
- Platforms: Windows
- Malware: Still Toolkit
- Tools: Not specified
- Search tags: Armored Likho, Telegram, Windows, Still Toolkit, T1204.002, T1059, T1059.001, T1204

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1204 User Execution/ T1204.002 Malicious File (medium); Execution: T1059 Command and Scripting Interpreter (high); Execution: T1059 Command and Scripting Interpreter/ T1059.001 PowerShell (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where FolderPath has_any (@"\Telegram Desktop\tdata", @"\AppData\Roaming\Telegram Desktop\tdata")
| where ActionType in ("FileRead", "FileAccessed", "FileCreated", "FileModified")
| where InitiatingProcessFileName !in~ ("Telegram.exe", "Updater.exe", "Update.exe")
| where not(InitiatingProcessFileName startswith_cs "Telegram")
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    InitiatingProcessAccountName,
    InitiatingProcessId,
    FolderPath,
    FileName,
    ActionType
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Backup agents (e.g., Veeam, Windows Backup) that traverse AppData directories may trigger if they read tdata files.
- Antivirus or EDR sensors performing on-access scanning may appear as accessing tdata files.
- User-initiated file copy or archiving tools (7-Zip, robocopy) run manually against AppData.

**Tuning notes:**
- After initial deployment, collect InitiatingProcessFileName values from results over 7 days and add confirmed-legitimate processes to the exclusion list.
- If alert volume is high, add a DeviceName filter scoped to endpoints known to have Telegram Desktop installed.

**Risks / caveats:**
- ActionType values 'FileRead' and 'FileAccessed' may not be emitted by MDE on all Windows versions or sensor configurations; verify that these ActionType values appear in DeviceFileEvents for the environment before relying on them as primary filters.
- Backup and AV processes will require allowlist entries after baselining; the exclusion list should be extended with observed legitimate accessors.
- The 1-day lookback window may miss low-frequency access patterns; consider extending to 7 days for initial baselining.
- If Telegram Desktop is installed in a non-standard path (e.g., outside AppData), the path filter will not match.

### Triage Runbook

**First 15 minutes:**
- Confirm the accessing process name, command line, parent process, and account on the alerting host; treat Office, script interpreters, archivers, backup tools, and unknown binaries as suspicious until explained.
- Check whether the same host or user also shows recent Office/script execution, phishing-lure activity, or other suspicious process lineage consistent with the Still Toolkit infection chain.
- Review the specific tdata files accessed and whether access was read-only, modified, or created; multiple file reads across the tdata directory are more concerning than a single incidental access.
- Determine whether the process is signed, expected on the endpoint, and present in your approved software inventory; if not, assume possible credential theft and escalate quickly.

**Evidence to collect:**
- InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessAccountName, and InitiatingProcessId from the alert.
- FolderPath, FileName, and ActionType to identify which Telegram session artifacts were touched and whether the activity was read, modified, or created.
- Recent DeviceProcessEvents on the same DeviceName for the prior 1-24 hours to identify the launch chain and any follow-on tooling.
- User sign-in activity for the affected account, including unusual logons, new geographies, or concurrent sessions that could indicate stolen Telegram tokens.
- Any related email, document, or download artifact that may have delivered the initial lure or payload.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and InitiatingProcessAccountName to reconstruct process lineage.
- DeviceFileEvents for additional Telegram tdata access by the same process or account.
- DeviceLogonEvents or Entra sign-in logs for suspicious logons tied to the affected user.
- Email and attachment telemetry if the host recently opened a lure document or archive.
- DeviceNetworkEvents to look for immediate outbound connections after tdata access.

**Benign explanations:**
- Telegram Desktop itself, Updater.exe, or Update.exe accessing tdata during normal operation or update activity.
- Backup, sync, or endpoint protection software scanning AppData directories and touching Telegram files.
- User-initiated file copy, archive, or migration activity involving Telegram profile data.
- A known internal support or migration tool that legitimately handles Telegram Desktop data on managed endpoints.

**Escalation criteria:**
- The accessing process is unknown, unsigned, or launched from Office, script, temp, or user-writable paths.
- Multiple tdata files were accessed, especially by PowerShell, cmd.exe, wscript.exe, cscript.exe, mshta.exe, or another non-standard process.
- The same user or host shows suspicious logons, new Telegram sessions, or follow-on malware behavior.
- No approved business justification exists for the process accessing Telegram session data.

**Containment actions:**
- Isolate the endpoint if the process is unknown or there is evidence of broader compromise.
- Disable or reset the affected user account if Telegram session theft is likely and the account is high value.
- Terminate the suspicious process and preserve the binary, command line, and parent-child process chain for forensics.
- Force Telegram session revocation or password reset if the account is confirmed or strongly suspected to be exposed.

**Closure criteria:**
- The accessing process is confirmed as Telegram.exe, Updater.exe, Update.exe, or another approved legitimate accessor.
- The activity matches a documented backup, migration, or security tool and no other suspicious telemetry is present.
- No additional suspicious process lineage, logon anomalies, or follow-on access to Telegram data is found on the host or account.
- The event is added to the allowlist or tuning set after validation with endpoint owners.

<br/>
---
<br/>

## Detection 2: CoolClient Rootkit - Unsigned or Low-Prevalence Kernel Driver Load on Windows

### Detection Opportunity

CoolClient backdoor loads a kernel-mode rootkit driver to hide malicious processes, files, and network connections on Windows systems, attributed to APT group HoneyMyte.

### Intelligence Context

- Securelist: APT group HoneyMyte upgrades CoolClient: the backdoor gets a kernel-level Windows rootkit — [https://securelist.com/honeymyte-coolclient-driver-rootkit/121028/](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028/)
  - Context: HoneyMyte upgraded the CoolClient backdoor with a kernel-mode rootkit driver that hides malicious processes, files, and network connections. The driver load event is the earliest detectable signal before rootkit concealment takes effect.

### Search Metadata

- CVEs: Not specified
- Threat actors: HoneyMyte
- ATT&CK tags: T1547.006, T1014, T1547
- Products: Windows
- Platforms: Windows
- Malware: CoolClient
- Tools: Not specified
- Search tags: HoneyMyte, CoolClient, Windows, T1547.006, T1014, T1547

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1547 Boot or Logon Autostart Execution/ T1547.006 Kernel Modules and Extensions (high); Defense Evasion: T1014 Rootkit (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceEvents, DeviceProcessEvents

### KQL

```kql
let TrustedDriverPaths = dynamic([
    @"c:\windows\system32\drivers",
    @"c:\windows\syswow64\drivers",
    @"c:\windows\inf",
    @"c:\windows\winsxs",
    @"c:\program files"
]);
let DriverLoads = DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "DriverLoad"
| where isnotempty(SHA256)
| extend DriverFolder = tolower(FolderPath)
| where not(DriverFolder has_any (TrustedDriverPaths))
| project
    DriverLoadTime = Timestamp,
    DeviceName,
    DriverFileName = FileName,
    DriverFolder,
    SHA256,
    InitiatingProcessFileName;
let PostLoadActivity = DeviceProcessEvents
| where Timestamp > ago(7d)
| project
    ProcessTime = Timestamp,
    DeviceName,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    SpawnedProcess = FileName,
    InitiatingProcessFileName;
DriverLoads
| join kind=leftouter (PostLoadActivity) on DeviceName
| where isnull(ProcessTime) or ProcessTime between (DriverLoadTime .. (DriverLoadTime + 5m))
| project
    DriverLoadTime,
    ProcessTime,
    DeviceName,
    DriverFileName,
    DriverFolder,
    SHA256,
    InitiatingProcessFileName,
    SpawnedProcess,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName
| order by DriverLoadTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Third-party security software (EDR, AV, DLP) that loads kernel drivers from non-standard installation directories.
- Hardware vendor drivers (GPU, NIC, storage) installed to custom Program Files subdirectories not covered by the exclusion list.
- Virtualization software (VMware, VirtualBox, Hyper-V tools) loading drivers from application-specific paths.

**Tuning notes:**
- After initial run, collect DriverFolder values from results and add confirmed-legitimate vendor paths to the TrustedDriverPaths dynamic list.
- Consider correlating SHA256 values against threat intelligence or VirusTotal via external enrichment after hunting results are reviewed.
- Adjust the post-load correlation window from 5 minutes based on observed staging timelines in the environment.

**Risks / caveats:**
- ActionType == 'DriverLoad' availability in DeviceEvents depends on MDE sensor version and Windows kernel telemetry configuration; this ActionType may not be present in all environments. Verify with a baseline count before relying on this query.
- DeviceFileEvents was listed as a required table in the original detection but is not used in the query logic; removed to avoid confusion.
- The leftouter join will return driver load events with no correlated process activity; analysts should triage both correlated and uncorrelated rows.
- Third-party security and hardware drivers loaded from non-standard paths will require allowlist entries after baselining.

### Triage Runbook

**First 15 minutes:**
- Validate the driver file path, SHA256, and initiating process; treat any driver loaded from a non-standard path as potentially malicious until proven otherwise.
- Check whether the driver load was followed by unusual process behavior, hidden services, network anomalies, or missing telemetry on the same host.
- Identify the parent process and account that initiated the driver load; unexpected user-context loading of a kernel driver is highly suspicious.
- Confirm whether the driver belongs to a known security, hardware, virtualization, or management product installed on the endpoint.

**Evidence to collect:**
- DriverFileName, DriverFolder, SHA256, DriverLoadTime, and DeviceName from the alert.
- InitiatingProcessFileName and any available InitiatingProcessCommandLine or account context tied to the load.
- Any correlated DeviceProcessEvents within 5 minutes after the load, especially new shells, service creation, or suspicious child processes.
- Installed software inventory and driver/vendor ownership for the host to validate whether the driver is expected.
- Recent DeviceNetworkEvents and DeviceEvents for signs of concealment, tampering, or defense evasion after the load.

**Pivot points:**
- DeviceEvents for additional DriverLoad events on the same DeviceName or SHA256.
- DeviceProcessEvents for post-load activity and suspicious parent-child chains.
- DeviceNetworkEvents for hidden or unexpected outbound connections from the host.
- DeviceFileEvents for related driver file creation, modification, or staging activity.
- DeviceInfo or software inventory to identify legitimate vendor drivers and installed security tools.

**Benign explanations:**
- Legitimate third-party security software loading a kernel driver from a non-standard installation directory.
- Hardware vendor drivers for GPU, NIC, storage, or virtualization software installed outside standard Windows paths.
- Enterprise management or DLP software that uses a signed kernel component.
- A newly installed or updated driver from a trusted vendor that is not yet in the allowlist.

**Escalation criteria:**
- The driver is unsigned, low prevalence, or not attributable to a trusted vendor/product.
- The driver path is outside standard Windows or approved vendor locations and no business justification exists.
- There are signs of concealment, missing telemetry, hidden processes, or network activity consistent with a rootkit.
- The same host shows additional suspicious persistence, privilege escalation, or defense evasion behavior.

**Containment actions:**
- Isolate the host if the driver is untrusted or rootkit behavior is suspected.
- Suspend or block the associated user account if the load was initiated from a compromised context.
- Preserve the driver file, memory, and relevant event telemetry before rebooting or remediation.
- Coordinate with endpoint engineering before removal if the driver may belong to a critical security or hardware product.

**Closure criteria:**
- The driver is confirmed as a legitimate, signed component from an approved vendor or security product.
- The SHA256 and path match a known-good baseline and no suspicious post-load activity is present.
- The event is explained by a documented installation, update, or maintenance action.
- Allowlist updates are applied only after validation with endpoint owners and driver inventory.

<br/>
---
<br/>

## Detection 3: SharePoint RCE Chain - Worker Process Spawning Unexpected Shell

### Detection Opportunity

SharePoint critical RCE chain exploitation results in the SharePoint IIS worker process (w3wp.exe) spawning unexpected command interpreter child processes such as cmd.exe or powershell.exe.

### Intelligence Context

- Rapid7: Patch Tuesday - August 2026 — [https://www.rapid7.com/blog/post/em-patch-tuesday-august-2026](https://www.rapid7.com/blog/post/em-patch-tuesday-august-2026)
  - Context: Rapid7 identified a critical SharePoint RCE chain in the August 2026 Patch Tuesday release. SharePoint RCE exploitation typically results in the IIS worker process spawning shell interpreters, which is the primary detectable post-exploitation signal.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.001
- Products: Microsoft SharePoint
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Microsoft SharePoint, Windows, Microsoft products, T1059, T1059.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (high); Execution: T1059 Command and Scripting Interpreter/ T1059.001 PowerShell (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let SharePointServers = dynamic([]);
DeviceProcessEvents
| where Timestamp > ago(1d)
| where array_length(SharePointServers) == 0 or DeviceName in~ (SharePointServers)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ (
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "rundll32.exe",
    "regsvr32.exe"
)
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    InitiatingProcessId,
    FileName,
    ProcessCommandLine,
    ActionType
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- SharePoint health analyzer or timer jobs that legitimately invoke PowerShell for administrative tasks.
- Monitoring agents or deployment tools that spawn cmd.exe or powershell.exe from IIS worker processes during maintenance windows.
- Other IIS-hosted applications on the same server that spawn shell processes for legitimate reasons.

**Tuning notes:**
- Populate the SharePointServers dynamic list with hostnames of SharePoint servers before scheduling.
- After initial deployment, review ProcessCommandLine values for known-legitimate SharePoint administrative invocations and add exclusions.
- Consider filtering on InitiatingProcessCommandLine containing SharePoint-specific application pool names (e.g., 'SharePoint') for additional precision.

**Risks / caveats:**
- The SharePointServers dynamic list is empty in the improved KQL; when empty, the query runs across all devices. Populate this list with SharePoint server hostnames before scheduling as a production rule.
- SharePoint administrative PowerShell jobs may trigger the rule; baseline w3wp.exe child process activity on SharePoint servers before enabling.
- The rule does not distinguish between SharePoint application pools and other IIS application pools on the same host; w3wp.exe process command line inspection for SharePoint pool names can further reduce noise.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is an actual SharePoint server and not another IIS workload; if the server list is not populated, treat the alert as higher risk until validated.
- Review the child process name and command line for cmd.exe, powershell.exe, pwsh.exe, or LOLBins spawned by w3wp.exe.
- Check whether the activity aligns with a known maintenance window, deployment job, or SharePoint administrative task.
- Look for immediate follow-on actions such as webshell creation, suspicious file writes, new services, or outbound connections.

**Evidence to collect:**
- DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessId, FileName, and ProcessCommandLine from the alert.
- The w3wp.exe application pool context and any SharePoint-specific identifiers in the command line.
- Recent DeviceProcessEvents on the same host for additional child processes spawned by w3wp.exe.
- DeviceFileEvents for webroot or SharePoint directory modifications, especially script, aspx, or webshell-like files.
- DeviceNetworkEvents for outbound connections from the SharePoint host after the shell spawn.

**Pivot points:**
- DeviceProcessEvents filtered to the same DeviceName and InitiatingProcessFileName == w3wp.exe.
- DeviceFileEvents for recent writes in SharePoint web directories and temporary folders.
- DeviceNetworkEvents for suspicious outbound traffic from the SharePoint server.
- IIS, SharePoint, and Windows event logs for application pool restarts, errors, or exploit indicators.
- Change-management or deployment records for the server and time window.

**Benign explanations:**
- Legitimate SharePoint administration or timer jobs invoking PowerShell for maintenance tasks.
- Deployment tools, monitoring agents, or patching workflows that spawn shells from IIS worker processes.
- Other IIS-hosted applications on the same server that use w3wp.exe for normal automation.
- Known SharePoint health or support operations during approved maintenance windows.

**Escalation criteria:**
- The host is a confirmed SharePoint server and the child process is not tied to an approved maintenance or admin task.
- The spawned process is an interpreter or LOLBin with suspicious command-line arguments, encoded content, or download behavior.
- There are signs of webshell placement, suspicious file writes, or outbound command-and-control traffic.
- Multiple w3wp.exe child process events occur outside normal administrative windows.

**Containment actions:**
- Isolate the SharePoint server if exploitation is suspected and business impact can be managed.
- Disable external access to the affected SharePoint service or application pool if coordinated containment is required.
- Preserve IIS logs, process telemetry, and relevant webroot files before remediation.
- If a webshell or active payload is confirmed, coordinate emergency patching and credential review for service accounts.

**Closure criteria:**
- The host is confirmed as a SharePoint server and the process activity matches a documented administrative or deployment action.
- The child process command line is benign and no webroot changes or suspicious network activity are found.
- The alert is tuned with a validated SharePoint server hostname list and known-good maintenance patterns.
- No additional suspicious w3wp.exe child processes appear during the review window.

<br/>
---
<br/>

## Detection 4: Armored Likho - Office or Script Interpreter Spawning Suspicious Child Process After Document Open

### Detection Opportunity

Malicious document delivered via fundraising lure by Armored Likho causes Office applications or script interpreters to spawn unexpected child processes as the initial stage of the Still Toolkit infection chain.

### Intelligence Context

- Securelist: Armored Likho expands its cyber-espionage toolkit — [https://securelist.com/armored-likho-still-toolkit/121033/](https://securelist.com/armored-likho-still-toolkit/121033/)
  - Context: Armored Likho delivers the Still Toolkit via a fundraising-themed lure document. The infection chain begins with a document or file that causes Office or a script interpreter to spawn malicious child processes, leading to Telegram data theft and eavesdropping.

### Search Metadata

- CVEs: Not specified
- Threat actors: Armored Likho
- ATT&CK tags: T1204.002, T1059, T1059.001, T1204
- Products: Telegram
- Platforms: Windows
- Malware: Still Toolkit
- Tools: Not specified
- Search tags: Armored Likho, Telegram, Windows, Still Toolkit, T1204.002, T1059, T1059.001, T1204

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1204 User Execution/ T1204.002 Malicious File (medium); Execution: T1059 Command and Scripting Interpreter (high); Execution: T1059 Command and Scripting Interpreter/ T1059.001 PowerShell (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let LureSpawn = DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe", "cmd.exe"
)
| where FileName !in~ (
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "splwow64.exe", "dw20.exe", "dwwin.exe",
    "msosync.exe", "msoasb.exe", "OfficeClickToRun.exe"
)
| project
    SpawnTime = Timestamp,
    DeviceName,
    ParentProcess = InitiatingProcessFileName,
    ChildProcess = FileName,
    ProcessCommandLine,
    InitiatingProcessAccountName;
let TdataAccess = DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any (@"\Telegram Desktop\tdata", @"\AppData\Roaming\Telegram Desktop\tdata")
| where ActionType in ("FileRead", "FileAccessed", "FileCreated", "FileModified")
| where InitiatingProcessFileName !in~ ("Telegram.exe", "Updater.exe", "Update.exe")
| project
    TdataTime = Timestamp,
    DeviceName,
    AccessingProcess = InitiatingProcessFileName,
    AccessingProcessCommandLine = InitiatingProcessCommandLine,
    FolderPath,
    FileName;
LureSpawn
| join kind=inner (TdataAccess) on DeviceName
| where TdataTime between (SpawnTime .. (SpawnTime + 30m))
| project
    SpawnTime,
    TdataTime,
    DeviceName,
    ParentProcess,
    ChildProcess,
    ProcessCommandLine,
    InitiatingProcessAccountName,
    AccessingProcess,
    AccessingProcessCommandLine,
    FolderPath,
    FileName
| order by SpawnTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Office macros or automation scripts that legitimately spawn PowerShell or cmd.exe for business processes, followed by a user manually accessing Telegram within 30 minutes.
- IT administration scripts that invoke script interpreters from Office-adjacent processes on endpoints where Telegram is installed.
- Security awareness or training tools that simulate phishing and spawn child processes.

**Tuning notes:**
- Reduce the correlation window from 30 minutes if the observed infection chain in test scenarios completes faster.
- Add additional Office helper process exclusions to the ChildProcess filter based on observed legitimate Office automation in the environment.
- Run each subquery independently first to assess baseline event volume before executing the join.

**Risks / caveats:**
- ActionType values 'FileRead' and 'FileAccessed' in DeviceFileEvents may not be emitted on all MDE sensor configurations; verify tdata access events are present before relying on the TdataAccess subquery.
- The 30-minute correlation window may produce coincidental matches on endpoints with active Office usage and Telegram installed; analyst review of each result is required.
- The LureSpawn subquery will match any Office or script interpreter child process spawn, not only those attributable to malicious documents; context from ProcessCommandLine is needed to distinguish.
- If Telegram Desktop is installed in a non-standard path, the tdata path filter will not match.

### Triage Runbook

**First 15 minutes:**
- Inspect the parent and child process names, command lines, and account context to determine whether Office, script, or shell execution is involved.
- Check whether the same host also shows Telegram tdata access, suspicious downloads, or other post-document activity within the 30-minute window.
- Review the child process for encoded PowerShell, cmd.exe, mshta.exe, or other suspicious interpreter behavior.
- Identify the likely document or file open event that preceded the process spawn and whether the user recently received a fundraising-themed lure or similar phishing content.

**Evidence to collect:**
- SpawnTime, DeviceName, ParentProcess, ChildProcess, ProcessCommandLine, and InitiatingProcessAccountName from the alert.
- TdataTime, AccessingProcess, AccessingProcessCommandLine, FolderPath, and FileName if the correlated Telegram access is present.
- Recent DeviceProcessEvents for the same host to reconstruct the full chain from document open to child process execution.
- Email, download, or browser telemetry that may identify the lure document source.
- Any file hashes or filenames for the document, script, or dropped payload involved in the chain.

**Pivot points:**
- DeviceProcessEvents for Office, script interpreter, and shell activity on the same DeviceName.
- DeviceFileEvents for Telegram tdata access and any dropped files in user-writable locations.
- Email and attachment telemetry to identify the lure source and recipients.
- DeviceNetworkEvents for outbound connections after the suspicious child process starts.
- DeviceLogonEvents or sign-in logs for unusual activity by the affected user.

**Benign explanations:**
- Legitimate Office automation, macros, or add-ins that spawn PowerShell or cmd.exe for business workflows.
- Security awareness simulations or internal training exercises that intentionally mimic phishing behavior.
- Approved IT scripts launched from Office-adjacent processes during support or deployment tasks.
- A user opening a document and later independently accessing Telegram within the correlation window by coincidence.

**Escalation criteria:**
- The child process is an interpreter or LOLBin with suspicious arguments, and no approved business reason exists.
- The same host also shows Telegram tdata access, credential theft indicators, or other malware-like behavior.
- The document source is untrusted, external, or matches a phishing campaign pattern.
- Multiple users or hosts show the same lure-to-execution pattern, indicating an active campaign.

**Containment actions:**
- Isolate the endpoint if the process chain is clearly malicious or linked to broader compromise.
- Quarantine the email or remove the lure document from circulation if the source is identified.
- Reset credentials for the affected user if there is evidence of token theft or follow-on access.
- Block the suspicious payload or script path if it is still reachable on the host.

**Closure criteria:**
- The process chain is explained by a documented macro, automation, or training activity and no malicious follow-on behavior exists.
- The correlated Telegram access is confirmed benign or unrelated to the document execution.
- No suspicious command-line content, dropped files, or network activity is observed after review.
- The event is used to tune known-good Office helper processes or approved automation patterns.

<br/>
---
<br/>

## Detection 5: Metasploit Linux LPE - Non-Root Process Spawning Root Child Process (CVE-2026-46300)

### Detection Opportunity

Metasploit module exploiting CVE-2026-46300 Linux kernel LPE causes a non-privileged process to spawn a child process running as root, indicating successful local privilege escalation.

### Intelligence Context

- Rapid7: Metasploit Wrap Up: Lot of summer shells and fit http profiles — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-lot-of-summer-shells-and-fit-http-profiles](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-lot-of-summer-shells-and-fit-http-profiles)
  - Context: Rapid7 added a Metasploit module for CVE-2026-46300, a Linux kernel local privilege escalation vulnerability. Successful exploitation results in a non-root process gaining root-level execution, detectable as an unexpected privilege change in process telemetry.

### Search Metadata

- CVEs: CVE-2026-46300
- Threat actors: Not specified
- ATT&CK tags: T1190, T1068
- Products: Metasploit
- Platforms: Linux
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-46300, T1190, Metasploit, Linux, T1068

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Privilege Escalation: T1068 Exploitation for Privilege Escalation (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let LinuxDevices = DeviceInfo
| where OSPlatform == "Linux"
| distinct DeviceName;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName in (LinuxDevices)
| where AccountName == "root"
| where isnotempty(InitiatingProcessAccountName)
| where InitiatingProcessAccountName != "root"
| where InitiatingProcessFileName !in~ (
    "sudo", "su", "doas", "pkexec",
    "sshd", "login", "systemd", "init",
    "cron", "at", "newgrp", "runuser",
    "start-stop-daemon", "capsh"
)
| where isnotempty(InitiatingProcessFileName)
| project
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AccountName,
    FileName,
    ProcessCommandLine,
    ActionType
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Setuid binaries not included in the exclusion list that legitimately escalate to root (e.g., passwd, mount, ping on older Linux distributions).
- Container orchestration agents (e.g., containerd, dockerd) that spawn root processes from non-root parent contexts.
- Configuration management tools (Ansible, Chef, Puppet) that invoke privilege escalation outside of sudo.
- Custom capability-enabled binaries in the environment that do not appear in the exclusion list.

**Tuning notes:**
- After initial run, review InitiatingProcessFileName values in results and add confirmed-legitimate escalation binaries to the exclusion list.
- Scope DeviceName to known internet-facing or sensitive Linux hosts to prioritize highest-risk exploitation targets.
- Verify InitiatingProcessAccountName field population by running a baseline count on Linux devices before relying on this query.

**Risks / caveats:**
- The OSPlatform field is not a standard field in DeviceProcessEvents in Defender XDR; Linux device filtering should use the DeviceInfo table joined on DeviceName or rely on the MDE Linux agent being deployed only to Linux hosts. The 'Platform' field referenced in the original query is also non-standard for this table.
- InitiatingProcessAccountName population for Linux endpoints in MDE DeviceProcessEvents is not guaranteed across all MDE Linux agent versions; verify field population before relying on this as a primary filter.
- InitiatingProcessAccountName may not be reliably populated for all Linux process events in MDE; results should be validated against known-good Linux endpoints before drawing conclusions.
- The exclusion list for legitimate escalation binaries is not exhaustive; environment-specific setuid and capability-enabled binaries will require additional entries after baselining.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a Linux device and identify the non-root parent process, its command line, and the spawned root child process.
- Check whether the activity is associated with a known administrative tool, setuid workflow, or configuration management system.
- Review the timing for any preceding suspicious downloads, shell activity, or exploit attempts on the same host.
- Assess whether the root child process is interactive, network-connected, or launching additional tooling.

**Evidence to collect:**
- Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName, FileName, ProcessCommandLine, and ActionType from the alert.
- The exact parent and child process lineage, including any shell or script interpreter involved.
- Recent DeviceProcessEvents on the same host for exploit staging, downloads, or privilege escalation attempts.
- DeviceInfo records confirming the host OSPlatform and any relevant Linux agent details.
- Any authentication or sudo logs that may explain the root transition.

**Pivot points:**
- DeviceProcessEvents on the same DeviceName for the prior 24 hours to reconstruct process lineage.
- DeviceInfo to confirm Linux platform and host metadata.
- Linux authentication logs or syslog if available through your telemetry stack.
- DeviceNetworkEvents for outbound connections from the host around the escalation time.
- File and download telemetry for exploit payload staging or post-exploitation tools.

**Benign explanations:**
- Legitimate setuid or capability-based binaries not included in the exclusion list.
- Configuration management tools such as Ansible, Chef, or Puppet invoking root actions.
- Container or orchestration components that spawn root processes from non-root contexts.
- Custom administrative scripts or wrappers that perform controlled privilege escalation.

**Escalation criteria:**
- A non-root process spawns a root child with no approved administrative explanation.
- The parent process is unknown, user-writable, or associated with exploit tooling or a shell.
- The root child process launches additional suspicious commands, network connections, or persistence actions.
- The same host shows signs of exploitation, lateral movement, or unauthorized access.

**Containment actions:**
- Isolate the Linux host if exploitation is suspected and the system is business critical.
- Terminate suspicious processes only after preserving evidence, especially if the root child is active.
- Rotate credentials or revoke access for the affected account if compromise is confirmed.
- Coordinate with Linux operations to capture memory, logs, and process state before rebooting or remediation.

**Closure criteria:**
- The root child process is explained by a documented and approved administrative or automation workflow.
- The parent and child process names, command lines, and timing match a known-good baseline.
- No additional suspicious activity, persistence, or network behavior is found on the host.
- The event is added to the environment-specific allowlist after validation with Linux administrators.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- CoolClient Rootkit - Unsigned or Low-Prevalence Kernel Driver Load on Windows: Do not schedule yet; validate as an analyst-led hunt first.
- Armored Likho - Office or Script Interpreter Spawning Suspicious Child Process After Document Open: Do not schedule yet; validate as an analyst-led hunt first.
- Metasploit Linux LPE - Non-Root Process Spawning Root Child Process (CVE-2026-46300): Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- SharePoint RCE Chain - Worker Process Spawning Unexpected Shell: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.

**Shared-table notes:**
- DeviceFileEvents: shared by Still Toolkit - Non-Telegram Process Accessing Telegram tdata Directory; Armored Likho - Office or Script Interpreter Spawning Suspicious Child Process After Document Open
- DeviceProcessEvents: shared by CoolClient Rootkit - Unsigned or Low-Prevalence Kernel Driver Load on Windows; SharePoint RCE Chain - Worker Process Spawning Unexpected Shell; Armored Likho - Office or Script Interpreter Spawning Suspicious Child Process After Document Open; Metasploit Linux LPE - Non-Root Process Spawning Root Child Process (CVE-2026-46300)

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Still Toolkit - Non-Telegram Process Accessing Telegram tdata Directory.
2. Resolve environment-mapping detections next: SharePoint RCE Chain - Worker Process Spawning Unexpected Shell.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: CoolClient Rootkit - Unsigned or Low-Prevalence Kernel Driver Load on Windows; Armored Likho - Office or Script Interpreter Spawning Suspicious Child Process After Document Open; Metasploit Linux LPE - Non-Root Process Spawning Root Child Process (CVE-2026-46300).

### Hunting Agenda and Promotion Criteria

- CoolClient Rootkit - Unsigned or Low-Prevalence Kernel Driver Load on Windows: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Armored Likho - Office or Script Interpreter Spawning Suspicious Child Process After Document Open: Do not schedule yet; validate as an analyst-led hunt first.; confirm required file-access telemetry exists and produces representative events; baseline expected benign activity and define an alert-volume threshold.
- Metasploit Linux LPE - Non-Root Process Spawning Root Child Process (CVE-2026-46300): Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- SharePoint RCE Chain - Worker Process Spawning Unexpected Shell: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

This run exposes a file-access telemetry blind spot: browser cookie theft and resource-file loader behaviors depend on file-read style events that may not be emitted in every Defender deployment. Validate that coverage before treating these as scheduled analytics.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
