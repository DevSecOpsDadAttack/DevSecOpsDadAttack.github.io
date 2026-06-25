---
layout: post
title: "Detection Engineering Brief - Thursday, June 25, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-25
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Securelist
  - Windows
  - SharkLoader
  - Cobalt Strike
  - Cobalt Strike Beacon
  - Microsoft Security Blog
  - Microsoft Digital Crimes Unit
  - StealC
  - Amadey
  - SANS ISC
  - Linux
  - T1036
  - T1055
  - T1055.001
  - T1204
  - T1204.002
---

## Executive Signal

This brief produced 5 detection candidates.

0 production candidates, 3 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Securelist, Windows, SharkLoader, Cobalt Strike, Cobalt Strike Beacon, Microsoft Security Blog, Microsoft Digital Crimes Unit, StealC, Amadey, SANS ISC, Linux, T1036, T1055, T1055.001, T1204, T1204.002.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: SharkLoader Cobalt Strike Beacon Named Pipe and Network Beaconing; SharkLoader Unsigned Process Injecting into Trusted System Process; Infostealer Accessing Browser Credential Stores from Non-Browser Process; Infostealer Delivery via Suspicious Child Process Writing Executable to Temp Directory; Linux Process Name Masquerading via Executable Path Mismatch.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: SharkLoader Cobalt Strike Beacon Named Pipe and Network Beaconing

### Detection Opportunity

Custom loader (SharkLoader) executing Cobalt Strike Beacon in memory with named pipe creation and C2 network beaconing.

### Intelligence Context

- Securelist: StrikeShark: investigating a new campaign delivering Cobalt Strike through SharkLoader — [https://securelist.com/strikeshark-campaign/120326/](https://securelist.com/strikeshark-campaign/120326/)
  - Context: The StrikeShark campaign uses SharkLoader as a custom loader to deliver Cobalt Strike Beacon in memory. The loader produces detectable process lineage anomalies and Beacon exhibits well-known named pipe and C2 beaconing behaviors.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1055, T1055.001, T1036
- Products: Cobalt Strike Beacon
- Platforms: Windows
- Malware: SharkLoader
- Tools: Cobalt Strike
- Search tags: Securelist, Windows, SharkLoader, Cobalt Strike, Cobalt Strike Beacon, T1055, T1055.001, T1036

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Defense Evasion: T1055 Process Injection/ T1055.001 Dynamic-link Library Injection (high); Defense Evasion: T1036 Masquerading (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- Defender for Endpoint file-event coverage must be confirmed on the target host population.

Required telemetry:
- DeviceEvents, DeviceNetworkEvents

### KQL

```kql
let CobaltStrikePipes = DeviceEvents
| where ActionType == "NamedPipeEvent"
| extend PipeFields = parse_json(AdditionalFields)
| extend PipeName = tostring(PipeFields.PipeName)
| where PipeName matches regex @'(?i)(MSSE-|postex_|status_|msagent_)'
| where not(PipeName has "svcctl")
| project DeviceId, PipeTime = Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256, InitiatingProcessId, PipeName;
let SubsequentBeacon = DeviceNetworkEvents
| where RemotePort in (80, 443, 8080, 8443)
| where ActionType == "ConnectionSuccess"
| where not(ipv4_is_private(RemoteIP))
| where RemoteIP != "127.0.0.1"
| project DeviceId, NetTime = Timestamp, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId;
CobaltStrikePipes
| join kind=inner SubsequentBeacon on DeviceId, InitiatingProcessId
| where NetTime between (PipeTime .. (PipeTime + 2m))
| project DeviceId, PipeTime, NetTime, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256, PipeName, RemoteUrl, RemoteIP, RemotePort
| order by PipeTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate software using named pipes with substrings matching MSSE- or status_ (e.g., some Microsoft or third-party products) may trigger the pipe filter.
- Any process on a busy host making outbound HTTP/S connections within 2 minutes of any pipe event will correlate without the process ID anchor.

Tuning notes:
- Extend the PipeName regex to include additional known Cobalt Strike pipe name patterns observed in threat intelligence relevant to your environment.
- Adjust the 2-minute time window based on beacon sleep configuration observed during incident response.
- Add additional RemotePort values if C2 traffic is observed on non-standard ports in your environment.

Risks / caveats:
- NamedPipeEvent ActionType in DeviceEvents requires Defender for Endpoint with advanced hunting telemetry enabled; this event type is not available in all MDE licensing tiers or sensor configurations.
- AdditionalFields is a dynamic JSON column in DeviceEvents; the pipe name is nested under a key such as 'PipeName' and has_any against the raw blob may not match reliably depending on JSON serialization. The pipe name should be extracted with parse_json() before filtering.
- Custom Cobalt Strike malleable C2 profiles with renamed pipes will not match the regex patterns.
- The 2-minute correlation window between pipe creation and network connection may need adjustment based on observed beacon sleep intervals in the environment.

### Triage Runbook

First 15 minutes:
- Confirm the alert is tied to the same host and same process lineage by checking DeviceId, InitiatingProcessId, PipeTime, and NetTime in the alert details.
- Review the initiating process name, command line, and SHA256 for signs of a loader or staged execution from user-writable paths, temp folders, or unusual parent-child relationships.
- Inspect the named pipe name and compare it to known Cobalt Strike-style patterns versus legitimate software pipes used by EDR, backup, or remote support tools.
- Check the remote destination details for suspicious beaconing behavior: repeated connections, short intervals, uncommon ports, or destinations not associated with approved services.
- Look for adjacent endpoint activity on the same host such as process injection, new services, scheduled tasks, or additional network connections from the same process tree.

Evidence to collect:
- Device name, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256, and InitiatingProcessId.
- PipeName, PipeTime, NetTime, RemoteUrl, RemoteIP, and RemotePort from the alert.
- Process tree for the initiating process and any parent or child processes around the alert time.
- Any related DeviceEvents showing injection, service creation, persistence, or suspicious script execution on the same host.
- Network history for the host to identify repeated outbound connections to the same destination or other suspicious endpoints.

Pivot points:
- DeviceEvents for NamedPipeEvent and any injection-related activity on the same DeviceId and InitiatingProcessId.
- DeviceNetworkEvents for repeated outbound connections from the same InitiatingProcessId or same host in the alert window.
- DeviceProcessEvents to reconstruct the parent-child chain and identify the original launcher.
- DeviceFileEvents to look for dropped loader files, temp executables, or recent file writes by the same process tree.

Benign explanations:
- Legitimate EDR, AV, remote support, or backup software may create named pipes with similar substrings and also make outbound connections.
- A busy host may have unrelated network traffic within the correlation window if the process ID anchor is imperfect or telemetry is noisy.
- Some administrative tools and software updaters use named pipes and periodic network check-ins that can resemble beaconing.

Escalation criteria:
- The initiating process is unsigned, runs from a user-writable or temp path, and is not associated with approved software.
- The same process creates a suspicious named pipe and then makes repeated outbound connections to an unapproved external destination.
- There are additional signs of compromise on the host such as process injection, persistence, credential access, or lateral movement.
- The destination is a known malicious IP/domain or the beaconing pattern is consistent with Cobalt Strike behavior.

Containment actions:
- Isolate the host if the process is unapproved and the beaconing is confirmed or strongly suspected.
- Terminate the suspicious process tree only after preserving evidence if your response workflow requires it.
- Block the remote IP or domain at the network edge if it is confirmed malicious and not shared with legitimate services.
- Preserve the process hash, command line, and timeline for incident response and threat hunting.

Closure criteria:
- The named pipe and network activity are attributed to approved software with matching hash, path, and vendor context.
- No additional suspicious endpoint or network activity is found after reviewing the process tree and host history.
- The alert is determined to be a false positive caused by legitimate pipe naming or unrelated network traffic on the same host.
- Any suspicious destination or process is documented and added to an allowlist or suppression rule after validation.

---

## Detection 2: SharkLoader Unsigned Process Injecting into Trusted System Process

### Detection Opportunity

SharkLoader spawning child processes or performing remote thread injection into legitimate Windows system processes as part of Cobalt Strike delivery.

### Intelligence Context

- Securelist: StrikeShark: investigating a new campaign delivering Cobalt Strike through SharkLoader — [https://securelist.com/strikeshark-campaign/120326/](https://securelist.com/strikeshark-campaign/120326/)
  - Context: SharkLoader acts as a loader stage that injects Cobalt Strike Beacon into legitimate processes. Unsigned loaders injecting into trusted system processes such as svchost or explorer produce detectable process anomalies in endpoint telemetry.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1055, T1055.001, T1036
- Products: Cobalt Strike Beacon
- Platforms: Windows
- Malware: SharkLoader
- Tools: Cobalt Strike
- Search tags: Securelist, Windows, SharkLoader, Cobalt Strike, Cobalt Strike Beacon, T1055, T1055.001, T1036

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Defense Evasion: T1055 Process Injection/ T1055.001 Dynamic-link Library Injection (high); Defense Evasion: T1036 Masquerading (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- CreateRemoteThreadApiCall events in DeviceEvents require Defender for Endpoint with advanced hunting telemetry; availability depends on sensor configuration and licensing tier.

Required telemetry:
- DeviceEvents, DeviceProcessEvents

### KQL

```kql
let TrustedTargets = dynamic(["svchost.exe", "explorer.exe", "lsass.exe", "winlogon.exe", "services.exe", "spoolsv.exe"]);
let KnownLegitInjectors = dynamic(["MsMpEng.exe", "svchost.exe", "csrss.exe", "wininit.exe"]);
DeviceEvents
| where ActionType == "CreateRemoteThreadApiCall"
| where FileName in~ (TrustedTargets)
| where InitiatingProcessIntegrityLevel in ("Medium", "Low")
| where not(InitiatingProcessFileName in~ (KnownLegitInjectors))
| where InitiatingProcessFolderPath matches regex @'(?i)(\\Users\\|\\Temp\\|\\AppData\\|\\ProgramData\\)'
| project
    DeviceId,
    DeviceName,
    Timestamp,
    ActionType,
    InjectionTargetProcess = FileName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessIntegrityLevel,
    InitiatingProcessSHA256,
    InitiatingProcessId
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate software deployment or update tools running from AppData or ProgramData that use CreateRemoteThread for inter-process communication.
- Some EDR and AV products perform thread injection into system processes for monitoring purposes and may not be fully covered by the exclusion list.

Tuning notes:
- Add additional known legitimate injector process names to KnownLegitInjectors based on security tooling deployed in the environment.
- Consider splitting lsass.exe injection into a separate higher-severity detection given its credential access implications.
- If volume is high, add a filter requiring InitiatingProcessSHA256 to be non-empty to focus on events with hash telemetry available.

Risks / caveats:
- ProcessInjection is not a confirmed standard ActionType value in Defender for Endpoint DeviceEvents; using it may produce zero results. Only CreateRemoteThreadApiCall is documented. The query has been corrected to remove ProcessInjection.
- CreateRemoteThreadApiCall events in DeviceEvents require Defender for Endpoint with advanced hunting telemetry; availability depends on sensor configuration and licensing tier.
- Loaders placed in system directories (e.g., System32) will not match the InitiatingProcessFolderPath filter and will be missed.
- The exclusion list for known legitimate injectors covers common cases but may need expansion for specific security products deployed in the environment.

### Triage Runbook

First 15 minutes:
- Validate the target process and initiating process in the alert, focusing on whether the injector is unsigned and running from a user-writable path.
- Review the command line, folder path, and integrity level of the initiating process for signs of staging, unpacking, or execution from temp or AppData locations.
- Check whether the target process is one of the common trusted processes listed in the alert and whether the injection timing aligns with other suspicious activity on the host.
- Look for related events such as new file creation, script execution, service creation, or outbound connections from the same process tree.
- Confirm whether the host has approved EDR, AV, or application control software that legitimately injects into system processes.

Evidence to collect:
- DeviceName, DeviceId, Timestamp, ActionType, InjectionTargetProcess, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessIntegrityLevel, and InitiatingProcessSHA256.
- Parent process details and the full process tree around the injection event.
- File path and hash of the injector, plus any recent file writes in the same directory.
- Any concurrent DeviceNetworkEvents from the same host or process tree.
- Any security product inventory or allowlist entries that explain the injection behavior.

Pivot points:
- DeviceEvents for CreateRemoteThreadApiCall and related injection telemetry on the same host.
- DeviceProcessEvents to identify the parent process and any spawned children from the injector.
- DeviceFileEvents for recent executable writes in temp, AppData, or ProgramData paths.
- DeviceNetworkEvents for outbound connections from the injector or its child processes.

Benign explanations:
- EDR, AV, and endpoint monitoring tools may inject into trusted processes for telemetry or protection.
- Software updaters and installers may use remote thread techniques during installation or self-update workflows.
- Some legitimate enterprise applications run from user-writable paths and can resemble malicious loaders if not allowlisted.

Escalation criteria:
- The injector is unsigned, unknown, or located in a user-writable directory and targets a trusted system process.
- The same host shows additional malicious behavior such as beaconing, credential access, or persistence.
- The target includes high-value processes such as lsass.exe or other security-sensitive system processes.
- No approved software or security product explains the injection behavior.

Containment actions:
- Isolate the host if the injector is untrusted and the behavior is not explained by approved software.
- Stop the suspicious process tree if operationally safe and evidence has been preserved.
- Block the file hash and prevent re-execution through endpoint controls if confirmed malicious.
- Escalate to incident response for memory and process analysis if injection into sensitive processes is confirmed.

Closure criteria:
- The injector is matched to a known approved security or management product with supporting vendor context.
- The process path, hash, and command line align with a legitimate installer or updater workflow.
- No additional suspicious activity is found on the host after process-tree review and network review.
- The alert is documented as benign and the process hash or path is added to an allowlist if appropriate.

---

## Detection 3: Infostealer Accessing Browser Credential Stores from Non-Browser Process

### Detection Opportunity

Post-compromise credential theft via infostealer (StealC or Amadey) accessing browser credential database files from unexpected initiating processes.

### Intelligence Context

- Microsoft Security Blog: StealC and Amadey: Breaking down infostealers and the cybercrime services that deliver them — [https://www.microsoft.com/en-us/security/blog/2026/06/24/stealc-and-amadey-breaking-down-infostealers-and-the-cybercrime-services-that-deliver-them/](https://www.microsoft.com/en-us/security/blog/2026/06/24/stealc-and-amadey-breaking-down-infostealers-and-the-cybercrime-services-that-deliver-them/)
  - Context: StealC and Amadey are infostealers that access browser credential stores as part of post-compromise credential harvesting. File access to known browser credential database paths by non-browser processes is a reliable behavioral indicator of infostealer activity.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1204, T1204.002, T1036
- Products: Microsoft Security Blog, Microsoft Digital Crimes Unit
- Platforms: Windows
- Malware: StealC, Amadey
- Tools: Not specified
- Search tags: Microsoft Security Blog, Microsoft Digital Crimes Unit, Windows, StealC, Amadey, T1204, T1204.002, T1036

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1204 User Execution/ T1204.002 Malicious File (medium); Defense Evasion: T1036 Masquerading (low)

### Deployment Gates

- File-read style telemetry must be confirmed before scheduling detections that depend on FileRead, FileAccessed, or SensitiveFileRead-style events.

Required telemetry:
- DeviceFileEvents

### KQL

```kql
let BrowserCredFiles = dynamic(["Login Data", "logins.json", "cookies", "Web Data", "key4.db", "signons.sqlite"]);
let KnownBrowsers = dynamic(["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "iexplore.exe", "chromium.exe"]);
let KnownExclusions = dynamic(["SearchIndexer.exe", "MsMpEng.exe", "svchost.exe"]);
DeviceFileEvents
| where ActionType == "FileRead"
| where FileName in~ (BrowserCredFiles)
| where FolderPath has_any (
    "\\AppData\\Local\\Google\\Chrome\\",
    "\\AppData\\Local\\Microsoft\\Edge\\",
    "\\AppData\\Roaming\\Mozilla\\Firefox\\",
    "\\AppData\\Local\\BraveSoftware\\"
)
| where not(InitiatingProcessFileName in~ (KnownBrowsers))
| where not(InitiatingProcessFileName in~ (KnownExclusions))
| project
    Timestamp,
    DeviceId,
    DeviceName,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessSHA256,
    ActionType
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Password manager applications that read browser credential stores for import or sync functionality.
- Backup agents or file sync tools that traverse AppData directories may access credential database files.
- Security scanning tools that enumerate browser credential paths for vulnerability assessment.

Tuning notes:
- Before scheduling, run: DeviceFileEvents | where Timestamp > ago(1d) | where ActionType == 'FileRead' | summarize count() to confirm FileRead telemetry is present.
- Add known password manager executable names to KnownExclusions after identifying them in the environment.
- Consider adding InitiatingProcessAccountName filtering to exclude SYSTEM-context access if system-level noise is observed.

Risks / caveats:
- FileRead and FileAccessed ActionType values in DeviceFileEvents are not universally available in all Defender for Endpoint tenants; their collection depends on MDE sensor configuration. If these ActionTypes are absent, the query returns no results. Confirm ActionType availability by running: DeviceFileEvents | where Timestamp > ago(1d) | summarize count() by ActionType before scheduling.
- FileAccessed is not a documented standard ActionType in Defender for Endpoint DeviceFileEvents; it may not exist in the schema. The query has been updated to use only FileRead.
- If FileRead ActionType is not collected in the tenant, the query returns no results; telemetry availability must be confirmed before scheduling.
- Password manager executables not included in the exclusion list will generate false positives until identified and added.

### Triage Runbook

First 15 minutes:
- Identify the initiating process and confirm it is not a known browser or approved password manager.
- Review the file path and file name to verify the access is to browser credential stores such as Login Data, logins.json, cookies, Web Data, or key databases.
- Check the process command line and folder path for signs of malware staging, script execution, or execution from temp, AppData, or ProgramData.
- Look for nearby signs of credential theft or post-compromise activity such as browser profile enumeration, archive creation, or outbound connections.
- Confirm whether the host has approved backup, sync, or security software that legitimately accesses browser data.

Evidence to collect:
- Timestamp, DeviceId, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, and ActionType.
- The full process tree for the initiating process and any child processes.
- Any related file access events to other browser profile or credential files on the same host.
- Any network activity from the same process tree around the alert time.
- Any user context or account context available for the initiating process.

Pivot points:
- DeviceFileEvents for additional reads of browser profile files or credential stores on the same host.
- DeviceProcessEvents to identify whether the process is a browser, password manager, backup agent, or unknown executable.
- DeviceNetworkEvents for outbound connections from the same process tree after the file access.
- DeviceEvents for related suspicious actions such as injection, script execution, or persistence.

Benign explanations:
- Password managers may read browser credential stores for import, sync, or migration.
- Backup, sync, or endpoint security tools may enumerate browser profile files as part of normal operations.
- A browser update or profile migration process may access credential-related files in a controlled way.

Escalation criteria:
- The initiating process is unknown, unsigned, or running from a user-writable path and is not a browser or approved utility.
- Multiple browser credential files are accessed in a short period by the same process.
- The access is followed by suspicious network activity, archive creation, or other post-compromise behavior.
- The host shows signs of broader compromise such as credential theft, persistence, or lateral movement.

Containment actions:
- Isolate the host if the process is untrusted and the access pattern suggests credential theft.
- Terminate the suspicious process tree if it is confirmed malicious and evidence has been preserved.
- Force password resets or session revocation for affected accounts if credential theft is likely.
- Block the file hash and investigate for additional affected hosts using the same process or hash.

Closure criteria:
- The process is identified as a legitimate browser, password manager, backup, or security tool.
- The access pattern is consistent with approved business functionality and no other suspicious behavior is present.
- No additional browser credential access or post-access malicious activity is found on the host.
- The event is documented and, if needed, the process is added to an exclusion list after validation.

---

## Detection 4: Infostealer Delivery via Suspicious Child Process Writing Executable to Temp Directory

### Detection Opportunity

Infostealer process execution associated with StealC or Amadey delivered via suspicious child processes spawned from common delivery vectors writing executables to temporary directories.

### Intelligence Context

- Microsoft Security Blog: StealC and Amadey: Breaking down infostealers and the cybercrime services that deliver them — [https://www.microsoft.com/en-us/security/blog/2026/06/24/stealc-and-amadey-breaking-down-infostealers-and-the-cybercrime-services-that-deliver-them/](https://www.microsoft.com/en-us/security/blog/2026/06/24/stealc-and-amadey-breaking-down-infostealers-and-the-cybercrime-services-that-deliver-them/)
  - Context: StealC and Amadey are delivered via common infection vectors. Detection relies on behavioral patterns including suspicious process lineage from Office or browser parents writing and executing payloads in temporary directories, consistent with infostealer delivery chains.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1204, T1204.002, T1036
- Products: Microsoft Security Blog, Microsoft Digital Crimes Unit
- Platforms: Windows
- Malware: StealC, Amadey
- Tools: Not specified
- Search tags: Microsoft Security Blog, Microsoft Digital Crimes Unit, Windows, StealC, Amadey, T1204, T1204.002, T1036

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Execution: T1204 User Execution/ T1204.002 Malicious File (medium); Defense Evasion: T1036 Masquerading (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let DeliveryParents = dynamic(["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "chrome.exe", "msedge.exe", "firefox.exe", "wscript.exe", "cscript.exe", "mshta.exe"]);
let WrittenExes = DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith ".exe" or FileName endswith ".dll"
| where FolderPath matches regex @'(?i)(\\Temp\\|\\AppData\\Local\\Temp\\|\\AppData\\Roaming\\|\\ProgramData\\)'
| where InitiatingProcessFileName in~ (DeliveryParents)
| project DeviceId, DeviceName, WriteTime = Timestamp, WrittenFile = FileName, WrittenPath = FolderPath, WriterProcess = InitiatingProcessFileName, WrittenSHA256 = SHA256;
let ExecutedPayloads = DeviceProcessEvents
| where FolderPath matches regex @'(?i)(\\Temp\\|\\AppData\\Local\\Temp\\|\\AppData\\Roaming\\|\\ProgramData\\)'
| project DeviceId, ExecTime = Timestamp, ExecFile = FileName, ExecPath = FolderPath, ExecCmdLine = ProcessCommandLine, ExecSHA256 = SHA256;
WrittenExes
| join kind=inner ExecutedPayloads on DeviceId
| where ExecFile =~ WrittenFile
| where ExecTime between (WriteTime .. (WriteTime + 5m))
| project
    DeviceId,
    DeviceName,
    WriteTime,
    ExecTime,
    WrittenFile,
    WrittenPath,
    WriterProcess,
    ExecCmdLine,
    WrittenSHA256,
    ExecSHA256
| order by WriteTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate software installers downloaded via browsers and executed from temp directories.
- Software update mechanisms that write and execute update payloads from AppData or ProgramData.
- IT deployment tools that stage executables in temp directories before execution.

Tuning notes:
- Run over 7 days of historical data and summarize by WriterProcess and WrittenFile to identify recurring legitimate installer patterns before scheduling.
- Adjust the 5-minute time window based on observed delivery chain timing in the environment.
- Consider restricting to FileName endswith '.exe' only if DLL false positive volume is high.
- Add known software deployment tool names to an exclusion filter on WriterProcess after reviewing historical results.

Risks / caveats:
- DeviceFileEvents FileCreated ActionType must be present in the tenant for the write-side of the correlation to populate; confirm availability before running at scale.
- The 5-minute correlation window may miss delayed execution chains or catch unrelated file-write and execution events on busy hosts.
- The join on DeviceId and filename without a process ID anchor means coincidental filename matches on the same device within the window will produce results.
- Legitimate software installers triggered by browser downloads are the primary false positive source and require allowlist tuning.

### Triage Runbook

First 15 minutes:
- Review the written file name, path, and hash to confirm it is an executable or DLL staged in a temp, AppData, or ProgramData location.
- Check the writer process name and command line to see whether it originated from Office, a browser, script host, or another common delivery vector.
- Confirm whether the executed payload matches the written file and whether execution occurred shortly after the write event.
- Look for signs of user interaction, downloaded content, or archive extraction that could explain the file creation.
- Assess whether the host has active software deployment or update activity that could legitimately stage executables in temp paths.

Evidence to collect:
- DeviceId, DeviceName, WriteTime, ExecTime, WrittenFile, WrittenPath, WriterProcess, ExecCmdLine, WrittenSHA256, and ExecSHA256.
- The parent process chain for both the writer and the executed payload.
- Any related file writes in the same directory or by the same writer process.
- Any network connections made by the writer or executed payload after execution.
- Any user context or download source information available in the telemetry.

Pivot points:
- DeviceFileEvents for additional file creations in the same temp or AppData path.
- DeviceProcessEvents to reconstruct the execution chain and identify the original launcher.
- DeviceNetworkEvents for outbound activity from the executed payload.
- DeviceEvents for persistence, injection, or script execution associated with the same host.

Benign explanations:
- Legitimate software installers often write executables to temp directories before launching them.
- Browser downloads and self-extracting archives can create and run payloads from temporary paths.
- IT deployment tools and update agents may stage executables in AppData or ProgramData.

Escalation criteria:
- The writer process is a browser, Office app, or script host and the payload is unsigned or unknown.
- The written file is executed quickly and followed by suspicious network activity or credential access.
- The payload hash is unknown and the path is consistent with malware staging rather than a normal installer.
- Multiple hosts show the same writer process and payload pattern.

Containment actions:
- Isolate the host if the payload is untrusted and execution is confirmed.
- Block the file hash if it is confirmed malicious and not part of approved software.
- Remove persistence or scheduled tasks if discovered during triage.
- Escalate to incident response if the payload is linked to infostealer behavior or broader compromise.

Closure criteria:
- The file write and execution are attributed to a known installer, updater, or deployment tool.
- The payload hash and path match approved software and no suspicious follow-on activity exists.
- No additional malicious files or executions are found on the host.
- The event is documented and tuned if the same legitimate pattern recurs frequently.

---

## Detection 5: Linux Process Name Masquerading via Executable Path Mismatch

### Detection Opportunity

Malicious process masquerading as a legitimate Linux system process name while executing from an unexpected or user-writable filesystem path.

### Intelligence Context

- SANS ISC: Linux Process Name Masquerading, (Wed, Jun 24th) — [https://isc.sans.edu/diary/rss/33102](https://isc.sans.edu/diary/rss/33102)
  - Context: The SANS ISC diary documents malicious processes on Linux that mimic legitimate system process names while running from unexpected paths. Comparing the process name reported in Syslog against the actual executable path reveals masquerading activity consistent with T1036.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1036
- Products: Not specified
- Platforms: Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: SANS ISC, Linux, T1036

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Defense Evasion: T1036 Masquerading (high)

### Deployment Gates

- The join condition uses $left.ProcessName == $right.ProcName, but ProcessName in the Syslog table is populated from the syslog header process field, which may differ from the exe= path basename depending on how the process set its argv[0]. This mismatch is the intended detection signal but also means the join may miss records where ProcessName is not populated.

Required telemetry:
- Syslog

### KQL

```kql
let LegitPaths = datatable(ProcName: string, ExpectedPathPrefix: string)[
    "sshd", "/usr/sbin/",
    "cron", "/usr/sbin/",
    "systemd", "/lib/systemd/",
    "bash", "/bin/",
    "sh", "/bin/",
    "python", "/usr/bin/",
    "python3", "/usr/bin/",
    "perl", "/usr/bin/",
    "nginx", "/usr/sbin/",
    "apache2", "/usr/sbin/"
];
Syslog
| where Facility in ("kern", "daemon", "user", "authpriv") or ProcessName in (LegitPaths | project ProcName)
| where SyslogMessage has "exe="
| extend ExePath = extract(@'exe="([^"]+)"', 1, SyslogMessage)
| where isnotempty(ExePath)
| extend ExeBasename = tostring(split(ExePath, "/")[-1])
| join kind=inner LegitPaths on $left.ExeBasename == $right.ProcName
| where not(ExePath startswith ExpectedPathPrefix)
| where not(ExePath startswith "/usr/local/")
| where not(ExePath startswith "/snap/")
| where not(ExePath startswith "/opt/")
| project TimeGenerated, Computer, ProcessName, ExeBasename, ExePath, ExpectedPathPrefix, SyslogMessage
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate system binaries installed in non-standard paths by package managers, configuration management tools, or containerized environments.
- Snap or Flatpak packaged applications that use system binary names but run from /snap/ or /var/lib/flatpak/ paths.
- Custom-compiled binaries installed to /usr/local/ that share names with system binaries.

Tuning notes:
- Confirm auditd is configured with at minimum '-a always,exit -F arch=b64 -S execve -k exec' rules and that records are forwarded to Syslog before running.
- Run: Syslog | where SyslogMessage has 'exe=' | take 100 to confirm exe= fields are present in the tenant before deploying.
- Extend LegitPaths with additional system binaries observed in masquerading incidents relevant to the environment.
- Add /snap/, /opt/, and other non-standard installation prefixes used in the environment to the exclusion filters to reduce false positives from legitimate non-standard installations.

Risks / caveats:
- The exe= field in SyslogMessage is only present when auditd is configured with EXECVE or SYSCALL audit rules and those records are forwarded to the Syslog table. Standard syslog without auditd produces no exe= fields, causing ExePath to be empty for all records and the query to return zero results.
- The Facility == 'authpriv' filter does not reliably capture auditd events; auditd records typically arrive with Facility values of 'kern', 'daemon', or 'user' depending on the auditd dispatcher and syslog configuration. Filtering on authpriv alone will exclude most auditd EXECVE records.
- The join condition uses $left.ProcessName == $right.ProcName, but ProcessName in the Syslog table is populated from the syslog header process field, which may differ from the exe= path basename depending on how the process set its argv[0]. This mismatch is the intended detection signal but also means the join may miss records where ProcessName is not populated.
- If auditd is not configured with EXECVE or SYSCALL rules on Linux hosts, or if auditd records are not forwarded to the Syslog table, the query returns no results regardless of masquerading activity.

### Triage Runbook

First 15 minutes:
- Compare the reported process name, executable path, and expected path prefix to confirm the mismatch is real and not a packaging or syslog artifact.
- Review the SyslogMessage for the full exe= value and any surrounding auditd context to understand how the process was launched.
- Check whether the executable path is under user-writable, temporary, container, snap, or custom installation directories.
- Identify the host role and whether the process name is expected on that system, especially for servers, containers, or developer workstations.
- Look for adjacent signs of compromise such as unusual network connections, privilege escalation, or persistence on the same host.

Evidence to collect:
- TimeGenerated, Computer, ProcessName, ExePath, ExpectedPathPrefix, and the full SyslogMessage.
- Any related auditd or syslog entries showing parent process, command line, or user context.
- The host role, package manager context, and whether the binary is part of a known application stack.
- Any network or authentication events from the same host around the alert time.
- Any additional occurrences of the same process name from different paths across the environment.

Pivot points:
- Syslog for other entries with the same ProcessName or ExePath on the host.
- Syslog for exe= values under /tmp, /var/tmp, /dev/shm, /usr/local, /snap, or /opt paths.
- Authentication and privilege-related logs for the same host and time window.
- Network telemetry, if available, to identify outbound activity from the suspicious process.

Benign explanations:
- Legitimate locally installed binaries may run from /usr/local, /opt, or snap/flatpak paths.
- Configuration management or package deployment may place system-named binaries in non-standard locations.
- Containerized or developer environments can produce process names that look unusual compared with standard server paths.

Escalation criteria:
- The executable path is user-writable or temporary and the process name matches a common system binary.
- The process is running with elevated privileges or is associated with suspicious network or authentication activity.
- The binary is unknown, unsigned, or not accounted for by approved software inventory.
- Multiple hosts show the same masquerading pattern, suggesting a broader campaign.

Containment actions:
- Isolate the Linux host if the process is untrusted and the path indicates likely masquerading.
- Stop the suspicious process only after preserving logs and confirming it is not a critical service.
- Quarantine or remove the binary if it is confirmed malicious and operationally safe to do so.
- Escalate to Linux incident response for host forensics if privilege escalation or persistence is suspected.

Closure criteria:
- The executable path is explained by approved software, package management, or containerization.
- The process name/path mismatch is a known benign pattern in the environment and no other suspicious activity exists.
- No additional hosts or processes show the same suspicious path/name combination.
- The event is documented and the expected path list is updated if needed.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Schema / correlation keys:
- SharkLoader Cobalt Strike Beacon Named Pipe and Network Beaconing: Do not schedule yet; validate as an analyst-led hunt first.
- SharkLoader Unsigned Process Injecting into Trusted System Process: Do not schedule yet; validate as an analyst-led hunt first.
- Infostealer Delivery via Suspicious Child Process Writing Executable to Temp Directory: Do not schedule yet; validate as an analyst-led hunt first.

Other deployment dependency:
- SharkLoader Cobalt Strike Beacon Named Pipe and Network Beaconing: Defender for Endpoint file-event coverage must be confirmed on the target host population.

Licensing / identity risk fields:
- SharkLoader Unsigned Process Injecting into Trusted System Process: CreateRemoteThreadApiCall events in DeviceEvents require Defender for Endpoint with advanced hunting telemetry; availability depends on sensor configuration and licensing tier.

Telemetry availability:
- File-read style telemetry must be confirmed before scheduling detections that depend on FileRead, FileAccessed, or SensitiveFileRead-style events.
- Linux Process Name Masquerading via Executable Path Mismatch: The join condition uses $left.ProcessName == $right.ProcName, but ProcessName in the Syslog table is populated from the syslog header process field, which may differ from the exe= path basename depending on how the process set its argv[0]. This mismatch is the intended detection signal but also means the join may miss records where ProcessName is not populated.

Shared-table notes:
- DeviceEvents: shared by SharkLoader Cobalt Strike Beacon Named Pipe and Network Beaconing; SharkLoader Unsigned Process Injecting into Trusted System Process
- DeviceProcessEvents: shared by SharkLoader Unsigned Process Injecting into Trusted System Process; Infostealer Delivery via Suspicious Child Process Writing Executable to Temp Directory
- DeviceFileEvents: shared by Infostealer Accessing Browser Credential Stores from Non-Browser Process; Infostealer Delivery via Suspicious Child Process Writing Executable to Temp Directory

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: Infostealer Accessing Browser Credential Stores from Non-Browser Process; Linux Process Name Masquerading via Executable Path Mismatch.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: SharkLoader Cobalt Strike Beacon Named Pipe and Network Beaconing; SharkLoader Unsigned Process Injecting into Trusted System Process; Infostealer Delivery via Suspicious Child Process Writing Executable to Temp Directory.

### Hunting Agenda and Promotion Criteria

- SharkLoader Cobalt Strike Beacon Named Pipe and Network Beaconing: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- SharkLoader Unsigned Process Injecting into Trusted System Process: Do not schedule yet; validate as an analyst-led hunt first..
- Infostealer Delivery via Suspicious Child Process Writing Executable to Temp Directory: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Infostealer Accessing Browser Credential Stores from Non-Browser Process: File-read style telemetry must be confirmed before scheduling detections that depend on FileRead, FileAccessed, or SensitiveFileRead-style events.; confirm required file-access telemetry exists and produces representative events; baseline expected benign activity and define an alert-volume threshold.
- Linux Process Name Masquerading via Executable Path Mismatch: The join condition uses $left.ProcessName == $right.ProcName, but ProcessName in the Syslog table is populated from the syslog header process field, which may differ from the exe= path basename depending on how the process set its argv[0]. This mismatch is the intended detection signal but also means the join may miss records where ProcessName is not populated.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

This run exposes a file-access telemetry blind spot: browser cookie theft and resource-file loader behaviors depend on file-read style events that may not be emitted in every Defender deployment. Validate that coverage before treating these as scheduled analytics.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
