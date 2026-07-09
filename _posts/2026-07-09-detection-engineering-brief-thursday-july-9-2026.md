---
layout: post
title: "Detection Engineering Brief - Thursday, July 9, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-09
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Windows
  - Vidar Stealer
  - T1027.001
  - T1036
  - T1027
---

## Detection Engineering Summary

This brief produced 2 detection candidates.

1 production candidate, 1 hunting-only, 0 require environment mapping, and 0 rejected.

2 detections include KQL. 2 include ATT&CK mappings. 2 include triage guidance.

Search metadata extracted for this run includes: Windows, Vidar Stealer, T1027.001, T1036, T1027.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Vidar Stealer - Anomalously Large Executable Written to User-Writable Directory (File Inflation Evasion).

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Vidar Stealer - Fake MpClient.dll Sideloaded Outside Windows Defender Directory

### Detection Opportunity

Go-compiled fake MpClient.dll written to and loaded from a non-standard path by a legitimate signed binary, consistent with Vidar Stealer DLL sideloading delivery.

### Intelligence Context

- Unit 42: Vidar Stealer Unmasked: Code Signing Abuse, Go Loaders and File Inflation — [https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/](https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/)
  - Context: Unit 42 reported that Vidar Stealer used a Go-compiled fake MpClient.dll placed outside the legitimate Windows Defender directory and sideloaded by a legitimate signed binary as part of a loader-as-a-service delivery chain.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1027.001, T1036, T1027
- Products: Not specified
- Platforms: Windows
- Malware: Vidar Stealer
- Tools: Not specified
- Search tags: Windows, Vidar Stealer, T1027.001, T1036, T1027

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Defense Evasion: T1027 Obfuscated Files or Information/ T1027.001 Binary Padding (high); Defense Evasion: T1036 Masquerading (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceImageLoadEvents, DeviceFileEvents

### KQL

```kql
let LegitDefenderPaths = dynamic([
    @'c:\program files\windows defender',
    @'c:\programdata\microsoft\windows defender'
]);
let LookbackWindow = 2h;
let SuspectLoads = DeviceImageLoadEvents
| where FileName =~ 'MpClient.dll'
| where not(tolower(FolderPath) has_any (LegitDefenderPaths))
| project
    DeviceId,
    DeviceName,
    LoadTimestamp = Timestamp,
    LoadedDllPath = tolower(FolderPath),
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessSHA256,
    SHA256;
let RecentWrites = DeviceFileEvents
| where FileName =~ 'MpClient.dll'
| where not(tolower(FolderPath) has_any (LegitDefenderPaths))
| where ActionType in ('FileCreated', 'FileModified')
| project
    DeviceId,
    WriteTimestamp = Timestamp,
    WrittenPath = tolower(FolderPath),
    WriteSHA256 = SHA256;
SuspectLoads
| join kind=leftouter (
    RecentWrites
) on DeviceId, $left.LoadedDllPath == $right.WrittenPath
| where isnull(WriteTimestamp) or (WriteTimestamp <= LoadTimestamp and WriteTimestamp >= LoadTimestamp - LookbackWindow)
| project
    LoadTimestamp,
    DeviceName,
    LoadedDllPath,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessSHA256,
    LoadedDllSHA256 = SHA256,
    WriteTimestamp,
    WrittenPath,
    WriteSHA256
| sort by LoadTimestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Third-party security products that ship their own MpClient.dll shim or compatibility layer outside the Defender directory.
- Developer or test environments where Defender components are installed to non-standard paths.
- Software packaging tools that temporarily stage MpClient.dll in a temp directory during installation.

**Tuning notes:**
- Extend LegitDefenderPaths if your environment has non-standard Defender installation paths (e.g., redirected Program Files on non-system drives).
- Adjust LookbackWindow from 2h to a tighter value (e.g., 30m) to reduce cross-event noise once baseline behavior is understood.
- Add an allowlist of known legitimate InitiatingProcessFileName values that load MpClient.dll outside Defender paths if third-party tools generate recurring false positives.

**Risks / caveats:**
- DeviceImageLoadEvents requires Defender for Endpoint with DLL load telemetry enabled (MDE advanced feature 'Load Library Telemetry' or equivalent sensor configuration). If this telemetry level is not enabled, the query will return no results.
- Loads with no corroborating write event (WriteTimestamp is null) are included in results; these may represent DLL loads where the write occurred outside the 2-hour lookback window or where file write telemetry was not captured. Analysts should treat null-write rows as lower-confidence hits.
- The 2-hour write-to-load correlation window may need adjustment in environments where software staging pipelines write files well before execution.
- LegitDefenderPaths uses lowercase comparison; if Defender is installed to a path with unusual casing not covered by these two roots, those loads will be flagged as suspicious.

### Triage Runbook

**First 15 minutes:**
- Confirm the loaded DLL path is outside the standard Defender roots and note whether the alert includes a recent write event; treat null WriteTimestamp as lower confidence but still investigate.
- Identify the initiating process name, folder path, and SHA256; verify whether it is a known signed vendor binary or an unexpected executable in a user-writable or temp location.
- Check whether the DLL was written shortly before load on the same device and path, and whether the write came from a suspicious parent process or installer chain.
- Review the host for concurrent signs of Vidar-style activity such as browser credential access, archive creation, suspicious outbound connections, or additional dropped files.
- If the initiating process is unknown or the DLL path is in a user-writable location, treat the alert as likely malicious until disproven.

**Evidence to collect:**
- LoadedDllPath, LoadedDllSHA256, and WriteTimestamp/WrittenPath from the alert.
- InitiatingProcessFileName, InitiatingProcessFolderPath, and InitiatingProcessSHA256.
- File signer information and reputation for the initiating binary and the DLL, if available.
- DeviceFileEvents for the same device around the alert time to identify the write source and any related file drops.
- DeviceProcessEvents and DeviceNetworkEvents around the same time to identify execution chain and outbound connections.

**Pivot points:**
- DeviceImageLoadEvents filtered on the same DeviceId, LoadedDllPath, or LoadedDllSHA256 to find repeated loads and other affected hosts.
- DeviceFileEvents filtered on the same DeviceId and SHA256 values to find the original write, rename, or copy activity.
- DeviceProcessEvents filtered on InitiatingProcessSHA256 or InitiatingProcessFileName to map parent-child process lineage.
- DeviceNetworkEvents filtered on the same DeviceId and alert time window to look for command-and-control or download activity.
- DeviceFileEvents and DeviceImageLoadEvents for other files in the same folder to identify companion payloads.

**Benign explanations:**
- A third-party security product or compatibility layer may ship its own MpClient.dll shim outside the Defender directory.
- A developer, test, or lab system may have Defender components installed to a non-standard path.
- A software installer or packaging tool may temporarily stage MpClient.dll in a temp directory during installation.
- A legitimate signed binary may load a same-named DLL from its own application directory as part of normal application behavior.

**Escalation criteria:**
- The initiating process is unsigned, newly seen, or located in a user-writable or temp directory.
- The DLL was written shortly before load by an unexpected process, especially from Downloads, Temp, AppData, or Public paths.
- The host shows additional suspicious activity such as credential theft behavior, persistence, or outbound connections to unknown infrastructure.
- The same DLL hash or path appears on multiple hosts, suggesting a broader campaign.

**Containment actions:**
- Isolate the host if the initiating process is untrusted or if there are additional indicators of compromise.
- Quarantine or block the initiating binary and the suspicious MpClient.dll hash if confirmed malicious.
- Preserve the file, process tree, and relevant memory or forensic artifacts before remediation.
- Disable or restrict the user account if the activity originated from a user-writable location and there are signs of active compromise.

**Closure criteria:**
- The initiating binary is verified as a legitimate signed vendor component and the DLL path is an approved non-standard installation path.
- The DLL hash matches an approved third-party security product or known internal software package.
- No suspicious parent process, no corroborating file-write evidence, and no follow-on malicious activity are found after review.
- The alert is documented with the approved exception or allowlist entry for the specific path and hash.

<br/>
---
<br/>

## Detection 2: Vidar Stealer - Anomalously Large Executable Written to User-Writable Directory (File Inflation Evasion)

### Detection Opportunity

Executable file with anomalously inflated size written to a temp or user-writable directory, consistent with Vidar Stealer's file inflation evasion technique used to bypass scanner size thresholds.

### Intelligence Context

- Unit 42: Vidar Stealer Unmasked: Code Signing Abuse, Go Loaders and File Inflation — [https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/](https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/)
  - Context: Unit 42 identified file inflation as a novel evasion layer used by Vidar Stealer, where executables are padded to exceed common scanner size thresholds, and these inflated files are delivered to user-accessible paths.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1027.001, T1036, T1027
- Products: Not specified
- Platforms: Windows
- Malware: Vidar Stealer
- Tools: Not specified
- Search tags: Windows, Vidar Stealer, T1027.001, T1036, T1027

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Defense Evasion: T1027 Obfuscated Files or Information/ T1027.001 Binary Padding (high); Defense Evasion: T1036 Masquerading (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let SizeLimitBytes = 104857600;
let SuspectPaths = dynamic(['\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\', '\\users\\public\\', '\\downloads\\']);
let ExecWindow = 10m;
let LargeExes = DeviceFileEvents
| where ActionType in ('FileCreated', 'FileModified')
| where FileName endswith '.exe' or FileName endswith '.dll'
| where tolower(FolderPath) has_any (SuspectPaths)
| where isnotnull(FileSize) and FileSize >= SizeLimitBytes
| project
    DeviceId,
    DeviceName,
    WriteTimestamp = Timestamp,
    FileName,
    NormalizedFolderPath = tolower(FolderPath),
    FolderPath,
    FileSize,
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine;
let SubsequentExec = DeviceProcessEvents
| project
    DeviceId,
    ExecTimestamp = Timestamp,
    ProcessFileName = FileName,
    NormalizedProcessFolderPath = tolower(FolderPath),
    ProcessCommandLine;
LargeExes
| join kind=leftouter (
    SubsequentExec
) on DeviceId,
    $left.NormalizedFolderPath == $right.NormalizedProcessFolderPath,
    $left.FileName == $right.ProcessFileName
| where isnull(ExecTimestamp) or (ExecTimestamp >= WriteTimestamp and ExecTimestamp <= WriteTimestamp + ExecWindow)
| extend HasSubsequentExecution = isnotnull(ExecTimestamp)
| project
    WriteTimestamp,
    ExecTimestamp,
    DeviceName,
    FileName,
    FolderPath,
    FileSize,
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ProcessCommandLine,
    HasSubsequentExecution
| sort by HasSubsequentExecution desc, WriteTimestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Large legitimate software installers (e.g., game clients, development tools, browser installers) downloaded to the Downloads or Temp folder and executed by the user.
- Automated software deployment agents (e.g., SCCM, Intune, PDQ) that stage large packages in temp directories before execution.
- Self-extracting archives that write a large executable to a temp path as part of their extraction process.

**Tuning notes:**
- Verify that FileSize is populated in DeviceFileEvents in your MDE deployment before scheduling this query.
- Raise SizeLimitBytes (e.g., to 200MB or 500MB) if the 100MB threshold generates excessive noise from legitimate software in your environment.
- Add an exclusion for known software deployment process names in InitiatingProcessFileName (e.g., msiexec.exe, ccmexec.exe) if automated deployment tools are a significant noise source.
- Extend ExecWindow beyond 10 minutes if threat hunting across longer staging-to-execution intervals is desired.

**Risks / caveats:**
- FileSize is not guaranteed to be populated in DeviceFileEvents across all MDE sensor versions and configurations. If FileSize is null or zero for most events, the size threshold filter will produce no meaningful results.
- DeviceProcessEvents.FileName refers to the process image file name, not the full path file name. The join condition matching DeviceProcessEvents.FolderPath == DeviceFileEvents.FolderPath and DeviceProcessEvents.FileName == DeviceFileEvents.FileName is valid only if the process was launched directly from the written path with the same file name, which is the expected behavior for this technique but should be confirmed against the schema.
- FileSize population in DeviceFileEvents must be verified in the target environment before relying on the size threshold filter. If FileSize is consistently null, the query will return no results.
- The 100MB threshold is based on the Unit 42 report context. Environments with legitimate large installers staged in temp paths will require a higher threshold or additional exclusion logic to reduce noise.

### Triage Runbook

**First 15 minutes:**
- Check whether the alert has HasSubsequentExecution set to true; prioritize any row where the large file was executed after being written.
- Validate the file path, file name, and size against the environment; focus on Downloads, Temp, AppData, Public, and other user-writable locations.
- Review the initiating process that wrote the file to determine whether it was a browser download, installer, archive extractor, or an unexpected process.
- Inspect the SHA256 and file metadata for signs of a packed, padded, or unusual executable, and compare against known software inventory if available.
- If the file was executed, identify the process command line and parent process to determine whether the user launched it or it was started by another process.

**Evidence to collect:**
- WriteTimestamp, FileName, FolderPath, FileSize, SHA256, and InitiatingProcessFileName/CommandLine.
- ExecTimestamp, ProcessCommandLine, and whether HasSubsequentExecution is true.
- File signer information, version metadata, and any available reputation or prevalence data for the SHA256.
- DeviceFileEvents for the same host to identify related drops, renames, or extraction activity.
- DeviceProcessEvents for the same host to reconstruct the execution chain and parent-child relationships.

**Pivot points:**
- DeviceFileEvents filtered on the same DeviceId, SHA256, or FolderPath to find related files and repeated writes.
- DeviceProcessEvents filtered on the same DeviceId and FileName to confirm execution and identify the parent process.
- DeviceNetworkEvents for the same DeviceId and time window to look for download, beaconing, or post-execution activity.
- DeviceImageLoadEvents for the same SHA256 or folder to see whether the binary loaded additional modules or DLLs.
- DeviceFileEvents for the initiating process name to determine whether it commonly writes large executables in your environment.

**Benign explanations:**
- A legitimate large software installer, game client, or development tool downloaded to a user-writable directory.
- An automated deployment agent such as SCCM, Intune, or PDQ staging a package in a temp path.
- A self-extracting archive or updater that writes a large executable before launching it.
- A vendor-signed application that is unusually large but expected in the specific environment.

**Escalation criteria:**
- The file is unsigned, newly seen, or has a poor reputation and resides in a user-writable or temp directory.
- The file was executed shortly after creation and the parent process is a browser, script host, archive utility, or unknown binary.
- The file size is unusually large for the application type and there is evidence of packing, padding, or masquerading.
- The host shows additional suspicious activity such as credential theft, persistence, or outbound connections after execution.

**Containment actions:**
- Isolate the host if the file was executed and the binary is untrusted or there are additional compromise indicators.
- Quarantine the file hash and block execution if the binary is confirmed malicious or clearly padded for evasion.
- Preserve the file, command line, and process tree for forensic analysis before cleanup.
- If the file originated from a user download, consider resetting the user session and reviewing recent downloads and browser activity.

**Closure criteria:**
- The file is confirmed as a legitimate installer or deployment artifact from an approved software source.
- The file hash matches a known-good vendor package and the execution path is expected for that software.
- No suspicious parent process, no additional malicious activity, and the size is consistent with the approved application baseline.
- The event is documented with an approved exception or tuning note for the specific software and path.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- Vidar Stealer - Anomalously Large Executable Written to User-Writable Directory (File Inflation Evasion): Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- DeviceFileEvents: shared by Vidar Stealer - Fake MpClient.dll Sideloaded Outside Windows Defender Directory; Vidar Stealer - Anomalously Large Executable Written to User-Writable Directory (File Inflation Evasion)

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Vidar Stealer - Fake MpClient.dll Sideloaded Outside Windows Defender Directory.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Vidar Stealer - Anomalously Large Executable Written to User-Writable Directory (File Inflation Evasion).

### Hunting Agenda and Promotion Criteria

- Vidar Stealer - Anomalously Large Executable Written to User-Writable Directory (File Inflation Evasion): Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
