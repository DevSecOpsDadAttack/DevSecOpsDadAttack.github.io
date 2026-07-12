---
layout: post
title: "Detection Engineering Brief - Sunday, July 12, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-12
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-41264
  - T1190
  - T1059
  - Flowise
  - MacOS Package Kit
  - macOS
  - Metasploit
  - GigaWiper
  - Windows
  - T1059.006
  - T1486
---

## Detection Engineering Summary

This brief produced 3 detection candidates.

2 production candidates, 0 hunting-only, 1 require environment mapping, and 0 rejected.

3 detections include KQL. 3 include ATT&CK mappings. 3 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-41264, T1190, T1059, Flowise, MacOS Package Kit, macOS, Metasploit, GigaWiper, Windows, T1059.006, T1486.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Flowise CSV Upload Triggering Python Child Process Execution.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Flowise CSV Upload Triggering Python Child Process Execution

### Detection Opportunity

Unauthenticated CSV file upload to Flowise CSV Agent triggers Python code execution as a child process of the Node.js web service

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Exploits for FlowiseAI CSV Agent and MacOS Package Kit — [https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-exploits-for-flowiseai-csv-agent-and-macos-package-kit](https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-exploits-for-flowiseai-csv-agent-and-macos-package-kit)
  - Context: CVE-2026-41264 allows unauthenticated attackers to upload a malicious CSV file to the Flowise CSV Agent endpoint, which executes arbitrary Python code via the run method of the CSV_Agents class. A Metasploit module exists for this vulnerability, indicating active exploitation tooling is available.

### Search Metadata

- CVEs: CVE-2026-41264
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059, T1059.006
- Products: Flowise
- Platforms: macOS
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-41264, T1190, T1059, Flowise, MacOS Package Kit, macOS, Metasploit, T1059.006

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter/ T1059.006 Python (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName has_any ("python", "python3")
| where InitiatingProcessFileName has_any ("node", "nodejs")
| where ProcessCommandLine has_any ("-c ", ".py", "exec(", "import ", "__import__")
    or ProcessCommandLine matches regex @"\s+-c\s+"
| where not (
    ProcessCommandLine has "-i"
    and not ProcessCommandLine has_any ("-c ", ".py", "exec(", "import ")
)
| where InitiatingProcessParentFileName !in~ ("jenkins", "gradle", "mvn", "make", "cmake")
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessAccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Flowise or other Node.js applications that legitimately invoke Python scripts as part of their normal workflow will trigger this detection.
- Development environments where Node.js tooling routinely shells out to Python for build or test tasks.
- Any other Node.js web service co-located on the same host that spawns Python child processes.

**Tuning notes:**
- Scope DeviceName to the specific host or hosts running Flowise to reduce noise from other Node.js applications.
- Extend the ProcessCommandLine has_any list with any additional Python execution patterns observed in the environment.
- Consider joining with DeviceNetworkEvents on the same DeviceName and a short time window to correlate inbound HTTP POST requests to the Flowise CSV Agent endpoint with the Python child process spawn.

**Risks / caveats:**
- macOS DeviceProcessEvents telemetry requires MDE sensor with full-disk access and system extension approval on macOS; telemetry may be absent or incomplete without these prerequisites.
- InitiatingProcessFileName on macOS may reflect the full binary path or a versioned node binary name rather than the bare string 'node', causing the filter to produce no results if the process name does not match.
- The 7-day lookback window may miss events if the Flowise host has intermittent MDE connectivity or delayed ingestion.
- The regex match on ProcessCommandLine may not cover all Python code execution patterns used by Metasploit payloads; review and extend the has_any list based on observed payload patterns.

### Triage Runbook

**First 15 minutes:**
- Confirm the alert is on the expected Flowise host and identify the service account running the Node.js/Flowise process.
- Review the Python process command line for exploit indicators such as -c, embedded import statements, script paths, or unusual arguments.
- Check the parent Node.js command line and process tree to confirm the child Python spawn came from the Flowise service rather than a known build or admin workflow.
- Look for inbound web activity to the Flowise host around the same timestamp, especially POST requests or uploads to the CSV Agent endpoint.
- If the Python command line is suspicious or the host is internet-facing, treat as likely exploitation and begin incident escalation.

**Evidence to collect:**
- DeviceName, Timestamp, AccountName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, and ProcessCommandLine from the alert.
- Any related DeviceNetworkEvents showing inbound connections or HTTP POST activity to the Flowise host near the alert time.
- Any subsequent child processes spawned by the Python process or the Node.js parent within the same time window.
- File artifacts referenced in the Python command line, uploaded CSV names, or temporary files created during execution.
- Host context showing whether Flowise is expected to run on this macOS device and whether the Node.js binary name/path matches normal deployment.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and a wider time window to find the full process tree before and after the Python spawn.
- DeviceNetworkEvents on the same DeviceName to correlate inbound traffic, source IPs, and timing of the CSV upload.
- DeviceFileEvents to identify any files created, modified, or dropped by the Node.js or Python process.
- If available, application or reverse proxy logs for the Flowise endpoint to confirm the upload request and source.

**Benign explanations:**
- Flowise may legitimately invoke Python as part of a configured workflow or plugin integration.
- A development or test environment may routinely use Node.js to shell out to Python scripts.
- Another co-located Node.js application on the same host may be the true source of the Python child process.
- Interactive or administrative Python usage may appear similar if the command line is not reviewed carefully.

**Escalation criteria:**
- The Python command line contains attacker-like execution patterns such as -c, import chains, or a suspicious script path.
- The host is a public-facing Flowise instance and there is evidence of a recent CSV upload or inbound exploit traffic.
- The Python process spawns additional suspicious processes, touches sensitive files, or establishes outbound network connections.
- The Flowise service account or Node.js parent process is not expected to launch Python in normal operations.

**Containment actions:**
- If exploitation is likely, isolate the Flowise host from the network using endpoint containment.
- Disable or restrict the Flowise CSV Agent endpoint until the vulnerability is validated and remediated.
- Terminate the suspicious Python process and any clearly related child processes if they are still running.
- Preserve volatile evidence before rebooting or reimaging the host.

**Closure criteria:**
- The Python child process is confirmed to be part of an approved Flowise workflow and no suspicious network or file activity is found.
- The host is not internet-facing, the process tree matches a known administrative or development task, and no exploit indicators are present.
- No additional suspicious processes, file changes, or outbound connections are observed after review.
- The alert is documented with the legitimate use case and the detection is tuned if needed for that host or workflow.

<br/>
---
<br/>

## Detection 2: GigaWiper - Bulk File Deletion or Overwrite by Single Process

### Detection Opportunity

A single process performs mass file deletion or overwrite operations across multiple directories within a short time window, consistent with GigaWiper destructive wiper behavior

### Intelligence Context

- Microsoft Security Blog: GigaWiper: Anatomy of a destructive backdoor assembled from multiple malware — [https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/](https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/)
  - Context: GigaWiper is a destructive backdoor that combines wiping and ransomware-like capabilities assembled from multiple malware families. Its wiper component performs mass file deletion or overwrite on Windows hosts. No specific IOCs were published, requiring behavioral heuristics based on volume and directory spread.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1486
- Products: Not specified
- Platforms: Windows
- Malware: GigaWiper
- Tools: Not specified
- Search tags: GigaWiper, Windows, T1486

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Impact: T1486 Data Encrypted for Impact (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
let fileThreshold = 200;
let folderThreshold = 10;
DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType in ("FileDeleted", "FileModified")
| where InitiatingProcessFileName !in~ (
    "MsMpEng.exe",
    "svchost.exe",
    "TiWorker.exe",
    "cleanmgr.exe",
    "vssadmin.exe",
    "BackupExec.exe",
    "beremote.exe",
    "robocopy.exe",
    "veeam.backup.service.exe",
    "SqlWriter.exe"
)
| extend TopFolder = extract(@"^([A-Za-z]:\\[^\\]+(?:\\[^\\]+)?)", 1, FolderPath)
| summarize
    FileCount = count(),
    UniqueFolders = dcount(FolderPath),
    UniqueTopFolders = dcount(TopFolder),
    SampleFiles = make_set(FileName, 5),
    SampleFolders = make_set(FolderPath, 5),
    InitiatingProcessCommandLine = any(InitiatingProcessCommandLine),
    InitiatingProcessAccountName = any(InitiatingProcessAccountName)
    by
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessId,
    bin(Timestamp, 5m)
| where FileCount >= fileThreshold and UniqueFolders >= folderThreshold
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessId,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    FileCount,
    UniqueFolders,
    UniqueTopFolders,
    SampleFiles,
    SampleFolders
| order by FileCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Backup agents not in the exclusion list that perform large-scale file cleanup or rotation.
- Software deployment or patch management tools that delete old versions of files across many directories.
- Antivirus quarantine or remediation processes that delete detected malware files at scale.
- Large-scale file migration or archival jobs run by administrators.

**Tuning notes:**
- Run the query over a 7-day historical window during a known-clean period to identify the maximum FileCount and UniqueFolders values produced by legitimate processes, then set thresholds above that observed maximum.
- Expand the InitiatingProcessFileName exclusion list with any backup, archival, or patch management agents present in the environment that generate high file event volumes.
- Consider scheduling this rule every 5 minutes with a 10-minute lookback to ensure overlapping coverage without gaps, accounting for ingestion latency.

**Risks / caveats:**
- FileModified ActionType coverage in DeviceFileEvents depends on MDE sensor version and Windows endpoint configuration; some sensor versions may not emit FileModified for all overwrite patterns, potentially reducing detection coverage for the overwrite variant of GigaWiper behavior.
- The 1-hour lookback window is appropriate for a scheduled rule running on a short cadence but may miss events if ingestion latency exceeds the lookback minus the schedule interval.
- FileModified may not capture all overwrite patterns depending on how GigaWiper implements file destruction; if GigaWiper uses direct handle writes without a rename-then-write pattern, some events may not appear as FileModified.
- The exclusion list is not exhaustive; environment-specific backup agents not listed will generate false positives until the list is extended.

### Triage Runbook

**First 15 minutes:**
- Identify the initiating process, account, and device, and confirm whether the process is expected on that host.
- Check whether file activity is still ongoing; if so, prioritize immediate containment.
- Review the process command line for destructive utilities, scripting, remote execution, or suspicious paths.
- Assess the scope of file impact by reviewing the sample files and folders to see whether user data, shared drives, or system locations are affected.
- Look for concurrent signs of compromise such as unusual logons, remote admin tools, or other suspicious process activity on the same host.

**Evidence to collect:**
- InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCommandLine, InitiatingProcessAccountName, DeviceName, Timestamp, FileCount, UniqueFolders, SampleFiles, and SampleFolders.
- A timeline of DeviceFileEvents for the same process to determine whether deletion or overwrite is still in progress.
- Any related DeviceProcessEvents showing the parent process, spawned children, or remote execution chain.
- Any DeviceNetworkEvents indicating command-and-control, lateral movement, or remote management activity.
- If available, the process hash and any file paths showing whether the activity targeted user documents, shares, or backups.

**Pivot points:**
- DeviceFileEvents for the same DeviceName and InitiatingProcessId to expand the file impact timeline.
- DeviceProcessEvents to reconstruct the parent-child process tree and identify the launch source.
- DeviceNetworkEvents to check for outbound connections or remote access around the same time.
- DeviceLogonEvents, if available, to identify suspicious interactive or remote sessions tied to the initiating account.

**Benign explanations:**
- Backup, archival, patching, or software deployment tools can delete or overwrite many files in many folders.
- Antivirus remediation or quarantine activity can generate high-volume file deletion events.
- Administrative cleanup jobs may legitimately remove large numbers of files across directories.
- A known maintenance script may be responsible if the account, command line, and timing match an approved change window.

**Escalation criteria:**
- File deletion or overwrite is ongoing or has affected a large number of directories or critical data locations.
- The initiating process is unknown, unsigned, or launched from a suspicious path or remote execution tool.
- There are signs of lateral movement, suspicious logons, or concurrent destructive activity on other hosts.
- The activity is not attributable to an approved backup, patching, or maintenance workflow.

**Containment actions:**
- Isolate the host immediately if destructive activity is active or the process is untrusted.
- Terminate the initiating process and any related child processes if safe to do so.
- Disable the associated account or revoke active sessions if the account appears compromised.
- Preserve evidence and coordinate with backup/recovery teams to protect unaffected systems and restore data.

**Closure criteria:**
- The activity is confirmed to be a legitimate backup, patching, or maintenance job with approved change evidence.
- The process and account are known, expected, and the file targets match normal operational behavior.
- No additional destructive activity is observed after review of process, file, and network telemetry.
- The alert is documented and exclusions or thresholds are adjusted if the legitimate workflow is recurring.

<br/>
---
<br/>

## Detection 3: GigaWiper - Mass File Rename to Unknown Extensions Indicating Ransomware-Like Encryption

### Detection Opportunity

A single process renames a large number of files to novel or unknown extensions across multiple directories within a short window, consistent with GigaWiper ransomware-like file encryption behavior

### Intelligence Context

- Microsoft Security Blog: GigaWiper: Anatomy of a destructive backdoor assembled from multiple malware — [https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/](https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/)
  - Context: GigaWiper incorporates ransomware-like capabilities in addition to its wiper component. This includes bulk file renaming consistent with encryption staging, where files are renamed to novel extensions across many directories. This behavior is distinct from the pure deletion wiper behavior and warrants a separate detection.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1486
- Products: Not specified
- Platforms: Windows
- Malware: GigaWiper
- Tools: Not specified
- Search tags: GigaWiper, Windows, T1486

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Impact: T1486 Data Encrypted for Impact (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
let renameThreshold = 100;
let folderThreshold = 5;
let knownExtensions = dynamic([
    ".txt", ".doc", ".docx", ".xls", ".xlsx", ".pdf",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff",
    ".mp4", ".mp3", ".avi", ".mov",
    ".csv", ".pptx", ".ppt", ".zip", ".rar", ".7z", ".tar", ".gz",
    ".log", ".json", ".xml", ".html", ".htm",
    ".py", ".ps1", ".bat", ".cmd", ".sh",
    ".exe", ".dll", ".msi", ".sys",
    ".db", ".sqlite", ".bak", ".cfg", ".ini", ".yaml", ".yml"
]);
DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType == "FileRenamed"
| where isnotempty(PreviousFileName)
| extend RawExt = tostring(split(FileName, ".")[-1])
| extend NewExt = iff(FileName contains ".", tolower(strcat(".", RawExt)), "")
| where isnotempty(NewExt)
| where NewExt !in (knownExtensions)
| where InitiatingProcessFileName !in~ ("MsMpEng.exe", "svchost.exe")
| extend OldExt = iff(PreviousFileName contains ".", tolower(strcat(".", tostring(split(PreviousFileName, ".")[-1]))), "")
| summarize
    RenameCount = count(),
    UniqueFolders = dcount(FolderPath),
    UniqueNewExtensions = dcount(NewExt),
    SampleNewNames = make_set(FileName, 5),
    SampleOldNames = make_set(PreviousFileName, 5),
    SampleOldExtensions = make_set(OldExt, 10),
    InitiatingProcessCommandLine = any(InitiatingProcessCommandLine),
    InitiatingProcessAccountName = any(InitiatingProcessAccountName)
    by
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessId,
    bin(Timestamp, 5m)
| where RenameCount >= renameThreshold and UniqueFolders >= folderThreshold
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessId,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    RenameCount,
    UniqueFolders,
    UniqueNewExtensions,
    SampleNewNames,
    SampleOldNames,
    SampleOldExtensions
| order by RenameCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- File format conversion tools that rename files to application-specific extensions in bulk.
- Software installers that rename temporary files to final names using proprietary extensions.
- Backup agents that append backup-specific suffixes to files during staging.
- Development toolchains that produce build artifacts with non-standard extensions at scale.

**Tuning notes:**
- Confirm PreviousFileName is non-null in DeviceFileEvents for FileRenamed events by running a spot-check query against recent events on enrolled Windows endpoints before scheduling this rule.
- Expand the knownExtensions list with any application-specific file extensions routinely produced by line-of-business software in the environment.
- Consider adding a UniqueNewExtensions threshold of 1 or more as an additional filter if the environment has legitimate bulk-rename tools that always produce the same extension, to focus on the multi-extension ransomware pattern.
- Schedule this rule every 5 minutes with a 10-minute lookback to ensure overlapping coverage without gaps, accounting for ingestion latency.

**Risks / caveats:**
- PreviousFileName is populated in DeviceFileEvents only for FileRenamed events and only on MDE sensor versions that support this field; older sensor versions may leave PreviousFileName null, causing the isnotempty filter to drop all events and produce no results.
- PreviousFileName availability must be confirmed on the specific MDE sensor version deployed before relying on this detection; if the field is consistently null, the query will return no results.
- The known-extension allowlist does not cover all possible legitimate extensions in every environment; application-specific extensions used by line-of-business software may trigger false positives until the list is extended.
- The renameThreshold of 100 and folderThreshold of 5 are starting points and should be baselined against observed rename activity in the environment before the rule is promoted to high-severity alerting.

### Triage Runbook

**First 15 minutes:**
- Confirm the initiating process, account, and device, and determine whether the rename activity is still in progress.
- Review the new and old file names to see whether the renamed files are user documents, shared data, or system files.
- Inspect the process command line for encryption tools, scripting, archive utilities, or suspicious execution paths.
- Check whether the same process also created, modified, or deleted files, which would strengthen the ransomware hypothesis.
- Look for signs of broader compromise such as suspicious logons, remote execution, or other hosts showing similar rename activity.

**Evidence to collect:**
- InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCommandLine, InitiatingProcessAccountName, DeviceName, Timestamp, RenameCount, UniqueFolders, UniqueNewExtensions, SampleNewNames, SampleOldNames, and SampleOldExtensions.
- A sequence of DeviceFileEvents for the same process to determine whether renames are continuing or were followed by deletion/encryption-like behavior.
- Any DeviceProcessEvents showing the parent process and any spawned children associated with the rename activity.
- Any DeviceNetworkEvents that indicate command-and-control, remote access, or staging activity near the same time.
- If available, file hashes or file samples from renamed items to confirm whether content was altered or only renamed.

**Pivot points:**
- DeviceFileEvents for the same DeviceName and InitiatingProcessId to expand the rename timeline and identify affected directories.
- DeviceProcessEvents to reconstruct the process tree and identify the source of the rename job.
- DeviceNetworkEvents to look for outbound connections or remote management activity around the rename window.
- DeviceLogonEvents, if available, to identify suspicious interactive or remote sessions tied to the initiating account.

**Benign explanations:**
- Bulk file conversion tools may rename many files to application-specific extensions.
- Installers or update processes may rename temporary files during deployment.
- Backup or archival tools may append custom suffixes during staging or rotation.
- Development or build systems may generate large numbers of files with non-standard extensions.

**Escalation criteria:**
- The rename activity affects many folders and user data files and is accompanied by other destructive file operations.
- The new extensions are novel, random-looking, or inconsistent with any approved application workflow.
- The initiating process is unknown, suspicious, or launched from a remote execution or scripting context.
- There are additional indicators of compromise such as suspicious logons, outbound connections, or parallel file deletion.

**Containment actions:**
- Isolate the host if the rename activity appears malicious or is still active.
- Terminate the initiating process and related children if safe to do so.
- Disable the associated account or revoke sessions if compromise is suspected.
- Preserve evidence and coordinate recovery actions before any cleanup or restoration.

**Closure criteria:**
- The rename activity is confirmed to be a legitimate conversion, installer, backup, or build workflow.
- The process, account, and file targets match an approved operational task and no other malicious behavior is present.
- No evidence of encryption, deletion, or suspicious network activity is found after review.
- The alert is documented and tuning is updated if the legitimate workflow is expected to recur.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- Flowise CSV Upload Triggering Python Child Process Execution: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.

**Shared-table notes:**
- DeviceFileEvents: shared by GigaWiper - Bulk File Deletion or Overwrite by Single Process; GigaWiper - Mass File Rename to Unknown Extensions Indicating Ransomware-Like Encryption

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: GigaWiper - Bulk File Deletion or Overwrite by Single Process; GigaWiper - Mass File Rename to Unknown Extensions Indicating Ransomware-Like Encryption.
2. Resolve environment-mapping detections next: Flowise CSV Upload Triggering Python Child Process Execution.

### Hunting Agenda and Promotion Criteria

- Flowise CSV Upload Triggering Python Child Process Execution: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
