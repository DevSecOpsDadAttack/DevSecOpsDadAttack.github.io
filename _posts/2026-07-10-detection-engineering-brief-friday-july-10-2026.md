---
layout: post
title: "Detection Engineering Brief - Friday, July 10, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-10
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Vidar Stealer
  - Windows
  - GigaWiper
  - HTML attachments
  - email
  - T1036
  - T1036.005
  - T1553
  - T1553.002
  - T1486
  - T1485
  - T1566
  - T1566.001
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

2 production candidates, 2 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Vidar Stealer, Windows, GigaWiper, HTML attachments, email, T1036, T1036.005, T1553, T1553.002, T1486, T1485, T1566, T1566.001.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: GigaWiper - Ransomware-Like Bulk File Rename or Overwrite from Single Process; Vidar Stealer - Signed Executable Created in User-Writable Directory with Low Tenant Prevalence; HTML Phishing Attachment Delivered from First-Time External Sender.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Vidar Stealer - Fake MpClient.dll Sideloading from Non-Standard Path

### Detection Opportunity

DLL sideloading via Go-compiled fake MpClient.dll placed alongside a legitimate signed binary and loaded from a non-standard directory

### Intelligence Context

- Unit 42: Vidar Stealer Unmasked: Code Signing Abuse, Go Loaders and File Inflation — [https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/](https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/)
  - Context: Unit 42 reported that the Vidar Stealer campaign used a Go-compiled fake MpClient.dll placed alongside a legitimate signed binary to achieve DLL sideloading. The legitimate MpClient.dll is exclusively loaded by MsMpEng.exe from the Windows Defender installation directory; any load from another path or by another process is anomalous.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1036, T1036.005, T1553, T1553.002
- Products: Not specified
- Platforms: Windows
- Malware: Vidar Stealer
- Tools: Not specified
- Search tags: Vidar Stealer, Windows, T1036, T1036.005, T1553, T1553.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Defense Evasion: T1036 Masquerading/ T1036.005 Match Legitimate Name or Location (medium); Defense Evasion: T1553 Subvert Trust Controls/ T1553.002 Code Signing (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceImageLoadEvents, DeviceFileEvents

### KQL

```kql
let joinWindow = 24h;
let lookback = 48h;
let defenderPaths = dynamic(["\\Windows Defender\\", "\\Microsoft\\Windows Defender\\"]);
let suspiciousDllLoad = DeviceImageLoadEvents
| where Timestamp > ago(lookback)
| where FileName =~ "MpClient.dll"
| where not(
    InitiatingProcessFileName =~ "MsMpEng.exe"
    and FolderPath has_any (defenderPaths)
)
| project DeviceName, LoadTimestamp = Timestamp, InitiatingProcessFileName, InitiatingProcessFolderPath, LoadedDllPath = FolderPath, LoadSHA256 = SHA256;
let stagedDll = DeviceFileEvents
| where Timestamp > ago(lookback)
| where FileName =~ "MpClient.dll"
| where ActionType == "FileCreated"
| where not(FolderPath has_any (defenderPaths))
| project DeviceName, CreateTimestamp = Timestamp, CreatedPath = FolderPath, CreateSHA256 = SHA256;
suspiciousDllLoad
| join kind=inner stagedDll on DeviceName
| where LoadTimestamp between (CreateTimestamp .. (CreateTimestamp + joinWindow))
| project
    DeviceName,
    CreateTimestamp,
    CreatedPath,
    CreateSHA256,
    LoadTimestamp,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    LoadedDllPath,
    LoadSHA256
| sort by LoadTimestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Security testing tools or EDR simulators that deliberately load MpClient.dll from non-standard paths.
- Custom Windows Defender installation paths in enterprise environments that do not contain the standard path substrings.

**Tuning notes:**
- If legitimate Defender paths in the environment use a different directory structure, add those path substrings to the defenderPaths dynamic array.
- Adjust joinWindow from 24h to a shorter value (e.g., 1h) if the campaign is observed to execute immediately after staging.
- Scope to specific device groups using a DeviceName filter or a watchlist join during initial rollout to limit volume.

**Risks / caveats:**
- DeviceImageLoadEvents requires Microsoft Defender for Endpoint Plan 2 with DLL load telemetry enabled. If the tenant has not enabled this telemetry level, the table will return no rows and the rule will never fire.
- Enterprise environments with non-standard Windows Defender installation paths (e.g., relocated via GPO) may not match the defenderPaths filter, causing false positives for legitimate loads.
- The 24-hour join window between file creation and DLL load may miss staged attacks where the DLL was pre-positioned more than 24 hours before execution.
- If the same MpClient.dll SHA256 is staged and loaded multiple times, the join will produce duplicate rows per staging event.

### Triage Runbook

**First 15 minutes:**
- Confirm the loaded DLL path is outside the Windows Defender installation directory and that the initiating process is not MsMpEng.exe.
- Review the creating process and parent process chain for the staged DLL and the signed binary that loaded it.
- Check whether the same SHA256 appears on other hosts or whether the file was created from a user-writable or temporary directory.
- Look for nearby process creation, network, or credential-access activity on the same device around the load timestamp.

**Evidence to collect:**
- DeviceName, CreatedPath, LoadedDllPath, CreateTimestamp, LoadTimestamp, CreateSHA256, LoadSHA256
- InitiatingProcessFileName and InitiatingProcessFolderPath for both the file creation and DLL load events
- Any related process tree entries for the signed executable that performed the load
- Any subsequent outbound connections, archive creation, browser activity, or credential theft indicators on the same host

**Pivot points:**
- DeviceImageLoadEvents for other loads of MpClient.dll or the same SHA256 across the tenant
- DeviceFileEvents for the first creation time and any additional writes to the same DLL path
- DeviceProcessEvents for the initiating process, its parent, and any child processes spawned after the load
- DeviceNetworkEvents for outbound connections from the same device within a few hours of the alert

**Benign explanations:**
- A security testing tool or EDR simulator intentionally loading MpClient.dll from a non-standard path.
- An enterprise environment with a custom Defender installation path that does not match the expected path substrings.
- A legitimate signed binary packaged by IT that happens to use a similarly named DLL in a non-standard application directory.

**Escalation criteria:**
- The DLL was created in a user-writable or temporary directory and loaded by a non-Defender process.
- The same host shows additional suspicious activity such as credential theft, archive staging, or outbound command-and-control traffic.
- The file hash or parent process is seen on multiple endpoints or matches other Vidar-related activity in the environment.

**Containment actions:**
- Isolate the host if the DLL load is confirmed malicious or if there are concurrent signs of active compromise.
- Quarantine the staged DLL and any associated signed executable if they are still present and not required for business use.
- Block the file hash and any confirmed related parent process hashes through endpoint protection controls.
- Preserve volatile evidence before remediation if the host is still active and suspected to be in use by an attacker.

**Closure criteria:**
- Validated as a known-good Defender path exception or approved security test activity with supporting change evidence.
- No suspicious parent process, no additional malicious activity, and the file hash is tied to a sanctioned application package.
- The alert is attributable to a documented enterprise-specific Defender installation path and the detection is tuned accordingly.

<br/>
---
<br/>

## Detection 2: GigaWiper - Mass File Deletion Combined with Shadow Copy Removal

### Detection Opportunity

Destructive wiper activity producing mass file deletion events correlated with volume shadow copy deletion commands on the same device

### Intelligence Context

- Microsoft Security Blog: GigaWiper: Anatomy of a destructive backdoor assembled from multiple malware — [https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/](https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/)
  - Context: Microsoft described GigaWiper as a destructive backdoor combining wiping and ransomware-like capabilities assembled from multiple malware families. Wipers characteristically delete large volumes of files and remove volume shadow copies to prevent recovery. Correlating both signals on the same device within a short window produces a high-confidence compound indicator.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1486, T1485
- Products: Not specified
- Platforms: Windows
- Malware: GigaWiper
- Tools: Not specified
- Search tags: GigaWiper, Windows, T1486, T1485

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Impact: T1486 Data Encrypted for Impact (low); Impact: T1485 Data Destruction (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let lookback = 30min;
let deletionThreshold = 200;
let massDeletion = DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType == "FileDeleted"
| summarize
    DeletedCount = count(),
    FirstDelete = min(Timestamp),
    LastDelete = max(Timestamp),
    InitiatingProcessFolderPath = any(InitiatingProcessFolderPath)
    by DeviceName, bin(Timestamp, 10m), InitiatingProcessFileName
| where DeletedCount >= deletionThreshold
| project
    DeviceName,
    WindowStart = FirstDelete,
    WindowEnd = LastDelete,
    InitiatingProcess = InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    DeletedCount;
let shadowDeletion = DeviceProcessEvents
| where Timestamp > ago(1h)
| where
    ProcessCommandLine has_any ("delete shadows", "shadowcopy delete", "delete catalog", "resize shadowstorage")
    or (FileName has_any ("vssadmin.exe", "wbadmin.exe") and ProcessCommandLine has "delete")
    or (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy" and ProcessCommandLine has "delete")
| project
    DeviceName,
    ShadowCmdTime = Timestamp,
    ShadowProcess = FileName,
    ShadowCmd = ProcessCommandLine;
massDeletion
| join kind=inner shadowDeletion on DeviceName
| where ShadowCmdTime between (WindowStart .. (WindowStart + lookback))
| project
    DeviceName,
    WindowStart,
    WindowEnd,
    DeletedCount,
    InitiatingProcess,
    InitiatingProcessFolderPath,
    ShadowCmdTime,
    ShadowProcess,
    ShadowCmd
| sort by WindowStart desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Enterprise backup agents (e.g., Veeam, Commvault) that perform large-scale file deletion during backup rotation and also interact with VSS may match both signals.
- Disk cleanup or migration scripts run by IT operations that delete many files and resize shadow storage simultaneously.

**Tuning notes:**
- Increase deletionThreshold above 200 if backup agents or cleanup scripts on endpoints routinely delete files at this rate.
- Add known backup agent process names (e.g., VeeamAgent.exe, BackupExec.exe) as exclusions in the massDeletion subquery if they trigger false positives.
- Narrow the lookback join window from 30 minutes to 5-10 minutes if observed GigaWiper activity shows rapid sequential execution of both behaviors.

**Risks / caveats:**
- DeviceProcessEvents.ProcessCommandLine may be partially redacted or empty for some process creation events depending on MDE telemetry configuration and process command line collection policy.
- A 1-hour lookback window means the rule only catches wiper activity that began within the last hour. For scheduled rules running every hour, this is appropriate, but ingestion delays could cause missed detections.
- Backup agents that legitimately delete large file sets and interact with VSS will require process name exclusions tuned to the environment.
- The 200-file threshold in 10 minutes may be too low for environments with active backup or archiving jobs running on endpoints.

### Triage Runbook

**First 15 minutes:**
- Verify the mass deletion process and the shadow copy deletion command occurred on the same device within the alert window.
- Identify the initiating process, its command line, and whether it is a known admin, backup, or deployment tool.
- Check whether file deletion is still ongoing and whether the host is showing signs of user impact or service disruption.
- Review recent logons, remote sessions, and privilege changes to see whether the activity followed suspicious access.

**Evidence to collect:**
- DeviceName, WindowStart, WindowEnd, DeletedCount, InitiatingProcess, InitiatingProcessFolderPath
- ShadowCmdTime, ShadowProcess, ShadowCmd, and the exact command line used to remove shadow copies
- Process tree for the deletion initiator and any parent process that launched it
- Recent file deletion samples, affected directories, and any evidence of backup or recovery suppression

**Pivot points:**
- DeviceFileEvents for additional FileDeleted bursts from the same process or host
- DeviceProcessEvents for vssadmin.exe, wbadmin.exe, wmic.exe, powershell.exe, cmd.exe, and their parent processes
- DeviceLogonEvents for recent interactive or remote logons to the host
- DeviceNetworkEvents and DeviceRegistryEvents for signs of remote administration, payload staging, or persistence

**Benign explanations:**
- A backup agent or endpoint management tool performing maintenance, cleanup, or retention tasks.
- An IT migration or disk cleanup script that deletes many files and also interacts with VSS.
- A software deployment or uninstall workflow that removes large numbers of files and adjusts shadow storage.

**Escalation criteria:**
- Shadow copy deletion is performed by an unexpected process such as cmd.exe, powershell.exe, or wmic.exe from a user context.
- The host shows continued file destruction, service failures, or user reports of missing data.
- The activity is accompanied by suspicious logons, lateral movement, or other destructive behavior on additional hosts.

**Containment actions:**
- Isolate the host immediately if destructive activity is active or confirmed malicious.
- Disable or suspend the initiating account if it appears to be attacker-controlled and not a service account.
- Stop the offending process only if it is safe to do so and the host is already isolated or data loss is in progress.
- Preserve logs and relevant process evidence before rebooting or remediating the system.

**Closure criteria:**
- The activity is matched to a documented backup, migration, or cleanup job with approved change records.
- The process and command line are consistent with a sanctioned administrative workflow and no other suspicious behavior is present.
- No further deletion activity is observed after validation and the host is returned to normal operation.

<br/>
---
<br/>

## Detection 3: GigaWiper - Ransomware-Like Bulk File Rename or Overwrite from Single Process

### Detection Opportunity

Ransomware-like bulk file renaming or overwriting at scale from a single initiating process within a short time window, consistent with GigaWiper destructive activity

### Intelligence Context

- Microsoft Security Blog: GigaWiper: Anatomy of a destructive backdoor assembled from multiple malware — [https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/](https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/)
  - Context: Microsoft described GigaWiper as incorporating ransomware-like capabilities in addition to wiping. This manifests as high-frequency file rename or overwrite operations from a single process, which is detectable via volume thresholds on DeviceFileEvents without requiring specific file extensions or process names.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1486, T1485
- Products: Not specified
- Platforms: Windows
- Malware: GigaWiper
- Tools: Not specified
- Search tags: GigaWiper, Windows, T1486, T1485

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Impact: T1486 Data Encrypted for Impact (low); Impact: T1485 Data Destruction (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
let renameThreshold = 150;
let excludedProcesses = dynamic(["robocopy.exe", "xcopy.exe", "7z.exe", "winzip.exe", "backup.exe"]);
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType in ("FileRenamed", "FileModified")
| where not(InitiatingProcessFileName in~ (excludedProcesses))
| summarize
    FileCount = count(),
    DistinctFolders = dcount(FolderPath),
    SampleFiles = make_set(FileName, 5),
    CommandLine = any(InitiatingProcessCommandLine),
    InitiatingProcessFolderPath = any(InitiatingProcessFolderPath)
    by DeviceName, InitiatingProcessFileName, BinStart = bin(Timestamp, 5m)
| where FileCount >= renameThreshold and DistinctFolders >= 3
| project
    DeviceName,
    BinStart,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    FileCount,
    DistinctFolders,
    SampleFiles,
    CommandLine
| sort by FileCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Cloud sync clients (OneDrive, Dropbox, Google Drive) performing bulk sync operations.
- Software deployment tools performing in-place upgrades that overwrite many files.
- Antivirus or EDR products performing file quarantine or remediation operations.
- Development build systems that compile and overwrite many output files rapidly.

**Tuning notes:**
- Run over 7 days of historical data and review top results to identify legitimate processes that should be added to the excludedProcesses list before considering promotion to a scheduled rule.
- Increase renameThreshold to 300 or higher and DistinctFolders to 5 or higher if cloud sync clients or build systems generate significant noise.
- Consider adding a corroborating signal (e.g., network connection to an unusual destination or shadow copy deletion) before promoting to a scheduled rule to reduce false positive rate.

**Risks / caveats:**
- FileRenamed ActionType availability in DeviceFileEvents should be confirmed for the tenant, as not all MDE configurations surface rename events at the same fidelity as create/delete events.
- Volume thresholds (150 files, 3 directories, 5 minutes) are heuristic and will require adjustment based on environment baseline before this query can be promoted to a scheduled rule.
- FileModified events in DeviceFileEvents can be extremely high volume in environments with active development or sync workloads, potentially causing query performance issues over 24 hours.
- The exclusion list covers only common archiving tools; environment-specific sync clients and build tools must be added after baseline review.

### Triage Runbook

**First 15 minutes:**
- Identify the initiating process, command line, and folder path responsible for the bulk file activity.
- Check whether the activity spans multiple directories and whether the file changes are still continuing.
- Look for nearby signs of ransomware or wiper behavior such as shadow copy deletion, service stoppage, or mass process termination.
- Confirm whether the process belongs to a known backup, sync, deployment, or build tool before treating it as malicious.

**Evidence to collect:**
- DeviceName, BinStart, InitiatingProcessFileName, InitiatingProcessFolderPath, FileCount, DistinctFolders, SampleFiles, CommandLine
- A sample of renamed or modified file paths to understand the scope and target directories
- Process tree and parent process for the initiating executable
- Any concurrent file deletion, shadow copy removal, or suspicious network activity on the same host

**Pivot points:**
- DeviceFileEvents for additional rename or modify bursts from the same process or device
- DeviceProcessEvents for the initiating process and any child processes spawned during the window
- DeviceNetworkEvents for outbound connections that may indicate malware staging or exfiltration
- DeviceFileEvents and DeviceProcessEvents for known backup, sync, or build tools on the same endpoint

**Benign explanations:**
- Cloud sync clients performing large synchronization or conflict-resolution operations.
- Software deployment, patching, or uninstall tools overwriting many files at once.
- Development build systems generating or replacing large numbers of output files.
- Endpoint security tools quarantining or remediating files in bulk.

**Escalation criteria:**
- The process is unknown, user-launched, or running from a suspicious directory such as Downloads, Temp, or AppData.
- The activity is paired with shadow copy deletion, service disruption, or other destructive indicators.
- Multiple endpoints show similar bulk overwrite behavior or the same hash/process lineage.

**Containment actions:**
- Isolate the host if the activity is ongoing and not attributable to a sanctioned workflow.
- Suspend or terminate the process only after isolation if the host is actively being destroyed and business impact is escalating.
- Disable the associated account if it is clearly unauthorized and appears to be driving the activity.
- Preserve the process tree and affected file samples for forensic review.

**Closure criteria:**
- The process is confirmed as a known-good sync, deployment, backup, or build tool with supporting operational evidence.
- The file activity is limited to expected directories and matches a documented maintenance window.
- No additional destructive indicators are present and the behavior is consistent with baseline operations.

<br/>
---
<br/>

## Detection 4: Vidar Stealer - Signed Executable Created in User-Writable Directory with Low Tenant Prevalence

### Detection Opportunity

Code-signing abuse where executables signed with low-prevalence certificates are created and executed from user-writable directories as an evasion layer for Vidar Stealer delivery

### Intelligence Context

- Unit 42: Vidar Stealer Unmasked: Code Signing Abuse, Go Loaders and File Inflation — [https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/](https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/)
  - Context: Unit 42 identified that the Vidar Stealer campaign used executables signed with likely stolen or fraudulent certificates as a novel evasion layer. These signed binaries were executed from non-standard, user-writable paths. Correlating low-prevalence signer names with execution from user-writable directories provides a behaviorally specific signal.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1036, T1036.005, T1553, T1553.002
- Products: Not specified
- Platforms: Windows
- Malware: Vidar Stealer
- Tools: Not specified
- Search tags: Vidar Stealer, Windows, T1036, T1036.005, T1553, T1553.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Defense Evasion: T1036 Masquerading/ T1036.005 Match Legitimate Name or Location (medium); Defense Evasion: T1553 Subvert Trust Controls/ T1553.002 Code Signing (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let userWritablePaths = dynamic(["\\AppData\\", "\\Temp\\", "\\Downloads\\", "\\Public\\", "\\Users\\Public\\"]);
let dropWindow = 1h;
let recentDrops = DeviceFileEvents
| where Timestamp > ago(48h)
| where ActionType == "FileCreated"
| where FolderPath has_any (userWritablePaths)
| where FileName endswith ".exe"
| where isnotempty(SHA256)
| project DeviceName, DroppedFile = FileName, DroppedPath = FolderPath, DropTime = Timestamp, DropSHA256 = SHA256;
let executions = DeviceProcessEvents
| where Timestamp > ago(48h)
| where FolderPath has_any (userWritablePaths)
| where FileName endswith ".exe"
| where isnotempty(SHA256)
| project
    DeviceName,
    ExecFile = FileName,
    ExecPath = FolderPath,
    ExecTime = Timestamp,
    ExecSHA256 = SHA256,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath;
recentDrops
| join kind=inner executions on DeviceName, $left.DropSHA256 == $right.ExecSHA256
| where ExecTime between (DropTime .. (DropTime + dropWindow))
| summarize
    DropTime = min(DropTime),
    ExecTime = min(ExecTime),
    DroppedPath = any(DroppedPath),
    ProcessCommandLine = any(ProcessCommandLine),
    InitiatingProcessFileName = any(InitiatingProcessFileName),
    InitiatingProcessFolderPath = any(InitiatingProcessFolderPath)
    by DeviceName, ExecFile, ExecPath, ExecSHA256
| project
    DeviceName,
    DroppedPath,
    DropTime,
    ExecTime,
    ExecFile,
    ExecPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    ExecSHA256
| sort by DropTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Software installers downloaded by users to Downloads or Temp directories that execute immediately after download.
- IT-managed software deployment tools that stage executables in user-accessible directories before execution.
- Browser-downloaded utilities or portable applications executed directly from the Downloads folder.

**Tuning notes:**
- After initial hunting runs, build an exclusion list of known-good SHA256 hashes or FolderPath patterns for legitimate installers to reduce noise.
- Extend dropWindow beyond 1h if the campaign is observed to use delayed execution after staging.
- Consider adding a filter on InitiatingProcessFileName to focus on executions spawned by browsers (e.g., chrome.exe, msedge.exe, firefox.exe) or email clients to increase signal specificity.

**Risks / caveats:**
- SHA256 field population in DeviceProcessEvents depends on MDE telemetry configuration. If SHA256 is not consistently populated for process creation events, the inner join on SHA256 will produce no results for those events.
- The query cannot directly observe code-signing certificate information; the code-signing abuse behavior described in the source article is not directly detectable from available fields, making this a behavioral proxy rather than a direct detection.
- The 1-hour drop-to-execution window may miss staged loaders that execute after a longer delay.
- High volume of results is expected in environments with active software deployment or user-initiated downloads; exclusion lists for known installer SHA256 hashes or paths must be built from baseline review.

### Triage Runbook

**First 15 minutes:**
- Validate the dropped executable path, creation time, and execution time on the host.
- Review the parent process and command line that created and launched the executable.
- Check whether the file hash is known-good, seen elsewhere in the tenant, or associated with a sanctioned software package.
- Look for immediate follow-on activity such as browser launches, archive extraction, credential prompts, or outbound connections.

**Evidence to collect:**
- DeviceName, DroppedPath, DropTime, ExecTime, ExecFile, ExecPath, ExecSHA256
- ProcessCommandLine, InitiatingProcessFileName, and InitiatingProcessFolderPath for the execution event
- Any available signer or reputation context from adjacent tooling or enrichment sources
- Related file creation and process creation events for the same SHA256 on the same or other devices

**Pivot points:**
- DeviceFileEvents for the original drop location and any additional copies of the same SHA256
- DeviceProcessEvents for the execution chain, parent process, and child processes
- DeviceNetworkEvents for outbound traffic shortly after execution
- Threat intelligence or reputation sources for the SHA256 and any related signer metadata

**Benign explanations:**
- A user downloaded and ran a legitimate installer from Downloads or Temp.
- An IT deployment tool staged software in a user-accessible directory before execution.
- A portable application or self-extracting archive was launched from a user-writable path.

**Escalation criteria:**
- The executable is unsigned, low-prevalence, or originates from a suspicious user-writable path with no business justification.
- The process tree shows browser, email, or script-based delivery followed by suspicious child processes.
- The same hash or path appears on multiple hosts or is linked to other Vidar-related activity.

**Containment actions:**
- Quarantine the file if it is confirmed malicious or if reputation and lineage strongly indicate compromise.
- Isolate the host if the executable has already run and there are signs of post-execution malicious behavior.
- Block the SHA256 through endpoint protection if it is validated as malicious.
- Reset credentials for the affected user if the executable appears to be part of a credential theft chain.

**Closure criteria:**
- The executable is verified as a legitimate installer, portable app, or approved IT deployment artifact.
- The hash is known-good and the parent process aligns with expected user or software distribution behavior.
- No suspicious network, persistence, or credential-access activity follows execution.

<br/>
---
<br/>

## Detection 5: HTML Phishing Attachment Delivered from First-Time External Sender

### Detection Opportunity

Phishing credential harvesting page delivered as an HTML email attachment from an external sender with no prior communication history with the recipient

### Intelligence Context

- SANS ISC: "Comment stuffing" in an HTML phishing attachment as a mechanism for evading AI-based detection, (Fri, Jul 10th) — [https://isc.sans.edu/diary/rss/33144](https://isc.sans.edu/diary/rss/33144)
  - Context: SANS ISC reported that attackers are embedding phishing credential harvesting content in HTML attachments and using comment stuffing to evade AI-based detection. The delivery mechanism is an HTML file attached to an inbound email. Detecting HTML attachments from first-time external senders provides a practical heuristic aligned with this delivery pattern.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1566, T1566.001
- Products: Not specified
- Platforms: email, HTML attachments
- Malware: Not specified
- Tools: Not specified
- Search tags: HTML attachments, email, T1566, T1566.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1566 Phishing/ T1566.001 Spearphishing Attachment (high)

### Deployment Gates

- EmailEvents and EmailAttachmentInfo require the Microsoft Defender XDR data connector to be enabled in Microsoft Sentinel and the tenant to have Microsoft Defender for Office 365 Plan 1 or Plan 2 licensed. Without this connector, these tables will not exist in the Sentinel workspace.

**Required telemetry:**
- EmailEvents, EmailAttachmentInfo

### KQL

```kql
let lookbackDays = 90d;
let knownSenderDomains = EmailEvents
| where Timestamp > ago(lookbackDays)
| extend SenderDomain = tolower(tostring(split(SenderFromAddress, "@")[1]))
| where isnotempty(SenderDomain)
| where not(SenderDomain endswith ".local")
| summarize by SenderDomain;
let htmlAttachments = EmailAttachmentInfo
| where Timestamp > ago(1d)
| where FileName endswith ".html" or FileName endswith ".htm" or FileType =~ "html"
| project NetworkMessageId, AttachmentName = FileName;
EmailEvents
| where Timestamp > ago(1d)
| where DeliveryAction == "Delivered"
| extend SenderDomain = tolower(tostring(split(SenderFromAddress, "@")[1]))
| where isnotempty(SenderDomain)
| where not(SenderDomain endswith ".local")
| join kind=inner htmlAttachments on NetworkMessageId
| join kind=leftanti knownSenderDomains on SenderDomain
| project
    Timestamp,
    SenderFromAddress,
    SenderDomain,
    RecipientEmailAddress,
    AttachmentName,
    DeliveryAction,
    NetworkMessageId
| sort by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate HTML-based newsletters or transactional emails from new vendor domains not previously seen in the tenant.
- Automated reports or notifications from newly onboarded SaaS platforms delivered as HTML attachments.
- Internal communications forwarded from external partners using new domains.

**Tuning notes:**
- After initial deployment, build an exclusion list of known legitimate sender domains that deliver HTML attachments (e.g., marketing platforms, SaaS notification domains) and add them as a leftanti join or where clause.
- Extend lookbackDays beyond 90 days for tenants with longer email history to reduce first-time sender false positives.
- Consider adding a filter on RecipientEmailAddress to scope to high-value targets (e.g., executives, finance, IT admins) during initial rollout.

**Risks / caveats:**
- EmailEvents and EmailAttachmentInfo require the Microsoft Defender XDR data connector to be enabled in Microsoft Sentinel and the tenant to have Microsoft Defender for Office 365 Plan 1 or Plan 2 licensed. Without this connector, these tables will not exist in the Sentinel workspace.
- OfficeActivity does not reliably expose per-attachment metadata (AttachmentName) for inbound Exchange Online messages in standard connector configurations, making the original query non-functional in most tenants.
- The 90-day sender domain history baseline covers the entire tenant, not per-recipient history. A domain that has emailed one user but not the targeted recipient will be excluded from alerting.
- Newly onboarded tenants with less than 90 days of email history will have an incomplete baseline, increasing false positive volume during the initial period.

### Triage Runbook

**First 15 minutes:**
- Review the sender domain, recipient, subject, and attachment name to assess whether the message is expected.
- Confirm the message was delivered and whether the recipient opened the attachment or clicked any embedded links.
- Check whether the sender domain is newly observed tenant-wide or only new to the recipient.
- Look for similar messages delivered to other users, especially high-value targets such as finance, executives, or IT.

**Evidence to collect:**
- Timestamp, SenderFromAddress, SenderDomain, RecipientEmailAddress, AttachmentName, DeliveryAction, NetworkMessageId
- Message subject, message body preview, and any embedded URLs if available from email security tooling
- User interaction evidence such as attachment open, URL click, or browser launch after delivery
- Any related messages with the same sender domain, subject, or attachment hash across the tenant

**Pivot points:**
- EmailEvents for the sender domain, recipient list, and delivery history
- EmailAttachmentInfo for other messages carrying the same HTML attachment name or type
- UrlClickEvents or browser telemetry for user interaction after delivery
- DeviceProcessEvents and DeviceNetworkEvents on the recipient device if the attachment was opened

**Benign explanations:**
- A legitimate first-time vendor, SaaS notification, or transactional email delivered as HTML.
- A marketing or newsletter message from a new external domain.
- A forwarded external communication that is new to the tenant but expected by the recipient.

**Escalation criteria:**
- The attachment contains credential-harvesting content, brand impersonation, or suspicious obfuscation such as comment stuffing.
- The recipient opened the attachment and entered credentials or visited a suspicious URL.
- The same sender domain or message pattern is delivered to multiple users or high-value targets.

**Containment actions:**
- Purge the message from mailboxes if it is confirmed malicious and the mail platform supports tenant-wide removal.
- Block the sender domain or message pattern if it is clearly malicious and not business-critical.
- Reset credentials and revoke sessions if the recipient interacted with the attachment and entered credentials.
- Isolate the endpoint only if there is evidence the attachment led to malware execution or browser compromise.

**Closure criteria:**
- The sender domain is validated as a legitimate business contact and the attachment is expected.
- No user interaction occurred and the message is confirmed benign by the recipient or business owner.
- The message is removed from the alert scope through an approved allowlist or sender-domain exception.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- GigaWiper - Ransomware-Like Bulk File Rename or Overwrite from Single Process: Do not schedule yet; validate as an analyst-led hunt first.
- Vidar Stealer - Signed Executable Created in User-Writable Directory with Low Tenant Prevalence: Do not schedule yet; validate as an analyst-led hunt first.

**Licensing / identity risk fields:**
- HTML Phishing Attachment Delivered from First-Time External Sender: EmailEvents and EmailAttachmentInfo require the Microsoft Defender XDR data connector to be enabled in Microsoft Sentinel and the tenant to have Microsoft Defender for Office 365 Plan 1 or Plan 2 licensed. Without this connector, these tables will not exist in the Sentinel workspace.

**Shared-table notes:**
- DeviceFileEvents: shared by Vidar Stealer - Fake MpClient.dll Sideloading from Non-Standard Path; GigaWiper - Mass File Deletion Combined with Shadow Copy Removal; GigaWiper - Ransomware-Like Bulk File Rename or Overwrite from Single Process; Vidar Stealer - Signed Executable Created in User-Writable Directory with Low Tenant Prevalence
- DeviceProcessEvents: shared by GigaWiper - Mass File Deletion Combined with Shadow Copy Removal; Vidar Stealer - Signed Executable Created in User-Writable Directory with Low Tenant Prevalence

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Vidar Stealer - Fake MpClient.dll Sideloading from Non-Standard Path; GigaWiper - Mass File Deletion Combined with Shadow Copy Removal.
2. Resolve environment-mapping detections next: HTML Phishing Attachment Delivered from First-Time External Sender.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: GigaWiper - Ransomware-Like Bulk File Rename or Overwrite from Single Process; Vidar Stealer - Signed Executable Created in User-Writable Directory with Low Tenant Prevalence.

### Hunting Agenda and Promotion Criteria

- GigaWiper - Ransomware-Like Bulk File Rename or Overwrite from Single Process: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Vidar Stealer - Signed Executable Created in User-Writable Directory with Low Tenant Prevalence: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- HTML Phishing Attachment Delivered from First-Time External Sender: EmailEvents and EmailAttachmentInfo require the Microsoft Defender XDR data connector to be enabled in Microsoft Sentinel and the tenant to have Microsoft Defender for Office 365 Plan 1 or Plan 2 licensed. Without this connector, these tables will not exist in the Sentinel workspace.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
