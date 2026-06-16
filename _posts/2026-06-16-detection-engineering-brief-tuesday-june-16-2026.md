---
layout: post
title: "Detection Engineering Brief - Tuesday, June 16, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-16
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Remcos RAT
  - Windows
  - T1059
  - MSI
  - T1059.007
  - T1071
  - T1218
  - T1218.007
  - T1036
---

## Executive Signal

This brief produced 3 detection candidates.

2 production candidates, 1 hunting-only, 0 require environment mapping, and 0 rejected.

3 detections include KQL. 3 include ATT&CK mappings. 3 include triage guidance.

Search metadata extracted for this run includes: Remcos RAT, Windows, T1059, MSI, T1059.007, T1071, T1218, T1218.007, T1036.

Relevant IOCs were preserved and rendered inside their associated detection sections.

Deployment blockers or scheduling gates were identified for: msiexec.exe Spawning Unexpected Child Processes or Writing to Suspicious Paths.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: VHDX Auto-Mount Followed by JavaScript Execution from Mounted Volume

### Detection Opportunity

VHDX file created from ZIP delivery and subsequently used to launch JavaScript via wscript or cscript from a mounted volume path

### Intelligence Context

- SANS ISC: From a VHDX File to a Remcos RAT, (Tue, Jun 16th) — [https://isc.sans.edu/diary/rss/33080](https://isc.sans.edu/diary/rss/33080)
  - Context: A malicious ZIP archive delivered a VHDX file that auto-mounted on Windows, revealing a malicious JavaScript file. Execution of that JavaScript initiated the Remcos RAT deployment chain.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.007, T1071
- Products: Not specified
- Platforms: Windows
- Malware: Remcos RAT
- Tools: Not specified
- Search tags: Remcos RAT, Windows, T1059, T1059.007, T1071

### Relevant IOCs

| Type | Indicator |
|---|---|
| SHA256 | `a0104921a2d37ab87482ac9a9f5c3713479c118846c3e999178e75b81620c094` |

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.007 JavaScript (medium); Command and Control: T1071 Application Layer Protocol (low)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let lookback = 7d;
let vhdxCreations = DeviceFileEvents
| where Timestamp > ago(lookback)
| where FileExtension =~ "vhdx"
| where ActionType == "FileCreated"
| project
    DeviceName,
    VhdxCreatedTime = Timestamp,
    VhdxFile = FileName,
    VhdxFolderPath = FolderPath,
    VhdxCreatedBy = InitiatingProcessFileName,
    VhdxCreatedByCommandLine = InitiatingProcessCommandLine;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ ("wscript.exe", "cscript.exe")
| where ProcessCommandLine matches regex @"(?i)\b[D-Zd-z]:\\[^\\].*\.js"
| join kind=inner vhdxCreations on DeviceName
| where Timestamp between (VhdxCreatedTime .. (VhdxCreatedTime + 30m))
| project
    Timestamp,
    DeviceName,
    AccountName,
    AccountDomain,
    ScriptInterpreter = FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ProcessId,
    InitiatingProcessId,
    VhdxCreatedTime,
    VhdxFile,
    VhdxFolderPath,
    VhdxCreatedBy,
    VhdxCreatedByCommandLine
| sort by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate enterprise software delivered via VHDX containers that include JavaScript-based installers or configuration scripts.
- Developer or IT workflows that mount VHDX images and execute JS-based tooling from mounted volumes.
- Endpoints with multiple concurrent VHDX operations may produce cross-correlated false matches if two unrelated VHDX files are created within 30 minutes of a legitimate script execution.

Tuning notes:
- Extend the lookback or correlation window if threat intelligence indicates longer gaps between VHDX delivery and JS execution in observed campaigns.
- Add known-good VHDX-based software delivery paths to an exclusion filter on VhdxFolderPath if enterprise tooling generates false positives.
- Consider adding a SHA256 filter for the known IOC hash a0104921a2d37ab87482ac9a9f5c3713479c118846c3e999178e75b81620c094 against DeviceFileEvents.SHA256 as a parallel high-confidence branch.

Risks / caveats:
- DeviceFileEvents.FileExtension field population depends on Defender for Endpoint sensor version and file event coverage; VHDX creation events may not be captured if the file is written by a non-monitored process or arrives via a network share without local file write telemetry.
- The 30-minute correlation window is a heuristic; adversaries with longer dwell between VHDX delivery and execution will evade this detection.
- VHDX files delivered via email attachment and opened directly by the user may not generate a FileCreated event if the mail client writes to a temp path not covered by the sensor.
- The drive-letter regex does not validate that the matched drive letter corresponds to an actually mounted VHDX; it matches any non-C drive path, which may include USB drives or network-mapped drives.

### Triage Runbook

First 15 minutes:
- Validate the alert timeline: confirm the VHDX creation time, the mounted volume path, and the subsequent wscript.exe or cscript.exe execution on the same device.
- Check the script command line for the exact .js path, parent process, and user context; treat execution from a non-C: mounted drive as suspicious unless clearly tied to approved software delivery.
- Look up the SHA256 a0104921a2d37ab87482ac9a9f5c3713479c118846c3e999178e75b81620c094 in your environment and determine whether the file was seen on other hosts.
- Assess whether the device has any immediate signs of follow-on activity such as new persistence, additional script execution, or outbound connections from the same user session.

Evidence to collect:
- DeviceFileEvents for the VHDX creation event, including FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName, and AccountDomain.
- DeviceProcessEvents for wscript.exe or cscript.exe, including ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessId, and InitiatingProcessId.
- Any file telemetry showing the mounted volume contents, especially the JavaScript file name and any dropped executables or scripts.
- The user identity and logon session associated with the VHDX creation and script execution.
- Any matching detections or alerts on the same host within the prior and subsequent 24 hours.

Pivot points:
- DeviceFileEvents filtered on the SHA256 a0104921a2d37ab87482ac9a9f5c3713479c118846c3e999178e75b81620c094 and on FileExtension == vhdx.
- DeviceProcessEvents for wscript.exe, cscript.exe, powershell.exe, cmd.exe, mshta.exe, rundll32.exe, and regsvr32.exe on the same DeviceName.
- DeviceNetworkEvents for the same DeviceName and user session to identify any outbound connections after script execution.
- Alert and incident history for the same DeviceName and AccountName to identify repeated delivery or execution attempts.

Benign explanations:
- Approved software distribution packages that use VHDX containers and JavaScript-based installers.
- IT or developer workflows that mount VHDX images for testing, packaging, or automation.
- A legitimate VHDX created by backup, virtualization, or imaging software that happens to contain a script file but is not executed.

Escalation criteria:
- The JavaScript was executed from the mounted VHDX and is followed by any outbound network activity, especially to an external IP or URL.
- The SHA256 matches the known IOC or the same VHDX/script appears on multiple endpoints.
- The host shows additional suspicious child processes, persistence, or credential access behavior after the script runs.

Containment actions:
- If execution is confirmed and no approved business justification exists, isolate the endpoint from the network.
- Preserve the VHDX file, the JavaScript, and any dropped payloads for forensic analysis before remediation.
- Disable or reset the affected user account if there are signs of active malicious use or repeated execution attempts.

Closure criteria:
- The VHDX and script are verified as part of an approved software or IT workflow.
- No malicious child processes, outbound connections, or follow-on activity are found on the host.
- The file hash and path are added to an allowlist or suppression rule after validation with the business owner.

---

## Detection 2: Script Interpreter Spawning Suspicious Child Process with Outbound Network Connection - Remcos RAT Chain

### Detection Opportunity

wscript.exe or cscript.exe spawning a child process that subsequently establishes an outbound network connection, consistent with Remcos RAT deployment following JavaScript execution from a mounted VHDX

### Intelligence Context

- SANS ISC: From a VHDX File to a Remcos RAT, (Tue, Jun 16th) — [https://isc.sans.edu/diary/rss/33080](https://isc.sans.edu/diary/rss/33080)
  - Context: After JavaScript execution from the mounted VHDX, the infection chain culminated in Remcos RAT deployment. Remcos exhibits C2 beaconing behavior. Detecting the script interpreter parent-to-RAT child process chain combined with outbound network activity provides high-confidence alerting.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.007, T1071
- Products: Not specified
- Platforms: Windows
- Malware: Remcos RAT
- Tools: Not specified
- Search tags: Remcos RAT, Windows, T1059, T1059.007, T1071

### Relevant IOCs

| Type | Indicator |
|---|---|
| SHA256 | `a0104921a2d37ab87482ac9a9f5c3713479c118846c3e999178e75b81620c094` |

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.007 JavaScript (medium); Command and Control: T1071 Application Layer Protocol (low)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let lookback = 7d;
let scriptSpawnedProcs = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName in~ ("wscript.exe", "cscript.exe")
| where FileName !in~ ("conhost.exe", "WerFault.exe")
| project
    DeviceName,
    ChildProcessName = FileName,
    ChildPID = ProcessId,
    SpawnTime = Timestamp,
    ProcessCommandLine,
    InitiatingProcessFileName,
    AccountName,
    AccountDomain;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType == "ConnectionSuccess"
| where RemoteIP !startswith "10."
| where RemoteIP !startswith "192.168."
| where not(RemoteIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\.") 
| where RemoteIP !startswith "127."
| where RemoteIP !startswith "169.254."
| join kind=inner scriptSpawnedProcs on DeviceName, $left.InitiatingProcessId == $right.ChildPID
| where Timestamp between (SpawnTime .. (SpawnTime + 15m))
| project
    SpawnTime,
    NetworkTimestamp = Timestamp,
    DeviceName,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    ChildProcessName,
    ChildPID,
    ProcessCommandLine,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    NetworkActionType = ActionType
| sort by SpawnTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate enterprise automation scripts executed via wscript or cscript that spawn helper processes which make outbound connections to update services or telemetry endpoints.
- Software deployment workflows using wscript to invoke installers that phone home to vendor update infrastructure.
- Security tooling or monitoring agents spawned indirectly from script interpreters that establish outbound connections.

Tuning notes:
- If DeviceNetworkEvents.InitiatingProcessId is not consistently populated in your environment, replace the dual-key join with a DeviceName-only join and add a filter on DeviceNetworkEvents.InitiatingProcessFileName to match the known child process names observed in your environment.
- Add known-safe child process names and their associated remote IP ranges to an exclusion list if legitimate automation workflows generate false positives.
- Consider correlating with the first detection (VHDX creation) by chaining all three events for a higher-confidence alert with lower volume.

Risks / caveats:
- DeviceNetworkEvents.InitiatingProcessId and DeviceProcessEvents.ProcessId are both available in Defender XDR but joining on ProcessId across tables requires that the child process PID is captured as the initiating process in the network event; if the RAT spawns a further child that makes the network connection, the join on DeviceName alone may miss the direct lineage.
- If Remcos RAT injects into an existing process rather than running as a direct child of the script interpreter, the ProcessId join will not correlate the network connection to the script interpreter parent.
- The 15-minute window may miss slow-beacon or delayed C2 check-in patterns used by some Remcos configurations.
- DeviceNetworkEvents.InitiatingProcessId may not be populated for all network connection types or sensor configurations, which would cause the tightened join to return no results; if this occurs, fall back to DeviceName-only join with additional process name filtering.

### Triage Runbook

First 15 minutes:
- Verify the parent-child chain: confirm the script interpreter, the spawned child process name, and the child PID that made the network connection.
- Inspect the child process command line for download, execution, or staging behavior and note any unusual working directory or user-writable path.
- Review the remote IP, port, and URL to determine whether the connection is external, newly observed, or associated with known infrastructure.
- Check whether the same host also triggered the VHDX-to-JavaScript detection or any other script-based execution alerts.

Evidence to collect:
- DeviceProcessEvents for the script interpreter and its child process, including ProcessId, InitiatingProcessId, ProcessCommandLine, AccountName, and AccountDomain.
- DeviceNetworkEvents for the child PID, including RemoteIP, RemotePort, RemoteUrl, ActionType, and timestamp.
- Any related DeviceFileEvents showing payload drops, script files, or executables created shortly before or after the network connection.
- The full process tree for the affected session to identify additional spawned processes or injection behavior.
- Historical sightings of the same remote IP, URL, or child process name across the tenant.

Pivot points:
- DeviceNetworkEvents filtered by DeviceName, InitiatingProcessId, RemoteIP, and RemoteUrl.
- DeviceProcessEvents for the same DeviceName and child process name to reconstruct the process tree.
- DeviceFileEvents for files created in temp, AppData, ProgramData, or user profile paths around the same timestamp.
- Alert and incident timeline for the host to identify whether this is part of a broader intrusion chain.

Benign explanations:
- Legitimate automation or software deployment scripts that spawn helper processes and contact vendor update services.
- Enterprise tooling launched by wscript.exe or cscript.exe that performs normal telemetry or licensing checks.
- A benign child process that happens to make an external connection but is part of an approved workflow.

Escalation criteria:
- The child process is not an approved helper binary and the network connection is to an external, suspicious, or newly observed destination.
- The host also shows the VHDX/JavaScript execution chain or other signs of staged malware delivery.
- The child process exhibits persistence, credential access, or repeated beaconing behavior.

Containment actions:
- Isolate the endpoint if the child process and outbound connection cannot be explained by an approved workflow.
- Block the remote IP or URL if it is confirmed malicious and used by multiple affected hosts.
- Preserve the process tree, network telemetry, and any dropped files for incident response.

Closure criteria:
- The child process is identified as a known-good enterprise component with a documented purpose.
- The remote destination is validated as legitimate and tied to an approved service or vendor.
- No additional malicious activity is found in the process tree, file system, or network telemetry.

---

## Detection 3: msiexec.exe Spawning Unexpected Child Processes or Writing to Suspicious Paths

### Detection Opportunity

msiexec.exe spawning child processes outside of expected installer behavior or writing files to temporary or user-writable paths, consistent with malicious MSI installer execution

### Intelligence Context

- SANS ISC: Evil MSI Background: BASE64 Statistical Analysis, (Mon, Jun 15th) — [https://isc.sans.edu/diary/rss/33072](https://isc.sans.edu/diary/rss/33072)
  - Context: The reporting analyzed malicious MSI installer content including embedded encoded payloads. Malicious MSI files are detectable at execution time via anomalous msiexec child process behavior or file writes to suspicious paths that deviate from legitimate installer patterns.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1218, T1218.007, T1059, T1036
- Products: MSI
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: MSI, Windows, T1218, T1218.007, T1059, T1036

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Execution: T1218 System Binary Proxy Execution/ T1218.007 Msiexec (high); Execution: T1059 Command and Scripting Interpreter (medium); Defense Evasion: T1036 Masquerading (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let lookback = 7d;
let suspiciousChildren = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName =~ "msiexec.exe"
| where FileName in~ (
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "regasm.exe",
    "regsvcs.exe"
)
| project
    DetectionBranch = "SuspiciousChildProcess",
    Timestamp,
    DeviceName,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ChildProcess = FileName,
    ProcessCommandLine,
    ProcessId,
    DroppedFile = "",
    FolderPath = "",
    SHA256 = "",
    ActionType = "";
let suspiciousWrites = DeviceFileEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName =~ "msiexec.exe"
| where ActionType == "FileCreated"
| where FolderPath matches regex @"(?i)\\(temp|appdata|users\\public|programdata|windows\\temp)\\"
| where FileName endswith ".exe"
    or FileName endswith ".dll"
    or FileName endswith ".ps1"
    or FileName endswith ".js"
    or FileName endswith ".vbs"
    or FileName endswith ".bat"
    or FileName endswith ".cmd"
| project
    DetectionBranch = "SuspiciousFileWrite",
    Timestamp,
    DeviceName,
    AccountName = "",
    AccountDomain = "",
    InitiatingProcessFileName,
    InitiatingProcessCommandLine = "",
    ChildProcess = "",
    ProcessCommandLine = "",
    ProcessId = int(null),
    DroppedFile = FileName,
    FolderPath,
    SHA256,
    ActionType;
union suspiciousChildren, suspiciousWrites
| sort by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Enterprise software packages that use PowerShell or cmd custom actions as part of legitimate installation workflows (e.g., configuration scripts, license activation, service registration).
- Software deployment platforms such as SCCM or Intune that invoke msiexec with custom action scripts as part of managed deployment.
- Developer tools and IDEs that write scripts or executables to AppData paths as part of their installation.
- Security software installers that drop components to temp paths during staged installation.

Tuning notes:
- Build an allowlist of known-good MSI package SHA256 hashes or installer command-line patterns from your software deployment baseline and add them as exclusion filters on InitiatingProcessCommandLine.
- After initial hunting runs, identify recurring false positive child process names from approved enterprise software and add them to a per-environment exclusion set.
- Consider promoting to a scheduled rule only after establishing a per-environment allowlist that reduces false positive volume to an actionable level.
- Correlate the two branches by joining on DeviceName and a short time window to surface devices exhibiting both suspicious child process spawning and suspicious file writes from msiexec in the same session, which would be a higher-confidence signal.

Risks / caveats:
- DeviceFileEvents.InitiatingProcessFileName may not reliably attribute file writes to msiexec.exe when the MSI custom action runs in a subprocess chain; the sensor may record the immediate parent rather than msiexec.exe itself, causing the filter to miss events.
- The union produces two structurally different event types in a single result set; analysts must interpret DetectionBranch to apply appropriate triage steps for each signal type.
- The InitiatingProcessFileName filter on DeviceFileEvents may miss cases where msiexec.exe uses a subprocess chain and the immediate file-writing process is not msiexec.exe itself.
- No correlation is performed between the two branches; a device appearing in both branches within a short window would be a stronger signal but is not surfaced by this query.

### Triage Runbook

First 15 minutes:
- Identify which branch fired: suspicious child process spawning or suspicious file creation, and capture the exact timestamp and host.
- Review the msiexec command line, parent process, and initiating user to determine whether this was a managed software deployment or a user-initiated install.
- If a child process was spawned, inspect whether it is a LOLBin, script interpreter, or shell commonly used in malicious MSI custom actions.
- If a file was written, check the folder path and extension to see whether the installer dropped executables or scripts into temp, AppData, ProgramData, or Windows Temp.

Evidence to collect:
- DeviceProcessEvents for msiexec.exe and its child processes, including ProcessCommandLine, InitiatingProcessCommandLine, AccountName, and AccountDomain.
- DeviceFileEvents for files created by msiexec.exe, including FolderPath, FileName, SHA256, and ActionType.
- The full installer context, including package name, source path, and whether the install was signed or centrally deployed.
- Any related alerts on the same host for script execution, persistence, or network connections shortly after the MSI activity.
- Hash and path details for any dropped files to support reputation and prevalence checks.

Pivot points:
- DeviceProcessEvents filtered on InitiatingProcessFileName == msiexec.exe and the suspicious child process names.
- DeviceFileEvents filtered on InitiatingProcessFileName == msiexec.exe and FileCreated events in temp, AppData, ProgramData, or Windows Temp.
- DeviceNetworkEvents for the same host if the child process or dropped file later initiates outbound connections.
- Software deployment logs or endpoint management records to confirm whether the MSI was approved.

Benign explanations:
- Approved enterprise software installation that uses custom actions, scripts, or helper binaries.
- SCCM, Intune, or other deployment tooling performing a managed install with expected temporary file writes.
- Legitimate vendor installers that stage components in user-writable or temp directories during setup.

Escalation criteria:
- msiexec.exe spawns a script interpreter, shell, or LOLBin without a clear approved deployment context.
- The installer drops executable or script content into suspicious paths and the files are unsigned, unknown, or match malicious reputation.
- The same host later shows outbound connections, persistence, or additional execution consistent with post-install compromise.

Containment actions:
- If the MSI is unapproved or clearly malicious, isolate the endpoint to stop further execution.
- Quarantine or remove the dropped files after preserving them for analysis.
- Block the installer source or package hash if it is confirmed malicious and still circulating.

Closure criteria:
- The MSI is verified as an approved package from a trusted deployment source.
- The child process and file writes are consistent with documented installer behavior.
- No malicious follow-on activity is observed and any noisy paths or hashes are documented for future suppression.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Schema / correlation keys:
- msiexec.exe Spawning Unexpected Child Processes or Writing to Suspicious Paths: Do not schedule yet; validate as an analyst-led hunt first.

Shared-table notes:
- DeviceFileEvents: shared by VHDX Auto-Mount Followed by JavaScript Execution from Mounted Volume; msiexec.exe Spawning Unexpected Child Processes or Writing to Suspicious Paths
- DeviceProcessEvents: shared by VHDX Auto-Mount Followed by JavaScript Execution from Mounted Volume; Script Interpreter Spawning Suspicious Child Process with Outbound Network Connection - Remcos RAT Chain; msiexec.exe Spawning Unexpected Child Processes or Writing to Suspicious Paths

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: VHDX Auto-Mount Followed by JavaScript Execution from Mounted Volume; Script Interpreter Spawning Suspicious Child Process with Outbound Network Connection - Remcos RAT Chain.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: msiexec.exe Spawning Unexpected Child Processes or Writing to Suspicious Paths.

### Hunting Agenda and Promotion Criteria

- msiexec.exe Spawning Unexpected Child Processes or Writing to Suspicious Paths: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

## Observed IOCs

> Indicators are extracted from source reporting context and should be validated before blocking, alerting, or enrichment.

| Type | Indicator |
|---|---|
| SHA256 | `a0104921a2d37ab87482ac9a9f5c3713479c118846c3e999178e75b81620c094` |


---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
