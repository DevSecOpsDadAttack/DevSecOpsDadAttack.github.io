---
layout: post
title: "Detection Engineering Brief - Wednesday, June 17, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-17
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Remcos RAT
  - Windows
  - T1059
---

## Executive Signal

This brief produced 3 detection candidates.

1 production candidate, 2 hunting-only, 0 require environment mapping, and 0 rejected.

3 detections include KQL. 0 include ATT&CK mappings. 3 include triage guidance.

Search metadata extracted for this run includes: Remcos RAT, Windows, T1059.

Relevant IOCs were preserved and rendered inside their associated detection sections.

Deployment blockers or scheduling gates were identified for: VHDX Mount Followed by JavaScript Execution on Same Device; VHDX File Created by Archive Extraction Process in User-Writable Path.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: VHDX Mount Followed by JavaScript Execution on Same Device

### Detection Opportunity

VHDX file written to disk by an archive or download process, followed by wscript or cscript execution on the same device within a short time window, consistent with Remcos RAT delivery chain.

### Intelligence Context

- SANS ISC: From a VHDX File to a Remcos RAT, (Tue, Jun 16th) — [https://isc.sans.edu/diary/rss/33080](https://isc.sans.edu/diary/rss/33080)
  - Context: A malicious ZIP archive delivers a VHDX file. Once mounted, the VHDX discloses a malicious JavaScript file that is executed via a Windows script host, ultimately leading to Remcos RAT execution. The compound behavior of VHDX file creation followed by script host execution on the same device is the core detection signal.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059
- Products: Not specified
- Platforms: Windows
- Malware: Remcos RAT
- Tools: Not specified
- Search tags: Remcos RAT, Windows, T1059

### Relevant IOCs

| Type | Indicator |
|---|---|
| SHA256 | `a0104921a2d37ab87482ac9a9f5c3713479c118846c3e999178e75b81620c094` |

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: T1059

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let vhdxCreation = DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith ".vhdx"
| where InitiatingProcessFileName in~ (
    "explorer.exe", "winrar.exe", "7zfm.exe", "7z.exe",
    "winzip32.exe", "winzip64.exe", "msedge.exe", "chrome.exe",
    "firefox.exe", "outlook.exe"
  )
| summarize VhdxTime = min(Timestamp), VhdxFile = any(FileName), VhdxFolder = any(FolderPath), ExtractedBy = any(InitiatingProcessFileName)
    by DeviceName, DeviceId;
let scriptExec = DeviceProcessEvents
| where FileName in~ ("wscript.exe", "cscript.exe")
| project ScriptTime = Timestamp, DeviceName, DeviceId,
    ScriptProcess = FileName, ProcessCommandLine,
    InitiatingProcessCommandLine, AccountName;
vhdxCreation
| join kind=inner scriptExec on DeviceName, DeviceId
| where ScriptTime between (VhdxTime .. (VhdxTime + 10m))
| project
    VhdxTime,
    ScriptTime,
    DeviceName,
    DeviceId,
    VhdxFile,
    VhdxFolder,
    ExtractedBy,
    ScriptProcess,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    AccountName
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- IT administrators or developers who legitimately extract VHDX files and subsequently run scripts on the same device.
- Automated software deployment pipelines that use archive tools and script hosts in sequence.
- Environments with frequent scripted workflows may produce matches unrelated to VHDX delivery.

Tuning notes:
- Expand the InitiatingProcessFileName list to include archive or download tools specific to the environment.
- Add a FolderPath filter on the VHDX creation event to restrict to user-writable paths (Downloads, Temp, AppData) if broad VHDX creation matches produce noise.
- After baselining, consider adding an exclusion for known IT administrator device groups using a DeviceName not in (...) or anti-join against a device group watchlist.
- Adjust the 10-minute window based on observed delivery chain timing in the environment.

Risks / caveats:
- The 10-minute correlation window is heuristic; environments with slower user interaction may require a longer window, while noisier environments may need a shorter one.
- The initiating process list for VHDX creation is not exhaustive; download managers, email clients beyond Outlook, or custom extraction tools used in the environment will not be covered without list expansion.
- summarize on DeviceName and DeviceId takes the earliest VHDX creation event per device; if multiple distinct VHDX delivery attempts occur on the same device within the lookback window, only the first is correlated.
- DeviceId may not be populated for all device records depending on onboarding status; DeviceName alone is used as fallback by the join but may produce cross-device matches in environments with non-unique hostnames.

### Triage Runbook

First 15 minutes:
- Validate the timeline: confirm the VHDX creation time and the wscript.exe/cscript.exe execution time are within the expected short window on the same DeviceName and DeviceId.
- Inspect the script command line and parent process details to determine whether the script references a mounted VHDX, a downloaded archive, or a suspicious user-writable path.
- Check whether the account is a normal user, admin, or service account and whether the activity aligns with that user's recent behavior.
- Look for immediate follow-on signs of compromise on the host, including new child processes, persistence, outbound connections, or additional file drops around the script execution time.

Evidence to collect:
- VhdxTime, ScriptTime, DeviceName, DeviceId, VhdxFile, VhdxFolder, ExtractedBy, ScriptProcess, ProcessCommandLine, InitiatingProcessCommandLine, AccountName.
- The full DeviceFileEvents record for the VHDX creation, including the initiating process name and command line.
- The full DeviceProcessEvents record for the script host execution, including the script command line and any child processes spawned shortly after.
- Any matching SHA256 values for the VHDX-related content or subsequent dropped files if available in adjacent telemetry.

Pivot points:
- Pivot in DeviceProcessEvents from the script host process to its child processes and sibling activity on the same DeviceId within the same hour.
- Pivot in DeviceFileEvents for additional files created by the same account or device in Downloads, Temp, AppData, or ProgramData around the alert time.
- Review DeviceNetworkEvents for outbound connections from the same device shortly after script execution, especially to rare or newly seen destinations.
- Check DeviceLogonEvents and DeviceInfo for recent interactive logons, remote sessions, or unusual device ownership context.

Benign explanations:
- An IT administrator or developer legitimately extracted a VHDX and then ran a script on the same workstation.
- A software deployment or imaging workflow used archive tools and script hosts in sequence on a managed endpoint.
- A user opened a legitimate VHDX from email or a download and then executed a benign script as part of normal work.

Escalation criteria:
- The script command line references obfuscation, encoded content, suspicious URLs, or a dropped payload from a user-writable path.
- The same host shows additional malicious behavior such as persistence, credential access, unusual network beacons, or multiple suspicious child processes.
- The VHDX or related files hash to the known Remcos RAT SHA256 or match other campaign artifacts.
- The activity occurs on a non-administrative user endpoint with no credible business justification.

Containment actions:
- Isolate the endpoint if the script execution appears malicious or if follow-on compromise indicators are present.
- Suspend or reset the affected user account if there is evidence of active malicious execution or lateral movement.
- Preserve the VHDX file, script content, and related dropped files for forensic analysis before remediation.
- Block the known SHA256 and any confirmed malicious child processes or destinations if validated by investigation.

Closure criteria:
- The VHDX and script activity are confirmed to be part of a documented, benign workflow with matching user and business context.
- No suspicious child processes, network activity, persistence, or additional malicious artifacts are found on the device.
- The script command line and related files are reviewed and assessed as non-malicious by the SOC or endpoint team.
- Any required allowlist or exception is documented with the owning team and approved by security operations.

---

## Detection 2: Script Host Spawning Suspicious Child Process from Temp or AppData Path

### Detection Opportunity

wscript.exe or cscript.exe spawning an executable from a user-writable path such as Temp or AppData, consistent with JavaScript-based Remcos RAT delivery following VHDX mount.

### Intelligence Context

- SANS ISC: From a VHDX File to a Remcos RAT, (Tue, Jun 16th) — [https://isc.sans.edu/diary/rss/33080](https://isc.sans.edu/diary/rss/33080)
  - Context: The malicious JavaScript executed via wscript or cscript spawns a child process that delivers Remcos RAT. The parent-child relationship between a Windows script host and an executable dropped in a user-writable path is a high-fidelity behavioral signal for this delivery chain.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059
- Products: Not specified
- Platforms: Windows
- Malware: Remcos RAT
- Tools: Not specified
- Search tags: Remcos RAT, Windows, T1059

### Relevant IOCs

| Type | Indicator |
|---|---|
| SHA256 | `a0104921a2d37ab87482ac9a9f5c3713479c118846c3e999178e75b81620c094` |

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: T1059

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("wscript.exe", "cscript.exe")
| where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\ProgramData\\")
| where FileName endswith ".exe"
| where FileName !in~ ("conhost.exe", "cmd.exe", "powershell.exe")
| project
    Timestamp,
    DeviceName,
    DeviceId,
    AccountName,
    AccountDomain,
    ParentScript = InitiatingProcessFileName,
    InitiatingProcessId,
    InitiatingProcessCommandLine,
    SpawnedProcess = FileName,
    ProcessId,
    FolderPath,
    ProcessCommandLine,
    SHA256
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate software installers or update mechanisms that use script hosts to launch executables from AppData or ProgramData.
- Enterprise software deployment tools that invoke wscript or cscript to run setup executables staged in ProgramData.
- Developer workstations where build or test scripts launch executables from Temp directories.

Tuning notes:
- After a 7-day baseline review, add confirmed-benign executable names or FolderPath subpaths to the exclusion filters.
- Consider adding an InitiatingProcessCommandLine filter to further scope to .js or .vbs script arguments if environment noise is high.
- If ProgramData matches are predominantly legitimate, narrow the FolderPath filter to exclude known vendor subdirectories under ProgramData.

Risks / caveats:
- The exclusion list for benign script host children is minimal; environments with scripted software deployment may require additional exclusions for specific executable names or FolderPath subpaths.
- ProgramData is included in the path filter; some legitimate enterprise applications stage executables there and may generate false positives until allowlisted.
- Non-.exe payloads (e.g., .dll side-loading via rundll32, .bat, .ps1 launched indirectly) are not covered by this query.
- SHA256 field population depends on Defender for Endpoint sensor configuration; it may be empty for some process creation events.

### Triage Runbook

First 15 minutes:
- Confirm the parent-child relationship: verify the initiating process is wscript.exe or cscript.exe and the spawned executable resides in Temp, AppData, or ProgramData.
- Review the spawned process name, command line, and SHA256 to identify whether it is a known installer, updater, or a suspicious payload.
- Check the parent script command line and initiating process command line for references to .js, .vbs, encoded content, or dropped files.
- Assess the user context and device role to determine whether the behavior is expected for that endpoint.

Evidence to collect:
- Timestamp, DeviceName, DeviceId, AccountName, AccountDomain, ParentScript, InitiatingProcessId, InitiatingProcessCommandLine, SpawnedProcess, ProcessId, FolderPath, ProcessCommandLine, SHA256.
- The full process tree around the alert, including any grandchildren spawned by the executable.
- The file hash and file path of the spawned executable and any adjacent files in the same directory.
- Any related network connections or persistence artifacts created within the same session.

Pivot points:
- Pivot in DeviceProcessEvents on the ProcessId and InitiatingProcessId to reconstruct the full process tree for the alert window.
- Search DeviceFileEvents for other files created in the same folder path by the same account or parent script.
- Review DeviceNetworkEvents for outbound connections from the spawned process and its descendants.
- Check DeviceRegistryEvents for persistence-related changes made by the same account or process around the same time.

Benign explanations:
- A legitimate installer or updater used a script host to launch a setup executable from ProgramData or AppData.
- A developer or tester ran a script that intentionally staged and executed a binary from Temp.
- Enterprise software deployment tooling invoked wscript.exe or cscript.exe as part of a normal installation process.

Escalation criteria:
- The spawned executable hash matches the known Remcos RAT SHA256 or another confirmed malicious hash.
- The executable exhibits suspicious behavior such as persistence, credential theft, injection, or outbound beaconing.
- The parent script is obfuscated, downloaded from an untrusted source, or references a VHDX-derived path.
- The activity occurs on a user workstation with no documented software deployment or admin task.

Containment actions:
- Isolate the endpoint if the spawned executable is untrusted or shows malicious behavior.
- Terminate the suspicious process tree if it is still active and the host can be safely contained.
- Preserve the script, spawned executable, and surrounding directory contents for analysis.
- Block the file hash and any confirmed malicious network indicators after validation.

Closure criteria:
- The process chain is confirmed to be a legitimate installer, updater, or approved administrative workflow.
- The executable hash and command line are matched to a known benign application or deployment package.
- No additional suspicious processes, network activity, or persistence artifacts are found.
- The event is documented and, if needed, added to an allowlist or tuning exception.

---

## Detection 3: VHDX File Created by Archive Extraction Process in User-Writable Path

### Detection Opportunity

A VHDX file written to disk by an archive extraction tool or browser download handler in a user-writable directory, consistent with the initial delivery stage of the Remcos RAT campaign.

### Intelligence Context

- SANS ISC: From a VHDX File to a Remcos RAT, (Tue, Jun 16th) — [https://isc.sans.edu/diary/rss/33080](https://isc.sans.edu/diary/rss/33080)
  - Context: The attack begins with a malicious ZIP archive that, when extracted, drops a VHDX file. Detection of a VHDX file created by an archive tool or browser in a user-writable path provides early-stage visibility into this delivery chain before script execution occurs.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059
- Products: Not specified
- Platforms: Windows
- Malware: Remcos RAT
- Tools: Not specified
- Search tags: Remcos RAT, Windows, T1059

### Relevant IOCs

| Type | Indicator |
|---|---|
| SHA256 | `a0104921a2d37ab87482ac9a9f5c3713479c118846c3e999178e75b81620c094` |

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: T1059

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceFileEvents

### KQL

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith ".vhdx"
| where InitiatingProcessFileName in~ (
    "explorer.exe", "winrar.exe", "7zfm.exe", "7z.exe",
    "winzip32.exe", "winzip64.exe", "msedge.exe", "chrome.exe",
    "firefox.exe", "outlook.exe", "pezip.exe", "bandizip.exe"
  )
| where FolderPath has_any ("\\Downloads\\", "\\Temp\\", "\\AppData\\")
| project
    Timestamp,
    DeviceName,
    DeviceId,
    VhdxFile = FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    SHA256
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- IT administrators or Hyper-V operators who download or extract VHDX files for legitimate virtual machine management.
- Developers who work with virtual disk images and extract them via archive tools to Temp or AppData paths.
- Enterprise imaging workflows that stage VHDX files in user-accessible directories.

Tuning notes:
- Add a DeviceName not in (...) or DeviceId not in (...) exclusion for known IT administrator or Hyper-V host devices after identifying them in the environment.
- Expand the InitiatingProcessFileName list to include additional archive or download tools observed in the environment.
- Consider combining this query with the correlated detection (VHDX Mount Followed by JavaScript Execution) for higher-fidelity alerting.

Risks / caveats:
- The initiating process list is heuristic and will miss VHDX delivery via unlisted archive tools, download managers, or email clients other than Outlook.
- VHDX files legitimately used by IT staff or Hyper-V administrators will match unless those devices are excluded; no device-group exclusion is embedded in the query.
- SHA256 and InitiatingProcessCommandLine may not be populated for all file creation events depending on sensor configuration.
- This query does not confirm the VHDX was mounted or that script execution followed; it is an early-stage indicator only.

### Triage Runbook

First 15 minutes:
- Verify the initiating process name and command line to confirm the VHDX was created by a browser, archive tool, or other allowed source process.
- Check the folder path to see whether the VHDX landed in Downloads, Temp, or AppData and whether that location is consistent with user activity.
- Review the file hash and file size to determine whether the VHDX appears to be a normal virtual disk or a suspicious payload container.
- Look for immediate follow-on activity from the same device or account, especially script host execution, mounting behavior, or additional file drops.

Evidence to collect:
- Timestamp, DeviceName, DeviceId, VhdxFile, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, SHA256.
- The original download or archive source if visible in browser, email, or extraction telemetry.
- Any subsequent DeviceProcessEvents showing wscript.exe or cscript.exe execution on the same device.
- Any related DeviceFileEvents showing files extracted from or created alongside the VHDX.

Pivot points:
- Pivot in DeviceProcessEvents for script host activity on the same DeviceId within the next 10 to 30 minutes.
- Search DeviceFileEvents for other files created by the same initiating process or account in the same folder.
- Review browser or email-related telemetry for the source of the download if available in the environment.
- Check DeviceNetworkEvents for recent downloads from unusual domains or rare destinations tied to the same user.

Benign explanations:
- An IT administrator or Hyper-V user legitimately downloaded or extracted a VHDX for virtual machine work.
- A developer or tester staged a VHDX in a user-writable directory as part of a lab or build workflow.
- An enterprise imaging or software distribution process created a VHDX in a user-accessible path.

Escalation criteria:
- The VHDX is followed by script host execution, especially if the script launches a payload from the same path.
- The initiating process is not a known archive, browser, or approved tool, or the command line is suspicious.
- The VHDX hash matches the known campaign artifact or other malicious content.
- The activity occurs on a standard user endpoint with no documented business need for VHDX handling.

Containment actions:
- Do not isolate solely on this alert unless additional malicious behavior is confirmed.
- If follow-on script execution or malicious content is found, isolate the endpoint and preserve the VHDX file.
- Block the known malicious hash if the VHDX is confirmed to be part of the campaign.
- Notify the user or asset owner only after confirming whether the activity is expected or unauthorized.

Closure criteria:
- The VHDX is confirmed to be part of a legitimate admin, developer, or imaging workflow.
- No subsequent script execution or other malicious follow-on activity is observed on the device.
- The file hash, source process, and folder path are consistent with approved use.
- Any needed tuning or device exclusions are documented for future alerts.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Schema / correlation keys:
- VHDX Mount Followed by JavaScript Execution on Same Device: Do not schedule yet; validate as an analyst-led hunt first.
- VHDX File Created by Archive Extraction Process in User-Writable Path: Do not schedule yet; validate as an analyst-led hunt first.

Shared-table notes:
- DeviceFileEvents: shared by VHDX Mount Followed by JavaScript Execution on Same Device; VHDX File Created by Archive Extraction Process in User-Writable Path
- DeviceProcessEvents: shared by VHDX Mount Followed by JavaScript Execution on Same Device; Script Host Spawning Suspicious Child Process from Temp or AppData Path

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Script Host Spawning Suspicious Child Process from Temp or AppData Path.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: VHDX Mount Followed by JavaScript Execution on Same Device; VHDX File Created by Archive Extraction Process in User-Writable Path.

### Hunting Agenda and Promotion Criteria

- VHDX Mount Followed by JavaScript Execution on Same Device: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- VHDX File Created by Archive Extraction Process in User-Writable Path: Do not schedule yet; validate as an analyst-led hunt first..

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
