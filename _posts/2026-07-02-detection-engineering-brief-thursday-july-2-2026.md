---
layout: post
title: "Detection Engineering Brief - Thursday, July 2, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-02
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - ScreenConnect
  - Windows
  - AsyncRAT
  - T1059
  - T1059.004
  - T1059.001
---

## Detection Engineering Summary

This brief produced 3 detection candidates.

1 production candidate, 2 hunting-only, 0 require environment mapping, and 0 rejected.

3 detections include KQL. 3 include ATT&CK mappings. 3 include triage guidance.

Search metadata extracted for this run includes: ScreenConnect, Windows, AsyncRAT, T1059, T1059.004, T1059.001.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Executable File Written by ScreenConnect Process to Staging Directories - Potential AsyncRAT Drop; Outbound Network Connection from ScreenConnect Child Process - Potential AsyncRAT C2 Beaconing.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

---

## Detection 1: ScreenConnect Spawning Suspicious Child Processes - Potential AsyncRAT Delivery

### Detection Opportunity

ScreenConnect process spawns scripting engines or command interpreters indicative of malware delivery during a campaign distributing AsyncRAT via compromised ScreenConnect software.

### Intelligence Context

- Securelist: The SOC Files: ScreenConnect masked as freeware. An inside look at a large-scale campaign — [https://securelist.com/tr/the-soc-files-screenconnect-campaign-with-asyncrat/120472/](https://securelist.com/tr/the-soc-files-screenconnect-campaign-with-asyncrat/120472/)
  - Context: Reporting describes a large-scale campaign where compromised ScreenConnect software was used to drop AsyncRAT on Windows endpoints. ScreenConnect spawning scripting engines or shells is the primary initial delivery signal identified in the infection chain.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.004, T1059.001
- Products: ScreenConnect
- Platforms: Windows
- Malware: AsyncRAT
- Tools: Not specified
- Search tags: ScreenConnect, Windows, AsyncRAT, T1059, T1059.004, T1059.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Command and Scripting Interpreter: T1059 Command and Scripting Interpreter (low); Command and Scripting Interpreter: T1059 Command and Scripting Interpreter/ 004 Unix Shell (low); Command and Scripting Interpreter: T1059 Command and Scripting Interpreter/ 001 PowerShell (low)

### Deployment Gates

- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where tolower(InitiatingProcessFileName) in (
    "screenconnect.clientservice.exe",
    "screenconnect.windowsclient.exe",
    "screenconnect.windowsbackstageshell.exe",
    "screenconnect.windowsinteractiveclient.exe"
  )
| where tolower(FileName) in (
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "msiexec.exe"
  )
| project
    Timestamp,
    DeviceName,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    FileName,
    FolderPath,
    ProcessCommandLine
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate remote IT administration sessions via ScreenConnect that invoke cmd.exe or powershell.exe for scripted tasks.
- Software deployment workflows that use ScreenConnect to push installers via msiexec.exe or certutil.exe.

**Tuning notes:**
- Add an AccountName exclusion list for known IT admin accounts that routinely use ScreenConnect to run scripts.
- Add a DeviceName exclusion list for jump hosts or IT management workstations where ScreenConnect-spawned shells are expected.
- Consider narrowing FileName to the highest-fidelity subset (e.g., mshta.exe, wscript.exe, cscript.exe) if powershell.exe and cmd.exe generate excessive volume in the environment.

**Risks / caveats:**
- DeviceProcessEvents requires Microsoft Defender for Endpoint (MDE) P1/P2 licensing and onboarded Windows endpoints; if MDE is not deployed, this table will be empty.
- The 7-day lookback window may miss earlier stages of a slow-moving campaign; adjust to match the organization's scheduled rule cadence and ingestion lag.
- ScreenConnect installations using non-default executable names or paths will not be caught; validate installed binary names in the environment.
- Legitimate admin use of ScreenConnect for scripted remote management will generate FPs until an allowlist of known-good accounts or devices is applied.

### Triage Runbook

**First 15 minutes:**
- Confirm whether the DeviceName is a known IT support or jump host and whether the AccountName/AccountDomain belongs to an authorized administrator.
- Review InitiatingProcessCommandLine and ProcessCommandLine for encoded commands, download cradles, script execution, or suspicious arguments.
- Check whether the child process launched from an expected ScreenConnect installation path in InitiatingProcessFolderPath or from a masqueraded location.
- Look for nearby process activity on the same host that indicates staging or follow-on execution, especially powershell.exe, certutil.exe, mshta.exe, or rundll32.exe.

**Evidence to collect:**
- Timestamp, DeviceName, AccountName, AccountDomain, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FileName, FolderPath, and ProcessCommandLine.
- Any ScreenConnect session metadata available from remote support tooling or endpoint logs to identify the operator and ticket/change record.
- Process tree around the alert time to determine whether the child process was spawned directly by ScreenConnect or through an intermediate shell.
- Any related file, network, or logon events on the same host within the same time window.

**Pivot points:**
- DeviceProcessEvents for parent-child process lineage around the alert time on the same DeviceName.
- DeviceNetworkEvents for outbound connections from the same child process or subsequent processes on the host.
- DeviceFileEvents for files created shortly before or after the suspicious process launch.
- If available, ScreenConnect administrative or audit logs to validate the remote session and operator identity.

**Benign explanations:**
- Authorized IT staff used ScreenConnect to run scripted maintenance, software deployment, or troubleshooting commands.
- A managed software installation or update used cmd.exe or powershell.exe as part of a normal remote support workflow.
- A known admin workstation or jump host routinely runs remote commands through ScreenConnect and should be allowlisted.

**Escalation criteria:**
- The child process command line shows download-and-execute behavior, encoded PowerShell, or script-based payload staging.
- The ScreenConnect binary path or parent process name is inconsistent with the organization's approved installation.
- The account or device is not a known IT support asset and the activity is not tied to a change ticket or approved remote session.
- Additional suspicious activity appears on the host, such as file drops, persistence, or outbound connections from the spawned process.

**Containment actions:**
- If the session is not authorized or the command line is clearly malicious, isolate the endpoint from the network.
- Terminate the suspicious child process and any related follow-on processes if containment is approved by incident response.
- Disable or reset the involved account if it is not a legitimate administrator account or if compromise is suspected.
- Preserve volatile evidence and collect the process tree before rebooting or cleaning the host.

**Closure criteria:**
- The activity is confirmed as an approved ScreenConnect administrative session with matching ticket/change evidence.
- The process command lines are consistent with routine maintenance and no additional suspicious telemetry is found.
- The host shows no follow-on file creation, persistence, credential access, or outbound C2 behavior.
- Any necessary allowlist entries for known admin accounts or devices have been documented and approved.

---

## Detection 2: Executable File Written by ScreenConnect Process to Staging Directories - Potential AsyncRAT Drop

### Detection Opportunity

AsyncRAT payload written to disk in user-writable directories by a ScreenConnect-related process following initial compromise via compromised ScreenConnect software.

### Intelligence Context

- Securelist: The SOC Files: ScreenConnect masked as freeware. An inside look at a large-scale campaign — [https://securelist.com/tr/the-soc-files-screenconnect-campaign-with-asyncrat/120472/](https://securelist.com/tr/the-soc-files-screenconnect-campaign-with-asyncrat/120472/)
  - Context: The campaign involved AsyncRAT being dropped to disk on Windows endpoints via compromised ScreenConnect software. File creation by ScreenConnect processes in temp or appdata directories is a key indicator of payload staging.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.004, T1059.001
- Products: ScreenConnect
- Platforms: Windows
- Malware: AsyncRAT
- Tools: Not specified
- Search tags: ScreenConnect, Windows, AsyncRAT, T1059, T1059.004, T1059.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Scripting Interpreter: T1059 Command and Scripting Interpreter (low); Command and Scripting Interpreter: T1059 Command and Scripting Interpreter/ 004 Unix Shell (low); Command and Scripting Interpreter: T1059 Command and Scripting Interpreter/ 001 PowerShell (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let SuspiciousFileDrops = DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where tolower(InitiatingProcessFileName) in (
    "screenconnect.clientservice.exe",
    "screenconnect.windowsclient.exe",
    "screenconnect.windowsbackstageshell.exe",
    "screenconnect.windowsinteractiveclient.exe"
  )
| where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\ProgramData\\")
| where FileName endswith ".exe"
    or FileName endswith ".dll"
    or FileName endswith ".bat"
    or FileName endswith ".ps1"
    or FileName endswith ".vbs"
| project
    DropTimestamp = Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    FileName,
    DropFolderPath = FolderPath,
    SHA256;
let SubsequentExecution = DeviceProcessEvents
| where Timestamp > ago(7d)
| project
    ExecTimestamp = Timestamp,
    DeviceName,
    ExecFileName = FileName,
    ExecFolderPath = FolderPath,
    ProcessCommandLine;
SuspiciousFileDrops
| join kind=inner SubsequentExecution
    on DeviceName,
    $left.FileName == $right.ExecFileName,
    $left.DropFolderPath == $right.ExecFolderPath
| where ExecTimestamp between (DropTimestamp .. (DropTimestamp + 10m))
| project
    DropTimestamp,
    ExecTimestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    FileName,
    DropFolderPath,
    SHA256,
    ProcessCommandLine
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate software packages (e.g., .msi, .exe installers) pushed by IT via ScreenConnect to AppData or Temp directories.
- Scripted deployments that write and immediately execute .ps1 or .bat files in Temp directories as part of normal IT workflows.

**Tuning notes:**
- Extend the execution window beyond 10 minutes if payload execution is observed to be delayed in historical data.
- Add AccountName exclusions for known IT admin accounts that legitimately push software via ScreenConnect.
- Consider splitting .dll drops into a separate query that joins against DeviceImageLoadEvents rather than DeviceProcessEvents.

**Risks / caveats:**
- DeviceFileEvents requires MDE P1/P2 licensing with file creation telemetry enabled; file events may be incomplete if advanced hunting data collection is not fully configured.
- DeviceProcessEvents requires MDE P1/P2 licensing and onboarded Windows endpoints.
- Joining on FolderPath requires that the executed process FolderPath in DeviceProcessEvents exactly matches the FolderPath recorded in DeviceFileEvents; path casing or trailing slash differences may cause missed matches.
- The 10-minute execution window may miss delayed payload execution; adjust based on observed campaign timing.

### Triage Runbook

**First 15 minutes:**
- Verify whether the DeviceName and AccountName correspond to a known IT support workflow or an unexpected remote session.
- Inspect the dropped FileName, DropFolderPath, and SHA256 to determine whether the file is a common installer or a suspicious payload.
- Check whether the file was created in Temp, AppData, or ProgramData and whether it was executed within the observed time window.
- Review ProcessCommandLine for signs of staged execution, script launchers, or installer abuse.

**Evidence to collect:**
- DropTimestamp, ExecTimestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, DropFolderPath, SHA256, and ProcessCommandLine.
- Any available file reputation or threat intelligence results for the SHA256 hash.
- The process tree showing the ScreenConnect parent and the subsequent execution chain from the dropped file.
- Any related DeviceNetworkEvents or DeviceRegistryEvents that indicate payload activity, persistence, or external communication.

**Pivot points:**
- DeviceFileEvents for additional file creations by the same ScreenConnect process on the same host.
- DeviceProcessEvents to confirm execution of the dropped file and identify any child processes it spawned.
- DeviceNetworkEvents for outbound connections from the dropped file or its descendants.
- DeviceRegistryEvents if persistence or configuration changes are suspected after the drop.

**Benign explanations:**
- IT used ScreenConnect to push a legitimate installer or script into Temp or AppData as part of remote support.
- A software deployment tool or maintenance script created a temporary executable or batch file before running it.
- The dropped file is a known vendor installer or update component with a matching SHA256 in internal allowlists.

**Escalation criteria:**
- The dropped file is unknown, unsigned, or has a malicious reputation and was executed shortly after creation.
- The file name, path, or hash matches known AsyncRAT or other malware staging patterns.
- The same host shows follow-on suspicious processes, persistence, or outbound connections after the file drop.
- The ScreenConnect session is unauthorized or the operator identity cannot be validated.

**Containment actions:**
- If the file is suspicious and executed, isolate the host to prevent further payload activity.
- Quarantine or delete the dropped file only after preserving the hash and collecting evidence.
- Block the SHA256 in endpoint controls if it is confirmed malicious.
- Suspend the remote support session and disable the account if the session is not legitimate.

**Closure criteria:**
- The dropped file is verified as a legitimate installer or script used in an approved support action.
- The SHA256 is known-good and no malicious follow-on execution occurred.
- No additional suspicious file drops, persistence, or network activity are present on the host.
- The event is documented with the supporting ticket or change record and any necessary allowlist updates.

---

## Detection 3: Outbound Network Connection from ScreenConnect Child Process - Potential AsyncRAT C2 Beaconing

### Detection Opportunity

Outbound network connections initiated by processes spawned from ScreenConnect, consistent with AsyncRAT C2 beaconing following delivery via compromised ScreenConnect software.

### Intelligence Context

- Securelist: The SOC Files: ScreenConnect masked as freeware. An inside look at a large-scale campaign — [https://securelist.com/tr/the-soc-files-screenconnect-campaign-with-asyncrat/120472/](https://securelist.com/tr/the-soc-files-screenconnect-campaign-with-asyncrat/120472/)
  - Context: The campaign involved AsyncRAT establishing C2 communications after being dropped via compromised ScreenConnect. Outbound connections from processes in the ScreenConnect execution chain to external infrastructure represent the post-compromise C2 phase analyzed in the reporting.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.004, T1059.001
- Products: ScreenConnect
- Platforms: Windows
- Malware: AsyncRAT
- Tools: Not specified
- Search tags: ScreenConnect, Windows, AsyncRAT, T1059, T1059.004, T1059.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Scripting Interpreter: T1059 Command and Scripting Interpreter (low); Command and Scripting Interpreter: T1059 Command and Scripting Interpreter/ 004 Unix Shell (low); Command and Scripting Interpreter: T1059 Command and Scripting Interpreter/ 001 PowerShell (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let ScreenConnectChildren = DeviceProcessEvents
| where Timestamp > ago(7d)
| where tolower(InitiatingProcessFileName) in (
    "screenconnect.clientservice.exe",
    "screenconnect.windowsclient.exe",
    "screenconnect.windowsbackstageshell.exe",
    "screenconnect.windowsinteractiveclient.exe"
  )
| project
    SpawnTime = Timestamp,
    DeviceName,
    ChildProcess = tolower(FileName),
    SpawnCommandLine = ProcessCommandLine;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| where not(ipv4_is_private(RemoteIP))
| where RemotePort !in (80, 443)
| extend NormalizedInitiatingProcess = tolower(InitiatingProcessFileName)
| join kind=inner ScreenConnectChildren
    on DeviceName, $left.NormalizedInitiatingProcess == $right.ChildProcess
| where Timestamp between (SpawnTime .. (SpawnTime + 30m))
| project
    Timestamp,
    SpawnTime,
    DeviceName,
    AccountName,
    ChildProcess,
    SpawnCommandLine,
    InitiatingProcessFileName,
    NetworkCommandLine = InitiatingProcessCommandLine,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    LocalIP,
    LocalPort
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate outbound connections from powershell.exe or cmd.exe spawned by ScreenConnect during IT admin remote sessions to cloud endpoints or update servers.
- Software update checks initiated by binaries deployed via ScreenConnect remote management.

**Tuning notes:**
- Remove the RemotePort exclusion of 80 and 443 if the environment has SSL inspection and HTTPS-based C2 is a concern.
- Extend the join to a second hop by joining ScreenConnectChildren against DeviceProcessEvents again to capture grandchild processes before joining to DeviceNetworkEvents, at the cost of increased query complexity and scan time.
- Add AccountName exclusions for known IT admin accounts that use ScreenConnect for legitimate remote management with outbound connectivity.
- Adjust the 30-minute window based on observed AsyncRAT beaconing timing in threat intelligence or historical incident data.

**Risks / caveats:**
- DeviceNetworkEvents requires MDE P1/P2 licensing with network telemetry enabled; ConnectionSuccess ActionType availability depends on MDE sensor version and configuration.
- ipv4_is_private() is a built-in KQL function available in Defender XDR advanced hunting; confirm the workspace supports this function if the query is ported to Microsoft Sentinel.
- Single-hop lineage only: if ScreenConnect spawns cmd.exe which then spawns payload.exe, the network connection from payload.exe will not be captured because InitiatingProcessFileName in DeviceNetworkEvents will be cmd.exe, not a ScreenConnect binary.
- The 30-minute spawn-to-connection window may miss delayed C2 check-ins; adjust based on observed AsyncRAT beaconing intervals.

### Triage Runbook

**First 15 minutes:**
- Confirm whether the DeviceName and AccountName belong to a legitimate remote support session or an unexpected user context.
- Review RemoteIP, RemotePort, and RemoteUrl to determine whether the destination is expected business infrastructure or suspicious external hosting.
- Inspect the child process command line and parent lineage to see whether the network connection came from a script, shell, or payload process.
- Check whether the connection timing aligns with a recent ScreenConnect session, file drop, or suspicious process launch on the same host.

**Evidence to collect:**
- Timestamp, SpawnTime, DeviceName, AccountName, ChildProcess, SpawnCommandLine, InitiatingProcessFileName, NetworkCommandLine, RemoteIP, RemotePort, RemoteUrl, LocalIP, and LocalPort.
- Any threat intelligence or reputation data for the RemoteIP and RemoteUrl.
- Process lineage showing the ScreenConnect parent, any intermediate shell, and the network-making process.
- Any related file creation or registry changes on the host around the same time.

**Pivot points:**
- DeviceProcessEvents to expand the process tree before and after the network event.
- DeviceNetworkEvents to identify repeated connections, beaconing patterns, or additional remote destinations from the same host.
- DeviceFileEvents for payload drops that preceded the connection.
- DeviceLogonEvents or ScreenConnect audit logs to validate the remote operator and session context.

**Benign explanations:**
- Authorized IT support used ScreenConnect to run a script or tool that legitimately reached out to a vendor update server or cloud service.
- A software installer or updater launched through ScreenConnect made a normal external connection.
- The destination is a known corporate SaaS, patching, or telemetry endpoint used by approved admin tooling.

**Escalation criteria:**
- The destination is unknown, newly registered, low reputation, or inconsistent with business use.
- The process command line indicates encoded PowerShell, download-and-execute behavior, or other malware-like activity.
- Multiple repeated connections suggest beaconing rather than a one-time admin action.
- The host also shows suspicious file drops, persistence, or additional child processes after the connection.

**Containment actions:**
- If the connection is to suspicious infrastructure and the host is not clearly authorized, isolate the endpoint.
- Block the remote IP or domain at network controls if confirmed malicious and approved by incident response.
- Terminate the suspicious process chain if containment is required and evidence has been preserved.
- Disable the involved account or revoke remote support access if compromise is suspected.

**Closure criteria:**
- The outbound connection is tied to a documented and approved ScreenConnect support activity.
- The destination is verified as legitimate business infrastructure or a known vendor service.
- No repeated beaconing, suspicious process behavior, or additional compromise indicators are found.
- Any required allowlist or monitoring updates have been completed and recorded.

---

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Licensing / identity risk fields:**
- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Schema / correlation keys:**
- Executable File Written by ScreenConnect Process to Staging Directories - Potential AsyncRAT Drop: Do not schedule yet; validate as an analyst-led hunt first.
- Outbound Network Connection from ScreenConnect Child Process - Potential AsyncRAT C2 Beaconing: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- DeviceProcessEvents: shared by ScreenConnect Spawning Suspicious Child Processes - Potential AsyncRAT Delivery; Executable File Written by ScreenConnect Process to Staging Directories - Potential AsyncRAT Drop; Outbound Network Connection from ScreenConnect Child Process - Potential AsyncRAT C2 Beaconing

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: ScreenConnect Spawning Suspicious Child Processes - Potential AsyncRAT Delivery.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Executable File Written by ScreenConnect Process to Staging Directories - Potential AsyncRAT Drop; Outbound Network Connection from ScreenConnect Child Process - Potential AsyncRAT C2 Beaconing.

### Hunting Agenda and Promotion Criteria

- Executable File Written by ScreenConnect Process to Staging Directories - Potential AsyncRAT Drop: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- Outbound Network Connection from ScreenConnect Child Process - Potential AsyncRAT C2 Beaconing: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
