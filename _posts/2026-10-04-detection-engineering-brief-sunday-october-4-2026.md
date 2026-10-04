---
layout: post
title: "Detection Engineering Brief - Sunday, October 4, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-10-04
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - T1059
  - Linux
  - BPFDoor
  - AVERAT
  - ScreenConnect
  - Windows
  - T1059.004
  - T1036
---

## Detection Engineering Summary

This brief produced 4 detection candidates.

2 production candidates, 2 hunting-only, 0 require environment mapping, and 0 rejected.

4 detections include KQL. 3 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: T1059, Linux, BPFDoor, AVERAT, ScreenConnect, Windows, T1059.004, T1036.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: BPFDoor - Shell Script Written and Executed by Non-Interactive Dropper Process; ScreenConnect Client Execution on Host Without Prior Installation Record.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: BPFDoor - Payload Staged in /sbin as ntpdate or udevds

### Detection Opportunity

Dropper stages malicious binaries in /sbin using the filenames ntpdate and udevds to masquerade as legitimate system utilities.

### Intelligence Context

- Rapid7: SMTP is the key: BPFDoor and AVERAT hitting the network edge — [https://www.rapid7.com/blog/post/tr-smtp-is-the-key-bpfdoor-averat-hitting-the-network-edge](https://www.rapid7.com/blog/post/tr-smtp-is-the-key-bpfdoor-averat-hitting-the-network-edge)
  - Context: A dropper shell script stages two payloads into /sbin under the names ntpdate and udevds. These filenames mimic legitimate Linux system binaries to evade detection. The binaries are then executed and the files deleted within ten seconds while processes remain running.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.004, T1036
- Products: Not specified
- Platforms: Linux
- Malware: BPFDoor, AVERAT
- Tools: Not specified
- Search tags: T1059, Linux, BPFDoor, AVERAT, T1059.004, T1036

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.004 Unix Shell (high); Defense Evasion: T1036 Masquerading (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath == "/sbin" or FolderPath startswith "/sbin/"
| where FileName in~ ("ntpdate", "udevds")
| where InitiatingProcessFileName !in~ ("apt", "apt-get", "yum", "rpm", "dpkg", "dnf", "zypper", "install", "update-alternatives")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, SHA256, ReportId
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Manual sysadmin installation of ntp packages outside a package manager on non-standard distributions.
- Custom provisioning scripts that copy binaries into /sbin using non-package-manager parent processes.

**Tuning notes:**
- Expand InitiatingProcessFileName exclusion list to include any custom provisioning or configuration management tools present in the environment (e.g., ansible, puppet, chef).
- Scope DeviceName to edge appliance hostname patterns if ScreenConnect or BPFDoor targeting is confirmed to specific host classes.

**Risks / caveats:**
- DeviceFileEvents /sbin path coverage depends on Linux MDE agent version and onboarding configuration; file creation telemetry for /sbin may not be collected on all agent versions.
- Environments where ntpdate is legitimately installed via non-package-manager scripts will generate false positives until those initiating process names are added to the exclusion list.
- If the MDE Linux agent does not collect FileCreated events for /sbin on a given kernel version, the rule will produce no results silently.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a Linux appliance or server where /sbin writes are unusual; note the exact timestamp, filename, and initiating process.
- Review the initiating process command line and account to determine whether this was a package manager, provisioning tool, or an unexpected non-interactive dropper.
- Check whether the file hash is known, whether the same hash appears on other hosts, and whether the file was created on an edge-facing system.
- Look for immediate follow-on activity on the same host: process execution of ntpdate or udevds, file deletion, or other suspicious shell activity.

**Evidence to collect:**
- Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, SHA256, ReportId.
- Any DeviceProcessEvents for ntpdate or udevds on the same host around the alert time.
- Any DeviceFileEvents showing deletion or modification of the same file shortly after creation.
- Host role and ownership context from CMDB or asset inventory to determine whether /sbin writes are expected.

**Pivot points:**
- DeviceFileEvents for the same DeviceName and SHA256 to find other file creations or deletions involving the same hash.
- DeviceProcessEvents for FileName in ntpdate or udevds on the same DeviceName within a short window around the alert.
- DeviceFileEvents and DeviceProcessEvents for the initiating process name and command line to identify the parent dropper chain.
- If available, pivot to other hosts with the same SHA256 or same initiating process account to identify spread.

**Benign explanations:**
- A sysadmin manually installed ntpdate outside a package manager on a non-standard Linux distribution.
- A legitimate provisioning or configuration script copied a utility into /sbin using a custom installer.
- A maintenance workflow on an appliance temporarily staged a binary in /sbin before cleanup.

**Escalation criteria:**
- The initiating process is not a known package manager, provisioning tool, or approved automation account.
- The file is executed or deleted shortly after creation, especially if the host is an internet-facing appliance or edge device.
- The same filename, hash, or initiating process appears on multiple hosts, or the host shows additional suspicious shell activity.
- The account or parent process is unexpected for software installation on that system.

**Containment actions:**
- If the host is confirmed suspicious, isolate the endpoint from the network using your EDR containment workflow.
- Preserve the staged file hash and any related process artifacts before remediation if the file still exists.
- Block or suspend the initiating account if it is not a legitimate automation or admin account and compromise is likely.

**Closure criteria:**
- The file creation is attributed to a known and approved package manager, provisioning tool, or maintenance workflow.
- The host owner confirms the activity and the file hash/path match an expected software installation or upgrade.
- No execution, deletion, or other malicious follow-on activity is observed, and the event is consistent with documented baseline behavior.

<br/>
---
<br/>

## Detection 2: BPFDoor - Execute-Then-Delete: Binary Launched from /sbin and Deleted Within 30 Seconds

### Detection Opportunity

Staged malicious binaries in /sbin are executed and then deleted within approximately ten seconds while the processes continue running in memory, a classic fileless evasion technique.

### Intelligence Context

- Rapid7: SMTP is the key: BPFDoor and AVERAT hitting the network edge — [https://www.rapid7.com/blog/post/tr-smtp-is-the-key-bpfdoor-averat-hitting-the-network-edge](https://www.rapid7.com/blog/post/tr-smtp-is-the-key-bpfdoor-averat-hitting-the-network-edge)
  - Context: After staging ntpdate and udevds in /sbin, the dropper launches both binaries and deletes each file ten seconds later. The processes continue running after file deletion, leaving no on-disk artifact. This execute-then-delete pattern is a strong evasion signal specific to this BPFDoor/AVERAT deployment chain.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.004, T1036
- Products: Not specified
- Platforms: Linux
- Malware: BPFDoor, AVERAT
- Tools: Not specified
- Search tags: T1059, Linux, BPFDoor, AVERAT, T1059.004, T1036

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.004 Unix Shell (high); Defense Evasion: T1036 Masquerading (low)

### Deployment Gates

- DeviceProcessEvents FolderPath field on Linux reflects the binary's on-disk path at launch time; if the field is not populated for Linux processes on the deployed agent version, the process-side filter will return no rows.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let ProcessLaunches = DeviceProcessEvents
| where FolderPath == "/sbin" or FolderPath startswith "/sbin/"
| where FileName in~ ("ntpdate", "udevds")
| project LaunchTime = Timestamp, DeviceName, FileName, FolderPath, ProcessId, ProcessCommandLine, AccountName, SHA256;
let FileDeletions = DeviceFileEvents
| where ActionType == "FileDeleted"
| where FolderPath == "/sbin" or FolderPath startswith "/sbin/"
| where FileName in~ ("ntpdate", "udevds")
| project DeleteTime = Timestamp, DeviceName, FileName, FolderPath;
ProcessLaunches
| join kind=inner FileDeletions on DeviceName, FileName, FolderPath
| where DeleteTime > LaunchTime and DeleteTime <= LaunchTime + 30s
| extend TimeDeltaSeconds = datetime_diff('second', DeleteTime, LaunchTime)
| project LaunchTime, DeleteTime, TimeDeltaSeconds, DeviceName, FileName, FolderPath, ProcessId, ProcessCommandLine, AccountName, SHA256
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Automated system update scripts that install, run, and clean up binaries in /sbin within a short window.
- Custom appliance provisioning that stages and removes temporary binaries.

**Tuning notes:**
- Tighten the correlation window to 15s if telemetry latency is confirmed low and false positives from provisioning scripts emerge.
- Extend the FileName list if additional masquerading filenames are identified in future threat reporting.

**Risks / caveats:**
- DeviceProcessEvents FolderPath field on Linux reflects the binary's on-disk path at launch time; if the field is not populated for Linux processes on the deployed agent version, the process-side filter will return no rows.
- DeviceFileEvents FileDeleted ActionType availability on Linux depends on MDE agent version and kernel audit configuration.
- Telemetry ingestion latency between DeviceProcessEvents and DeviceFileEvents could cause the 30-second window to miss events if one stream is delayed; consider widening to 60s if misses are observed.
- If the MDE Linux agent does not emit FileDeleted events for /sbin on a given kernel, the deletion side of the join will always be empty and the rule will produce no results.

### Triage Runbook

**First 15 minutes:**
- Verify the launch and deletion timestamps, the process ID, and whether the same filename and folder path match on both process and file telemetry.
- Inspect the process command line and account to determine whether the execution came from an expected installer or from a suspicious non-interactive parent.
- Check whether the binary hash is present on other hosts or whether the same host has additional suspicious shell or network activity.
- Assess whether the host is an appliance or edge system where rapid execute-and-delete behavior would be unusual.

**Evidence to collect:**
- LaunchTime, DeleteTime, TimeDeltaSeconds, DeviceName, FileName, FolderPath, ProcessId, ProcessCommandLine, AccountName, SHA256.
- Related DeviceProcessEvents for the same ProcessId and parent process chain.
- Related DeviceFileEvents for the same filename and folder path to confirm deletion and any prior creation events.
- Any network or authentication activity from the host during the same window that could indicate active compromise.

**Pivot points:**
- DeviceProcessEvents filtered to the same DeviceName, FileName, and ProcessId to reconstruct the execution chain.
- DeviceFileEvents filtered to the same DeviceName and FileName to find creation, deletion, or repeated staging attempts.
- DeviceNetworkEvents for the same DeviceName and time window to identify outbound connections after execution.
- Search for the same SHA256 across all hosts to determine whether the payload is localized or widespread.

**Benign explanations:**
- An automated update or provisioning script staged a temporary binary, executed it, and cleaned it up quickly.
- A legitimate appliance maintenance workflow used temporary files in /sbin during an upgrade.
- A custom installer or configuration management tool performed short-lived execution with cleanup.

**Escalation criteria:**
- The process tree is not attributable to a known installer, package manager, or approved automation account.
- The binary is executed from /sbin and deleted within seconds on an internet-facing or high-value Linux host.
- The same behavior is observed on multiple hosts or is accompanied by suspicious network connections or shell activity.
- The file hash or parent process is associated with other suspicious events in the environment.

**Containment actions:**
- Isolate the host if the execution chain cannot be explained by approved maintenance or deployment activity.
- Preserve volatile evidence, including process lineage, command line, and any remaining file artifacts, before reboot or cleanup.
- Suspend or disable the initiating account if it is not a trusted automation identity and compromise is likely.

**Closure criteria:**
- The execution and deletion are confirmed as part of a documented maintenance or deployment workflow.
- The process lineage matches an approved installer or automation tool and no other suspicious activity is present.
- No additional hosts or hashes are implicated after pivoting.

<br/>
---
<br/>

## Detection 3: BPFDoor - Shell Script Written and Executed by Non-Interactive Dropper Process

### Detection Opportunity

A dropper binary writes a shell script to appliance storage and immediately executes it as part of the BPFDoor/AVERAT deployment chain.

### Intelligence Context

- Rapid7: SMTP is the key: BPFDoor and AVERAT hitting the network edge — [https://www.rapid7.com/blog/post/tr-smtp-is-the-key-bpfdoor-averat-hitting-the-network-edge](https://www.rapid7.com/blog/post/tr-smtp-is-the-key-bpfdoor-averat-hitting-the-network-edge)
  - Context: The BPFDoor/AVERAT infection chain begins with a dropper binary that writes a shell script to the appliance storage mount and executes it. The shell script then stages the final payloads. Detecting the write-then-execute pattern of a shell script by a non-shell parent process is the earliest observable signal in the chain.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.004, T1036
- Products: Not specified
- Platforms: Linux
- Malware: BPFDoor, AVERAT
- Tools: Not specified
- Search tags: T1059, Linux, BPFDoor, AVERAT, T1059.004, T1036

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.004 Unix Shell (high); Defense Evasion: T1036 Masquerading (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let ShellInterpreters = dynamic(["sh", "bash", "dash", "zsh", "ksh", "fish"]);
let ScriptWrites = DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith ".sh"
| where InitiatingProcessFileName !in~ (ShellInterpreters)
| project WriteTime = Timestamp, DeviceName, ScriptPath = FolderPath, ScriptName = FileName, WriterProcess = InitiatingProcessFileName, WriterCommandLine = InitiatingProcessCommandLine, AccountName;
let ShellExecs = DeviceProcessEvents
| where FileName in~ (ShellInterpreters)
| where ProcessCommandLine has ".sh"
| extend NormalizedScriptRef = extract(@"([^\s]+\.sh)", 1, ProcessCommandLine)
| project ExecTime = Timestamp, DeviceName, ProcessCommandLine, NormalizedScriptRef, ExecAccountName = AccountName;
ScriptWrites
| join kind=inner ShellExecs on DeviceName
| where ExecTime > WriteTime and ExecTime <= WriteTime + 60s
| where NormalizedScriptRef has ScriptName or NormalizedScriptRef has ScriptPath
| extend TimeDeltaSeconds = datetime_diff('second', ExecTime, WriteTime)
| project WriteTime, ExecTime, TimeDeltaSeconds, DeviceName, ScriptName, ScriptPath, WriterProcess, WriterCommandLine, ProcessCommandLine, AccountName, ExecAccountName
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Ansible, Puppet, Chef, and similar configuration management agents that write and execute shell scripts as part of normal operations.
- CI/CD pipeline agents running on Linux endpoints.
- Cron-triggered scripts that happen to be written and executed within the correlation window.
- Any non-shell binary that writes a .sh file as part of legitimate software installation.

**Tuning notes:**
- Restrict ScriptPath to specific mount points or directories associated with appliance storage (e.g., /mnt, /opt, /tmp) to reduce noise from general-purpose hosts.
- Add WriterProcess exclusions for known automation agents present in the environment before promoting to scheduled rule.
- Tighten the 60-second window after baselining typical write-to-execute latency for legitimate tools in the environment.

**Risks / caveats:**
- DeviceFileEvents .sh file creation coverage on Linux depends on MDE agent version; not all file types or paths are guaranteed to be captured.
- The path-level correlation using extract and has is heuristic; if the dropper writes the script to a path not referenced by name in the shell command line, the join will not match.
- Legitimate automation tools will generate significant volume on general-purpose Linux hosts; this query is most useful when scoped to specific appliance host groups.
- If the dropper does not use a .sh extension for the staged script, this detection will not fire.

### Triage Runbook

**First 15 minutes:**
- Review the writer process, writer command line, and account to determine whether the script creation came from a legitimate automation tool or an unexpected binary.
- Confirm the script path, script name, and execution command line to see whether the same script was immediately invoked.
- Check whether the host is a Linux appliance or server where script write-and-execute behavior is unusual.
- Look for additional shell activity, file staging, or network connections around the same time.

**Evidence to collect:**
- WriteTime, ExecTime, TimeDeltaSeconds, DeviceName, ScriptName, ScriptPath, WriterProcess, WriterCommandLine, ProcessCommandLine, AccountName, ExecAccountName.
- The full process tree for the writer process and the shell interpreter that executed the script.
- Any related DeviceFileEvents showing the script contents, renames, or deletions.
- Any DeviceNetworkEvents from the same host during the same interval.

**Pivot points:**
- DeviceProcessEvents for the writer process and shell interpreter on the same DeviceName and time window.
- DeviceFileEvents for the same ScriptPath or ScriptName to identify repeated writes or cleanup.
- DeviceNetworkEvents for the same DeviceName to identify outbound connections after script execution.
- Search for the same WriterProcess or AccountName across hosts to determine whether this is a broader automation pattern.

**Benign explanations:**
- Ansible, Puppet, Chef, or another configuration management tool wrote and executed a shell script.
- A CI/CD or deployment agent performed a scripted installation on a Linux host.
- A cron-driven maintenance job generated and ran a temporary shell script.
- A legitimate installer or updater used a shell wrapper to complete setup.

**Escalation criteria:**
- The writer process is not a known automation agent, installer, or shell-based deployment tool.
- The script path is in an unusual location for the host, or the script is executed almost immediately after being written.
- The host is an edge appliance or internet-facing system and the behavior is not part of a documented change.
- The same pattern appears on multiple hosts or is followed by suspicious network activity.

**Containment actions:**
- Isolate the host if the script write-and-execute chain is unexplained or tied to an unapproved process.
- Preserve the script file and process artifacts before cleanup if possible.
- Disable the initiating account or automation token if it is not expected and compromise is suspected.

**Closure criteria:**
- The activity is confirmed as approved automation, deployment, or maintenance with matching change records.
- The writer process and script path align with known baseline behavior for the host group.
- No additional suspicious processes, files, or network connections are found after pivoting.

<br/>
---
<br/>

## Detection 4: ScreenConnect Client Execution on Host Without Prior Installation Record

### Detection Opportunity

Attackers abuse the ScreenConnect remote access client on endpoints where it was not previously installed, using it as a living-off-the-land remote access mechanism to avoid deploying custom malware.

### Intelligence Context

- SANS ISC: ScreenConnect Client (Ab)used by Attackers, (Thu, Oct 1st) — [https://isc.sans.edu/diary/rss/33388](https://isc.sans.edu/diary/rss/33388)
  - Context: Threat actors abused the ScreenConnect remote access client on Windows endpoints rather than deploying custom malware. The reporting highlights that attackers leverage existing or newly installed legitimate applications to maintain access, making process-name-only detection insufficient without installation context.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: Not specified
- Products: ScreenConnect
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: ScreenConnect, Windows

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Not mapped

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let ScreenConnectProcs = DeviceProcessEvents
| where FileName has_any ("ScreenConnect", "screenconnect", "ConnectWise")
    or ProcessCommandLine has_any ("ScreenConnect", "screenconnect", "ConnectWise")
| summarize
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    ExecutionCount = count(),
    SHA256Values = make_set(SHA256),
    CommandLines = make_set(ProcessCommandLine)
    by DeviceName, FileName, AccountName, AccountDomain, InitiatingProcessFileName;
let ScreenConnectNet = DeviceNetworkEvents
| where InitiatingProcessFileName has_any ("ScreenConnect", "screenconnect", "ConnectWise")
| summarize
    RemoteIPs = make_set(RemoteIP),
    RemotePorts = make_set(RemotePort),
    RemoteUrls = make_set(RemoteUrl)
    by DeviceName;
ScreenConnectProcs
| join kind=leftouter ScreenConnectNet on DeviceName
| project
    FirstSeen,
    LastSeen,
    ExecutionCount,
    DeviceName,
    FileName,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    SHA256Values,
    CommandLines,
    RemoteIPs,
    RemotePorts,
    RemoteUrls
| order by FirstSeen desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- IT helpdesk staff legitimately deploying ScreenConnect on endpoints for remote support.
- Managed service providers using ScreenConnect as their standard remote access tool.
- Endpoints where ScreenConnect was installed before MDE onboarding and therefore has no installation event in telemetry.

**Tuning notes:**
- Add AccountName exclusions for IT administrator and MSP service accounts known to legitimately use ScreenConnect.
- Restrict DeviceName to organizational units or device groups where ScreenConnect is not an approved tool to reduce volume.
- Compare SHA256Values against the vendor-published ScreenConnect installer hash list to distinguish legitimate installs from trojanized variants.
- Add RemoteIP exclusions for known ConnectWise relay infrastructure if the goal is to surface only attacker-controlled relay connections.

**Risks / caveats:**
- DeviceNetworkEvents RemoteUrl field availability varies by MDE agent version and network inspection configuration; it may be empty for some connections.
- ScreenConnect variants installed with randomized or rebranded executable names will not be matched by the has_any string filter on FileName or ProcessCommandLine.
- Without a native approved-host inventory in Defender XDR, the query cannot programmatically flag unauthorized instances; analyst cross-referencing against an external list is mandatory.
- ScreenConnect instances installed with rebranded or randomized executable names will evade the string-based filter entirely.

### Triage Runbook

**First 15 minutes:**
- Identify the host, user, process command line, and initiating process that launched ScreenConnect, and compare them to approved support workflows.
- Check whether the device is on an approved ScreenConnect host list or managed by an IT/MSP team that legitimately uses the tool.
- Review the remote IPs, ports, and URLs to determine whether the client connected to expected relay infrastructure or an unknown endpoint.
- Look for signs of interactive use, privilege escalation, or follow-on activity from the same account and host.

**Evidence to collect:**
- FirstSeen, LastSeen, ExecutionCount, DeviceName, FileName, ProcessCommandLine, AccountName, AccountDomain, InitiatingProcessFileName, SHA256Values, RemoteIPs, RemotePorts, RemoteUrls.
- The full DeviceProcessEvents lineage for the ScreenConnect execution.
- DeviceNetworkEvents for the same host and time window to capture all remote connections and relay destinations.
- External approval or CMDB records showing whether ScreenConnect is authorized on the host.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName, FileName, and SHA256 to identify repeated executions or alternate launchers.
- DeviceNetworkEvents for the same DeviceName to identify other remote access tools or suspicious outbound connections.
- Search for the same SHA256 or command line across the environment to find other hosts running the client.
- Compare the host against an external approved-host or support-team inventory before deciding on escalation.

**Benign explanations:**
- IT helpdesk or an MSP legitimately installed ScreenConnect for remote support.
- The host had ScreenConnect installed before MDE onboarding, so no installation event exists in telemetry.
- A sanctioned support session used a known relay and approved administrative account.

**Escalation criteria:**
- The host is not on an approved ScreenConnect list and the execution is not tied to a documented support request.
- The remote IPs, URLs, or command line do not match known ScreenConnect infrastructure or standard deployment patterns.
- The client was launched by an unexpected user, service, or parent process, especially on a server or high-value endpoint.
- There is evidence of persistence, repeated execution, or additional suspicious remote access activity.

**Containment actions:**
- If unauthorized use is likely, isolate the host to stop remote access and prevent lateral movement.
- Terminate the ScreenConnect process if it is confirmed unauthorized and you have approval to do so.
- Disable the account used to launch or operate the client if it is not a legitimate support identity.

**Closure criteria:**
- The host is confirmed as approved for ScreenConnect and the execution matches a documented support or MSP workflow.
- Remote infrastructure matches known vendor relay endpoints and no suspicious follow-on activity is present.
- The SHA256 and command line align with a sanctioned installation and the host owner validates the activity.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Environment scope / baselines:**
- BPFDoor - Execute-Then-Delete: Binary Launched from /sbin and Deleted Within 30 Seconds: DeviceProcessEvents FolderPath field on Linux reflects the binary's on-disk path at launch time; if the field is not populated for Linux processes on the deployed agent version, the process-side filter will return no rows.

**Schema / correlation keys:**
- BPFDoor - Shell Script Written and Executed by Non-Interactive Dropper Process: Do not schedule yet; validate as an analyst-led hunt first.
- ScreenConnect Client Execution on Host Without Prior Installation Record: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- DeviceFileEvents: shared by BPFDoor - Payload Staged in /sbin as ntpdate or udevds; BPFDoor - Execute-Then-Delete: Binary Launched from /sbin and Deleted Within 30 Seconds; BPFDoor - Shell Script Written and Executed by Non-Interactive Dropper Process
- DeviceProcessEvents: shared by BPFDoor - Execute-Then-Delete: Binary Launched from /sbin and Deleted Within 30 Seconds; BPFDoor - Shell Script Written and Executed by Non-Interactive Dropper Process; ScreenConnect Client Execution on Host Without Prior Installation Record

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: BPFDoor - Payload Staged in /sbin as ntpdate or udevds; BPFDoor - Execute-Then-Delete: Binary Launched from /sbin and Deleted Within 30 Seconds.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: BPFDoor - Shell Script Written and Executed by Non-Interactive Dropper Process; ScreenConnect Client Execution on Host Without Prior Installation Record.

### Hunting Agenda and Promotion Criteria

- BPFDoor - Shell Script Written and Executed by Non-Interactive Dropper Process: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- ScreenConnect Client Execution on Host Without Prior Installation Record: Do not schedule yet; validate as an analyst-led hunt first..

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
