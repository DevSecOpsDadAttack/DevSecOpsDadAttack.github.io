---
layout: post
title: "Detection Engineering Brief - Monday, June 8, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-08
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - T1190
  - T1059
  - Apache ActiveMQ
  - Windows
  - Linux
  - Metasploit
  - Gogs
---

## Executive Signal

This brief produced 3 detection candidates.

2 production candidates, 0 hunting-only, 1 require environment mapping, and 0 rejected.

3 detections include KQL. 0 include ATT&CK mappings. 3 include triage guidance.

Search metadata extracted for this run includes: T1190, T1059, Apache ActiveMQ, Windows, Linux, Metasploit, Gogs.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Unsigned Process Invoking NtQuerySystemInformation for Kernel Pointer Enumeration.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: Apache ActiveMQ Child Process Spawned via Jolokia RCE

### Detection Opportunity

Apache ActiveMQ spawning unexpected child processes following Jolokia addNetworkConnector API abuse

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Apache ActiveMQ RCE, Gogs Rebase RCE, and Windows Kernel Pointer Enum — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-05-06-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-05-06-2026)
  - Context: A Metasploit module exploits the Jolokia addNetworkConnector endpoint in Apache ActiveMQ to achieve remote code execution. The exploit causes ActiveMQ to spawn child processes, which is the primary detectable signal.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Apache ActiveMQ
- Platforms: Windows, Linux
- Malware: Not specified
- Tools: Metasploit
- Search tags: T1190, T1059, Apache ActiveMQ, Windows, Linux, Metasploit

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: T1190, T1059

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessCommandLine has_any ("activemq", "activemq.jar")
    or InitiatingProcessFileName =~ "activemq"
| where FileName in~ (
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "sh", "bash", "dash", "zsh", "ksh",
    "python", "python3", "perl", "ruby",
    "wget", "curl",
    "nc", "ncat", "netcat",
    "whoami", "id", "ifconfig", "ip"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessId,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ProcessId,
    FileName,
    FolderPath,
    ProcessCommandLine
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate administrative scripts that invoke shell commands from within an ActiveMQ management context.
- Monitoring or health-check agents that run as child processes of the ActiveMQ JVM.
- Developer workstations where ActiveMQ is run locally alongside shell tooling.

Tuning notes:
- Scope DeviceName to known ActiveMQ server hostnames or a watchlist of server assets to eliminate developer workstation noise.
- Baseline legitimate child processes from ActiveMQ in the environment and add confirmed benign process names to an exclusion filter on FileName.
- Consider promoting to a scheduled rule with a 1-hour lookback once FP baseline is established.

Risks / caveats:
- MDE agent must be deployed on hosts running Apache ActiveMQ for DeviceProcessEvents to contain relevant telemetry. If ActiveMQ hosts are not onboarded to MDE, the query will return no results for those hosts.
- The 7-day lookback window may miss activity in environments with high event volume if ingestion lag is present; adjust to match hunting cadence.
- On Linux, shell binary names without full paths (e.g., 'sh', 'bash') may match developer workstations if ActiveMQ is run locally; scope DeviceName to known server assets to reduce noise.
- ActiveMQ deployments that wrap the JVM in a custom launcher script may not surface 'activemq' in InitiatingProcessCommandLine; validate against actual process telemetry from ActiveMQ hosts.

### Triage Runbook

First 15 minutes:
- Confirm the host is a known Apache ActiveMQ server and identify whether the alert time aligns with any planned maintenance or admin activity.
- Review the child process name, command line, parent command line, and account context to see if the spawned process is a shell, downloader, or discovery command.
- Check whether the parent process is the ActiveMQ JVM or wrapper script and whether the parent command line includes activemq or activemq.jar.
- Look for multiple child processes, repeated spawning, or a sequence consistent with post-exploitation activity such as whoami, id, ip, ifconfig, curl, wget, sh, bash, cmd.exe, or powershell.exe.
- If the child process is clearly suspicious and not tied to approved administration, treat as probable compromise and begin incident handling.

Evidence to collect:
- Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, FileName, ProcessCommandLine, ProcessId, and FolderPath for the alerting event.
- Process ancestry for the child process and any sibling processes spawned by the ActiveMQ JVM around the same time.
- Any related network activity from the ActiveMQ host during the alert window, especially outbound connections following the child process spawn.
- Host inventory details showing whether the system is a production ActiveMQ server, test instance, or developer workstation.
- Any change-management, patching, or administrative ticket that explains the process execution.

Pivot points:
- DeviceProcessEvents for the same DeviceName and InitiatingProcessId to find additional child processes and process ancestry.
- DeviceNetworkEvents for the same DeviceName and time window to identify outbound connections after the spawn.
- DeviceFileEvents for dropped files, scripts, or archives created near the alert time.
- DeviceLogonEvents to identify whether an interactive or remote admin session preceded the activity.

Benign explanations:
- A legitimate administrator may have used ActiveMQ management functions that launched a shell or helper script.
- Monitoring or health-check tooling may run as a child of the ActiveMQ service and appear unusual if not previously baselined.
- A local developer or test environment may run ActiveMQ alongside shell tooling and generate expected child processes.

Escalation criteria:
- The child process is a shell, downloader, or discovery tool and there is no approved maintenance activity to explain it.
- Multiple suspicious child processes or follow-on network connections indicate interactive post-exploitation behavior.
- The host is a production ActiveMQ server and the process lineage suggests execution from the JVM rather than a known admin tool.
- Evidence of file creation, credential access, or lateral movement appears in the same time window.

Containment actions:
- If compromise is likely, isolate the ActiveMQ host from the network using your endpoint containment workflow.
- Preserve volatile evidence before rebooting or killing processes, including process tree, command lines, and active network connections.
- Disable or rotate any credentials used on the host if they may have been exposed during the activity.
- Block external access to the Jolokia/management interface until the exposure path is understood and remediated.

Closure criteria:
- The process is confirmed as authorized administration or approved monitoring activity with supporting change evidence.
- No additional suspicious child processes, network activity, or file modifications are found during the alert window.
- The host is not a production ActiveMQ server and the activity is consistent with a known lab or developer workflow.
- A benign baseline is established for the specific child process and parent command line combination.

---

## Detection 2: Gogs Git Rebase with --exec Argument Spawning Commands

### Detection Opportunity

Git rebase operation containing '--exec' argument triggered by a maliciously named branch on a Gogs server, resulting in command execution

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Apache ActiveMQ RCE, Gogs Rebase RCE, and Windows Kernel Pointer Enum — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-05-06-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-05-06-2026)
  - Context: Attackers name a Git branch '--exec' and request a rebase operation in Gogs. The branch name is passed unsanitized to git rebase, causing arbitrary command execution on the Gogs server host.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Gogs
- Platforms: Windows, Linux
- Malware: Not specified
- Tools: Metasploit
- Search tags: T1190, T1059, Gogs, Windows, Linux, Metasploit

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: T1190, T1059

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "git"
| where ProcessCommandLine has "rebase" and ProcessCommandLine has "--exec"
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessId,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ProcessId,
    FileName,
    FolderPath,
    ProcessCommandLine
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Developer workstations where git rebase --exec is used legitimately in CI/CD scripts or interactive rebasing workflows.
- CI/CD pipeline agents that run git rebase --exec as part of automated testing or commit hook validation.

Tuning notes:
- Scope DeviceName to known Gogs server hostnames to eliminate developer workstation matches.
- Add AccountName filter for the Gogs service account once it is identified in the environment.
- Consider adding InitiatingProcessFileName filter for the Gogs process name (e.g., 'gogs') if it is consistently visible as the parent in DeviceProcessEvents telemetry from the server.

Risks / caveats:
- MDE agent must be deployed on the Gogs server host for DeviceProcessEvents to contain relevant telemetry. If the Gogs server is not onboarded to MDE, the query will return no results for that host.
- Developer workstations running git rebase --exec legitimately will match this query; host scoping to known Gogs server assets is strongly recommended before scheduling.
- The Gogs service account name varies by deployment; adding an AccountName filter for the known Gogs service account would significantly reduce FP volume.
- On Windows, git may be invoked as 'git.exe'; the =~ operator handles case insensitivity but the FileName field may include the extension depending on MDE version and OS.

### Triage Runbook

First 15 minutes:
- Confirm the host is a Gogs server and verify whether the alert occurred during any deployment, repository maintenance, or CI/CD activity.
- Inspect the git process command line for rebase and --exec usage, and identify the exact command that was launched.
- Review the parent process and account context to determine whether the execution came from the Gogs service account or an unexpected user session.
- Check for follow-on child processes, especially shells, downloaders, or discovery commands spawned by git or the Gogs service.
- If the command line is not tied to an approved workflow, treat the event as likely remote code execution and escalate.

Evidence to collect:
- Timestamp, DeviceName, AccountName, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessId, FileName, FolderPath, and ProcessCommandLine for the alerting event.
- Any repository, branch, or request metadata available from Gogs that shows the malicious branch name or triggering action.
- Process ancestry for git and any child processes spawned immediately after the rebase operation.
- Network and file activity from the Gogs host during the same time window.
- Change tickets or pipeline logs that could explain legitimate use of git rebase --exec.

Pivot points:
- DeviceProcessEvents for the same DeviceName and ProcessId to identify child processes and repeated git activity.
- DeviceNetworkEvents to look for outbound connections from the Gogs host after the rebase command.
- DeviceFileEvents to identify scripts, artifacts, or modified repository files created during the event.
- DeviceLogonEvents to determine whether an interactive user session or service account initiated the activity.

Benign explanations:
- A developer or CI/CD pipeline may legitimately use git rebase --exec in a controlled workflow.
- A maintenance script may invoke git commands on a server during repository housekeeping.
- A non-production Gogs instance may be used for testing and generate expected command execution patterns.

Escalation criteria:
- The host is a production Gogs server and the command line shows rebase --exec without an approved change record.
- The git process spawns a shell, downloader, or other suspicious child process.
- There is evidence of repository tampering, unexpected outbound connections, or file creation outside the repository path.
- The activity is associated with an unexpected account or an interactive session on the server.

Containment actions:
- If the activity is not clearly authorized, isolate the Gogs server from the network.
- Suspend or rotate the service account credentials used by Gogs if compromise is suspected.
- Preserve process, repository, and host telemetry before making disruptive changes.
- Restrict access to the Gogs service and review exposed repository endpoints until the issue is resolved.

Closure criteria:
- A valid change ticket, pipeline log, or admin record explains the git rebase --exec usage.
- No suspicious child processes, file changes, or outbound connections are observed.
- The activity is confirmed to be on a non-production or lab system with expected automation.
- The command line and account context match a known benign server-side maintenance workflow.

---

## Detection 3: Unsigned Process Invoking NtQuerySystemInformation for Kernel Pointer Enumeration

### Detection Opportunity

Unsigned or anomalous process using NtQuerySystemInformation to enumerate kernel pointers as a pre-exploitation reconnaissance step

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Apache ActiveMQ RCE, Gogs Rebase RCE, and Windows Kernel Pointer Enum — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-05-06-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-05-06-2026)
  - Context: A Metasploit module enumerates kernel pointers leaked via NtQuerySystemInformation on Windows. This is a known pre-exploitation technique used to defeat KASLR and is surfaced here as a new Metasploit capability.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059
- Products: Windows
- Platforms: Windows
- Malware: Not specified
- Tools: Metasploit
- Search tags: T1059, Windows, Metasploit

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: T1059

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.
- If ActionType 'NtQuerySystemInformation' is not emitted in the environment, this query returns no results and provides no detection value. Operators must run a spot-check query (DeviceEvents | where ActionType == 'NtQuerySystemInformation' | take 10) before scheduling.

Required telemetry:
- DeviceEvents, DeviceProcessEvents

### KQL

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "NtQuerySystemInformation"
| where InitiatingProcessFolderPath has_any (
    "\\Users\\",
    "\\Temp\\",
    "\\AppData\\",
    "\\Downloads\\",
    "\\ProgramData\\"
)
    or InitiatingProcessSignatureStatus != "Valid"
| project
    Timestamp,
    DeviceName,
    AccountName,
    ActionType,
    InitiatingProcessId,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath,
    InitiatingProcessSignatureStatus,
    InitiatingProcessParentFileName
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Security tooling, EDR agents, and vulnerability scanners that call NtQuerySystemInformation and run from non-standard paths or are unsigned.
- Developer tools and debuggers running from user profile directories.
- Legitimate unsigned internal tooling deployed to temp or appdata directories.

Tuning notes:
- Before scheduling, verify ActionType 'NtQuerySystemInformation' exists in DeviceEvents by running: DeviceEvents | where Timestamp > ago(1d) | where ActionType == 'NtQuerySystemInformation' | take 10
- Add known security tooling and monitoring agent process names to an exclusion on InitiatingProcessFileName once baseline is established.
- Consider adding a filter on InitiatingProcessParentFileName to further restrict to processes spawned by suspicious parents such as Office applications, browsers, or script interpreters.

Risks / caveats:
- The ActionType value 'NtQuerySystemInformation' is not a confirmed standard MDE DeviceEvents ActionType. MDE does not document individual NT syscall names as ActionType values. If this ActionType is not emitted in the environment, the query will return zero results. Operators must verify this ActionType exists in their DeviceEvents telemetry before deployment.
- InitiatingProcessSignatureStatus is a field on DeviceProcessEvents and DeviceEvents rows for the initiating process context, but its availability depends on MDE telemetry depth and may not be populated for all process events.
- InitiatingProcessFolderPath availability in DeviceEvents depends on MDE agent version and telemetry configuration; it may be null for some event types.
- If ActionType 'NtQuerySystemInformation' is not emitted in the environment, this query returns no results and provides no detection value. Operators must run a spot-check query (DeviceEvents | where ActionType == 'NtQuerySystemInformation' | take 10) before scheduling.

### Triage Runbook

First 15 minutes:
- Validate that the process is unsigned or otherwise anomalous and confirm the host, user, and folder path are consistent with suspicious execution.
- Check whether the process is running from a user-writable location such as Users, Temp, AppData, Downloads, or ProgramData.
- Review the parent process and command line to see whether the activity was launched by a browser, Office app, script interpreter, or another suspicious parent.
- Determine whether the host is a security appliance, scanner, developer workstation, or endpoint running known diagnostic tools that could explain the call.
- If the process is both unsigned and running from an unusual path with no business justification, escalate for deeper investigation.

Evidence to collect:
- Timestamp, DeviceName, AccountName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessSignatureStatus, InitiatingProcessId, and InitiatingProcessParentFileName.
- Process ancestry and any child processes spawned by the initiating process.
- File path and hash information for the initiating binary if available from endpoint telemetry.
- Any related network, file, or registry activity from the same process and host around the alert time.
- Asset role and software inventory to determine whether the process belongs to approved security tooling or diagnostics.

Pivot points:
- DeviceProcessEvents for the same DeviceName and InitiatingProcessId to identify child processes and full ancestry.
- DeviceEvents for additional NtQuerySystemInformation occurrences from the same host or account.
- DeviceNetworkEvents to check for outbound connections from the suspicious process.
- DeviceFileEvents and DeviceRegistryEvents to identify persistence, dropped files, or configuration changes.

Benign explanations:
- Security tools, EDR agents, or vulnerability scanners may call NtQuerySystemInformation as part of normal operation.
- Developer tools or debuggers running from user directories may legitimately query system information.
- Internal unsigned utilities deployed to temp or appdata locations may trigger the detection if not yet baselined.

Escalation criteria:
- The process is unsigned, runs from a user-writable path, and has no approved business purpose.
- The parent process is a browser, Office application, script interpreter, or other suspicious launcher.
- The process is associated with additional suspicious behavior such as shell spawning, credential access, or persistence.
- The host is a high-value system and the activity appears to be exploit reconnaissance rather than approved diagnostics.

Containment actions:
- If the process appears malicious, isolate the host to prevent follow-on exploitation.
- Preserve the binary and process telemetry for analysis before terminating the process.
- Block the file or hash if it is confirmed malicious and distributed beyond the initial host.
- Review nearby hosts for the same binary or behavior to determine spread.

Closure criteria:
- The process is confirmed as approved security, diagnostic, or developer tooling with documented ownership.
- The binary is signed or otherwise validated and the folder path matches expected deployment locations.
- No suspicious child processes, network activity, or persistence indicators are found.
- The behavior is consistent with a known benign baseline for the host role.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Other deployment dependency:
- Unsigned Process Invoking NtQuerySystemInformation for Kernel Pointer Enumeration: Defender for Endpoint file-event coverage must be confirmed on the target host population.

Telemetry availability:
- Unsigned Process Invoking NtQuerySystemInformation for Kernel Pointer Enumeration: If ActionType 'NtQuerySystemInformation' is not emitted in the environment, this query returns no results and provides no detection value. Operators must run a spot-check query (DeviceEvents | where ActionType == 'NtQuerySystemInformation' | take 10) before scheduling.

Shared-table notes:
- DeviceProcessEvents: shared by Apache ActiveMQ Child Process Spawned via Jolokia RCE; Gogs Git Rebase with --exec Argument Spawning Commands; Unsigned Process Invoking NtQuerySystemInformation for Kernel Pointer Enumeration

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Apache ActiveMQ Child Process Spawned via Jolokia RCE; Gogs Git Rebase with --exec Argument Spawning Commands.
2. Resolve environment-mapping detections next: Unsigned Process Invoking NtQuerySystemInformation for Kernel Pointer Enumeration.

### Hunting Agenda and Promotion Criteria

- Unsigned Process Invoking NtQuerySystemInformation for Kernel Pointer Enumeration: Defender for Endpoint file-event coverage must be confirmed on the target host population.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
