---
layout: post
title: "Detection Engineering Brief - Monday, November 16, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-11-16
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - ScreenConnect
  - Microsoft Defender XDR
  - Windows
  - SCKit
  - Retadup
  - CoffeeLoader
  - VMware ESXi
  - VMware vCenter
  - macOS
  - DownTheDRAIN
  - T1003
  - T1033
  - T1059
  - T1059.001
  - T1091
  - T1204
  - T1204.002
  - T1529
  - T1490
  - T1059.004
  - T1105
  - T1204.001
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

0 production candidates, 3 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: ScreenConnect, Microsoft Defender XDR, Windows, SCKit, Retadup, CoffeeLoader, VMware ESXi, VMware vCenter, macOS, DownTheDRAIN, T1003, T1033, T1059, T1059.001, T1091, T1204, T1204.002, T1529, T1490, T1059.004, ....

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: SCKit - ScreenConnect Spawning Suspicious Child Processes with Outbound Network Activity; SCKit - ScreenConnect Parent Process Initiating Interactive Logon Events Targeting Technician Sessions; Retadup/CoffeeLoader - Executable Written to Removable Media Followed by Execution from Removable Drive Path; ESXi Ransomware - Bulk VM Power-Off or Snapshot Deletion Commands from Unexpected Sources; DownTheDRAIN - Browser Process Spawning Shell Interpreter Followed by File Write on macOS.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: SCKit - ScreenConnect Spawning Suspicious Child Processes with Outbound Network Activity

### Detection Opportunity

SCKit abuses ScreenConnect to deploy unauthorized remote access by spawning unexpected child processes and establishing outbound connections to non-standard endpoints.

### Intelligence Context

- Microsoft Security Blog: SCKit abuses ScreenConnect to deploy remote access and target technician sessions — [https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/](https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/)
  - Context: SCKit was observed abusing ScreenConnect to deploy unauthorized remote access tools and target active technician sessions, using ScreenConnect as a trusted carrier to evade detection.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1003, T1033, T1059, T1059.001
- Products: ScreenConnect, Microsoft Defender XDR
- Platforms: Windows
- Malware: Not specified
- Tools: SCKit
- Search tags: ScreenConnect, Microsoft Defender XDR, Windows, SCKit, T1003, T1033, T1059, T1059.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1003 OS Credential Dumping (low); Discovery: T1033 System Owner/User Discovery (medium); Execution: T1059 Command and Scripting Interpreter/ T1059.001 PowerShell (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let ScreenConnectChildren = DeviceProcessEvents
| where InitiatingProcessFileName has_any ("ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe", "ScreenConnect.WindowsBackstageShell.exe")
| where FileName has_any ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "net.exe", "nltest.exe")
| project DeviceName, AccountName, InitiatingProcessFileName, ChildProcess = FileName, ProcessCommandLine, SpawnTime = Timestamp, ChildProcessId = ProcessId;
let ChildNetworkEvents = DeviceNetworkEvents
| where RemotePort !in (443, 80)
| project DeviceName, RemoteIP, RemotePort, NetTime = Timestamp, NetInitiatingProcessId = InitiatingProcessId, NetInitiatingProcessFileName = InitiatingProcessFileName;
ScreenConnectChildren
| join kind=inner ChildNetworkEvents on DeviceName
| where NetInitiatingProcessId == ChildProcessId
| where NetTime between (SpawnTime .. (SpawnTime + 5m))
| project DeviceName, AccountName, InitiatingProcessFileName, ChildProcess, ProcessCommandLine, SpawnTime, ChildProcessId, RemoteIP, RemotePort, NetTime
| order by SpawnTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- IT administrators running legitimate scripting tools under ScreenConnect sessions for maintenance tasks.
- Software deployment or patch management workflows that use ScreenConnect to invoke cmd.exe or powershell.exe with outbound package downloads.
- Monitoring or RMM agents that establish non-443/80 connections as part of normal operation when invoked via ScreenConnect.

**Tuning notes:**
- Extend the 5-minute window if post-exploitation activity in your environment shows longer delays between process spawn and network connection.
- Add known-legitimate child process and command-line patterns to an exclusion list based on your IT team's ScreenConnect usage baseline.
- Consider adding a RemoteIP allowlist for known ScreenConnect relay infrastructure to suppress legitimate relay traffic that uses non-standard ports.

**Risks / caveats:**
- ProcessId values in DeviceProcessEvents may be reused within the 5-minute window on high-activity systems, causing rare false matches.
- ScreenConnect deployments using non-default executable names will not be detected; validate executable names against your ScreenConnect deployment.
- Outbound C2 over ports 80 or 443 will not be flagged due to the port exclusion; this is a deliberate noise trade-off.
- The 5-minute correlation window may miss slow-burn post-exploitation where the child process delays network activity.

### Triage Runbook

**First 15 minutes:**
- Confirm the child process name, command line, and parent ScreenConnect process on the same host; verify the network event is tied to the same child process ID, not just the same device.
- Check whether the account associated with the ScreenConnect session is a known IT/admin account and whether the activity occurred during an approved support window.
- Review the remote IP and port for legitimacy; compare against known ScreenConnect relay infrastructure, vendor services, and your internal allowlists.
- Look for follow-on activity from the same host such as additional script execution, credential access tooling, archive creation, or lateral movement attempts.

**Evidence to collect:**
- DeviceProcessEvents for the child process tree, command line, parent process, and timestamps.
- DeviceNetworkEvents for the matching ProcessId/InitiatingProcessId, remote IP, remote port, and connection timing.
- ScreenConnect session logs or admin audit records showing who initiated the session and whether it was approved.
- Any nearby alerts on the same host for credential dumping, discovery, persistence, or remote access tooling.

**Pivot points:**
- DeviceProcessEvents filtered to the host, ScreenConnect parent processes, and the child process name.
- DeviceNetworkEvents filtered to the same host and child ProcessId to enumerate all outbound connections.
- DeviceLogonEvents and DeviceFileEvents on the same host around the same time to identify interactive use, dropped files, or staged payloads.
- ScreenConnect administrative logs or remote support audit trails if available in your environment.

**Benign explanations:**
- Legitimate IT support sessions using ScreenConnect to run cmd.exe or powershell.exe for maintenance or software deployment.
- Approved software installation or patching workflows that download packages over non-standard ports.
- Monitoring or RMM tooling launched through ScreenConnect as part of normal operations.

**Escalation criteria:**
- The child process is a LOLBin or scripting interpreter with suspicious command-line content, especially if it contacts an unknown external IP.
- The ScreenConnect session is not attributable to a known technician or approved maintenance activity.
- You observe credential access, discovery, persistence, or additional remote access tooling on the same host.
- The remote destination is unrecognized, associated with a suspicious ASN/geography, or appears to be attacker-controlled infrastructure.

**Containment actions:**
- If unauthorized activity is confirmed, isolate the host from the network using your EDR or endpoint containment workflow.
- Disable or suspend the associated ScreenConnect account/session and revoke any exposed credentials used during the session.
- Block the remote IP/domain at perimeter controls if it is confirmed malicious and not required for business operations.
- Preserve volatile evidence and collect the process tree and network artifacts before remediation.

**Closure criteria:**
- The activity is confirmed as an approved ScreenConnect support action with matching change ticket or maintenance record.
- The child process and outbound connection are attributable to a known benign workflow and no additional suspicious activity is present.
- No evidence of unauthorized access, credential theft, or follow-on malicious behavior is found after host and account review.

<br/>
---
<br/>

## Detection 2: SCKit - ScreenConnect Parent Process Initiating Interactive Logon Events Targeting Technician Sessions

### Detection Opportunity

SCKit targets active technician sessions by using ScreenConnect as a parent process to initiate anomalous interactive or network logon events.

### Intelligence Context

- Microsoft Security Blog: SCKit abuses ScreenConnect to deploy remote access and target technician sessions — [https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/](https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/)
  - Context: SCKit was specifically observed targeting active technician sessions through ScreenConnect, suggesting session hijacking or credential harvesting from privileged support sessions.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1003, T1033, T1059, T1059.001
- Products: ScreenConnect, Microsoft Defender XDR
- Platforms: Windows
- Malware: Not specified
- Tools: SCKit
- Search tags: ScreenConnect, Microsoft Defender XDR, Windows, SCKit, T1003, T1033, T1059, T1059.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1003 OS Credential Dumping (low); Discovery: T1033 System Owner/User Discovery (medium); Execution: T1059 Command and Scripting Interpreter/ T1059.001 PowerShell (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- DeviceLogonEvents.InitiatingProcessFileName may not be populated for all logon types in all Defender for Endpoint sensor versions; if the field is empty, the LogonEvents subquery returns no rows and the join produces no results.

**Required telemetry:**
- DeviceProcessEvents, DeviceLogonEvents

### KQL

```kql
let HighConfidenceChildren = dynamic(["mimikatz.exe", "procdump.exe", "procdump64.exe"]);
let MediumConfidenceChildren = dynamic(["cmd.exe", "powershell.exe", "net.exe", "whoami.exe"]);
let ScreenConnectProcs = DeviceProcessEvents
| where InitiatingProcessFileName has_any ("ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe", "ScreenConnect.WindowsBackstageShell.exe")
| where FileName has_any ("cmd.exe", "powershell.exe", "net.exe", "whoami.exe", "mimikatz.exe", "procdump.exe", "procdump64.exe")
| extend HighConfidence = iff(FileName in (HighConfidenceChildren), true, false)
| project DeviceName, AccountName, ChildProcess = FileName, ProcessCommandLine, ProcTime = Timestamp, HighConfidence;
let LogonEvents = DeviceLogonEvents
| where InitiatingProcessFileName has_any ("ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe")
| where LogonType in (2, 3, 10)
| extend LogonTypeName = case(LogonType == 2, "Interactive", LogonType == 3, "Network", LogonType == 10, "RemoteInteractive", "Other")
| project DeviceName, LogonAccountName = AccountName, LogonType, LogonTypeName, LogonTime = Timestamp;
ScreenConnectProcs
| join kind=inner LogonEvents on DeviceName
| where LogonTime between (ProcTime .. (ProcTime + 10m))
| project DeviceName, AccountName, ChildProcess, ProcessCommandLine, ProcTime, LogonAccountName, LogonType, LogonTypeName, LogonTime, HighConfidence
| order by HighConfidence desc, ProcTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- IT technicians running whoami.exe, net.exe, or powershell.exe during legitimate ScreenConnect support sessions followed by normal authentication events.
- Automated IT workflows that authenticate to network resources immediately after ScreenConnect-initiated scripting tasks.
- Security tools or EDR agents that spawn enumeration processes under ScreenConnect sessions during scheduled scans.

**Tuning notes:**
- Prioritize triage of rows where HighConfidence is true, as these involve credential-access tooling.
- Cross-reference LogonAccountName against your known IT technician account list to identify anomalous logon targets.
- If DeviceLogonEvents.InitiatingProcessFileName is consistently empty in your environment, consider removing the LogonEvents InitiatingProcessFileName filter and relying solely on the time-window correlation, accepting higher FP volume.
- Extend the child process list with renamed credential-dumping tool variants observed in your threat intelligence.

**Risks / caveats:**
- DeviceLogonEvents.InitiatingProcessFileName population depends on Defender for Endpoint sensor version and logon type; network logon type 3 events may not reliably populate this field, which would cause the LogonEvents subquery to return no results for those logon types.
- DeviceLogonEvents.InitiatingProcessFileName may not be populated for all logon types in all Defender for Endpoint sensor versions; if the field is empty, the LogonEvents subquery returns no rows and the join produces no results.
- The DeviceName-only join key means logon events from unrelated processes on the same device within 10 minutes will match if ScreenConnect also spawned a child process in that window.
- The 10-minute correlation window is a heuristic; adjust based on observed session interaction timing in your environment.

### Triage Runbook

**First 15 minutes:**
- Validate the ScreenConnect-spawned child process and the associated logon event on the same host within the time window.
- Check whether the logon target account is a technician, privileged admin, or service account and whether the logon type is expected for the workflow.
- Prioritize any row marked HighConfidence, especially if mimikatz.exe, procdump.exe, or procdump64.exe is present.
- Review nearby process activity for discovery commands, credential access, or remote access tooling launched from the same ScreenConnect session.

**Evidence to collect:**
- DeviceProcessEvents for the ScreenConnect child process, command line, and parent lineage.
- DeviceLogonEvents for the matching host, logon type, logon account, and timestamp.
- Account context for the technician or privileged user involved, including recent sign-ins and MFA status if available.
- Any related alerts for credential dumping, suspicious logons, or lateral movement from the same host.

**Pivot points:**
- DeviceProcessEvents on the host for ScreenConnect child processes and any credential-access or discovery tools.
- DeviceLogonEvents on the host filtered by logon type 2, 3, or 10 to identify the exact logon sequence.
- DeviceFileEvents for evidence of dumped credentials, archives, or staging files.
- Identity and authentication logs to verify whether the logon was expected and whether the account was used elsewhere around the same time.

**Benign explanations:**
- Legitimate technician activity during a support session that triggers normal interactive or remote interactive logons.
- Automated administrative workflows that authenticate to network resources after ScreenConnect-launched scripts.
- Security or IT tools that perform enumeration or validation during scheduled maintenance or scans.

**Escalation criteria:**
- HighConfidence is true and the child process is a credential-dumping or memory-dumping tool.
- The logon target is a privileged or technician account that should not be used in this context.
- There is evidence of credential theft, suspicious authentication, or follow-on lateral movement.
- The ScreenConnect session cannot be tied to an approved support event or known administrator.

**Containment actions:**
- If malicious, isolate the host and terminate the ScreenConnect session or service path used for abuse.
- Reset or disable any accounts that may have been exposed or targeted, especially technician and privileged accounts.
- Preserve process, logon, and authentication evidence before cleanup or reboot.
- Block further remote access from the affected host until the investigation is complete.

**Closure criteria:**
- The logon activity is validated as expected technician or automation behavior with supporting change records.
- No credential-access tooling, suspicious authentication, or lateral movement is found after review.
- The ScreenConnect session and associated account are confirmed benign and consistent with baseline support activity.

<br/>
---
<br/>

## Detection 3: Retadup/CoffeeLoader - Executable Written to Removable Media Followed by Execution from Removable Drive Path

### Detection Opportunity

Retadup USB worm writes CoffeeLoader payload to removable media and subsequently executes it from the removable drive path.

### Intelligence Context

- Securelist: A USB worm's second life: Retadup spreading CoffeeLoader — [https://securelist.com/retadup-delivers-coffeeloader/121908/](https://securelist.com/retadup-delivers-coffeeloader/121908/)
  - Context: Retadup, a USB worm with infrastructure previously seized by law enforcement in 2019, was observed in a new campaign dropping CoffeeLoader onto removable media and executing it from those paths to propagate across systems.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1091, T1204, T1204.002
- Products: Not specified
- Platforms: Windows
- Malware: Retadup, CoffeeLoader
- Tools: Not specified
- Search tags: Windows, Retadup, CoffeeLoader, T1091, T1204, T1204.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1091 Replication Through Removable Media (high); Execution: T1204 User Execution/ T1204.002 Malicious File (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let RemovableWrites = DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath matches regex @"^[D-Zd-z]:\\"
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".scr" or FileName endswith ".com"
| where not(InitiatingProcessFileName has_any ("explorer.exe", "setup.exe", "msiexec.exe", "robocopy.exe", "xcopy.exe"))
| extend DriveRoot = toupper(substring(FolderPath, 0, 2))
| project DeviceName, WrittenFile = FileName, WritePath = FolderPath, SHA256, WriteTime = Timestamp, WritingProcess = InitiatingProcessFileName, DriveRoot;
let RemovableExec = DeviceProcessEvents
| where FolderPath matches regex @"^[D-Zd-z]:\\"
| where FileName endswith ".exe" or FileName endswith ".scr" or FileName endswith ".com"
| extend DriveRoot = toupper(substring(FolderPath, 0, 2))
| project DeviceName, ExecFile = FileName, ExecPath = FolderPath, ProcessCommandLine, ExecTime = Timestamp, ExecDriveRoot = DriveRoot;
RemovableWrites
| join kind=inner RemovableExec on DeviceName
| where ExecDriveRoot == DriveRoot
| where ExecTime between (WriteTime .. (WriteTime + 30m))
| project DeviceName, WrittenFile, WritePath, SHA256, WriteTime, WritingProcess, DriveRoot, ExecFile, ExecPath, ProcessCommandLine, ExecTime
| order by WriteTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Portable application launchers that write updated binaries to USB drives and then execute them.
- IT deployment tools that stage executables on removable media for offline installation.
- Secondary internal hard drives or virtual disks assigned drive letters in the D-Z range that are not removable media.

**Tuning notes:**
- If your environment assigns fixed secondary drives letters in the D-Z range, add those specific drive letters to an exclusion list to reduce false positives.
- Reduce the 30-minute window if USB propagation in your environment shows faster write-to-execute timing.
- Submit flagged SHA256 values to threat intelligence platforms to prioritize confirmed CoffeeLoader or Retadup samples.
- Consider adding AutoRun-related process names (e.g., autorun.exe) to the execution-side filter to catch autorun-based propagation specifically.

**Risks / caveats:**
- DeviceProcessEvents.FolderPath reflects the process image path; on some Defender for Endpoint versions this field may be empty or contain only the directory without the drive letter prefix, which would cause the drive-letter prefix match to fail silently.
- Drive letters D-Z include fixed secondary drives, network-mapped drives, and virtual disks in addition to removable media; the query cannot distinguish removable from non-removable drives using available schema fields.
- The 30-minute execution window may produce false matches on systems with frequent executable activity on secondary drives.
- DeviceProcessEvents.FolderPath may be empty or inconsistently populated depending on the Defender for Endpoint sensor version, causing the execution-side filter to miss events.

### Triage Runbook

**First 15 minutes:**
- Confirm the written file and executed file are the same or related sample by comparing filename, path, and SHA256 if present.
- Verify the drive letter and whether it corresponds to removable media, a mapped drive, or a fixed secondary disk in your environment.
- Identify the user and process that wrote the file and the process that executed it; determine whether the execution was user-initiated.
- Check whether the host shows additional signs of worm-like spread, such as repeated writes to other removable drives or similar file hashes on other endpoints.

**Evidence to collect:**
- DeviceFileEvents for the file creation event, including initiating process, path, timestamp, and SHA256.
- DeviceProcessEvents for the execution event, including command line, parent process, and execution path.
- USB/removable media insertion logs or endpoint device control logs if available.
- Any detections or file sightings of the same hash on other hosts or removable drives.

**Pivot points:**
- DeviceFileEvents for the same SHA256 or filename across the environment.
- DeviceProcessEvents for executions from the same drive root or with the same file path pattern.
- DeviceFileEvents and DeviceProcessEvents on the same host around the same time for other removable-media activity.
- Endpoint device control or removable storage telemetry if your environment collects it.

**Benign explanations:**
- Portable application or offline installer workflows that stage executables on removable media and then run them.
- IT deployment or field-support processes that use USB media for software transfer.
- A legitimate secondary drive or virtual disk assigned a D-Z letter in the environment rather than true removable media.

**Escalation criteria:**
- The file hash matches known Retadup, CoffeeLoader, or another malicious sample.
- The same or similar file is observed on multiple hosts or multiple removable drives.
- The execution was user-initiated and not part of an approved deployment or support workflow.
- Additional suspicious persistence, network activity, or lateral spread is observed on the host.

**Containment actions:**
- Remove the removable media from service and prevent further use until it is scanned and cleared.
- Isolate the host if the sample is confirmed malicious or if additional spread is suspected.
- Block the file hash across EDR and email/web controls if applicable.
- Collect the removable media and host artifacts for malware analysis before remediation.

**Closure criteria:**
- The file and execution are confirmed to be part of an approved software transfer or deployment process.
- The drive is verified as a benign mapped or fixed disk and no malicious hash or follow-on activity is found.
- No evidence of propagation, persistence, or malicious execution remains after review.

<br/>
---
<br/>

## Detection 4: ESXi Ransomware - Bulk VM Power-Off or Snapshot Deletion Commands from Unexpected Sources

### Detection Opportunity

Ransomware actors abuse native ESXi and vCenter features to power off virtual machines and delete snapshots in bulk, maximizing impact across hosted VMs.

### Intelligence Context

- Securelist: Ransomware at the hypervisor layer: how attackers use ESXi and vCenter features for malicious purposes — [https://securelist.com/esxi-ransomware/121959/](https://securelist.com/esxi-ransomware/121959/)
  - Context: Ransomware operators were observed targeting ESXi hypervisors by using native ESXi and vCenter administrative features to power off VMs and delete snapshots in bulk, preventing recovery and maximizing encryption impact across all hosted virtual machines.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1529, T1490
- Products: VMware ESXi, VMware vCenter
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: VMware ESXi, VMware vCenter, T1529, T1490

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Impact: T1529 System Shutdown/Reboot (high); Impact: T1490 Inhibit System Recovery (high)

### Deployment Gates

- ESXi syslog forwarding to the Sentinel Syslog table must be explicitly configured on each ESXi host or via a syslog aggregator; without this connector, the Syslog table will contain no ESXi events and the query will return no results.

**Required telemetry:**
- Syslog

### KQL

```kql
Syslog
| where TimeGenerated > ago(24h)
| where SyslogMessage has_any ("vim-cmd vmsvc/power.off", "vim-cmd vmsvc/snapshot.removeall", "PowerOffVM_Task", "RemoveAllSnapshots_Task", "vim-cmd vmsvc/destroy", "esxcli vm process kill")
| summarize EventCount = count(), Commands = make_set(SyslogMessage, 20), ProcessNames = make_set(ProcessName, 10) by HostName, HostIP, bin(TimeGenerated, 10m)
| where EventCount >= 3
| order by EventCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Scheduled maintenance windows involving bulk VM power-off operations by administrators.
- Automated DR testing or backup workflows that power off and snapshot VMs in bulk.
- vCenter orchestration tasks that generate multiple power-off events in rapid succession during planned migrations.

**Tuning notes:**
- Increase the EventCount threshold above 3 if your environment performs scheduled bulk VM operations during maintenance windows.
- Add a HostName filter using a known list of ESXi host names from your inventory to scope results to hypervisor hosts only and exclude other syslog sources.
- Reduce the TimeGenerated lookback from 24h to 1h if deploying as a scheduled analytic rule to reduce result volume and improve alert latency.
- Consider adding a HostIP filter to exclude known vCenter orchestration source IPs if automated workflows generate bulk events from specific management hosts.

**Risks / caveats:**
- ESXi syslog forwarding to the Sentinel Syslog table must be explicitly configured on each ESXi host or via a syslog aggregator; without this connector, the Syslog table will contain no ESXi events and the query will return no results.
- The SourceIP field referenced in the original query is not a standard field in the Sentinel Syslog table schema; it has been replaced with Computer and HostIP which are the standard Syslog table fields for source identification.
- ESXi environments using vCenter API exclusively for VM management may log PowerOffVM_Task and RemoveAllSnapshots_Task events in vCenter logs rather than ESXi host syslog, requiring a separate vCenter log connector.
- The threshold of 3 events per 10-minute window may be too low in environments with automated VM lifecycle management; baseline normal operation counts before treating results as alerts.

### Triage Runbook

**First 15 minutes:**
- Identify the source host and process name generating the commands and verify whether it is a known management system or an unexpected source.
- Review the command set and count to confirm whether the activity is bulk power-off, snapshot deletion, or destructive VM management.
- Check whether the activity aligns with a scheduled maintenance window, DR test, or approved change ticket.
- Assess whether the affected ESXi host is part of a critical cluster and whether multiple VMs are being impacted in a short period.

**Evidence to collect:**
- Syslog messages showing the exact commands, timestamps, hostnames, and source host/IP.
- Change management records or maintenance approvals for the time window.
- vCenter or hypervisor admin logs showing the initiating account and any API activity.
- Inventory of affected VMs and whether snapshots or power state changes were expected.

**Pivot points:**
- Syslog for the same HostName or HostIP to enumerate all related destructive commands in the time window.
- vCenter logs or management-plane logs if available to confirm whether the action came from API or shell.
- Asset inventory or CMDB to identify the host role and expected administrators.
- Backup/DR logs to determine whether snapshot deletion or power-off was part of a sanctioned workflow.

**Benign explanations:**
- Planned maintenance windows involving bulk VM shutdowns or snapshot cleanup.
- Automated DR testing or backup workflows that power off VMs or remove snapshots.
- vCenter orchestration or migration tasks that generate clustered power-off events during approved operations.

**Escalation criteria:**
- The source is not a known management host or approved administrator.
- The commands are destructive, repeated, and not tied to a change ticket or maintenance window.
- Multiple critical VMs are affected or recovery snapshots are being removed unexpectedly.
- There are concurrent signs of compromise on the management plane or hypervisor.

**Containment actions:**
- If malicious, immediately restrict access to the ESXi/vCenter management plane and isolate the source host or account.
- Suspend or disable the administrative account used to issue the commands if unauthorized.
- Engage virtualization operations to halt further destructive actions and preserve logs.
- Initiate incident response for potential ransomware impact and verify backup integrity.

**Closure criteria:**
- The activity is confirmed as approved maintenance, DR testing, or orchestration with supporting records.
- The source host and account are validated as legitimate and no unauthorized destructive actions occurred.
- Affected VMs are accounted for and recovery posture remains intact after review.

<br/>
---
<br/>

## Detection 5: DownTheDRAIN - Browser Process Spawning Shell Interpreter Followed by File Write on macOS

### Detection Opportunity

ClickFix-style social engineering causes a browser on macOS to spawn a shell or script interpreter, which then writes files to user directories as part of DownTheDRAIN infostealer delivery.

### Intelligence Context

- SANS ISC: Macfinger ClickFix campaign sends DownTheDRAIN infostealer for macOS, (Fri, Nov 13th) — [https://isc.sans.edu/diary/rss/33518](https://isc.sans.edu/diary/rss/33518)
  - Context: The Macfinger ClickFix campaign was observed tricking macOS users into executing clipboard-injected commands via browser prompts, causing browsers to spawn shell interpreters that downloaded and wrote the DownTheDRAIN infostealer to user-accessible directories.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.004, T1105, T1204, T1204.001
- Products: Not specified
- Platforms: macOS
- Malware: DownTheDRAIN
- Tools: Not specified
- Search tags: macOS, DownTheDRAIN, T1059, T1059.004, T1105, T1204, T1204.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.004 Unix Shell (high); Command and Control: T1105 Ingress Tool Transfer (medium); Defense Evasion: T1204 User Execution/ T1204.001 Malicious Link (medium)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let MacOSDevices = DeviceProcessEvents
| where OSPlatform == "macOS"
| distinct DeviceName;
let BrowserShellSpawn = DeviceProcessEvents
| where DeviceName in (MacOSDevices)
| where InitiatingProcessFileName has_any ("Google Chrome", "Safari", "Firefox", "Microsoft Edge", "Brave Browser", "Arc", "chrome", "firefox", "safari", "msedge")
| where FileName has_any ("bash", "zsh", "sh", "python3", "python", "osascript", "curl", "wget", "perl", "ruby")
| project DeviceName, AccountName, BrowserParent = InitiatingProcessFileName, ShellChild = FileName, ProcessCommandLine, SpawnTime = Timestamp;
let ShellFileWrites = DeviceFileEvents
| where DeviceName in (MacOSDevices)
| where ActionType == "FileCreated"
| where FolderPath has_any ("/Users/", "/tmp/", "/var/folders/", "/Library/Application Support/")
| where FileName endswith ".sh" or FileName endswith ".py" or FileName endswith ".dylib" or FileName endswith ".app" or FileName endswith ".pkg" or FileName endswith ".dmg" or FileName endswith ".zip" or FileName endswith ".command"
| where InitiatingProcessFileName has_any ("bash", "zsh", "sh", "python3", "python", "curl", "wget")
| project DeviceName, WrittenFile = FileName, WritePath = FolderPath, WriteTime = Timestamp, WritingProcess = InitiatingProcessFileName;
BrowserShellSpawn
| join kind=inner ShellFileWrites on DeviceName
| where WriteTime between (SpawnTime .. (SpawnTime + 15m))
| project DeviceName, AccountName, BrowserParent, ShellChild, ProcessCommandLine, SpawnTime, WrittenFile, WritePath, WriteTime, WritingProcess
| order by SpawnTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Developers using browser-based terminals or web IDEs that spawn shell processes and write script files to user directories.
- Package managers invoked via browser-launched terminals (e.g., Homebrew installation via curl piped to bash).
- Legitimate software downloads where a browser spawns a shell to run a downloaded installer script.

**Tuning notes:**
- Validate browser binary names by running: DeviceProcessEvents → where OSPlatform == 'macOS' → where InitiatingProcessFileName has_any ('Chrome', 'Safari', 'Firefox') → summarize count() by InitiatingProcessFileName against your enrolled macOS device telemetry before deploying.
- Reduce the 15-minute correlation window if ClickFix delivery in your environment shows faster write timing after shell spawn.
- Add known-legitimate shell command patterns (e.g., Homebrew installation commands) to a ProcessCommandLine exclusion list to reduce developer machine false positives.
- Extend the WrittenFile extension list if DownTheDRAIN variants are observed dropping payloads with additional file types such as .plist or .bin.

**Risks / caveats:**
- macOS endpoint enrollment in Microsoft Defender for Endpoint is required for DeviceProcessEvents and DeviceFileEvents to contain macOS telemetry; if no macOS devices are enrolled, the query returns no results.
- Browser process executable names in InitiatingProcessFileName on macOS reflect the binary inside the .app bundle (e.g., 'Google Chrome' may appear as 'Google Chrome' or 'chrome' depending on MDE sensor version and macOS version); these names must be validated against actual DeviceProcessEvents telemetry from enrolled macOS devices before the query is meaningful.
- OSPlatform field availability in DeviceProcessEvents for macOS devices depends on the Defender for Endpoint sensor version deployed on macOS endpoints.
- Browser binary names in InitiatingProcessFileName on macOS must be validated against actual DeviceProcessEvents telemetry from enrolled macOS devices; mismatched names will cause the BrowserShellSpawn subquery to return no results.

### Triage Runbook

**First 15 minutes:**
- Confirm the browser parent, shell child, and file write occurred on the same macOS host within the time window.
- Review the command line for clipboard-injected commands, curl/wget usage, or suspicious download-and-execute behavior.
- Check the written file path and extension to determine whether the file is a likely payload, installer, or script in a user-accessible location.
- Ask the user or IT contact whether they recently followed browser prompts, pasted commands, or attempted software installation from a website.

**Evidence to collect:**
- DeviceProcessEvents for the browser-to-shell process chain, including command line and timestamps.
- DeviceFileEvents for the file creation event, including path, filename, and hash if available.
- User context for the account on the macOS device and any recent browser activity or downloads.
- Any related detections for persistence, credential theft, or additional payload execution on the same host.

**Pivot points:**
- DeviceProcessEvents on the macOS host for browser parents and shell children around the alert time.
- DeviceFileEvents for the same host to identify other files written by shell or download utilities.
- Browser history or download artifacts if available through endpoint telemetry or user support records.
- Any other alerts on the host for suspicious scripts, archive extraction, or network downloads.

**Benign explanations:**
- Developer or IT workflows that use browser-based terminals or web IDEs to spawn shells and write scripts.
- Legitimate software installation or package management initiated from a browser page.
- User-initiated downloads where a browser launches a shell to run a trusted installer or setup script.

**Escalation criteria:**
- The command line shows suspicious download-and-execute behavior, encoded commands, or known malicious patterns.
- The written file is an executable, script, or package in a user directory with no legitimate business justification.
- The user reports being instructed by a website to paste commands or bypass security prompts.
- There are additional signs of infostealer activity, persistence, or credential theft on the host.

**Containment actions:**
- If malicious behavior is confirmed, isolate the macOS host from the network.
- Quarantine or remove the written payload and any related files after preserving evidence.
- Reset credentials used on the device if there is any indication of credential theft or browser session compromise.
- Block any malicious URLs or domains identified during triage through web controls.

**Closure criteria:**
- The browser-to-shell activity is confirmed as a legitimate developer, IT, or software installation workflow.
- The written file is identified as benign and no suspicious follow-on activity is present.
- No evidence of payload execution, persistence, or credential theft is found after review.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- SCKit - ScreenConnect Spawning Suspicious Child Processes with Outbound Network Activity: Do not schedule yet; validate as an analyst-led hunt first.
- SCKit - ScreenConnect Parent Process Initiating Interactive Logon Events Targeting Technician Sessions: Do not schedule yet; validate as an analyst-led hunt first.
- Retadup/CoffeeLoader - Executable Written to Removable Media Followed by Execution from Removable Drive Path: Do not schedule yet; validate as an analyst-led hunt first.

**Environment scope / baselines:**
- SCKit - ScreenConnect Parent Process Initiating Interactive Logon Events Targeting Technician Sessions: DeviceLogonEvents.InitiatingProcessFileName may not be populated for all logon types in all Defender for Endpoint sensor versions; if the field is empty, the LogonEvents subquery returns no rows and the join produces no results.

**Telemetry availability:**
- ESXi Ransomware - Bulk VM Power-Off or Snapshot Deletion Commands from Unexpected Sources: ESXi syslog forwarding to the Sentinel Syslog table must be explicitly configured on each ESXi host or via a syslog aggregator; without this connector, the Syslog table will contain no ESXi events and the query will return no results.

**Other deployment dependency:**
- DownTheDRAIN - Browser Process Spawning Shell Interpreter Followed by File Write on macOS: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Shared-table notes:**
- DeviceProcessEvents: shared by SCKit - ScreenConnect Spawning Suspicious Child Processes with Outbound Network Activity; SCKit - ScreenConnect Parent Process Initiating Interactive Logon Events Targeting Technician Sessions; Retadup/CoffeeLoader - Executable Written to Removable Media Followed by Execution from Removable Drive Path; DownTheDRAIN - Browser Process Spawning Shell Interpreter Followed by File Write on macOS
- DeviceFileEvents: shared by Retadup/CoffeeLoader - Executable Written to Removable Media Followed by Execution from Removable Drive Path; DownTheDRAIN - Browser Process Spawning Shell Interpreter Followed by File Write on macOS

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: ESXi Ransomware - Bulk VM Power-Off or Snapshot Deletion Commands from Unexpected Sources; DownTheDRAIN - Browser Process Spawning Shell Interpreter Followed by File Write on macOS.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: SCKit - ScreenConnect Spawning Suspicious Child Processes with Outbound Network Activity; SCKit - ScreenConnect Parent Process Initiating Interactive Logon Events Targeting Technician Sessions; Retadup/CoffeeLoader - Executable Written to Removable Media Followed by Execution from Removable Drive Path.

### Hunting Agenda and Promotion Criteria

- SCKit - ScreenConnect Spawning Suspicious Child Processes with Outbound Network Activity: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- SCKit - ScreenConnect Parent Process Initiating Interactive Logon Events Targeting Technician Sessions: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- Retadup/CoffeeLoader - Executable Written to Removable Media Followed by Execution from Removable Drive Path: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- ESXi Ransomware - Bulk VM Power-Off or Snapshot Deletion Commands from Unexpected Sources: ESXi syslog forwarding to the Sentinel Syslog table must be explicitly configured on each ESXi host or via a syslog aggregator; without this connector, the Syslog table will contain no ESXi events and the query will return no results.; baseline expected benign activity and define an alert-volume threshold.
- DownTheDRAIN - Browser Process Spawning Shell Interpreter Followed by File Write on macOS: Defender for Endpoint file-event coverage must be confirmed on the target host population.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
