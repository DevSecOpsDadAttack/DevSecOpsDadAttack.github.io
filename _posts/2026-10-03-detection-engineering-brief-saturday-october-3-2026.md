---
layout: post
title: "Detection Engineering Brief - Saturday, October 3, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-10-03
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - T1059
  - BPFDoor
  - AVERAT
  - BPF Rekoobe
  - Linux
  - BPFDoor controller
  - CVE-2026-76504
  - T1190
  - Cisco Catalyst SD-WAN Manager
  - T1059.004
  - T1036
---

## Detection Engineering Summary

This brief produced 4 detection candidates.

2 production candidates, 1 hunting-only, 1 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: T1059, BPFDoor, AVERAT, BPF Rekoobe, Linux, BPFDoor controller, CVE-2026-76504, T1190, Cisco Catalyst SD-WAN Manager, T1059.004, T1036.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: BPFDoor - Shell Script Written and Executed by Non-Interactive Process on Linux Appliance; CVE-2026-76504 - Unauthenticated Admin-Level API Access on Cisco SD-WAN Manager.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: BPFDoor - Masqueraded Binaries Staged in /sbin (ntpdate or udevds)

### Detection Opportunity

Dropper stages BPFDoor or AVERAT payloads into /sbin under masqueraded system utility names ntpdate and udevds.

### Intelligence Context

- Rapid7: SMTP is the key: BPFDoor and AVERAT hitting the network edge — [https://www.rapid7.com/blog/post/tr-smtp-is-the-key-bpfdoor-averat-hitting-the-network-edge](https://www.rapid7.com/blog/post/tr-smtp-is-the-key-bpfdoor-averat-hitting-the-network-edge)
  - Context: A dropper writes a shell script to appliance storage, which then stages BPFDoor and AVERAT payloads into /sbin under the masqueraded names ntpdate and udevds. The payloads are launched and the dropped files are deleted approximately ten seconds later while processes continue running.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.004, T1036
- Products: BPFDoor controller
- Platforms: Linux
- Malware: BPFDoor, AVERAT, BPF Rekoobe
- Tools: Not specified
- Search tags: T1059, BPFDoor, AVERAT, BPF Rekoobe, Linux, BPFDoor controller, T1059.004, T1036

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
| where FolderPath startswith "/sbin"
| where FileName in ("ntpdate", "udevds")
| where InitiatingProcessFileName !in (
    "apt", "apt-get", "dpkg", "rpm", "yum", "dnf", "zypper", "snap",
    "pip", "pip3", "ansible", "chef", "puppet"
)
| project
    Timestamp,
    DeviceName,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    ReportId
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Custom in-house deployment scripts that install ntpdate outside of a package manager.
- Configuration management tools not covered by the exclusion list writing files to /sbin.
- Appliance vendor update mechanisms that do not use standard package managers.

**Tuning notes:**
- Add any additional package managers, configuration management agents, or appliance vendor update processes to the InitiatingProcessFileName exclusion list after baselining.
- Scope DeviceName to network edge appliance device groups in MDE to reduce noise from general-purpose Linux servers if MDE coverage is broad.

**Risks / caveats:**
- DeviceFileEvents file creation telemetry for Linux hosts requires Microsoft Defender for Endpoint agent deployed and onboarded on the target Linux appliances. If MDE Linux coverage is absent, this query will return no results.
- Exclusion list may not cover all package managers or configuration management agents present in the environment; baseline review recommended before scheduling.
- If ntpdate is legitimately deployed via a non-package-manager mechanism in the environment, this will generate false positives until that initiating process is added to the exclusion list.
- udevds is not a standard Linux binary name; any hit on this filename is inherently high-fidelity, but ntpdate hits require additional triage.

### Triage Runbook

**First 15 minutes:**
- Confirm the device is a Linux appliance or network edge host that should not normally create ntpdate or udevds in /sbin.
- Review the initiating process name, command line, and parent process to identify whether the writer is a package manager, configuration tool, or an unexpected non-interactive process.
- Check whether the file creation is followed by execution, deletion, or additional suspicious file writes in the same time window.
- Look for signs of a dropper chain such as shell scripts, temporary files, or repeated creation of masqueraded binaries in /sbin.

**Evidence to collect:**
- Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, and InitiatingProcessParentFileName.
- Any nearby DeviceProcessEvents showing shell execution, child processes, or commands referencing ntpdate, udevds, /sbin, or temporary paths.
- File hash or file content if available from endpoint response or forensic collection.
- Recent authentication, admin activity, or maintenance change records for the host.

**Pivot points:**
- DeviceFileEvents for other FileCreated events in /sbin on the same DeviceName within the last 24 hours.
- DeviceProcessEvents for the same DeviceName and InitiatingProcessFileName to identify the parent chain and any spawned shells.
- DeviceNetworkEvents for the host to look for outbound connections from the same time period.
- If available, endpoint file inventory or live response to confirm whether ntpdate or udevds still exists on disk.

**Benign explanations:**
- A custom in-house deployment or appliance update process may write ntpdate outside of a package manager.
- A configuration management tool not covered by the exclusion list may stage files in /sbin during legitimate maintenance.
- An appliance vendor update mechanism may use nonstandard file names and paths that resemble malware staging.

**Escalation criteria:**
- The initiating process is not a known package manager, configuration management agent, or approved vendor updater.
- The file is quickly deleted after creation, or there is evidence of execution from /sbin shortly after staging.
- The host is a network edge appliance and the activity is consistent with the BPFDoor/AVERAT staging pattern described in the alert.
- Multiple related artifacts appear, such as shell scripts, masqueraded binaries, or repeated /sbin writes.

**Containment actions:**
- If the activity is not attributable to an approved maintenance process, isolate the host from the network using endpoint containment.
- Preserve volatile evidence before rebooting or cleaning up the host, including running processes and command lines.
- Block or suspend the suspicious initiating process if endpoint controls allow and it will not disrupt critical forensic collection.

**Closure criteria:**
- The initiating process is confirmed as an approved maintenance or vendor update workflow and the file names/paths match documented behavior.
- No execution, deletion, or follow-on malicious activity is found, and the host baseline supports this as expected automation.
- Any created files are verified as benign and removed through standard change-management procedures.

<br/>
---
<br/>

## Detection 2: BPFDoor - Process Execution Followed by Self-Deletion in /sbin Within 30 Seconds

### Detection Opportunity

BPFDoor or AVERAT payload is launched from /sbin and the corresponding file is deleted approximately ten seconds after execution while the process continues running.

### Intelligence Context

- Rapid7: SMTP is the key: BPFDoor and AVERAT hitting the network edge — [https://www.rapid7.com/blog/post/tr-smtp-is-the-key-bpfdoor-averat-hitting-the-network-edge](https://www.rapid7.com/blog/post/tr-smtp-is-the-key-bpfdoor-averat-hitting-the-network-edge)
  - Context: After staging payloads as ntpdate and udevds in /sbin, the dropper launches them and deletes each file ten seconds later while the processes continue running. This file-delete-after-execute pattern is a deliberate evasion technique to remove on-disk artifacts.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.004, T1036
- Products: BPFDoor controller
- Platforms: Linux
- Malware: BPFDoor, AVERAT, BPF Rekoobe
- Tools: Not specified
- Search tags: T1059, BPFDoor, AVERAT, BPF Rekoobe, Linux, BPFDoor controller, T1059.004, T1036

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.004 Unix Shell (high); Defense Evasion: T1036 Masquerading (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let executions = DeviceProcessEvents
| where FolderPath startswith "/sbin"
| where FileName in ("ntpdate", "udevds")
| project
    ExecTime = Timestamp,
    DeviceName,
    FileName,
    ProcessId,
    ProcessCommandLine,
    InitiatingProcessFileName;
let deletions = DeviceFileEvents
| where ActionType == "FileDeleted"
| where FolderPath startswith "/sbin"
| where FileName in ("ntpdate", "udevds")
| project
    DelTime = Timestamp,
    DeviceName,
    FileName,
    DeletingProcessFileName = InitiatingProcessFileName,
    DelReportId = ReportId;
executions
| join kind=inner deletions on DeviceName, FileName
| where DelTime >= ExecTime and DelTime <= datetime_add('second', 30, ExecTime)
| project
    ExecTime,
    DelTime,
    DeviceName,
    FileName,
    ProcessId,
    ProcessCommandLine,
    InitiatingProcessFileName,
    DeletingProcessFileName,
    DelReportId
| order by ExecTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Automated system update or self-updating agent processes that execute and then replace binaries named ntpdate in /sbin within a short window.
- Test or validation scripts in CI/CD pipelines that create, execute, and clean up binaries in /sbin.

**Tuning notes:**
- Adjust the 30-second window to 60 seconds if telemetry ingestion latency causes missed correlations in testing.
- Add DeviceName filtering to restrict scope to network edge appliance device groups if MDE coverage extends to general Linux servers.

**Risks / caveats:**
- Both DeviceProcessEvents and DeviceFileEvents require MDE Linux agent deployment. FileDeleted ActionType availability on Linux hosts should be confirmed; some MDE Linux agent versions may not surface FileDeleted events for all file system paths.
- Timestamp fidelity for sub-30-second correlation depends on MDE agent event buffering behavior on Linux; high-load appliances may batch events with coarser timestamps.
- If MDE Linux agent telemetry ingestion latency exceeds 20 seconds, the 30-second window may miss correlations; consider widening to 60 seconds after baseline testing.
- FileDeleted ActionType availability on the specific Linux appliance OS and MDE agent version must be confirmed before scheduling.

### Triage Runbook

**First 15 minutes:**
- Validate that the execution and deletion occurred on the same Linux host and that the file name is ntpdate or udevds in /sbin.
- Inspect the process command line and process ID to determine whether the binary was launched by an unexpected parent or shell script.
- Check whether the file was deleted shortly after execution while the process continued running, which is a strong evasion indicator.
- Identify any child processes, network connections, or additional file activity associated with the running process.

**Evidence to collect:**
- ExecTime, DelTime, DeviceName, FileName, ProcessId, ProcessCommandLine, InitiatingProcessFileName, DeletingProcessFileName, and DelReportId.
- DeviceProcessEvents for the same ProcessId and nearby parent/child processes.
- DeviceNetworkEvents for the same DeviceName and time window to identify outbound connections from the running process.
- Any available file recovery, memory capture, or live response output showing the process image or command line.

**Pivot points:**
- DeviceProcessEvents filtered to the same DeviceName and ProcessId to reconstruct the process tree.
- DeviceFileEvents for FileDeleted, FileCreated, or FileModified on the same DeviceName within +/- 1 hour.
- DeviceNetworkEvents for the same DeviceName to identify command-and-control or lateral movement activity.
- If available, Linux audit or endpoint telemetry showing the deleted file path and any open handles.

**Benign explanations:**
- A legitimate self-updating agent may replace a binary after execution, though this is uncommon for /sbin and these filenames.
- A test or CI/CD workflow may create, execute, and clean up a temporary binary during validation.
- An appliance vendor maintenance routine may briefly stage and remove a utility binary during upgrade activity.

**Escalation criteria:**
- The binary is not associated with a known maintenance workflow and the deletion follows execution within seconds.
- The process remains active after the file is deleted, especially if it is listening on the network or spawning shells.
- The host is a network edge appliance and the behavior matches the known BPFDoor/AVERAT pattern of staged execution and cleanup.
- Additional suspicious artifacts appear, such as shell scripts, masqueraded filenames, or repeated file recreation.

**Containment actions:**
- Isolate the host if the process is still active and the behavior cannot be tied to approved maintenance.
- Preserve the running process and memory if possible before remediation, since the on-disk artifact may already be gone.
- Terminate the suspicious process only after evidence capture if the host is not business-critical and containment is approved.

**Closure criteria:**
- The execution and deletion are explained by a documented, approved update or maintenance process.
- No suspicious child processes, network activity, or persistence mechanisms are found.
- The deleted binary is confirmed benign through change records, package logs, or vendor documentation.

<br/>
---
<br/>

## Detection 3: BPFDoor - Shell Script Written and Executed by Non-Interactive Process on Linux Appliance

### Detection Opportunity

A dropper process writes a shell script to appliance storage and executes it, initiating the BPFDoor/AVERAT payload staging chain.

### Intelligence Context

- Rapid7: SMTP is the key: BPFDoor and AVERAT hitting the network edge — [https://www.rapid7.com/blog/post/tr-smtp-is-the-key-bpfdoor-averat-hitting-the-network-edge](https://www.rapid7.com/blog/post/tr-smtp-is-the-key-bpfdoor-averat-hitting-the-network-edge)
  - Context: The initial dropper writes a shell script to the appliance storage mount and executes it. This script is responsible for staging both BPFDoor and AVERAT payloads into /sbin under masqueraded names. The dropper is a non-interactive process, making shell script creation by such a parent anomalous.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.004, T1036
- Products: BPFDoor controller
- Platforms: Linux
- Malware: BPFDoor, AVERAT, BPF Rekoobe
- Tools: Not specified
- Search tags: T1059, BPFDoor, AVERAT, BPF Rekoobe, Linux, BPFDoor controller, T1059.004, T1036

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
let scriptCreations = DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith ".sh"
| where InitiatingProcessFileName !in (
    "bash", "sh", "zsh", "dash", "sshd", "sudo",
    "python3", "python", "ruby", "perl", "node"
)
| project
    CreateTime = Timestamp,
    DeviceName,
    ScriptName = FileName,
    ScriptPath = FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessParentFileName,
    CreateReportId = ReportId;
let shellExecs = DeviceProcessEvents
| where FileName in ("bash", "sh", "zsh", "dash")
| project
    ExecTime = Timestamp,
    DeviceName,
    ShellProcess = FileName,
    ProcessCommandLine;
scriptCreations
| join kind=inner shellExecs on DeviceName
| where ExecTime >= CreateTime and ExecTime <= datetime_add('second', 60, CreateTime)
| where ProcessCommandLine has ScriptName
| project
    CreateTime,
    ExecTime,
    DeviceName,
    ScriptName,
    ScriptPath,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessParentFileName,
    ShellProcess,
    ProcessCommandLine,
    CreateReportId
| order by CreateTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Ansible, Chef, Puppet, or other configuration management agents that write and execute shell scripts as part of normal operations.
- Application deployment pipelines that stage and run shell scripts on Linux hosts.
- Appliance vendor update mechanisms that use shell scripts.
- Monitoring agents that write and execute diagnostic scripts.

**Tuning notes:**
- If the appliance storage mount path is known (e.g., /mnt/storage, /var/appliance), add a FolderPath startswith filter on the scriptCreations subquery to dramatically reduce noise.
- Adjust the 60-second window based on observed dropper execution timing after testing in the environment.
- Add DeviceName filtering to restrict scope to network edge appliance device groups.
- Consider promoting to scheduled_rule only after baselining confirms the script name correlation reduces FP rate to an acceptable level.

**Risks / caveats:**
- MDE Linux agent must be deployed on the target appliances and must surface FileCreated events for .sh files. Coverage gaps on Linux appliances will produce no results.
- The ProcessCommandLine has ScriptName filter requires that the shell invocation explicitly references the script filename. If the dropper executes the script via a file descriptor or sourcing mechanism that does not include the filename in the command line, this correlation will miss the event.
- High-volume environments with frequent shell script creation and execution will still produce noise even with the script name correlation; analyst review is required before scheduling.
- The 60-second window may need adjustment based on observed dropper timing; too wide a window increases false positives, too narrow may miss events under load.

### Triage Runbook

**First 15 minutes:**
- Review the script creation event to identify the script path, creator process, and whether the parent is a known automation tool or an unexpected daemon.
- Inspect the execution event to confirm the script was run by a shell and whether the command line references the created script name.
- Check whether the script wrote payloads into /sbin, launched additional processes, or deleted itself or its outputs.
- Assess whether the host is an appliance or edge device where non-interactive shell script creation is unusual.

**Evidence to collect:**
- CreateTime, ExecTime, DeviceName, ScriptName, ScriptPath, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessParentFileName, ShellProcess, ProcessCommandLine, and CreateReportId.
- DeviceFileEvents for related file creations in /sbin or temporary directories around the same time.
- DeviceProcessEvents for the full parent/child chain, including any shell, chmod, curl, wget, or interpreter activity.
- Any available script content, file hash, or endpoint live response artifact for the created .sh file.

**Pivot points:**
- DeviceFileEvents for other .sh creations on the same DeviceName in the last 24 hours.
- DeviceProcessEvents for bash, sh, zsh, or dash on the same host around CreateTime and ExecTime.
- DeviceNetworkEvents for the same host to identify downloads or outbound connections initiated by the script.
- If available, configuration management or deployment logs to confirm whether the script path is part of a known automation workflow.

**Benign explanations:**
- Ansible, Chef, Puppet, or another configuration management agent may legitimately write and execute shell scripts.
- Application deployment pipelines may stage shell scripts on Linux hosts as part of normal releases.
- Appliance vendor update or monitoring agents may use shell scripts for diagnostics or maintenance.

**Escalation criteria:**
- The initiating process is not a known automation or deployment tool and the script path is not part of an approved workflow.
- The script is followed by staging of masqueraded binaries in /sbin or by self-deletion behavior.
- The host is a Linux appliance and the activity aligns with the BPFDoor dropper chain described in the alert.
- The script launches network activity, persistence, or additional suspicious processes.

**Containment actions:**
- If the script is not attributable to approved automation, isolate the host to stop further staging or execution.
- Preserve the script and surrounding process evidence before cleanup or reboot.
- Block the initiating process or account if it is clearly malicious and containment will not disrupt evidence collection.

**Closure criteria:**
- The script creation and execution are matched to a documented, approved automation or maintenance process.
- No follow-on malicious file staging, execution, or network activity is observed.
- The script path and parent process are confirmed benign through change records or baseline behavior.

<br/>
---
<br/>

## Detection 4: CVE-2026-76504 - Unauthenticated Admin-Level API Access on Cisco SD-WAN Manager

### Detection Opportunity

An unauthenticated remote attacker sends crafted HTTP requests to bypass authentication and achieves admin-level API access on Cisco Catalyst SD-WAN Manager.

### Intelligence Context

- Rapid7: Critical Cisco Catalyst SD-WAN Manager API authentication bypass exploited in the wild (CVE-2026-76504) — [https://www.rapid7.com/blog/post/etr-critical-cisco-catalyst-sd-wan-manager-api-authentication-bypass-exploited-in-the-wild-cve-2026-76504](https://www.rapid7.com/blog/post/etr-critical-cisco-catalyst-sd-wan-manager-api-authentication-bypass-exploited-in-the-wild-cve-2026-76504)
  - Context: CVE-2026-76504 allows an unauthenticated remote attacker to send a crafted HTTP request that bypasses an authentication rule on Cisco Catalyst SD-WAN Manager, granting API access with admin user privileges. Exploitation has been confirmed in the wild.

### Search Metadata

- CVEs: CVE-2026-76504
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Cisco Catalyst SD-WAN Manager
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-76504, T1190, Cisco Catalyst SD-WAN Manager

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
let lookback = 1h;
let authIPs = CommonSecurityLog
| where TimeGenerated >= ago(lookback)
| where DeviceVendor == "Cisco"
| where Activity has_any ("login", "authenticate", "auth")
| where ResponseCode in (200, 302)
| summarize by SourceIP;
CommonSecurityLog
| where TimeGenerated >= ago(lookback)
| where DeviceVendor == "Cisco"
| where RequestURL has_any ("/dataservice/", "/api/v1/")
| where ResponseCode == 200
| where Activity has_any ("admin", "Administrator")
| where SourceIP !in (authIPs)
| project
    HitTime = TimeGenerated,
    SourceIP,
    SourcePort,
    RequestURL,
    ResponseCode,
    Activity,
    DeviceVendor,
    DeviceProduct,
    DestinationHostName
| order by HitTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Service accounts or API clients that authenticate via mechanisms not logged as 'login'/'authenticate'/'auth' Activity values will appear as unauthenticated and trigger false positives.
- Load balancers or proxies that aggregate source IPs may cause legitimate authenticated sessions to appear unauthenticated if the proxy IP differs from the client IP in auth logs.
- Internal monitoring or health-check systems that poll API endpoints without standard authentication flows.

**Tuning notes:**
- Validate DeviceVendor, Activity, and RequestURL field values against actual CommonSecurityLog samples from the Cisco SD-WAN Manager before enabling as a scheduled rule.
- Add DeviceProduct filter if the environment forwards logs from multiple Cisco products to CommonSecurityLog to avoid cross-product false matches.
- Adjust the lookback window based on the SD-WAN Manager session token lifetime to ensure legitimate sessions are correctly excluded.
- If the SD-WAN Manager emits dedicated authentication failure or bypass-specific log events, incorporate those as higher-confidence signals.

**Risks / caveats:**
- CommonSecurityLog requires a CEF or syslog connector configured to receive logs from Cisco Catalyst SD-WAN Manager. If this connector is not deployed, the query returns no results.
- The DeviceVendor field value 'Cisco' must match the exact string emitted by the SD-WAN Manager CEF header. Cisco devices may emit 'Cisco Systems' or product-specific vendor strings depending on firmware version and syslog configuration.
- The RequestURL field is only populated in CommonSecurityLog if the SD-WAN Manager emits HTTP access log data in CEF format with the cs-uri or request field mapped. Many Cisco syslog configurations do not include HTTP request paths in CEF output.
- The Activity field values 'admin' and 'Administrator' for identifying admin-level API responses, and 'login', 'authenticate', 'auth' for authentication events, are assumptions about the SD-WAN Manager log format that must be validated against actual log samples.

### Triage Runbook

**First 15 minutes:**
- Confirm the target is a Cisco Catalyst SD-WAN Manager instance and that the request path and response code match the alert.
- Identify the source IP, source port, and destination host to determine whether the request came from an external address, proxy, or internal management network.
- Check whether the same source IP has nearby authentication events, and whether the request is part of a burst of API activity.
- Review the affected time window for signs of follow-on actions such as configuration changes, new admin sessions, or additional API calls.

**Evidence to collect:**
- HitTime, SourceIP, SourcePort, RequestURL, ResponseCode, Activity, DeviceVendor, DeviceProduct, and DestinationHostName.
- Raw CommonSecurityLog entries around the hit time, including any authentication, admin, or API activity from the same source IP.
- Cisco SD-WAN Manager audit logs or application logs showing configuration changes, user creation, or privilege changes.
- Network telemetry showing whether the source IP is external, NATed, or a known management system.

**Pivot points:**
- CommonSecurityLog for the same SourceIP and DestinationHostName over the last 24 hours to reconstruct request sequence.
- CommonSecurityLog for authentication, login, or admin events tied to the same host and source IP.
- If available, Cisco SD-WAN Manager audit or syslog tables for configuration changes and admin actions.
- Network firewall or proxy logs to validate whether the source IP is truly unauthenticated or behind a shared gateway.

**Benign explanations:**
- A legitimate API client or service account may not emit the expected authentication log values and can appear unauthenticated.
- A proxy, load balancer, or NAT device may obscure the true client identity and make a valid session look suspicious.
- Internal monitoring or health-check systems may poll API endpoints without standard interactive login behavior.

**Escalation criteria:**
- The source IP is external or untrusted and the request matches the vulnerable API path with a successful response.
- There is evidence of configuration changes, new admin activity, or other post-exploitation actions on the SD-WAN Manager.
- No legitimate authentication trail can be tied to the source IP, and the request pattern is consistent with exploitation in the wild.
- Multiple requests or multiple source IPs target the same SD-WAN Manager instance in a short period.

**Containment actions:**
- Restrict access to the SD-WAN Manager from untrusted networks or block the source IP at the perimeter if exploitation is suspected.
- If compromise is likely, place the SD-WAN Manager in a controlled maintenance state and preserve logs before making changes.
- Rotate credentials or tokens associated with the management plane if unauthorized admin access is confirmed.

**Closure criteria:**
- The request is confirmed as a legitimate management or monitoring action and the source is validated through logs or change records.
- No unauthorized configuration changes, admin actions, or follow-on exploitation are found.
- The alert is attributable to a known proxy, service account, or approved automation path after validation against raw logs.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- BPFDoor - Shell Script Written and Executed by Non-Interactive Process on Linux Appliance: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- CVE-2026-76504 - Unauthenticated Admin-Level API Access on Cisco SD-WAN Manager: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Shared-table notes:**
- DeviceFileEvents: shared by BPFDoor - Masqueraded Binaries Staged in /sbin (ntpdate or udevds); BPFDoor - Process Execution Followed by Self-Deletion in /sbin Within 30 Seconds; BPFDoor - Shell Script Written and Executed by Non-Interactive Process on Linux Appliance
- DeviceProcessEvents: shared by BPFDoor - Process Execution Followed by Self-Deletion in /sbin Within 30 Seconds; BPFDoor - Shell Script Written and Executed by Non-Interactive Process on Linux Appliance

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: BPFDoor - Masqueraded Binaries Staged in /sbin (ntpdate or udevds); BPFDoor - Process Execution Followed by Self-Deletion in /sbin Within 30 Seconds.
2. Resolve environment-mapping detections next: CVE-2026-76504 - Unauthenticated Admin-Level API Access on Cisco SD-WAN Manager.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: BPFDoor - Shell Script Written and Executed by Non-Interactive Process on Linux Appliance.

### Hunting Agenda and Promotion Criteria

- BPFDoor - Shell Script Written and Executed by Non-Interactive Process on Linux Appliance: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- CVE-2026-76504 - Unauthenticated Admin-Level API Access on Cisco SD-WAN Manager: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
