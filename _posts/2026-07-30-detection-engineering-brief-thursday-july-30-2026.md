---
layout: post
title: "Detection Engineering Brief - Thursday, July 30, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-30
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-63077
  - T1190
  - T1059
  - JetBrains TeamCity
  - CVE-2026-59309
  - CVE-2026-59310
  - VMware vCenter Server
  - VMware Directory Service
  - vCenter Syslog
  - T1046
  - SSH
  - Linux
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

2 production candidates, 1 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-63077, T1190, T1059, JetBrains TeamCity, CVE-2026-59309, CVE-2026-59310, VMware vCenter Server, VMware Directory Service, vCenter Syslog, T1046, SSH, Linux.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: TeamCity Post-Exploitation - Credential File Access by Unexpected Process (CVE-2026-63077); vCenter Auth Bypass - Anomalous vmdir Authentication Failure Sequence (CVE-2026-59309); SSH Bot - Post-Compromise Lateral SSH Scanning from Linux Host.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: TeamCity RCE - OS Command Execution Spawned from JVM Process (CVE-2026-63077)

### Detection Opportunity

Arbitrary OS commands executed by a child process spawned from the TeamCity server JVM process following unauthenticated HTTP exploitation

### Intelligence Context

- Rapid7: CVE-2026-63077: Critical unauthenticated remote code execution in JetBrains TeamCity — [https://www.rapid7.com/blog/post/etr-cve-2026-63077-critical-unauthenticated-remote-code-execution-in-jetbrains-teamcity](https://www.rapid7.com/blog/post/etr-cve-2026-63077-critical-unauthenticated-remote-code-execution-in-jetbrains-teamcity)
  - Context: An unauthenticated attacker exploiting CVE-2026-63077 abuses the TeamCity agent polling protocol to bypass authentication and execute arbitrary OS commands. The TeamCity server process (java.exe or teamcity-server) spawns shell interpreters such as cmd.exe, sh, or bash as child processes.

### Search Metadata

- CVEs: CVE-2026-63077
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: JetBrains TeamCity
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-63077, T1190, T1059, JetBrains TeamCity

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium); Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where (
    InitiatingProcessFileName =~ "java.exe"
    or InitiatingProcessCommandLine has_any ("teamcity-server", "TeamCity")
)
| where FileName in~ (
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "sh",
    "bash",
    "dash",
    "ksh",
    "zsh",
    "wscript.exe",
    "cscript.exe"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    FileName,
    ProcessCommandLine
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Other Java applications (e.g., Jenkins, Confluence, Elasticsearch) running on the same host as TeamCity will match the java.exe parent condition if host-scoping is not applied.
- Legitimate TeamCity build steps that invoke shell interpreters will generate events; these are distinguishable by AccountName matching the build-agent service account and ProcessCommandLine containing expected build tool invocations.

**Tuning notes:**
- Add a DeviceName filter referencing a dynamic list of TeamCity server hostnames to reduce noise from other Java application servers.
- Consider adding a ProcessCommandLine exclusion for known build-step patterns (e.g., lines containing 'gradlew', 'mvn', 'ant') when the AccountName matches the TeamCity service account.
- pwsh.exe added alongside powershell.exe to cover PowerShell 7+ on both Windows and Linux.

**Risks / caveats:**
- Linux process telemetry requires the Defender for Endpoint Linux agent to be deployed on TeamCity hosts; without it, sh/bash/dash/ksh/zsh child-process events will not appear in DeviceProcessEvents.
- Without scoping DeviceName to known TeamCity server hosts, any Java process on any monitored endpoint that spawns a shell will match; host-scoping via a dynamic list or watchlist is strongly recommended before scheduling.
- The 24-hour lookback window may generate high alert volume in environments with active build pipelines; consider reducing to 1h for scheduled rules with frequent evaluation.
- The InitiatingProcessCommandLine has_any (teamcity-server, TeamCity) branch may match developer workstations running local TeamCity instances; restrict to server-class hosts.

### Triage Runbook

**First 15 minutes:**
- Confirm the alerting host is a real TeamCity server and not another Java application server; verify DeviceName against your TeamCity server inventory.
- Review the parent/child process chain for the shell process and confirm it was spawned by java.exe or teamcity-server, not by a known build job or admin action.
- Check the ProcessCommandLine for obvious attacker activity such as curl, wget, powershell download cradles, encoded commands, or file staging paths.
- Look for nearby alerts or telemetry on the same host within the last hour, especially file reads from TeamCity config/data paths and outbound connections from the shell process.
- If the process lineage and command line are clearly malicious or unexplained, treat the host as compromised and move to containment immediately.

**Evidence to collect:**
- DeviceProcessEvents for the alert window, including full process lineage, command line, and AccountName/AccountDomain.
- Any DeviceFileEvents showing reads of TeamCity config or data files on the same DeviceName around the same time.
- DeviceNetworkEvents from the TeamCity host for outbound connections initiated by the shell or its children.
- TeamCity application logs and server logs covering the alert timestamp to identify the triggering HTTP request or agent polling abuse.
- A list of recent legitimate build jobs on the host to compare against the observed shell command line.

**Pivot points:**
- DeviceProcessEvents filtered to the same DeviceName and a 2-hour window around the alert to map parent/child process lineage.
- DeviceFileEvents on the same DeviceName for reads of TeamCity config/data directories and credential-related files.
- DeviceNetworkEvents on the same DeviceName for outbound connections from cmd.exe, powershell.exe, sh, bash, or python processes.
- TeamCity server logs or reverse proxy logs to identify unauthenticated requests, unusual agent polling, or exploitation timing.
- If available, correlate with the TeamCity post-exploitation credential file access detection on the same host.

**Benign explanations:**
- A legitimate TeamCity build step spawned a shell to run scripts, especially if the AccountName is the TeamCity service account and the command line matches normal build tooling.
- An administrator used an interactive shell for maintenance or troubleshooting on the TeamCity server.
- Another Java-based application on the same host spawned a shell if host scoping was incomplete.
- A scheduled backup, monitoring, or configuration management task launched a shell process on the server.

**Escalation criteria:**
- Shell command line contains attacker-like behavior such as download-and-execute, credential dumping, or suspicious file staging.
- The shell was spawned by java.exe/teamcity-server and there is no matching approved maintenance or build activity.
- You observe follow-on file access to TeamCity config/data paths or outbound connections from the spawned shell.
- Multiple suspicious child processes or repeated shell spawns occur on the same TeamCity host.

**Containment actions:**
- Isolate the TeamCity server from the network if the shell activity is unexplained or clearly malicious.
- Disable or rotate TeamCity service credentials and any credentials stored on the host if compromise is suspected.
- Preserve volatile evidence before rebooting or cleaning the host, including process tree, network connections, and relevant logs.
- Block suspicious outbound destinations if the shell established external connections.

**Closure criteria:**
- The process chain is confirmed as a known, approved TeamCity build or maintenance action.
- No suspicious command line, file access, or network activity is present beyond the expected build behavior.
- The host is validated as not being a TeamCity server or the alert is attributable to another known Java application after scoping review.
- Any suspicious activity has been investigated and ruled out with supporting logs and change records.

<br/>
---
<br/>

## Detection 2: TeamCity Post-Exploitation - Credential File Access by Unexpected Process (CVE-2026-63077)

### Detection Opportunity

Credential files stored in the TeamCity data directory accessed by a process other than the expected TeamCity service following exploitation

### Intelligence Context

- Rapid7: CVE-2026-63077: Critical unauthenticated remote code execution in JetBrains TeamCity — [https://www.rapid7.com/blog/post/etr-cve-2026-63077-critical-unauthenticated-remote-code-execution-in-jetbrains-teamcity](https://www.rapid7.com/blog/post/etr-cve-2026-63077-critical-unauthenticated-remote-code-execution-in-jetbrains-teamcity)
  - Context: Rapid7 explicitly states that attackers exploiting CVE-2026-63077 can read stored credentials from the TeamCity server. This post-exploitation behavior involves file reads of TeamCity configuration or data directory files by processes spawned after the initial RCE.

### Search Metadata

- CVEs: CVE-2026-63077
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: JetBrains TeamCity
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-63077, T1190, T1059, JetBrains TeamCity

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium); Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType == "FileRead"
| where FolderPath has_any (
    ".BuildServer",
    "TeamCity\\config",
    "TeamCity/config",
    "TeamCity\\data",
    "TeamCity/data",
    "teamcity\\lib",
    "teamcity/lib"
)
| where InitiatingProcessFileName !in~ ("java.exe", "teamcity-server")
| where InitiatingProcessFileName in~ (
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "sh",
    "bash",
    "dash",
    "python.exe",
    "python3",
    "curl",
    "wget",
    "cat"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    AccountDomain,
    FolderPath,
    FileName,
    ActionType,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Backup agents, configuration management tools, or antivirus scanners that read TeamCity data directory files will match if not excluded.
- Administrators using shell utilities (cat, type) to inspect TeamCity configuration files during maintenance will generate events.

**Tuning notes:**
- Add the actual TeamCity data directory path from the environment's TEAMCITY_DATA_PATH environment variable or server configuration to the FolderPath filter.
- Consider joining this query with the RCE detection results on DeviceName and a 30-minute time window to surface only file accesses that follow a confirmed shell-spawn event.
- Extend the InitiatingProcessFileName exclusion list to include any backup or monitoring agent process names observed in the environment.

**Risks / caveats:**
- DeviceFileEvents ActionType 'FileRead' and 'FileAccessed' are not guaranteed to be collected by all MDE agent configurations; file-read telemetry requires advanced hunting file-event collection to be enabled in the Defender for Endpoint policy.
- The FolderPath values '.BuildServer', 'TeamCity\config', 'TeamCity/config', 'TeamCity\data', 'TeamCity/data', 'teamcity\lib', 'teamcity/lib' reflect default installation paths only; non-default installation directories will not be matched and must be identified per environment before deployment.
- Non-default TeamCity installation paths will not be matched; the FolderPath list must be updated to reflect the actual data directory configured in the environment before this query produces meaningful results.
- FileRead ActionType availability depends on MDE advanced file-event collection policy being enabled; confirm this is active on TeamCity hosts before relying on this detection.

### Triage Runbook

**First 15 minutes:**
- Confirm the file path is within the TeamCity data/config area and identify the exact file accessed.
- Review the initiating process and its parent chain; verify it is not java.exe/teamcity-server or a known backup/monitoring agent.
- Check whether the process is a shell, scripting interpreter, or file utility that would be unusual for normal TeamCity operations.
- Correlate the file access time with any TeamCity RCE shell-spawn alert on the same host.
- If the process is unexpected and the file is credential-related, assume secret exposure until proven otherwise.

**Evidence to collect:**
- DeviceFileEvents for the same DeviceName and time window, including FolderPath, FileName, ActionType, and initiating process details.
- DeviceProcessEvents to reconstruct the process tree that led to the file read.
- Any TeamCity logs showing authentication failures, unusual requests, or service restarts near the file access time.
- Inventory of what secrets are stored in the accessed file, including service credentials, tokens, or database passwords.
- If available, evidence of outbound connections or subsequent authentication attempts using the same host or account.

**Pivot points:**
- DeviceFileEvents on the same DeviceName for all reads of TeamCity config/data paths in the preceding and following hour.
- DeviceProcessEvents for the initiating process and its parent to determine whether it was spawned by a shell or by TeamCity itself.
- DeviceNetworkEvents for the same host to identify exfiltration or post-access beaconing.
- TeamCity server logs to identify the exploitation window and any admin or build activity that could explain the access.
- If the file contains credentials, pivot to authentication logs for those accounts after the access time.

**Benign explanations:**
- A backup agent, antivirus scanner, or configuration management tool read TeamCity files as part of normal operations.
- An administrator used a shell utility to inspect TeamCity configuration during maintenance.
- A legitimate build or deployment process accessed files in the TeamCity data directory if the environment stores build artifacts there.
- The host is a non-TeamCity Java server or developer workstation with a local TeamCity instance and the path matched by broad scoping.

**Escalation criteria:**
- The accessing process is a shell, scripting interpreter, or downloader and is not an approved maintenance tool.
- The accessed file is known to contain credentials, tokens, or database secrets.
- The file access occurs shortly after a TeamCity RCE shell-spawn event on the same host.
- There is evidence of credential use, lateral movement, or outbound exfiltration after the file read.

**Containment actions:**
- Isolate the TeamCity server if unauthorized credential access is confirmed or strongly suspected.
- Rotate any credentials, tokens, or passwords stored in the accessed TeamCity files.
- Preserve the host and logs before remediation to support root-cause analysis.
- Block suspicious outbound destinations and disable any accounts whose secrets may have been exposed.

**Closure criteria:**
- The file access is attributed to a known backup, monitoring, or administrative process.
- The accessed file is not credential-bearing or the contents are already known to be non-sensitive.
- No supporting evidence of exploitation, shell execution, or post-access misuse is found.
- The environment-specific TeamCity path and expected readers have been validated and the event matches approved activity.

<br/>
---
<br/>

## Detection 3: vCenter Auth Bypass - Anomalous vmdir Authentication Failure Sequence (CVE-2026-59309)

### Detection Opportunity

Authentication bypass attempts against VMware Directory Service (vmdir/vmdird) reflected as authentication failure sequences in vCenter appliance syslog

### Intelligence Context

- Rapid7: Critical VMware vCenter Vulnerabilities Allow Authentication Bypass and Remote Code Execution (CVE-2026-59309, CVE-2026-59310) — [https://www.rapid7.com/blog/post/etr-critical-vmware-vcenter-vulnerabilities-allow-authentication-bypass-and-remote-code-execution-cve-2026-59309-cve-2026-59310](https://www.rapid7.com/blog/post/etr-critical-vmware-vcenter-vulnerabilities-allow-authentication-bypass-and-remote-code-execution-cve-2026-59309-cve-2026-59310)
  - Context: CVE-2026-59309 is an authentication bypass in the VMware Directory Service of vCenter. Exploitation by an unauthenticated network attacker produces anomalous authentication events in the vmdir or vmdird process logs forwarded via syslog. CVE-2026-59310 adds a directory traversal component via the vCenter Syslog service.

### Search Metadata

- CVEs: CVE-2026-59309, CVE-2026-59310
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: VMware vCenter Server, VMware Directory Service, vCenter Syslog
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-59309, CVE-2026-59310, T1190, VMware vCenter Server, VMware Directory Service, vCenter Syslog

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.

**Required telemetry:**
- Syslog

### KQL

```kql
let vcenter_hosts = dynamic(["vcenter", "vcsa"]);
let lookback = 1h;
let join_tolerance = 10m;
let auth_events = Syslog
| where TimeGenerated > ago(lookback)
| where HostName has_any (vcenter_hosts)
| where ProcessName in~ ("vmdir", "vmdird")
| where SyslogMessage has_any (
    "authentication failure",
    "auth bypass",
    "unauthorized",
    "bind failed",
    "invalid credentials"
)
| project auth_time = TimeGenerated, HostName, ProcessName, SyslogMessage, Facility, SeverityLevel;
let traversal_events = Syslog
| where TimeGenerated > ago(lookback)
| where HostName has_any (vcenter_hosts)
| where SyslogMessage matches regex @"(\.\./|%2e%2e%2f|%2e%2e/|\.%2e/)"
| project traversal_time = TimeGenerated, HostName, traversal_msg = SyslogMessage;
auth_events
| join kind=inner (
    traversal_events
) on HostName
| where traversal_time between (auth_time .. (auth_time + join_tolerance))
| project
    auth_time,
    HostName,
    ProcessName,
    SyslogMessage,
    Facility,
    SeverityLevel,
    traversal_msg,
    traversal_time
| order by auth_time desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrative LDAP bind failures during password changes or service restarts will match the auth failure keywords.
- Security scanners or vulnerability assessment tools probing the vCenter LDAP endpoint will generate matching auth failure messages.

**Tuning notes:**
- Replace the vcenter_hosts list values with the exact HostName strings observed in the Syslog table for the vCenter appliances in the environment.
- If ProcessName is not populated, replace the ProcessName in~ filter with SyslogMessage has_any ('vmdir', 'vmdird') as a fallback.
- Consider a standalone scheduled rule on auth_events alone (without the traversal join) to detect CVE-2026-59309 independently of CVE-2026-59310 traversal activity.
- Adjust join_tolerance based on observed timing between auth failure and traversal events in test exploitation scenarios.

**Risks / caveats:**
- The Syslog table is only populated if a syslog data connector (CEF, syslog forwarder, or Azure Monitor Agent syslog collection) is configured to receive vCenter appliance logs in the Sentinel workspace; without this connector the query returns no results.
- ProcessName field population depends on the syslog format sent by the vCenter appliance; if the appliance uses RFC 3164 without a structured program field, ProcessName may be empty or null, causing the vmdir/vmdird filter to match nothing.
- The leftouter join between auth_events and traversal_events on HostName alone without a time-bounded join condition may produce a Cartesian product if many traversal events exist for the same host within the lookback window, leading to result explosion.
- The vcenter_hosts dynamic list uses generic substring values ('vcenter', 'vcsa'); these must be replaced with the exact HostName values as they appear in ingested Syslog records for the query to scope correctly.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a vCenter appliance and identify whether the syslog messages are from vmdir or vmdird.
- Review the exact SyslogMessage sequence to determine if the failures are unusual, repeated, or paired with traversal indicators.
- Check whether the source IP or source host is a known admin workstation, vulnerability scanner, or management system.
- Look for concurrent vCenter service errors, restarts, or other signs of instability around the alert time.
- If the sequence is paired with traversal strings or repeated unauthenticated failures from an unknown source, escalate immediately.

**Evidence to collect:**
- Raw Syslog records for the alert window, including HostName, ProcessName, Facility, SeverityLevel, and full SyslogMessage text.
- vCenter appliance logs and any reverse proxy or load balancer logs in front of the appliance.
- Source IP information if present in the syslog forwarding path or adjacent network telemetry.
- Any authentication or directory service logs showing bind failures, invalid credentials, or unauthorized access attempts.
- Change records or maintenance windows that could explain legitimate LDAP or directory service failures.

**Pivot points:**
- Syslog on the same HostName for all vmdir/vmdird messages in a 1-hour window around the alert.
- Syslog for traversal patterns such as ../ or encoded traversal strings on the same host and time range.
- Network telemetry for inbound connections to the vCenter appliance from the same source IP if available.
- vCenter service logs to determine whether the failure sequence aligns with a restart, patching, or admin activity.
- If the environment has multiple vCenter appliances, compare the pattern across all appliances to identify spread or repeated targeting.

**Benign explanations:**
- A legitimate administrator mistyped credentials or triggered a bind failure during maintenance.
- A vulnerability scanner or security assessment tool probed the vCenter LDAP endpoint.
- A service restart or password rotation caused transient authentication failures.
- The syslog pattern is from a non-vCenter host whose hostname matched the generic scoping values.

**Escalation criteria:**
- Authentication failures are repeated and originate from an unknown or untrusted source.
- Traversal indicators appear in the same time window as the auth failures.
- There are signs of vCenter service instability, unexpected restarts, or additional suspicious syslog activity.
- The host is a confirmed vCenter appliance and the event cannot be explained by maintenance or scanning.

**Containment actions:**
- Restrict network access to the vCenter appliance from untrusted sources if exploitation is suspected.
- Engage virtualization administrators to assess whether the appliance should be taken offline or isolated.
- Preserve syslog and appliance logs before any restart or patching action.
- Block the source IP if it is clearly malicious and not part of approved scanning or admin activity.

**Closure criteria:**
- The event is attributed to approved administrative activity, a known scanner, or a maintenance window.
- No traversal indicators or additional suspicious vCenter activity are present.
- The host is not a confirmed vCenter appliance after scoping validation.
- The syslog pattern is consistent with expected password failures or service restarts and no further suspicious activity is observed.

<br/>
---
<br/>

## Detection 4: SSH Bot - Hardware Reconnaissance Followed by Cryptominer Deployment on Linux

### Detection Opportunity

SSH bot executes hardware enumeration commands then deploys a cryptominer with outbound connections to mining pool ports on a compromised Linux host

### Intelligence Context

- SANS ISC: Reconnaissance First: An SSH Bot That Sizes Up Your Hardware Before Deploying a Miner [Guest Diary], (Thu, Jul 30th) — [https://isc.sans.edu/diary/rss/33198](https://isc.sans.edu/diary/rss/33198)
  - Context: SANS ISC describes an SSH bot that first profiles hardware capabilities using commands such as lscpu, nproc, free, and dmidecode before deploying a cryptominer. The compound behavior of hardware reconnaissance followed by miner deployment and outbound mining pool connections is the distinguishing pattern.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1046, T1059
- Products: SSH
- Platforms: Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: T1046, T1059, SSH, Linux

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Discovery: T1046 Network Service Discovery (medium); Execution: T1059 Command and Scripting Interpreter (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let recon_window = 30m;
let recon_hosts = DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ ("sshd", "bash", "sh", "dash")
| where ProcessCommandLine has_any (
    "lscpu",
    "nproc",
    "dmidecode",
    "free -m",
    "free -h",
    "cat /proc/cpuinfo",
    "cat /proc/meminfo"
)
| summarize
    recon_count = count(),
    first_recon = min(Timestamp)
    by DeviceName, AccountName, AccountDomain;
let miner_connections = DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort in (3333, 4444, 14444, 45700, 5555, 8080)
| where InitiatingProcessFileName !in~ (
    "sshd",
    "systemd",
    "chronyd",
    "ntpd",
    "apt",
    "apt-get",
    "yum",
    "dnf",
    "zypper"
)
| project
    DeviceName,
    RemoteIP,
    RemotePort,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    miner_time = Timestamp;
recon_hosts
| join kind=inner (miner_connections) on DeviceName
| where miner_time between (first_recon .. (first_recon + recon_window))
| project
    first_recon,
    miner_time,
    DeviceName,
    AccountName,
    AccountDomain,
    recon_count,
    RemoteIP,
    RemotePort,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by first_recon desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Development or testing environments running local mining software for legitimate purposes will match.
- Outbound connections to ports 8080 and 5555 are common for web proxies and Android Debug Bridge respectively; these may generate false positives if not excluded.
- Hardware enumeration commands (lscpu, free, nproc) are routinely executed by monitoring agents and configuration management tools under shell parent processes.

**Tuning notes:**
- Remove ports 5555 and 8080 from the RemotePort list if they generate excessive false positives from legitimate services in the environment.
- Adjust recon_window to match observed timing between reconnaissance and miner deployment if telemetry shows a longer or shorter gap.
- Add AccountName exclusions for known monitoring service accounts that routinely execute hardware enumeration commands.

**Risks / caveats:**
- DeviceProcessEvents and DeviceNetworkEvents Linux telemetry requires the Defender for Endpoint Linux agent to be deployed and process/network event collection to be enabled on monitored hosts; without the agent these tables will contain no Linux records.
- Ports 5555 and 8080 are used by many legitimate services; consider removing them from the RemotePort list if false-positive volume is high in the environment.
- The 30-minute recon_window between hardware enumeration and miner connection is an assumption based on the SANS ISC report; actual dwell time may vary.
- Hardware enumeration commands executed by monitoring agents (e.g., Ansible, Puppet, Chef) under bash or sh parent processes will match the recon stage; these should be excluded by AccountName or InitiatingProcessCommandLine if identifiable.

### Triage Runbook

**First 15 minutes:**
- Verify the host is a Linux server and identify the account and shell process that ran the reconnaissance commands.
- Review the command line for lscpu, nproc, dmidecode, free, or /proc reads and determine whether they were executed interactively or by automation.
- Inspect the outbound connection details for the remote IP and port, and determine whether they match known mining pool patterns or suspicious high ports.
- Check for new or unusual processes, persistence artifacts, or downloaded binaries around the recon and connection times.
- If the host is not a known test system or automation node, treat the event as likely compromise.

**Evidence to collect:**
- DeviceProcessEvents showing the reconnaissance commands, parent process, and account context.
- DeviceNetworkEvents showing the outbound connection, remote IP, remote port, and initiating process command line.
- Any downloaded files, scripts, or binaries associated with the miner deployment.
- System logs for cron, systemd, shell history, or package manager activity around the alert time.
- Threat intelligence or reputation data for the remote IPs and ports involved in the outbound connections.

**Pivot points:**
- DeviceProcessEvents on the same DeviceName for all shell activity in the preceding and following 24 hours.
- DeviceNetworkEvents for the same host to identify additional outbound connections to mining ports or suspicious destinations.
- DeviceFileEvents for newly created or modified binaries, scripts, or cron entries on the host.
- Authentication logs to determine whether the account used for recon was a legitimate admin or a compromised service account.
- If available, pivot to other Linux hosts using the same account or remote IPs to identify spread.

**Benign explanations:**
- A monitoring, inventory, or configuration management tool ran hardware discovery commands as part of normal operations.
- A developer or administrator manually checked system resources before maintenance or troubleshooting.
- The outbound connection is to a legitimate service using a high port that overlaps with mining pool ports.
- The host is a lab or development system where mining software is intentionally installed.

**Escalation criteria:**
- Recon commands are followed by outbound connections to suspicious ports or known mining infrastructure.
- A miner binary, script, or persistence mechanism is found on the host.
- The account or shell context is not associated with approved automation or administration.
- Additional hosts show the same pattern or the same remote IPs are contacted from multiple systems.

**Containment actions:**
- Isolate the Linux host from the network if miner deployment or active compromise is confirmed.
- Terminate the suspicious miner process and remove persistence only after preserving evidence if your process allows it.
- Block the remote IPs and ports associated with the mining activity.
- Reset credentials for any account used on the compromised host if credential theft is suspected.

**Closure criteria:**
- The recon commands are attributable to approved automation, monitoring, or maintenance.
- The outbound connection is confirmed to be legitimate and not associated with mining infrastructure.
- No miner binary, persistence, or suspicious follow-on activity is found.
- The host is a sanctioned lab or test system where this behavior is expected and documented.

<br/>
---
<br/>

## Detection 5: SSH Bot - Post-Compromise Lateral SSH Scanning from Linux Host

### Detection Opportunity

Compromised Linux host initiates outbound SSH connections to multiple distinct remote IPs in rapid succession following an inbound SSH session, indicating SSH-based lateral movement or scanning

### Intelligence Context

- SANS ISC: Reconnaissance First: An SSH Bot That Sizes Up Your Hardware Before Deploying a Miner [Guest Diary], (Thu, Jul 30th) — [https://isc.sans.edu/diary/rss/33198](https://isc.sans.edu/diary/rss/33198)
  - Context: The SSH bot described by SANS ISC performs reconnaissance and deployment behaviors consistent with a self-propagating bot that scans for additional SSH targets after gaining initial access. Post-compromise outbound SSH scanning from the victim host to multiple new IPs is a distinguishing lateral movement indicator.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1046, T1059
- Products: SSH
- Platforms: Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: T1046, T1059, SSH, Linux

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Discovery: T1046 Network Service Discovery (medium); Execution: T1059 Command and Scripting Interpreter (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- If 'InboundConnectionAccepted' is not a populated ActionType in the environment's DeviceNetworkEvents, the inbound_ssh subquery returns no rows and the detection produces no results; confirm ActionType values present in the workspace before relying on this query.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
let scan_window = 15m;
let inbound_ssh = DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort == 22
| where ActionType == "InboundConnectionAccepted"
| project DeviceName, inbound_time = Timestamp, inbound_src = RemoteIP;
let outbound_ssh = DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort == 22
| where ActionType in ("ConnectionSuccess", "ConnectionAttempt")
| where InitiatingProcessFileName in~ ("ssh", "bash", "sh", "dash")
| project DeviceName, outbound_time = Timestamp, outbound_dst = RemoteIP;
inbound_ssh
| join kind=inner (outbound_ssh) on DeviceName
| where outbound_time between (inbound_time .. (inbound_time + scan_window))
| summarize
    distinct_targets = dcount(outbound_dst),
    targets = make_set(outbound_dst, 20),
    first_inbound = min(inbound_time),
    first_outbound = min(outbound_time)
    by DeviceName, inbound_src
| where distinct_targets >= 5
| order by distinct_targets desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Linux jump hosts and bastion servers that receive inbound SSH sessions and then fan out to many managed hosts will match this pattern at high volume.
- Automated configuration management tools (Ansible, Fabric) that SSH from a control node to many targets after receiving a trigger connection will match.
- Developers using SSH agent forwarding through a shared Linux host to reach multiple targets will match.

**Tuning notes:**
- Before scheduling, run a baseline query to confirm 'InboundConnectionAccepted' is present in ActionType for the Linux hosts in the environment; if absent, consider using LocalPort == 22 with ActionType == 'NetworkConnectionEvents' as an alternative inbound anchor if available.
- Increase distinct_targets to 10 or higher if the environment includes Linux jump hosts that legitimately fan out SSH connections.
- Exclude known jump host and bastion server DeviceName values to reduce false positives from legitimate SSH management infrastructure.
- Consider promoting to a scheduled rule only after confirming ActionType availability and validating the threshold against at least two weeks of baseline telemetry.

**Risks / caveats:**
- ActionType 'InboundConnectionAccepted' availability in DeviceNetworkEvents depends on the MDE Linux agent version and network event collection configuration; if this ActionType is not present in the workspace the inbound_ssh subquery returns no results and the join produces nothing.
- DeviceNetworkEvents Linux telemetry requires the Defender for Endpoint Linux agent to be deployed on monitored hosts.
- If 'InboundConnectionAccepted' is not a populated ActionType in the environment's DeviceNetworkEvents, the inbound_ssh subquery returns no rows and the detection produces no results; confirm ActionType values present in the workspace before relying on this query.
- The distinct_targets threshold of 5 and the 15-minute scan_window are assumptions; these must be validated against SSH management baselines in the environment before scheduling.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is not a known bastion, jump host, or automation node before treating the behavior as malicious.
- Review the inbound SSH session source and the subsequent outbound SSH destinations to understand the scan pattern.
- Check whether the outbound SSH activity is initiated by ssh, bash, or sh and whether it occurs shortly after the inbound session.
- Look for signs of credential abuse, new accounts, or unauthorized key-based access on the host.
- If the host is not a sanctioned management system and is fanning out to many targets, escalate as likely compromise.

**Evidence to collect:**
- DeviceNetworkEvents showing the inbound SSH acceptance and the outbound SSH connections, including source and destination IPs.
- DeviceProcessEvents for any shell activity, command execution, or scripts launched during the scan window.
- Authentication logs, SSH authorized_keys changes, and shell history from the host if available.
- A list of outbound target IPs and whether they belong to internal production, lab, or management networks.
- Any alerts on the same host indicating brute force, credential theft, or malware execution.

**Pivot points:**
- DeviceNetworkEvents on the same DeviceName for all SSH-related inbound and outbound activity over the last 24 hours.
- DeviceProcessEvents for shell commands and scripts executed around the first inbound SSH session.
- Authentication logs for repeated logins, new users, or key changes on the host.
- Asset inventory to determine whether the host is a jump server, bastion, or ordinary Linux endpoint.
- If available, pivot to the outbound target hosts to see whether they also received suspicious SSH attempts.

**Benign explanations:**
- A legitimate jump host or bastion server receives an inbound SSH session and then connects to many managed hosts.
- An automation tool such as Ansible or Fabric triggered SSH fan-out after a control connection.
- A developer used SSH agent forwarding or a management script that legitimately touched multiple systems.
- The host is a shared admin server where this pattern is expected and documented.

**Escalation criteria:**
- The host is not a known jump host or automation node and still shows rapid SSH fan-out.
- Outbound targets include many distinct internal systems in a short window.
- There is evidence of unauthorized login, new keys, or suspicious shell commands on the host.
- The same pattern appears on multiple hosts or is accompanied by other compromise indicators.

**Containment actions:**
- Isolate the host if it is not an approved management system and the SSH fan-out is unexplained.
- Disable or rotate credentials and SSH keys used on the host if compromise is suspected.
- Block outbound SSH from the host temporarily if it is actively scanning internal systems.
- Preserve logs and shell history before remediation.

**Closure criteria:**
- The host is confirmed as a sanctioned bastion, jump server, or automation node.
- The outbound SSH activity matches approved administrative workflows and target sets.
- No unauthorized login, key change, or suspicious shell activity is found.
- The alert is attributable to expected management traffic after validation with the system owner.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Other deployment dependency:**
- TeamCity Post-Exploitation - Credential File Access by Unexpected Process (CVE-2026-63077): Defender for Endpoint file-event coverage must be confirmed on the target host population.
- SSH Bot - Post-Compromise Lateral SSH Scanning from Linux Host: If 'InboundConnectionAccepted' is not a populated ActionType in the environment's DeviceNetworkEvents, the inbound_ssh subquery returns no rows and the detection produces no results; confirm ActionType values present in the workspace before relying on this query.

**Telemetry availability:**
- vCenter Auth Bypass - Anomalous vmdir Authentication Failure Sequence (CVE-2026-59309): Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.

**Schema / correlation keys:**
- SSH Bot - Post-Compromise Lateral SSH Scanning from Linux Host: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- DeviceProcessEvents: shared by TeamCity RCE - OS Command Execution Spawned from JVM Process (CVE-2026-63077); SSH Bot - Hardware Reconnaissance Followed by Cryptominer Deployment on Linux
- DeviceNetworkEvents: shared by SSH Bot - Hardware Reconnaissance Followed by Cryptominer Deployment on Linux; SSH Bot - Post-Compromise Lateral SSH Scanning from Linux Host

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: TeamCity RCE - OS Command Execution Spawned from JVM Process (CVE-2026-63077); SSH Bot - Hardware Reconnaissance Followed by Cryptominer Deployment on Linux.
2. Resolve environment-mapping detections next: TeamCity Post-Exploitation - Credential File Access by Unexpected Process (CVE-2026-63077); vCenter Auth Bypass - Anomalous vmdir Authentication Failure Sequence (CVE-2026-59309).
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: SSH Bot - Post-Compromise Lateral SSH Scanning from Linux Host.

### Hunting Agenda and Promotion Criteria

- SSH Bot - Post-Compromise Lateral SSH Scanning from Linux Host: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- TeamCity Post-Exploitation - Credential File Access by Unexpected Process (CVE-2026-63077): Defender for Endpoint file-event coverage must be confirmed on the target host population.; confirm required file-access telemetry exists and produces representative events; prove correlation keys join correctly on real tenant telemetry.
- vCenter Auth Bypass - Anomalous vmdir Authentication Failure Sequence (CVE-2026-59309): Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

This run exposes a file-access telemetry blind spot: browser cookie theft and resource-file loader behaviors depend on file-read style events that may not be emitted in every Defender deployment. Validate that coverage before treating these as scheduled analytics.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
