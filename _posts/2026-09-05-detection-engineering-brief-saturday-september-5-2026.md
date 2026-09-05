---
layout: post
title: "Detection Engineering Brief - Saturday, September 5, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-05
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - T1059
  - Linux
  - server
  - ted backdoor
  - curlRAT
  - crond
  - agetty
  - atd
  - sshd
  - polkitd
  - HAProxy
  - Microsoft Teams
  - Microsoft Defender
  - Windows
  - Node.js
  - Toy Ghouls
  - HiveMQ
  - backdoor
  - email
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 3 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 3 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: T1059, Linux, server, ted backdoor, curlRAT, crond, agetty, atd, sshd, polkitd, HAProxy, Microsoft Teams, Microsoft Defender, Windows, Node.js, Toy Ghouls, HiveMQ, backdoor, email.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Trojanized Linux Service Binary Hash Deviation Detected; Shell Command Execution Spawned by Trojanized Linux Service Binary with Outbound Network Connection; Node.js Implant Execution from Unusual Parent or Path Following Teams External Access; Invisible Unicode Tag Characters Detected in Inbound Email Subject or Metadata.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Trojanized Linux Service Binary Hash Deviation Detected

### Detection Opportunity

Trojanized versions of legitimate Linux service binaries (crond, agetty, atd, sshd, polkitd) executed on compromised servers as part of DPRK-linked backdoor deployment.

### Intelligence Context

- Rapid7: DPRK APTs: Ted backdoor and curlRAT target South Korean media and automotive sectors — [https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors](https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors)
  - Context: DPRK-linked threat actors deployed trojanized versions of crond, agetty, atd, sshd, and polkitd on Linux servers targeting South Korean media and automotive organizations. The binaries retained legitimate names but carried malicious code, making hash deviation the primary detection signal.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059
- Products: crond, agetty, atd, sshd, polkitd
- Platforms: Linux, server
- Malware: ted backdoor, curlRAT
- Tools: Not specified
- Search tags: T1059, Linux, server, ted backdoor, curlRAT, crond, agetty, atd, sshd, polkitd, HAProxy

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let ServiceBinaries = dynamic(["crond", "agetty", "atd", "sshd", "polkitd"]);
let ServicePaths = dynamic(["/usr/sbin", "/usr/bin", "/sbin", "/bin"]);
let PackageManagers = dynamic(["rpm", "dpkg", "apt", "apt-get", "yum", "dnf", "zypper", "packagekitd"]);
let SuspiciousFileWrites = DeviceFileEvents
| where FileName in (ServiceBinaries)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath has_any (ServicePaths)
| where isnotempty(SHA256)
| where not(InitiatingProcessFileName in (PackageManagers))
| project DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, FileWriteTime = TimeGenerated;
let SubsequentExecution = DeviceProcessEvents
| where FileName in (ServiceBinaries)
| project DeviceName, ExecFileName = FileName, ProcessCommandLine, ExecutionTime = TimeGenerated, AccountName;
SuspiciousFileWrites
| join kind=inner SubsequentExecution on DeviceName, $left.FileName == $right.ExecFileName
| where ExecutionTime between (FileWriteTime .. (FileWriteTime + 1h))
| project
    DeviceName,
    FileName,
    FolderPath,
    SHA256,
    InitiatingProcessFileName,
    FileWriteTime,
    ProcessCommandLine,
    AccountName,
    ExecutionTime
| order by FileWriteTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Manual binary replacement during legitimate system administration (e.g., sysadmin copying a patched sshd outside of a package manager).
- Configuration management tools such as Ansible, Chef, or Puppet that write binaries directly without invoking a package manager.
- Container image layer extraction or chroot environment setup that writes service binaries to disk.

**Tuning notes:**
- To enable true hash-deviation detection, populate a Sentinel watchlist with known-good SHA256 values for each service binary per Linux distribution and version, then join against it and filter where SHA256 is not in the watchlist.
- Adjust the 1-hour execution window based on observed service restart behavior in the environment.
- Consider scoping to specific device groups (e.g., internet-facing servers) to reduce volume during initial deployment.

**Risks / caveats:**
- DeviceFileEvents SHA256 field is only populated when Defender for Endpoint performs file hashing; on Linux agents this depends on agent version and file size thresholds — large binaries may not be hashed inline.
- DeviceFileEvents ActionType values 'FileCreated', 'FileModified', and 'FileRenamed' must be confirmed as supported on the Linux MDE agent version deployed; some ActionType strings differ between Windows and Linux telemetry.
- No known-good SHA256 baseline is embedded; the rule detects the write-then-execute pattern but cannot confirm hash deviation without a reference watchlist.
- The 1-hour join window between file write and execution may miss delayed service restarts (e.g., after a reboot) or generate noise if the binary is executed frequently.

### Triage Runbook

**First 15 minutes:**
- Validate the host is a real server and identify the affected service binary, path, SHA256, and write time.
- Check whether the initiating process was a package manager or a legitimate configuration tool; if not, treat as suspicious.
- Review the subsequent execution event to see which account ran the binary and whether the command line or service behavior is abnormal.
- Compare the SHA256 against any known-good baseline or package inventory for that Linux distribution and version.
- If the host is internet-facing or production-critical, prioritize immediate isolation planning while you continue validation.

**Evidence to collect:**
- DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, FileWriteTime, ExecutionTime, AccountName, ProcessCommandLine.
- Any package-management or configuration-management logs showing why the binary was written.
- Service state and recent changes for the affected binary or daemon.
- Other file writes or process executions on the same host around the same time, especially to /usr/sbin, /usr/bin, /sbin, or /bin.

**Pivot points:**
- DeviceFileEvents for the same DeviceName and SHA256 to find additional writes, renames, or modifications.
- DeviceProcessEvents for the same DeviceName and FileName to identify parent/child process chains and repeated executions.
- DeviceNetworkEvents for the host to look for outbound connections after the binary execution.
- If available, host or package manager logs to confirm whether the binary matches an approved package version.

**Benign explanations:**
- A sysadmin manually replaced a service binary during emergency patching.
- Ansible, Chef, Puppet, or a similar tool wrote the binary directly without invoking a package manager.
- Container image extraction or chroot setup wrote a legitimate service binary into a standard path.

**Escalation criteria:**
- The initiating process is not a known package manager or approved deployment tool.
- The SHA256 does not match any approved baseline for that host or OS build.
- The binary was executed by an unexpected account or followed by suspicious outbound activity.
- Multiple core service binaries on the same host show similar write-then-execute behavior.

**Containment actions:**
- If compromise is likely, isolate the host from the network while preserving access for forensics.
- Disable or stop the affected service only if doing so will not cause unacceptable business impact.
- Preserve the suspicious binary and relevant logs before remediation or replacement.

**Closure criteria:**
- The binary hash matches an approved baseline and the write is explained by a sanctioned change or deployment.
- The execution is confirmed as legitimate service maintenance with no other suspicious host activity.
- No additional malicious processes, network connections, or persistence indicators are found on the host.

<br/>
---
<br/>

## Detection 2: Shell Command Execution Spawned by Trojanized Linux Service Binary with Outbound Network Connection

### Detection Opportunity

Remote commands executed on compromised Linux servers via backdoored service binaries (crond, sshd) with associated outbound network connections, consistent with ted backdoor or curlRAT C2 activity.

### Intelligence Context

- Rapid7: DPRK APTs: Ted backdoor and curlRAT target South Korean media and automotive sectors — [https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors](https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors)
  - Context: Trojanized Linux service binaries enabled threat actors to execute remote commands on compromised servers. Detection correlates shell processes spawned by service binaries with outbound network connections to identify active C2 command execution.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059
- Products: crond, sshd, HAProxy
- Platforms: Linux, server
- Malware: ted backdoor, curlRAT
- Tools: Not specified
- Search tags: T1059, Linux, server, ted backdoor, curlRAT, crond, sshd, HAProxy

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let ServiceBinaries = dynamic(["crond", "agetty", "atd", "sshd", "polkitd"]);
let ShellInterpreters = dynamic(["bash", "sh", "dash", "zsh", "python", "python3", "perl"]);
let ExcludedPorts = dynamic([22, 53, 80, 443, 8080, 8443]);
let ShellsFromServices = DeviceProcessEvents
| where InitiatingProcessFileName in (ServiceBinaries)
| where FileName in (ShellInterpreters)
| where isnotempty(ProcessCommandLine)
| project DeviceName, AccountName, InitiatingProcessFileName, ShellFileName = FileName, ProcessCommandLine, ShellTime = TimeGenerated;
let OutboundConns = DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where isnotempty(RemoteIP)
| where not(ipv4_is_private(RemoteIP))
| where not(RemotePort in (ExcludedPorts))
| project DeviceName, RemoteIP, RemotePort, ConnTime = TimeGenerated;
ShellsFromServices
| join kind=inner OutboundConns on DeviceName
| where ConnTime between (ShellTime .. (ShellTime + 5m))
| project
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    ShellFileName,
    ProcessCommandLine,
    ShellTime,
    RemoteIP,
    RemotePort,
    ConnTime
| order by ShellTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- sshd spawning bash for legitimate interactive SSH sessions followed by any outbound connection from the same host within 5 minutes.
- crond executing scheduled maintenance scripts that make outbound connections to monitoring or update endpoints.
- Automation frameworks (Ansible, Fabric) that connect via SSH and run shell commands with subsequent outbound calls.

**Tuning notes:**
- Add known internal management IP ranges to the OutboundConns filter using an ipv4_is_in_range() expression to reduce noise from legitimate internal traffic.
- Consider adding a ProcessCommandLine filter to exclude common legitimate cron payloads (e.g., backup scripts, monitoring agents) by keyword.
- Extend the port exclusion list to cover any additional legitimate service ports in the environment before promoting to a scheduled rule.

**Risks / caveats:**
- DeviceNetworkEvents InitiatingProcessFileName is not always populated for all connection types on Linux MDE agent; connections initiated by child processes of the shell may attribute to the shell rather than the service binary.
- ipv4_is_private() does not cover IPv6 private ranges; if the environment uses IPv6 for C2 egress, those connections will not be caught.
- sshd spawning shells for legitimate interactive sessions is a high-volume FP source; without additional behavioral filters (e.g., unusual command content, non-standard AccountName), alert volume may be high.
- The 5-minute correlation window is a heuristic; C2 beacons with longer intervals will not be correlated.

### Triage Runbook

**First 15 minutes:**
- Confirm the parent process, shell/interpreter name, account, and command line for the shell execution.
- Review the outbound RemoteIP and RemotePort to determine whether the connection is external and suspicious.
- Check whether the shell was spawned by sshd during a legitimate admin session or by crond during a scheduled task.
- Look for repeated shell launches or multiple outbound connections from the same host in the same time window.
- If the host is a server with no expected interactive shell use, treat the alert as likely compromise and prepare containment.

**Evidence to collect:**
- DeviceName, AccountName, InitiatingProcessFileName, ShellFileName, ProcessCommandLine, ShellTime, RemoteIP, RemotePort, ConnTime.
- Any SSH session logs, cron job definitions, or service logs that explain the shell spawn.
- Network reputation and geolocation for the RemoteIP.
- Other process activity on the host around the same time, especially privilege escalation or persistence.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and InitiatingProcessFileName to find additional shell spawns.
- DeviceNetworkEvents for the same DeviceName and RemoteIP to identify other connections from the host.
- DeviceFileEvents for recent writes to service binaries or suspicious scripts on the host.
- Authentication or SSH logs, if available, to validate whether the shell was user-initiated.

**Benign explanations:**
- A legitimate interactive SSH session spawned bash or sh on the server.
- A cron job or maintenance script launched a shell and then made a normal outbound call.
- Automation tooling such as Ansible or Fabric executed remote commands during approved maintenance.

**Escalation criteria:**
- The shell was not tied to a known admin session, cron job, or approved automation.
- The outbound IP is untrusted, newly observed, or associated with suspicious infrastructure.
- The host shows additional signs of compromise such as persistence, privilege escalation, or lateral movement.
- The same host generates repeated shell-plus-network correlations in a short period.

**Containment actions:**
- If the connection appears malicious, isolate the host or block the suspicious destination at the network edge.
- Suspend the affected service or account only if needed to stop active command execution.
- Preserve process, network, and authentication evidence before remediation.

**Closure criteria:**
- The shell is confirmed as a legitimate admin or automation action and the outbound connection is expected.
- No suspicious follow-on activity, persistence, or additional external connections are found.
- The RemoteIP is validated as a sanctioned internal or management endpoint and the process chain is approved.

<br/>
---
<br/>

## Detection 3: Node.js Implant Execution from Unusual Parent or Path Following Teams External Access

### Detection Opportunity

A Node.js-based implant deployed on Windows endpoints after IT support impersonation via Microsoft Teams external collaboration, with node.exe spawned from non-standard parent processes or user-writable directories.

### Intelligence Context

- Microsoft Security Blog: Impersonating IT support: how threat actors turn a remote session into enterprise-wide access — [https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/](https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/)
  - Context: Threat actors impersonated IT support via Microsoft Teams external collaboration to gain remote access, then deployed a Node.js-based implant on Windows endpoints. The implant was executed from unusual parent processes or user-writable paths and established outbound network connections for C2.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059
- Products: Microsoft Teams, Microsoft Defender
- Platforms: Windows
- Malware: Not specified
- Tools: Node.js
- Search tags: T1059, Microsoft Teams, Microsoft Defender, Windows, Node.js

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Both
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- OfficeActivity is a Microsoft Sentinel table and is not available natively in Defender XDR Advanced Hunting; this query requires a Sentinel workspace with the Office 365 connector enabled.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents, OfficeActivity

### KQL

```kql
let SuspiciousParents = dynamic(["cmd.exe", "powershell.exe", "powershell_ise.exe", "mshta.exe", "wscript.exe", "cscript.exe", "explorer.exe"]);
let SuspiciousNodeExec = DeviceProcessEvents
| where FileName =~ "node.exe"
| where InitiatingProcessFileName in~ (SuspiciousParents)
    or tolower(FolderPath) has_any ("\\appdata\\", "\\temp\\", "\\users\\public\\")
| project DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, NodeTime = TimeGenerated;
let NodeOutbound = DeviceNetworkEvents
| where InitiatingProcessFileName =~ "node.exe"
| where ActionType == "ConnectionSuccess"
| where isnotempty(RemoteIP)
| where not(ipv4_is_private(RemoteIP))
| project DeviceName, RemoteIP, RemotePort, NetTime = TimeGenerated;
let TeamsExternalAccess = OfficeActivity
| where OfficeWorkload == "MicrosoftTeams"
| where Operation in ("MessageCreatedHasLink", "MessagesListed", "MessageSent", "MemberAdded")
| where ExternalAccess == true
| project UserId, TeamsTime = TimeGenerated;
SuspiciousNodeExec
| join kind=inner NodeOutbound on DeviceName
| where NetTime between (NodeTime .. (NodeTime + 30m))
| join kind=leftouter TeamsExternalAccess on $left.AccountName == $right.UserId
| extend TeamsCorrelated = isnotempty(TeamsTime) and TeamsTime between ((NodeTime - 2h) .. NodeTime)
| project
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    NodeTime,
    RemoteIP,
    RemotePort,
    NetTime,
    TeamsTime,
    TeamsCorrelated
| order by TeamsCorrelated desc, NodeTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Developer workstations where node.exe is legitimately launched from cmd.exe or powershell.exe for development or build tasks.
- CI/CD agents that run node.exe from Temp or AppData directories as part of build pipelines.
- Electron-based applications (e.g., VS Code, Slack) that embed node.exe and may be launched from explorer.exe.
- Teams external access events from legitimate external collaborators coincidentally preceding unrelated node.exe activity.

**Tuning notes:**
- Scope DeviceProcessEvents to specific device groups (e.g., non-developer endpoints) using a DeviceName not in (...) filter or a Sentinel watchlist to reduce FP volume.
- Add known legitimate node.exe FolderPath values (e.g., Program Files\nodejs) to an exclusion filter if node.exe is installed enterprise-wide.
- Adjust the 2-hour Teams lookback window based on observed attacker dwell time between initial Teams contact and implant execution.
- Consider promoting to a scheduled_rule scoped to endpoints where Node.js is not an approved runtime, using a device group tag or watchlist.

**Risks / caveats:**
- OfficeActivity is a Microsoft Sentinel table and is not available natively in Defender XDR Advanced Hunting; this query requires a Sentinel workspace with the Office 365 connector enabled.
- The ExternalAccess field in OfficeActivity for Teams events is not guaranteed to be populated in all tenant configurations; tenants without external access audit logging enabled will have null values, causing the Teams correlation leg to silently produce no results.
- OfficeActivity Teams Operation values ('MessageCreatedHasLink', 'MessagesListed', 'MessageSent', 'MemberAdded') must be confirmed as available in the tenant's audit log schema; not all Operations are enabled by default.
- The OfficeActivity Teams leg requires the Microsoft 365 audit log connector to be enabled in Sentinel and the tenant to have Teams audit logging configured; without this, TeamsCorrelated will always be false.

### Triage Runbook

**First 15 minutes:**
- Validate the node.exe parent process, folder path, command line, and account to determine whether execution is unusual.
- Check whether the device is a developer or build system where node.exe is expected.
- Review the outbound RemoteIP and RemotePort for suspicious external communication after node.exe starts.
- Confirm whether the Teams external access event is real and whether it occurred before the node.exe execution.
- If the endpoint is not a developer machine and the path is user-writable, treat the alert as high risk.

**Evidence to collect:**
- DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, NodeTime, RemoteIP, RemotePort, NetTime, TeamsTime, TeamsCorrelated.
- OfficeActivity details for the Teams event, including UserId, Operation, and ExternalAccess.
- Any recent downloads, script execution, or archive extraction that preceded node.exe.
- Network reputation and destination details for the RemoteIP.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName to find other suspicious child processes, script hosts, or LOLBins.
- DeviceNetworkEvents for the same DeviceName and RemoteIP to identify additional beaconing or lateral movement.
- OfficeActivity for the same UserId to review other Teams external collaboration events.
- DeviceFileEvents for recent writes in AppData, Temp, or Users\Public on the same host.

**Benign explanations:**
- A developer workstation legitimately launched node.exe from a user-writable path.
- A CI/CD or build agent used node.exe as part of an approved pipeline.
- An Electron-based application embedded node.exe and was launched from explorer.exe.

**Escalation criteria:**
- node.exe is running from an unusual parent or user-writable directory on a non-developer endpoint.
- The Teams external access event is confirmed and temporally aligns with the suspicious execution.
- The host makes external connections to an untrusted IP or shows additional malicious process activity.
- The same user or device shows repeated suspicious node.exe launches or related script execution.

**Containment actions:**
- If compromise is likely, isolate the endpoint from the network.
- Terminate the suspicious node.exe process only if active malicious behavior is confirmed and containment is needed.
- Reset or disable the affected account if there is evidence of credential abuse or remote support impersonation.

**Closure criteria:**
- The node.exe execution is confirmed as legitimate development, build, or approved application activity.
- The Teams event is unrelated or not present, and no suspicious network or file activity is found.
- The process path, parent, and command line match an approved software baseline.

<br/>
---
<br/>

## Detection 4: Outbound MQTT Connection to Port 1883 or 8883 from Non-IoT Endpoint Process

### Detection Opportunity

Toy Ghouls backdoor using HiveMQ MQTT broker on ports 1883/8883 for C2 communications from compromised endpoints running unexpected processes.

### Intelligence Context

- Securelist: Angry Birds: Toy Ghouls' new toys — [https://securelist.com/toy-ghouls-new-hivemq-and-element-backdoors/121270/](https://securelist.com/toy-ghouls-new-hivemq-and-element-backdoors/121270/)
  - Context: Toy Ghouls deployed a backdoor that uses the HiveMQ MQTT broker as its C2 server, communicating over MQTT ports 1883 and 8883. Detection targets outbound connections to these ports from processes that are not expected IoT management tools.

### Search Metadata

- CVEs: Not specified
- Threat actors: Toy Ghouls
- ATT&CK tags: Not specified
- Products: HiveMQ
- Platforms: Not specified
- Malware: backdoor
- Tools: Not specified
- Search tags: Toy Ghouls, HiveMQ, backdoor

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Not mapped

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
let KnownMqttClients = dynamic(["mosquitto", "mqtt", "hivemq", "mqttfx"]);
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where RemotePort in (1883, 8883)
| where isnotempty(RemoteIP)
| where not(ipv4_is_private(RemoteIP))
| where not(InitiatingProcessFileName has_any (KnownMqttClients))
| summarize
    ConnectionCount = count(),
    RemoteIPs = make_set(RemoteIP, 50),
    RemoteUrls = make_set(RemoteUrl, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemotePort
| order by LastSeen desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- IoT management platforms or industrial control system software that use MQTT for legitimate device telemetry.
- Development or testing environments where MQTT brokers are used for application development.
- Security research tools or packet capture utilities that connect to MQTT test brokers.

**Tuning notes:**
- Add known legitimate MQTT client process names specific to the environment to the KnownMqttClients list before promoting to a scheduled rule.
- Add known legitimate MQTT broker IP ranges (e.g., AWS IoT, Azure IoT Hub) to a RemoteIP exclusion filter if IoT management is present.
- Consider restricting to specific device groups where MQTT is not expected to reduce volume.

**Risks / caveats:**
- RemoteUrl may not be populated for all TCP connections in DeviceNetworkEvents; the aggregation includes it as a set but analysts should not rely on it being present for every record.
- ipv4_is_private() does not cover IPv6 addresses; MQTT C2 over IPv6 will not be filtered.
- Environments with legitimate IoT management software not covered by the KnownMqttClients list will generate FPs until the exclusion list is tuned.
- MQTT over TLS on port 8883 to a public cloud MQTT broker (e.g., AWS IoT, Azure IoT Hub) used for legitimate device management will appear as a hit.

### Triage Runbook

**First 15 minutes:**
- Identify the initiating process, its folder path, and whether the host is expected to use MQTT.
- Check whether the destination IP or URL is a known broker, cloud IoT service, or internal management platform.
- Review the connection count and timing to see whether this is a one-off event or repeated beaconing.
- Confirm whether the device is a workstation, server, or IoT/OT asset and whether MQTT is normal for that role.
- If the process is unknown and the host should not use MQTT, escalate for deeper host review.

**Evidence to collect:**
- DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemotePort, ConnectionCount, RemoteIPs, RemoteUrls, FirstSeen, LastSeen.
- Process reputation and any associated command line or parent process details if available.
- Asset role information showing whether the device is expected to run MQTT clients.
- Destination reputation and ownership for the remote IPs or URLs.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceName and RemoteIP to find other unusual ports or destinations.
- DeviceProcessEvents for the same initiating process to identify parent process and command line context.
- Asset inventory or CMDB data to confirm whether the host is an IoT, OT, or standard endpoint.
- Proxy or firewall logs to see whether the same destination is contacted by other hosts.

**Benign explanations:**
- Legitimate IoT management software or industrial telemetry uses MQTT.
- A development or test environment is connecting to a broker for application testing.
- A security or research tool is intentionally connecting to an MQTT service.

**Escalation criteria:**
- The host is not an IoT or development asset and the process is not a known MQTT client.
- The destination is a public broker or suspicious external IP with no business justification.
- The connection pattern repeats or is accompanied by other suspicious outbound activity.
- The process path suggests user-writable or temporary execution locations.

**Containment actions:**
- If the process and destination are not approved, block the remote IP or broker at the network edge.
- Isolate the endpoint if additional suspicious behavior is present or if the process is clearly malicious.
- Preserve process and network evidence before removing the process.

**Closure criteria:**
- The process and destination are confirmed as approved MQTT usage for the asset role.
- The connection is tied to a legitimate IoT, OT, or development workflow.
- No other suspicious network or process activity is found on the host.

<br/>
---
<br/>

## Detection 5: Invisible Unicode Tag Characters Detected in Inbound Email Subject or Metadata

### Detection Opportunity

Phishing emails using invisible Unicode characters from the Unicode tag block (U+E0000 range) to obfuscate content and evade email security filters, as observed in ASCII smuggling campaigns.

### Intelligence Context

- Microsoft Security Blog: ASCII smuggling crosses over from AI prompt injection to phishing evasion — [https://www.microsoft.com/en-us/security/blog/2026/09/03/ascii-smuggling-crosses-over-from-ai-prompt-injection-to-phishing-evasion/](https://www.microsoft.com/en-us/security/blog/2026/09/03/ascii-smuggling-crosses-over-from-ai-prompt-injection-to-phishing-evasion/)
  - Context: Threat actors adapted ASCII smuggling techniques originally used for AI prompt injection to embed invisible Unicode tag block characters in phishing emails, causing content to appear benign to email filters while hiding malicious instructions readable by AI-assisted tools or downstream parsers.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: Not specified
- Products: Not specified
- Platforms: email
- Malware: Not specified
- Tools: Not specified
- Search tags: email

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Not mapped

### Deployment Gates

- OfficeActivity Subject field is not populated for all Exchange operations; MessageBind and MessagesListed operations may not include Subject in all tenant configurations.

**Required telemetry:**
- OfficeActivity

### KQL

```kql
let TagBlockSamples = dynamic(["\u{E0001}", "\u{E0020}", "\u{E0041}", "\u{E0042}", "\u{E0043}", "\u{E0044}", "\u{E0045}", "\u{E0046}", "\u{E0047}", "\u{E0048}", "\u{E0049}", "\u{E004A}", "\u{E004B}", "\u{E004C}", "\u{E004D}", "\u{E004E}", "\u{E004F}", "\u{E0050}", "\u{E0051}", "\u{E0052}", "\u{E0053}", "\u{E0054}", "\u{E0055}", "\u{E0056}", "\u{E0057}", "\u{E0058}", "\u{E0059}", "\u{E005A}", "\u{E007F}"]);
OfficeActivity
| where OfficeWorkload == "Exchange"
| where Operation in ("Send", "MessageBind", "Create")
| where isnotempty(Subject)
| extend TagCharacterCount = array_length(array_concat(
    array_iff(Subject contains "\u{E0001}", dynamic([1]), dynamic([])),
    array_iff(Subject contains "\u{E0020}", dynamic([1]), dynamic([])),
    array_iff(Subject contains "\u{E007F}", dynamic([1]), dynamic([]))
  ))
| extend HasTagBlockChar = Subject has_any (TagBlockSamples)
| where HasTagBlockChar == true
| project
    TimeGenerated,
    SenderMailFromAddress,
    RecipientEmailAddress,
    Subject,
    Operation,
    HasTagBlockChar
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Automated email systems or marketing platforms that embed non-standard Unicode for tracking or formatting purposes.
- Emails forwarded through systems that corrupt or re-encode Unicode content in ways that introduce tag block characters.

**Tuning notes:**
- Before deploying, test the has_any string matching with a synthetic OfficeActivity record containing a known U+E0001 character to confirm the Kusto engine in the Sentinel workspace correctly matches supplementary plane Unicode literals.
- Expand the TagBlockSamples list to cover additional U+E0000-U+E007F codepoints as the threat intelligence on observed characters matures.
- Consider extending the query to check the ClientIP or SenderIPAddress field against known phishing infrastructure if additional context becomes available.
- Scope to high-value recipient mailboxes or external sender domains during initial hunting to manage volume.

**Risks / caveats:**
- KQL's matches regex operator in Kusto does not support Unicode codepoint range escapes in the format \uE0000-\uE007F; the original regex pattern will not match tag block characters and will return zero results without error.
- OfficeActivity Subject field is not populated for all Exchange operations; MessageBind and MessagesListed operations may not include Subject in all tenant configurations.
- The OfficeActivity table requires the Microsoft 365 Office 365 connector to be enabled in Microsoft Sentinel; without it, the table will be empty.
- Exchange audit logging for the required Operations (Send, MessageBind, Create) must be explicitly enabled in the Microsoft 365 compliance center for the tenant.

### Triage Runbook

**First 15 minutes:**
- Inspect the sender, recipient, subject, and operation to confirm the message is inbound and suspicious.
- Validate whether the subject contains invisible or unusual Unicode characters and whether the content is otherwise benign-looking.
- Check if the sender is external, newly seen, or spoofed, and whether the recipient is a high-value user.
- Determine whether the message was delivered, quarantined, or forwarded to other recipients.
- If the message is confirmed malicious or part of a campaign, initiate tenant-wide search for similar messages.

**Evidence to collect:**
- TimeGenerated, SenderMailFromAddress, RecipientEmailAddress, Subject, Operation, and any available message identifiers.
- Message headers, if available, to inspect sender authentication and routing.
- Delivery status and whether the message was opened, clicked, or forwarded.
- Any other messages from the same sender or with similar subject patterns.

**Pivot points:**
- OfficeActivity for the same sender or recipient to find related Exchange events.
- Email security or quarantine logs to determine whether the message was blocked or delivered.
- Tenant-wide searches for the same sender, subject fragment, or similar Unicode patterns.
- User-reported message telemetry to see whether recipients interacted with the email.

**Benign explanations:**
- A legitimate automated email system introduced unusual Unicode during formatting or encoding.
- A forwarding or mail gateway process corrupted the subject during re-encoding.
- A false positive caused by non-malicious Unicode content in a multilingual message.

**Escalation criteria:**
- The sender is external, spoofed, or associated with phishing infrastructure.
- The message was delivered to a high-value user or multiple recipients.
- The email contains links, attachments, or instructions consistent with phishing or social engineering.
- Similar messages are observed across the tenant or the recipient reports suspicious behavior.

**Containment actions:**
- Quarantine or purge the message if it is confirmed malicious and your process allows it.
- Block the sender or related domains if the campaign is validated.
- Warn affected users and search for additional delivered copies across the tenant.

**Closure criteria:**
- The message is confirmed benign and the Unicode content is explained by a legitimate system or encoding issue.
- No user interaction or downstream malicious activity is found.
- The detection is validated as a false positive and documented for future tuning.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- Trojanized Linux Service Binary Hash Deviation Detected: Do not schedule yet; validate as an analyst-led hunt first.
- Shell Command Execution Spawned by Trojanized Linux Service Binary with Outbound Network Connection: Do not schedule yet; validate as an analyst-led hunt first.
- Node.js Implant Execution from Unusual Parent or Path Following Teams External Access: Do not schedule yet; validate as an analyst-led hunt first.
- Invisible Unicode Tag Characters Detected in Inbound Email Subject or Metadata: OfficeActivity Subject field is not populated for all Exchange operations; MessageBind and MessagesListed operations may not include Subject in all tenant configurations.

**Telemetry availability:**
- Node.js Implant Execution from Unusual Parent or Path Following Teams External Access: OfficeActivity is a Microsoft Sentinel table and is not available natively in Defender XDR Advanced Hunting; this query requires a Sentinel workspace with the Office 365 connector enabled.

**Shared-table notes:**
- DeviceProcessEvents: shared by Trojanized Linux Service Binary Hash Deviation Detected; Shell Command Execution Spawned by Trojanized Linux Service Binary with Outbound Network Connection; Node.js Implant Execution from Unusual Parent or Path Following Teams External Access
- DeviceNetworkEvents: shared by Shell Command Execution Spawned by Trojanized Linux Service Binary with Outbound Network Connection; Node.js Implant Execution from Unusual Parent or Path Following Teams External Access; Outbound MQTT Connection to Port 1883 or 8883 from Non-IoT Endpoint Process
- OfficeActivity: shared by Node.js Implant Execution from Unusual Parent or Path Following Teams External Access; Invisible Unicode Tag Characters Detected in Inbound Email Subject or Metadata

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Outbound MQTT Connection to Port 1883 or 8883 from Non-IoT Endpoint Process.
2. Resolve environment-mapping detections next: Invisible Unicode Tag Characters Detected in Inbound Email Subject or Metadata.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Trojanized Linux Service Binary Hash Deviation Detected; Shell Command Execution Spawned by Trojanized Linux Service Binary with Outbound Network Connection; Node.js Implant Execution from Unusual Parent or Path Following Teams External Access.

### Hunting Agenda and Promotion Criteria

- Trojanized Linux Service Binary Hash Deviation Detected: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Shell Command Execution Spawned by Trojanized Linux Service Binary with Outbound Network Connection: Do not schedule yet; validate as an analyst-led hunt first..
- Node.js Implant Execution from Unusual Parent or Path Following Teams External Access: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- Invisible Unicode Tag Characters Detected in Inbound Email Subject or Metadata: OfficeActivity Subject field is not populated for all Exchange operations; MessageBind and MessagesListed operations may not include Subject in all tenant configurations..

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
