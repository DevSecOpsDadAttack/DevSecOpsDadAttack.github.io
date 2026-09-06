---
layout: post
title: "Detection Engineering Brief - Sunday, September 6, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-06
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - T1059
  - HAProxy
  - crond
  - agetty
  - atd
  - sshd
  - polkitd
  - Linux
  - Ted backdoor
  - curlRAT
  - T1078
  - T1219
  - Microsoft Teams
  - Microsoft Defender
  - Windows
  - Node.js
  - email
  - messaging
  - T1543
  - T1021.001
  - T1021
  - T1027
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

0 production candidates, 1 hunting-only, 4 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: T1059, HAProxy, crond, agetty, atd, sshd, polkitd, Linux, Ted backdoor, curlRAT, T1078, T1219, Microsoft Teams, Microsoft Defender, Windows, Node.js, email, messaging, T1543, T1021.001, ....

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Trojanized System Daemon Written to Known Daemon Path on Linux; HAProxy Spawning Shell or Interpreter Process on Linux; External Teams IT Support Impersonation Followed by Node.js Implant Execution; Lateral Movement Using Legitimate Tools Following External Teams Remote Session; Invisible Unicode Tag Characters Detected in Inbound Email Body.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Trojanized System Daemon Written to Known Daemon Path on Linux

### Detection Opportunity

System daemons (crond, agetty, atd, sshd, polkitd) replaced with trojanized versions on compromised Linux hosts

### Intelligence Context

- Rapid7: DPRK APTs: Ted backdoor and curlRAT target South Korean media and automotive sectors — [https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors](https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors)
  - Context: DPRK-linked actors deployed trojanized versions of crond, agetty, atd, sshd, and polkitd to blend into victim Linux environments for long-term persistence and surveillance.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1543
- Products: HAProxy, crond, agetty, atd, sshd, polkitd
- Platforms: Linux
- Malware: Ted backdoor, curlRAT
- Tools: Not specified
- Search tags: T1059, HAProxy, crond, agetty, atd, sshd, polkitd, Linux, Ted backdoor, curlRAT, T1543

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (high); Persistence: T1543 Create or Modify System Process (low)

### Deployment Gates

- Auditd must be deployed and forwarding to the Log Analytics agent or AMA Syslog connector on each monitored Linux host. Absence of this connector means zero telemetry coverage.

**Required telemetry:**
- Syslog

### KQL

```kql
Syslog
| where TimeGenerated > ago(7d)
| where SyslogMessage has_any (
    "/usr/sbin/crond", "/usr/sbin/agetty", "/usr/sbin/atd",
    "/usr/sbin/sshd", "/usr/sbin/polkitd",
    "/bin/crond", "/bin/sshd"
)
| where SyslogMessage has_any ("SYSCALL", "PATH", "rename", "openat", "open", "execve")
| where not (SyslogMessage has_any ("rpm", "dpkg", "apt", "yum", "dnf", "zypper", "snap"))
| project
    TimeGenerated,
    Computer,
    HostName,
    ProcessName,
    SyslogMessage
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate system administrator manual file operations on daemon paths (e.g., manual binary replacement during maintenance) will trigger this rule.
- Configuration management tools (Ansible, Chef, Puppet) that write daemon binaries directly without invoking a package manager will generate false positives.
- Build or deployment pipelines that install binaries to /usr/sbin may trigger if their process names are not in the exclusion list.

**Tuning notes:**
- Expand the daemon path list to include /sbin/ variants if the Linux distributions in scope use that path convention.
- Add additional package manager or configuration management tool names to the exclusion list based on the environment's software deployment tooling.
- Consider adding a Facility filter (e.g., Facility == 'kern' or ProcessName == 'auditd') to reduce noise from non-auditd syslog sources.
- For higher-fidelity detection, consider deploying the Microsoft Sentinel CEF connector with auditd configured to emit CEF-formatted events, which provides structured fields rather than free-text matching.

**Risks / caveats:**
- Syslog table does not provide structured file-write fields; detection relies on auditd-formatted free-text in SyslogMessage. If auditd is not configured with -w watches on /usr/sbin and /bin for write/rename/execute permissions, no relevant events will appear.
- Auditd must be deployed and forwarding to the Log Analytics agent or AMA Syslog connector on each monitored Linux host. Absence of this connector means zero telemetry coverage.
- The query uses SyslogMessage keyword matching for operation verbs (write, open, rename, mv, install, cp) which are not auditd syscall names; auditd logs syscall numbers or names like 'open', 'openat', 'rename', 'renameat'. The verb 'write' in auditd context refers to the syscall, not a string that reliably appears in the message alongside a path. This mismatch may cause the query to miss actual file-write events.
- Auditd watch rules must be explicitly configured on each Linux host to monitor write/rename/execute events on /usr/sbin and /bin. Without these rules, the query returns no results.

### Triage Runbook

**First 15 minutes:**
- Confirm the exact file path, filename, and timestamp in SyslogMessage; verify whether the write/rename occurred under /usr/sbin, /bin, or /sbin and whether the process name suggests auditd output.
- Check whether the event aligns with a package manager or approved configuration management activity; if not, treat as likely malicious binary replacement.
- Identify the affected host owner and recent admin change window; ask whether any maintenance, patching, or golden-image deployment was in progress.
- Look for immediate signs of follow-on activity on the same host such as new logins, shell execution, or service restarts around the same time.

**Evidence to collect:**
- Raw SyslogMessage lines before and after the alert time, including any SYSCALL and PATH records.
- Host identity, OS version, and whether auditd watch rules are enabled on daemon paths.
- ProcessName and any parent/child context visible in the log line, especially package manager or deployment tooling names.
- Recent authentication and service-management activity on the host from adjacent telemetry if available.

**Pivot points:**
- Syslog for the same Computer/HostName over the prior 24-72 hours to find repeated writes, renames, or execve activity on daemon paths.
- Syslog for package manager and configuration management process names on the same host around the alert time.
- If available, host authentication or remote access logs for new logons preceding the file replacement.
- If available, process telemetry for shell execution or service restarts on the same host after the replacement.

**Benign explanations:**
- Planned OS patching or package installation that replaced a daemon binary.
- Configuration management tools such as Ansible, Chef, or Puppet writing binaries directly without a package manager.
- Manual administrator maintenance on a lab or break-glass host.
- Golden image or deployment pipeline activity on newly provisioned servers.

**Escalation criteria:**
- The replacement is not attributable to a known maintenance/change window or approved tool.
- The replaced binary is outside package manager activity and the host shows suspicious shell execution, new logons, or service restarts.
- Multiple daemon paths are affected on the same host or across multiple hosts.
- The host is internet-facing, high value, or shows evidence of persistence beyond the file replacement.

**Containment actions:**
- Isolate the host from the network if the replacement is confirmed malicious or if follow-on execution is observed.
- Preserve the trojanized binary and relevant logs before remediation.
- Disable or stop the affected service only if business impact is understood and containment is required.
- Initiate credential review for accounts that administered the host if compromise is suspected.

**Closure criteria:**
- A legitimate change record, package manager transaction, or approved automation explains the file replacement.
- No suspicious follow-on execution, logons, or persistence indicators are found on the host.
- The affected binary is restored from a trusted source and the host is validated clean.
- Auditd coverage gaps are documented if the alert was caused by incomplete telemetry rather than malicious activity.

<br/>
---
<br/>

## Detection 2: HAProxy Spawning Shell or Interpreter Process on Linux

### Detection Opportunity

Backdoored HAProxy process spawning shell or interpreter child processes to execute remote commands on compromised Linux servers

### Intelligence Context

- Rapid7: DPRK APTs: Ted backdoor and curlRAT target South Korean media and automotive sectors — [https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors](https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors)
  - Context: A backdoored HAProxy binary was used by DPRK-linked actors to execute remote commands on compromised servers, representing anomalous child process spawning from the HAProxy parent.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1543
- Products: HAProxy
- Platforms: Linux
- Malware: Ted backdoor, curlRAT
- Tools: Not specified
- Search tags: T1059, HAProxy, Linux, Ted backdoor, curlRAT, T1543

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (high); Persistence: T1543 Create or Modify System Process (low)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.

**Required telemetry:**
- Syslog

### KQL

```kql
Syslog
| where TimeGenerated > ago(7d)
| where SyslogMessage has "haproxy"
| where SyslogMessage has "execve"
| where SyslogMessage has_any (
    "/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh",
    "python", "perl", "ruby",
    "netcat", "ncat"
)
| project
    TimeGenerated,
    Computer,
    HostName,
    ProcessName,
    SyslogMessage
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- HAProxy health check scripts or wrapper scripts that legitimately invoke shell commands may appear in logs alongside haproxy process context.
- Log aggregation or monitoring agents that emit haproxy status lines alongside shell execution events on the same host may produce co-occurrence false positives.
- Environments where haproxy is managed by shell-based init scripts may generate benign matches during service start/stop.

**Tuning notes:**
- For higher-fidelity parent-child detection on Linux, consider deploying Microsoft Defender for Endpoint Linux agent, which provides structured process tree telemetry in DeviceProcessEvents with InitiatingProcessFileName.
- Add additional interpreter paths (/usr/bin/python3, /usr/bin/ruby) based on the scripting languages present in the environment.
- Restrict Computer to known HAProxy server hostnames if the deployment is limited to a defined set of servers to reduce noise.

**Risks / caveats:**
- Auditd EXECVE records in Syslog do not natively include parent process name in the same message line. Establishing haproxy as the parent process requires PPID correlation across multiple auditd records (SYSCALL + EXECVE), which is not achievable with simple SyslogMessage keyword matching in the Syslog table.
- If auditd is not deployed and forwarding execve events to Syslog, the query will return no results.
- Matching 'haproxy' and shell names in the same SyslogMessage line without confirmed PPID context produces a correlation that may reflect log co-occurrence rather than a true parent-child process relationship.
- Without PPID context in auditd Syslog messages, this query detects co-occurrence of haproxy and shell/interpreter references in the same log line, not a confirmed parent-child process relationship. Analyst review of raw SyslogMessage is required to confirm the relationship.

### Triage Runbook

**First 15 minutes:**
- Confirm the exact child process name and command line in SyslogMessage; prioritize bash, sh, python, perl, ruby, netcat, or ncat spawned in the HAProxy context.
- Check whether the host is a known HAProxy server and whether any approved health checks, wrapper scripts, or automation could explain the child process.
- Look for evidence that the HAProxy binary or service was recently modified, replaced, or restarted unexpectedly.
- Assess whether the child process timing aligns with inbound traffic spikes, admin maintenance, or suspicious remote activity.

**Evidence to collect:**
- Raw SyslogMessage lines showing haproxy and execve context, including PID or any available process identifiers.
- Service status and binary path for HAProxy on the affected host.
- Recent file integrity or package update evidence for the HAProxy binary and related service files.
- Any adjacent logs showing outbound connections, command execution, or service restarts near the alert time.

**Pivot points:**
- Syslog for the same host to find other execve events from haproxy or related service processes.
- Syslog for recent writes, renames, or package changes affecting HAProxy binaries or service files.
- If available, network telemetry for outbound connections from the HAProxy host after the alert.
- If available, process telemetry for child shells or interpreters launched by HAProxy or its service account.

**Benign explanations:**
- Legitimate HAProxy health-check or maintenance scripts that invoke shell commands.
- Service start/stop wrappers that use shell or interpreter processes during deployment.
- Administrative troubleshooting on a load balancer host.
- Log co-occurrence artifacts where haproxy and shell names appear in the same syslog line without a true parent-child relationship.

**Escalation criteria:**
- A shell or interpreter is spawned by HAProxy outside a known maintenance window or approved script path.
- The HAProxy binary or service files show unauthorized modification or replacement.
- The child process performs suspicious actions such as downloading payloads, opening reverse shells, or enumerating the host.
- Multiple HAProxy hosts show the same behavior, suggesting a broader campaign.

**Containment actions:**
- Isolate the host if the HAProxy binary is confirmed trojanized or if suspicious child processes are active.
- Stop the HAProxy service only if necessary to prevent further command execution and after confirming service impact.
- Preserve the binary, service files, and relevant logs for forensic analysis.
- Block suspicious outbound destinations if the child process is making external connections.

**Closure criteria:**
- The child process is explained by a documented HAProxy script, wrapper, or approved automation.
- No evidence of binary tampering, reverse shell behavior, or unauthorized outbound activity is found.
- The host is validated as a known-good HAProxy server with expected service behavior.
- Any telemetry limitations are documented, especially if the alert was based on log co-occurrence rather than confirmed parent-child process lineage.

<br/>
---
<br/>

## Detection 3: External Teams IT Support Impersonation Followed by Node.js Implant Execution

### Detection Opportunity

External Microsoft Teams account impersonating IT support initiates contact, followed by Node.js-based implant execution on the targeted Windows endpoint

### Intelligence Context

- Microsoft Security Blog: Impersonating IT support: how threat actors turn a remote session into enterprise-wide access — [https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/](https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/)
  - Context: Threat actors abused Microsoft Teams external collaboration to impersonate IT support personnel, then deployed a Node.js-based implant on the victim Windows endpoint after gaining remote access through social engineering.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1078, T1219, T1059, T1021.001, T1021
- Products: Microsoft Teams, Microsoft Defender
- Platforms: Windows, Node.js
- Malware: Not specified
- Tools: Not specified
- Search tags: T1078, T1219, T1059, Microsoft Teams, Microsoft Defender, Windows, Node.js, T1021.001, T1021

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Both
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1219 Remote Access Software (medium); Lateral Movement: T1021 Remote Services/ T1021.001 Remote Desktop Protocol (medium); Execution: T1059 Command and Scripting Interpreter (low)

### Deployment Gates

- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.
- DeviceLogonEvents may not contain AccountUpn for all logon types or all device configurations; the UPN-to-device mapping step may miss devices where AccountUpn is not populated.

**Required telemetry:**
- OfficeActivity, DeviceProcessEvents

### KQL

```kql
let ITKeywords = dynamic(["it support", "helpdesk", "help desk", "tech support", "it helpdesk", "service desk"]);
let LookbackWindow = 1d;
let CorrelationWindow = 2h;
// Step 1: Identify external Teams contacts with IT support keyword in sender UserId
let TeamsExternalContact = OfficeActivity
| where TimeGenerated > ago(LookbackWindow)
| where RecordType == "MicrosoftTeams"
| where Operation in ("MessageCreated", "MessageCreatedHasLink", "MemberAdded")
| where ExternalAccess == true
| where tolower(tostring(UserId)) has_any (ITKeywords)
| project TeamsTime = TimeGenerated, TeamsUserId = tostring(UserId), ClientIP = tostring(ClientIP);
// Step 2: Map external Teams contact to a device via recent logon events
let UserDeviceMap = DeviceLogonEvents
| where Timestamp > ago(LookbackWindow)
| where isnotempty(AccountUpn)
| summarize DeviceName = any(DeviceName) by AccountUpn
| project AccountUpn, DeviceName;
// Step 3: Identify node.exe running from user-writable paths
let NodeExecution = DeviceProcessEvents
| where Timestamp > ago(LookbackWindow)
| where FileName =~ "node.exe"
| where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\Users\\", "\\ProgramData\\")
| where not (InitiatingProcessFileName has_any ("code.exe", "devenv.exe", "webstorm.exe"))
| project NodeTime = Timestamp, DeviceName, AccountUpn, ProcessCommandLine, FolderPath, InitiatingProcessFileName;
// Step 4: Correlate Teams contact -> device mapping -> node.exe execution
TeamsExternalContact
| join kind=inner UserDeviceMap on $left.TeamsUserId == $right.AccountUpn
| join kind=inner NodeExecution on $left.DeviceName == $right.DeviceName
| where (NodeTime - TeamsTime) between (0min .. CorrelationWindow)
| project
    TeamsTime,
    NodeTime,
    DeviceName,
    AccountUpn,
    TeamsUserId,
    ClientIP,
    ProcessCommandLine,
    FolderPath,
    InitiatingProcessFileName
| sort by TeamsTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate external IT vendors or managed service providers contacting users via Teams followed by authorized remote support sessions that involve Node.js tooling.
- Developers who receive external Teams messages and subsequently run Node.js scripts from AppData or Temp paths for legitimate development purposes.
- Automated Teams bots or external integration accounts with IT-related display names that contact users around the same time as unrelated Node.js activity.

**Tuning notes:**
- Extend the IT support keyword list to include organization-specific IT team names or localized equivalents.
- Adjust the CorrelationWindow variable from 2h based on observed attacker dwell time in the environment.
- If AccountUpn is not reliably populated in DeviceLogonEvents, consider using IdentityLogonEvents from Defender XDR as an alternative identity-to-device bridge.
- Consider adding a minimum node.exe command-line length filter to exclude trivial or empty command lines that may indicate benign invocations.

**Risks / caveats:**
- The join between OfficeActivity (UserId = UPN) and DeviceProcessEvents (DeviceName = hostname) on UserId == DeviceName is a type mismatch that will produce zero results. An identity-to-device mapping table (e.g., IdentityInfo or a custom watchlist) is required to bridge UPN to DeviceName.
- OfficeActivity ExternalAccess field availability for Teams MessageCreated events depends on the Microsoft 365 audit log plan (E3/E5) and whether Teams audit logging is enabled at the tenant level. This field may not be populated in all configurations.
- SensitiveInfoTypeData is not a standard OfficeActivity field for Teams MessageCreated records; referencing it will cause a runtime error or always evaluate to empty.
- OfficeActivity does not expose Teams message body or sender display name in a reliable structured field for MessageCreated events; display name matching against IT support keywords via UserId is unreliable.

### Triage Runbook

**First 15 minutes:**
- Verify the Teams sender identity, external access status, and whether the sender name or account resembles IT support or helpdesk branding.
- Confirm the target device and user account involved in the correlation and whether the Node.js execution occurred on a user-writable path such as Temp or AppData.
- Check the Node.js command line and parent process to determine whether the execution was user-initiated, script-driven, or launched by a suspicious process.
- Ask the user or service desk whether they recently received a remote support request, file, or link from the external Teams contact.

**Evidence to collect:**
- Teams message metadata: sender, recipient, timestamp, external access indicator, and any available conversation or message identifiers.
- DeviceProcessEvents for node.exe command line, folder path, initiating process, and execution time.
- DeviceLogonEvents or identity-to-device mapping evidence showing which account was active on the endpoint around the alert time.
- Any related file, script, or archive names executed by node.exe and any child processes spawned afterward.

**Pivot points:**
- OfficeActivity for other external Teams contacts from the same sender or to the same recipient in the prior 24-72 hours.
- DeviceProcessEvents for node.exe, powershell.exe, wscript.exe, mshta.exe, or browser-launched script activity on the same device.
- DeviceLogonEvents for recent remote or interactive logons to the endpoint.
- If available, email and chat telemetry for links, attachments, or follow-up instructions from the same external contact.

**Benign explanations:**
- A legitimate external managed service provider or vendor contacting the user via Teams before a support session.
- Developer or IT staff running Node.js from AppData or Temp for testing or local tooling.
- A benign remote support workflow that uses Node.js-based utilities or scripts.
- A false correlation caused by unrelated Teams contact and Node.js activity on the same device within the time window.

**Escalation criteria:**
- The external Teams contact is unverified, impersonates IT support, or is associated with suspicious follow-up instructions.
- Node.js runs from a user-writable path with suspicious command-line arguments, downloads, or child processes.
- The user reports interacting with the sender, granting remote access, or executing a file/script from the conversation.
- Additional suspicious activity appears on the endpoint, such as credential prompts, browser automation, or persistence creation.

**Containment actions:**
- Isolate the endpoint if malicious execution is confirmed or strongly suspected.
- Disable or reset the affected user account if there is evidence of credential compromise or remote access abuse.
- Preserve the node.exe command line, related files, and chat artifacts before remediation.
- Block the external Teams account or tenant if it is confirmed malicious and coordinate with collaboration platform admins.

**Closure criteria:**
- The Teams contact is verified as legitimate and the Node.js execution is explained by approved activity.
- No suspicious command line, child process, or persistence behavior is found on the endpoint.
- The user confirms no interaction with a malicious support impersonation attempt.
- Any telemetry join limitations are documented and the alert is judged non-actionable after review.

<br/>
---
<br/>

## Detection 4: Lateral Movement Using Legitimate Tools Following External Teams Remote Session

### Detection Opportunity

Lateral movement performed using legitimate administrative tools on Windows endpoints shortly after an external Teams-initiated remote access session

### Intelligence Context

- Microsoft Security Blog: Impersonating IT support: how threat actors turn a remote session into enterprise-wide access — [https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/](https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/)
  - Context: After gaining initial remote access through Teams IT support impersonation, threat actors used legitimate tools to move laterally across the enterprise, escalating from a single compromised endpoint to enterprise-wide access.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1078, T1219, T1059, T1021.001, T1021
- Products: Microsoft Teams, Microsoft Defender
- Platforms: Windows, Node.js
- Malware: Not specified
- Tools: Not specified
- Search tags: T1078, T1219, T1059, Microsoft Teams, Microsoft Defender, Windows, Node.js, T1021.001, T1021

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1219 Remote Access Software (medium); Lateral Movement: T1021 Remote Services/ T1021.001 Remote Desktop Protocol (medium); Execution: T1059 Command and Scripting Interpreter (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceLogonEvents, DeviceProcessEvents

### KQL

```kql
let LateralTools = dynamic([
    "psexec.exe", "psexec64.exe",
    "wmic.exe",
    "mstsc.exe",
    "net.exe", "net1.exe",
    "schtasks.exe",
    "at.exe",
    "sc.exe"
]);
let LookbackWindow = 1d;
let CorrelationWindow = 30min;
let RemoteLogons = DeviceLogonEvents
| where Timestamp > ago(LookbackWindow)
| where LogonType in (3, 10)
| where isnotempty(RemoteIP)
| where RemoteIP !in ("127.0.0.1", "::1", "169.254.0.0")
| project
    LogonTime = Timestamp,
    DeviceName,
    AccountName,
    AccountDomain,
    RemoteIP,
    LogonType,
    InitiatingProcessFileName;
let LateralProcesses = DeviceProcessEvents
| where Timestamp > ago(LookbackWindow)
| where FileName has_any (LateralTools)
| project
    ProcTime = Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName;
RemoteLogons
| join kind=inner LateralProcesses on DeviceName, AccountName
| where (ProcTime - LogonTime) between (0min .. CorrelationWindow)
| project
    LogonTime,
    ProcTime,
    DeviceName,
    AccountName,
    AccountDomain,
    RemoteIP,
    LogonType,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName
| sort by LogonTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- IT administrators performing legitimate remote administration using psexec, wmic, mstsc, or net.exe following a network logon to a server.
- Automated system management tools (SCCM, Intune, RMM agents) that authenticate remotely and then invoke administrative binaries.
- Scheduled tasks or scripts that run lateral movement tool names as part of legitimate automation shortly after a service account network logon.
- Help desk personnel using mstsc for legitimate remote desktop support sessions.

**Tuning notes:**
- Add known IT administration jump host IP addresses to a RemoteIP exclusion list to suppress legitimate admin activity from those sources.
- Adjust the CorrelationWindow variable from 30min based on observed attacker tempo and legitimate admin workflow timing in the environment.
- Consider adding an AccountName exclusion list for known service accounts or admin accounts that routinely perform these operations.
- Expand the LateralTools list to include additional living-off-the-land binaries observed in the environment (e.g., winrs.exe, reg.exe, certutil.exe) based on threat intelligence.

**Risks / caveats:**
- DeviceLogonEvents and DeviceProcessEvents require Microsoft Defender for Endpoint P1/P2 licensing and device onboarding for all Windows endpoints in scope.
- wmiexec.py is a Python script name, not a Windows executable; it will not appear as FileName in DeviceProcessEvents on Windows hosts where it is not explicitly saved with that name. Matching on it may produce no results.
- This detection does not incorporate the Teams external contact signal; it is a lateral movement heuristic that will fire on any remote logon followed by lateral tool execution, regardless of whether a Teams impersonation event preceded it. Analyst triage is required to confirm the Teams connection.
- The AccountName join between DeviceLogonEvents and DeviceProcessEvents may miss cases where the lateral tool is executed under a different account than the one that performed the remote logon (e.g., privilege escalation between logon and tool execution).

### Triage Runbook

**First 15 minutes:**
- Confirm the account, device, remote IP, and logon type; determine whether the source IP is a known admin jump host or VPN egress point.
- Review the tool name and command line to see whether the process is psexec, wmic, mstsc, net, schtasks, at, or sc and whether the usage is expected for that account.
- Check whether the account is a privileged admin, service account, or help desk account with a history of remote administration.
- Look for additional signs of lateral movement on the same device, such as multiple remote logons, service creation, scheduled task creation, or remote execution bursts.

**Evidence to collect:**
- DeviceLogonEvents showing logon time, logon type, remote IP, account name, and device name.
- DeviceProcessEvents showing the administrative tool name, command line, initiating process, and execution time.
- Account context including domain, privilege level, and whether the account is normally used for remote administration.
- Any available remote access or VPN logs that identify the source system or user behind the remote IP.

**Pivot points:**
- DeviceProcessEvents for the same account and device to find additional remote admin tools or follow-on execution.
- DeviceLogonEvents for repeated logons from the same remote IP or to other hosts in the same time window.
- If available, authentication logs or VPN logs to validate whether the remote IP belongs to a known admin source.
- If available, endpoint telemetry for service creation, scheduled tasks, or remote service use after the logon.

**Benign explanations:**
- Routine IT administration from a jump host or VPN using approved tools.
- Help desk remote support sessions using mstsc or administrative utilities.
- Automated management platforms such as SCCM, Intune, or RMM agents performing maintenance.
- Service accounts running scheduled administrative scripts after a network logon.

**Escalation criteria:**
- The remote IP is unknown, external, or not associated with approved administration.
- The account is not expected to perform remote administration or shows unusual privilege use.
- The tool execution is followed by service creation, scheduled task creation, or additional host-to-host movement.
- Multiple hosts show the same account or source IP performing the pattern in a short period.

**Containment actions:**
- Block or disable the account if unauthorized lateral movement is confirmed.
- Isolate the affected host if the activity is clearly malicious or accompanied by persistence or credential theft.
- Preserve process, logon, and remote IP evidence before remediation.
- Coordinate with identity and network teams to trace the source IP and any additional compromised hosts.

**Closure criteria:**
- The activity is attributed to approved administration from a known source and matches the account's normal behavior.
- No additional lateral movement, persistence, or suspicious remote access is found.
- The remote IP is validated as a corporate jump host, VPN, or managed service source.
- The alert is documented as benign with any necessary allowlist or tuning recommendation.

<br/>
---
<br/>

## Detection 5: Invisible Unicode Tag Characters Detected in Inbound Email Body

### Detection Opportunity

Invisible Unicode characters embedded in inbound email body to evade content-based security filters

### Intelligence Context

- Microsoft Security Blog: ASCII smuggling crosses over from AI prompt injection to phishing evasion — [https://www.microsoft.com/en-us/security/blog/2026/09/03/ascii-smuggling-crosses-over-from-ai-prompt-injection-to-phishing-evasion/](https://www.microsoft.com/en-us/security/blog/2026/09/03/ascii-smuggling-crosses-over-from-ai-prompt-injection-to-phishing-evasion/)
  - Context: Threat actors embedded invisible Unicode tag block characters (U+E0000-U+E007F) and other invisible formatting characters in email bodies to obfuscate malicious content from content-based email security filters before message parsing.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1027
- Products: Not specified
- Platforms: email, messaging
- Malware: Not specified
- Tools: Not specified
- Search tags: email, messaging, T1027

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Defense Evasion: T1027 Obfuscated Files or Information (high)

### Deployment Gates

- OfficeActivity Exchange audit logging must be enabled at the tenant level and the audit log plan must capture the relevant Operations (MessageBind, Send, Create) for the mailboxes in scope.

**Required telemetry:**
- OfficeActivity

### KQL

```kql
OfficeActivity
| where TimeGenerated > ago(7d)
| where RecordType in ("ExchangeItem", "ExchangeItemGroup")
| where Operation in ("MessageBind", "Create", "Send")
| where isnotempty(Subject)
| where Subject matches regex @"[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u2061\u2062\u2063\u2064\u206A\u206B\u206C\u206D\u206E\u206F]"
| project
    TimeGenerated,
    SenderAddress,
    RecipientAddress,
    Subject,
    InternetMessageId,
    UserId,
    Operation
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate emails from certain international senders or mail clients that embed zero-width joiners or non-breaking soft hyphens in subject lines for text rendering purposes.
- Automated notification emails from systems that generate subjects with Unicode formatting characters.
- Internal emails from applications that use BOM (U+FEFF) as a byte-order marker in subject encoding.

**Tuning notes:**
- Extend the regex character class to include additional invisible Unicode ranges (U+2028 line separator, U+2029 paragraph separator, U+180E Mongolian vowel separator) if broader evasion variants are observed.
- Add a SenderAddress filter to restrict to external senders (e.g., SenderAddress !endswith your-domain.com) to reduce internal false positives.
- For detection of tag block characters (U+E0000-U+E007F) specifically, consider querying Microsoft Defender for Office 365 email entity data via EmailEvents in Defender XDR, which may provide richer message metadata with less normalization.
- Consider correlating flagged messages with subsequent user activity (file downloads, URL clicks) to prioritize triage.

**Risks / caveats:**
- KQL regex does not support \x{E0000} syntax for Unicode supplementary plane characters (U+E0000-U+E007F are above U+FFFF and require surrogate pair or multi-byte encoding). Standard KQL regex Unicode escapes only support \uXXXX for BMP characters. The original regex will fail to compile or match correctly for tag block characters.
- Exchange Online may strip or normalize Unicode tag block characters (U+E0000-U+E007F) from message metadata before writing to OfficeActivity audit logs, making Subject-field detection of these characters unreliable or impossible without raw message access.
- SenderAddress, RecipientAddress, and InternetMessageId are top-level columns in OfficeActivity for Exchange records, not nested inside a Parameters JSON field. The original parse_json(Parameters) approach will return null for these fields.
- OfficeActivity Exchange audit logging must be enabled at the tenant level and the audit log plan must capture the relevant Operations (MessageBind, Send, Create) for the mailboxes in scope.

### Triage Runbook

**First 15 minutes:**
- Verify the sender, recipient, subject, and operation; determine whether the message is external and whether the sender is known or spoofed.
- Inspect the subject for visible oddities, unusual spacing, or suspicious branding, and confirm whether the message is inbound rather than an internal notification.
- Check whether the recipient opened, replied to, forwarded, or clicked anything associated with the message if that telemetry is available.
- Assess whether the message is part of a broader campaign affecting multiple users or mailboxes.

**Evidence to collect:**
- OfficeActivity record details including SenderAddress, RecipientAddress, Subject, InternetMessageId, and Operation.
- Any available email security verdicts, quarantine status, or message trace details for the same InternetMessageId.
- User activity after receipt, such as clicks, downloads, replies, or forwarding actions.
- Whether the sender domain is external, newly seen, or impersonating a trusted brand.

**Pivot points:**
- OfficeActivity for the same sender, subject pattern, or InternetMessageId across other recipients.
- Email security or message trace tables for delivery status, quarantine, and related detections.
- If available, endpoint or browser telemetry for user clicks or file downloads after message receipt.
- If available, search for other messages with similar invisible-character indicators or suspicious subject patterns.

**Benign explanations:**
- Legitimate international or multilingual email content that includes unusual Unicode formatting.
- Automated notification systems that generate subjects with zero-width or formatting characters.
- Internal applications or mail gateways that insert BOM or soft hyphen characters during encoding.
- A false positive caused by benign invisible characters in the subject rather than malicious obfuscation.

**Escalation criteria:**
- The sender is external, spoofed, or associated with phishing indicators.
- The message is part of a broader campaign or multiple recipients report similar content.
- The recipient interacted with the message and subsequent suspicious activity appears on the endpoint or account.
- The subject contains obfuscation and the message includes links, attachments, or urgent credential-related language.

**Containment actions:**
- Quarantine or purge the message if it is confirmed malicious and still present in mailboxes.
- Warn the recipient and nearby users if the message is part of an active phishing campaign.
- Block the sender or domain if confirmed malicious and coordinate with email security admins.
- If the user interacted with the message, initiate endpoint and account review for follow-on compromise.

**Closure criteria:**
- The message is verified as legitimate or an expected automated notification.
- No user interaction, malicious links, or campaign indicators are found.
- The invisible characters are explained by benign encoding or formatting behavior.
- The alert is documented with sender reputation and message trace evidence supporting closure.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- Trojanized System Daemon Written to Known Daemon Path on Linux: Auditd must be deployed and forwarding to the Log Analytics agent or AMA Syslog connector on each monitored Linux host. Absence of this connector means zero telemetry coverage.
- HAProxy Spawning Shell or Interpreter Process on Linux: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.

**Licensing / identity risk fields:**
- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Other deployment dependency:**
- External Teams IT Support Impersonation Followed by Node.js Implant Execution: DeviceLogonEvents may not contain AccountUpn for all logon types or all device configurations; the UPN-to-device mapping step may miss devices where AccountUpn is not populated.
- Invisible Unicode Tag Characters Detected in Inbound Email Body: OfficeActivity Exchange audit logging must be enabled at the tenant level and the audit log plan must capture the relevant Operations (MessageBind, Send, Create) for the mailboxes in scope.

**Schema / correlation keys:**
- Lateral Movement Using Legitimate Tools Following External Teams Remote Session: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- Syslog: shared by Trojanized System Daemon Written to Known Daemon Path on Linux; HAProxy Spawning Shell or Interpreter Process on Linux
- OfficeActivity: shared by External Teams IT Support Impersonation Followed by Node.js Implant Execution; Invisible Unicode Tag Characters Detected in Inbound Email Body
- DeviceProcessEvents: shared by External Teams IT Support Impersonation Followed by Node.js Implant Execution; Lateral Movement Using Legitimate Tools Following External Teams Remote Session

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: Trojanized System Daemon Written to Known Daemon Path on Linux; HAProxy Spawning Shell or Interpreter Process on Linux; External Teams IT Support Impersonation Followed by Node.js Implant Execution; Invisible Unicode Tag Characters Detected in Inbound Email Body.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Lateral Movement Using Legitimate Tools Following External Teams Remote Session.

### Hunting Agenda and Promotion Criteria

- Lateral Movement Using Legitimate Tools Following External Teams Remote Session: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- Trojanized System Daemon Written to Known Daemon Path on Linux: Auditd must be deployed and forwarding to the Log Analytics agent or AMA Syslog connector on each monitored Linux host. Absence of this connector means zero telemetry coverage..
- HAProxy Spawning Shell or Interpreter Process on Linux: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling..
- External Teams IT Support Impersonation Followed by Node.js Implant Execution: Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Invisible Unicode Tag Characters Detected in Inbound Email Body: OfficeActivity Exchange audit logging must be enabled at the tenant level and the audit log plan must capture the relevant Operations (MessageBind, Send, Create) for the mailboxes in scope.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
