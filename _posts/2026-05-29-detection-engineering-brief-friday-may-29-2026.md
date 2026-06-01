---
layout: post
title: "Detection Engineering Brief - Friday, May 29, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-05-29
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Storm-2697
  - The Gentlemen
  - Windows
  - enterprise networks
  - T1059
  - Gogs
  - Linux
  - npm
  - cloud
  - CI/CD
  - T1021.002
  - T1078
  - T1021
  - T1059.007
  - T1071.001
  - T1071
---

## Executive Signal

This brief produced 5 detection candidates.

2 production candidates, 1 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Storm-2697, The Gentlemen, Windows, enterprise networks, T1059, Gogs, Linux, npm, cloud, CI/CD, T1021.002, T1078, T1021, T1059.007, T1071.001, T1071.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Gogs RCE - Git Rebase Spawning Unexpected Child Process via Argument Injection; npm Supply Chain - Node Process Spawning Child Process with Outbound Network Connection After Package Install; Gogs RCE - Suspicious Branch Name Containing Argument Injection Patterns in Syslog.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: Gentlemen Ransomware - Mass File Encryption by Single Process

### Detection Opportunity

A single process generating high-volume file rename or overwrite events with extension changes within a short time window, consistent with The Gentlemen ransomware per-file ephemeral key encryption behavior.

### Intelligence Context

- Microsoft Security Blog: The Gentlemen ransomware: Dissecting a self-propagating Go encryptor — [https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/](https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/)
  - Context: The Gentlemen ransomware, attributed to Storm-2697, encrypts files using per-file ephemeral keys and self-propagates across enterprise networks. Mass file rename and overwrite events from a single process are the primary observable signature of the encryption phase.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-2697
- ATT&CK tags: T1021.002, T1078, T1021
- Products: Not specified
- Platforms: Windows, enterprise networks
- Malware: The Gentlemen
- Tools: Not specified
- Search tags: Storm-2697, The Gentlemen, Windows, enterprise networks, T1021.002, T1078, T1021

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1021 Remote Services/ T1021.002 SMB/Windows Admin Shares (medium); Lateral Movement: T1078 Valid Accounts (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let timeWindow = 5m;
let fileThreshold = 200;
let excludedProcesses = dynamic(["MsMpEng.exe", "svchost.exe", "explorer.exe", "SearchIndexer.exe", "OneDrive.exe"]);
DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType in ("FileRenamed", "FileModified")
| where InitiatingProcessFileName !in~ (excludedProcesses)
| extend FileExtension = extract(@"\.([^.]+)$", 1, FileName)
| summarize
    FileCount = count(),
    UniqueExtensions = dcount(FileExtension),
    FolderPaths = make_set(FolderPath, 20),
    CmdLine = any(InitiatingProcessCommandLine),
    InitiatingProcessId = any(InitiatingProcessId),
    InitiatingProcessSHA256 = any(InitiatingProcessSHA256)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, timeWindow)
| where FileCount >= fileThreshold and UniqueExtensions >= 2
| rename WindowStart = Timestamp
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(1h)
    | project
        DeviceName,
        InitiatingProcessFileName = FileName,
        ProcessCommandLine,
        SHA256,
        ProcessId
) on DeviceName, InitiatingProcessFileName
| project
    WindowStart,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessId,
    FileCount,
    UniqueExtensions,
    FolderPaths,
    CmdLine,
    ProcessCommandLine,
    SHA256 = coalesce(SHA256, InitiatingProcessSHA256)
| order by WindowStart desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Backup agents performing bulk file versioning or snapshot operations may exceed the file count threshold.
- Search indexers such as Windows Search or third-party indexers renaming temporary files in bulk.
- File migration or deduplication tools operating on large datasets.
- Antivirus quarantine operations renaming files in bulk.

Tuning notes:
- Adjust fileThreshold based on observed peak file event rates from legitimate processes in the environment.
- Add known backup agent executable names to the excludedProcesses dynamic list.
- Consider adding InitiatingProcessAccountName to the summarize to enable per-user context in triage.
- If the environment uses Defender for Endpoint advanced hunting with custom detection rules, set the rule frequency to 5 minutes to match the bin window.

Risks / caveats:
- FileRenamed ActionType availability depends on Defender for Endpoint sensor version and OS build; confirm ActionType values present in DeviceFileEvents for the monitored fleet before scheduling.
- The join on InitiatingProcessFileName is a weak key — multiple distinct processes may share the same filename. Adding InitiatingProcessId or InitiatingProcessSHA256 as a join key would be more precise, but those fields must be confirmed available in both tables for the deployed sensor version.
- The fileThreshold of 200 is a starting point; environments with active backup or indexing agents should baseline normal file event rates before scheduling.
- The excludedProcesses list should be expanded with environment-specific backup agent executable names before production deployment.

### Triage Runbook

First 15 minutes:
- Confirm the alerting process name, SHA256, command line, and device owner; identify whether the process is user-launched, service-launched, or spawned by a suspicious parent.
- Check whether file activity is still ongoing and whether the affected folders include user data, shared drives, or backup locations rather than known application/cache paths.
- Look for concurrent signs of ransomware such as shadow copy deletion, backup service disruption, new ransom note files, or multiple hosts showing similar file activity.
- Validate whether the process is one of the known benign high-volume writers in the environment, especially backup, indexing, AV, or migration tooling.

Evidence to collect:
- InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessSHA256, and full command line from the alerting host.
- Sample FolderPaths and FileNames from the affected directories, including whether extensions are changing to a new pattern.
- Recent DeviceProcessEvents for the same host to identify the parent process tree and any suspicious child processes.
- Any related file deletion, rename, or overwrite events around the same WindowStart on the same device.
- User context for the initiating account and whether the host is a server, workstation, or file share endpoint.

Pivot points:
- DeviceFileEvents for the same DeviceName and WindowStart to expand affected folders and file types.
- DeviceProcessEvents on the same DeviceName for the initiating process tree and any suspicious parent or child processes.
- DeviceLogonEvents for the initiating account to determine whether the activity followed a remote logon or unusual session.
- DeviceNetworkEvents for the host to look for outbound connections, SMB activity, or lateral movement around the same time.

Benign explanations:
- Backup agents or snapshot tools performing bulk versioning or restore-point operations.
- Search indexing or file migration tools touching many files in a short period.
- Antivirus quarantine or remediation actions renaming many files.
- Large-scale deduplication, sync, or content transformation jobs run by approved admin tooling.

Escalation criteria:
- The process is unknown, unsigned, or has a suspicious command line and file activity is still active.
- Affected files are user documents, shared data, or multiple extensions across many folders rather than a single application path.
- There are additional ransomware indicators such as ransom notes, shadow copy deletion, or parallel alerts on other hosts.
- The initiating account or parent process is unexpected for the host role or time of day.

Containment actions:
- Isolate the host from the network if encryption is ongoing or if multiple ransomware indicators are present.
- Terminate the suspicious process only after capturing process details and confirming the host is not running an approved bulk file operation.
- Disable or reset the initiating account if there is evidence of compromise or lateral movement.
- Preserve volatile evidence and notify incident response to protect adjacent hosts and file shares.

Closure criteria:
- Confirmed benign bulk file operation from an approved process, account, and maintenance window.
- No ongoing file modification activity and no secondary ransomware indicators after review.
- Process hash, parent chain, and command line match a documented legitimate tool.
- Affected folders and file patterns align with expected application or maintenance behavior.

---

## Detection 2: Gentlemen Ransomware - Self-Propagation via Rapid Lateral Logons Across Multiple Hosts

### Detection Opportunity

Rapid sequential remote logon events from a single source account or device to multiple distinct target hosts within a short time window, consistent with The Gentlemen ransomware's aggressive self-propagation module.

### Intelligence Context

- Microsoft Security Blog: The Gentlemen ransomware: Dissecting a self-propagating Go encryptor — [https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/](https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/)
  - Context: The Gentlemen ransomware uses an aggressive self-propagation module that deploys itself across entire enterprise networks using simultaneous lateral movement techniques per target. This produces a detectable spike of concurrent remote logon events from a single source to many distinct targets.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-2697
- ATT&CK tags: T1021.002, T1078, T1021
- Products: Not specified
- Platforms: Windows, enterprise networks
- Malware: The Gentlemen
- Tools: Not specified
- Search tags: Storm-2697, The Gentlemen, Windows, enterprise networks, T1021.002, T1078, T1021

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1021 Remote Services/ T1021.002 SMB/Windows Admin Shares (medium); Lateral Movement: T1078 Valid Accounts (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceLogonEvents, DeviceNetworkEvents

### KQL

```kql
let propagationWindow = 60s;
let targetThreshold = 5;
let excludedAccounts = dynamic(["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"]);
DeviceLogonEvents
| where Timestamp > ago(1h)
| where LogonType in ("Network", "NetworkCleartext")
| where ActionType == "LogonSuccess"
| where AccountName !endswith "$"
| where AccountName !in (excludedAccounts)
| where isnotempty(RemoteIP)
| summarize
    TargetDevices = dcount(DeviceName),
    TargetList = make_set(DeviceName, 20),
    LogonCount = count(),
    AccountDomain = any(AccountDomain)
    by AccountName, RemoteIP, bin(Timestamp, propagationWindow)
| where TargetDevices >= targetThreshold
| rename WindowStart = Timestamp
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp > ago(1h)
    | where RemotePort in (445, 135, 139)
    | summarize SMBConnections = count() by LocalIP, SMBSourceDevice = DeviceName
) on $left.RemoteIP == $right.LocalIP
| project
    WindowStart,
    AccountName,
    AccountDomain,
    RemoteIP,
    TargetDevices,
    TargetList,
    LogonCount,
    SMBConnections = coalesce(SMBConnections, 0),
    SMBSourceDevice
| order by WindowStart desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Automated patch management or software deployment systems authenticating to many hosts simultaneously.
- IT orchestration tools such as Ansible, SCCM, or similar that perform parallel remote operations.
- Domain controllers processing Kerberos ticket requests that may appear as rapid multi-host logons.
- Vulnerability scanners performing authenticated network sweeps.

Tuning notes:
- Add known service account names used by patch management, SCCM, or orchestration tools to the excludedAccounts dynamic list.
- Consider raising targetThreshold to 10 or more in environments with large-scale automated administration.
- If RemoteIP is frequently null in the environment, consider correlating on AccountName and DeviceName alone without the network join.
- Add AccountDomain filtering to scope detection to domain accounts only if the environment uses separate naming conventions for service accounts.

Risks / caveats:
- DeviceLogonEvents.RemoteIP may be empty for some Network logon events depending on the authentication path and sensor version; if RemoteIP is null the join to DeviceNetworkEvents on RemoteIP = LocalIP will produce no results for those events.
- LogonType values in DeviceLogonEvents use string labels; confirm that 'Network' and 'NetworkCleartext' are the exact string values present in the table for the deployed sensor version, as some versions use numeric logon type codes.
- The targetThreshold of 5 distinct devices in 60 seconds may generate false positives in environments with automated deployment tooling; baseline against known orchestration accounts before scheduling.
- RemoteIP in DeviceLogonEvents represents the source IP of the authenticating client; in NAT or VPN environments this may resolve to a gateway IP rather than the individual host, causing over-counting of TargetDevices.

### Triage Runbook

First 15 minutes:
- Identify the source account, source IP, target host list, and whether the logons are concentrated on servers, workstations, or both.
- Check whether the account is a known admin, deployment, or orchestration account and whether the activity matches a scheduled job or change window.
- Look for follow-on signs of propagation such as remote service creation, SMB file activity, process launches on targets, or simultaneous file encryption alerts.
- Determine whether the source device is itself compromised or whether the source IP is a shared gateway, VPN, or NAT address that could mask the true origin.

Evidence to collect:
- AccountName, AccountDomain, RemoteIP, TargetList, LogonCount, and SMBConnections from the alert.
- DeviceLogonEvents for the same account and time window to see the full sequence of successful logons.
- DeviceNetworkEvents from the source IP or SMBSourceDevice to confirm SMB-related connections and remote administration activity.
- DeviceProcessEvents on the source device and the first few target hosts to identify suspicious tools, scripts, or service creation.
- Any identity or VPN logs that explain whether the RemoteIP is a jump host, bastion, or shared egress address.

Pivot points:
- DeviceLogonEvents filtered to the AccountName and RemoteIP to expand the target host set and timing.
- DeviceNetworkEvents for SMB ports 445, 135, and 139 on the source device and target hosts.
- DeviceProcessEvents on target hosts for remote execution tools, service creation, or suspicious child processes.
- Identity or VPN telemetry to map the source IP to a user, jump box, or remote access gateway.

Benign explanations:
- Automated patching, software deployment, or configuration management tools authenticating to many hosts.
- Vulnerability scanners or inventory tools performing authenticated sweeps.
- Domain controller or enterprise service activity that legitimately touches many systems.
- Large-scale admin actions during maintenance windows using a shared orchestration account.

Escalation criteria:
- The account is not a known automation or admin account, or the activity occurs outside a maintenance window.
- Targets include many hosts across multiple segments, especially if the sequence is unusually fast and broad.
- There are concurrent signs of ransomware, remote service creation, or suspicious process execution on targets.
- The source device or account shows additional compromise indicators such as unusual logons, new services, or malware alerts.

Containment actions:
- Disable or reset the account if it is not an approved automation identity or if compromise is likely.
- Isolate the source device if it is a workstation or server under attacker control.
- Block the source IP only if it is not a shared VPN/NAT/jump address and the activity is clearly malicious.
- Coordinate with endpoint response to inspect the first few target hosts for remote execution or encryption activity.

Closure criteria:
- The account is confirmed as an approved orchestration or admin identity and the activity matches a documented change.
- Target hosts and timing align with expected deployment or scanning behavior.
- No suspicious process execution, service creation, or encryption activity is found on source or target systems.
- Identity and network logs explain the source IP as a legitimate shared access path.

---

## Detection 3: Gogs RCE - Git Rebase Spawning Unexpected Child Process via Argument Injection

### Detection Opportunity

Git rebase process spawning a non-git child process such as a shell or interpreter on a Gogs server host, consistent with --exec flag injection via a malicious branch name in a pull request.

### Intelligence Context

- Rapid7: Authenticated RCE via Argument Injection in Gogs (NOT FIXED) — [https://www.rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed](https://www.rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed)
  - Context: An authenticated user can achieve RCE on Gogs servers by creating a pull request with a malicious branch name that injects the --exec flag into git rebase. This causes git rebase to spawn arbitrary child processes, which is detectable as an anomalous parent-child process relationship on the Gogs host.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059
- Products: Gogs
- Platforms: Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: T1059, Gogs, Linux

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
let gogsServers = dynamic([]);  // Populate with Gogs server DeviceName values before scheduling
DeviceProcessEvents
| where Timestamp > ago(1h)
| where array_length(gogsServers) == 0 or DeviceName in~ (gogsServers)
| where InitiatingProcessFileName =~ "git"
| where InitiatingProcessCommandLine has "rebase"
| where FileName in~ ("sh", "bash", "zsh", "dash", "python", "python3", "perl", "ruby", "node", "curl", "wget", "nc", "ncat")
| project
    Timestamp,
    DeviceName,
    AccountName,
    ChildProcess = FileName,
    ChildCommandLine = ProcessCommandLine,
    ParentCommandLine = InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    InitiatingProcessId,
    ProcessId
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Developer workstations where git rebase --exec is used legitimately with shell commands in CI scripts.
- Automated git tooling that wraps rebase with exec hooks for linting or testing.
- Any Linux host running git rebase with --exec as part of a legitimate workflow where the child process happens to be in the monitored list.

Tuning notes:
- Populate the gogsServers dynamic list with the DeviceName values of all hosts running Gogs before scheduling as a production rule.
- Add the Gogs service account name to an AccountName filter if the service runs under a dedicated OS user.
- If git is called via wrapper scripts, expand InitiatingProcessCommandLine matching to include the wrapper script names.
- Consider adding InitiatingProcessParentFileName has_any ('gogs', 'app') as an additional filter once the Gogs process name in telemetry is confirmed.

Risks / caveats:
- Defender for Endpoint Linux agent must be deployed on Gogs server hosts with process telemetry enabled; if the Gogs host is not onboarded, DeviceProcessEvents will contain no entries for it and the query will produce no results.
- InitiatingProcessCommandLine on Linux may contain the full argv string including arguments; the has 'git rebase' filter depends on git being invoked with that exact substring in the command line, which may vary if git is called via a wrapper script or absolute path such as /usr/bin/git rebase.
- The gogsServers dynamic list must be populated with actual Gogs server hostnames before this query is scheduled as a production rule; leaving it empty causes the query to run across the entire fleet, generating false positives from developer workstations.
- If git is invoked via an absolute path such as /usr/bin/git, the InitiatingProcessFileName field may contain the full path rather than just 'git'; test against actual telemetry from the Gogs host to confirm the field value.

### Triage Runbook

First 15 minutes:
- Confirm the host is an actual Gogs server and not a developer workstation or build host.
- Review the child process name, command line, parent command line, and initiating account to see whether the spawned process is a shell, interpreter, or download utility.
- Check whether the activity aligns with a recent pull request, branch creation, or merge event from an authenticated user.
- Look for immediate post-exploitation behavior such as outbound connections, file writes, credential access, or additional child processes.

Evidence to collect:
- DeviceName, AccountName, ChildProcess, ChildCommandLine, ParentCommandLine, InitiatingProcessParentFileName, InitiatingProcessId, and ProcessId from the alert.
- The exact branch name or pull request context if available from Gogs logs or application telemetry.
- Recent DeviceProcessEvents on the Gogs host to reconstruct the full process tree around the alert time.
- DeviceNetworkEvents from the Gogs host to identify outbound connections or downloads after the suspicious spawn.
- Any application or web logs showing the authenticated user, repository, and request path that triggered the rebase.

Pivot points:
- DeviceProcessEvents on the Gogs host for the same account and time window to find additional shells, interpreters, or download tools.
- DeviceNetworkEvents from the Gogs server to look for outbound connections following the suspicious process spawn.
- Gogs application logs or reverse proxy logs to identify the pull request, branch name, and authenticated user.
- File or audit telemetry on the Gogs host for new files, scripts, or modified repositories after the event.

Benign explanations:
- Legitimate Gogs maintenance or CI workflows that invoke git rebase with exec hooks on a server host.
- Administrative scripts that use shell or interpreter children as part of repository automation.
- Build or test automation running on the same host if Gogs is co-located with CI tooling.
- Wrapper scripts that call git indirectly and appear unusual in process telemetry.

Escalation criteria:
- The child process is a shell, interpreter, or downloader and the account is not a known service identity.
- The Gogs host shows outbound connections, file changes, or additional suspicious processes after the spawn.
- The branch name or request context contains clear injection patterns such as --exec or shell metacharacters.
- The host is internet-facing or contains sensitive repositories and the activity is not explained by a change window.

Containment actions:
- Suspend external access to the Gogs service if exploitation appears active and the host is internet-facing.
- Isolate the Gogs server if there are signs of post-exploitation activity or unauthorized command execution.
- Preserve process, application, and network telemetry before restarting or remediating the host.
- Disable the affected user account or revoke tokens if the request originated from a compromised authenticated user.

Closure criteria:
- The host is confirmed to be a non-production or approved automation system and the process tree matches documented behavior.
- The branch/request context is benign and no follow-on suspicious activity is present.
- No outbound connections, file modifications, or additional child processes indicate exploitation.
- The event is attributable to a known CI or maintenance workflow with validated command lines.

---

## Detection 4: npm Supply Chain - Node Process Spawning Child Process with Outbound Network Connection After Package Install

### Detection Opportunity

A node or npm process spawning a child process that subsequently makes an outbound network connection, consistent with malicious post-install scripts in typosquatted npm packages exfiltrating CI/CD or cloud credentials.

### Intelligence Context

- Microsoft Security Blog: Typosquatted npm packages used to steal cloud and CI/CD secrets — [https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/](https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/)
  - Context: The Mini Shai-Hulud campaign used typosquatted npm packages with malicious post-install scripts to steal cloud and CI/CD credentials from developer environments. The observable behavior is npm or node spawning child processes that make outbound network connections, consistent with credential exfiltration via post-install hooks.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059.007, T1071.001, T1059, T1071
- Products: npm
- Platforms: cloud, CI/CD
- Malware: Not specified
- Tools: Not specified
- Search tags: npm, cloud, CI/CD, T1059.007, T1071.001, T1059, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.007 JavaScript (medium); Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let lookback = 1h;
let correlationWindow = 2m;
let npmSpawnedProcesses = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessCommandLine has_any ("npm install", "npm ci", "npm run")
    or (InitiatingProcessFileName in~ ("npm", "node") and InitiatingProcessCommandLine has "install")
| where FileName !in~ ("node", "npm", "npx", "git")
| project
    DeviceName,
    AccountName,
    SpawnTime = Timestamp,
    ChildProcess = FileName,
    ChildCmdLine = ProcessCommandLine,
    ParentCmdLine = InitiatingProcessCommandLine,
    ChildProcessId = ProcessId;
let outboundConnections = DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where not(ipv4_is_private(RemoteIP))
| where RemoteIP != "127.0.0.1" and RemoteIP != "::1"
| where (isempty(RemoteUrl) or (
    RemoteUrl !has "registry.npmjs.org"
    and RemoteUrl !has "nodejs.org"
    and RemoteUrl !has "github.com"
))
| project
    DeviceName,
    NetTime = Timestamp,
    RemoteIP,
    RemoteUrl,
    RemotePort,
    NetInitiatingProcess = InitiatingProcessCommandLine,
    NetInitiatingFileName = InitiatingProcessFileName;
npmSpawnedProcesses
| join kind=inner outboundConnections on DeviceName
| where NetTime between (SpawnTime .. (SpawnTime + correlationWindow))
| project
    SpawnTime,
    DeviceName,
    AccountName,
    ChildProcess,
    ChildCmdLine,
    ParentCmdLine,
    RemoteIP,
    RemoteUrl,
    RemotePort,
    NetInitiatingProcess
| order by SpawnTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate post-install scripts that download additional build dependencies from approved CDN endpoints not in the exclusion list.
- Testing frameworks that spawn child processes with network activity as part of integration tests.
- Package managers that invoke curl or wget to download supplementary binaries during installation.
- CI/CD pipeline steps that use node to run scripts with outbound API calls to approved services.

Tuning notes:
- Expand the RemoteUrl exclusion list with internal artifact registry hostnames and approved CDN endpoints used in the CI/CD environment.
- Narrow DeviceName to known CI/CD runner hostnames to reduce noise from developer workstations.
- Consider adding ChildProcess filtering to focus on high-risk binaries such as curl, wget, bash, sh, python rather than any non-node process.
- After running as a hunting query, promote to a scheduled rule only after establishing a baseline of legitimate post-install network activity and adding appropriate exclusions.

Risks / caveats:
- DeviceNetworkEvents.RemoteUrl may be empty for connections that do not resolve to a URL or where DNS resolution is not captured by the sensor; filtering on RemoteUrl exclusions will not exclude connections where RemoteUrl is null, potentially passing legitimate registry traffic.
- The correlation between DeviceProcessEvents and DeviceNetworkEvents relies on InitiatingProcessCommandLine matching between the child process spawn and the network event; if the network connection is made by a grandchild process, the InitiatingProcessCommandLine in DeviceNetworkEvents will not match the child process and the join will miss the event.
- The correlation between process spawn and network connection is time-based and device-scoped; it does not confirm that the specific child process made the network connection, only that a network connection occurred on the same device within 2 minutes of the spawn.
- The RemoteUrl exclusion list covers only npmjs.org, nodejs.org, and github.com; environments using private artifact registries, approved CDN endpoints, or internal package mirrors will need those URLs added to the exclusion list to reduce false positives.

### Triage Runbook

First 15 minutes:
- Identify the package install context, runner or host name, account, child process, and destination URL/IP from the alert.
- Check whether the host is a CI/CD runner, developer workstation, or build server and whether the activity occurred during an expected pipeline run.
- Review the child process command line for download, shell, or credential-access behavior and determine whether the destination is an approved artifact or API endpoint.
- Look for additional signs of secret theft such as access to cloud metadata, credential files, token stores, or environment variables.

Evidence to collect:
- SpawnTime, DeviceName, AccountName, ChildProcess, ChildCmdLine, ParentCmdLine, RemoteIP, RemoteUrl, RemotePort, and NetInitiatingProcess from the alert.
- DeviceProcessEvents around the same time to reconstruct the npm/node parent-child chain and any subsequent processes.
- DeviceNetworkEvents from the same host to identify all outbound destinations and whether the traffic is to approved registries or unknown endpoints.
- Any CI/CD job metadata, package-lock changes, or build logs that show which package was installed and by whom.
- Cloud or identity logs for token use, secret access, or unusual authentication immediately after the install.

Pivot points:
- DeviceProcessEvents on the host for npm, node, sh, bash, curl, wget, python, or other spawned children.
- DeviceNetworkEvents for the host to enumerate outbound destinations and ports during the install window.
- CI/CD pipeline logs or runner telemetry to map the install to a specific job and package version.
- Identity and cloud audit logs to check for token use, secret reads, or new sessions after the event.

Benign explanations:
- Legitimate package post-install scripts that download dependencies or binaries from approved registries or CDNs.
- CI/CD jobs that run tests, linting, or build steps which spawn shells and make outbound API calls.
- Developer tooling such as Husky, lint-staged, or build wrappers that execute child processes during install.
- Internal artifact mirrors or private package registries not yet added to the allowlist.

Escalation criteria:
- The child process is a shell, downloader, or scripting interpreter and the destination is not an approved endpoint.
- The host is a sensitive CI/CD runner or developer machine with access to cloud credentials or signing keys.
- There is evidence of secret access, token use, or exfiltration after the install.
- The package name, version, or source is suspicious, typosquatted, or not expected in the build.

Containment actions:
- Pause the affected CI/CD job or disable the runner if the activity is still in progress and suspicious.
- Revoke exposed credentials, API tokens, or cloud sessions if secret theft is suspected.
- Quarantine the package source or remove the suspicious dependency from the build until validated.
- Isolate the host if it is a developer workstation and there are signs of credential access or malware execution.

Closure criteria:
- The package, destination, and child process are confirmed as approved and documented for the pipeline.
- No secret access, token abuse, or suspicious outbound destinations are found.
- The activity matches a known build or install workflow on a trusted runner.
- Any missing allowlist entries are updated and the event is attributable to legitimate automation.

---

## Detection 5: Gogs RCE - Suspicious Branch Name Containing Argument Injection Patterns in Syslog

### Detection Opportunity

Gogs application log entries via Syslog containing branch names with shell metacharacters or --exec argument injection patterns in pull request events, indicating exploitation attempts against the Gogs argument injection vulnerability.

### Intelligence Context

- Rapid7: Authenticated RCE via Argument Injection in Gogs (NOT FIXED) — [https://www.rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed](https://www.rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed)
  - Context: The Gogs RCE vulnerability is exploited by creating a pull request with a branch name that injects the --exec flag into git rebase. If Gogs application logs are forwarded to Sentinel via Syslog, branch names containing --exec or shell metacharacters in pull request events are a direct indicator of exploitation attempts.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059
- Products: Gogs
- Platforms: Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: T1059, Gogs, Linux

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- Gogs application logs must be forwarded to Microsoft Sentinel via the Syslog data connector with ProcessName populated as 'gogs' or 'Gogs'; if Gogs logs are not ingested into the Syslog table, this query will return no results.

Required telemetry:
- Syslog

### KQL

```kql
Syslog
| where TimeGenerated > ago(24h)
| where ProcessName has_any ("gogs", "Gogs")
| where SyslogMessage has_any ("pull_request", "merge", "rebase", "branch")
| where SyslogMessage matches regex @"(--exec|;|`|\$\(|\|\||&&|>>?|<)"
| project
    TimeGenerated,
    HostName,
    ProcessName,
    SyslogFacility,
    SyslogMessage
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate branch names that contain characters such as > or < used in naming conventions.
- Gogs log entries for administrative operations that include shell-like syntax in commit messages or descriptions.
- Log noise from other processes that share the 'gogs' process name string if multiple applications forward Syslog to the same workspace.

Tuning notes:
- Before scheduling, run a baseline query against the Syslog table filtering only on ProcessName has_any ('gogs', 'Gogs') to confirm that Gogs log entries are present and to inspect the SyslogMessage format.
- Scope HostName to known Gogs server hostnames once confirmed in the workspace to reduce noise from other Linux hosts.
- Refine the regex pattern based on the actual branch name representation in Gogs log output after inspecting real log samples.
- If Gogs logs are structured as JSON within SyslogMessage, consider using parse_json() to extract the branch name field directly rather than regex matching against the full message string.

Risks / caveats:
- Gogs application logs must be forwarded to Microsoft Sentinel via the Syslog data connector with ProcessName populated as 'gogs' or 'Gogs'; if Gogs logs are not ingested into the Syslog table, this query will return no results.
- The detection assumes Gogs log entries include branch name content in the SyslogMessage field for pull request and merge events; if Gogs logs branch names only in a structured log format not captured in SyslogMessage, the regex match will not fire.
- The Syslog table is populated by the Log Analytics agent or Azure Monitor Agent with Syslog collection configured; if neither agent is deployed on Gogs hosts or Syslog facility forwarding is not configured for the Gogs process, the table will not contain Gogs entries.
- The regex pattern is based on common shell injection metacharacters; the actual Gogs log format must be inspected after ingestion to confirm that branch names appear verbatim in SyslogMessage and that the regex matches the expected log structure.

### Triage Runbook

First 15 minutes:
- Confirm the Syslog host is a Gogs server and that the message is from the Gogs application process, not another service.
- Read the full SyslogMessage to identify the exact branch name, pull request context, and injection pattern.
- Check whether the branch name was part of a legitimate test, admin action, or automated workflow.
- Look for related process or network activity on the same host that would indicate successful exploitation rather than just an attempt.

Evidence to collect:
- TimeGenerated, HostName, ProcessName, SyslogFacility, and the full SyslogMessage from the alert.
- The exact branch name or request text embedded in the log message.
- Any corresponding Gogs web, reverse proxy, or application logs that identify the authenticated user and repository.
- Recent DeviceProcessEvents or host telemetry from the same server to see whether git, shell, or downloader processes were spawned.
- Any network telemetry from the Gogs host showing outbound connections after the log event.

Pivot points:
- Syslog for the same HostName and ProcessName to find adjacent Gogs events and repeated attempts.
- DeviceProcessEvents on the Gogs server to look for shells, interpreters, or git rebase child processes.
- DeviceNetworkEvents from the Gogs host to check for outbound connections after the suspicious log entry.
- Web or reverse proxy logs to identify the source IP and authenticated user behind the request.

Benign explanations:
- Unusual but legitimate branch names used in testing or proof-of-concept repositories.
- Administrative or migration activity that includes shell-like characters in log text.
- Log formatting artifacts where special characters appear in the message but are not part of a malicious branch name.
- Non-Gogs processes on the same host if Syslog forwarding is broad and process naming is ambiguous.

Escalation criteria:
- The branch name clearly contains --exec or shell metacharacters and the request came from an authenticated user.
- There is any evidence of successful command execution, outbound connections, or file changes on the Gogs host.
- Multiple similar log entries indicate repeated exploitation attempts from the same source.
- The host is internet-facing or contains sensitive repositories and the event is not explained by a known test.

Containment actions:
- Temporarily restrict access to the Gogs service if exploitation appears active or repeated.
- Block or challenge the source user or IP if the request is clearly malicious and authenticated.
- Preserve logs before any service restart or log rotation that could remove evidence.
- Escalate to the server owner to validate whether the branch/request was part of an approved test.

Closure criteria:
- The log entry is confirmed as a benign branch naming convention or approved test case.
- No corresponding process execution, network activity, or file changes indicate exploitation.
- The message format and source are validated as expected Gogs application logging.
- The event is attributable to a known user action with no security impact.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Telemetry availability:
- Gogs RCE - Git Rebase Spawning Unexpected Child Process via Argument Injection: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.
- Gogs RCE - Suspicious Branch Name Containing Argument Injection Patterns in Syslog: Gogs application logs must be forwarded to Microsoft Sentinel via the Syslog data connector with ProcessName populated as 'gogs' or 'Gogs'; if Gogs logs are not ingested into the Syslog table, this query will return no results.

Schema / correlation keys:
- npm Supply Chain - Node Process Spawning Child Process with Outbound Network Connection After Package Install: Do not schedule yet; validate as an analyst-led hunt first.

Shared-table notes:
- DeviceProcessEvents: shared by Gentlemen Ransomware - Mass File Encryption by Single Process; Gogs RCE - Git Rebase Spawning Unexpected Child Process via Argument Injection; npm Supply Chain - Node Process Spawning Child Process with Outbound Network Connection After Package Install
- DeviceNetworkEvents: shared by Gentlemen Ransomware - Self-Propagation via Rapid Lateral Logons Across Multiple Hosts; npm Supply Chain - Node Process Spawning Child Process with Outbound Network Connection After Package Install

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Gentlemen Ransomware - Mass File Encryption by Single Process; Gentlemen Ransomware - Self-Propagation via Rapid Lateral Logons Across Multiple Hosts.
2. Resolve environment-mapping detections next: Gogs RCE - Git Rebase Spawning Unexpected Child Process via Argument Injection; Gogs RCE - Suspicious Branch Name Containing Argument Injection Patterns in Syslog.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: npm Supply Chain - Node Process Spawning Child Process with Outbound Network Connection After Package Install.

### Hunting Agenda and Promotion Criteria

- npm Supply Chain - Node Process Spawning Child Process with Outbound Network Connection After Package Install: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Gogs RCE - Git Rebase Spawning Unexpected Child Process via Argument Injection: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- Gogs RCE - Suspicious Branch Name Containing Argument Injection Patterns in Syslog: Gogs application logs must be forwarded to Microsoft Sentinel via the Syslog data connector with ProcessName populated as 'gogs' or 'Gogs'; if Gogs logs are not ingested into the Syslog table, this query will return no results.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
