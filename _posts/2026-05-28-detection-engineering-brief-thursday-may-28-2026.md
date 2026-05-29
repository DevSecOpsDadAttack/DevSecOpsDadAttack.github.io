---
layout: post
title: "Detection Engineering Brief - Thursday, May 28, 2026"
subtitle: "Machine-speed threat intelligence translated into detection engineering action."
date: 2026-05-28
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - MITRE ATT&CK
  - Gogs
  - Linux
  - T1059
  - Storm-2697
  - The Gentlemen
  - Windows
  - Akira
  - consumer endpoints
  - web browsers
  - T1486
  - T1068
  - T1078
  - T1071
  - T1496
---

## Executive Signal

This brief produced 5 detection candidates.

2 production candidates, 1 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Gogs, Linux, T1059, Storm-2697, The Gentlemen, Windows, Akira, consumer endpoints, web browsers, T1486, T1068, T1078, T1071, T1496.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Gogs Git Rebase Argument Injection via Malicious Branch Name; Akira Ransomware Privilege Escalation to Domain Admin Correlated with Logon on Domain Controller; Cryptominer with RAT Module Exhibiting Sustained CPU Load and Persistent Outbound C2 Connections.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: Gogs Git Rebase Argument Injection via Malicious Branch Name

### Detection Opportunity

Authenticated user injects --exec flag into git rebase on Gogs server via malicious branch name during merge operation

### Intelligence Context

- Rapid7: Authenticated RCE via Argument Injection in Gogs (NOT FIXED) — [https://www.rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed](https://www.rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed)
  - Context: A pull request with a malicious branch name injects the --exec flag into a git rebase command executed server-side by Gogs during the rebase-before-merging merge operation, resulting in authenticated RCE.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059
- Products: Gogs
- Platforms: Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: Gogs, Linux, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (high)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (
    // git rebase with --exec flag where parent is the Gogs service
    (
        FileName =~ "git"
        and ProcessCommandLine has "rebase"
        and ProcessCommandLine has "--exec"
        and InitiatingProcessFileName has_any ("gogs", "gogs.exe")
    )
    or
    // Gogs spawning shells or interpreters unexpectedly
    (
        InitiatingProcessFileName has_any ("gogs", "gogs.exe")
        and FileName has_any ("bash", "sh", "dash", "python", "python3", "perl", "ruby", "nc", "ncat", "curl", "wget")
    )
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SHA256
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate administrative scripts that invoke git rebase --exec on the Gogs host outside of the Gogs service context may match the first branch if the parent filter is not sufficient.
- Monitoring or health-check scripts spawned by the Gogs process for legitimate operational reasons could match the child-process branch.

Tuning notes:
- Confirm the exact process name of the Gogs binary on the target host (e.g., 'gogs', 'gogs-server') and update the has_any list accordingly.
- Reduce the lookback from 7d to 1d once the query is promoted to a scheduled rule to manage query cost.
- Consider adding FolderPath exclusions for known-good git wrapper scripts if they appear in results.

Risks / caveats:
- MDE Linux agent must be deployed on the Gogs host and process command-line telemetry must be enabled; if the host is not onboarded, DeviceProcessEvents will contain no rows for it and the query will silently return nothing.
- The 7-day lookback may miss older activity if the Gogs host was only recently onboarded to MDE.
- The interpreter list (bash, sh, dash, python, python3, perl, ruby, nc, ncat, curl, wget) should be reviewed against the specific Linux distribution running Gogs to add or remove binaries.
- Legitimate git rebase --exec usage by developers with sudo or service accounts on the same host could generate noise if the Gogs binary name filter is insufficient.

### Triage Runbook

First 15 minutes:
- Confirm the alert is on the actual Gogs host and note the exact parent/child process chain, command line, and user account involved.
- Check whether the process tree shows git rebase with --exec or a Gogs-spawned shell/interpreter such as bash, sh, python, perl, ruby, curl, or wget.
- Review recent Gogs activity around the timestamp: repository, pull request, branch name, merge action, and whether the branch name contains shell metacharacters or injected arguments.
- Look for immediate post-exploitation behavior on the host such as new outbound connections, file creation in unusual paths, or additional child processes spawned by the Gogs process.

Evidence to collect:
- DeviceProcessEvents for the Gogs host covering at least 24 hours before and after the alert, including full command lines and parent/child relationships.
- Gogs application logs, repository audit logs, and merge/rebase records for the affected repository and user account.
- Any files created or modified by the spawned child process, including hashes and paths from the alert window.
- Network telemetry from the Gogs host for outbound connections initiated shortly after the suspicious rebase or child process execution.

Pivot points:
- DeviceProcessEvents filtered to the Gogs host, the initiating account, and child processes spawned by gogs or git.
- Gogs server logs or application audit logs for pull request merges, branch names, and rebase-before-merging actions.
- DeviceNetworkEvents for the Gogs host to identify outbound connections after the alert time.
- DeviceFileEvents for the Gogs host to identify dropped scripts, web shells, or modified repository content.

Benign explanations:
- A legitimate administrator may have used git rebase --exec on the Gogs host outside the service context.
- A maintenance script or health-check launched by the Gogs service may have spawned a shell or interpreter.
- The alert may reflect a false positive if the Gogs binary name filter matched an unrelated process named similarly to gogs.

Escalation criteria:
- Escalate immediately if the Gogs process spawned a shell, interpreter, downloader, or network utility after the suspicious rebase.
- Escalate if the branch name or merge metadata shows argument injection characters or attacker-controlled content.
- Escalate if there is evidence of file modification, credential access, or outbound connections from the Gogs host after the event.
- Escalate if the affected Gogs instance is internet-facing or hosts sensitive repositories.

Containment actions:
- Temporarily isolate the Gogs host from the network if there is evidence of command execution beyond the expected git process.
- Disable or suspend the affected Gogs account and revoke any tokens or SSH keys used by that user.
- Block further merges or repository writes on the affected instance until the branch name and merge path are validated.
- Preserve volatile evidence before rebooting or restarting the service.

Closure criteria:
- The branch name and merge activity are confirmed benign and no unexpected child processes, file changes, or outbound connections occurred.
- The Gogs host shows no evidence of post-exploitation activity and the alert is attributable to approved administrative use.
- Relevant logs and process telemetry were reviewed and documented, including the exact merge/rebase context.
- Any suspicious account or repository activity has been ruled out or remediated.

---

## Detection 2: The Gentlemen Ransomware Aggressive Lateral Movement via Rapid Internal SMB Connections

### Detection Opportunity

Self-propagating Go-based ransomware making rapid sequential SMB or RPC connections to multiple internal hosts from a single process

### Intelligence Context

- Microsoft Security Blog: The Gentlemen ransomware: Dissecting a self-propagating Go encryptor — [https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/](https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/)
  - Context: The Gentlemen ransomware includes an aggressive self-propagation module that performs simultaneous lateral movement across Windows networks, generating high-volume internal SMB or RPC connection patterns from a single process in a short time window.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-2697
- ATT&CK tags: T1486
- Products: Not specified
- Platforms: Windows
- Malware: The Gentlemen
- Tools: Not specified
- Search tags: Storm-2697, The Gentlemen, Windows, T1486

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Impact: T1486 Data Encrypted for Impact (high)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceNetworkEvents, DeviceLogonEvents

### KQL

```kql
let LateralMovementWindow = 5m;
let MinTargetHosts = 10;
let SuspiciousConnections =
    DeviceNetworkEvents
    | where Timestamp > ago(1d)
    | where ActionType == "ConnectionSuccess"
    | where RemotePort in (445, 135)
    | where not (
        RemoteIP startswith "127."
        or RemoteIP startswith "169.254."
        or RemoteIP == "::1"
    )
    | summarize
        TargetCount = dcount(RemoteIP),
        TargetIPs = make_set(RemoteIP, 50),
        FirstSeen = min(Timestamp),
        LastSeen = max(Timestamp)
        by DeviceName, InitiatingProcessFileName, bin(Timestamp, LateralMovementWindow)
    | where TargetCount >= MinTargetHosts;
let LateralLogons =
    DeviceLogonEvents
    | where Timestamp > ago(1d)
    | where LogonType in (3, 10)
    | summarize
        LogonCount = count(),
        LogonAccounts = make_set(AccountName, 20)
        by DeviceName, bin(Timestamp, LateralMovementWindow);
let ProcessContext =
    DeviceProcessEvents
    | where Timestamp > ago(1d)
    | summarize
        InitiatingProcessFolderPath = take_any(FolderPath),
        InitiatingProcessCommandLine = take_any(ProcessCommandLine)
        by DeviceName, FileName;
SuspiciousConnections
| join kind=leftouter LateralLogons on DeviceName, Timestamp
| join kind=leftouter (
    ProcessContext
    | project DeviceName, InitiatingProcessFileName = FileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
) on DeviceName, InitiatingProcessFileName
| project
    FirstSeen,
    LastSeen,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    TargetCount,
    TargetIPs,
    LogonCount,
    LogonAccounts
| order by TargetCount desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Vulnerability scanners, backup agents, and patch management tools that contact many hosts over SMB in short windows will match this detection.
- Domain-joined workstations running Group Policy processing or SCCM client push installations may generate bursts of SMB connections.
- Network monitoring tools performing SMB health checks across subnets will trigger this rule.

Tuning notes:
- Raise MinTargetHosts above 10 if backup agents, SCCM, or vulnerability scanners generate false positives at that threshold.
- Add an InitiatingProcessFileName exclusion list for known management tools identified during baseline review.
- Consider reducing LateralMovementWindow to 2m to tighten detection against slower propagation variants.

Risks / caveats:
- ActionType value 'ConnectionSuccess' must be present in DeviceNetworkEvents for SMB traffic; some MDE configurations emit only 'ConnectionAttempt' for blocked connections. Verify ActionType coverage for port 445 and 135 in the environment.
- The 5-minute bin window may split a rapid propagation burst across two bins if it straddles a boundary, potentially causing the TargetCount to fall below the threshold in each bin individually.
- The MinTargetHosts threshold of 10 is a starting point and should be baselined against the environment's legitimate management tooling before scheduling.
- The ProcessContext join uses take_any, which may surface a different process invocation than the one responsible for the network connections if the binary ran multiple times in the lookback window.

### Triage Runbook

First 15 minutes:
- Identify the initiating process, host, and account that generated the burst of SMB/RPC connections and confirm whether the target hosts are internal and distinct.
- Check whether the same process is also associated with suspicious logons, remote service creation, or other lateral movement indicators on the source host.
- Determine whether the target hosts are servers, workstations, or management systems and whether the activity spans multiple subnets or critical assets.
- Look for concurrent signs of ransomware impact such as file renames, mass modifications, service disruption, or user reports of inaccessible files.

Evidence to collect:
- DeviceNetworkEvents showing the full set of target IPs, ports, and timestamps for the initiating process.
- DeviceLogonEvents for the source host and target hosts to identify authentication patterns and account use.
- DeviceProcessEvents for the initiating host to capture the process path, command line, and hash of the spreading binary.
- Any endpoint alerts or user reports indicating encryption, service disruption, or rapid file changes on affected hosts.

Pivot points:
- DeviceNetworkEvents for the initiating host and process to map all SMB/RPC targets in the alert window.
- DeviceLogonEvents for LogonType 3 and 10 on the source and target hosts to identify lateral authentication.
- DeviceProcessEvents for the initiating process hash or file name across the environment to find additional infected hosts.
- DeviceFileEvents on the source and target hosts for mass rename or modification activity.

Benign explanations:
- Vulnerability scanners, backup agents, or patch management tools can contact many hosts over SMB in a short period.
- Domain-joined systems may generate bursts of SMB traffic during Group Policy processing or software deployment.
- Network monitoring or inventory tools may perform rapid connection checks that resemble propagation.

Escalation criteria:
- Escalate immediately if the same process is contacting many internal hosts over SMB/RPC and there are any signs of encryption or service disruption.
- Escalate if the initiating process is unsigned, runs from a user-writable path, or is associated with a suspicious logon session.
- Escalate if multiple hosts show similar connection bursts or if the activity reaches domain controllers, file servers, or backup infrastructure.
- Escalate if the source host also shows file modification, persistence, or credential theft indicators.

Containment actions:
- Isolate the source host from the network if propagation is ongoing or strongly suspected.
- Disable or reset the account used by the initiating process if it appears compromised.
- Block SMB/RPC lateral movement paths where feasible and alert infrastructure teams to watch for additional infected hosts.
- Prioritize containment of critical servers and backup systems if they are among the targets.

Closure criteria:
- The connection burst is confirmed to be from an approved management tool, scanner, or backup process.
- No additional hosts show suspicious SMB/RPC bursts or ransomware impact after review.
- The initiating process, account, and host are documented as benign and match known operational activity.
- Any suspicious binaries or accounts were either ruled out or remediated.

---

## Detection 3: The Gentlemen Ransomware Mass File Modification by Unsigned Go Binary

### Detection Opportunity

Go-based ransomware binary generating mass file rename and modification events across multiple directories in a short time window as part of per-file ephemeral key encryption

### Intelligence Context

- Microsoft Security Blog: The Gentlemen ransomware: Dissecting a self-propagating Go encryptor — [https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/](https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/)
  - Context: The Gentlemen ransomware encrypts files using per-file ephemeral keys, producing a high volume of FileModified and FileRenamed events across multiple directories from a single Go binary process in a compressed time window.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-2697
- ATT&CK tags: T1486
- Products: Not specified
- Platforms: Windows
- Malware: The Gentlemen
- Tools: Not specified
- Search tags: Storm-2697, The Gentlemen, Windows, T1486

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Impact: T1486 Data Encrypted for Impact (high)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let EncryptionWindow = 5m;
let MinFileEvents = 200;
let MinDirectories = 5;
let MassFileActivity =
    DeviceFileEvents
    | where Timestamp > ago(1d)
    | where ActionType in ("FileModified", "FileRenamed")
    | extend ParentDirectory = tostring(extract(@'^(.+)\\[^\\]+$', 1, FolderPath))
    | summarize
        FileEventCount = count(),
        DirectoryCount = dcount(ParentDirectory),
        SampleFiles = make_set(FileName, 10),
        WindowStart = min(Timestamp)
        by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, bin(Timestamp, EncryptionWindow)
    | where FileEventCount >= MinFileEvents and DirectoryCount >= MinDirectories;
let ProcessContext =
    DeviceProcessEvents
    | where Timestamp > ago(1d)
    | summarize SHA256 = take_any(SHA256)
        by DeviceName, FileName;
MassFileActivity
| join kind=leftouter (
    ProcessContext
) on DeviceName, $left.InitiatingProcessFileName == $right.FileName
| project
    Timestamp = WindowStart,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileEventCount,
    DirectoryCount,
    SampleFiles,
    SHA256
| order by FileEventCount desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Backup agents (e.g., Veeam, Windows Backup, Acronis) that read and rewrite large numbers of files during backup jobs will match this detection.
- Search indexing services (e.g., Windows Search, Elasticsearch) performing bulk index updates may generate high FileModified counts.
- Antivirus or EDR products performing on-access scanning and quarantine operations may rename or modify many files rapidly.

Tuning notes:
- Raise MinFileEvents above 200 if backup or indexing agents generate false positives at that threshold.
- Add an InitiatingProcessFileName exclusion for known backup agent binary names identified during baseline review.
- Consider adding a FolderPath exclusion for backup staging directories if backup agents operate in predictable paths.

Risks / caveats:
- DeviceFileEvents ActionType values 'FileModified' and 'FileRenamed' must be collected by the MDE agent on the monitored Windows hosts; file event telemetry volume settings may suppress these events on high-activity hosts if MDE is configured to reduce noise.
- The 5-minute bin window may split a rapid encryption burst across two bins if it straddles a boundary, causing FileEventCount to fall below MinFileEvents in each bin.
- The SHA256 join uses take_any, which may return a hash from a different execution of the same binary name if the process ran multiple times in the lookback window.
- MinFileEvents of 200 and MinDirectories of 5 are starting thresholds and must be baselined against backup and indexing workloads in the environment.

### Triage Runbook

First 15 minutes:
- Confirm the initiating process name, path, hash, and command line, and verify whether it is an unsigned or unknown Go binary.
- Review the sample files and directory spread to see whether the changes are broad, rapid, and consistent with encryption rather than a single application workflow.
- Check whether the same host has concurrent network alerts, suspicious logons, or other ransomware indicators.
- Ask the user or system owner whether a backup, indexing, antivirus, or deployment job was running at the same time.

Evidence to collect:
- DeviceFileEvents for the host covering the alert window, including file names, paths, and action types.
- DeviceProcessEvents for the initiating binary, including hash, command line, parent process, and execution path.
- Any ransom note files, extension changes, or deleted shadow copy indicators if available from other telemetry.
- User or admin activity records showing whether a legitimate bulk operation was scheduled.

Pivot points:
- DeviceFileEvents for the initiating process hash or file name to identify other affected directories and hosts.
- DeviceProcessEvents for the same SHA256 to determine whether the binary executed elsewhere.
- DeviceNetworkEvents for the host to look for outbound connections associated with the same process.
- DeviceFileEvents for ransom note filenames, mass renames, or repeated modifications in the same time window.

Benign explanations:
- Backup agents can rewrite many files across multiple directories during normal jobs.
- Search indexing, synchronization, or antivirus tools can generate large volumes of file modifications and renames.
- Software deployment or update processes may touch many files in a short period.

Escalation criteria:
- Escalate immediately if the file activity is accompanied by ransom notes, extension changes, or other encryption indicators.
- Escalate if the binary is unsigned, unknown, or launched from a user-writable path and no legitimate job explains the activity.
- Escalate if the same host shows lateral movement, privilege escalation, or outbound C2 activity.
- Escalate if multiple endpoints begin showing similar mass file modification patterns.

Containment actions:
- Isolate the host if encryption is active or strongly suspected.
- Stop the suspicious process if it is still running and preserve the binary and command line for analysis.
- Disable affected user accounts if the process was launched under a compromised account.
- Coordinate with backup teams to protect recovery points and prevent further spread.

Closure criteria:
- The file activity is confirmed to be from a known backup, indexing, or maintenance process.
- No ransom notes, encryption artifacts, or additional suspicious host activity are found.
- The binary hash, path, and command line match an approved application or scheduled task.
- The alert is documented with the legitimate job owner and timing.

---

## Detection 4: Akira Ransomware Privilege Escalation to Domain Admin Correlated with Logon on Domain Controller

### Detection Opportunity

Attacker escalates to domain admin privileges during Akira intrusion, evidenced by special privilege assignment correlated with a new network logon on a domain controller

### Intelligence Context

- SANS ISC: Reconstructing an Akira Ransomware Kill Chain from Perimeter and Endpoint Logs, (Wed, May 27th) — [https://isc.sans.edu/diary/rss/33024](https://isc.sans.edu/diary/rss/33024)
  - Context: The SANS ISC article reconstructs an Akira intrusion kill chain and specifically investigates when attackers obtained domain admin, using Windows Security Event logs correlated across perimeter and endpoint sources.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1068, T1078
- Products: Not specified
- Platforms: Windows
- Malware: Akira
- Tools: Not specified
- Search tags: Akira, Windows, T1068, T1078

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Privilege Escalation: T1068 Exploitation for Privilege Escalation (low); Persistence: T1078 Valid Accounts (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.

Required telemetry:
- SecurityEvent

### KQL

```kql
let CorrelationWindow = 10m;
let DCLogons =
    SecurityEvent
    | where TimeGenerated > ago(1d)
    | where EventID == 4624
    | where LogonType in (3, 10)
    | where Computer has_any ("DC", "PDC", "GC")
    | project
        LogonTime = TimeGenerated,
        TargetUserName,
        LogonType,
        Computer;
let PrivEscalation =
    SecurityEvent
    | where TimeGenerated > ago(1d)
    | where EventID == 4672
    | where PrivilegeList has_any ("SeDebugPrivilege", "SeTcbPrivilege", "SeBackupPrivilege", "SeRestorePrivilege")
    | project
        PrivTime = TimeGenerated,
        SubjectUserName,
        PrivilegeList,
        Computer;
DCLogons
| join kind=inner PrivEscalation
    on $left.TargetUserName == $right.SubjectUserName
| where Computer == Computer1
| where abs(datetime_diff('second', LogonTime, PrivTime)) <= totimespan(CorrelationWindow)
| project
    LogonTime,
    PrivTime,
    Computer,
    TargetUserName,
    LogonType,
    PrivilegeList
| order by LogonTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate domain administrators performing remote administration tasks on domain controllers will match this detection.
- Automated privileged access management (PAM) solutions that check out domain admin credentials and log on to DCs for rotation or validation will generate matches.
- Backup software running under domain admin accounts on DCs will match due to SeBackupPrivilege and SeRestorePrivilege.

Tuning notes:
- Replace Computer has_any ("DC", "PDC", "GC") with a lookup against a watchlist or explicit list of DC hostnames in the environment.
- Consider restricting PrivilegeList to SeDebugPrivilege and SeTcbPrivilege only to reduce volume from backup-related privilege assignments.
- Add a TargetUserName exclusion for known privileged service accounts that legitimately log on to DCs with elevated privileges.

Risks / caveats:
- EventID 4672 and 4624 must be collected from domain controllers into the Sentinel SecurityEvent table via the Log Analytics agent or AMA with the appropriate Windows Security Events data connector configured for DC hosts.
- The Computer has_any ("DC", "PDC", "GC") filter is a hostname substring assumption that will silently exclude all domain controllers whose names do not contain these strings, producing no results in environments with different DC naming conventions.
- The Computer has_any ("DC", "PDC", "GC") filter must be replaced with the actual domain controller hostnames or a Sentinel watchlist lookup before this query will return meaningful results.
- SeBackupPrivilege and SeRestorePrivilege are assigned to many legitimate backup service accounts on DCs; restricting to SeDebugPrivilege and SeTcbPrivilege alone will significantly reduce false positives at the cost of some coverage.

### Triage Runbook

First 15 minutes:
- Verify the domain controller hostname and the exact user account involved, since the hostname filter may be environment-specific.
- Check whether the 4624 logon and 4672 special privileges occurred within the correlation window for the same account and host.
- Determine whether the account is a known admin, service account, or unexpected user and whether the logon source is legitimate.
- Look for follow-on actions from the same account such as group membership changes, remote service creation, or additional DC logons.

Evidence to collect:
- SecurityEvent records for EventID 4624 and 4672 on the relevant domain controller, including LogonType, PrivilegeList, and source details.
- Account history for the user, including recent password changes, group membership changes, and prior logon patterns.
- Any related endpoint or network telemetry showing the source host or workstation used for the logon.
- Administrative activity logs or PAM records if the account is managed by a privileged access system.

Pivot points:
- SecurityEvent for the same TargetUserName or SubjectUserName across all domain controllers.
- SecurityEvent for EventID 4728, 4732, 4756, 7040, or other privilege/group change events around the same time.
- Device or network logs for the source workstation or IP associated with the logon.
- PAM or identity logs to confirm whether the account checkout or elevation was authorized.

Benign explanations:
- A legitimate domain administrator may have logged on to a DC for maintenance or incident response.
- Backup software or privileged service accounts may legitimately receive SeBackupPrivilege or SeRestorePrivilege on DCs.
- PAM workflows can generate a network logon followed by special privilege assignment on a DC.

Escalation criteria:
- Escalate immediately if the account is not a known administrator or the source host is unfamiliar or suspicious.
- Escalate if the logon is followed by group membership changes, remote execution, or other domain control actions.
- Escalate if the account shows signs of compromise, such as unusual source IPs, impossible travel, or recent credential theft indicators.
- Escalate if multiple DCs show the same account receiving special privileges unexpectedly.

Containment actions:
- Disable or suspend the suspicious account if compromise is likely and coordinate with identity teams before taking action on privileged accounts.
- Isolate the source workstation or jump host if it appears to be the origin of the logon.
- Force credential reset or token revocation for the affected account if unauthorized use is confirmed.
- Increase monitoring on domain controllers for additional privileged activity until the incident is resolved.

Closure criteria:
- The logon and privilege assignment are confirmed as authorized administrative or PAM activity.
- The account, source host, and timing match approved change or maintenance records.
- No additional suspicious domain controller activity or privilege changes are found.
- Any environment-specific DC hostname mapping issues have been corrected for future detections.

---

## Detection 5: Cryptominer with RAT Module Exhibiting Sustained CPU Load and Persistent Outbound C2 Connections

### Detection Opportunity

Cryptominer process with embedded RAT module maintaining persistent outbound connections to non-standard or mining pool ports while sustaining high CPU utilization

### Intelligence Context

- Securelist: Pirates in the crosshairs: how one cybercrime gang has been infecting book, movie, and TV show fans for years — [https://securelist.com/video-books-pirates-miners-rat/119943/](https://securelist.com/video-books-pirates-miners-rat/119943/)
  - Context: A cybercrime campaign targeting consumers of pirated content deployed a cryptominer that subsequently gained a RAT module, combining sustained CPU-intensive mining activity with C2 network connectivity characteristic of remote access tooling.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1496
- Products: Not specified
- Platforms: consumer endpoints, web browsers
- Malware: Not specified
- Tools: Not specified
- Search tags: consumer endpoints, web browsers, T1071, T1496

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol (low); Resource Development: T1496 Resource Hijacking (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceNetworkEvents, DeviceProcessEvents

### KQL

```kql
let MiningPorts = dynamic([3333, 4444, 5555, 7777, 8888, 9999, 14444, 45700]);
let SuspiciousNetworkActivity =
    DeviceNetworkEvents
    | where Timestamp > ago(1d)
    | where ActionType in ("ConnectionSuccess", "ConnectionAttempt")
    | where RemotePort in (MiningPorts)
    | summarize
        ConnectionCount = count(),
        DistinctRemoteIPs = dcount(RemoteIP),
        RemoteIPs = make_set(RemoteIP, 10),
        Ports = make_set(RemotePort, 10),
        FirstSeen = min(Timestamp)
        by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
    | where ConnectionCount > 20;
let ProcessPaths =
    DeviceProcessEvents
    | where Timestamp > ago(1d)
    | where FolderPath has_any ("AppData", "Temp", "Downloads", "\\Users\\")
    | summarize
        FolderPath = take_any(FolderPath),
        ProcessCommandLine = take_any(ProcessCommandLine),
        ParentProcessName = take_any(ParentProcessName),
        SHA256 = take_any(SHA256)
        by DeviceName, FileName;
SuspiciousNetworkActivity
| join kind=leftouter (
    ProcessPaths
    | project DeviceName, InitiatingProcessFileName = FileName, FolderPath, ProcessCommandLine, ParentProcessName, SHA256
) on DeviceName, InitiatingProcessFileName
| where isnotempty(FolderPath)
| project
    FirstSeen,
    DeviceName,
    InitiatingProcessFileName,
    FolderPath,
    ProcessCommandLine,
    ParentProcessName,
    ConnectionCount,
    DistinctRemoteIPs,
    RemoteIPs,
    Ports,
    SHA256
| order by ConnectionCount desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate peer-to-peer applications (torrent clients, game launchers) installed in AppData that contact many peers over high-numbered ports will match.
- Browser update helpers and user-installed software in AppData that make frequent outbound connections will generate false positives.
- Development tools such as Node.js servers or Python HTTP servers running from user directories on developer workstations may match.

Tuning notes:
- Expand MiningPorts with additional Stratum protocol ports as threat intelligence for this campaign becomes available.
- Raise ConnectionCount above 20 if peer-to-peer or update client software generates false positives at that threshold.
- Consider adding a SHA256 lookup against VirusTotal or an internal threat intelligence watchlist to strengthen the signal before scheduling as a rule.
- Add FolderPath exclusions for known legitimate software paths within AppData (e.g., browser update helpers) identified during baseline review.

Risks / caveats:
- ActionType 'ConnectionAttempt' may not be populated in all MDE configurations; verify that both 'ConnectionSuccess' and 'ConnectionAttempt' are present in DeviceNetworkEvents for the monitored endpoints before relying on connection count thresholds.
- The MiningPorts list is speculative; the actual ports used by this campaign are not confirmed in the source article and the list may miss the true C2 ports or generate noise from unrelated services.
- The user-writable path heuristic is broad and will generate significant false positives from legitimate user-installed software on consumer endpoints.
- The 1-hour bin window and ConnectionCount threshold of 20 are not derived from observed campaign behavior and require baselining against the environment.

### Triage Runbook

First 15 minutes:
- Confirm the process path, hash, parent process, and whether it is running from a user-writable location such as AppData, Temp, Downloads, or a user profile.
- Check whether the endpoint is experiencing sustained CPU load, fan activity, or user complaints about slowness at the same time as the network connections.
- Review the remote IPs and ports to see whether the traffic is to known mining pools, unusual high ports, or repeated persistent destinations.
- Determine whether the process is associated with a browser, pirated content installer, game launcher, or other user-installed software.

Evidence to collect:
- DeviceProcessEvents for the suspicious binary, including SHA256, command line, parent process, and execution path.
- DeviceNetworkEvents showing the remote IPs, ports, connection frequency, and whether connections are persistent.
- Endpoint performance telemetry or user reports indicating CPU saturation or degraded performance.
- Any downloaded files, browser history, or recent user activity that may explain the process origin.

Pivot points:
- DeviceProcessEvents for the same SHA256 or file name across the environment to find other affected endpoints.
- DeviceNetworkEvents for the same remote IPs or ports to identify additional hosts communicating with the infrastructure.
- DeviceFileEvents for recent downloads or file drops in user-writable paths.
- Browser or download telemetry if available to determine whether the process was introduced via pirated content or a browser-based installer.

Benign explanations:
- Legitimate user-installed applications in AppData or Downloads may maintain persistent connections and use CPU heavily.
- Game launchers, peer-to-peer clients, or update helpers can resemble mining or RAT behavior on consumer endpoints.
- Developer tools or local servers running from user directories may generate similar network and CPU patterns.

Escalation criteria:
- Escalate if the process is unsigned, unknown, or clearly associated with pirated content, and the CPU/network behavior is sustained.
- Escalate if the remote destinations are suspicious, repeated, or match mining-like behavior and the endpoint is not expected to run such software.
- Escalate if the process shows additional RAT-like actions such as spawning shells, downloading payloads, or creating persistence.
- Escalate if multiple consumer endpoints show the same hash or similar behavior.

Containment actions:
- Isolate the endpoint if the process is confirmed malicious or if there is evidence of RAT activity.
- Terminate the suspicious process and preserve the binary and command line for analysis.
- Block the remote IPs or domains if they are confirmed malicious and not shared infrastructure.
- Remove the binary and any persistence mechanisms after evidence capture and coordinate with the user to restore normal operation.

Closure criteria:
- The process is identified as a legitimate application or user-approved software and the network destinations are benign.
- CPU and network activity return to normal after the process is stopped or the legitimate application is validated.
- No additional endpoints show the same hash, persistence, or suspicious outbound connections.
- The alert is documented with the confirmed benign explanation or remediation steps.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Other deployment dependency:
- Gogs Git Rebase Argument Injection via Malicious Branch Name: Defender for Endpoint file-event coverage must be confirmed on the target host population.

Telemetry availability:
- Akira Ransomware Privilege Escalation to Domain Admin Correlated with Logon on Domain Controller: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.

Schema / correlation keys:
- Cryptominer with RAT Module Exhibiting Sustained CPU Load and Persistent Outbound C2 Connections: Do not schedule yet; validate as an analyst-led hunt first.

Shared-table notes:
- DeviceProcessEvents: shared by Gogs Git Rebase Argument Injection via Malicious Branch Name; The Gentlemen Ransomware Mass File Modification by Unsigned Go Binary; Cryptominer with RAT Module Exhibiting Sustained CPU Load and Persistent Outbound C2 Connections
- DeviceNetworkEvents: shared by The Gentlemen Ransomware Aggressive Lateral Movement via Rapid Internal SMB Connections; Cryptominer with RAT Module Exhibiting Sustained CPU Load and Persistent Outbound C2 Connections

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: The Gentlemen Ransomware Aggressive Lateral Movement via Rapid Internal SMB Connections; The Gentlemen Ransomware Mass File Modification by Unsigned Go Binary.
2. Resolve environment-mapping detections next: Gogs Git Rebase Argument Injection via Malicious Branch Name; Akira Ransomware Privilege Escalation to Domain Admin Correlated with Logon on Domain Controller.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Cryptominer with RAT Module Exhibiting Sustained CPU Load and Persistent Outbound C2 Connections.

### Hunting Agenda and Promotion Criteria

- Cryptominer with RAT Module Exhibiting Sustained CPU Load and Persistent Outbound C2 Connections: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Gogs Git Rebase Argument Injection via Malicious Branch Name: Defender for Endpoint file-event coverage must be confirmed on the target host population..
- Akira Ransomware Privilege Escalation to Domain Admin Correlated with Logon on Domain Controller: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
