---
layout: post
title: "Detection Engineering Brief - Wednesday, September 30, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-30
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - MSP360
  - ScreenConnect
  - Windows
  - Storm-3068
  - NeedyMantis
  - T1219
  - T1098
  - T1098.003
  - T1530
  - T1547
  - T1547.001
  - T1053
  - T1053.005
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

2 production candidates, 3 hunting-only, 0 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: MSP360, ScreenConnect, Windows, Storm-3068, NeedyMantis, T1219, T1098, T1098.003, T1530, T1547, T1547.001, T1053, T1053.005.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Concurrent Multi-RMM Tool Installation on Single Endpoint; NeedyMantis - Loader Process Writing Encrypted or Unusually Named Archive Files to User or Temp Directories; NeedyMantis - Unsigned or Unknown Binary Establishing Persistence via Registry Run Key or Scheduled Task.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: RMM Chaining - ScreenConnect Spawned by MSP360 Agent Process

### Detection Opportunity

MSP360 RMM tool used to deploy ScreenConnect remote access software, creating redundant remote-access channels

### Intelligence Context

- Microsoft Security Blog: Phishing Abuses RMM Tools for Persistent Access — [https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/](https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/)
  - Context: Phishing campaigns abused MSP360 RMM to deploy ScreenConnect, creating redundant remote-access channels for follow-on activity.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1219
- Products: MSP360, ScreenConnect
- Platforms: Windows
- Malware: Not specified
- Tools: ScreenConnect, MSP360
- Search tags: MSP360, ScreenConnect, Windows, T1219

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1219 Remote Access Software (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let lookback = 24h;
let msp360Processes = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ ("BackupAgent.exe", "BackupAgentService.exe", "MSP360.exe", "CloudBerry.exe")
| project DeviceName, msp360Time = Timestamp, msp360Process = FileName, AccountName, msp360FolderPath = InitiatingProcessFolderPath;
let screenConnectProcesses = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ ("ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe", "ConnectWiseControl.ClientService.exe")
    or ProcessCommandLine has_any ("screenconnect", "connectwise")
| where InitiatingProcessFileName in~ ("BackupAgent.exe", "BackupAgentService.exe", "MSP360.exe", "CloudBerry.exe")
    or InitiatingProcessFileName =~ ""
| summarize
    scTime = min(Timestamp),
    scProcess = any(FileName),
    scCommandLine = any(ProcessCommandLine),
    InitiatingProcessCommandLine = any(InitiatingProcessCommandLine)
    by DeviceName;
msp360Processes
| join kind=inner screenConnectProcesses on DeviceName
| where scTime between (msp360Time .. (msp360Time + 1h))
| extend TimeDeltaMinutes = datetime_diff('minute', scTime, msp360Time)
| project
    DeviceName,
    AccountName,
    msp360Process,
    msp360Time,
    scProcess,
    scTime,
    scCommandLine,
    InitiatingProcessCommandLine,
    TimeDeltaMinutes
| order by msp360Time desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Endpoints where IT legitimately manages both MSP360 and ScreenConnect and deploys or updates ScreenConnect via MSP360 automation.
- Software deployment pipelines that use MSP360 as a distribution mechanism for authorized ScreenConnect rollouts.

**Tuning notes:**
- Add a → where DeviceName !in~ (exclusion_list) filter after the join to suppress known co-managed endpoints.
- If MSP360 uses intermediate processes, remove the InitiatingProcessFileName filter from the ScreenConnect subquery and rely solely on the temporal join.
- Adjust the 1h window in the between clause to match observed deployment timing in the environment.

**Risks / caveats:**
- The InitiatingProcessFileName filter on the ScreenConnect subquery requires that MSP360 directly spawns ScreenConnect as a child process. If MSP360 uses an intermediate script host (cmd.exe, powershell.exe, msiexec.exe) the direct parent filter will miss the chain; the fallback empty-string OR branch preserves temporal detection in that case but reduces specificity.
- MSP360 process names may differ across product versions or rebranded deployments; validate BackupAgent.exe, BackupAgentService.exe, MSP360.exe, and CloudBerry.exe against observed process names in the environment.
- The 1-hour temporal window may need adjustment if legitimate ScreenConnect deployments via MSP360 in the environment take longer than 1 hour to complete.
- Endpoints co-managed by MSPs with both tools authorized should be added to a DeviceName exclusion list to suppress recurring alerts.

### Triage Runbook

**First 15 minutes:**
- Confirm whether the device is a known MSP-managed or IT-administered endpoint and whether ScreenConnect deployment was expected.
- Review the parent/child process chain, command line, and timing to verify MSP360 directly launched ScreenConnect or an intermediate script/installer did so.
- Check whether the ScreenConnect session is active, who initiated it, and whether any other remote access tools were installed or executed around the same time.
- Look for recent phishing, suspicious logons, or helpdesk tickets tied to the same host or account.

**Evidence to collect:**
- DeviceName, AccountName, msp360Process, msp360Time, scProcess, scTime, scCommandLine, InitiatingProcessCommandLine, TimeDeltaMinutes.
- Any ScreenConnect service/session logs, installation records, and remote session operator identity.
- Recent DeviceProcessEvents for the same host showing additional RMM tools, script hosts, installers, or PowerShell activity.
- User or admin ticket/change record proving the deployment was authorized.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and AccountName within +/- 24h to find other remote access tools or installers.
- DeviceNetworkEvents to identify outbound connections from ScreenConnect or MSP360 processes to remote management infrastructure.
- DeviceLogonEvents and SigninLogs to correlate the account with unusual logons or MFA prompts.
- Alert/incident history for the host to see whether this is part of a broader intrusion.

**Benign explanations:**
- Authorized MSP360 automation used to deploy or update ScreenConnect on a managed endpoint.
- IT onboarding or software rollout where both tools are intentionally present during migration.
- Lab, staging, or support workstation where dual remote access is standard practice.

**Escalation criteria:**
- ScreenConnect was not approved for this host or was installed outside a change window.
- The initiating account is non-IT, newly created, compromised, or shows suspicious sign-in behavior.
- Additional remote access tools, script execution, or persistence activity are present on the same host.
- The ScreenConnect session is active and cannot be tied to a known administrator or ticket.

**Containment actions:**
- If unauthorized, isolate the endpoint from the network and terminate active remote sessions.
- Disable or reset the suspected account and revoke active sessions/tokens if the account appears compromised.
- Remove unauthorized RMM software only after preserving evidence and coordinating with IT if the host is managed.
- Block known malicious remote access infrastructure only if confirmed by investigation.

**Closure criteria:**
- A valid change ticket, MSP record, or admin confirmation explains the MSP360-to-ScreenConnect deployment.
- No additional suspicious process activity, remote sessions, or persistence indicators are found.
- The endpoint is confirmed to be a managed device with expected dual-RMM usage.
- Any suspicious account activity has been ruled out or remediated.

<br/>
---
<br/>

## Detection 2: Concurrent Multi-RMM Tool Installation on Single Endpoint

### Detection Opportunity

Multiple distinct RMM tools installed or executed concurrently on the same endpoint to establish redundant remote-access channels

### Intelligence Context

- Microsoft Security Blog: Phishing Abuses RMM Tools for Persistent Access — [https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/](https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/)
  - Context: Attackers created redundant remote-access channels by installing multiple RMM tools concurrently on compromised endpoints following phishing delivery.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1219
- Products: MSP360, ScreenConnect
- Platforms: Windows
- Malware: Not specified
- Tools: ScreenConnect, MSP360
- Search tags: MSP360, ScreenConnect, Windows, T1219

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Persistence: T1219 Remote Access Software (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let lookback = 7d;
let rmmProcessNames = dynamic([
    "ScreenConnect.ClientService.exe", "ConnectWiseControl.ClientService.exe",
    "BackupAgent.exe", "BackupAgentService.exe", "MSP360.exe", "CloudBerry.exe",
    "AnyDesk.exe", "TeamViewer.exe", "TeamViewer_Service.exe",
    "LTService.exe", "LTSvc.exe", "Automate.exe",
    "NinjaRMMAgent.exe", "NinjaRMM.exe",
    "Atera.exe", "AteraAgent.exe",
    "SplashtopSOS.exe", "SRService.exe"
]);
let rmmEvents = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ (rmmProcessNames)
| summarize
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    AccountName = any(AccountName)
    by DeviceName, FileName;
rmmEvents
| join kind=inner (
    rmmEvents
    | project DeviceName, FileName2 = FileName, Time2 = FirstSeen
) on DeviceName
| where FileName != FileName2
| where abs(datetime_diff('minute', FirstSeen, Time2)) <= 120
| summarize
    RMMTools = make_set(pack_array(FileName, FileName2)),
    FirstSeen = min(FirstSeen),
    LastSeen = max(LastSeen),
    AccountName = any(AccountName)
    by DeviceName
| extend
    DistinctToolCount = array_length(RMMTools),
    WindowMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| where DistinctToolCount >= 2
| project DeviceName, AccountName, FirstSeen, LastSeen, WindowMinutes, DistinctToolCount, RMMTools
| order by FirstSeen desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- MSP-managed endpoints where multiple RMM agents are legitimately deployed and run concurrently.
- IT onboarding workflows that install a new RMM agent while the previous one is still running.
- Security assessment or pen-test activities using multiple remote access tools.

**Tuning notes:**
- Add → where DeviceName !in~ (known_msp_endpoints) before the final project to suppress managed endpoints.
- Reduce the 120-minute window to tighten the detection if legitimate sequential RMM deployments in the environment complete within a shorter timeframe.
- Consider promoting to scheduled_rule only after baselining the environment and establishing a DeviceName exclusion list.

**Risks / caveats:**
- The self-join on rmmEvents produces a row per pair of distinct tools; the final make_set collapses these but may produce duplicate tool entries in the array depending on KQL evaluation order. Analysts should review the RMMTools array for duplicates.
- Environments with many legitimately co-deployed RMM agents will generate high volumes of results; a DeviceName exclusion list is strongly recommended before using this as a scheduled rule.
- The 120-minute proximity threshold is a heuristic; adjust based on observed legitimate deployment timing in the environment.

### Triage Runbook

**First 15 minutes:**
- Identify which RMM tools were present and whether they are normally approved for this endpoint or business unit.
- Check whether the tools appeared during a known migration, onboarding, or support activity.
- Review the account context and process lineage for each tool to see if one installer or process deployed multiple agents.
- Look for signs of user interaction, phishing, or recent privilege changes on the host.

**Evidence to collect:**
- DeviceName, AccountName, FirstSeen, LastSeen, WindowMinutes, RMMTools, DistinctToolCount.
- Process command lines and parent processes for each RMM executable.
- Any installation logs, software deployment records, or endpoint management records showing approved rollout.
- Recent sign-in and logon data for the account associated with the installs.

**Pivot points:**
- DeviceProcessEvents for the host to find installers, script hosts, or service creation around FirstSeen/LastSeen.
- DeviceFileEvents and DeviceRegistryEvents to identify dropped binaries, service installs, or persistence artifacts.
- DeviceNetworkEvents to see whether the RMM tools contacted known vendor infrastructure or unusual external IPs.
- SigninLogs or DeviceLogonEvents to correlate the install window with suspicious access.

**Benign explanations:**
- Managed endpoint where multiple RMM agents are intentionally co-deployed during a migration or support transition.
- IT onboarding workflow that installs a new RMM agent before removing the old one.
- Security testing or remote support validation using multiple approved tools.

**Escalation criteria:**
- The endpoint is not expected to have multiple RMM tools and no change record explains the overlap.
- One or more tools were installed by a non-admin, unusual, or recently compromised account.
- The tools were dropped from temp/user-writable paths or accompanied by persistence, script execution, or credential theft behavior.
- The host shows active remote sessions or additional post-install activity inconsistent with normal IT operations.

**Containment actions:**
- If unauthorized, isolate the endpoint and disable active remote access sessions.
- Remove unauthorized RMM agents after preserving evidence and confirming business impact.
- Reset or disable the account used to install the tools if compromise is suspected.
- Coordinate with IT before removal on managed endpoints to avoid disrupting legitimate support.

**Closure criteria:**
- The tool combination is confirmed as approved for the endpoint and supported by a ticket or deployment record.
- No suspicious account activity, persistence, or follow-on execution is found.
- The overlap is explained by a documented migration or onboarding process.
- Any unauthorized tools have been removed or the alert is otherwise accounted for by legitimate operations.

<br/>
---
<br/>

## Detection 3: Storm-3068 - Compromised Identity Performing Cloud Role Assignment and Multi-Resource Access Expansion

### Detection Opportunity

Single compromised identity used to assign new roles and access multiple cloud resources in rapid succession, expanding cloud access beyond initial compromise

### Intelligence Context

- Microsoft Security Blog: Beyond source code: A path to the keys to the kingdom — [https://www.microsoft.com/en-us/security/blog/2026/09/29/beyond-source-code-a-path-to-the-keys-to-the-kingdom/](https://www.microsoft.com/en-us/security/blog/2026/09/29/beyond-source-code-a-path-to-the-keys-to-the-kingdom/)
  - Context: Storm-3068 turned a single compromised identity into broader cloud access by escalating privileges and accessing multiple cloud resources, representing a post-compromise lateral movement pattern within cloud infrastructure.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-3068
- ATT&CK tags: T1098, T1098.003, T1530
- Products: Not specified
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: Storm-3068, T1098, T1098.003, T1530

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Privilege Escalation: T1098 Account Manipulation/ T1098.003 Additional Cloud Roles (high); Lateral Movement: T1530 Data from Cloud Storage Object (low)

### Deployment Gates

- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Required telemetry:**
- AuditLogs, SigninLogs

### KQL

```kql
let lookback = 1h;
let roleAssignments = AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName in ("Add member to role", "Add eligible member to role", "Add app role assignment to service principal", "Add delegated permission grant")
| where Result =~ "success"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| where isnotempty(Actor)
| project AssignTime = TimeGenerated, Actor, OperationName, TargetResource = tostring(TargetResources[0].displayName);
let resourceAccess = AuditLogs
| where TimeGenerated > ago(lookback)
| where Result =~ "success"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| where isnotempty(Actor)
| summarize
    DistinctResources = dcount(tostring(TargetResources[0].displayName)),
    ResourceList = make_set(tostring(TargetResources[0].displayName)),
    LastAccess = max(TimeGenerated),
    EarliestAccess = min(TimeGenerated)
    by Actor;
roleAssignments
| join kind=inner resourceAccess on Actor
| where DistinctResources >= 3
| where LastAccess >= AssignTime
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType == 0
    | summarize
        RiskLevel = max(RiskLevelDuringSignIn),
        SigninIP = take_any(IPAddress)
        by UserPrincipalName
) on $left.Actor == $right.UserPrincipalName
| project
    Actor,
    AssignTime,
    OperationName,
    TargetResource,
    DistinctResources,
    ResourceList,
    EarliestAccess,
    LastAccess,
    RiskLevel,
    SigninIP
| order by AssignTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Privileged administrators who routinely assign roles and then immediately access multiple resources as part of normal operations.
- Automated service accounts or deployment pipelines that perform role assignments followed by multi-resource configuration.
- Break-glass account usage during incident response where broad resource access follows emergency role assignment.

**Tuning notes:**
- Add → where Actor !in~ (known_admin_upns) before the final project to suppress known privileged admin accounts.
- Increase DistinctResources threshold from 3 to 5 or higher if legitimate admin workflows routinely access many resources after role assignments.
- Add a separate detection branch targeting InitiatedBy.app.displayName for service principal-initiated role escalations.

**Risks / caveats:**
- AuditLogs and SigninLogs require the Microsoft Entra ID (Azure Active Directory) data connector to be enabled and ingesting into the Sentinel workspace. If the connector is absent, both tables will be empty and the query will return no results.
- RiskLevelDuringSignIn is only populated when Microsoft Entra ID P2 licensing (Identity Protection) is active. Without P2, the field will be empty for all sign-in records, making the risk enrichment column always null.
- The resourceAccess subquery counts all AuditLogs operations including the role assignment operations themselves, which may inflate the DistinctResources count. If role assignment target resources should be excluded from the resource access count, add a OperationName exclusion filter to the resourceAccess subquery.
- The 1-hour lookback window means the query must run at least every hour as a scheduled rule to avoid missing events at window boundaries; consider a 2-hour lookback with deduplication if ingestion delays are observed.

### Triage Runbook

**First 15 minutes:**
- Identify the actor, role assignment target, and the exact resources accessed after the assignment.
- Check whether the sign-in was risky, unfamiliar, or from an unusual IP/location/device.
- Confirm whether the role assignment was expected and whether the actor is a privileged admin or service account.
- Look for concurrent suspicious activity such as consent grants, mailbox access, token abuse, or additional role changes.

**Evidence to collect:**
- Actor, AssignTime, OperationName, TargetResource, DistinctResources, ResourceList, EarliestAccess, LastAccess, RiskLevel, SigninIP.
- AuditLogs entries for the role assignment and subsequent resource accesses.
- SigninLogs for the actor around the same time, including IP, device, MFA status, and risk indicators.
- Any CorrelationId or related incident records linking the same identity activity.

**Pivot points:**
- AuditLogs for the same Actor to find other role changes, consent grants, or privileged operations.
- SigninLogs for the Actor to identify unusual sign-ins, MFA failures, or impossible travel.
- Azure resource activity logs or workload-specific audit logs for the accessed resources.
- Identity Protection or risk events tied to the same user principal.

**Benign explanations:**
- A privileged administrator performing routine role assignment and immediate post-change validation.
- Break-glass or incident-response activity where broad access follows an emergency role change.
- Automated deployment or service principal workflow that legitimately assigns roles and touches multiple resources.

**Escalation criteria:**
- The role assignment was not approved or was performed by an unexpected identity.
- The sign-in is high risk, from an unfamiliar IP, or lacks a normal admin context.
- Resource access expanded rapidly across multiple assets with no business justification.
- Additional suspicious identity actions or token/consent abuse are present.

**Containment actions:**
- Disable the account or revoke sessions/tokens if compromise is likely.
- Remove unauthorized role assignments and review for additional privilege grants.
- Block or challenge the source sign-in if it is clearly malicious and supported by evidence.
- Preserve AuditLogs and SigninLogs before making changes.

**Closure criteria:**
- The role assignment and resource access are confirmed as legitimate and documented.
- The actor is a known admin or automation identity with an expected workflow.
- No additional suspicious identity activity is found in the investigation window.
- Any unauthorized privilege changes have been reversed and access reviewed.

<br/>
---
<br/>

## Detection 4: NeedyMantis - Loader Process Writing Encrypted or Unusually Named Archive Files to User or Temp Directories

### Detection Opportunity

Custom loader process drops or decrypts encrypted archive payloads into user-writable or temporary directories as part of NeedyMantis post-compromise staging

### Intelligence Context

- Microsoft Security Blog: NeedyMantis: Unpacking a post-compromise malware family used in targeted operations — [https://www.microsoft.com/en-us/security/blog/2026/09/28/needymantis-unpacking-a-post-compromise-malware-family-used-in-targeted-operations/](https://www.microsoft.com/en-us/security/blog/2026/09/28/needymantis-unpacking-a-post-compromise-malware-family-used-in-targeted-operations/)
  - Context: NeedyMantis uses custom loaders combined with encrypted archives as part of its modular post-compromise framework. Loaders write or decrypt archive payloads to disk as a staging step for follow-on components.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1547, T1547.001, T1053, T1053.005
- Products: Not specified
- Platforms: Windows
- Malware: NeedyMantis
- Tools: Not specified
- Search tags: NeedyMantis, Windows, T1547, T1547.001, T1053, T1053.005

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1547 Boot or Logon Autostart Execution/ T1547.001 Registry Run Keys / Startup Folder (high); Persistence: T1053 Scheduled Task/Job/ T1053.005 Scheduled Task (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let lookback = 7d;
let knownArchivers = dynamic(["7z.exe", "winrar.exe", "winzip32.exe", "msiexec.exe", "setup.exe", "installer.exe", "expand.exe", "tar.exe"]);
let suspiciousWritePaths = dynamic(["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\appdata\\roaming\\", "\\users\\public\\"]);
let suspiciousLoaderPaths = dynamic(["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\appdata\\roaming\\", "\\users\\public\\"]);
DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType in ("FileCreated", "FileModified")
| where tolower(FolderPath) has_any (suspiciousWritePaths)
| where FileName endswith_any (".enc", ".bin", ".dat", ".pak", ".cab", ".zip", ".7z", ".rar")
| where tolower(InitiatingProcessFileName) !in (knownArchivers)
| where InitiatingProcessFileName !startswith "MpCmdRun"
| where tolower(InitiatingProcessFolderPath) has_any (suspiciousLoaderPaths)
| summarize
    FilesWritten = count(),
    FileNames = make_set(FileName),
    FolderPaths = make_set(FolderPath),
    WrittenFileSHA256s = make_set(SHA256),
    InitiatingProcessCommandLine = any(InitiatingProcessCommandLine),
    InitiatingProcessFolderPath = any(InitiatingProcessFolderPath),
    WindowStart = min(Timestamp)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 30m)
| where FilesWritten >= 2
| project
    DeviceName,
    WindowStart,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    FilesWritten,
    FileNames,
    FolderPaths,
    WrittenFileSHA256s
| order by FilesWritten desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Software installers that extract archive components to temp directories during installation.
- Backup or sync agents writing compressed data to AppData paths.
- Development tools or build systems writing intermediate binary artifacts to temp locations.
- Custom or renamed archiving utilities not in the exclusion list.

**Tuning notes:**
- Add InitiatingProcessSHA256 to the projection if available in the environment's DeviceFileEvents schema for hash-based threat intelligence lookup.
- Increase FilesWritten threshold above 2 if legitimate software frequently writes multiple archive files to temp paths in the environment.
- Remove the InitiatingProcessFolderPath filter if NeedyMantis loaders are observed residing outside temp and user-writable directories.

**Risks / caveats:**
- The original query joins DeviceFileEvents to DeviceProcessEvents on InitiatingProcessFileName alone without DeviceName or Timestamp correlation, which can produce cross-device matches. The improved query corrects this by scoping the join to DeviceName and a time window.
- No NeedyMantis-specific loader filenames, hashes, or archive naming patterns are publicly documented; this query is entirely heuristic and will detect any loader-like behavior matching the path and extension criteria, not NeedyMantis specifically.
- The InitiatingProcessFolderPath filter on the loader process requires that NeedyMantis loaders reside in temp or user-writable paths; loaders installed to Program Files or System32 will not be detected.
- The bin(Timestamp, 30m) window may split a staging sequence that spans a bin boundary; consider increasing to 1h if staging takes longer.

### Triage Runbook

**First 15 minutes:**
- Inspect the initiating process name, folder path, and command line to determine whether it is a known installer, archiver, or an unusual loader.
- Review the written file names, extensions, and hashes to see whether they resemble encrypted payloads or staged archives.
- Check whether the process is running from temp, AppData, Public, or another user-writable path and whether it recently spawned other suspicious processes.
- Look for concurrent script execution, archive extraction, or network downloads tied to the same host.

**Evidence to collect:**
- DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FilesWritten, FileNames, FolderPaths, WrittenFileSHA256s, WindowStart.
- DeviceFileEvents showing the created or modified files and their hashes.
- DeviceProcessEvents for the initiating process and any child processes.
- Any related network activity or downloaded payloads associated with the same host.

**Pivot points:**
- DeviceProcessEvents to find the initiating process lineage and any child execution.
- DeviceFileEvents for the same DeviceName and time window to identify additional dropped files or archive extraction.
- DeviceNetworkEvents to identify download sources or command-and-control connections.
- Threat intelligence or hash reputation lookups for WrittenFileSHA256s.

**Benign explanations:**
- Legitimate software installers or updaters extracting archives to temp directories.
- Backup, sync, or packaging tools writing compressed data to user-writable paths.
- Development or build tooling creating intermediate artifacts in temp locations.

**Escalation criteria:**
- The initiating process is unknown, unsigned, or not associated with an approved application.
- The written files are encrypted archives or payloads with no legitimate business explanation.
- The process is running from a suspicious user-writable path and is accompanied by other malware-like behavior.
- Threat intelligence or sandboxing indicates the written files are malicious.

**Containment actions:**
- Isolate the endpoint if the process appears malicious or is actively staging payloads.
- Terminate the suspicious process and any child processes after preserving evidence.
- Quarantine or remove the written files only after collecting hashes and confirming they are not legitimate software artifacts.
- Block associated hashes or download sources if confirmed malicious.

**Closure criteria:**
- The process is identified as a legitimate installer, updater, or approved tool.
- The written files are benign artifacts consistent with normal software behavior.
- No additional suspicious execution, persistence, or network activity is found.
- Hashes and paths are documented and the alert is explained by a known workflow.

<br/>
---
<br/>

## Detection 5: NeedyMantis - Unsigned or Unknown Binary Establishing Persistence via Registry Run Key or Scheduled Task

### Detection Opportunity

NeedyMantis malware establishes persistent access by modifying registry run keys or creating scheduled tasks via unsigned or unrecognized loader binaries

### Intelligence Context

- Microsoft Security Blog: NeedyMantis: Unpacking a post-compromise malware family used in targeted operations — [https://www.microsoft.com/en-us/security/blog/2026/09/28/needymantis-unpacking-a-post-compromise-malware-family-used-in-targeted-operations/](https://www.microsoft.com/en-us/security/blog/2026/09/28/needymantis-unpacking-a-post-compromise-malware-family-used-in-targeted-operations/)
  - Context: NeedyMantis is designed to support long-term access and follow-on operations, implying the use of persistence mechanisms. The modular framework with custom loaders is consistent with registry or scheduled task persistence to survive reboots.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1547, T1547.001, T1053, T1053.005
- Products: Not specified
- Platforms: Windows
- Malware: NeedyMantis
- Tools: Not specified
- Search tags: NeedyMantis, Windows, T1547, T1547.001, T1053, T1053.005

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1547 Boot or Logon Autostart Execution/ T1547.001 Registry Run Keys / Startup Folder (high); Persistence: T1053 Scheduled Task/Job/ T1053.005 Scheduled Task (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- The ActionType value 'ScheduledTaskCreated' in DeviceEvents may not be available in all Defender for Endpoint sensor configurations or licensing tiers. Validate this ActionType is present in the environment's DeviceEvents table before deployment.

**Required telemetry:**
- DeviceRegistryEvents, DeviceEvents

### KQL

```kql
let lookback = 7d;
let persistenceRunKeys = dynamic([
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
]);
let suspiciousPaths = dynamic(["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\appdata\\roaming\\", "\\users\\public\\"]);
let registryPersistence = DeviceRegistryEvents
| where Timestamp > ago(lookback)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has_any (persistenceRunKeys)
| where tolower(InitiatingProcessFolderPath) has_any (suspiciousPaths)
| project
    DeviceName,
    EventTime = Timestamp,
    PersistenceType = "RegistryRunKey",
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    RegistryKey,
    RegistryValueName,
    TaskCommandLine = "",
    AccountName;
let scheduledTaskPersistence = DeviceEvents
| where Timestamp > ago(lookback)
| where ActionType == "ScheduledTaskCreated"
| where tolower(InitiatingProcessFolderPath) has_any (suspiciousPaths)
| project
    DeviceName,
    EventTime = Timestamp,
    PersistenceType = "ScheduledTask",
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    RegistryKey = "",
    RegistryValueName = "",
    TaskCommandLine = InitiatingProcessCommandLine,
    AccountName;
let allPersistence = union registryPersistence, scheduledTaskPersistence;
let compoundActors = allPersistence
| summarize PersistenceTypes = make_set(PersistenceType) by DeviceName, InitiatingProcessFileName
| where array_length(PersistenceTypes) >= 2
| project DeviceName, InitiatingProcessFileName, BothPersistenceTypes = true;
allPersistence
| join kind=leftouter compoundActors on DeviceName, InitiatingProcessFileName
| extend BothPersistenceTypes = coalesce(BothPersistenceTypes, false)
| project
    DeviceName,
    EventTime,
    PersistenceType,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    RegistryKey,
    RegistryValueName,
    TaskCommandLine,
    AccountName,
    BothPersistenceTypes
| order by BothPersistenceTypes desc, EventTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Software installers that extract to temp directories and set run keys as part of a staged installation process.
- Legitimate scheduled task creation by scripts or tools running from AppData paths.
- IT automation tools that reside in user-writable paths and configure persistence for managed software.

**Tuning notes:**
- Prioritize investigation of rows where BothPersistenceTypes is true, as these represent the compound persistence signal most consistent with a deliberate adversary action.
- Add InitiatingProcessSHA256 to the projection and cross-reference against threat intelligence if the field is populated in the environment.
- Expand suspiciousPaths to include additional non-standard directories observed in the environment where loaders may reside.
- Add → where InitiatingProcessFileName !in~ (known_software_list) to suppress recurring false positives from identified legitimate software.

**Risks / caveats:**
- InitiatingProcessFolderPath is not guaranteed to be populated in all DeviceRegistryEvents and DeviceEvents records depending on the sensor version and event type. If the field is empty, the has_any path filter will silently exclude all events, producing no results. Validate field population before relying on this filter.
- The ActionType value 'ScheduledTaskCreated' in DeviceEvents may not be available in all Defender for Endpoint sensor configurations or licensing tiers. Validate this ActionType is present in the environment's DeviceEvents table before deployment.
- InitiatingProcessFolderPath may be empty in some DeviceRegistryEvents and DeviceEvents records; if empty, the has_any filter silently drops those events. Run a validation query counting non-empty InitiatingProcessFolderPath values in both tables before relying on this detection.
- ScheduledTaskCreated ActionType availability in DeviceEvents should be confirmed in the environment before deployment.

### Triage Runbook

**First 15 minutes:**
- Review the persistence type, registry key or task details, and the initiating process path to determine if the action came from a trusted installer or a suspicious user-writable location.
- Check whether both persistence types are present on the same device and process, which increases confidence of malicious activity.
- Inspect the command line and any task command data to understand what will run at logon or on schedule.
- Look for related file drops, script execution, or network connections around the same time.

**Evidence to collect:**
- DeviceName, EventTime, PersistenceType, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RegistryKey, RegistryValueName, TaskCommandLine, AccountName, BothPersistenceTypes.
- Registry value data for the run key if available.
- DeviceEvents and DeviceRegistryEvents showing the exact persistence creation events.
- Hashes and file paths for the initiating binary and any payloads it launched.

**Pivot points:**
- DeviceProcessEvents for the same host to identify the parent process and any child execution.
- DeviceRegistryEvents to find additional autoruns, service creation, or defense evasion changes.
- DeviceEvents for scheduled task creation details and task names.
- DeviceFileEvents and DeviceNetworkEvents to identify dropped payloads or outbound connections.

**Benign explanations:**
- A legitimate installer or updater creating a run key or scheduled task for auto-start.
- IT automation or management software running from a user-writable path in a controlled environment.
- A known application that uses scheduled tasks for maintenance or synchronization.

**Escalation criteria:**
- The initiating binary is unsigned, unknown, or located in a suspicious temp/AppData path.
- Both registry and scheduled task persistence are present from the same process or host.
- The persistence was created without a change record or by a non-admin user.
- Additional malware indicators are present, such as payload drops, suspicious network traffic, or defense evasion.

**Containment actions:**
- If unauthorized, isolate the host and prevent the persistence from executing on reboot or schedule.
- Remove the malicious run key or scheduled task after preserving evidence and confirming the payload path.
- Disable or reset the account used to create persistence if compromise is suspected.
- Collect the binary and hashes for analysis before cleanup when possible.

**Closure criteria:**
- The persistence mechanism is explained by a legitimate installer, updater, or approved automation.
- The initiating process is identified as trusted and no other malicious behavior is present.
- Any unauthorized persistence has been removed and the host is clean on follow-up review.
- The alert is linked to a documented change or software deployment.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- Concurrent Multi-RMM Tool Installation on Single Endpoint: Do not schedule yet; validate as an analyst-led hunt first.
- NeedyMantis - Loader Process Writing Encrypted or Unusually Named Archive Files to User or Temp Directories: Do not schedule yet; validate as an analyst-led hunt first.
- NeedyMantis - Unsigned or Unknown Binary Establishing Persistence via Registry Run Key or Scheduled Task: Do not schedule yet; validate as an analyst-led hunt first.

**Licensing / identity risk fields:**
- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.
- NeedyMantis - Unsigned or Unknown Binary Establishing Persistence via Registry Run Key or Scheduled Task: The ActionType value 'ScheduledTaskCreated' in DeviceEvents may not be available in all Defender for Endpoint sensor configurations or licensing tiers. Validate this ActionType is present in the environment's DeviceEvents table before deployment.

**Shared-table notes:**
- DeviceProcessEvents: shared by RMM Chaining - ScreenConnect Spawned by MSP360 Agent Process; Concurrent Multi-RMM Tool Installation on Single Endpoint; NeedyMantis - Loader Process Writing Encrypted or Unusually Named Archive Files to User or Temp Directories

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: RMM Chaining - ScreenConnect Spawned by MSP360 Agent Process; Storm-3068 - Compromised Identity Performing Cloud Role Assignment and Multi-Resource Access Expansion.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Concurrent Multi-RMM Tool Installation on Single Endpoint; NeedyMantis - Loader Process Writing Encrypted or Unusually Named Archive Files to User or Temp Directories; NeedyMantis - Unsigned or Unknown Binary Establishing Persistence via Registry Run Key or Scheduled Task.

### Hunting Agenda and Promotion Criteria

- Concurrent Multi-RMM Tool Installation on Single Endpoint: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- NeedyMantis - Loader Process Writing Encrypted or Unusually Named Archive Files to User or Temp Directories: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- NeedyMantis - Unsigned or Unknown Binary Establishing Persistence via Registry Run Key or Scheduled Task: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

This run exposes an identity-risk licensing blind spot: detections using RiskLevelDuringSignIn lose fidelity in tenants without Entra ID P2 risk enrichment.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
