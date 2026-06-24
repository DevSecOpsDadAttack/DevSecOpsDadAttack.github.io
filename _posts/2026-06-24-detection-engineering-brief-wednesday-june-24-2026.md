---
layout: post
title: "Detection Engineering Brief - Wednesday, June 24, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-24
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Cobalt Strike
  - SharkLoader
  - cloud
  - T1204
  - T1071
  - T1071.001
  - T1105
  - T1567
  - T1583
  - T1583.001
  - T1021
  - T1021.001
---

## Executive Signal

This brief produced 5 detection candidates.

1 production candidate, 4 hunting-only, 0 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Cobalt Strike, SharkLoader, cloud, T1204, T1071, T1071.001, T1105, T1567, T1583, T1583.001, T1021, T1021.001.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: SharkLoader Staging Cobalt Strike Beacon via Unsigned Process Network Activity; Azure Storage Bucket Creation Matching Previously Deleted Resource Names; Concurrent Remote Logons from Distinct Source IPs on Same Host Indicating Multi-Actor Access; Large-Volume Azure Storage Read Operations Followed by Write to Newly Created Storage Account.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: SharkLoader Staging Cobalt Strike Beacon via Unsigned Process Network Activity

### Detection Opportunity

Custom loader malware (SharkLoader) stages and executes Cobalt Strike Beacon, producing unsigned process creation followed by outbound network connections shortly after file creation on endpoint.

### Intelligence Context

- Securelist: StrikeShark: investigating a new campaign delivering Cobalt Strike through SharkLoader — [https://securelist.com/strikeshark-campaign/120326/](https://securelist.com/strikeshark-campaign/120326/)
  - Context: SharkLoader is a custom loader malware that stages and executes Cobalt Strike Beacon on the endpoint. The campaign produces observable process creation, file drop, and outbound network connection artifacts consistent with loader-to-beacon staging.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1204, T1071, T1071.001, T1105
- Products: Not specified
- Platforms: Not specified
- Malware: Cobalt Strike, SharkLoader
- Tools: Not specified
- Search tags: Cobalt Strike, SharkLoader, T1204, T1071, T1071.001, T1105

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1204 User Execution (medium); Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium); Ingress Tool Transfer: T1105 Ingress Tool Transfer (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceFileEvents, DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let lookback = 30d;
let stageWindow = 5m;
let suspiciousPorts = dynamic([4444, 8080, 8443, 443, 80]);
let fileDrops = DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType == "FileCreated"
| where tolower(FolderPath) has_any ("temp", "appdata", "programdata", "downloads")
| project FileDropTime = Timestamp, DeviceId, DeviceName, DroppedFile = FileName, DroppedPath = FolderPath, DroppedFileSHA256 = SHA256;
let processSpawns = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where tolower(InitiatingProcessFileName) !in (
    "explorer.exe", "svchost.exe", "services.exe", "lsass.exe",
    "msiexec.exe", "trustedinstaller.exe", "wuauclt.exe"
)
| project SpawnTime = Timestamp, DeviceId, DeviceName, SpawnedProcess = FileName,
    CommandLine = ProcessCommandLine, InitParent = InitiatingProcessFileName,
    ProcessSHA256 = SHA256, InitiatingProcessId;
let netConns = DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where RemotePort in (suspiciousPorts)
| where ActionType == "ConnectionSuccess"
| project NetTime = Timestamp, DeviceId, ConnProcess = tolower(InitiatingProcessFileName),
    RemoteUrl, RemoteIP = RemoteIP, RemotePort;
fileDrops
| join kind=inner (processSpawns) on DeviceId
| where SpawnTime between (FileDropTime .. (FileDropTime + stageWindow))
| extend SpawnedProcessLower = tolower(SpawnedProcess)
| join kind=inner (netConns) on DeviceId
| where NetTime between (SpawnTime .. (SpawnTime + stageWindow))
| where ConnProcess == SpawnedProcessLower
| project
    FileDropTime, SpawnTime, NetTime,
    DeviceId, DeviceName,
    DroppedFile, DroppedPath, DroppedFileSHA256,
    SpawnedProcess, CommandLine, InitParent, ProcessSHA256,
    RemoteUrl, RemoteIP, RemotePort
| order by FileDropTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Software installers that drop executables to Temp or AppData and immediately launch them with outbound update checks.
- Browser-initiated downloads that auto-execute and phone home.
- Legitimate remote management agents deployed via software distribution tools.
- Port 443 and 80 matches will be extremely common; analysts should focus on non-browser, non-signed processes.

Tuning notes:
- Remove ports 443 and 80 from suspiciousPorts if the environment has broad legitimate HTTPS/HTTP traffic from user-space processes.
- Add a SHA256 allowlist join against known-good software hashes to suppress installer false positives.
- Consider adding a filter requiring SpawnedProcess to not be code-signed (IsSigned == false) if that field is available in your MDE schema version.
- Reduce lookback to 7d for routine scheduled hunting to control query cost.

Risks / caveats:
- DeviceFileEvents.SHA256 is not always populated for all ActionType values; file-drop events may return empty SHA256 depending on MDE sensor version and file size.
- DeviceNetworkEvents.RemoteUrl may be empty for direct IP connections; beacon C2 over IP without DNS will not populate this field.
- Three-way join on DeviceId alone without process-lineage linkage means the dropped file and spawned process are correlated only by timing and device, not by parent-child relationship.
- Port 443 and 80 are included in suspiciousPorts; these will match a very large volume of legitimate outbound connections and should be removed or further filtered by process name in high-noise environments.

### Triage Runbook

First 15 minutes:
- Validate the file drop, spawned process, and outbound connection occurred on the same host within the expected time window.
- Check whether the spawned process is unsigned, unusual for the endpoint, or launched from Temp/AppData/ProgramData/Downloads.
- Review the command line and initiating parent process to identify the execution chain and any user interaction that preceded it.
- Inspect the remote IP/URL and port for beacon-like behavior, repeated connections, or known malicious reputation.
- Determine whether the process is still running and whether additional suspicious child processes or follow-on activity exist on the host.

Evidence to collect:
- DeviceName, DeviceId, FileDropTime, SpawnTime, NetTime, DroppedFile, DroppedPath, DroppedFileSHA256
- SpawnedProcess, CommandLine, InitParent, ProcessSHA256, InitiatingProcessId
- RemoteUrl, RemoteIP, RemotePort, connection frequency, and any repeated destinations from the same process
- Process signing status, parent-child lineage, and any nearby file creation or execution events
- Any user activity around the time of execution, including downloads, email attachments, or browser activity

Pivot points:
- DeviceFileEvents for additional file drops from the same DeviceId and SHA256
- DeviceProcessEvents for parent-child lineage, unsigned processes, and repeated launches from the same path
- DeviceNetworkEvents for other outbound connections from the same process or host
- DeviceLogonEvents if user interaction or remote access may have preceded execution
- Defender XDR device timeline for correlated alerts, quarantines, or suspicious child processes

Benign explanations:
- Legitimate software installers or updaters that drop executables into Temp or AppData and immediately connect out for updates
- Browser-initiated downloads that auto-launch a helper process and perform normal network checks
- Remote management or endpoint agent deployment activity from software distribution tools
- Signed vendor software that happens to use common web ports and user-writable staging directories

Escalation criteria:
- The spawned process is unsigned or masquerades as a common system binary and the network destination is unfamiliar or suspicious
- The same host shows repeated outbound connections from the spawned process consistent with beaconing
- Additional suspicious processes, persistence, credential access, or lateral movement activity are present
- The dropped file hash, path, or command line matches known malware behavior or the host has other correlated high-confidence alerts

Containment actions:
- Isolate the endpoint if the process is confirmed malicious or the host shows active beaconing
- Kill the suspicious process and any obvious child processes if containment is authorized and safe to do so
- Quarantine the dropped file or associated hash if supported by the platform
- Block the remote IP/domain at network controls if it is confirmed malicious and not shared with legitimate services

Closure criteria:
- The file drop and process execution are confirmed to be a known-good installer, updater, or approved remote management agent
- The network activity is attributable to a legitimate signed process with expected behavior and no additional suspicious telemetry is found
- No persistence, credential theft, lateral movement, or repeated beacon-like connections are observed after review
- The hash, path, and parent process are added to an approved allowlist or documented as benign for this environment

---

## Detection 2: Azure Storage Bucket Creation Matching Previously Deleted Resource Names

### Detection Opportunity

Attacker registers a cloud storage bucket using a previously used or predictable name to intercept data streams redirected to the newly created bucket.

### Intelligence Context

- Unit 42: The Global Namespace Risk: Universal Bucket Hijacking Technique for Cloud Data Exfiltration — [https://unit42.paloaltonetworks.com/cloud-bucket-hijacking-risks/](https://unit42.paloaltonetworks.com/cloud-bucket-hijacking-risks/)
  - Context: Attackers exploit the global uniqueness of cloud storage bucket names by registering a bucket name that was previously used by a target organization, allowing them to intercept data streams that still reference the old bucket name and redirect them for exfiltration.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1567, T1583, T1583.001
- Products: Not specified
- Platforms: cloud
- Malware: Not specified
- Tools: Not specified
- Search tags: cloud, T1567, T1583, T1583.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Exfiltration: T1567 Exfiltration to Cloud Storage (medium); Resource Development: T1583 Acquire Infrastructure/ T1583.001 Domains (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- AzureActivity

### KQL

```kql
let lookback = 90d;
let hijackWindow = 30d;
let deletions = AzureActivity
| where TimeGenerated > ago(lookback)
| where tolower(OperationName) has "microsoft.storage/storageaccounts"
    and tolower(OperationName) has "delete"
| where ActivityStatus =~ "Succeeded"
| extend DeletedResource = tolower(tostring(split(ResourceId, "/")[-1]))
| where isnotempty(DeletedResource)
| project DeleteTime = TimeGenerated, DeletedResource, DeletedBy = Caller,
    DeletedFromIP = CallerIpAddress, SubscriptionId;
let creations = AzureActivity
| where TimeGenerated > ago(hijackWindow)
| where tolower(OperationName) has "microsoft.storage/storageaccounts"
    and (tolower(OperationName) has "write" or tolower(OperationName) has "create")
| where ActivityStatus =~ "Succeeded"
| extend CreatedResource = tolower(tostring(split(ResourceId, "/")[-1]))
| where isnotempty(CreatedResource)
| project CreateTime = TimeGenerated, CreatedResource, CreatedBy = Caller,
    CreatedFromIP = CallerIpAddress, SubscriptionId, ResourceGroup;
deletions
| join kind=inner (creations) on $left.DeletedResource == $right.CreatedResource
| where CreateTime > DeleteTime
| where CreatedBy != DeletedBy
| project
    DeleteTime, CreateTime, DeletedResource,
    DeletedBy, DeletedFromIP,
    CreatedBy, CreatedFromIP,
    SubscriptionId, ResourceGroup
| order by CreateTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate infrastructure-as-code pipelines that delete and recreate storage accounts under a different service principal identity.
- Organizational account transitions where a new team or service principal takes ownership of a resource.
- Automated disaster recovery or blue-green deployment patterns that recreate storage accounts with identical names.

Tuning notes:
- Add a Caller allowlist for known automation service principals and managed identity object IDs to suppress CI/CD false positives.
- Consider adding a ResourceGroup exclusion list for known infrastructure automation resource groups.
- Reduce lookback to 30d for deletions if query performance is a concern, accepting reduced historical coverage.
- Cross-subscription detection would require a separate query correlating deletions and creations across SubscriptionId values.

Risks / caveats:
- AzureActivity requires the Azure Activity Log connector to be enabled in Microsoft Sentinel; if not configured, the table will be empty.
- AzureActivity.Caller may be a service principal object ID rather than a human UPN, making cross-identity comparison less reliable for automated pipelines.
- ResourceId path parsing via split(ResourceId, '/')[-1] assumes a fixed ARM path structure; non-standard resource paths may produce incorrect name extraction.
- OperationName values in AzureActivity are not fully standardized across all Azure regions and API versions; the has-based matching may miss some deletion or creation events.

### Triage Runbook

First 15 minutes:
- Confirm the deleted and created resources have the same name and that the creation occurred after the deletion.
- Compare DeletedBy and CreatedBy to determine whether the identities differ and whether either is a known automation principal.
- Review the subscription, resource group, and caller IPs for signs of unexpected ownership transfer or external access.
- Check whether the recreated storage account is part of an approved migration, disaster recovery, or blue-green deployment workflow.
- Assess whether any dependent applications, DNS records, or data streams still reference the old resource name.

Evidence to collect:
- DeleteTime, CreateTime, DeletedResource, DeletedBy, DeletedFromIP, CreatedBy, CreatedFromIP
- SubscriptionId, ResourceGroup, and any related resource tags or naming conventions
- ActivityStatus for both events and any nearby create/delete operations on the same resource group
- Caller identity type if available, including whether the caller is a user, service principal, or managed identity
- Any change-management ticket, deployment pipeline record, or approved maintenance window tied to the recreation

Pivot points:
- AzureActivity for additional delete/write operations on the same resource name or resource group
- AzureActivity for other actions by DeletedBy and CreatedBy around the same time
- Azure Resource Graph or ARM activity history for ownership and configuration changes
- Microsoft Sentinel incidents for related cloud alerts involving the same subscription or caller
- Identity logs for the caller account or service principal if the identity is unfamiliar

Benign explanations:
- Infrastructure-as-code pipelines that delete and recreate storage accounts under a different service principal
- Planned migration or ownership transfer between teams or subscriptions
- Disaster recovery or blue-green deployment workflows that reuse a previously deleted name
- Administrative cleanup followed by legitimate reprovisioning during maintenance

Escalation criteria:
- The recreated account is not tied to an approved change, pipeline, or maintenance activity
- The new creator identity is unfamiliar, external, or inconsistent with normal automation patterns
- The recreated resource is referenced by active data streams, applications, or DNS and may be intercepting traffic
- There are additional suspicious AzureActivity events from the same caller, IP, or subscription

Containment actions:
- Suspend or disable the suspicious caller identity if it is confirmed unauthorized and operationally safe to do so
- Revoke active credentials or tokens for the creating identity if compromise is suspected
- Coordinate with cloud administrators to rename, remove, or replace the suspicious storage account if hijacking is confirmed
- Preserve activity logs and resource configuration before making destructive changes

Closure criteria:
- A valid change record, deployment pipeline, or approved migration explains the delete-and-recreate sequence
- The creator identity is a known automation principal or managed identity used by the organization
- No evidence shows the recreated resource is receiving redirected data or unauthorized access
- The event is documented as expected infrastructure lifecycle activity

---

## Detection 3: Ransomware Pre-Deployment: Shadow Copy Deletion Combined with Mass File Modification

### Detection Opportunity

Ransomware-related activity within a multi-actor intrusion including shadow copy deletion and mass file encryption or renaming as pre-deployment preparation.

### Intelligence Context

- Microsoft Security Blog: One intrusion, two cyberattackers: Uncovering parallel threat activity — [https://www.microsoft.com/en-us/security/blog/2026/06/22/one-intrusion-two-cyberattackers-uncovering-parallel-threat-activity/](https://www.microsoft.com/en-us/security/blog/2026/06/22/one-intrusion-two-cyberattackers-uncovering-parallel-threat-activity/)
  - Context: A ransomware case involving two parallel threat actors operating within the same compromised environment revealed ransomware pre-deployment behaviors including shadow copy deletion and mass file modification, consistent with imminent encryption activity.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1021, T1021.001
- Products: Not specified
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: T1021, T1021.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1021 Remote Services/ T1021.001 Remote Desktop Protocol (low); Lateral Movement: T1021 Remote Services (low)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let lookback = 1d;
let encryptWindow = 15m;
let massFileThreshold = 50;
let shadowDeletions = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where ProcessCommandLine has_any (
    "vssadmin delete shadows",
    "wmic shadowcopy delete",
    "Get-WmiObject Win32_ShadowCopy",
    "Win32_ShadowCopy"
)
| project
    ShadowDeleteTime = Timestamp,
    DeviceId,
    DeviceName,
    AccountName = InitiatingProcessAccountName,
    DeleteProcess = FileName,
    DeleteCmdLine = ProcessCommandLine;
let massFileChanges = DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType in ("FileModified", "FileRenamed")
| summarize
    FileChangeCount = count(),
    FirstChange = min(Timestamp)
    by DeviceId, bin(Timestamp, 1m)
| where FileChangeCount >= massFileThreshold
| project MassChangeTime = FirstChange, DeviceId, FileChangeCount;
shadowDeletions
| join kind=inner (massFileChanges) on DeviceId
| where MassChangeTime between (ShadowDeleteTime .. (ShadowDeleteTime + encryptWindow))
| summarize
    ShadowDeleteTime = min(ShadowDeleteTime),
    MassChangeTime = min(MassChangeTime),
    DeleteCmdLine = take_any(DeleteCmdLine),
    DeleteProcess = take_any(DeleteProcess),
    AccountName = take_any(AccountName),
    FileChangeCount = max(FileChangeCount)
    by DeviceId, DeviceName
| project
    ShadowDeleteTime, MassChangeTime,
    DeviceId, DeviceName,
    AccountName, DeleteProcess, DeleteCmdLine, FileChangeCount
| order by ShadowDeleteTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate backup software that deletes VSS snapshots as part of its own snapshot management cycle before performing bulk file operations.
- System administrators running vssadmin or wmic for maintenance on servers with high file I/O workloads.
- Disk cleanup or defragmentation tools that trigger both VSS management and high file modification rates.

Tuning notes:
- Increase massFileThreshold to 100 or 200 on file servers or build systems with high legitimate file modification rates.
- Add a ProcessCommandLine decode step for base64-encoded PowerShell to catch obfuscated VSS deletion commands.
- Consider adding a separate branch for 'bcdedit /set recoveryenabled no' and 'wbadmin delete catalog' as complementary backup destruction signals.
- Pair with a DeviceLogonEvents query to establish prior lateral movement context for alert enrichment.

Risks / caveats:
- DeviceFileEvents ActionType values 'FileModified' and 'FileRenamed' must be confirmed as available in the tenant's MDE sensor version; older sensor versions may not emit FileModified events for all file system activity.
- The 1-day lookback is appropriate for a scheduled rule but will miss pre-deployment activity that occurred before the lookback window if the rule was not deployed in time.
- massFileThreshold of 50 files per minute may be too low for file servers or developer workstations with high legitimate file I/O; baseline the environment before deploying.
- The query does not distinguish between user-space and kernel-space file modifications; some backup agents may trigger the threshold.

### Triage Runbook

First 15 minutes:
- Verify the shadow copy deletion command and identify the executing account, process, and host.
- Check whether mass file modifications or renames began shortly after the deletion and whether the rate is increasing.
- Look for signs of encryption, extension changes, ransom notes, or widespread file access failures on the host.
- Determine whether the activity is occurring on a server, workstation, or backup host and whether the account is privileged.
- Assess whether the host is still actively modifying files or whether the activity has stopped.

Evidence to collect:
- ShadowDeleteTime, MassChangeTime, DeviceId, DeviceName, AccountName, DeleteProcess, DeleteCmdLine, FileChangeCount
- Nearby DeviceFileEvents showing FileModified and FileRenamed activity, including affected paths and extensions
- Any ransom note filenames, unusual file extensions, or evidence of encryption across user and shared directories
- Process lineage and command-line details for the deletion command, including parent process and initiating account
- Any correlated alerts for credential theft, lateral movement, or backup tampering on the same host or account

Pivot points:
- DeviceProcessEvents for additional VSS, wbadmin, bcdedit, or PowerShell destruction commands
- DeviceFileEvents for mass rename, modification, or deletion activity across the same DeviceId
- DeviceLogonEvents for recent privileged logons or remote access to the host
- Defender XDR incidents for related ransomware, tampering, or lateral movement alerts
- File and process timeline on the endpoint to identify the first malicious action and scope of impact

Benign explanations:
- Backup software or snapshot management tools that delete VSS snapshots as part of normal operations
- Administrator maintenance on a server with high file churn
- Disk cleanup, imaging, or defragmentation tools that trigger both snapshot and file activity
- Legitimate bulk file operations from deployment, synchronization, or data processing jobs

Escalation criteria:
- Shadow copy deletion is confirmed and file modifications are widespread, rapid, and not attributable to a known maintenance task
- File extensions, contents, or filenames indicate encryption or ransom note deployment
- The executing account is privileged, unexpected, or recently compromised
- There is evidence of lateral movement, backup deletion, or multiple hosts showing the same pattern

Containment actions:
- Isolate the host immediately if active encryption or destructive file modification is confirmed
- Disable or reset the executing account if it is suspected to be compromised
- Stop the malicious process and any related backup-destruction utilities if safe to do so
- Protect backups and restore points by validating backup infrastructure is not also impacted

Closure criteria:
- The activity is confirmed to be a documented backup, maintenance, or imaging workflow
- File modification volume is explained by a known business process and no encryption indicators are present
- No additional hosts, accounts, or processes show the same destructive pattern
- The event is linked to a benign administrative action and documented accordingly

---

## Detection 4: Concurrent Remote Logons from Distinct Source IPs on Same Host Indicating Multi-Actor Access

### Detection Opportunity

Multiple threat actors sharing simultaneous access within the same compromised environment, observable as overlapping interactive or remote logon sessions from distinct source IP addresses on a single host.

### Intelligence Context

- Microsoft Security Blog: One intrusion, two cyberattackers: Uncovering parallel threat activity — [https://www.microsoft.com/en-us/security/blog/2026/06/22/one-intrusion-two-cyberattackers-uncovering-parallel-threat-activity/](https://www.microsoft.com/en-us/security/blog/2026/06/22/one-intrusion-two-cyberattackers-uncovering-parallel-threat-activity/)
  - Context: The investigation revealed two distinct threat actors operating simultaneously within the same compromised host environment, producing overlapping remote session artifacts from different source IPs that are detectable via logon telemetry.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1021, T1021.001
- Products: Not specified
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: T1021, T1021.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1021 Remote Services/ T1021.001 Remote Desktop Protocol (low); Lateral Movement: T1021 Remote Services (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceLogonEvents

### KQL

```kql
let lookback = 7d;
let sessionWindow = 30m;
let remoteSessions = DeviceLogonEvents
| where Timestamp > ago(lookback)
| where LogonType in ("RemoteInteractive", "Network", "Interactive")
| where isnotempty(RemoteIP)
| where isnotempty(AccountName)
| where RemoteIP !startswith "10."
    and RemoteIP !startswith "192.168."
    and not (RemoteIP startswith "172." and
        toint(split(RemoteIP, ".")[1]) between (16 .. 31))
    and RemoteIP !startswith "169.254."
    and RemoteIP != "127.0.0.1"
| project SessionTime = Timestamp, DeviceId, DeviceName, AccountName, RemoteIP, LogonType;
remoteSessions
| summarize
    DistinctIPs = dcount(RemoteIP),
    IPList = make_set(RemoteIP, 10),
    SessionCount = count(),
    FirstSession = min(SessionTime),
    LastSession = max(SessionTime),
    LogonTypes = make_set(LogonType, 5)
    by DeviceId, DeviceName, AccountName, bin(SessionTime, sessionWindow)
| where DistinctIPs >= 2
| extend TimeDeltaMinutes = datetime_diff('minute', LastSession, FirstSession)
| where TimeDeltaMinutes <= 30
| project
    FirstSession, LastSession, TimeDeltaMinutes,
    DeviceId, DeviceName, AccountName,
    DistinctIPs, IPList, SessionCount, LogonTypes
| order by FirstSession desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate concurrent administrative access from multiple administrators using different workstations or VPN exit nodes.
- VPN concentrators or NAT gateways that present different external IPs for the same user session across reconnects.
- Load-balanced RDP or remote access infrastructure where session source IPs rotate.
- IT support tools that initiate remote sessions alongside user interactive sessions.

Tuning notes:
- Add an AccountName exclusion list for known shared service accounts, break-glass accounts, and monitoring agents.
- Add a RemoteIP allowlist for known VPN concentrators, jump hosts, and IT management platform egress IPs.
- Consider reducing LogonType filter to only 'RemoteInteractive' and 'Network' if 'Interactive' generates excessive noise from local console sessions with non-empty RemoteIP.
- Reduce lookback to 3d for routine scheduled hunting to control query cost on high-volume tenants.

Risks / caveats:
- DeviceLogonEvents.RemoteIP may be empty for locally initiated interactive logons; the isnotempty filter handles this but reduces coverage for non-remote session types.
- DeviceLogonEvents LogonType field uses string values in Defender XDR (e.g., 'RemoteInteractive', 'Network'); confirm these exact string values are present in the tenant before deploying.
- The 172.x RFC1918 exclusion using toint(split()) may produce unexpected results if RemoteIP contains IPv6 addresses or malformed values; add isnotempty and ipv4 validation if needed.
- The sessionWindow bin grouping means sessions that straddle a bin boundary may not be correlated; a sliding window approach would be more accurate but significantly more expensive.

### Triage Runbook

First 15 minutes:
- Identify the host, account, logon types, and source IPs involved in the overlapping sessions.
- Check whether the IPs belong to known VPN, jump host, IT support, or admin infrastructure.
- Review the timing and overlap of sessions to see if the access pattern is normal for the account or host.
- Look for concurrent suspicious activity on the host during the same window, such as process creation, file changes, or privilege escalation.
- Confirm whether the account is a shared service account, break-glass account, or a named administrator.

Evidence to collect:
- FirstSession, LastSession, TimeDeltaMinutes, DeviceId, DeviceName, AccountName, DistinctIPs, IPList, SessionCount, LogonTypes
- Exact RemoteIP values and whether they map to VPN, NAT, jump hosts, or external networks
- Recent DeviceProcessEvents and DeviceFileEvents on the host during the overlap window
- Any account history showing prior use from the same IPs or similar logon patterns
- Change tickets, support cases, or maintenance records that explain concurrent access

Pivot points:
- DeviceLogonEvents for the same account across other hosts and time windows
- DeviceProcessEvents for suspicious commands launched during the overlapping sessions
- DeviceFileEvents for file changes, staging, or encryption activity on the host
- Identity logs for the account to determine whether the source IPs are expected
- VPN, jump host, or remote access platform logs to validate the source IPs

Benign explanations:
- Two administrators working on the same host during a maintenance window
- VPN reconnects or NAT behavior causing different external IPs for the same user session
- Load-balanced remote access infrastructure that rotates source IPs
- Shared service or break-glass accounts used by multiple operators

Escalation criteria:
- The source IPs are not associated with approved remote access infrastructure or known administrators
- The account is not expected to be shared and the overlap is unusual for that user
- The host also shows suspicious process execution, file tampering, or privilege escalation
- There is evidence of multiple actors, unauthorized access, or follow-on malicious activity

Containment actions:
- Disable or reset the account if unauthorized access is confirmed or strongly suspected
- Terminate active remote sessions through the remote access platform if available and safe
- Isolate the host if concurrent access is accompanied by malicious activity
- Preserve logon and session evidence before making disruptive changes

Closure criteria:
- The overlapping sessions are explained by approved administrative work, VPN behavior, or known remote access infrastructure
- The account is a documented shared or break-glass account with expected concurrent use
- No suspicious process, file, or privilege activity is found on the host
- The IPs are validated as legitimate and the event is documented as benign

---

## Detection 5: Large-Volume Azure Storage Read Operations Followed by Write to Newly Created Storage Account

### Detection Opportunity

Cloud data streams redirected to attacker-controlled storage for exfiltration, observable as high-volume read operations on existing storage resources followed by write activity targeting a recently created storage account.

### Intelligence Context

- Unit 42: The Global Namespace Risk: Universal Bucket Hijacking Technique for Cloud Data Exfiltration — [https://unit42.paloaltonetworks.com/cloud-bucket-hijacking-risks/](https://unit42.paloaltonetworks.com/cloud-bucket-hijacking-risks/)
  - Context: After hijacking a bucket name, attackers redirect cloud data streams to their newly registered storage resource. This produces a pattern of high-volume reads on source storage followed by writes to a newly created destination storage account, detectable via Azure audit activity logs.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1567, T1583, T1583.001
- Products: Not specified
- Platforms: cloud
- Malware: Not specified
- Tools: Not specified
- Search tags: cloud, T1567, T1583, T1583.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Exfiltration: T1567 Exfiltration to Cloud Storage (medium); Resource Development: T1583 Acquire Infrastructure/ T1583.001 Domains (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- AzureActivity

### KQL

```kql
let lookback = 14d;
let newAccountWindow = 7d;
let readVolumeThreshold = 100;
let newAccounts = AzureActivity
| where TimeGenerated > ago(newAccountWindow)
| where tolower(OperationName) has "microsoft.storage/storageaccounts"
    and (tolower(OperationName) has "write" or tolower(OperationName) has "create")
| where ActivityStatus =~ "Succeeded"
| extend NewAccountResource = tolower(tostring(split(ResourceId, "/")[-1]))
| where isnotempty(NewAccountResource)
| project
    AccountCreateTime = TimeGenerated,
    NewAccountResource,
    CreatorCaller = Caller,
    CreatorIP = CallerIpAddress,
    SubscriptionId,
    ResourceGroup;
let bulkReads = AzureActivity
| where TimeGenerated > ago(lookback)
| where tolower(OperationName) has "microsoft.storage/storageaccounts"
    and (tolower(OperationName) has "read"
        or tolower(OperationName) has "list"
        or tolower(OperationName) has "get")
| where ActivityStatus =~ "Succeeded"
| summarize
    ReadCount = count(),
    FirstRead = min(TimeGenerated),
    LastRead = max(TimeGenerated),
    ReadFromIPs = make_set(CallerIpAddress, 5)
    by Caller;
| where ReadCount >= readVolumeThreshold;
newAccounts
| join kind=inner (bulkReads) on $left.CreatorCaller == $right.Caller
| where FirstRead < AccountCreateTime
| project
    AccountCreateTime, NewAccountResource,
    CreatorCaller, CreatorIP,
    ReadCount, FirstRead, LastRead, ReadFromIPs,
    SubscriptionId, ResourceGroup
| order by AccountCreateTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Data migration pipelines that enumerate existing storage accounts before creating a new destination account.
- Infrastructure-as-code tools (Terraform, Bicep) that perform read operations to check existing state before provisioning new resources.
- Backup and replication services that read from source storage and write to newly provisioned destination accounts.
- Security scanning tools that enumerate storage accounts at high volume.

Tuning notes:
- For higher-fidelity data exfiltration detection, complement this query with StorageBlobLogs querying for high-volume GetBlob operations from the same Caller identity.
- Add a Caller allowlist for known automation service principals, managed identities, and IaC pipeline identities.
- Increase readVolumeThreshold to 500 or 1000 in environments with active storage management automation.
- Consider adding a ResourceGroup exclusion list for known infrastructure automation resource groups to reduce IaC false positives.

Risks / caveats:
- AzureActivity requires the Azure Activity Log connector to be enabled in Microsoft Sentinel; if not configured, the table will be empty.
- AzureActivity captures control-plane operations only; actual data-plane blob read/write operations require Azure Storage diagnostic logs (StorageBlobLogs) which are a separate connector and not queried here.
- AzureActivity.Caller may be a service principal object ID rather than a UPN, making identity correlation less reliable across automated pipelines.
- AzureActivity captures control-plane operations only; actual data exfiltration via blob reads would appear in StorageBlobLogs (data-plane), not AzureActivity. This detection identifies the account creation pattern, not confirmed data transfer.

### Triage Runbook

First 15 minutes:
- Confirm the same caller identity performed the reads and created the new storage account.
- Check whether the read activity and account creation align with a known migration, backup, or IaC workflow.
- Review the caller IP, subscription, and resource group for unexpected origin or scope.
- Assess whether the new storage account is receiving data from an application or pipeline that should be expected.
- Look for other AzureActivity events from the same caller that indicate broader resource manipulation.

Evidence to collect:
- AccountCreateTime, NewAccountResource, CreatorCaller, CreatorIP, ReadCount, FirstRead, LastRead, ReadFromIPs
- SubscriptionId, ResourceGroup, and any tags or naming conventions on the new account
- ActivityStatus and exact OperationName values for the read and create events
- Any related StorageBlobLogs or other data-plane logs if available to confirm actual data movement
- Change-management or deployment records tied to the caller identity

Pivot points:
- AzureActivity for additional reads, writes, or deletes by the same Caller
- StorageBlobLogs or storage diagnostic logs to validate actual data-plane exfiltration
- Azure Resource Graph for resource inventory and ownership context
- Identity logs for the CreatorCaller if it is a service principal or managed identity
- Microsoft Sentinel incidents for related cloud or identity alerts

Benign explanations:
- Infrastructure-as-code or deployment tools reading existing state before creating a new account
- Backup, replication, or migration workflows that enumerate storage resources before provisioning
- Security or inventory scanning that generates high-volume read-like control-plane activity
- Planned cloud modernization or tenant reorganization work

Escalation criteria:
- The caller identity is unfamiliar, unapproved, or not tied to a known automation workflow
- The new storage account is not part of a documented migration or deployment
- There is evidence of actual data-plane transfer, unusual access patterns, or additional suspicious cloud activity
- The same identity is involved in other suspicious Azure operations or identity anomalies

Containment actions:
- Disable or suspend the suspicious caller identity if unauthorized activity is confirmed
- Revoke credentials or tokens for the identity if compromise is suspected
- Coordinate with cloud administrators to stop or roll back the suspicious provisioning if safe and approved
- Preserve AzureActivity and related storage logs before remediation

Closure criteria:
- A documented migration, backup, or IaC process explains the read and create sequence
- The caller identity is a known automation principal or managed identity
- No data-plane evidence or additional suspicious cloud activity is found
- The event is validated as expected cloud administration activity

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Schema / correlation keys:
- SharkLoader Staging Cobalt Strike Beacon via Unsigned Process Network Activity: Do not schedule yet; validate as an analyst-led hunt first.
- Azure Storage Bucket Creation Matching Previously Deleted Resource Names: Do not schedule yet; validate as an analyst-led hunt first.
- Concurrent Remote Logons from Distinct Source IPs on Same Host Indicating Multi-Actor Access: Do not schedule yet; validate as an analyst-led hunt first.
- Large-Volume Azure Storage Read Operations Followed by Write to Newly Created Storage Account: Do not schedule yet; validate as an analyst-led hunt first.

Shared-table notes:
- DeviceFileEvents: shared by SharkLoader Staging Cobalt Strike Beacon via Unsigned Process Network Activity; Ransomware Pre-Deployment: Shadow Copy Deletion Combined with Mass File Modification
- DeviceProcessEvents: shared by SharkLoader Staging Cobalt Strike Beacon via Unsigned Process Network Activity; Ransomware Pre-Deployment: Shadow Copy Deletion Combined with Mass File Modification
- AzureActivity: shared by Azure Storage Bucket Creation Matching Previously Deleted Resource Names; Large-Volume Azure Storage Read Operations Followed by Write to Newly Created Storage Account

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Ransomware Pre-Deployment: Shadow Copy Deletion Combined with Mass File Modification.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: SharkLoader Staging Cobalt Strike Beacon via Unsigned Process Network Activity; Azure Storage Bucket Creation Matching Previously Deleted Resource Names; Concurrent Remote Logons from Distinct Source IPs on Same Host Indicating Multi-Actor Access; Large-Volume Azure Storage Read Operations Followed by Write to Newly Created Storage Account.

### Hunting Agenda and Promotion Criteria

- SharkLoader Staging Cobalt Strike Beacon via Unsigned Process Network Activity: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Azure Storage Bucket Creation Matching Previously Deleted Resource Names: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Concurrent Remote Logons from Distinct Source IPs on Same Host Indicating Multi-Actor Access: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Large-Volume Azure Storage Read Operations Followed by Write to Newly Created Storage Account: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
