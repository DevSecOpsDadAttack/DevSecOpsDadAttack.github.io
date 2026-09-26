---
layout: post
title: "Detection Engineering Brief - Saturday, September 26, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-26
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Storm-3168
  - JADEPUFFER
  - Azure
  - Microsoft Entra ID
  - Storm-2570
  - Microsoft Defender XDR
  - Windows
  - Qilin
  - DragonForce
  - Anubis
  - BERT
  - Zimbra Collaboration Suite
  - macOS
  - MacSync
  - T1552.001
  - T1528
  - T1552
  - T1016
  - T1087
  - T1087.001
  - T1021.002
  - T1021
  - T1114.002
  - T1098.002
  - T1114.003
  - T1114
  - T1098
  - T1059
  - T1071
  - T1105
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

2 production candidates, 2 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Storm-3168, JADEPUFFER, Azure, Microsoft Entra ID, Storm-2570, Microsoft Defender XDR, Windows, Qilin, DragonForce, Anubis, BERT, Zimbra Collaboration Suite, macOS, MacSync, T1552.001, T1528, T1552, T1016, T1087, T1087.001, ....

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Storm-3168 - Service Principal Credential Access via Key Vault Following Cloud Sign-In; Storm-2570 - Pre-Ransomware Lateral Movement and Discovery Preceding Known Ransomware Family Activity; MacSync Backdoor - Suspicious Child Process and Outbound Connection on macOS Endpoint.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Storm-3168 - Service Principal Azure Resource Deletion Following Reconnaissance

### Detection Opportunity

Compromised service principal performs Azure resource enumeration followed by resource deletion within a short time window

### Intelligence Context

- Microsoft Security Blog: Storm-3168: Agentic-driven cloud attacks using compromised service principals — [https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/)
  - Context: Storm-3168 used compromised service principals to perform Azure reconnaissance and then delete resources, representing a compound destructive pattern attributable to this actor.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-3168, JADEPUFFER
- ATT&CK tags: T1552.001, T1528, T1552
- Products: Azure, Microsoft Entra ID
- Platforms: Azure
- Malware: Not specified
- Tools: Not specified
- Search tags: Storm-3168, JADEPUFFER, Azure, Microsoft Entra ID, T1552.001, T1528, T1552

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1552 Unsecured Credentials/ T1552.001 Credentials In Files (low); Credential Access: T1528 Steal Application Access Token (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- AzureActivity

### KQL

```kql
let lookback = 1h;
let recon_window = 30m;
let min_recon_count = 10;
let min_delete_count = 1;
let recon_ops = AzureActivity
| where TimeGenerated >= ago(lookback)
| where tolower(OperationName) has_any ("list", "read", "get")
| where ActivityStatus =~ "Succeeded"
| where isnotempty(Caller)
| summarize
    ReconCount = count(),
    ReconStart = min(TimeGenerated),
    ReconIPs = make_set(CallerIpAddress, 50)
    by Caller, ResourceGroup, SubscriptionId;
let delete_ops = AzureActivity
| where TimeGenerated >= ago(lookback)
| where tolower(OperationName) has "delete"
| where ActivityStatus =~ "Succeeded"
| where isnotempty(Caller)
| summarize
    DeleteCount = count(),
    DeleteTime = min(TimeGenerated),
    DeletedResources = make_set(OperationName, 20),
    DeleteIPs = make_set(CallerIpAddress, 50)
    by Caller, ResourceGroup, SubscriptionId;
recon_ops
| join kind=inner delete_ops on Caller, ResourceGroup, SubscriptionId
| where DeleteTime >= ReconStart
| where DeleteTime <= ReconStart + recon_window
| where ReconCount >= min_recon_count
| where DeleteCount >= min_delete_count
| project
    Caller,
    ResourceGroup,
    SubscriptionId,
    ReconCount,
    DeleteCount,
    ReconStart,
    DeleteTime,
    TimeDeltaMinutes = datetime_diff('minute', DeleteTime, ReconStart),
    ReconIPs,
    DeleteIPs,
    DeletedResources
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Automation service principals that perform bulk inventory reads before cleanup pipelines execute legitimate deletes.
- Infrastructure-as-code pipelines (Terraform, Bicep) that enumerate resources before destroying and recreating stacks.
- Monitoring agents that continuously poll resource state and co-occur with scheduled maintenance deletes.

**Tuning notes:**
- Raise min_recon_count to 25-50 in environments where automation service principals routinely perform bulk reads before maintenance windows.
- Narrow the recon_window to 10-15 minutes if legitimate pipelines complete their read-then-delete cycle faster than 30 minutes.
- Add a Caller exclusion list for known automation service principal object IDs identified during baseline review.
- Consider adding a SubscriptionId filter to scope detection to production subscriptions and exclude sandbox or dev environments.

**Risks / caveats:**
- AzureActivity requires the Azure Activity diagnostic connector to be enabled in Microsoft Sentinel; if not configured, the table will be empty.
- OperationName casing and format vary by Azure resource provider; has_any with lowercase strings may miss operations where the provider emits mixed-case names.
- The 30-minute correlation window and ReconCount threshold of 10 are starting points; environments with high-frequency automation may require raising the threshold significantly to reduce noise.
- Caller may contain human admin UPNs in addition to service principal IDs; post-deployment review should confirm whether results are dominated by non-human identities.

### Triage Runbook

**First 15 minutes:**
- Confirm the Caller identity is a service principal and not a known automation identity; note the SubscriptionId, ResourceGroup, ReconCount, DeleteCount, ReconStart, and DeleteTime.
- Review the specific OperationName values in DeletedResources and verify whether the deletes were expected maintenance, IaC teardown, or unexpected destructive actions.
- Check ReconIPs and DeleteIPs for source IP changes, unusual geographies, or IPs outside your normal admin/automation ranges.
- Look for additional AzureActivity events from the same Caller before and after the alert to see whether the activity expanded to other resource groups or subscriptions.

**Evidence to collect:**
- AzureActivity records for the Caller across the prior 24 hours, including OperationName, ActivityStatus, ResourceGroup, SubscriptionId, and CallerIpAddress.
- Identity details for the service principal: object ID/app ID, owner, last credential rotation, and any recent secret or certificate changes in Microsoft Entra ID.
- Change records or deployment pipeline logs for the affected ResourceGroup and SubscriptionId to confirm whether the deletes were authorized.
- Any correlated sign-in or token issuance events for the same service principal from Entra ID or related identity logs.

**Pivot points:**
- AzureActivity filtered by Caller, ResourceGroup, and SubscriptionId to enumerate all reads, writes, and deletes around the alert window.
- Microsoft Entra ID service principal sign-in and credential management logs to validate whether the identity was recently used from an unusual context.
- Resource-specific activity or deployment logs for the affected subscription/resource group to confirm whether the deletions were part of an approved change.
- If available, correlate with Defender XDR or endpoint logs for the host or automation runner that used the service principal.

**Benign explanations:**
- An infrastructure-as-code pipeline intentionally enumerated resources before a planned teardown or redeployment.
- A legitimate automation service principal performed inventory reads before cleanup or decommissioning tasks.
- A monitoring or maintenance workflow read resource state and then deleted a known test or temporary resource group.

**Escalation criteria:**
- Delete operations are not tied to an approved change, pipeline, or maintenance window.
- The Caller is a service principal with no known business owner or has recently had credentials rotated unexpectedly.
- Recon and delete activity spans multiple resource groups or subscriptions, or the source IP is clearly anomalous.
- Any evidence shows successful deletion of production resources or continued destructive activity after the alert.

**Containment actions:**
- Disable or revoke the service principal credentials if the activity is unauthorized or cannot be quickly explained.
- Remove active role assignments or temporarily block the identity from the affected subscription/resource group if supported by your process.
- Pause related automation pipelines and review recent secret/certificate changes for the service principal.
- Preserve AzureActivity and identity logs before making changes if incident response requires evidence retention.

**Closure criteria:**
- The service principal is confirmed as a known automation identity and the delete activity is matched to an approved change or pipeline run.
- No additional destructive actions are observed after review of surrounding AzureActivity events.
- The source IPs, timing, and resource group scope align with documented operational behavior.
- Any unexpected activity has been remediated and the identity has been revalidated or rotated as needed.

<br/>
---
<br/>

## Detection 2: Storm-3168 - Service Principal Credential Access via Key Vault Following Cloud Sign-In

### Detection Opportunity

Compromised service principal accesses Key Vault secrets or credential stores in Azure after authenticating from an anomalous caller context

### Intelligence Context

- Microsoft Security Blog: Storm-3168: Agentic-driven cloud attacks using compromised service principals — [https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/)
  - Context: Storm-3168 used compromised service principals to access credentials in cloud environments, a distinct post-authentication behavior following initial service principal compromise.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-3168, JADEPUFFER
- ATT&CK tags: T1552.001, T1528, T1552
- Products: Azure, Microsoft Entra ID
- Platforms: Azure
- Malware: Not specified
- Tools: Not specified
- Search tags: Storm-3168, JADEPUFFER, Azure, Microsoft Entra ID, T1552.001, T1528, T1552

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1552 Unsecured Credentials/ T1552.001 Credentials In Files (low); Credential Access: T1528 Steal Application Access Token (low)

### Deployment Gates

- Key Vault data plane operations (SecretGet, KeyGet, SecretList) are not emitted to AuditLogs (the Entra audit log table); they appear in AzureActivity or in a dedicated AzureDiagnostics/KeyVaultData table depending on whether Key Vault diagnostic settings route to Log Analytics. The original query targets the wrong table for Key Vault operations.

**Required telemetry:**
- AzureActivity, SigninLogs

### KQL

```kql
let lookback = 2h;
let correlation_window = 1h;
// Service principal sign-ins: prefer AADServicePrincipalSignInLogs if available in workspace
let sp_signins = AADServicePrincipalSignInLogs
| where TimeGenerated >= ago(lookback)
| where ResultType == 0
| where isnotempty(ServicePrincipalId)
| project SigninTime = TimeGenerated, ServicePrincipalId, ServicePrincipalName, SigninIP = IPAddress;
// Key Vault data plane operations from AzureActivity
// Requires Key Vault diagnostic settings to route to this Log Analytics workspace
let kv_access = AzureActivity
| where TimeGenerated >= ago(lookback)
| where ResourceProviderValue =~ "Microsoft.KeyVault"
| where tolower(OperationName) has_any ("secretget", "keyget", "secretlist", "certificateget", "certificatelist", "vaultget")
| where ActivityStatus =~ "Succeeded"
| where isnotempty(Caller)
| extend KeyVaultName = tostring(split(ResourceId, "/")[8])
| project
    KVAccessTime = TimeGenerated,
    Caller,
    OperationName,
    KeyVaultName,
    ResourceGroup,
    SubscriptionId,
    CallerIpAddress;
kv_access
| join kind=inner sp_signins on $left.Caller == $right.ServicePrincipalId
| where KVAccessTime >= SigninTime
| where KVAccessTime <= SigninTime + correlation_window
| project
    ServicePrincipalId,
    ServicePrincipalName,
    OperationName,
    KeyVaultName,
    ResourceGroup,
    SubscriptionId,
    KVAccessTime,
    SigninTime,
    SigninIP,
    CallerIpAddress
| summarize
    Operations = make_set(OperationName, 20),
    KeyVaults = make_set(KeyVaultName, 20),
    EarliestKVAccess = min(KVAccessTime),
    SigninTime = min(SigninTime),
    SigninIPs = make_set(SigninIP, 10),
    CallerIPs = make_set(CallerIpAddress, 10)
    by ServicePrincipalId, ServicePrincipalName, ResourceGroup, SubscriptionId
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate automation service principals that authenticate and immediately retrieve secrets as part of scheduled pipeline execution.
- Secret rotation workflows that sign in and then enumerate Key Vault contents as part of their normal operation.
- Monitoring or compliance tools that periodically authenticate and audit Key Vault access.

**Tuning notes:**
- If the workspace uses AzureDiagnostics for Key Vault logs instead of AzureActivity, replace the kv_access subquery with: AzureDiagnostics → where ResourceType == 'VAULTS' → where OperationName has_any ('SecretGet','KeyGet','SecretList').
- Add a ServicePrincipalId exclusion list for known secret-retrieval automation principals after baseline review.
- Narrow the correlation window to 15-30 minutes if service principal authentication and secret access are expected to occur in rapid succession in your environment.
- Consider adding a filter for CallerIpAddress not matching known corporate egress ranges to focus on anomalous source IPs.

**Risks / caveats:**
- Key Vault data plane operations (SecretGet, KeyGet, SecretList) are not emitted to AuditLogs (the Entra audit log table); they appear in AzureActivity or in a dedicated AzureDiagnostics/KeyVaultData table depending on whether Key Vault diagnostic settings route to Log Analytics. The original query targets the wrong table for Key Vault operations.
- Joining AuditLogs to SigninLogs on display name string equality is fragile; service principal display names are not guaranteed unique and may differ between the two tables. A join on ServicePrincipalId is required for reliable correlation but InitiatedBy.app.servicePrincipalId in AuditLogs must match the AppId or ObjectId used in SigninLogs.
- SigninLogs captures service principal sign-ins only when the ServicePrincipalSignInLogs table is not separately configured; in some tenants, service principal authentications appear in AADServicePrincipalSignInLogs rather than SigninLogs.
- If AADServicePrincipalSignInLogs is not present in the workspace, the query must be rewritten to use SigninLogs filtered to non-empty ServicePrincipalId; the join key must then use AppId rather than ServicePrincipalId to match Caller in AzureActivity.

### Triage Runbook

**First 15 minutes:**
- Validate the ServicePrincipalId and ServicePrincipalName against your approved automation inventory and confirm whether the SigninIP and CallerIpAddress are expected.
- Check whether the KeyVaultName and OperationName values indicate secret retrieval, key retrieval, or enumeration, and whether the access was authorized.
- Review the sign-in timing relative to KVAccessTime to see if the access immediately followed authentication from a suspicious IP or tenant context.
- Determine whether the service principal has access to sensitive vaults, production secrets, or credentials used by other systems.

**Evidence to collect:**
- AADServicePrincipalSignInLogs or SigninLogs for the ServicePrincipalId, including IPAddress, ResultType, and authentication timing.
- AzureActivity or Key Vault diagnostic logs showing the exact Key Vault operations, vault name, resource group, and subscription.
- Service principal credential history, including recent secret or certificate additions, expirations, and owner changes.
- Any downstream activity using secrets or tokens that may have been retrieved from the vault.

**Pivot points:**
- AADServicePrincipalSignInLogs or SigninLogs filtered to the ServicePrincipalId and the alert time window.
- AzureActivity or AzureDiagnostics/KeyVaultData for the KeyVaultName to enumerate all secret/key access by the same Caller.
- Microsoft Entra ID audit logs for service principal credential changes and role assignment changes.
- Defender XDR or other cloud logs for follow-on activity from the same identity or source IP.

**Benign explanations:**
- A scheduled automation or deployment pipeline authenticated and retrieved secrets as part of normal operation.
- Secret rotation or certificate renewal workflows accessed the vault immediately after sign-in.
- A compliance or monitoring tool authenticated and enumerated vault contents for inventory purposes.

**Escalation criteria:**
- The sign-in source IP is not recognized and does not match any approved automation or corporate egress range.
- The service principal accessed high-value secrets, keys, or certificates without a documented business reason.
- There is evidence of credential changes, token abuse, or follow-on activity from the same identity.
- The service principal is not a known automation account or the access pattern is inconsistent with baseline behavior.

**Containment actions:**
- Disable or rotate the service principal credentials if unauthorized access is suspected.
- Restrict Key Vault access policies or role assignments for the identity until the investigation is complete.
- Block the suspicious source IP only if it is safe to do so and consistent with your response process.
- Preserve Key Vault and sign-in logs before making changes if evidence retention is required.

**Closure criteria:**
- The service principal is confirmed as legitimate and the Key Vault access matches an approved workflow.
- The source IP and timing are consistent with baseline automation behavior.
- No additional suspicious vault access or identity abuse is found in surrounding logs.
- Any unexpected credential exposure has been remediated and the identity has been reviewed or rotated.

<br/>
---
<br/>

## Detection 3: Storm-2570 - Pre-Ransomware Lateral Movement and Discovery Preceding Known Ransomware Family Activity

### Detection Opportunity

Post-compromise lateral movement and discovery activity on endpoints where Qilin, DragonForce, Anubis, or BERT ransomware families are subsequently observed

### Intelligence Context

- Microsoft Security Blog: Beyond the ransomware: Tracking Storm-2570's consistent tradecraft across deployments — [https://www.microsoft.com/en-us/security/blog/2026/09/24/beyond-ransomware-tracking-storm-2570-consistent-tradecraft-across-deployments/](https://www.microsoft.com/en-us/security/blog/2026/09/24/beyond-ransomware-tracking-storm-2570-consistent-tradecraft-across-deployments/)
  - Context: Storm-2570 performs consistent post-compromise activity including lateral movement and discovery before deploying Qilin, DragonForce, Anubis, or BERT ransomware. Detecting this pre-deployment phase enables disruption before encryption occurs.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-2570
- ATT&CK tags: T1016, T1087, T1087.001, T1021.002, T1021
- Products: Microsoft Defender XDR
- Platforms: Windows
- Malware: Qilin, DragonForce, Anubis, BERT
- Tools: Not specified
- Search tags: Storm-2570, Microsoft Defender XDR, Windows, Qilin, DragonForce, Anubis, BERT, T1016, T1087, T1087.001, T1021.002, T1021

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Discovery: T1016 System Network Configuration Discovery (high); Discovery: T1087 Account Discovery/ T1087.001 Local Account (high); Lateral Movement: T1021 Remote Services/ T1021.002 SMB/Windows Admin Shares (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceLogonEvents, DeviceFileEvents

### KQL

```kql
let lookback = 48h;
let ransomware_families = dynamic(["qilin", "dragonforce", "anubis", "bert"]);
let discovery_commands = dynamic(["net view", "nltest", "whoami", "ipconfig", "net user", "net group", "arp -a", "net localgroup", "tasklist", "systeminfo"]);
let ransomware_devices = DeviceFileEvents
| where TimeGenerated >= ago(lookback)
| where ActionType == "FileCreated"
| where tolower(FileName) has_any (ransomware_families)
| summarize
    RansomwareTime = min(TimeGenerated),
    RansomwareFileName = take_any(FileName),
    RansomwareFolderPath = take_any(FolderPath)
    by DeviceId, DeviceName;
let discovery_cmds = DeviceProcessEvents
| where TimeGenerated >= ago(lookback)
| where tolower(ProcessCommandLine) has_any (discovery_commands)
| project
    DiscoveryTime = TimeGenerated,
    DeviceId,
    DeviceName,
    ProcessCommandLine,
    AccountName,
    InitiatingProcessFileName;
let lateral_logons = DeviceLogonEvents
| where TimeGenerated >= ago(lookback)
| where LogonType in (3, 10)
| where ActionType == "LogonSuccess"
| summarize LateralLogonCount = count() by DeviceId, DeviceName;
discovery_cmds
| join kind=inner ransomware_devices on DeviceId
| where DiscoveryTime < RansomwareTime
| summarize
    DiscoveryCommands = make_set(ProcessCommandLine, 50),
    EarliestDiscovery = min(DiscoveryTime),
    RansomwareTime = max(RansomwareTime),
    RansomwareFileName = take_any(RansomwareFileName),
    RansomwareFolderPath = take_any(RansomwareFolderPath)
    by DeviceId, DeviceName, AccountName
| extend MinutesBeforeRansomware = datetime_diff('minute', RansomwareTime, EarliestDiscovery)
| where MinutesBeforeRansomware > 5
| join kind=leftouter lateral_logons on DeviceId
| project
    DeviceName,
    DeviceId,
    AccountName,
    DiscoveryCommands,
    LateralLogonCount = coalesce(LateralLogonCount, 0),
    EarliestDiscovery,
    RansomwareTime,
    MinutesBeforeRansomware,
    RansomwareFileName,
    RansomwareFolderPath
| sort by MinutesBeforeRansomware asc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Security tools or EDR agents that create files with names containing 'anubis' or 'bert' as part of detection signatures or quarantine artifacts.
- Penetration testing or red team exercises that use discovery commands on endpoints where test payloware files are present.
- Legitimate administrative scripts that run net view, nltest, or whoami as part of inventory or health checks.

**Tuning notes:**
- Expand the ransomware_families list as new Storm-2570-associated family names are confirmed in threat intelligence.
- Add SHA256 hash-based detection in DeviceFileEvents as a parallel query when hashes become available from threat intelligence, as it is more reliable than name matching.
- Increase MinutesBeforeRansomware threshold to 60 or more to focus on cases with a meaningful dwell period between discovery and deployment.
- Consider adding a FolderPath filter to exclude known security tool quarantine directories from the ransomware file creation matches.

**Risks / caveats:**
- DeviceFileEvents FileName field contains only the file name without path; ransomware payloads renamed to non-family-name strings will not be detected by this query.
- LogonType in DeviceLogonEvents is an integer field; the original query correctly uses integer values 3 and 10, which is preserved.
- File name substring matching will miss ransomware payloads that are renamed or obfuscated; this is a fundamental limitation of name-based detection noted in the original assumptions.
- The 48-hour lookback window is expensive at scale; consider reducing to 24 hours for scheduled hunting runs and using 48 hours only for ad hoc investigation.

### Triage Runbook

**First 15 minutes:**
- Identify the affected DeviceName, DeviceId, AccountName, and the time gap between EarliestDiscovery and RansomwareTime.
- Review the DiscoveryCommands to determine whether they are administrative, troubleshooting, or clearly reconnaissance-oriented.
- Check whether the RansomwareFileName and RansomwareFolderPath are in user space, temp locations, quarantine paths, or known security tool directories.
- Look for additional logon activity on the same host and account, especially remote logons or repeated access to other systems.

**Evidence to collect:**
- DeviceProcessEvents for the host and account around the alert window, including command lines and parent processes.
- DeviceLogonEvents for the same DeviceId and AccountName to identify remote logons, lateral movement, and unusual logon types.
- DeviceFileEvents showing the ransomware-related file creation, folder path, and any related file hashes if available.
- Any Defender XDR alerts, isolation events, or malware detections on the same device or adjacent devices.

**Pivot points:**
- DeviceProcessEvents filtered by DeviceId and AccountName to expand discovery and execution activity before the ransomware timestamp.
- DeviceLogonEvents filtered by DeviceId to identify remote logons, admin share use, or suspicious authentication patterns.
- DeviceFileEvents filtered by DeviceId and the ransomware family names to confirm whether the file creation is real malware or a benign artifact.
- Defender XDR incident timeline for the device and user to correlate with other alerts and containment actions.

**Benign explanations:**
- An administrator or support engineer ran common discovery commands during troubleshooting or inventory work.
- A red team or penetration test generated discovery and logon activity in a controlled exercise.
- A security tool or quarantine process created a file whose name matches one of the ransomware family strings.

**Escalation criteria:**
- The discovery commands are followed by confirmed ransomware file creation outside a known test or quarantine path.
- The same account shows suspicious remote logons or lateral movement to other hosts.
- The device exhibits additional malicious behavior such as encryption, mass file renames, or multiple security alerts.
- The activity cannot be tied to an approved administrative or testing activity.

**Containment actions:**
- Isolate the endpoint from the network if ransomware activity is credible or file creation is confirmed as malicious.
- Disable or reset the affected account if it is not a shared admin account and compromise is suspected.
- Block suspicious remote access paths or credentials used for lateral movement.
- Preserve endpoint telemetry and memory or disk evidence according to your incident response process.

**Closure criteria:**
- The discovery and logon activity is confirmed as legitimate administration, testing, or security tooling.
- The ransomware file match is determined to be a benign artifact or quarantine-related file.
- No additional malicious activity is found on the host or adjacent systems.
- The device and account are validated against baseline behavior and no further response is required.

<br/>
---
<br/>

## Detection 4: BEC - Mailbox Access by Non-Owner with Subsequent Inbox Rule Creation

### Detection Opportunity

Unauthorized mailbox access followed by inbox rule creation, consistent with BEC actors silently monitoring operations and controlling inbox visibility

### Intelligence Context

- Rapid7: When Business Email Compromise Starts Rewriting Reality — [https://www.rapid7.com/blog/post/ve-business-email-compromise-rewriting-reality-zimbra-cve](https://www.rapid7.com/blog/post/ve-business-email-compromise-rewriting-reality-zimbra-cve)
  - Context: BEC actors breached mailboxes to silently monitor operations and then altered inbox visibility through rule creation and calendar or document modifications, enabling fraud by controlling what victims see.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1114.002, T1098.002, T1114.003, T1114, T1098
- Products: Zimbra Collaboration Suite
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: Zimbra Collaboration Suite, T1114.002, T1098.002, T1114.003, T1114, T1098

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Collection: T1114 Email Collection/ T1114.002 Remote Email Collection (high); Persistence: T1098 Account Manipulation/ T1098.002 Additional Email Delegate Permissions (medium); Defense Evasion: T1114 Email Collection/ T1114.003 Email Forwarding Rule (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- OfficeActivity

### KQL

```kql
let lookback = 24h;
let correlation_window = 60m;
let mailbox_access = OfficeActivity
| where TimeGenerated >= ago(lookback)
| where Operation in ("MailboxLogin", "FolderBind")
| where LogonType =~ "Delegate" or LogonType =~ "Admin"
| where UserId != MailboxOwnerUPN
| where isnotempty(UserId)
| where isnotempty(MailboxOwnerUPN)
| where isnotempty(ClientIP)
| project
    AccessTime = TimeGenerated,
    UserId,
    MailboxOwnerUPN,
    AccessIP = ClientIP;
let rule_changes = OfficeActivity
| where TimeGenerated >= ago(lookback)
| where Operation in (
    "New-InboxRule",
    "Set-InboxRule",
    "UpdateCalendarDelegation",
    "ModifyFolderPermissions",
    "AddFolderPermissions",
    "RemoveFolderPermissions"
    )
| where ResultStatus =~ "Succeeded" or ResultStatus =~ "True"
| where isnotempty(UserId)
| where isnotempty(MailboxOwnerUPN)
| project
    ChangeTime = TimeGenerated,
    UserId,
    MailboxOwnerUPN,
    Operation,
    ChangeIP = ClientIP;
mailbox_access
| join kind=inner rule_changes on UserId, MailboxOwnerUPN
| where ChangeTime >= AccessTime
| where ChangeTime <= AccessTime + correlation_window
| summarize
    Operations = make_set(Operation, 20),
    OperationCount = dcount(Operation),
    EarliestAccess = min(AccessTime),
    FirstChange = min(ChangeTime),
    AccessIP = take_any(AccessIP),
    ChangeIPs = make_set(ChangeIP, 10)
    by UserId, MailboxOwnerUPN
| extend MinutesFromAccessToChange = datetime_diff('minute', FirstChange, EarliestAccess)
| project
    UserId,
    MailboxOwnerUPN,
    Operations,
    OperationCount,
    EarliestAccess,
    FirstChange,
    MinutesFromAccessToChange,
    AccessIP,
    ChangeIPs
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Helpdesk administrators who access mailboxes via delegation and then create inbox rules on behalf of users as a legitimate support action.
- Executive assistant delegates who access executive mailboxes and configure inbox rules as part of their normal responsibilities.
- Migration tools or compliance agents that access mailboxes via admin impersonation and modify folder permissions during onboarding.

**Tuning notes:**
- Add a UserId exclusion list for known helpdesk accounts, executive assistants, and migration service accounts that legitimately access mailboxes via delegation.
- Extend correlation_window to 4 hours if post-deployment review shows BEC actors in your environment delay rule creation beyond 60 minutes.
- Add a filter for AccessIP not in known corporate IP ranges to focus on external access patterns.
- Consider adding MailboxOwnerUPN filtering to prioritize high-value targets such as finance, executive, or accounts payable mailboxes.

**Risks / caveats:**
- OfficeActivity requires the Microsoft 365 (Office 365) data connector to be enabled in Microsoft Sentinel; without it, the table will be empty.
- LogonType is a string field in OfficeActivity; the values 'Delegate' and 'Admin' must match exactly what Microsoft 365 audit logs emit. If the tenant emits different casing or values, the mailbox_access subquery will return no results.
- ResultStatus field availability and value format for inbox rule operations should be confirmed; some OfficeActivity records use 'True'/'False' or 'Succeeded'/'Failed' depending on the workload.
- LogonType field population in OfficeActivity is inconsistent across Microsoft 365 workloads; FolderBind events may not always carry a LogonType value, which could cause the mailbox_access subquery to miss some non-owner access events.

### Triage Runbook

**First 15 minutes:**
- Confirm whether UserId is a delegate, helpdesk account, executive assistant, migration account, or an unexpected actor for the MailboxOwnerUPN.
- Review the Operations list and OperationCount to see whether the change was a single rule or part of broader mailbox manipulation.
- Check AccessIP and ChangeIPs for unusual source locations or a change in source IP between access and rule creation.
- Determine whether the mailbox owner is a high-value target such as finance, payroll, executive leadership, or accounts payable.

**Evidence to collect:**
- OfficeActivity records for the UserId and MailboxOwnerUPN covering mailbox access, inbox rule changes, folder permission changes, and calendar delegation changes.
- Mailbox audit history or Exchange admin logs showing the exact rule names, forwarding targets, and timestamps.
- Identity logs for the accessing account, including sign-in IPs and any recent MFA or password events.
- User or helpdesk confirmation that the access and rule creation were authorized.

**Pivot points:**
- OfficeActivity filtered by UserId and MailboxOwnerUPN to enumerate all mailbox operations in the prior 24 hours.
- Exchange or Microsoft 365 audit logs for inbox rule details, forwarding addresses, and delegate permissions.
- Entra sign-in logs for the accessing account to validate source IP and authentication context.
- If available, email trace or message tracking logs to see whether messages were forwarded, hidden, or deleted after the rule was created.

**Benign explanations:**
- A legitimate delegate or executive assistant accessed the mailbox and created rules as part of normal support duties.
- A helpdesk or migration account performed mailbox changes during onboarding, migration, or remediation.
- An administrator applied mailbox rules or permissions during a documented support case.

**Escalation criteria:**
- The accessing account is not an approved delegate or admin for the mailbox owner.
- The inbox rule forwards, hides, deletes, or auto-archives messages in a way that could conceal fraud or monitoring.
- The mailbox owner is a sensitive target and the access came from an unusual IP or impossible travel context.
- There are additional signs of BEC such as suspicious forwarding, external recipients, or recent credential compromise.

**Containment actions:**
- Remove unauthorized inbox rules and revoke delegate or admin access if the activity is not approved.
- Reset credentials or disable the accessing account if compromise is suspected.
- Review and remove any suspicious forwarding or mailbox permission changes.
- Preserve mailbox audit logs and message trace data before making changes.

**Closure criteria:**
- The access and rule creation are confirmed as authorized and match a documented support or business process.
- No suspicious forwarding, hiding, or deletion behavior is present.
- The accessing account is a known delegate or admin with a valid business need.
- Any unauthorized mailbox changes have been removed and the mailbox owner has been notified as appropriate.

<br/>
---
<br/>

## Detection 5: MacSync Backdoor - Suspicious Child Process and Outbound Connection on macOS Endpoint

### Detection Opportunity

New backdoor module associated with MacSync establishes unexpected child processes and outbound network connections on macOS endpoints

### Intelligence Context

- Securelist: MacSync under the microscope: new delivery methods and a new payload — [https://securelist.com/macsync-new-version/121383/](https://securelist.com/macsync-new-version/121383/)
  - Context: MacSync introduced a new payload with a backdoor module targeting macOS users, particularly crypto enthusiasts and developers. The backdoor is expected to establish persistence and C2 communication typical of macOS backdoor implants.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1071, T1105
- Products: Not specified
- Platforms: macOS
- Malware: MacSync
- Tools: Not specified
- Search tags: macOS, MacSync, T1059, T1071, T1105

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (medium); Command and Control: T1071 Application Layer Protocol (low); Command and Control: T1105 Ingress Tool Transfer (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let lookback = 24h;
let c2_window = 5m;
let suspicious_parents = dynamic(["bash", "zsh", "python3", "python", "osascript", "curl", "wget", "sh"]);
let excluded_children = dynamic(["bash", "zsh", "sh", "python3", "python", "dash"]);
let new_procs = DeviceProcessEvents
| where TimeGenerated >= ago(lookback)
| where OSPlatform =~ "macOS"
| where tolower(InitiatingProcessFileName) has_any (suspicious_parents)
| where tolower(FileName) !in (excluded_children)
| where isnotempty(FileName)
| project
    ProcTime = TimeGenerated,
    DeviceId,
    DeviceName,
    ProcessId,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    AccountName,
    AccountDomain;
let outbound = DeviceNetworkEvents
| where TimeGenerated >= ago(lookback)
| where OSPlatform =~ "macOS"
| where ActionType == "ConnectionSuccess"
| where isnotempty(RemoteIP)
| where RemoteIP !startswith "127."
| where RemoteIP !startswith "169.254."
| where RemoteIP != "::1"
| where not(ipv4_is_private(RemoteIP))
| project
    NetTime = TimeGenerated,
    DeviceId,
    InitiatingProcessId,
    InitiatingProcessFileName,
    RemoteIP,
    RemotePort;
new_procs
| join kind=inner outbound on DeviceId
| where NetTime >= ProcTime
| where NetTime <= ProcTime + c2_window
| where InitiatingProcessId == InitiatingProcessId1
    or tolower(InitiatingProcessFileName1) == tolower(FileName)
| summarize
    RemoteIPs = make_set(RemoteIP, 50),
    RemotePorts = make_set(RemotePort, 20),
    Commands = make_set(ProcessCommandLine, 20),
    ProcTime = min(ProcTime)
    by DeviceName, DeviceId, AccountName, AccountDomain, FileName, InitiatingProcessFileName
| project
    DeviceName,
    DeviceId,
    AccountName,
    AccountDomain,
    FileName,
    InitiatingProcessFileName,
    Commands,
    RemoteIPs,
    RemotePorts,
    ProcTime
| sort by ProcTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Developer workflows where bash or zsh spawns build tools or package managers that make outbound connections to package repositories.
- Python scripts invoked from terminal sessions that make legitimate API calls to external services.
- curl or wget spawned from shell scripts that download updates or configuration files as part of normal operations.
- CI/CD agents running on macOS endpoints that spawn processes and make outbound connections as part of pipeline execution.

**Tuning notes:**
- Narrow the suspicious_parents list to osascript and curl only in developer-heavy environments where bash and python spawning outbound connections is routine.
- Add a RemoteIP allowlist for known package repository and update server IP ranges to reduce false positives from legitimate outbound connections.
- Reduce c2_window to 1 minute to tighten correlation if post-deployment review shows the 5-minute window generates excessive coincidental matches.
- Add a ProcessCommandLine exclusion for known package manager invocations such as pip install, npm install, or brew to filter common developer false positives.

**Risks / caveats:**
- OSPlatform field in DeviceProcessEvents and DeviceNetworkEvents must be populated with 'macOS' for Defender for Endpoint macOS agents; if the field is empty or uses a different value, the query returns no results. Confirm OSPlatform values in the workspace before relying on this filter.
- ipv4_is_private() function does not handle IPv6 addresses; if RemoteIP contains IPv6 addresses, the function may throw an error or return unexpected results. A type check or separate IPv6 handling is required.
- DeviceFileEvents is listed as a required table in the original detection but is not used in the improved query; it was removed as it was not referenced in the original KQL either.
- The join on InitiatingProcessId == InitiatingProcessId1 requires that DeviceNetworkEvents populates InitiatingProcessId consistently for macOS endpoints; if this field is empty, the fallback InitiatingProcessFileName match will be used, which is less precise.

### Triage Runbook

**First 15 minutes:**
- Review the DeviceName, AccountName, FileName, ProcessCommandLine, and RemoteIPs to understand what process spawned and where it connected.
- Check whether the initiating process is a known developer tool, package manager, script, or automation job on this Mac.
- Validate whether the RemoteIPs and RemotePorts are expected destinations such as corporate services, package repositories, or cloud APIs.
- Look for repeated process-to-network pairs on the same device that suggest persistence or recurring beaconing.

**Evidence to collect:**
- DeviceProcessEvents for the macOS host, including parent process, command line, and any repeated child process launches.
- DeviceNetworkEvents showing destination IPs, ports, and timing relative to process creation.
- Endpoint inventory or user profile information to determine whether the device is a developer workstation, CI/CD runner, or general-purpose endpoint.
- Any related Defender XDR alerts, quarantine actions, or file detections on the same device.

**Pivot points:**
- DeviceProcessEvents filtered by DeviceId and AccountName to identify repeated interpreter-spawned processes.
- DeviceNetworkEvents filtered by DeviceId and RemoteIP to see whether the same destinations recur across multiple processes.
- Defender XDR incident timeline for the device to correlate process, network, and file activity.
- If available, macOS-specific telemetry or EDR logs for persistence mechanisms, launch agents, or suspicious scripts.

**Benign explanations:**
- A developer or administrator used bash, zsh, python, curl, or wget for normal work.
- A package manager, build script, or CI/CD job made legitimate outbound connections.
- A user ran a script that contacted an external API or downloaded updates from a trusted source.

**Escalation criteria:**
- The outbound destination is unknown, suspicious, or not associated with the user’s normal workflow.
- The process command line indicates script execution, download, or command-and-control style behavior.
- The same host shows repeated suspicious child processes or multiple unusual outbound connections.
- There is evidence of persistence, credential theft, or additional malware activity on the Mac.

**Containment actions:**
- Isolate the macOS endpoint if the process and network behavior cannot be explained or appears malicious.
- Terminate the suspicious process only if your response process allows it and evidence has been captured.
- Block the suspicious destination IPs or domains if they are confirmed malicious and blocking is operationally safe.
- Preserve process and network telemetry before remediation.

**Closure criteria:**
- The process and outbound connection are confirmed as part of a legitimate developer, admin, or automation workflow.
- The destination IPs and ports are validated as trusted services or repositories.
- No additional suspicious process or network activity is observed on the host.
- Any suspicious artifacts are removed or accounted for and the device is returned to normal monitoring.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- Storm-3168 - Service Principal Credential Access via Key Vault Following Cloud Sign-In: Key Vault data plane operations (SecretGet, KeyGet, SecretList) are not emitted to AuditLogs (the Entra audit log table); they appear in AzureActivity or in a dedicated AzureDiagnostics/KeyVaultData table depending on whether Key Vault diagnostic settings route to Log Analytics. The original query targets the wrong table for Key Vault operations.

**Schema / correlation keys:**
- Storm-2570 - Pre-Ransomware Lateral Movement and Discovery Preceding Known Ransomware Family Activity: Do not schedule yet; validate as an analyst-led hunt first.
- MacSync Backdoor - Suspicious Child Process and Outbound Connection on macOS Endpoint: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- AzureActivity: shared by Storm-3168 - Service Principal Azure Resource Deletion Following Reconnaissance; Storm-3168 - Service Principal Credential Access via Key Vault Following Cloud Sign-In
- DeviceProcessEvents: shared by Storm-2570 - Pre-Ransomware Lateral Movement and Discovery Preceding Known Ransomware Family Activity; MacSync Backdoor - Suspicious Child Process and Outbound Connection on macOS Endpoint

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Storm-3168 - Service Principal Azure Resource Deletion Following Reconnaissance; BEC - Mailbox Access by Non-Owner with Subsequent Inbox Rule Creation.
2. Resolve environment-mapping detections next: Storm-3168 - Service Principal Credential Access via Key Vault Following Cloud Sign-In.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Storm-2570 - Pre-Ransomware Lateral Movement and Discovery Preceding Known Ransomware Family Activity; MacSync Backdoor - Suspicious Child Process and Outbound Connection on macOS Endpoint.

### Hunting Agenda and Promotion Criteria

- Storm-2570 - Pre-Ransomware Lateral Movement and Discovery Preceding Known Ransomware Family Activity: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- MacSync Backdoor - Suspicious Child Process and Outbound Connection on macOS Endpoint: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Storm-3168 - Service Principal Credential Access via Key Vault Following Cloud Sign-In: Key Vault data plane operations (SecretGet, KeyGet, SecretList) are not emitted to AuditLogs (the Entra audit log table); they appear in AzureActivity or in a dedicated AzureDiagnostics/KeyVaultData table depending on whether Key Vault diagnostic settings route to Log Analytics. The original query targets the wrong table for Key Vault operations.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
