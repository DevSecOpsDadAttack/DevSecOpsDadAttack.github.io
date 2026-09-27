---
layout: post
title: "Detection Engineering Brief - Sunday, September 27, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-27
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Storm-3168
  - Microsoft Entra ID
  - Azure
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
  - T1552
  - T1552.004
  - T1098
  - T1098.001
  - T1003
  - T1003.001
  - T1021
  - T1021.001
  - T1490
  - T1114
  - T1114.003
  - T1059
  - T1071
  - T1105
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

2 production candidates, 3 hunting-only, 0 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Storm-3168, Microsoft Entra ID, Azure, Storm-2570, Microsoft Defender XDR, Windows, Qilin, DragonForce, Anubis, BERT, Zimbra Collaboration Suite, macOS, MacSync, T1552, T1552.004, T1098, T1098.001, T1003, T1003.001, T1021, ....

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Storm-3168: Service Principal Resource Deletion Following Reconnaissance; Storm-2570: Pre-Ransomware Composite Signal - Credential Dumping, Lateral Movement, and Shadow Copy Deletion; MacSync Backdoor: macOS Process Making Outbound C2 Connection After Execution from Non-Standard Path.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Storm-3168: Service Principal Resource Deletion Following Reconnaissance

### Detection Opportunity

Compromised service principal performs bulk Azure resource enumeration followed by resource deletion operations

### Intelligence Context

- Microsoft Security Blog: Storm-3168: Agentic-driven cloud attacks using compromised service principals — [https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/)
  - Context: Storm-3168 used compromised service principals to perform Azure reconnaissance via bulk List/Get operations, then followed with destructive resource deletion. The compound sequence of enumeration then deletion by the same service principal caller is the key behavioral indicator.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-3168
- ATT&CK tags: T1552, T1552.004, T1098, T1098.001
- Products: Microsoft Entra ID
- Platforms: Azure
- Malware: Not specified
- Tools: Not specified
- Search tags: Storm-3168, Microsoft Entra ID, Azure, T1552, T1552.004, T1098, T1098.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1552 Unsecured Credentials/ T1552.004 Private Keys (medium); Persistence: T1098 Account Manipulation/ T1098.001 Additional Cloud Credentials (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- AzureActivity.ActivityStatusValue field name must be confirmed; some Sentinel workspaces surface this as ActivityStatus depending on connector version. If ActivityStatusValue is absent, the Success filter will silently drop all rows.

**Required telemetry:**
- AzureActivity

### KQL

```kql
let ReconWindow = 1h;
let DeleteWindow = 2h;
let MinReadOps = 20;
let LookbackPeriod = 24h;
let ReconActivity = AzureActivity
    | where TimeGenerated > ago(LookbackPeriod)
    | where tolower(OperationName) has_any ("list", "get", "read")
    | where ActivityStatusValue =~ "Success"
    | where isnotempty(Caller)
    | summarize
        ReadCount = count(),
        ReconStart = min(TimeGenerated),
        ReconEnd = max(TimeGenerated),
        ReadIPs = make_set(CallerIpAddress, 10),
        ResourceGroups = make_set(ResourceGroup, 10)
        by Caller, SubscriptionId
    | where ReadCount >= MinReadOps
    | where (ReconEnd - ReconStart) <= ReconWindow;
let DeleteActivity = AzureActivity
    | where TimeGenerated > ago(LookbackPeriod)
    | where tolower(OperationName) has "delete"
    | where ActivityStatusValue =~ "Success"
    | where isnotempty(Caller)
    | summarize
        DeleteCount = count(),
        FirstDelete = min(TimeGenerated),
        DeletedResources = make_set(ResourceId, 20)
        by Caller, SubscriptionId;
ReconActivity
| join kind=inner DeleteActivity on Caller, SubscriptionId
| where FirstDelete > ReconEnd
| where FirstDelete <= ReconEnd + DeleteWindow
| project
    Caller,
    SubscriptionId,
    ResourceGroups,
    ReadCount,
    ReconStart,
    ReconEnd,
    DeleteCount,
    FirstDelete,
    ReadIPs,
    DeletedResources
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate infrastructure-as-code pipelines that enumerate resources before applying changes including deletions as part of normal deployment cycles.
- Backup and disaster recovery automation that reads resource state before removing stale snapshots or replicas.
- Cost optimization tooling that lists resources and removes unused ones on a schedule.

**Tuning notes:**
- Increase MinReadOps above 20 in environments with heavy infrastructure-as-code automation to reduce false positives from deployment pipelines.
- Add a Caller exclusion list using a watchlist or dynamic() array for known automation service principal names or object IDs.
- Narrow tolower(OperationName) filters to specific resource provider prefixes such as 'microsoft.compute' or 'microsoft.storage' if cross-provider noise is high.
- Consider adding a ResourceGroup cardinality check to require that reads span multiple resource groups, which is more indicative of broad reconnaissance.

**Risks / caveats:**
- AzureActivity.ActivityStatusValue field name must be confirmed; some Sentinel workspaces surface this as ActivityStatus depending on connector version. If ActivityStatusValue is absent, the Success filter will silently drop all rows.
- AzureActivity.Caller is populated for ARM-authenticated callers but may be empty or contain object IDs for managed identity operations, reducing coverage for that authentication path.
- The ReconWindow filter (ReconEnd - ReconStart <= 1h) may exclude legitimate attack sequences where reconnaissance spans slightly longer than 1 hour; analysts should adjust based on observed attacker dwell time.
- Managed identity callers that do not include an @ symbol or GUID in the Caller field will be missed if the field is populated with a display name only.

### Triage Runbook

**First 15 minutes:**
- Confirm the Caller, SubscriptionId, and ResourceGroups in the alert are a known automation identity and not an expected deployment pipeline.
- Review ReconStart, ReconEnd, FirstDelete, ReadCount, and DeleteCount to verify the read-then-delete sequence occurred in the same subscription and within the expected window.
- Inspect DeletedResources to identify what was removed and whether the deletions affected production, security, identity, or recovery-related resources.
- Check ReadIPs and the caller's recent sign-in or activity history for a new source IP, unusual geography, or activity outside normal automation windows.
- Look for other actions by the same Caller around the same time, especially role assignments, credential changes, policy changes, or additional deletions.

**Evidence to collect:**
- AzureActivity records for the Caller across the prior 24 to 48 hours, including OperationName, ResourceId, ResourceGroup, ActivityStatusValue, and CallerIpAddress.
- Service principal metadata from Microsoft Entra ID, including display name, app ID, owners, credentials, and recent credential changes.
- Change history or deployment records for the affected SubscriptionId and ResourceGroups to determine whether the deletions were expected.
- A list of deleted resource types and any dependent resources that may have been impacted by the deletions.
- Any correlated sign-in or token issuance activity for the same service principal from Entra ID logs.

**Pivot points:**
- AzureActivity filtered by Caller and SubscriptionId to expand the full sequence of read, write, and delete operations.
- AuditLogs for service principal credential or role changes tied to the same app or object ID.
- AADServicePrincipalSignInLogs for recent sign-ins from the same service principal and source IPs.
- Resource Graph or Azure portal activity history to validate whether the deleted resources were part of a planned change.
- Entra ID service principal object details to identify owners, permissions, and recent modifications.

**Benign explanations:**
- Infrastructure-as-code or release automation that enumerates resources before removing stale or deprecated assets.
- Cost optimization or cleanup automation that deletes unused resources after inventorying them.
- Backup, DR, or environment reset workflows that intentionally remove resources as part of maintenance.

**Escalation criteria:**
- DeletedResources include production workloads, identity components, key vaults, storage accounts, or recovery resources.
- The Caller is not a known automation identity or the activity occurred from an unfamiliar IP or outside normal change windows.
- There are signs of additional malicious activity such as credential changes, role assignment changes, or repeated delete operations.
- The service principal has no documented business owner or the owner denies the activity.

**Containment actions:**
- Disable or revoke the suspected service principal credentials if the deletions are unauthorized.
- Remove any newly added credentials or role assignments associated with the service principal.
- Pause or disable related automation pipelines until ownership and intent are confirmed.
- Preserve AzureActivity and Entra ID logs before making changes.

**Closure criteria:**
- A documented change request, pipeline run, or maintenance record explains the enumeration and deletions.
- The service principal owner confirms the activity and no unauthorized resources were affected.
- No additional suspicious actions are found for the same Caller, SubscriptionId, or related identities.
- Any deleted resources were restored or the business impact was assessed and accepted.

<br/>
---
<br/>

## Detection 2: Storm-3168: Service Principal Credential Access Operations in Entra ID Audit Logs

### Detection Opportunity

Compromised service principal performs credential access operations against Entra ID resources

### Intelligence Context

- Microsoft Security Blog: Storm-3168: Agentic-driven cloud attacks using compromised service principals — [https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/)
  - Context: Storm-3168 accessed credentials in cloud environments using compromised service principals. Entra ID audit logs capture service principal operations against sensitive resources including key vaults, certificates, and secrets, providing a reliable post-authentication signal.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-3168
- ATT&CK tags: T1552, T1552.004, T1098, T1098.001
- Products: Microsoft Entra ID
- Platforms: Azure
- Malware: Not specified
- Tools: Not specified
- Search tags: Storm-3168, Microsoft Entra ID, Azure, T1552, T1552.004, T1098, T1098.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1552 Unsecured Credentials/ T1552.004 Private Keys (medium); Persistence: T1098 Account Manipulation/ T1098.001 Additional Cloud Credentials (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- AuditLogs, AADServicePrincipalSignInLogs

### KQL

```kql
let LookbackPeriod = 24h;
let CorrelationWindow = 30m;
let SPSignIns = AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(LookbackPeriod)
    | where ResultType == 0
    | summarize
        SignInIPs = make_set(IPAddress, 50),
        FirstSeen = min(TimeGenerated)
        by ServicePrincipalId, ServicePrincipalName;
let CredOps = AuditLogs
    | where TimeGenerated > ago(LookbackPeriod)
    | where OperationName in (
        "Update application",
        "Add key credentials to service principal",
        "Remove key credentials from service principal",
        "Update service principal",
        "Add password credential to service principal",
        "Remove password credential from service principal"
    )
    | where Result =~ "success"
    | extend SPId = tostring(InitiatedBy.app.servicePrincipalId)
    | where isnotempty(SPId)
    | project TimeGenerated, OperationName, SPId, ResourceId, CorrelationId;
CredOps
| join kind=inner SPSignIns on $left.SPId == $right.ServicePrincipalId
| where TimeGenerated >= FirstSeen
| where TimeGenerated <= FirstSeen + CorrelationWindow
| project
    TimeGenerated,
    OperationName,
    SPId,
    ServicePrincipalName,
    ResourceId,
    SignInIPs,
    FirstSeen,
    CorrelationId
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate CI/CD pipelines that authenticate a service principal for the first time in a new environment and immediately rotate credentials as part of a deployment workflow.
- Newly provisioned service principals that perform initial credential setup immediately after first authentication.
- Automated certificate rotation jobs that sign in and update key credentials on a schedule where the first observed sign-in in the lookback window precedes the rotation.

**Tuning notes:**
- Add a watchlist-based exclusion for known automation service principal IDs that legitimately rotate credentials as part of deployment pipelines.
- Extend CorrelationWindow to 2 hours if legitimate automation pipelines have startup delays longer than 30 minutes between authentication and credential operations.
- Scope OperationName to only 'Add key credentials' and 'Add password credential' operations if the environment generates high volume from legitimate 'Update application' events.

**Risks / caveats:**
- AADServicePrincipalSignInLogs requires explicit enablement in Entra ID diagnostic settings and streaming to the Log Analytics workspace. If not enabled, the join will produce zero results silently.
- AuditLogs.InitiatedBy is a dynamic JSON field; tostring(InitiatedBy.app.servicePrincipalId) will return empty string if the event was initiated by a user rather than a service principal, which is handled by the isnotempty filter.
- The OperationName values in AuditLogs vary by Entra ID operation category and may include additional suffixes; the updated list uses more specific names but should be validated against actual AuditLogs OperationName values in the target tenant.
- A 24-hour lookback means a service principal that signed in just before the lookback boundary will have its FirstSeen set to the earliest event in the window, potentially missing the true first sign-in.

### Triage Runbook

**First 15 minutes:**
- Confirm the SPId and ServicePrincipalName belong to a legitimate application and identify the business owner immediately.
- Review OperationName and ResourceId to determine whether the action was adding, removing, or updating key/password credentials.
- Check FirstSeen, TimeGenerated, and SignInIPs to see whether the credential operation followed a new or unusual sign-in pattern.
- Look for concurrent changes to the same service principal, such as role assignments, app updates, or owner changes.
- Verify whether the operation occurred during an approved certificate rotation or deployment window.

**Evidence to collect:**
- AuditLogs entries for the same SPId covering credential changes, app updates, and role changes.
- AADServicePrincipalSignInLogs for the same ServicePrincipalId, including IPAddress, ResultType, and timestamps.
- Service principal object details, including owners, credentials, app roles, and recent modifications.
- Change management records or automation logs for certificate rotation or application deployment.
- Any related Entra ID administrative actions performed by the same identity or from the same IP.

**Pivot points:**
- AuditLogs filtered on the SPId, ResourceId, or CorrelationId to reconstruct the full change sequence.
- AADServicePrincipalSignInLogs for the ServicePrincipalId to validate source IPs and sign-in timing.
- Entra ID application and service principal inventory to identify owners and expected automation.
- Directory audit events for owner changes, app role assignments, or consent grants tied to the same app.
- Microsoft Sentinel incident timeline to correlate with other identity alerts.

**Benign explanations:**
- Planned certificate or secret rotation by a deployment pipeline.
- Initial setup of a newly provisioned service principal.
- Routine application maintenance that updates credentials as part of normal operations.

**Escalation criteria:**
- The service principal owner cannot explain the credential operation.
- The operation was not part of a documented rotation or deployment process.
- The same service principal shows unusual sign-ins, new IPs, or additional suspicious Entra ID changes.
- The action involved adding credentials rather than only removing expired ones.

**Containment actions:**
- Disable the service principal or remove suspicious credentials if the activity is unauthorized.
- Revoke active sessions or tokens associated with the service principal where possible.
- Rotate any exposed secrets or certificates and review downstream applications that depend on them.
- Preserve audit evidence before making identity changes.

**Closure criteria:**
- The activity is confirmed as an approved credential rotation or application update.
- The service principal owner validates the change and no other suspicious actions are present.
- No unauthorized sign-ins or credential additions are found in the surrounding time window.
- Any risky credentials have been removed or rotated and the application is stable.

<br/>
---
<br/>

## Detection 3: Storm-2570: Pre-Ransomware Composite Signal - Credential Dumping, Lateral Movement, and Shadow Copy Deletion

### Detection Opportunity

Sequential pre-ransomware activity including credential access, lateral movement logons, and volume shadow copy deletion on Windows endpoints

### Intelligence Context

- Microsoft Security Blog: Beyond the ransomware: Tracking Storm-2570's consistent tradecraft across deployments — [https://www.microsoft.com/en-us/security/blog/2026/09/24/beyond-ransomware-tracking-storm-2570-consistent-tradecraft-across-deployments/](https://www.microsoft.com/en-us/security/blog/2026/09/24/beyond-ransomware-tracking-storm-2570-consistent-tradecraft-across-deployments/)
  - Context: Storm-2570 operates with consistent post-compromise tooling before deploying ransomware families including Qilin, DragonForce, Anubis, and BERT. The pre-ransomware phase involves credential access, lateral movement, and destructive preparation steps. Detecting this composite sequence enables disruption before ransomware payload execution.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-2570
- ATT&CK tags: T1003, T1003.001, T1021, T1021.001, T1490
- Products: Microsoft Defender XDR
- Platforms: Windows
- Malware: Qilin, DragonForce, Anubis, BERT
- Tools: Not specified
- Search tags: Storm-2570, Microsoft Defender XDR, Windows, Qilin, DragonForce, Anubis, BERT, T1003, T1003.001, T1021, T1021.001, T1490

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1003 OS Credential Dumping/ T1003.001 LSASS Memory (high); Lateral Movement: T1021 Remote Services/ T1021.001 Remote Desktop Protocol (medium); Impact: T1490 Inhibit System Recovery (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceLogonEvents

### KQL

```kql
let TimeWindow = 4h;
let CredDump = DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where ProcessCommandLine has_any ("sekurlsa", "mimikatz", "MiniDump", "procdump")
        or (FileName =~ "comsvcs.dll" and ProcessCommandLine has "MiniDump")
        or (ProcessCommandLine has "lsass" and ProcessCommandLine has_any ("dump", "minidump", "full"))
    | summarize
        CredDumpTime = min(Timestamp),
        CredDumpProcess = take_any(FileName),
        CredDumpCommandLine = take_any(ProcessCommandLine)
        by DeviceId, AccountName;
let LateralMove = DeviceLogonEvents
    | where Timestamp > ago(24h)
    | where LogonType in (3, 10)
    | where isnotempty(RemoteIP)
    | where RemoteIP !startswith "127."
    | summarize
        LateralTime = min(Timestamp),
        LateralTargetDevice = take_any(DeviceId),
        RemoteIP = take_any(RemoteIP)
        by AccountName;
let ShadowDelete = DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where (FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete")
        or (FileName =~ "wmic.exe" and ProcessCommandLine has_all ("shadowcopy", "delete"))
        or (FileName =~ "powershell.exe" and ProcessCommandLine has_all ("Win32_ShadowCopy", "Delete"))
    | summarize
        ShadowTime = min(Timestamp),
        ShadowCommandLine = take_any(ProcessCommandLine)
        by DeviceId;
CredDump
| join kind=inner LateralMove on AccountName
| join kind=inner ShadowDelete on $left.DeviceId == $right.DeviceId
| where ShadowTime > CredDumpTime
| where ShadowTime <= CredDumpTime + TimeWindow
| project
    SourceDeviceId = DeviceId,
    AccountName,
    CredDumpTime,
    CredDumpProcess,
    CredDumpCommandLine,
    LateralTargetDevice,
    LateralTime,
    RemoteIP,
    ShadowDeviceId = DeviceId1,
    ShadowTime,
    ShadowCommandLine
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Privileged administrator accounts that perform legitimate credential management, remote administration, and backup cleanup operations within the same maintenance window.
- Endpoint management tools that invoke comsvcs.dll or reference lsass in diagnostic contexts.
- Backup software that deletes shadow copies as part of normal backup rotation on the same device where admin logons occur.

**Tuning notes:**
- Add a DeviceId exclusion list for known privileged admin jump hosts or backup servers that legitimately perform all three activity types.
- Reduce TimeWindow from 4 hours to 2 hours to increase precision in environments where the baseline lateral movement rate is high.
- Extend the credential dumping filter with additional tool names specific to the environment after reviewing historical DeviceProcessEvents for known red team or pen test tooling.
- Consider adding a minimum count threshold on LateralMove to require at least 2 distinct target devices before alerting, reducing single-hop false positives.

**Risks / caveats:**
- DeviceLogonEvents in MDE records the logon event on the destination device (the device being logged into), not the source device. Joining CredDump and LateralMove on DeviceId means the query looks for lateral movement logons received by the same device that performed credential dumping, which is the opposite of the intended lateral movement signal. This is a semantic schema misalignment that will produce incorrect results.
- DeviceNetworkEvents is listed in required_tables in the original detection but is not used in the KQL; it has been removed from the improved query.
- The AccountName-based lateral movement correlation assumes the same account name is used for credential dumping and subsequent lateral movement logons, which may not hold if the attacker uses harvested credentials belonging to a different account.
- The credential dumping keyword list is behavioral and heuristic; it will miss novel tooling that does not use these command-line patterns and may match legitimate diagnostic tools that reference these terms.

### Triage Runbook

**First 15 minutes:**
- Identify the SourceDeviceId and AccountName and determine whether they are privileged, service, or admin accounts.
- Review CredDumpCommandLine and ShadowCommandLine to confirm the activity is consistent with LSASS dumping and shadow copy deletion.
- Check LateralTargetDevice, LateralTime, and RemoteIP for evidence of remote access to other hosts using the same account.
- Assess whether the activity occurred on a jump host, admin workstation, or backup server that could explain the sequence.
- Search for additional signs of ransomware staging such as archive creation, mass file renaming, or security tool tampering.

**Evidence to collect:**
- DeviceProcessEvents for the source host, including parent process, command line, and any related credential dumping tools.
- DeviceLogonEvents for the same AccountName to identify remote logons, target devices, and source IPs.
- DeviceProcessEvents on the shadow copy deletion host to capture exact commands and timestamps.
- Any Defender XDR alerts for credential theft, suspicious logons, or ransomware behavior on the same devices.
- Recent account activity and privilege assignments for the AccountName involved in the alert.

**Pivot points:**
- DeviceProcessEvents filtered by DeviceId and AccountName to expand process ancestry and related suspicious commands.
- DeviceLogonEvents filtered by AccountName and RemoteIP to identify additional lateral movement targets.
- DeviceFileEvents and DeviceRegistryEvents for signs of ransomware staging or defense evasion on the same host.
- Identity and endpoint incident timelines in Defender XDR to correlate with other alerts.
- DeviceNetworkEvents for the source and target devices to identify remote administration traffic.

**Benign explanations:**
- Authorized administrative troubleshooting that uses remote logons and recovery cleanup tools.
- Backup or imaging software that deletes shadow copies as part of normal operations.
- Security or red-team testing that intentionally exercises credential dumping and recovery inhibition techniques.

**Escalation criteria:**
- Credential dumping is confirmed on a production endpoint.
- The same account is used for remote access to multiple hosts in a short period.
- Shadow copy deletion is confirmed and not tied to a known maintenance process.
- There are signs of encryption, mass file modification, or ransomware notes on any host.

**Containment actions:**
- Isolate the source host and any confirmed lateral movement targets immediately if compromise is suspected.
- Disable or reset the involved account if it is not a break-glass or approved admin account.
- Block remote access paths used in the incident if they are still active.
- Preserve volatile evidence and endpoint telemetry before remediation.

**Closure criteria:**
- The activity is validated as approved admin, backup, or testing activity.
- No additional hosts, accounts, or processes show related malicious behavior.
- The environment shows no evidence of encryption, shadow copy abuse beyond the approved task, or credential theft.
- The incident is documented with a clear root cause and owner confirmation.

<br/>
---
<br/>

## Detection 4: BEC: External Forwarding Rule Created After Anomalous Mailbox Operation

### Detection Opportunity

New inbox forwarding rule to an external address created in proximity to an anomalous mailbox access operation, consistent with BEC fund diversion or data exfiltration preparation

### Intelligence Context

- Rapid7: When Business Email Compromise Starts Rewriting Reality — [https://www.rapid7.com/blog/post/ve-business-email-compromise-rewriting-reality-zimbra-cve](https://www.rapid7.com/blog/post/ve-business-email-compromise-rewriting-reality-zimbra-cve)
  - Context: BEC actors breach mailboxes and silently monitor operations before diverting funds or exfiltrating sensitive assets. A key observable artifact in M365-equivalent environments is the creation of inbox forwarding rules to external addresses, which enables persistent silent monitoring and data exfiltration without repeated access.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1114, T1114.003
- Products: Zimbra Collaboration Suite
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: Zimbra Collaboration Suite, T1114, T1114.003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Collection: T1114 Email Collection/ T1114.003 Email Forwarding Rule (high); Exfiltration: T1114 Email Collection/ T1114.003 Email Forwarding Rule (medium)

### Deployment Gates

- OfficeActivity.MailItemsAccessed requires Microsoft Purview Audit Premium (formerly E5 Compliance or Microsoft 365 E5). Tenants without this license will not have MailItemsAccessed events; the query falls back to FolderBind and MessageBind which are available at lower license tiers.

**Required telemetry:**
- OfficeActivity

### KQL

```kql
let CorrelationWindow = 2h;
let LookbackPeriod = 24h;
let ForwardingRules = OfficeActivity
    | where TimeGenerated > ago(LookbackPeriod)
    | where Operation in ("New-InboxRule", "Set-InboxRule")
    | where tostring(Parameters) has_any ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
    | extend RuleParams = tostring(Parameters)
    | where RuleParams matches regex @"@(?!.*\.onmicrosoft\.com)[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
    | project RuleTime = TimeGenerated, UserId, RuleClientIP = ClientIP, RuleParams, MailboxOwnerUPN;
let MailboxAccess = OfficeActivity
    | where TimeGenerated > ago(LookbackPeriod)
    | where Operation in ("MailItemsAccessed", "FolderBind", "MessageBind")
    | summarize
        AccessIPs = make_set(ClientIP, 20),
        AccessIPCount = dcount(ClientIP),
        FirstAccess = min(TimeGenerated),
        LastAccess = max(TimeGenerated)
        by UserId;
ForwardingRules
| join kind=inner MailboxAccess on UserId
| where LastAccess < RuleTime
| where RuleTime <= LastAccess + CorrelationWindow
| where RuleClientIP !in (AccessIPs)
| project
    RuleTime,
    UserId,
    MailboxOwnerUPN,
    RuleClientIP,
    RuleParams,
    AccessIPs,
    AccessIPCount,
    FirstAccess,
    LastAccess
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Users who legitimately create forwarding rules to personal external email addresses for convenience, particularly in environments without a policy blocking external forwarding.
- IT administrators who create forwarding rules on behalf of users from a different IP than the user's normal access IP.
- Users accessing mailbox from a VPN or new network location and then creating a forwarding rule in the same session.

**Tuning notes:**
- Add a UserId exclusion list for IT administrator accounts that legitimately create forwarding rules on behalf of users.
- Extend CorrelationWindow to 6 hours for environments where users access mailbox in the morning and create rules later in the day.
- Add a secondary filter requiring AccessIPCount to be low (e.g., 1 or 2) to focus on accounts with consistent access patterns where a new IP is more anomalous.
- Consider adding a domain allowlist for known personal email providers that are permitted by policy to reduce volume from legitimate personal forwarding.

**Risks / caveats:**
- OfficeActivity.MailItemsAccessed requires Microsoft Purview Audit Premium (formerly E5 Compliance or Microsoft 365 E5). Tenants without this license will not have MailItemsAccessed events; the query falls back to FolderBind and MessageBind which are available at lower license tiers.
- OfficeActivity.Parameters is a string field containing serialized JSON or key-value pairs; the regex match on this field depends on the exact serialization format used by the M365 audit pipeline, which may vary by operation type.
- The regex pattern for external domain detection may produce false negatives if the Parameters field serializes email addresses with additional escaping or encoding.
- MailboxAccess summarization collapses all access events in the 24-hour window into a single IP set; a user who legitimately accessed from many IPs over the day will have a large AccessIPs set, reducing the chance that the rule creation IP is flagged as new.

### Triage Runbook

**First 15 minutes:**
- Confirm the UserId and MailboxOwnerUPN belong to the same person and determine whether the forwarding rule was user-approved.
- Review RuleParams to identify the external destination and whether the rule forwards, redirects, or attaches messages to another mailbox.
- Check RuleClientIP against AccessIPs to see whether the rule was created from a new or unusual source IP.
- Review FirstAccess, LastAccess, and RuleTime to confirm mailbox access preceded rule creation within the alert window.
- Look for other mailbox changes such as password resets, MFA changes, delegate additions, or suspicious sign-ins.

**Evidence to collect:**
- OfficeActivity records for the mailbox owner covering MailItemsAccessed, FolderBind, MessageBind, New-InboxRule, and Set-InboxRule.
- Sign-in logs for the user account, including IPs, device details, and authentication methods.
- The exact forwarding destination extracted from RuleParams and whether it is an external domain.
- Mailbox audit history for other rule changes, delegate access, or deletion of sent items.
- User confirmation of whether the rule was created intentionally.

**Pivot points:**
- OfficeActivity filtered by UserId and MailboxOwnerUPN to reconstruct mailbox access and rule changes.
- Entra ID sign-in logs for the same user to identify suspicious IPs or impossible travel.
- Exchange mailbox audit logs for additional rule, delegate, or permission changes.
- Message trace or mail flow logs to determine whether mail was already forwarded externally.
- Incident timeline in Sentinel to correlate with phishing, MFA fatigue, or account compromise alerts.

**Benign explanations:**
- A user intentionally configured forwarding to a personal or alternate email address.
- Help desk or IT staff created a rule on behalf of the user from a different IP.
- A user accessed mail from a VPN or new network and then created a legitimate rule.

**Escalation criteria:**
- The forwarding destination is external and the user denies creating the rule.
- The mailbox shows suspicious sign-ins, MFA prompts, or other account compromise indicators.
- The rule was created shortly after unusual mailbox access from a new IP or device.
- The rule hides, deletes, or silently forwards messages in a way consistent with BEC tradecraft.

**Containment actions:**
- Remove the malicious forwarding rule if unauthorized.
- Reset the user password and revoke active sessions if compromise is suspected.
- Enforce MFA reauthentication and review mailbox delegation settings.
- Preserve mailbox audit evidence before making changes.

**Closure criteria:**
- The user or mailbox owner confirms the rule was intentional and policy-compliant.
- No suspicious sign-ins or additional mailbox changes are found.
- The forwarding destination is approved or has been removed.
- Any account compromise indicators have been remediated and documented.

<br/>
---
<br/>

## Detection 5: MacSync Backdoor: macOS Process Making Outbound C2 Connection After Execution from Non-Standard Path

### Detection Opportunity

MacSync backdoor module on macOS establishes outbound network connections to external IPs shortly after a new binary executes from a non-standard user directory

### Intelligence Context

- Securelist: MacSync under the microscope: new delivery methods and a new payload — [https://securelist.com/macsync-new-version/121383/](https://securelist.com/macsync-new-version/121383/)
  - Context: MacSync includes a backdoor module that establishes persistence or C2 communication on macOS. The backdoor component produces network connection events correlatable with process execution from non-standard paths, which is detectable via MDE on enrolled macOS endpoints.

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
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (low); Command and Control: T1071 Application Layer Protocol (low); Command and Control: T1105 Ingress Tool Transfer (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let C2Window = 5m;
let NonStandardPaths = dynamic(["/Users/", "/tmp/", "/var/folders/", "/private/tmp/"]);
let ExcludedProcesses = dynamic(["Google Chrome", "Safari", "Firefox", "softwareupdate", "curl", "wget"]);
let NewBinaries = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where OSPlatform == "macOS"
    | where not(FileName has_any (ExcludedProcesses))
    | where FolderPath has_any (NonStandardPaths)
    | project
        ProcessStart = Timestamp,
        DeviceId,
        FileName,
        FolderPath,
        ProcessCommandLine,
        InitiatingProcessFileName;
let OutboundConns = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemotePort !in (80, 443)
    | where not(
        RemoteIP startswith "10."
        or RemoteIP startswith "192.168."
        or RemoteIP startswith "172.16."
        or RemoteIP startswith "172.17."
        or RemoteIP startswith "172.18."
        or RemoteIP startswith "172.19."
        or RemoteIP startswith "172.20."
        or RemoteIP startswith "172.21."
        or RemoteIP startswith "172.22."
        or RemoteIP startswith "172.23."
        or RemoteIP startswith "172.24."
        or RemoteIP startswith "172.25."
        or RemoteIP startswith "172.26."
        or RemoteIP startswith "172.27."
        or RemoteIP startswith "172.28."
        or RemoteIP startswith "172.29."
        or RemoteIP startswith "172.30."
        or RemoteIP startswith "172.31."
        or RemoteIP startswith "127."
    )
    | project
        ConnTime = Timestamp,
        DeviceId,
        InitiatingProcessFileName,
        RemoteIP,
        RemotePort;
NewBinaries
| join kind=inner OutboundConns on DeviceId, $left.FileName == $right.InitiatingProcessFileName
| where ConnTime > ProcessStart
| where ConnTime <= ProcessStart + C2Window
| project
    ProcessStart,
    ConnTime,
    DeviceId,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    RemoteIP,
    RemotePort
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Developer tools such as node, python, go, or rust binaries executing from user home directories and making outbound connections to package registries or build services on non-standard ports.
- Legitimate macOS applications installed to user directories such as portable apps or developer previews that phone home for licensing or updates on non-standard ports.
- Security research or penetration testing tools executing from Downloads or tmp directories.

**Tuning notes:**
- Expand ExcludedProcesses with environment-specific developer tools such as node, python3, go, cargo, or java that legitimately execute from user directories.
- Adjust C2Window from 5 minutes to 15 minutes if MacSync or similar backdoors are observed to have a delayed first beacon pattern.
- Add a SHA256 hash filter if MacSync sample hashes become available from threat intelligence to increase precision.
- Consider adding a FolderPath depth filter to exclude well-known application subdirectories within /Users/ such as /Users/*/Applications/ which may contain legitimate portable apps.

**Risks / caveats:**
- OSPlatform field availability in DeviceProcessEvents for macOS endpoints depends on MDE macOS agent version and onboarding configuration. If OSPlatform is not populated, the macOS filter will silently drop all rows.
- DeviceNetworkEvents.InitiatingProcessFileName may not always match DeviceProcessEvents.FileName exactly due to path normalization differences on macOS; the join may miss connections initiated by processes with path-qualified names.
- OSPlatform field must be confirmed as populated for macOS endpoints in the target MDE deployment before this query will return results.
- The join on FileName == InitiatingProcessFileName may miss connections where the initiating process is identified by full path rather than filename alone in DeviceNetworkEvents.

### Triage Runbook

**First 15 minutes:**
- Confirm the FileName, FolderPath, and ProcessCommandLine to determine whether the binary is user-installed, developer-related, or clearly suspicious.
- Review the RemoteIP and RemotePort to see whether the connection is to an unusual external host or a known service.
- Check whether the process is one of the excluded legitimate tools or a common developer utility running from a user directory.
- Determine whether the host is a developer workstation, test machine, or production endpoint with a history of user-installed software.
- Look for repeated connections, persistence artifacts, or follow-on process activity from the same binary.

**Evidence to collect:**
- DeviceProcessEvents for the same DeviceId to capture parent process, command line, and any subsequent executions.
- DeviceNetworkEvents for the same process and host to identify repeated destinations, ports, and timing.
- File reputation or hash information for the binary if available from endpoint telemetry or threat intel.
- User context for the host, including whether the device is used for development or software testing.
- Any persistence indicators such as launch agents, login items, cron jobs, or configuration profiles on the macOS host.

**Pivot points:**
- DeviceProcessEvents filtered by DeviceId and FileName to find repeated execution or related child processes.
- DeviceNetworkEvents filtered by DeviceId and RemoteIP to identify additional outbound connections from the same host.
- DeviceFileEvents or available macOS telemetry for file creation, modification, or quarantine status.
- Defender XDR incident timeline for related alerts on the same host or user.
- Threat intelligence or reputation lookups for the RemoteIP and binary hash if available.

**Benign explanations:**
- Developer tools or scripts executed from a user directory and connecting to build, package, or update services.
- Portable applications installed in a user profile that legitimately phone home.
- Security research, testing, or penetration testing activity on a lab Mac.

**Escalation criteria:**
- The binary is unknown, unsigned, or not expected on the host.
- The outbound connection is to a suspicious or newly observed external IP and repeats after execution.
- Persistence artifacts or additional malicious behavior are found on the host.
- The user cannot explain the binary or the activity is outside normal workstation use.

**Containment actions:**
- Isolate the macOS host if the binary appears malicious or persistence is confirmed.
- Quarantine or remove the suspicious file if endpoint controls support it.
- Block the remote IP or domain if it is confirmed malicious and still active.
- Preserve the binary and endpoint telemetry for analysis before remediation.

**Closure criteria:**
- The binary is identified as a legitimate application or developer tool and the network activity is expected.
- No persistence, credential theft, or additional suspicious processes are found.
- The remote destination is benign and consistent with the software's normal behavior.
- The host owner or administrator confirms the activity and no further action is required.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- Storm-3168: Service Principal Resource Deletion Following Reconnaissance: Do not schedule yet; validate as an analyst-led hunt first.
- Storm-2570: Pre-Ransomware Composite Signal - Credential Dumping, Lateral Movement, and Shadow Copy Deletion: Do not schedule yet; validate as an analyst-led hunt first.
- MacSync Backdoor: macOS Process Making Outbound C2 Connection After Execution from Non-Standard Path: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- Storm-3168: Service Principal Resource Deletion Following Reconnaissance: AzureActivity.ActivityStatusValue field name must be confirmed; some Sentinel workspaces surface this as ActivityStatus depending on connector version. If ActivityStatusValue is absent, the Success filter will silently drop all rows.

**Licensing / identity risk fields:**
- BEC: External Forwarding Rule Created After Anomalous Mailbox Operation: OfficeActivity.MailItemsAccessed requires Microsoft Purview Audit Premium (formerly E5 Compliance or Microsoft 365 E5). Tenants without this license will not have MailItemsAccessed events; the query falls back to FolderBind and MessageBind which are available at lower license tiers.

**Other deployment dependency:**
- MacSync Backdoor: macOS Process Making Outbound C2 Connection After Execution from Non-Standard Path: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Shared-table notes:**
- DeviceProcessEvents: shared by Storm-2570: Pre-Ransomware Composite Signal - Credential Dumping, Lateral Movement, and Shadow Copy Deletion; MacSync Backdoor: macOS Process Making Outbound C2 Connection After Execution from Non-Standard Path

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Storm-3168: Service Principal Credential Access Operations in Entra ID Audit Logs; BEC: External Forwarding Rule Created After Anomalous Mailbox Operation.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Storm-3168: Service Principal Resource Deletion Following Reconnaissance; Storm-2570: Pre-Ransomware Composite Signal - Credential Dumping, Lateral Movement, and Shadow Copy Deletion; MacSync Backdoor: macOS Process Making Outbound C2 Connection After Execution from Non-Standard Path.

### Hunting Agenda and Promotion Criteria

- Storm-3168: Service Principal Resource Deletion Following Reconnaissance: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Storm-2570: Pre-Ransomware Composite Signal - Credential Dumping, Lateral Movement, and Shadow Copy Deletion: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- MacSync Backdoor: macOS Process Making Outbound C2 Connection After Execution from Non-Standard Path: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
