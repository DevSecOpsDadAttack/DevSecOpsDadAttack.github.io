---
layout: post
title: "Detection Engineering Brief - Tuesday, September 29, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-29
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Storm-3168
  - service principals
  - Azure
  - NeedyMantis
  - Windows
  - CVE-2026-88771
  - CVE-2026-88772
  - T1190
  - NetScaler
  - T1485
  - T1613
  - T1547
  - T1547.001
  - T1053
  - T1053.005
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 2 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Storm-3168, service principals, Azure, NeedyMantis, Windows, CVE-2026-88771, CVE-2026-88772, T1190, NetScaler, T1485, T1613, T1547, T1547.001, T1053, T1053.005.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Storm-3168: Service Principal Bulk Resource Deletion Following Reconnaissance; Storm-3168: Service Principal Credential Access Followed by Anomalous Resource Operations; NeedyMantis: Persistence via Registry Run Key or Scheduled Task by Unsigned or Atypical Process; CVE-2026-88771 / CVE-2026-88772: Anomalous HTTP Activity Against NetScaler Management or Authentication Endpoints.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Storm-3168: Service Principal Bulk Resource Deletion Following Reconnaissance

### Detection Opportunity

Compromised service principal performs Azure resource enumeration followed by bulk resource deletion across multiple resource types

### Intelligence Context

- Microsoft Security Blog: Storm-3168: Agentic-driven cloud attacks using compromised service principals — [https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/)
  - Context: Storm-3168 used compromised service principals to perform Azure reconnaissance via enumeration of resources, then followed with destructive deletion of cloud resources across multiple resource types.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-3168
- ATT&CK tags: T1485, T1613
- Products: service principals
- Platforms: Azure
- Malware: Not specified
- Tools: Not specified
- Search tags: Storm-3168, service principals, Azure, T1485, T1613

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Impact: T1485 Data Destruction (high); Discovery: T1613 Container and Resource Discovery (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- AzureActivity

### KQL

```kql
let ReconWindow = 4h;
let DestructionWindow = 60min;
let MinReadOps = 10;
let MinResourceTypes = 3;
let ReconActivity =
    AzureActivity
    | where TimeGenerated > ago(ReconWindow)
    | where OperationName has_any ("list", "get", "read")
    | where ActivityStatusValue == "Success"
    | where Caller !has "@"
    | extend ResourceType = tostring(coalesce(split(ResourceId, "/")[6], ""))
    | where isnotempty(ResourceType)
    | summarize
        ReadOpCount = count(),
        DistinctResourceTypes = dcount(ResourceType),
        ReconStart = min(TimeGenerated),
        ReconEnd = max(TimeGenerated),
        CallerIPs = make_set(CallerIpAddress, 5),
        ResourceGroup = take_any(ResourceGroup)
      by Caller, SubscriptionId
    | where ReadOpCount >= MinReadOps and DistinctResourceTypes >= MinResourceTypes;
let DeletionActivity =
    AzureActivity
    | where TimeGenerated > ago(ReconWindow + DestructionWindow)
    | where OperationName has "delete"
    | where ActivityStatusValue == "Success"
    | where Caller !has "@"
    | summarize
        DeleteOpCount = count(),
        DeletedResources = make_set(ResourceId, 10),
        FirstDelete = min(TimeGenerated)
      by Caller, SubscriptionId;
ReconActivity
| join kind=inner DeletionActivity on Caller, SubscriptionId
| where FirstDelete between (ReconEnd .. (ReconEnd + DestructionWindow))
| project
    ReconStart,
    ReconEnd,
    FirstDelete,
    Caller,
    SubscriptionId,
    ResourceGroup,
    ReadOpCount,
    DistinctResourceTypes,
    DeleteOpCount,
    DeletedResources,
    CallerIPs
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Infrastructure-as-code pipelines (e.g., Terraform destroy) that enumerate resources before tearing down environments will match this pattern.
- Automated cost-management or cleanup service principals that scan then delete stale resources on a schedule.
- CI/CD service principals running integration tests that provision and then delete resources.

**Tuning notes:**
- Increase MinReadOps or MinResourceTypes to reduce false positives from broad-scope automation.
- Add a Caller exclusion list (e.g., known Terraform or cleanup service principal object IDs) to suppress known-good pipelines.
- Narrow DestructionWindow if environment has automation that legitimately enumerates then deletes within minutes.

**Risks / caveats:**
- ActivityStatusValue is the correct field name in AzureActivity for Sentinel-ingested logs; the original query uses this correctly, but some older workspace schemas surface ActivityStatus instead — confirm which field is populated in the target workspace before scheduling.
- The expression tostring(split(ResourceId, '/')[6]) extracts the resource type provider segment only when ResourceId follows the standard ARM path format; non-standard or short ResourceId values will produce empty strings that inflate or deflate DistinctResourceTypes counts.
- The 4-hour lookback may miss slow-burn reconnaissance that spans multiple hours before deletion; consider extending to 8h for scheduled rule runs.
- Caller field matching on absence of '@' is a heuristic; managed identity callers may also lack '@' and could appear in results.

### Triage Runbook

**First 15 minutes:**
- Validate the Caller as a service principal object ID and identify the owning application, team, and change window.
- Check whether the recon and delete activity occurred in the same subscription and whether the deleted resources span multiple resource types or resource groups.
- Review the CallerIpAddress values and compare them to known corporate egress, CI/CD runners, or automation hosts.
- Determine whether the deletions are ongoing; if yes, preserve evidence and notify cloud operations immediately.
- Look for concurrent sign-in or token activity for the same service principal around ReconEnd and FirstDelete.

**Evidence to collect:**
- Caller, SubscriptionId, ResourceGroup, ReconStart, ReconEnd, FirstDelete, ReadOpCount, DistinctResourceTypes, DeleteOpCount, DeletedResources, CallerIPs.
- AzureActivity entries for the same Caller before and after the alert window, including OperationName, ResourceId, ActivityStatusValue, and CallerIpAddress.
- Service principal ownership details, recent credential changes, and any recent role assignment or permission expansion.
- Change tickets, deployment logs, or pipeline runs that explain the enumeration and deletion sequence.
- Subscription-level activity showing whether resources were deleted from multiple resource groups or subscriptions.

**Pivot points:**
- AzureActivity filtered on Caller and SubscriptionId for 24 hours before and after the alert.
- AzureActivity filtered on DeletedResources to identify the exact resource types and sequence of deletions.
- AAD sign-in or identity logs for the service principal if available in the tenant to confirm token issuance and source IP.
- Azure role assignment and audit logs to check for recent privilege changes to the service principal.

**Benign explanations:**
- Infrastructure-as-code teardown or environment cleanup by a known deployment service principal.
- Scheduled cost-optimization or stale-resource cleanup automation.
- CI/CD test environments that enumerate resources before destroying them as part of validation.

**Escalation criteria:**
- DeletedResources include production subscriptions, shared services, identity resources, or security tooling.
- The CallerIpAddress is unfamiliar, external, or inconsistent with approved automation.
- There is no matching change ticket, pipeline run, or approved maintenance window.
- Deletion is still in progress or multiple subscriptions are affected.
- The service principal recently had credentials rotated, permissions expanded, or ownership changed unexpectedly.

**Containment actions:**
- Disable or revoke the service principal credentials if the activity is unauthorized or still active.
- Remove the service principal from privileged roles or temporarily block its access to affected subscriptions.
- Preserve AzureActivity and related identity logs before making additional changes.
- Engage cloud operations to stop any automation jobs or pipelines using the identity.

**Closure criteria:**
- A validated change record or pipeline explains the recon and deletion sequence.
- Deleted resources are confirmed to be expected and no unauthorized access indicators remain.
- The service principal is confirmed to be a known-good automation identity with matching source IPs and timing.
- Any unauthorized credentials or role assignments have been remediated and follow-up monitoring is in place.

<br/>
---
<br/>

## Detection 2: Storm-3168: Service Principal Credential Access Followed by Anomalous Resource Operations

### Detection Opportunity

Compromised service principal accesses credentials and subsequently performs operations on Azure resources from an atypical caller context

### Intelligence Context

- Microsoft Security Blog: Storm-3168: Agentic-driven cloud attacks using compromised service principals — [https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/)
  - Context: Storm-3168 accessed credentials as part of their cloud attack chain using compromised service principals, enabling follow-on resource operations within Azure.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-3168
- ATT&CK tags: T1485, T1613
- Products: service principals
- Platforms: Azure
- Malware: Not specified
- Tools: Not specified
- Search tags: Storm-3168, service principals, Azure, T1485, T1613

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Impact: T1485 Data Destruction (high); Discovery: T1613 Container and Resource Discovery (medium)

### Deployment Gates

- AADServicePrincipalSignInLogs must be explicitly enabled in Entra ID diagnostic settings and connected to the Sentinel workspace; it is not ingested by default.

**Required telemetry:**
- AADServicePrincipalSignInLogs, AzureActivity

### KQL

```kql
let LookbackWindow = 4h;
let PostAuthWindow = 2h;
let SPSignIns =
    AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(LookbackWindow)
    | where ResultType == 0
    | project
        ServicePrincipalId,
        ServicePrincipalName,
        SignInTime = TimeGenerated,
        SignInIP = IPAddress,
        CorrelationId;
let CredentialOps =
    AzureActivity
    | where TimeGenerated > ago(LookbackWindow + PostAuthWindow)
    | where OperationName has_any ("Microsoft.KeyVault/vaults/secrets", "Microsoft.KeyVault/vaults/certificates", "Microsoft.KeyVault/vaults/keys")
        or OperationName has_any ("GetSecret", "ListSecrets", "GetCertificate", "ListCertificates", "GetKey", "ListKeys")
    | where ActivityStatusValue == "Success"
    | where Caller !has "@"
    | project
        Caller,
        CredOpTime = TimeGenerated,
        OperationName,
        ResourceId,
        CallerIpAddress;
SPSignIns
| join kind=inner CredentialOps on $left.ServicePrincipalId == $right.Caller
| where CredOpTime between (SignInTime .. (SignInTime + PostAuthWindow))
| project
    SignInTime,
    CredOpTime,
    ServicePrincipalId,
    ServicePrincipalName,
    SignInIP,
    CallerIpAddress,
    OperationName,
    ResourceId,
    CorrelationId
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate service principals that authenticate and then immediately access Key Vault secrets as part of normal application startup or secret rotation workflows.
- Monitoring or secrets-management automation that polls Key Vault on a schedule following a fresh token acquisition.

**Tuning notes:**
- If Key Vault diagnostic logs are forwarded to AzureDiagnostics instead of AzureActivity, add a parallel branch querying AzureDiagnostics with ResourceType == 'MICROSOFT.KEYVAULT/VAULTS'.
- Adjust PostAuthWindow if legitimate service principal workflows have longer delays between authentication and Key Vault access.
- Add a ServicePrincipalId exclusion list for known secrets-management automation principals.

**Risks / caveats:**
- AADServicePrincipalSignInLogs must be explicitly enabled in Entra ID diagnostic settings and connected to the Sentinel workspace; it is not ingested by default.
- The join on ServicePrincipalId == Caller assumes AzureActivity Caller values for service principals are object IDs — this must be confirmed in the target workspace as the field can contain UPNs, display names, or object IDs depending on the operation type and Entra ID configuration.
- Key Vault secret and certificate operations may appear in AzureActivity under the Microsoft.KeyVault provider but the exact OperationName values vary by API version; the has_any filter on generic terms like 'secrets' and 'keys' may miss or over-match depending on the ingested log format.
- The join key equivalence (ServicePrincipalId == Caller) must be validated in the target workspace before this query will return meaningful results.

### Triage Runbook

**First 15 minutes:**
- Confirm the sign-in was successful and identify the ServicePrincipalId, SignInIP, and CorrelationId.
- Validate whether the subsequent AzureActivity operations are expected for that service principal and application.
- Compare CallerIpAddress and SignInIP to known automation, build agents, or corporate egress locations.
- Check whether the service principal recently had credentials added, rotated, or exposed in a secret store.
- Assess whether the resource operations involve sensitive resources, unusual providers, or destructive actions.

**Evidence to collect:**
- ServicePrincipalId, ServicePrincipalName, SignInTime, CredOpTime, SignInIP, CallerIpAddress, OperationName, ResourceId, CorrelationId.
- AADServicePrincipalSignInLogs entries around the sign-in time, including ResultType and any available app metadata.
- AzureActivity records for the same Caller to identify the full sequence of resource operations.
- Recent credential and role assignment changes for the service principal.
- Any associated Key Vault or secret access logs if the resource operations involve secrets, keys, or certificates.

**Pivot points:**
- AADServicePrincipalSignInLogs for the ServicePrincipalId over the prior 24 hours.
- AzureActivity for the same Caller and SubscriptionId to map all follow-on actions.
- Azure role assignment and audit logs to identify privilege changes or new app credentials.
- Key Vault-related logs if the resource operations include secret, key, or certificate access.

**Benign explanations:**
- A legitimate application startup that authenticates and immediately reads secrets or configuration.
- Secrets rotation or monitoring automation that accesses Key Vault after token acquisition.
- A scheduled deployment or maintenance job running from an approved automation host.
- A managed identity or service principal used by a platform service with expected post-auth resource access.

**Escalation criteria:**
- The sign-in source IP is unfamiliar, external, or inconsistent with the application’s normal pattern.
- The resource operations are destructive, privilege-related, or target sensitive subscriptions.
- There is no approved deployment, rotation, or maintenance activity matching the timing.
- The service principal shows recent credential changes or suspicious new permissions.
- Multiple unusual resource operations occur shortly after authentication from the same identity.

**Containment actions:**
- Revoke or disable the service principal credentials if the activity is unauthorized.
- Remove or reduce the service principal’s permissions on affected subscriptions or resource groups.
- Block the source IP or automation host if it is confirmed malicious and operationally safe to do so.
- Preserve identity and AzureActivity logs before making changes.

**Closure criteria:**
- The sign-in and follow-on operations are matched to a known-good application or maintenance workflow.
- The source IP and timing align with approved automation and no additional suspicious activity is observed.
- Any unauthorized credentials or permissions have been removed.
- Monitoring is in place for repeat sign-in followed by anomalous resource operations.

<br/>
---
<br/>

## Detection 3: Storm-3168: Service Principal Bulk Resource Deletion Across Multiple Resource Types

### Detection Opportunity

Service principal executes delete operations across multiple distinct Azure resource types within a short time window

### Intelligence Context

- Microsoft Security Blog: Storm-3168: Agentic-driven cloud attacks using compromised service principals — [https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/)
  - Context: Storm-3168 performed destructive resource deletion as part of their cloud attack chain, with service principals deleting resources across multiple types in Azure subscriptions.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-3168
- ATT&CK tags: T1485, T1613
- Products: service principals
- Platforms: Azure
- Malware: Not specified
- Tools: Not specified
- Search tags: Storm-3168, service principals, Azure, T1485, T1613

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Impact: T1485 Data Destruction (high); Discovery: T1613 Container and Resource Discovery (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- AzureActivity

### KQL

```kql
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationName has "delete"
| where ActivityStatusValue == "Success"
| where Caller !has "@"
| extend ResourceType = tostring(coalesce(split(ResourceId, "/")[6], ""))
| where isnotempty(ResourceType)
| summarize
    DeleteCount = count(),
    DistinctResourceTypes = dcount(ResourceType),
    ResourceTypeList = make_set(ResourceType, 20),
    DeletedResources = make_set(ResourceId, 20),
    CallerIPs = make_set(CallerIpAddress, 5),
    ResourceGroup = take_any(ResourceGroup),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by Caller, SubscriptionId, bin(TimeGenerated, 30m)
| where DistinctResourceTypes >= 3
| project
    FirstSeen,
    LastSeen,
    Caller,
    SubscriptionId,
    ResourceGroup,
    DeleteCount,
    DistinctResourceTypes,
    ResourceTypeList,
    DeletedResources,
    CallerIPs
| order by DeleteCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Terraform destroy or ARM template cleanup pipelines that delete multiple resource types simultaneously.
- Automated environment teardown service principals used in dev/test lifecycle management.
- Cost-optimization automation that removes unused resources across multiple types in a single run.

**Tuning notes:**
- Add a Caller exclusion list for known automation service principal object IDs that perform legitimate bulk cleanup.
- Increase DistinctResourceTypes threshold to 5 or higher if IaC pipelines routinely delete 3-4 resource types.
- Consider adding a DeleteCount >= 5 secondary threshold to further reduce noise from low-volume multi-type deletions.

**Risks / caveats:**
- ActivityStatusValue field name must be confirmed in the target workspace; some ingestion paths surface this as ActivityStatus instead.
- The split(ResourceId, '/')[6] expression extracts the resource type provider segment only for standard ARM ResourceId formats; short or non-ARM ResourceId values will produce empty strings that reduce DistinctResourceTypes accuracy.
- The 1-hour lookback window for a scheduled rule should be aligned to the rule's run frequency to avoid gaps or double-counting; set the scheduled rule frequency to 30 minutes with a 1-hour lookback.
- Managed identities also lack '@' in the Caller field and may trigger this rule if they perform broad cleanup operations.

### Triage Runbook

**First 15 minutes:**
- Review the Caller, SubscriptionId, ResourceGroup, and ResourceTypeList to understand the scope of deletion.
- Check whether the deletion burst aligns with a deployment teardown, test environment cleanup, or approved change window.
- Validate the CallerIpAddress against known automation hosts and CI/CD runners.
- Determine whether the deleted resources are production, shared, or security-critical assets.
- Assess whether deletion is still active and whether additional resource groups or subscriptions are affected.

**Evidence to collect:**
- Caller, SubscriptionId, ResourceGroup, FirstSeen, LastSeen, DeleteCount, DistinctResourceTypes, ResourceTypeList, DeletedResources, CallerIPs.
- AzureActivity entries for the same Caller showing the exact delete operations and sequence.
- Change tickets, pipeline logs, or automation run history that explain the deletions.
- Service principal ownership, role assignments, and recent credential changes.
- Any evidence of preceding reconnaissance or resource enumeration by the same Caller.

**Pivot points:**
- AzureActivity filtered on Caller and SubscriptionId for the surrounding 24 hours.
- AzureActivity filtered on DeletedResources to identify all impacted resource types and resource groups.
- Azure role assignment and audit logs for the service principal.
- If available, identity sign-in logs for the service principal to confirm source IP and token issuance.

**Benign explanations:**
- Terraform destroy or ARM/Bicep teardown of a test or ephemeral environment.
- Automated cleanup of stale resources by a known platform or cost-management identity.
- Planned decommissioning of a workload or subscription by operations staff.
- Integration test pipelines that create and then delete multiple resource types.

**Escalation criteria:**
- Production or shared resources are being deleted.
- The Caller is not a known automation identity or the source IP is unexpected.
- The deletion pattern spans multiple subscriptions or critical resource groups.
- There is no approved change record or pipeline run to justify the activity.
- Deletion continues after the alert is reviewed.

**Containment actions:**
- Disable or revoke the service principal if the activity is unauthorized or ongoing.
- Stop any associated pipeline or automation job using the identity.
- Remove the identity from privileged roles on affected subscriptions if safe to do so.
- Preserve AzureActivity and related logs for incident response.

**Closure criteria:**
- A valid change record or automation run explains the deletion activity.
- The affected resources are confirmed to be expected teardown targets.
- No further delete operations are observed from the Caller.
- Unauthorized credentials or permissions have been remediated and monitoring is enabled.

<br/>
---
<br/>

## Detection 4: NeedyMantis: Persistence via Registry Run Key or Scheduled Task by Unsigned or Atypical Process

### Detection Opportunity

Post-compromise malware establishes persistence by modifying registry run keys or creating scheduled tasks from processes not associated with known software installers

### Intelligence Context

- Microsoft Security Blog: NeedyMantis: Unpacking a post-compromise malware family used in targeted operations — [https://www.microsoft.com/en-us/security/blog/2026/09/28/needymantis-unpacking-a-post-compromise-malware-family-used-in-targeted-operations/](https://www.microsoft.com/en-us/security/blog/2026/09/28/needymantis-unpacking-a-post-compromise-malware-family-used-in-targeted-operations/)
  - Context: NeedyMantis is a post-compromise malware family that uses extensible components and custom loaders to maintain long-term access, implying persistence mechanisms such as registry run key modifications or scheduled task creation on Windows endpoints.

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
- DeviceRegistryEvents, DeviceProcessEvents

### KQL

```kql
let SuspiciousPaths = dynamic(["\\AppData\\", "\\Temp\\", "\\ProgramData\\", "\\Users\\Public\\"]);
let RunKeys = dynamic([
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
]);
let RegistryPersistence =
    DeviceRegistryEvents
    | where Timestamp > ago(7d)
    | where ActionType == "RegistryValueSet"
    | where RegistryKey has_any (RunKeys)
    | where InitiatingProcessFolderPath has_any (SuspiciousPaths)
    | project
        Timestamp,
        DeviceId,
        DeviceName,
        AccountName,
        AccountDomain,
        RegistryKey,
        RegistryValueName,
        RegistryValueData,
        InitiatingProcessFileName,
        InitiatingProcessFolderPath,
        InitiatingProcessCommandLine,
        InitiatingProcessParentFileName,
        PersistenceType = "RegistryRunKey";
let ScheduledTaskPersistence =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "schtasks.exe"
    | where ProcessCommandLine has "/create"
    | where ProcessCommandLine has_any ("/tr ", "/sc ", "/ru ")
    | where InitiatingProcessFolderPath has_any (SuspiciousPaths)
    | project
        Timestamp,
        DeviceId,
        DeviceName,
        AccountName,
        AccountDomain,
        RegistryKey = "",
        RegistryValueName = "",
        RegistryValueData = "",
        InitiatingProcessFileName,
        InitiatingProcessFolderPath,
        InitiatingProcessCommandLine = ProcessCommandLine,
        InitiatingProcessParentFileName,
        PersistenceType = "ScheduledTask";
union RegistryPersistence, ScheduledTaskPersistence
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Software installers that run from AppData or Temp directories and write run keys as part of legitimate installation (e.g., user-scoped installers, update agents).
- Package managers (npm, pip, conda) that create scheduled tasks or run key entries from user-writable paths.
- Remote management or endpoint agents that self-update from ProgramData and register persistence.
- Developer tools that register themselves in run keys from AppData paths.

**Tuning notes:**
- Build an exclusion list of known-good InitiatingProcessFileName values (e.g., Teams.exe, OneDrive.exe, update agents) after reviewing initial results.
- Consider restricting to specific DeviceGroups or high-value asset tags to reduce volume before broad deployment.
- Cross-reference hits against DeviceProcessEvents parent process chains to identify suspicious ancestry patterns specific to NeedyMantis loader behavior.

**Risks / caveats:**
- DeviceRegistryEvents.RegistryValueData is not always populated for all ActionType values in Defender for Endpoint; confirm the field is present for RegistryValueSet events in the target tenant.
- Defender XDR Advanced Hunting tables use Timestamp as the primary time field, not TimeGenerated; the original query uses TimeGenerated which will cause a schema error in Advanced Hunting context.
- No NeedyMantis-specific indicators (hashes, process names, C2 patterns) are available to anchor this detection; all matches are heuristic and require analyst triage.
- The 7-day lookback is appropriate for hunting but should be reduced to 1-2 hours if converted to a near-real-time scheduled query.

### Triage Runbook

**First 15 minutes:**
- Identify the affected device, account, and initiating process chain from the alert details.
- Check whether the initiating process is signed, expected, and launched from a known software deployment path.
- Review the registry key or scheduled task command line to confirm whether it creates persistence at logon or startup.
- Look for related process activity on the same device around the same timestamp, including downloads, script execution, or archive extraction.
- Determine whether the host is a server, workstation, or high-value asset and whether the activity is still ongoing.

**Evidence to collect:**
- Timestamp, DeviceName, DeviceId, AccountName, AccountDomain, PersistenceType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName.
- DeviceProcessEvents for the initiating process and its parent/child chain.
- DeviceRegistryEvents showing prior or subsequent registry modifications on the same device.
- File reputation, signature status, and hash details for the initiating process and any dropped files.
- Any user activity or software deployment records that explain the persistence change.

**Pivot points:**
- DeviceProcessEvents for the same DeviceId and time window to identify related execution and download activity.
- DeviceRegistryEvents for the same DeviceId to find additional persistence locations or follow-on changes.
- DeviceFileEvents if available to identify dropped payloads or installer artifacts.
- Defender XDR alerts on the same device or account for lateral movement, credential theft, or malware execution.

**Benign explanations:**
- A legitimate user-scoped installer or updater writing a run key from AppData or ProgramData.
- A package manager or developer tool creating a scheduled task as part of installation or update.
- Remote management or endpoint software self-updating and registering persistence.
- An IT deployment script running from a user-writable path in a lab or test environment.

**Escalation criteria:**
- The initiating process is unsigned, unknown, or launched from a suspicious user-writable path.
- The registry value or scheduled task launches a script, LOLBin, or encoded command.
- The device is a server, privileged workstation, or high-value endpoint.
- There are additional malware indicators such as unusual network connections, downloads, or credential access.
- No legitimate software deployment or maintenance activity explains the change.

**Containment actions:**
- Isolate the device from the network if malicious persistence is likely or confirmed.
- Terminate the suspicious process tree and quarantine associated files if supported by your workflow.
- Disable the user account if compromise is suspected and the account is not required for immediate response.
- Collect volatile evidence and preserve the registry and process artifacts before remediation.

**Closure criteria:**
- The persistence change is matched to a known-good installer, updater, or admin action.
- The initiating process is verified as legitimate and no additional suspicious activity is present.
- Any malicious files, tasks, or registry entries have been removed or reverted.
- The host is monitored for re-creation of the same persistence mechanism.

<br/>
---
<br/>

## Detection 5: CVE-2026-88771 / CVE-2026-88772: Anomalous HTTP Activity Against NetScaler Management or Authentication Endpoints

### Detection Opportunity

Exploitation attempts against NetScaler ADC or Gateway devices via anomalous HTTP requests to authentication or management endpoints, consistent with active zero-day exploitation

### Intelligence Context

- Unit 42: Threat Brief: NetScaler Zero Days CVE-2026-88771 and CVE-2026-88772 Exploited in the Wild — [https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/](https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/)
  - Context: CVE-2026-88771 and CVE-2026-88772 have been actively exploited in the wild against NetScaler devices. Unit 42 observed possible zero-day activity targeting NetScaler appliances, warranting detection of anomalous inbound HTTP activity against these devices via forwarded appliance logs.

### Search Metadata

- CVEs: CVE-2026-88771, CVE-2026-88772
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: NetScaler
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-88771, CVE-2026-88772, T1190, NetScaler

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- CommonSecurityLog requires a CEF/Syslog forwarding pipeline from the NetScaler appliance to a Sentinel-connected log forwarder; this is not a built-in Sentinel connector and must be configured manually.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor has_any ("Citrix", "NetScaler")
| where DeviceProduct has_any ("NetScaler", "ADC", "Gateway")
| where RequestURL has_any ("/vpn/", "/logon/", "/cgi/", "/nf/", "/epa/", "/citrix/", "/ns_gui/")
    or Message has_any ("exploit", "overflow", "injection", "traversal", "malformed")
| summarize
    RequestCount = count(),
    DistinctURLs = dcount(RequestURL),
    URLSamples = make_set(RequestURL, 10),
    MessageSamples = make_set(Message, 5),
    DeviceActions = make_set(DeviceAction, 5),
    DestinationPorts = make_set(DestinationPort, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by SourceIP, DeviceVendor, DeviceProduct
| where RequestCount >= 3
| order by RequestCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate health check or monitoring probes from load balancers or uptime monitoring services hitting /vpn/ or /logon/ paths.
- Penetration testing or vulnerability scanning activity against NetScaler devices.
- Legitimate users repeatedly failing authentication against /logon/ endpoints.

**Tuning notes:**
- Confirm CommonSecurityLog contains recent records from NetScaler devices by running: CommonSecurityLog → where DeviceVendor has_any ('Citrix', 'NetScaler') → summarize count() by DeviceProduct, bin(TimeGenerated, 1h) → order by TimeGenerated desc.
- Review the DeviceAction values present in your NetScaler CEF logs and adjust the DeviceActions filter if the appliance uses non-standard action strings.
- As vendor-confirmed exploit indicators for CVE-2026-88771 and CVE-2026-88772 become available, add specific URL paths or payload patterns to the RequestURL and Message filters.
- Add SourceIP exclusions for known monitoring and health-check source addresses to reduce false positives.

**Risks / caveats:**
- CommonSecurityLog requires a CEF/Syslog forwarding pipeline from the NetScaler appliance to a Sentinel-connected log forwarder; this is not a built-in Sentinel connector and must be configured manually.
- DeviceVendor and DeviceProduct field values in CommonSecurityLog depend on the CEF header emitted by the appliance; the exact strings 'Citrix', 'NetScaler', 'ADC', and 'Gateway' must match what the appliance sends — these vary by firmware version and CEF configuration.
- The extract(@'HTTP/(\d+)', 1, Message) expression extracts only the HTTP protocol version number, not the HTTP status code; this logic is incorrect and will not reliably identify 4xx/5xx responses. HTTP status codes in CEF logs typically appear in the RequestContext or AdditionalExtensions fields depending on the appliance configuration.
- RequestURL may not be populated in all NetScaler CEF log event types; some event categories log the URL in the Message field instead.

### Triage Runbook

**First 15 minutes:**
- Confirm the affected device is a NetScaler ADC or Gateway appliance and identify the source IP and request pattern.
- Review the URL samples and message samples for repeated access to management or authentication endpoints.
- Check whether the source IP belongs to a vulnerability scanner, monitoring service, or known corporate proxy.
- Determine whether the appliance is internet-facing and whether the activity is ongoing.
- Escalate immediately if the requests are concentrated, repeated, or accompanied by error or exploit-like message content.

**Evidence to collect:**
- SourceIP, DeviceVendor, DeviceProduct, RequestCount, DistinctURLs, URLSamples, MessageSamples, DeviceActions, DestinationPorts, FirstSeen, LastSeen.
- Raw CommonSecurityLog events for the same SourceIP and time window.
- NetScaler appliance logs or admin console records if available to confirm request handling and any errors.
- Asset inventory details showing whether the appliance is public-facing and what services it exposes.
- Any change or maintenance activity on the appliance during the same period.

**Pivot points:**
- CommonSecurityLog filtered on SourceIP, DeviceProduct, and the relevant URL paths over the prior 24 hours.
- CommonSecurityLog grouped by SourceIP to identify other targets or repeated attempts.
- NetScaler appliance logs or syslog/CEF records for the same time window.
- Network perimeter logs to determine whether the source IP is external and whether other hosts were targeted.

**Benign explanations:**
- Legitimate health checks or uptime monitoring hitting login or VPN endpoints.
- Authorized vulnerability scanning or penetration testing.
- Users repeatedly failing authentication against the login page.
- Routine administrative access to management endpoints from a trusted admin network.

**Escalation criteria:**
- The source IP is external, unknown, or associated with broad scanning activity.
- Requests are repeated across multiple management or authentication endpoints.
- The appliance shows errors, crashes, or unusual behavior after the requests.
- There is no approved scan, test, or maintenance activity matching the timing.
- The appliance is internet-facing and the traffic pattern is consistent with exploitation attempts.

**Containment actions:**
- Block the source IP at the perimeter if the activity is clearly malicious and blocking is operationally safe.
- Place the appliance into heightened monitoring and involve the network/security team immediately.
- Preserve appliance logs and configuration state before making changes.
- If compromise is suspected, follow the vendor incident response guidance for the appliance.

**Closure criteria:**
- The traffic is attributed to a known scanner, monitor, or approved admin activity.
- No appliance errors, crashes, or suspicious follow-on activity are observed.
- The source IP is documented and, if needed, allowlisted or blocked appropriately.
- Monitoring confirms no repeat exploitation attempts from the same source.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- Storm-3168: Service Principal Bulk Resource Deletion Following Reconnaissance: Do not schedule yet; validate as an analyst-led hunt first.
- Storm-3168: Service Principal Credential Access Followed by Anomalous Resource Operations: AADServicePrincipalSignInLogs must be explicitly enabled in Entra ID diagnostic settings and connected to the Sentinel workspace; it is not ingested by default.
- NeedyMantis: Persistence via Registry Run Key or Scheduled Task by Unsigned or Atypical Process: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- CVE-2026-88771 / CVE-2026-88772: Anomalous HTTP Activity Against NetScaler Management or Authentication Endpoints: CommonSecurityLog requires a CEF/Syslog forwarding pipeline from the NetScaler appliance to a Sentinel-connected log forwarder; this is not a built-in Sentinel connector and must be configured manually.

**Shared-table notes:**
- AzureActivity: shared by Storm-3168: Service Principal Bulk Resource Deletion Following Reconnaissance; Storm-3168: Service Principal Credential Access Followed by Anomalous Resource Operations; Storm-3168: Service Principal Bulk Resource Deletion Across Multiple Resource Types

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Storm-3168: Service Principal Bulk Resource Deletion Across Multiple Resource Types.
2. Resolve environment-mapping detections next: Storm-3168: Service Principal Credential Access Followed by Anomalous Resource Operations; CVE-2026-88771 / CVE-2026-88772: Anomalous HTTP Activity Against NetScaler Management or Authentication Endpoints.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Storm-3168: Service Principal Bulk Resource Deletion Following Reconnaissance; NeedyMantis: Persistence via Registry Run Key or Scheduled Task by Unsigned or Atypical Process.

### Hunting Agenda and Promotion Criteria

- Storm-3168: Service Principal Bulk Resource Deletion Following Reconnaissance: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- NeedyMantis: Persistence via Registry Run Key or Scheduled Task by Unsigned or Atypical Process: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Storm-3168: Service Principal Credential Access Followed by Anomalous Resource Operations: AADServicePrincipalSignInLogs must be explicitly enabled in Entra ID diagnostic settings and connected to the Sentinel workspace; it is not ingested by default.; prove correlation keys join correctly on real tenant telemetry.
- CVE-2026-88771 / CVE-2026-88772: Anomalous HTTP Activity Against NetScaler Management or Authentication Endpoints: CommonSecurityLog requires a CEF/Syslog forwarding pipeline from the NetScaler appliance to a Sentinel-connected log forwarder; this is not a built-in Sentinel connector and must be configured manually.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
