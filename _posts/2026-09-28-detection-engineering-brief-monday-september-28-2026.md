---
layout: post
title: "Detection Engineering Brief - Monday, September 28, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-28
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Storm-3168
  - Azure
  - Microsoft Entra ID
  - CVE-2026-88771
  - CVE-2026-88772
  - T1190
  - Citrix NetScaler ADC
  - Citrix NetScaler Gateway
  - T1552.001
  - T1552
---

## Detection Engineering Summary

This brief produced 4 detection candidates.

1 production candidate, 1 hunting-only, 2 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: Storm-3168, Azure, Microsoft Entra ID, CVE-2026-88771, CVE-2026-88772, T1190, Citrix NetScaler ADC, Citrix NetScaler Gateway, T1552.001, T1552.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Storm-3168: Service Principal Reconnaissance Followed by Destructive Action; Storm-3168: Service Principal Credential Access Activity in Entra ID; CVE-2026-88771/88772: Anomalous External HTTP Requests to NetScaler Management Interfaces.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Storm-3168: Service Principal Bulk Azure Resource Deletion

### Detection Opportunity

A compromised service principal performed bulk resource deletion operations across multiple resource types in Azure within a short time window.

### Intelligence Context

- Microsoft Security Blog: Storm-3168: Agentic-driven cloud attacks using compromised service principals — [https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/)
  - Context: Storm-3168 used compromised service principals to perform destructive resource deletion operations in Azure as part of agentic-driven cloud attacks. Resource deletion across multiple resource types by a service principal in a short window is a high-fidelity destructive signal attributed to this actor.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-3168
- ATT&CK tags: T1552.001, T1552
- Products: Azure, Microsoft Entra ID
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: Storm-3168, Azure, Microsoft Entra ID, T1552.001, T1552

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: credential-access: T1552 Unsecured Credentials/ T1552.001 Credentials In Files (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- AzureActivity

### KQL

```kql
AzureActivity
| where TimeGenerated >= ago(1h)
| where tolower(OperationName) has "delete"
| where ActivityStatus =~ "Succeeded"
// Exclude UPN-format callers (interactive users); retain GUIDs and app display names used by service principals
| where Caller !contains "@"
| extend TimeBin = bin(TimeGenerated, 10m)
| summarize
    DeleteCount = count(),
    DistinctResourceTypes = dcount(ResourceType),
    ResourceTypeList = make_set(ResourceType, 20),
    CallerIpAddress = take_any(CallerIpAddress),
    SubscriptionId = take_any(SubscriptionId),
    ResourceGroup = take_any(ResourceGroup),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Caller, TimeBin
| where DistinctResourceTypes >= 3
| project
    FirstSeen,
    LastSeen,
    Caller,
    DeleteCount,
    DistinctResourceTypes,
    ResourceTypeList,
    CallerIpAddress,
    SubscriptionId,
    ResourceGroup
| sort by DistinctResourceTypes desc, DeleteCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate infrastructure teardown automation (e.g., CI/CD pipeline cleanup jobs) that deletes multiple resource types in a short window.
- Scheduled maintenance scripts run under a service principal identity that decommission multi-tier environments.
- Azure Deployment Scripts or Bicep/ARM cleanup operations that remove ancillary resource types as part of a deployment rollback.

**Tuning notes:**
- Raise DistinctResourceTypes threshold to 5 or higher in environments with frequent multi-resource infrastructure teardown automation.
- Add a Caller-based allowlist using a watchlist or dynamic() array to exclude known legitimate cleanup service principals.
- Narrow TimeBin to 5m for higher-precision detection of rapid bulk deletion, or widen to 30m to catch slower campaigns.
- Consider adding a minimum DeleteCount threshold (e.g., >= 5) in addition to DistinctResourceTypes to further reduce noise.

**Risks / caveats:**
- AzureActivity requires the Azure Activity connector to be enabled in Microsoft Sentinel. If the connector is not configured, the table will be empty and the rule will produce no results.
- The Caller != '@' heuristic for identifying service principals is a best-effort approximation. Managed identities and some federated workload identities may appear with display names that include '@' and would be excluded. Validate Caller field values in your environment.
- A 10-minute tumbling window may miss slow-paced deletion campaigns that spread operations across multiple bins. Consider widening to 30 minutes if threat intelligence indicates slower cadence.
- The DistinctResourceTypes >= 3 threshold requires baselining against legitimate automation in the environment before scheduling as a high-severity alert.

### Triage Runbook

**First 15 minutes:**
- Confirm the Caller identity and map it to the owning application, team, and expected automation purpose.
- Review the alert window for DeleteCount, DistinctResourceTypes, ResourceTypeList, SubscriptionId, ResourceGroup, FirstSeen, and LastSeen to understand scope and speed of deletion.
- Check whether the deletions align with a known change window, deployment rollback, or scheduled teardown job.
- Look for concurrent sign-in, token, or credential changes for the same service principal in Entra ID and any unusual CallerIpAddress or geolocation context.

**Evidence to collect:**
- AzureActivity records for the Caller covering at least 1 hour before and after the alert, including CorrelationId, ResourceType, ResourceGroup, and SubscriptionId.
- Entra ID service principal details: app registration, owners, recent credential additions/updates, and last sign-in activity.
- Change-management or CI/CD records showing whether the principal is used for infrastructure teardown or environment cleanup.
- Any related activity from the same CallerIpAddress or adjacent IPs, especially other delete, role assignment, or credential operations.

**Pivot points:**
- AzureActivity filtered on the same Caller, SubscriptionId, ResourceGroup, or CorrelationId to reconstruct the deletion sequence.
- AuditLogs for service principal credential changes, app role changes, or ownership changes tied to the same identity.
- Sign-in logs for the service principal or associated workload identity to identify source IPs and timing.
- Resource Graph or Azure portal activity history to confirm which resources were removed and whether deletion was complete or partial.

**Benign explanations:**
- Planned infrastructure teardown or environment decommissioning by a deployment pipeline.
- Rollback automation that removes multiple resource types after a failed release.
- Maintenance scripts that clean up test or ephemeral environments under a service principal.
- Azure Deployment Scripts, Bicep, or ARM cleanup operations that remove dependent resources as part of normal automation.

**Escalation criteria:**
- Deletion spans production subscriptions, shared services, or multiple resource groups without a documented change.
- The service principal has no known business owner, or the owner denies the activity.
- You find recent credential changes, unusual source IPs, or other suspicious activity preceding the deletions.
- The alert shows deletion of identity, logging, backup, or security resources, indicating destructive intent.

**Containment actions:**
- Disable or revoke the service principal credentials if the activity is not immediately validated as legitimate.
- Pause or disable the associated automation pipeline or runbook until ownership is confirmed.
- Restrict the principal’s role assignments or remove elevated permissions if compromise is suspected.
- Preserve logs and resource state before further remediation to support incident response.

**Closure criteria:**
- A documented change, pipeline, or maintenance task explains the deletions and matches the observed scope.
- The service principal owner confirms the activity and no additional suspicious actions are found.
- No evidence of unauthorized credential changes, unusual source IPs, or broader destructive behavior is present.
- Affected resources and subscriptions are accounted for, and the alert is linked to an approved change record.

<br/>
---
<br/>

## Detection 2: Storm-3168: Service Principal Reconnaissance Followed by Destructive Action

### Detection Opportunity

A compromised service principal performed high-volume Azure read/list reconnaissance operations and subsequently executed delete operations, indicating a full attack sequence consistent with Storm-3168.

### Intelligence Context

- Microsoft Security Blog: Storm-3168: Agentic-driven cloud attacks using compromised service principals — [https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/)
  - Context: Storm-3168 conducted Azure reconnaissance followed by resource deletion using compromised service principals. The compound sequence of enumeration then destruction within a session is a high-confidence behavioral indicator of this actor's agentic-driven attack pattern.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-3168
- ATT&CK tags: T1552.001, T1552
- Products: Azure, Microsoft Entra ID
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: Storm-3168, Azure, Microsoft Entra ID, T1552.001, T1552

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: credential-access: T1552 Unsecured Credentials/ T1552.001 Credentials In Files (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- AzureActivity

### KQL

```kql
let LookbackWindow = 4h;
let DestructionLookforward = 60m;
let ReconMinOps = 20;
let ReconMinTypes = 3;
let ReconPrincipals =
    AzureActivity
    | where TimeGenerated >= ago(LookbackWindow)
    | where tolower(OperationName) has_any ("list", "get", "read")
    | where ActivityStatus =~ "Succeeded"
    | where Caller !contains "@"
    | summarize
        ReconOps = count(),
        DistinctReconTypes = dcount(ResourceType),
        ReconStart = min(TimeGenerated)
        by Caller
    | where ReconOps >= ReconMinOps and DistinctReconTypes >= ReconMinTypes;
let DestructivePrincipals =
    AzureActivity
    | where TimeGenerated >= ago(LookbackWindow)
    | where tolower(OperationName) has "delete"
    | where ActivityStatus =~ "Succeeded"
    | where Caller !contains "@"
    | summarize
        DeleteOps = count(),
        DeleteStart = min(TimeGenerated),
        DeleteResourceTypes = make_set(ResourceType, 20),
        CallerIpAddress = take_any(CallerIpAddress),
        SubscriptionId = take_any(SubscriptionId)
        by Caller;
ReconPrincipals
| join kind=inner DestructivePrincipals on Caller
| where DeleteStart > ReconStart
| where DeleteStart <= ReconStart + DestructionLookforward
| extend MinutesFromReconToDelete = datetime_diff('minute', DeleteStart, ReconStart)
| project
    Caller,
    ReconStart,
    ReconOps,
    DistinctReconTypes,
    DeleteStart,
    DeleteOps,
    DeleteResourceTypes,
    MinutesFromReconToDelete,
    CallerIpAddress,
    SubscriptionId
| sort by MinutesFromReconToDelete asc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- CI/CD pipelines that enumerate resources before performing targeted cleanup as part of deployment workflows.
- Infrastructure-as-code tools (Terraform, Pulumi) that perform plan/refresh operations (read-heavy) followed by destroy operations.
- Monitoring or compliance automation that reads resource state before decommissioning non-compliant resources.
- Azure Policy remediation tasks that enumerate then delete non-compliant resources.

**Tuning notes:**
- Increase ReconMinOps to 50 or higher in environments with frequent read-heavy automation to reduce false positives.
- Add a Caller-based allowlist using a watchlist or dynamic() array to exclude known legitimate service principals such as Terraform runners or monitoring agents.
- Narrow DestructionLookforward to 30m for higher-precision detection if threat intelligence indicates rapid attack cadence.
- Consider adding a DistinctDeleteTypes filter on DestructivePrincipals to require deletion across multiple resource types, aligning with the first detection's signal.

**Risks / caveats:**
- AzureActivity requires the Azure Activity connector to be enabled in Microsoft Sentinel. If the connector is not configured, the table will be empty and the query will produce no results.
- OperationName values for read-class operations in AzureActivity do not consistently use 'list', 'get', or 'read' as substrings across all Azure resource providers. Some providers use provider-specific verb forms. Validate OperationName patterns in your environment before relying on this filter.
- The 'list/get/read' substring match on OperationName is a broad heuristic. Azure resource providers use inconsistent verb naming; some legitimate read operations may not match, and some non-read operations may contain these substrings. Validate OperationName distributions in your environment.
- Summarizing ReconPrincipals across the full 4-hour window rather than per-bin means a principal that performs moderate reads across multiple hours could cross the threshold even if no single burst occurred.

### Triage Runbook

**First 15 minutes:**
- Validate the Caller identity and confirm whether it is a known automation principal with a documented read-then-destroy workflow.
- Review ReconStart, ReconOps, DistinctReconTypes, DeleteStart, DeleteOps, and MinutesFromReconToDelete to confirm the sequence and timing.
- Check whether the reconnaissance touched sensitive subscriptions, resource groups, or resource types that would be unusual for the principal.
- Look for related Entra ID or Azure sign-in activity around ReconStart and DeleteStart to identify unusual source IPs or credential changes.

**Evidence to collect:**
- AzureActivity for the Caller across the full lookback window, including read/list/get and delete operations, ResourceTypeList, and DeleteResourceTypes.
- Service principal ownership, app registration details, and any recent credential or permission changes in Entra ID.
- Change tickets, deployment logs, or IaC pipeline runs that explain the read-heavy enumeration and subsequent deletion.
- CallerIpAddress and any correlated network or sign-in telemetry showing whether the activity came from expected infrastructure.

**Pivot points:**
- AzureActivity grouped by Caller, SubscriptionId, and ResourceGroup to map the full recon-to-delete timeline.
- AuditLogs for app credential changes, role assignments, or consent events involving the same service principal.
- Sign-in logs for the service principal to identify source IP, client app, and authentication method.
- Resource Graph or activity history to identify which resources were enumerated and which were deleted.

**Benign explanations:**
- Infrastructure-as-code tools such as Terraform or Pulumi that read state before destroying resources.
- CI/CD deployment or rollback workflows that enumerate resources before cleanup.
- Compliance or remediation automation that inventories resources and then removes non-compliant assets.
- Planned decommissioning of test or ephemeral environments by a trusted service principal.

**Escalation criteria:**
- Reconnaissance and deletion occur in a production subscription or outside an approved maintenance window.
- The principal is unknown, newly created, recently granted elevated permissions, or lacks a clear owner.
- The sequence includes unusual source IPs, credential changes, or activity across multiple subscriptions.
- The deletion targets logging, identity, backup, or security resources, or the scope is broader than expected for the principal.

**Containment actions:**
- Disable the service principal or revoke its credentials if the sequence is not validated as legitimate.
- Suspend the related automation pipeline or runbook to stop further enumeration or deletion.
- Remove excessive role assignments or temporarily restrict the principal to read-only access while investigating.
- Preserve AzureActivity and Entra ID logs before making additional changes.

**Closure criteria:**
- The sequence is explained by a documented automation or change record and matches expected scope.
- The service principal owner confirms the activity and no additional suspicious actions are identified.
- No evidence of unauthorized credential changes, abnormal source IPs, or broader destructive behavior is found.
- Deleted resources are accounted for and the incident is linked to an approved operational task.

<br/>
---
<br/>

## Detection 3: Storm-3168: Service Principal Credential Access Activity in Entra ID

### Detection Opportunity

A compromised service principal performed credential access operations in Entra ID, consistent with Storm-3168 post-compromise behavior targeting cloud identity infrastructure.

### Intelligence Context

- Microsoft Security Blog: Storm-3168: Agentic-driven cloud attacks using compromised service principals — [https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/)
  - Context: Storm-3168 performed credential access activity as part of its cloud attack chain using compromised service principals. Credential-related audit operations performed by service principals in Entra ID represent a high-value detection opportunity for this actor's post-compromise behavior.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-3168
- ATT&CK tags: T1552.001, T1552
- Products: Azure, Microsoft Entra ID
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: Storm-3168, Azure, Microsoft Entra ID, T1552.001, T1552

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: credential-access: T1552 Unsecured Credentials/ T1552.001 Credentials In Files (low)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: AuditLogs, AzureActivity before scheduling.

**Required telemetry:**
- AuditLogs, AzureActivity

### KQL

```kql
let CredentialOps = dynamic([
    "Add service principal credentials",
    "Update application",
    "Reset user password",
    "Add application",
    "Update service principal"
]);
let LookbackWindow = 2h;
let CredAccessByServicePrincipal =
    AuditLogs
    | where TimeGenerated >= ago(LookbackWindow)
    | where OperationName has_any (CredentialOps)
    | where Result =~ "Success"
    | extend InitiatedByParsed = parse_json(tostring(InitiatedBy))
    | extend
        SPId = tostring(InitiatedByParsed.app.servicePrincipalId),
        SPDisplayName = tostring(InitiatedByParsed.app.displayName),
        AppId = tostring(InitiatedByParsed.app.appId)
    | where isnotempty(SPId) or isnotempty(AppId)
    | summarize
        CredOpCount = count(),
        CredOps = make_set(OperationName, 10),
        FirstCredOpTime = min(TimeGenerated),
        SPDisplayName = take_any(SPDisplayName),
        AppId = take_any(AppId)
        by SPId;
let AzureOps =
    AzureActivity
    | where TimeGenerated >= ago(LookbackWindow)
    | where Caller !contains "@"
    | summarize
        AzureOpCount = count(),
        AzureOps = make_set(OperationName, 10),
        SubscriptionId = take_any(SubscriptionId)
        by Caller;
CredAccessByServicePrincipal
| join kind=leftouter AzureOps on $left.SPId == $right.Caller
| project
    FirstCredOpTime,
    SPId,
    SPDisplayName,
    AppId,
    CredOpCount,
    CredOps,
    AzureOpCount,
    AzureOps,
    SubscriptionId
| sort by CredOpCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate application lifecycle management automation that rotates service principal credentials on a schedule.
- DevOps pipelines that add or update application credentials as part of secret rotation workflows.
- Entra ID governance tools that update service principal properties as part of access reviews.
- Azure AD Connect or other synchronization services that update credentials as part of hybrid identity operations.

**Tuning notes:**
- Expand the CredentialOps list to include 'Remove service principal credentials' and 'Add owner to application' if credential removal or ownership changes are relevant to your threat model.
- Add a SPId or AppId-based allowlist to exclude known legitimate credential rotation service principals.
- If the AzureActivity Caller field in your environment uses display names rather than object IDs, change the join key to $left.SPDisplayName == $right.Caller.
- Consider promoting to a scheduled rule only after validating the join produces correlated results in your environment.

**Risks / caveats:**
- AuditLogs InitiatedBy is a JSON object with nested 'app' and 'user' sub-objects. Applying string contains/has_any directly to the raw field will not reliably identify service principal-initiated actions. The app.displayName, app.servicePrincipalId, or app.appId sub-fields must be extracted using parse_json() or tostring() before filtering.
- AuditLogs uses a 'Result' field with string values ('Success', 'Failure'), not a 'ResultType' field with numeric codes. Filtering on ResultType == '0' will not match records in the standard AuditLogs schema.
- The join between AuditLogs (SPName derived from InitiatedBy) and AzureActivity (Caller) assumes the service principal identifier format is consistent across both tables. In practice, AuditLogs may contain display names while AzureActivity Caller may contain object IDs or app IDs. This join may produce no results without environment-specific validation of the identifier format used in each table.
- AuditLogs requires the Microsoft Entra ID (Azure Active Directory) diagnostic settings connector to be configured and streaming to the Sentinel workspace.

### Triage Runbook

**First 15 minutes:**
- Validate the service principal identity, owner, and expected administrative role in Entra ID.
- Review the credential operations in CredOps and the timing of FirstCredOpTime to see whether they match a scheduled rotation or app maintenance task.
- Check whether the same principal also performed suspicious AzureActivity actions, especially delete or role-related operations.
- Look for recent changes to the principal’s credentials, owners, permissions, or sign-in patterns that could indicate takeover.

**Evidence to collect:**
- AuditLogs entries for the same SPId or AppId, including OperationName, Result, CorrelationId, and AdditionalDetails.
- Entra ID app registration and service principal configuration, including owners, secrets, certificates, and recent modifications.
- AzureActivity records tied to the same principal to identify whether credential activity was followed by destructive or privilege-related actions.
- Sign-in logs and any workload identity logs showing source IP, client app, and authentication method for the principal.

**Pivot points:**
- AuditLogs filtered on SPId, AppId, or SPDisplayName to reconstruct all credential and ownership changes.
- AzureActivity filtered on the same Caller or related SubscriptionId to identify follow-on cloud actions.
- Entra ID directory audit and sign-in logs for the principal and its owners.
- Change-management or secret-rotation records to confirm whether the credential activity was expected.

**Benign explanations:**
- Scheduled secret or certificate rotation for an application or service principal.
- DevOps automation that updates application credentials during deployment.
- Identity governance tooling that updates service principal properties as part of maintenance.
- Hybrid identity or synchronization processes that legitimately modify application-related credentials.

**Escalation criteria:**
- Credential changes were not approved, not documented, or were performed by an unexpected principal.
- The service principal is newly modified, recently granted elevated permissions, or has unknown ownership.
- You find correlated destructive AzureActivity or privilege escalation activity after the credential operations.
- The activity involves production applications, privileged identities, or multiple credential changes in a short period.

**Containment actions:**
- Disable or revoke the service principal credentials if the activity is not clearly authorized.
- Remove suspicious secrets, certificates, or ownership changes and rotate legitimate credentials.
- Suspend related automation or deployment pipelines until the identity is validated.
- Preserve AuditLogs and AzureActivity evidence before making further changes.

**Closure criteria:**
- The credential operations are confirmed as part of an approved rotation or maintenance workflow.
- The service principal owner validates the activity and no suspicious follow-on actions are found.
- No unauthorized credential additions, ownership changes, or destructive Azure actions are present.
- The principal’s configuration is restored to an expected state and the alert is documented with a change reference.

<br/>
---
<br/>

## Detection 4: CVE-2026-88771/88772: Anomalous External HTTP Requests to NetScaler Management Interfaces

### Detection Opportunity

External IP addresses sent anomalous HTTP requests to Citrix NetScaler ADC or Gateway management interfaces prior to vendor disclosure, consistent with zero-day exploitation activity.

### Intelligence Context

- Rapid7: Zero-Day Exploitation of Citrix NetScaler ADC and Gateway: CVE-2026-88771 and CVE-2026-88772 — [https://www.rapid7.com/blog/post/etr-zero-day-exploitation-of-citrix-netscaler-adc-and-gateway-cve-2026-88771-and-cve-2026-88772](https://www.rapid7.com/blog/post/etr-zero-day-exploitation-of-citrix-netscaler-adc-and-gateway-cve-2026-88771-and-cve-2026-88772)
  - Context: CVE-2026-88771 and CVE-2026-88772 were confirmed as actively exploited zero-days against Citrix NetScaler ADC and Gateway before vendor disclosure. The exploitation involved remote code execution via HTTP requests to vulnerable appliances. No payload signatures are available, so detection relies on anomalous external access patterns to NetScaler devices as logged in CommonSecurityLog.

### Search Metadata

- CVEs: CVE-2026-88771, CVE-2026-88772
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Citrix NetScaler ADC, Citrix NetScaler Gateway
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-88771, CVE-2026-88772, T1190, Citrix NetScaler ADC, Citrix NetScaler Gateway

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: initial-access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated >= ago(24h)
| where DeviceVendor =~ "Citrix"
| where DeviceProduct has_any ("NetScaler", "ADC", "Gateway")
| where isnotempty(RequestURL) and isnotempty(SourceIP)
// Exclude RFC1918 private addresses to focus on external sources
| where not(ipv4_is_private(SourceIP))
| where RequestURL has_any ("/vpn/", "/citrix/", "/logon/", "/cgi/", "/epa/", "/nf/", "/owa/")
| extend IsErrorResponse = ResponseCode >= 400
| summarize
    RequestCount = count(),
    DistinctURLs = dcount(RequestURL),
    URLSample = make_set(RequestURL, 10),
    Methods = make_set(RequestMethod, 5),
    ResponseCodes = make_set(ResponseCode, 10),
    ErrorResponseCount = countif(IsErrorResponse),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP, DestinationPort
| where RequestCount >= 10 or DistinctURLs >= 5
| extend ErrorRate = round(todouble(ErrorResponseCount) / todouble(RequestCount) * 100, 1)
| project
    SourceIP,
    DestinationPort,
    RequestCount,
    DistinctURLs,
    ErrorResponseCount,
    ErrorRate,
    URLSample,
    Methods,
    ResponseCodes,
    FirstSeen,
    LastSeen
| sort by DistinctURLs desc, RequestCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate external load balancers or health monitoring services that probe multiple NetScaler paths at high frequency.
- Security scanners or vulnerability assessment tools run by the organization against its own NetScaler appliances.
- Web crawlers or internet scanners that enumerate common web application paths.
- Legitimate remote users accessing multiple VPN or portal paths during normal authentication flows.

**Tuning notes:**
- Update the RequestURL path list when Citrix publishes specific vulnerable endpoint paths for CVE-2026-88771 and CVE-2026-88772.
- Raise RequestCount threshold to 50 or higher and DistinctURLs to 10 or higher after baselining normal external traffic volumes against your NetScaler appliances.
- Add a SourceIP allowlist using a watchlist or dynamic() array to exclude known legitimate external health checkers, monitoring services, and partner IP ranges.
- Consider adding a filter for specific HTTP methods (e.g., POST, PUT) associated with exploitation attempts once method patterns are disclosed.

**Risks / caveats:**
- CommonSecurityLog ingestion from Citrix NetScaler requires a CEF-over-syslog connector configured on the NetScaler appliance and a Log Analytics agent or AMA syslog data collection rule in the Sentinel workspace. If this connector is not configured, the table will contain no NetScaler records.
- DeviceVendor and DeviceProduct values in CommonSecurityLog are set by the CEF header emitted by the NetScaler appliance. These values vary by NetScaler firmware version and administrator configuration. The query filters on DeviceVendor == 'Citrix' and DeviceProduct has_any ('NetScaler', 'ADC', 'Gateway'), which must be validated against actual log output before the query will return results.
- RequestURL population in CommonSecurityLog from NetScaler depends on the log profile configured on the appliance. If the NetScaler log profile does not include HTTP request URL fields, RequestURL will be empty and the query will produce no results.
- Specific vulnerable URL paths for CVE-2026-88771 and CVE-2026-88772 are not publicly disclosed. The path list used (/vpn/, /citrix/, /logon/, /cgi/, /epa/, /nf/, /owa/) is a general approximation of NetScaler management and VPN paths and may not correspond to the actual vulnerable endpoints.

### Triage Runbook

**First 15 minutes:**
- Confirm the SourceIP is external and not a known health checker, scanner, or partner network.
- Review RequestCount, DistinctURLs, ErrorResponseCount, URLSample, Methods, ResponseCodes, FirstSeen, and LastSeen to assess whether the traffic looks like probing or exploitation.
- Validate that the destination is a Citrix NetScaler ADC or Gateway appliance and identify which interface or VIP received the traffic.
- Check whether the appliance shows signs of compromise such as unexpected admin logins, configuration changes, new sessions, or service instability.

**Evidence to collect:**
- CommonSecurityLog entries for the SourceIP and DestinationPort covering the full alert window and surrounding activity.
- NetScaler appliance logs, admin audit logs, and any available system or configuration change logs.
- External exposure details for the appliance, including public IPs, VIPs, and whether management interfaces are internet-facing.
- Any correlated IDS, WAF, or firewall logs showing the same SourceIP or related scanning behavior.

**Pivot points:**
- CommonSecurityLog filtered by SourceIP, DestinationPort, RequestURL, and ResponseCode to reconstruct the request pattern.
- NetScaler syslog or admin audit logs to check for login attempts, config changes, or service restarts.
- Firewall and perimeter logs for the same SourceIP to determine whether the host is scanning other assets.
- Asset inventory or CMDB records to confirm the appliance role, ownership, and exposure status.

**Benign explanations:**
- Legitimate vulnerability scanning or security testing performed by your organization or a managed service provider.
- External health checks or monitoring services that probe multiple NetScaler paths.
- Normal user traffic to VPN or portal endpoints that happens to hit several URLs during authentication.
- Internet background noise or opportunistic scanning that does not progress beyond simple requests.

**Escalation criteria:**
- The SourceIP is not recognized and the request pattern shows repeated probing, multiple URLs, or high error rates.
- The appliance is internet-facing and there are signs of admin access, configuration changes, or service disruption.
- Requests target management or authentication paths and occur from multiple external IPs or geographies.
- You observe post-exploitation indicators such as new sessions, unexpected files, or suspicious outbound connections from the appliance.

**Containment actions:**
- If exploitation is suspected, restrict external access to the NetScaler management interface or affected VIPs.
- Block the SourceIP at the perimeter if it is clearly malicious and not a legitimate scanner.
- Place the appliance into heightened monitoring and preserve logs before rebooting or making changes.
- If compromise indicators are present, engage incident response and follow your appliance isolation procedure.

**Closure criteria:**
- The traffic is attributed to a known scanner, health checker, or approved test activity.
- No appliance compromise indicators are found in admin, system, or configuration logs.
- The SourceIP pattern is consistent with benign user or monitoring behavior and does not recur.
- Exposure and logging are validated, and any required hardening actions are tracked separately.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- Storm-3168: Service Principal Reconnaissance Followed by Destructive Action: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- Storm-3168: Service Principal Credential Access Activity in Entra ID: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: AuditLogs, AzureActivity before scheduling.
- CVE-2026-88771/88772: Anomalous External HTTP Requests to NetScaler Management Interfaces: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Shared-table notes:**
- AzureActivity: shared by Storm-3168: Service Principal Bulk Azure Resource Deletion; Storm-3168: Service Principal Reconnaissance Followed by Destructive Action; Storm-3168: Service Principal Credential Access Activity in Entra ID

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Storm-3168: Service Principal Bulk Azure Resource Deletion.
2. Resolve environment-mapping detections next: Storm-3168: Service Principal Credential Access Activity in Entra ID; CVE-2026-88771/88772: Anomalous External HTTP Requests to NetScaler Management Interfaces.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Storm-3168: Service Principal Reconnaissance Followed by Destructive Action.

### Hunting Agenda and Promotion Criteria

- Storm-3168: Service Principal Reconnaissance Followed by Destructive Action: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Storm-3168: Service Principal Credential Access Activity in Entra ID: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: AuditLogs, AzureActivity before scheduling.; prove correlation keys join correctly on real tenant telemetry.
- CVE-2026-88771/88772: Anomalous External HTTP Requests to NetScaler Management Interfaces: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
