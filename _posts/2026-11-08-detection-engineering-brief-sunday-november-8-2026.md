---
layout: post
title: "Detection Engineering Brief - Sunday, November 8, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-11-08
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - GitHub
  - cloud identity
  - ARTEX
  - Storm-3358
  - T1190
  - Metasploit
  - T1528
  - T1078.004
  - T1485
  - T1078
  - T1098.003
  - T1098
  - T1566.002
  - T1656
  - T1566
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 2 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: GitHub, cloud identity, ARTEX, Storm-3358, T1190, Metasploit, T1528, T1078.004, T1485, T1078, T1098.003, T1098, T1566.002, T1656, T1566.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Compromised OAuth App Performing Authenticated Tenant Actions After Token Grant; Agentic Service Principal Performing Bulk Tenant Operations After OAuth Token Issuance; Spoofed Business-Service Sender Domain Bypassing Email Authentication Controls; Unauthenticated RCE Exploit Attempt Against Network Perimeter Device Management Interfaces.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Compromised OAuth App Performing Authenticated Tenant Actions After Token Grant

### Detection Opportunity

Compromised OAuth application used to perform authenticated actions within a victim tenant following secret exposure on GitHub

### Intelligence Context

- Microsoft Security Blog: Threat actors use agentic AI tooling to find and expose exposed secrets — [https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/](https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/)
  - Context: ARTEX was observed searching GitHub for exposed OAuth application secrets, then using those secrets to authenticate as the OAuth application and perform actions within the victim tenant. Detection targets the post-compromise authenticated action phase.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1528, T1078.004, T1485, T1078
- Products: GitHub
- Platforms: cloud identity
- Malware: Not specified
- Tools: ARTEX
- Search tags: GitHub, cloud identity, ARTEX, T1528, T1078.004, T1485, T1078

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1528 Steal Application Access Token (high); Execution: T1078 Valid Accounts/ T1078.004 Cloud Accounts (medium); Impact: T1485 Data Destruction (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- AuditLogs

### KQL

```kql
let TokenGrants = AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName in ("Add OAuth2PermissionGrant", "Consent to application", "Add service principal")
| where Result == "success"
| extend AppId = tostring(TargetResources[0].id)
| extend AppDisplayName = tostring(TargetResources[0].displayName)
| extend GrantIP = tostring(InitiatedBy.user.ipAddress)
| extend GrantorUPN = tostring(InitiatedBy.user.userPrincipalName)
| where isnotempty(AppId)
| project GrantTime = TimeGenerated, AppId, AppDisplayName, GrantIP, GrantorUPN, GrantCorrelationId = CorrelationId;
let SensitiveOps = AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName in (
    "Add member to role",
    "Update application",
    "Add owner to application",
    "Set federation settings on domain",
    "Add delegated permission grant",
    "Add service principal credentials"
  )
| where Result == "success"
| where isnotempty(InitiatedBy.app.appId)
| extend ActorAppId = tostring(InitiatedBy.app.appId)
| extend ActorAppDisplayName = tostring(InitiatedBy.app.displayName)
| project OpTime = TimeGenerated, ActorAppId, ActorAppDisplayName, OperationName, OpCorrelationId = CorrelationId;
TokenGrants
| join kind=inner SensitiveOps on $left.AppId == $right.ActorAppId
| where OpTime between (GrantTime .. (GrantTime + 2h))
| project
    GrantTime,
    OpTime,
    AppId,
    AppDisplayName,
    GrantIP,
    GrantorUPN,
    OperationName,
    ActorAppDisplayName,
    GrantCorrelationId,
    OpCorrelationId
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate OAuth application deployments followed by administrative configuration of the same app.
- Automated provisioning pipelines that grant permissions and immediately perform directory operations.
- Admin activity from a different network path than the consent event due to NAT or VPN split tunneling.

**Tuning notes:**
- Validate that TargetResources[0].id in grant events matches the value in InitiatedBy.app.appId in operation events for at least one known OAuth app before scheduling.
- Consider extending the lookback window to 7 days for hunting runs to capture slower post-compromise activity.
- Add a dynamic allowlist of known internal automation service principal IDs to suppress recurring false positives.

**Risks / caveats:**
- TargetResources[0].id in grant events surfaces the target object ID, which may be the service principal object ID rather than the application appId. InitiatedBy.app.appId in operation events surfaces the application appId. These two identifiers are not the same field type and the join may produce zero results if the schema does not align in the connected tenant.
- InitiatedBy.app.ipAddress is not a documented standard field in the Entra ID AuditLogs schema; service-principal-initiated operations typically do not carry a source IP in this path, which may cause OpIP to be empty for all service principal actions.
- The join on AppId (object ID from TargetResources) versus ActorAppId (appId from InitiatedBy.app.appId) may not match in all tenants; validate field values against known OAuth app events before relying on this correlation.
- The 2-hour window may miss slow-burn post-compromise activity; adjust based on observed attacker dwell patterns.

### Triage Runbook

**First 15 minutes:**
- Validate the AppId, GrantCorrelationId, and OpCorrelationId to confirm the grant event and the subsequent sensitive operation belong to the same service principal.
- Check whether the GrantorUPN and GrantIP are expected for your tenant automation or whether they indicate an unusual user, location, or consent path.
- Review the OperationName sequence for high-risk actions such as role assignment, credential addition, federation changes, or application ownership changes.
- Identify whether the app is a known internal automation app; if not, treat as likely compromise and notify identity administrators immediately.

**Evidence to collect:**
- AuditLogs entries for the grant event and the follow-on operation, including TimeGenerated, OperationName, Result, InitiatedBy, TargetResources, and CorrelationId.
- The service principal display name, AppId, and any related consent or credential changes around the same time window.
- Any sign-in or audit context showing who approved the grant and whether the app was recently created or modified.
- A short timeline of all operations performed by the app in the 2-hour window after the grant.

**Pivot points:**
- AuditLogs filtered on the AppId, GrantCorrelationId, and OpCorrelationId to enumerate all related operations.
- AuditLogs for additional operations by the same service principal in the prior and subsequent 24 hours.
- If available, Entra ID sign-in and consent records for the GrantorUPN to determine whether the grant was user-driven or automated.
- Tenant admin activity around the same time for role assignments, credential additions, or federation changes.

**Benign explanations:**
- A legitimate OAuth application deployment followed by normal post-install configuration.
- An internal automation service principal performing expected administrative tasks after a planned grant.
- A different network path for the grantor and the app operation due to NAT, VPN, or split tunneling.

**Escalation criteria:**
- The app is unknown, unapproved, or not on the internal automation allowlist.
- The follow-on action includes role assignment, credential addition, federation modification, or ownership changes.
- The grantor account or app activity is inconsistent with approved change management or occurs outside a maintenance window.
- Multiple sensitive operations occur in a short period or the app continues operating after the initial alert.

**Containment actions:**
- Revoke the OAuth grant or disable the service principal if the app is not recognized or cannot be quickly validated.
- Remove newly added credentials, owners, or role assignments associated with the app.
- Block or disable the consenting user account if the grant appears malicious and the account is still active.
- Preserve audit evidence before making changes, especially if the app is used for broader tenant access.

**Closure criteria:**
- The app is confirmed as approved internal automation and the observed operations match documented change activity.
- No additional suspicious operations are found in the surrounding time window.
- Any unauthorized grant, credential, or role change has been removed and the service principal is no longer active.
- Identity administrators have validated the event as benign and documented the approval source.

<br/>
---
<br/>

## Detection 2: Agentic Service Principal Performing Bulk Tenant Operations After OAuth Token Issuance

### Detection Opportunity

AI agents operating on behalf of threat actors using compromised OAuth applications to execute automated bulk actions within victim organizations

### Intelligence Context

- Microsoft Security Blog: Threat actors use agentic AI tooling to find and expose exposed secrets — [https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-AI-tooling-to-find-and-abuse-exposed-secrets/](https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-AI-tooling-to-find-and-abuse-exposed-secrets/)
  - Context: ARTEX agents operated autonomously on behalf of threat actors using compromised OAuth applications, performing authenticated actions at machine speed within victim tenants. Detection targets high-frequency service principal operations in AzureActivity correlated with a preceding OAuth grant event.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1528, T1078.004, T1485, T1078
- Products: GitHub
- Platforms: cloud identity
- Malware: Not specified
- Tools: ARTEX
- Search tags: GitHub, cloud identity, ARTEX, T1528, T1078.004, T1485, T1078

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1528 Steal Application Access Token (high); Execution: T1078 Valid Accounts/ T1078.004 Cloud Accounts (medium); Impact: T1485 Data Destruction (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- AuditLogs, AzureActivity

### KQL

```kql
let NewGrants = AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName in ("Add OAuth2PermissionGrant", "Consent to application", "Add service principal")
| where Result == "success"
| extend SPId = tostring(TargetResources[0].id)
| extend SPDisplayName = tostring(TargetResources[0].displayName)
| where isnotempty(SPId)
| project GrantTime = TimeGenerated, SPId, SPDisplayName;
let AgentActivity = AzureActivity
| where TimeGenerated > ago(1d)
| where ActivityStatusValue == "Success"
| where isnotempty(CallerIpAddress)
| where isnotempty(Caller)
| summarize
    OpCount = count(),
    DistinctOpTypes = dcount(OperationNameValue),
    Operations = make_set(OperationNameValue, 20),
    IPAddresses = make_set(CallerIpAddress, 10)
    by Caller, bin(TimeGenerated, 10m)
| where OpCount > 30 and DistinctOpTypes > 1
| project WindowStart = TimeGenerated, Caller, OpCount, DistinctOpTypes, Operations, IPAddresses;
NewGrants
| join kind=inner AgentActivity on $left.SPId == $right.Caller
| where WindowStart between (GrantTime .. (GrantTime + 4h))
| project
    GrantTime,
    WindowStart,
    SPId,
    SPDisplayName,
    OpCount,
    DistinctOpTypes,
    Operations,
    IPAddresses
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate CI/CD pipelines and infrastructure-as-code deployments that perform high-frequency Azure resource operations.
- Backup, monitoring, or compliance automation service principals that operate in bursts.
- Newly provisioned automation accounts that receive a grant and immediately begin scheduled work.

**Tuning notes:**
- Validate the Caller field format in AzureActivity for known service principals against the object IDs in AuditLogs TargetResources before scheduling.
- Baseline OpCount and DistinctOpTypes thresholds against known automation pipelines over a 7-day period before converting to a scheduled rule.
- Consider adding a ResourceGroup or SubscriptionId filter to scope the detection to sensitive subscriptions.

**Risks / caveats:**
- AzureActivity.Caller is populated with the service principal object ID for non-human callers in some resource providers, but with the appId or display name in others. The join on TargetResources[0].id (object ID) versus Caller may fail to match depending on how the resource provider records the caller identity.
- AzureActivity.ActivityStatusValue field name varies by workspace configuration; some environments use ActivityStatus instead. Verify the correct field name in the connected workspace.
- The join key alignment between AuditLogs TargetResources[0].id and AzureActivity Caller must be validated in the target environment before this query produces meaningful results.
- The 30-operation / 10-minute threshold requires baselining against legitimate automation workloads to avoid alert fatigue.

### Triage Runbook

**First 15 minutes:**
- Confirm the service principal identity, GrantTime, WindowStart, OpCount, and DistinctOpTypes to verify the activity is both post-grant and unusually high volume.
- Review the Operations list to determine whether the actions are administrative, destructive, or consistent with a known automation workflow.
- Check whether the SPId is on an approved automation allowlist and whether the activity occurred in a sanctioned subscription or resource group.
- If the service principal is unknown or the operations are high-risk, escalate immediately to cloud identity and platform owners.

**Evidence to collect:**
- AuditLogs grant event details for the service principal, including the consenting user and grant time.
- AzureActivity records for the same SPId, including OperationNameValue, CallerIpAddress, and the full set of operations in the 10-minute window.
- SubscriptionId, ResourceGroup, and any affected resource names to scope impact.
- A timeline of distinct operation types and whether the activity is continuing after the alert.

**Pivot points:**
- AzureActivity filtered on the SPId and a wider time range to identify all related operations and affected resources.
- AuditLogs for any additional grants, credential additions, or owner changes tied to the same service principal.
- Resource-specific activity logs for the impacted subscription or resource group to determine whether changes were successful or rolled back.
- If available, identity logs for the user who granted the app permissions.

**Benign explanations:**
- A legitimate CI/CD or infrastructure-as-code pipeline performing bursty resource changes.
- Backup, monitoring, or compliance automation that runs in scheduled batches.
- A newly provisioned automation account beginning its first scheduled job after a planned grant.

**Escalation criteria:**
- The service principal is not recognized or is not on the approved automation list.
- The operations include deletion, permission changes, credential changes, or broad resource modification across multiple resource groups.
- The activity spans multiple distinct operation types and continues beyond the initial 10-minute burst.
- There is evidence of unauthorized grant, unexpected source IPs, or activity in sensitive subscriptions.

**Containment actions:**
- Disable or revoke the service principal if the activity is not approved or cannot be quickly validated.
- Pause or stop the automation pipeline if it is the source of the activity and may be compromised.
- Restrict the service principal’s permissions or remove recently added role assignments if abuse is confirmed.
- Preserve AzureActivity and AuditLogs evidence before making changes.

**Closure criteria:**
- The service principal is confirmed as approved automation and the operation set matches documented behavior.
- The burst of activity is explained by a known deployment, migration, or maintenance task.
- No further suspicious operations occur after validation or containment.
- Any unauthorized permissions or resource changes have been remediated and documented.

<br/>
---
<br/>

## Detection 3: Storm-3358 ARTEX Pattern: Anomalous OAuth App Grant Followed by Privileged Resource Access

### Detection Opportunity

Financially motivated targeting of organizations using ARTEX-driven OAuth application abuse, inferred from anomalous OAuth grants and subsequent privileged resource access

### Intelligence Context

- Microsoft Security Blog: ARTEX abuse expands as cybercriminals target financial sector — [https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/](https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/)
  - Context: Storm-3358 was observed using ARTEX to target financial-sector organizations. The attack pattern relies on OAuth application abuse consistent with ARTEX tooling. Detection surfaces anomalous OAuth grants from new or external IPs followed by privileged directory or resource operations, which is the behavioral fingerprint of this campaign.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-3358
- ATT&CK tags: T1528, T1098.003, T1098
- Products: GitHub
- Platforms: cloud identity
- Malware: Not specified
- Tools: ARTEX
- Search tags: Storm-3358, ARTEX, GitHub, cloud identity, T1528, T1098.003, T1098

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1528 Steal Application Access Token (high); Persistence: T1098 Account Manipulation/ T1098.003 Additional Cloud Roles (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- AuditLogs, SigninLogs

### KQL

```kql
let LookbackDays = 30;
let KnownIPs = SigninLogs
| where TimeGenerated > ago(LookbackDays * 1d)
| where ResultType == 0
| summarize by IPAddress;
let SuspectGrants = AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName in (
    "Add OAuth2PermissionGrant",
    "Consent to application",
    "Add app role assignment to service principal"
  )
| where Result == "success"
| extend GrantorIP = tostring(InitiatedBy.user.ipAddress)
| extend GrantorUPN = tostring(InitiatedBy.user.userPrincipalName)
| where isnotempty(GrantorIP)
| where GrantorIP !in (KnownIPs)
| extend TargetAppId = tostring(TargetResources[0].id)
| extend TargetAppDisplayName = tostring(TargetResources[0].displayName)
| project
    GrantTime = TimeGenerated,
    GrantorIP,
    GrantorUPN,
    TargetAppId,
    TargetAppDisplayName,
    GrantOp = OperationName,
    GrantCorrelationId = CorrelationId;
let PrivOps = AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName in (
    "Add member to role",
    "Add owner to application",
    "Update application – Certificates and secrets management",
    "Add service principal credentials",
    "Set federation settings on domain"
  )
| where Result == "success"
| where isnotempty(InitiatedBy.app.appId)
| extend ActorId = tostring(InitiatedBy.app.appId)
| extend ActorDisplayName = tostring(InitiatedBy.app.displayName)
| project
    OpTime = TimeGenerated,
    ActorId,
    ActorDisplayName,
    PrivOp = OperationName,
    OpCorrelationId = CorrelationId;
SuspectGrants
| join kind=inner PrivOps on $left.TargetAppId == $right.ActorId
| where OpTime between (GrantTime .. (GrantTime + 6h))
| summarize
    PrivOps = make_set(PrivOp, 10),
    OpTimes = make_set(OpTime, 10),
    OpCorrelationIds = make_set(OpCorrelationId, 10)
    by
    GrantTime,
    TargetAppId,
    TargetAppDisplayName,
    GrantorIP,
    GrantorUPN,
    GrantOp,
    GrantCorrelationId
| project
    GrantTime,
    TargetAppId,
    TargetAppDisplayName,
    GrantorIP,
    GrantorUPN,
    GrantOp,
    PrivOps,
    OpTimes,
    GrantCorrelationId,
    OpCorrelationIds
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrators consenting to new OAuth applications from a new office location, travel IP, or VPN exit node not previously seen in SigninLogs.
- Automated provisioning workflows that use a service account signing in from a new IP range during infrastructure changes.
- New tenant onboarding where the first admin sign-in and OAuth app setup occur from an IP not yet in the baseline.

**Tuning notes:**
- Extend LookbackDays to 60 or 90 in environments with highly stable admin IP ranges to reduce false positives from infrequent but legitimate admin IPs.
- Add a dynamic exclusion list of known break-glass account UPNs or admin service account UPNs that operate from dynamic IPs.
- Validate the TargetAppId-to-ActorId join alignment against at least one known OAuth app provisioning event before enabling as a scheduled rule.

**Risks / caveats:**
- InitiatedBy.user.ipAddress is populated only for human-initiated grant events. Service-principal-initiated grants will have an empty GrantorIP, causing those events to be filtered out by the isnotempty(GrantorIP) filter. This is by design for this detection but means machine-initiated grants from new IPs are not covered.
- InitiatedBy.app.appId in PrivOps events is populated only when the operation is performed by a service principal. User-initiated privileged operations will not match the join and will be missed.
- The 30-day SigninLogs baseline will not include IPs used exclusively for non-interactive or service principal sign-ins; legitimate admin IPs that only appear in non-interactive logs will be flagged.
- The TargetAppId join key (object ID from TargetResources) versus ActorId (appId from InitiatedBy.app.appId) may not match in all tenants; validate against known OAuth app events.

### Triage Runbook

**First 15 minutes:**
- Validate the GrantorUPN, GrantorIP, TargetAppId, and PrivOp sequence to confirm the grant and privileged operation are linked.
- Check whether the GrantorIP is new or unusual for the consenting user and whether the app is known or approved.
- Review the privileged operations for role assignment, owner changes, credential additions, or federation changes.
- If the app or grantor is not recognized, treat as likely malicious and escalate to identity response.

**Evidence to collect:**
- AuditLogs grant event details, including the consenting user, source IP, target app, and correlation ID.
- AuditLogs privileged operation details, including the actor app, operation name, and timing relative to the grant.
- SigninLogs history for the GrantorUPN to determine whether the IP is novel or associated with travel, VPN, or automation.
- Any related changes to app credentials, owners, or directory roles within the same time window.

**Pivot points:**
- AuditLogs for all events involving the TargetAppId or ActorId across the prior and subsequent 24 hours.
- SigninLogs for the GrantorUPN and GrantorIP to establish whether the location is expected.
- AuditLogs for role assignments, application updates, and service principal credential changes tied to the same app.
- If available, mailbox or collaboration logs for signs of follow-on phishing or lateral movement from the consenting account.

**Benign explanations:**
- A legitimate administrator consenting to a new application from a new office, travel, or VPN IP.
- A planned provisioning workflow that grants an app and then performs expected configuration steps.
- A new tenant or new admin baseline where the first observed IP has not yet been learned.

**Escalation criteria:**
- The app is unapproved, unknown, or associated with a suspicious consent request.
- The privileged operation is a role assignment, credential addition, or ownership change.
- The consenting user or source IP is not expected and there is no approved change record.
- Multiple privileged operations occur after the grant or the app continues to act after the alert.

**Containment actions:**
- Revoke the OAuth grant and disable the service principal if malicious activity is suspected.
- Reset or disable the consenting user account if compromise is suspected and the account is still active.
- Remove any unauthorized role assignments, owners, or credentials added by the app.
- Preserve audit evidence before revocation if the incident may require broader investigation.

**Closure criteria:**
- The app and grantor are confirmed as approved and the privileged operations match a documented change.
- No additional suspicious activity is found for the app or user in the surrounding time window.
- Any unauthorized grant or privilege change has been removed.
- The incident is documented with the approved business justification and source IP explanation.

<br/>
---
<br/>

## Detection 4: Spoofed Business-Service Sender Domain Bypassing Email Authentication Controls

### Detection Opportunity

Phishing emails spoofing familiar business-service sender domains with failed SPF, DKIM, or DMARC authentication delivered to recipient inboxes

### Intelligence Context

- Microsoft Security Blog: Email threat landscape: Q3 2026 trends and insights — [https://www.microsoft.com/en-us/security/blog/2026/11/05/email-threat-landscape-q3-2026-trends-and-insights/](https://www.microsoft.com/en-us/security/blog/2026/11/05/email-threat-landscape-q3-2026-trends-and-insights/)
  - Context: Q3 2026 reporting identified a sharp rise in phishing emails spoofing familiar business-service sender domains. These messages were observed reaching inboxes despite failing email authentication checks, indicating either misconfigured DMARC enforcement or deliberate override abuse.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1566.002, T1656, T1566
- Products: Not specified
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: T1566.002, T1656, T1566

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1566 Phishing/ T1566.002 Spearphishing Link (low); Defense Evasion: T1656 Impersonation (high)

### Deployment Gates

- EmailEvents is available only with Microsoft Defender for Office 365 Plan 1 or Plan 2 licensing. Environments without this license cannot use this detection.

**Required telemetry:**
- EmailEvents

### KQL

```kql
let BusinessServiceKeywords = dynamic(["docusign", "sharepoint", "onedrive", "dropbox", "adobe", "zoom", "teams", "salesforce", "servicenow", "workday", "paypal", "microsoft", "google"]);
EmailEvents
| where Timestamp > ago(1d)
| where DeliveryAction == "Delivered"
| where isnotempty(AuthenticationDetails)
| extend AuthParsed = todynamic(AuthenticationDetails)
| extend SpfVerdict = tostring(AuthParsed.SPF)
| extend DkimVerdict = tostring(AuthParsed.DKIM)
| extend DmarcVerdict = tostring(AuthParsed.DMARC)
| where SpfVerdict =~ "Fail" or DkimVerdict =~ "Fail" or DmarcVerdict =~ "Fail"
| extend SenderDomainLower = tolower(SenderMailFromDomain)
| where SenderDomainLower has_any (BusinessServiceKeywords)
| project
    Timestamp,
    SenderFromAddress,
    SenderMailFromDomain,
    RecipientEmailAddress,
    Subject,
    DeliveryAction,
    SpfVerdict,
    DkimVerdict,
    DmarcVerdict,
    SenderIPv4,
    NetworkMessageId
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate business service providers with misconfigured SPF or DKIM records whose mail is delivered despite authentication failures.
- Forwarded mail from third-party services that breaks DKIM alignment.
- Marketing or transactional mail from business services sent through third-party ESPs that fail DMARC alignment.

**Tuning notes:**
- Validate the AuthenticationDetails JSON structure in EmailEvents for the connected tenant to confirm the SPF, DKIM, and DMARC key names before scheduling.
- Add a dynamic exclusion list of confirmed legitimate external sender domains that are known to have authentication misconfigurations.
- Consider requiring both a keyword match and at least two authentication failures to reduce noise from misconfigured but benign senders.

**Risks / caveats:**
- OfficeActivity does not contain AuthenticationDetails or DeliveryAction fields for inbound mail in the standard Entra/Exchange audit schema. The original query targeting OfficeActivity will not produce results for the authentication-failure filter. The rewritten query requires the Microsoft 365 Defender connector and EmailEvents table ingestion into Sentinel.
- EmailEvents is available only with Microsoft Defender for Office 365 Plan 1 or Plan 2 licensing. Environments without this license cannot use this detection.
- The AuthenticationDetails field structure in EmailEvents may vary; validate that todynamic() correctly parses the SPF, DKIM, and DMARC keys in the connected tenant before scheduling.
- The BusinessServiceKeywords list will match substrings in sender domains, which may produce false positives for domains that legitimately contain these strings as part of a different brand name.

### Triage Runbook

**First 15 minutes:**
- Review the sender domain, sender address, subject, and recipient list to determine whether the message impersonates a known service or vendor.
- Check the authentication verdicts to see whether one or more controls failed and whether the message was still delivered.
- Assess whether the sender domain is a known partner or a common business service used in your environment.
- If the message is clearly impersonating a trusted brand or contains suspicious content, escalate to email security response.

**Evidence to collect:**
- EmailEvents details including SenderFromAddress, SenderMailFromDomain, AuthenticationDetails, DeliveryAction, Subject, RecipientEmailAddress, and SenderIPv4.
- The parsed SPF, DKIM, and DMARC verdicts and whether the message was delivered to multiple recipients.
- Any user reports, clicks, replies, or subsequent mailbox activity tied to the NetworkMessageId.
- Historical mail from the same sender domain to determine whether this is a new or recurring pattern.

**Pivot points:**
- EmailEvents for the same sender domain, sender address, or NetworkMessageId across a wider time window.
- EmailEvents for other recipients of the same message to determine campaign scope.
- If available, Defender for Office 365 or mailbox audit data for user interaction with the message.
- Tenant allowlists or transport rules to verify whether the sender is intentionally permitted despite authentication failures.

**Benign explanations:**
- A legitimate business service provider with misconfigured SPF, DKIM, or DMARC records.
- Forwarded mail that breaks DKIM alignment while still being legitimate.
- Transactional or marketing mail from a trusted vendor delivered despite authentication failures.

**Escalation criteria:**
- The sender is impersonating a high-value business service or internal brand.
- Multiple recipients received the same message and at least one user interacted with it.
- The message contains credential prompts, payment requests, or links to login pages.
- The sender domain is not a known partner and the authentication failures are accompanied by suspicious content.

**Containment actions:**
- Quarantine or purge the message if it is confirmed malicious and still present in mailboxes.
- Block the sender domain or sender address if the campaign is active and clearly malicious.
- Warn recipients who received the message and instruct them not to interact with it.
- If user interaction occurred, initiate account review for the affected recipients.

**Closure criteria:**
- The message is confirmed as a benign misconfiguration or an approved business service.
- No user interaction or follow-on malicious activity is found.
- If malicious, the message has been removed and sender blocking or mail flow controls are in place.
- The sender domain has been documented as allowlisted or blocked based on investigation outcome.

<br/>
---
<br/>

## Detection 5: Unauthenticated RCE Exploit Attempt Against Network Perimeter Device Management Interfaces

### Detection Opportunity

Unauthenticated remote code execution attempts targeting network perimeter device management ports using Metasploit exploit modules

### Intelligence Context

- Rapid7: Metasploit Wrapup: Unauth RCE modules in Network Perimeter Devices and much more — [https://www.rapid7.com/blog/post/pt-metasploit-wrapup-unauth-rce-modules-in-network-perimeter-devices-and-much-more](https://www.rapid7.com/blog/post/pt-metasploit-wrapup-unauth-rce-modules-in-network-perimeter-devices-and-much-more)
  - Context: Rapid7 published new Metasploit modules targeting unauthenticated RCE vulnerabilities in network perimeter devices. Detection targets exploit-pattern HTTP requests to perimeter device management ports from external source IPs, consistent with Metasploit module delivery patterns.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Not specified
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: T1190, Metasploit

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- CommonSecurityLog.RequestURL is not populated by all CEF/syslog sources. Firewall vendors that log only connection-level metadata (allow/deny, bytes, ports) without HTTP inspection will produce no results for the RequestURL pattern filter. Confirm that the connected device performs HTTP deep inspection and populates this field.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
let MgmtPorts = dynamic([443, 8443, 8080, 8888, 4443, 10443, 9443]);
let ExploitPatterns = dynamic(["/cgi-bin/", "/admin/", "/management/", "/api/v1/", "cmd=", "exec=", "../", "%2e%2e", ";id;", "wget+", "curl+"]);
let PrivateRanges = dynamic(["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.", "127.", "100.64.", "100.65.", "100.66.", "100.67.", "100.68.", "100.69.", "100.70.", "100.71.", "100.72.", "100.73.", "100.74.", "100.75.", "100.76.", "100.77.", "100.78.", "100.79.", "100.80.", "100.81.", "100.82.", "100.83.", "100.84.", "100.85.", "100.86.", "100.87.", "100.88.", "100.89.", "100.90.", "100.91.", "100.92.", "100.93.", "100.94.", "100.95.", "100.96.", "100.97.", "100.98.", "100.99.", "100.100.", "100.101.", "100.102.", "100.103.", "100.104.", "100.105.", "100.106.", "100.107.", "100.108.", "100.109.", "100.110.", "100.111.", "100.112.", "100.113.", "100.114.", "100.115.", "100.116.", "100.117.", "100.118.", "100.119.", "100.120.", "100.121.", "100.122.", "100.123.", "100.124.", "100.125.", "100.126.", "100.127."]);
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DestinationPort in (MgmtPorts)
| where isnotempty(SourceIP)
| where not(SourceIP has_any (PrivateRanges))
| where (isnotempty(RequestURL) and RequestURL has_any (ExploitPatterns))
    or (isnotempty(Message) and Message has_any (ExploitPatterns) and isempty(RequestURL))
| summarize
    AttemptCount = count(),
    RequestURLs = make_set(RequestURL, 20),
    Ports = make_set(DestinationPort, 10)
    by SourceIP, DestinationIP, DeviceVendor, DeviceProduct, bin(TimeGenerated, 5m)
| where AttemptCount > 5
| project
    WindowStart = TimeGenerated,
    SourceIP,
    DestinationIP,
    DeviceVendor,
    DeviceProduct,
    AttemptCount,
    Ports,
    RequestURLs
| order by AttemptCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate vulnerability scanners and penetration testing tools operated by the organization's security team.
- Web application health checks and monitoring probes that access management endpoints.
- Search engine crawlers or internet scanners that probe common management paths.

**Tuning notes:**
- Add DeviceVendor and DeviceProduct filters to restrict the query to perimeter devices confirmed to populate RequestURL with HTTP inspection data.
- Increase AttemptCount threshold based on observed legitimate scanner volume in the environment.
- Add a SourceIP exclusion list for known internal vulnerability scanners and penetration testing infrastructure.

**Risks / caveats:**
- CommonSecurityLog.RequestURL is not populated by all CEF/syslog sources. Firewall vendors that log only connection-level metadata (allow/deny, bytes, ports) without HTTP inspection will produce no results for the RequestURL pattern filter. Confirm that the connected device performs HTTP deep inspection and populates this field.
- CommonSecurityLog.Message content varies significantly by vendor and may not contain HTTP request URI strings suitable for pattern matching. The Message has_any filter may match unrelated log content.
- No specific CVE or Metasploit module signature is available from the source reporting, so the exploit pattern strings are generic path and parameter indicators that will match broad categories of web traffic, not specifically Metasploit payloads.
- The detection will produce no results if the connected perimeter device does not populate RequestURL with HTTP request content in CommonSecurityLog. Confirm HTTP inspection capability and field population before use.

### Triage Runbook

**First 15 minutes:**
- Confirm the SourceIP, DestinationIP, DestinationPort, and RequestURL to verify the traffic is external and aimed at a management interface.
- Check whether the device vendor and product are expected to expose that port and whether the request pattern matches known management paths or exploit strings.
- Determine whether the source is a known internal scanner, security test, or external internet host.
- If the traffic is repeated, targeted, or accompanied by signs of device instability, escalate to network operations and incident response.

**Evidence to collect:**
- CommonSecurityLog entries for the SourceIP, DestinationIP, ports, RequestURLs, and Message content around the alert time.
- DeviceVendor and DeviceProduct to identify the perimeter appliance and confirm whether it is internet-facing.
- Any device logs showing authentication failures, crashes, restarts, or configuration changes after the request.
- A count of attempts and whether multiple management paths or ports were probed.

**Pivot points:**
- CommonSecurityLog for the same SourceIP across a wider time window to identify scanning breadth.
- CommonSecurityLog for the DestinationIP to see whether other exploit patterns or ports were targeted.
- Device-specific logs or management-plane logs for the targeted appliance to confirm impact or exploitation attempts.
- Network telemetry for other hosts contacted by the same source if lateral scanning is suspected.

**Benign explanations:**
- An authorized vulnerability scan or penetration test from a known security team source.
- A web health check or monitoring probe that touches management endpoints.
- Internet background noise or opportunistic scanning that did not progress beyond probing.

**Escalation criteria:**
- The source is external and not on an approved scanner list, and attempts are repeated or targeted.
- The device shows instability, unexpected restarts, or configuration changes after the traffic.
- The request pattern matches a known exploit path and the device is internet-facing.
- Multiple management ports or devices are probed in a short period.

**Containment actions:**
- Block the SourceIP at the perimeter if the activity is clearly malicious and ongoing.
- Restrict management interface exposure to trusted admin networks or VPN only if not already enforced.
- Place the targeted device into heightened monitoring or maintenance mode if instability is observed.
- If compromise is suspected, isolate the device from the internet and preserve logs before rebooting or patching.

**Closure criteria:**
- The source is confirmed as an approved scanner or benign probe.
- No device impact, authentication anomalies, or follow-on exploit attempts are observed.
- Perimeter exposure has been reviewed and management access is appropriately restricted.
- The event is documented with the source classification and device impact assessment.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- Compromised OAuth App Performing Authenticated Tenant Actions After Token Grant: Do not schedule yet; validate as an analyst-led hunt first.
- Agentic Service Principal Performing Bulk Tenant Operations After OAuth Token Issuance: Do not schedule yet; validate as an analyst-led hunt first.
- Unauthenticated RCE Exploit Attempt Against Network Perimeter Device Management Interfaces: CommonSecurityLog.RequestURL is not populated by all CEF/syslog sources. Firewall vendors that log only connection-level metadata (allow/deny, bytes, ports) without HTTP inspection will produce no results for the RequestURL pattern filter. Confirm that the connected device performs HTTP deep inspection and populates this field.

**Licensing / identity risk fields:**
- Spoofed Business-Service Sender Domain Bypassing Email Authentication Controls: EmailEvents is available only with Microsoft Defender for Office 365 Plan 1 or Plan 2 licensing. Environments without this license cannot use this detection.

**Shared-table notes:**
- AuditLogs: shared by Compromised OAuth App Performing Authenticated Tenant Actions After Token Grant; Agentic Service Principal Performing Bulk Tenant Operations After OAuth Token Issuance; Storm-3358 ARTEX Pattern: Anomalous OAuth App Grant Followed by Privileged Resource Access

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Storm-3358 ARTEX Pattern: Anomalous OAuth App Grant Followed by Privileged Resource Access.
2. Resolve environment-mapping detections next: Spoofed Business-Service Sender Domain Bypassing Email Authentication Controls; Unauthenticated RCE Exploit Attempt Against Network Perimeter Device Management Interfaces.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Compromised OAuth App Performing Authenticated Tenant Actions After Token Grant; Agentic Service Principal Performing Bulk Tenant Operations After OAuth Token Issuance.

### Hunting Agenda and Promotion Criteria

- Compromised OAuth App Performing Authenticated Tenant Actions After Token Grant: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Agentic Service Principal Performing Bulk Tenant Operations After OAuth Token Issuance: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Spoofed Business-Service Sender Domain Bypassing Email Authentication Controls: EmailEvents is available only with Microsoft Defender for Office 365 Plan 1 or Plan 2 licensing. Environments without this license cannot use this detection.; baseline expected benign activity and define an alert-volume threshold.
- Unauthenticated RCE Exploit Attempt Against Network Perimeter Device Management Interfaces: CommonSecurityLog.RequestURL is not populated by all CEF/syslog sources. Firewall vendors that log only connection-level metadata (allow/deny, bytes, ports) without HTTP inspection will produce no results for the RequestURL pattern filter. Confirm that the connected device performs HTTP deep inspection and populates this field.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
