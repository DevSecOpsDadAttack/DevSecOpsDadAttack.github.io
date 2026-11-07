---
layout: post
title: "Detection Engineering Brief - Saturday, November 7, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-11-07
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - GitHub
  - OAuth applications
  - cloud identity
  - ARTEX
  - Storm-3358
  - CVE-2023-20198
  - Cisco IOS
  - network devices
  - T1098.003
  - T1098
  - T1595
---

## Detection Engineering Summary

This brief produced 3 detection candidates.

1 production candidate, 1 hunting-only, 1 require environment mapping, and 0 rejected.

3 detections include KQL. 3 include ATT&CK mappings. 3 include triage guidance.

Search metadata extracted for this run includes: GitHub, OAuth applications, cloud identity, ARTEX, Storm-3358, CVE-2023-20198, Cisco IOS, network devices, T1098.003, T1098, T1595.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: OAuth App Service Principal Actions Following Recent Consent Grant; CVE-2023-20198 Probe Attempts Against Cisco IOS Devices.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: OAuth App Service Principal Actions Following Recent Consent Grant

### Detection Opportunity

Compromised OAuth applications used to perform actions within tenant environments after secrets were exposed on GitHub.

### Intelligence Context

- Microsoft Security Blog: Threat actors use agentic AI tooling to find and abuse exposed secrets — [https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/](https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/)
  - Context: Threat actors used the ARTEX agentic AI framework to search GitHub for exposed OAuth application secrets, then used those compromised OAuth applications to perform actions within victim tenant environments.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1098.003, T1098
- Products: GitHub, OAuth applications
- Platforms: cloud identity
- Malware: Not specified
- Tools: ARTEX
- Search tags: GitHub, OAuth applications, cloud identity, ARTEX, T1098.003, T1098

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1098 Account Manipulation/ T1098.003 Additional Cloud Roles (medium); Privilege Escalation: T1098 Account Manipulation/ T1098.003 Additional Cloud Roles (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- AuditLogs

### KQL

```kql
let lookback = 7d;
let op_threshold = 10;
let consent_apps = AuditLogs
    | where TimeGenerated >= ago(lookback)
    | where OperationName in ("Consent to application", "Add OAuth2PermissionGrant")
    | where Result == "success"
    | extend AppId = tostring(TargetResources[0].id)
    | extend AppDisplayName = tostring(TargetResources[0].displayName)
    | extend InitiatedByUPN = tostring(InitiatedBy.user.userPrincipalName)
    | where isnotempty(AppId)
    | project ConsentTime = TimeGenerated, AppId, AppDisplayName, InitiatedByUPN;
let sp_activity = AuditLogs
    | where TimeGenerated >= ago(lookback)
    | where isnotempty(tostring(InitiatedBy.app.appId))
    | extend SPAppId = tostring(InitiatedBy.app.appId)
    | extend SPName = tostring(InitiatedBy.app.displayName)
    | summarize
        OperationCount = count(),
        Operations = make_set(OperationName, 20),
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated)
        by SPAppId, SPName;
consent_apps
| join kind=inner sp_activity on $left.AppId == $right.SPAppId
| where OperationCount > op_threshold
| where FirstSeen >= ConsentTime
| project
    ConsentTime,
    AppDisplayName,
    AppId,
    InitiatedByUPN,
    SPName,
    OperationCount,
    Operations,
    FirstSeen,
    LastSeen
| sort by OperationCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate OAuth applications newly consented by administrators that immediately begin performing high-volume automated operations such as reporting, provisioning, or synchronization.
- Third-party SaaS integrations that receive consent and then perform bulk directory reads or audit operations as part of onboarding.

**Tuning notes:**
- Adjust op_threshold based on a 30-day percentile of service principal operation counts per app in your tenant.
- Consider adding an exclusion list of known-good first-party Microsoft appIds such as those associated with Microsoft Graph connectors or Azure AD Connect.
- Shorten the lookback window to 3 days if consent grant volume is high and false positive rates are elevated.

**Risks / caveats:**
- TargetResources[0].id in consent grant events returns the service principal object ID, not the application client ID (appId). The join to InitiatedBy.app.appId (which is the client appId) may produce zero results if these values differ. Validate that the correct field is used for the join key in your tenant's AuditLog schema.
- AdditionalDetails[0].value is used to extract an IP address for service principal operations, but this field is not consistently populated for app-initiated AuditLog events and may be empty for most records.
- The join key (TargetResources[0].id from consent events vs InitiatedBy.app.appId from SP-initiated events) may not match if the consent event records the service principal object ID rather than the application client ID. Validate join key accuracy in your tenant before relying on results.
- The OperationCount threshold of 10 is a starting point and should be baselined against normal service principal activity in the environment.

### Triage Runbook

**First 15 minutes:**
- Confirm the consent event is real and recent: identify the AppId, AppDisplayName, ConsentTime, and the user who granted consent.
- Review the downstream service principal operations and determine whether they are administrative, data-access, or directory-manipulation actions.
- Check whether the consenting user is expected to approve third-party apps; if not, treat this as suspicious immediately.
- Validate whether the app is a known internal or approved SaaS integration by comparing AppId and display name against your allowlist.
- Look for signs of immediate abuse such as high operation volume, unusual operation types, or activity outside normal business hours.

**Evidence to collect:**
- ConsentTime, AppId, AppDisplayName, and InitiatedByUPN from the consent event.
- OperationCount, Operations, FirstSeen, and LastSeen for the service principal activity.
- The exact AuditLogs records for the consent and the first few downstream operations.
- Any related sign-in or identity events for the consenting user around the same time window.
- Whether the app is first-party Microsoft, an internal automation app, or a third-party integration.

**Pivot points:**
- AuditLogs for additional consent events by the same user or for the same AppId.
- AuditLogs for all service principal operations tied to the AppId over a longer lookback to establish scope.
- Sign-in logs for the consenting user to check for impossible travel, unfamiliar device, or MFA anomalies.
- Enterprise application and app consent records to verify publisher, permissions, and tenant-wide grants.
- Directory audit activity for role assignments, credential additions, or permission grants associated with the app.

**Benign explanations:**
- A legitimate SaaS onboarding flow where an administrator recently approved the app and it immediately performed bulk directory or reporting operations.
- Internal automation or provisioning service principals that were re-consented and then resumed scheduled tasks.
- Microsoft first-party applications performing expected tenant automation after a consent or configuration change.

**Escalation criteria:**
- The app is not recognized, not approved, or was consented by a user who should not be granting application access.
- The downstream operations include credential additions, role assignments, delegated permission grants, or other privileged changes.
- The consenting account shows signs of compromise or the app activity is inconsistent with the stated business purpose.
- The activity spans multiple sensitive operations or multiple target objects in a short period.

**Containment actions:**
- Revoke the OAuth consent or disable the enterprise application if abuse is suspected.
- Disable or reset the consenting account if there is evidence the user was compromised.
- Remove suspicious app credentials or secrets if the app is owned by your organization and can be remediated safely.
- Block the app or service principal from further tenant access pending investigation.

**Closure criteria:**
- The app is verified as approved, the operations match documented business use, and no suspicious identity activity is found.
- The consented app is a known internal or first-party service principal with expected post-consent behavior.
- Any suspicious operations are explained by a change ticket, onboarding record, or scheduled automation job.
- No additional tenant activity, privilege changes, or user compromise indicators are identified after review.

<br/>
---
<br/>

## Detection 2: Storm-3358 OAuth App Abuse - Service Principal Tenant Actions After Recent Consent

### Detection Opportunity

Storm-3358 abused compromised OAuth application secrets obtained via ARTEX to perform actions within financial sector tenant environments.

### Intelligence Context

- Microsoft Security Blog: ARTEX abuse expands as cybercriminals target financial sector — [https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/](https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/)
  - Context: Storm-3358, a financially motivated threat actor, used ARTEX to search GitHub for OAuth application secrets and then abused those compromised OAuth applications to perform actions within tenant environments, with a focus on financial sector organizations.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-3358
- ATT&CK tags: T1098.003, T1098
- Products: GitHub, OAuth applications
- Platforms: cloud identity
- Malware: Not specified
- Tools: ARTEX
- Search tags: Storm-3358, GitHub, OAuth applications, cloud identity, ARTEX, T1098.003, T1098

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1098 Account Manipulation/ T1098.003 Additional Cloud Roles (medium); Privilege Escalation: T1098 Account Manipulation/ T1098.003 Additional Cloud Roles (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- AuditLogs

### KQL

```kql
let lookback = 14d;
let sensitive_ops = dynamic([
    "Add member to role",
    "Add app role assignment to service principal",
    "Update application",
    "Add service principal credentials",
    "Set delegation entry",
    "Add delegated permission grant"
]);
let recently_consented = AuditLogs
    | where TimeGenerated >= ago(lookback)
    | where OperationName in ("Consent to application", "Add OAuth2PermissionGrant")
    | where Result == "success"
    | extend AppId = tostring(TargetResources[0].id)
    | extend AppDisplayName = tostring(TargetResources[0].displayName)
    | extend ConsentGrantedBy = tostring(InitiatedBy.user.userPrincipalName)
    | where isnotempty(AppId)
    | project ConsentTime = TimeGenerated, AppId, AppDisplayName, ConsentGrantedBy;
let privileged_sp_ops = AuditLogs
    | where TimeGenerated >= ago(lookback)
    | where OperationName in (sensitive_ops)
    | where isnotempty(tostring(InitiatedBy.app.appId))
    | extend SPAppId = tostring(InitiatedBy.app.appId)
    | extend SPName = tostring(InitiatedBy.app.displayName)
    | extend TargetEntity = coalesce(
        tostring(TargetResources[0].userPrincipalName),
        tostring(TargetResources[0].displayName)
      )
    | project OpTime = TimeGenerated, SPAppId, SPName, OperationName, ResultType, TargetEntity;
recently_consented
| join kind=inner privileged_sp_ops on $left.AppId == $right.SPAppId
| where OpTime > ConsentTime
| project
    ConsentTime,
    OpTime,
    AppDisplayName,
    AppId,
    ConsentGrantedBy,
    SPName,
    OperationName,
    ResultType,
    TargetEntity
| sort by OpTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate third-party SaaS applications newly consented by administrators that immediately perform role assignments or credential operations as part of their setup process.
- Internal automation service principals that receive periodic re-consent and then perform privileged directory operations as part of scheduled maintenance.

**Tuning notes:**
- Add an exclusion set of known-good service principal appIds for internal automation to reduce false positives.
- Consider splitting the sensitive_ops list into tiers and assigning different severity levels to role assignment operations versus credential additions.
- Reduce the lookback window to 7 days if the 14-day window produces excessive volume from legitimate onboarding activity.

**Risks / caveats:**
- TargetResources[0].id in consent grant events may return the service principal object ID rather than the application client ID (appId), causing the join to InitiatedBy.app.appId to produce zero results. Validate that these values match in your tenant's AuditLog schema before relying on join output.
- ResultType field availability in AuditLogs varies by operation category; some privileged operations may not populate ResultType and would still be included in results.
- The join key accuracy between TargetResources[0].id (consent events) and InitiatedBy.app.appId (SP-initiated events) must be validated in the target tenant, as these may represent different identifier types (object ID vs client appId).
- The 14-day lookback window means that a compromised app consented more than 14 days ago will not be detected; consider a longer window for persistent access scenarios.

### Triage Runbook

**First 15 minutes:**
- Validate the consent event and identify the AppId, AppDisplayName, ConsentTime, and ConsentGrantedBy user.
- Inspect the privileged operations performed after consent and determine whether they include role changes, credential additions, or permission grants.
- Check whether the app is a known business application or an approved internal automation principal.
- Review the consenting user's recent sign-ins and identity risk indicators for signs of account compromise.
- Assess whether the activity is limited to one app or whether multiple suspicious service principals are active.

**Evidence to collect:**
- ConsentTime, AppId, AppDisplayName, and ConsentGrantedBy from the consent event.
- OpTime, OperationName, ResultType, and TargetEntity for each privileged operation.
- The full AuditLogs records for the consent and the subsequent privileged actions.
- Any related sign-in logs, MFA events, or identity protection alerts for the consenting user.
- Application metadata such as publisher, permissions granted, and whether the app is tenant-wide or user-consented.

**Pivot points:**
- AuditLogs for all operations by the same AppId before and after the consent window.
- AuditLogs for other apps consented by the same user in the same time period.
- Sign-in logs for the consenting user and any admin accounts involved in the same timeframe.
- Enterprise applications and app consent records to verify whether the app has unusual permissions.
- Directory audit logs for role assignments, service principal credential changes, and delegated permission grants.

**Benign explanations:**
- A legitimate third-party application onboarding process that performs role assignments or credential setup immediately after consent.
- Internal automation that was reauthorized and then executed expected privileged directory operations.
- Planned administrative provisioning activity documented in a change ticket or onboarding workflow.

**Escalation criteria:**
- The app is unapproved, unknown, or was consented by a suspicious or compromised account.
- The operations include privileged changes that are not consistent with the app's stated purpose.
- Multiple sensitive operations occur in a short time window or target high-value directory objects.
- There is evidence of broader identity compromise, such as anomalous sign-ins or additional malicious app consents.

**Containment actions:**
- Disable or revoke the suspicious enterprise application and remove its consent grants.
- Disable or reset the consenting account if compromise is suspected.
- Remove any unauthorized role assignments, credentials, or delegated permissions created by the app.
- Coordinate with identity administrators to block further app access while investigation is in progress.

**Closure criteria:**
- The app is confirmed as approved and the privileged actions are validated against expected onboarding or automation behavior.
- No unauthorized role changes, credential additions, or permission grants are found.
- The consenting account is verified as legitimate and not compromised.
- Any suspicious activity is fully explained by documented administrative activity and no additional indicators remain.

<br/>
---
<br/>

## Detection 3: CVE-2023-20198 Probe Attempts Against Cisco IOS Devices

### Detection Opportunity

Active scanning and exploitation probing for CVE-2023-20198 on Cisco IOS devices observed in honeypot telemetry.

### Intelligence Context

- SANS ISC: Vulnerability Scans for Older Cisco IOS Vulnerability / Opt-Out Headers, (Thu, Nov 5th) — [https://isc.sans.edu/diary/rss/33492](https://isc.sans.edu/diary/rss/33492)
  - Context: SANS ISC honeypot data captured active scanning and exploit probe attempts suspected to target CVE-2023-20198, a known Cisco IOS privilege escalation vulnerability, indicating ongoing opportunistic exploitation activity.

### Search Metadata

- CVEs: CVE-2023-20198
- Threat actors: Not specified
- ATT&CK tags: T1595
- Products: Cisco IOS
- Platforms: network devices
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2023-20198, Cisco IOS, network devices, T1595

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Reconnaissance: T1595 Active Scanning (high)

### Deployment Gates

- RequestURL field in CommonSecurityLog is not populated by all Cisco IOS log sources; many Cisco syslog-based CEF integrations do not include HTTP request URI details, which would cause the exploit_uri_patterns filter to match nothing.
- RequestURL is frequently empty in Cisco IOS CEF events forwarded via syslog-to-CEF conversion; if this field is not populated, the exploit_uri_patterns filter will exclude all events.

**Required telemetry:**
- CommonSecurityLog, Syslog

### KQL

```kql
let lookback = 1d;
let cisco_mgmt_ports = dynamic([80, 443, 8080, 8443]);
let exploit_uri_patterns = dynamic(["/level/", "/exec/", "/intf-"]);
let probe_events = CommonSecurityLog
    | where TimeGenerated >= ago(lookback)
    | where DeviceProduct has_any ("IOS", "Cisco")
    | where DestinationPort in (cisco_mgmt_ports)
    | where isnotempty(RequestURL)
    | where RequestURL has_any (exploit_uri_patterns)
    | where ipv4_is_valid(SourceIP) and ipv4_is_private(SourceIP) == false
    | project
        ProbeTime = TimeGenerated,
        SourceIP,
        DestinationIP,
        DestinationPort,
        RequestURL,
        Activity,
        DeviceProduct;
let cisco_syslog = Syslog
    | where TimeGenerated >= ago(lookback)
    | where ProcessName has_any ("IOS", "cisco")
    | where SyslogMessage has_any ("PRIV", "privilege", "HTTP", "webui", "level 15")
    | project
        SyslogTime = TimeGenerated,
        SyslogHost = Computer,
        SyslogMessage;
probe_events
| join kind=leftouter (
    cisco_syslog
  ) on $left.DestinationIP == $right.SyslogHost
| where isempty(SyslogTime) or (SyslogTime >= ProbeTime and SyslogTime <= ProbeTime + 1h)
| project
    ProbeTime,
    SourceIP,
    DestinationIP,
    DestinationPort,
    RequestURL,
    Activity,
    DeviceProduct,
    SyslogTime,
    SyslogHost,
    SyslogMessage
| sort by ProbeTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Internal vulnerability scanners or penetration testing tools targeting Cisco management interfaces with URI patterns that match the exploit signatures.
- Legitimate network monitoring tools that probe management ports and generate HTTP requests with path segments resembling exploit patterns.

**Tuning notes:**
- Confirm the exact DeviceProduct string emitted by your Cisco IOS devices in CommonSecurityLog before deploying.
- If RequestURL is not populated in your CEF events, consider parsing the raw syslog message from the AdditionalExtensions field or the Message field if available.
- Restrict DestinationIP to the specific subnet or IP list of your Cisco IOS management interfaces to reduce noise.
- Extend the lookback window to 7 days for initial hunting to identify historical probe activity before switching to a 1-day scheduled window.

**Risks / caveats:**
- CommonSecurityLog requires a CEF-compatible log forwarder configured to receive Cisco IOS HTTP server events. If Cisco IOS devices are not forwarding CEF logs to Sentinel, this table will contain no relevant records.
- DeviceProduct values in CommonSecurityLog are set by the sending device or forwarder and may not match 'IOS' or 'Cisco' exactly. The actual DeviceProduct string must be confirmed against ingested records.
- RequestURL field in CommonSecurityLog is not populated by all Cisco IOS log sources; many Cisco syslog-based CEF integrations do not include HTTP request URI details, which would cause the exploit_uri_patterns filter to match nothing.
- The Syslog table join requires that Cisco IOS devices forward syslog to the Sentinel Syslog connector and that the Computer field in Syslog can be correlated to DestinationIP in CommonSecurityLog. This IP-to-hostname mapping is environment-specific and not automatically available.

### Triage Runbook

**First 15 minutes:**
- Identify the source IP, destination IP, destination port, and request URI involved in the probe.
- Confirm whether the destination is a real Cisco IOS management interface in your environment.
- Check whether the source IP belongs to an internal vulnerability scanner, penetration test, or monitoring tool.
- Review nearby Syslog activity on the target device for signs of authentication attempts, privilege changes, crashes, or web UI anomalies.
- Determine whether the same source IP is probing multiple Cisco devices or other internet-facing assets.

**Evidence to collect:**
- ProbeTime, SourceIP, DestinationIP, DestinationPort, RequestURL, Activity, and DeviceProduct from the network event.
- SyslogTime, SyslogHost, and SyslogMessage from the target device around the same time.
- Any device configuration or management access logs that show whether the request reached the Cisco IOS web interface.
- Source IP reputation or ownership information, if available internally.
- Whether the target device is exposed to the internet or only reachable from internal networks.

**Pivot points:**
- CommonSecurityLog for additional requests from the same SourceIP to other Cisco devices or management ports.
- Syslog for the target host to look for privilege escalation, web UI, or authentication-related messages.
- Firewall or proxy logs to confirm whether the traffic was allowed, blocked, or NATed.
- Asset inventory or CMDB to verify the device role, management exposure, and owner.
- Threat intel or internal scanner allowlists to determine whether the source is expected.

**Benign explanations:**
- An internal vulnerability scanner or red team tool testing for CVE-2023-20198 exposure.
- A network monitoring or asset discovery platform generating management-plane probes.
- A misconfigured security tool or crawler that matches exploit-like URI patterns without malicious intent.

**Escalation criteria:**
- The source IP is external, unrecognized, or associated with repeated probing across multiple devices.
- The target device is internet-exposed and the probe pattern matches known exploit behavior.
- Syslog or device logs show follow-on activity such as authentication attempts, privilege changes, or service instability.
- Multiple probes occur from the same source over a short period or against multiple management interfaces.

**Containment actions:**
- Block the source IP at the perimeter if the traffic is clearly malicious and not part of approved testing.
- Restrict or disable external access to Cisco management interfaces if they are unnecessarily exposed.
- Increase monitoring on the target device and preserve logs if exploitation is suspected.
- Notify network operations to validate device hardening and patch status for CVE-2023-20198.

**Closure criteria:**
- The source is confirmed as an approved scanner, tester, or internal monitoring system.
- The target device shows no signs of exploitation, instability, or unauthorized configuration changes.
- The request pattern is determined to be benign or unrelated to CVE-2023-20198 exploitation.
- Exposure is documented and remediated or accepted by the device owner if no malicious activity is confirmed.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- OAuth App Service Principal Actions Following Recent Consent Grant: Do not schedule yet; validate as an analyst-led hunt first.
- CVE-2023-20198 Probe Attempts Against Cisco IOS Devices: RequestURL field in CommonSecurityLog is not populated by all Cisco IOS log sources; many Cisco syslog-based CEF integrations do not include HTTP request URI details, which would cause the exploit_uri_patterns filter to match nothing.
- CVE-2023-20198 Probe Attempts Against Cisco IOS Devices: RequestURL is frequently empty in Cisco IOS CEF events forwarded via syslog-to-CEF conversion; if this field is not populated, the exploit_uri_patterns filter will exclude all events.

**Shared-table notes:**
- AuditLogs: shared by OAuth App Service Principal Actions Following Recent Consent Grant; Storm-3358 OAuth App Abuse - Service Principal Tenant Actions After Recent Consent

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Storm-3358 OAuth App Abuse - Service Principal Tenant Actions After Recent Consent.
2. Resolve environment-mapping detections next: CVE-2023-20198 Probe Attempts Against Cisco IOS Devices.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: OAuth App Service Principal Actions Following Recent Consent Grant.

### Hunting Agenda and Promotion Criteria

- OAuth App Service Principal Actions Following Recent Consent Grant: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- CVE-2023-20198 Probe Attempts Against Cisco IOS Devices: RequestURL field in CommonSecurityLog is not populated by all Cisco IOS log sources; many Cisco syslog-based CEF integrations do not include HTTP request URI details, which would cause the exploit_uri_patterns filter to match nothing.; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
