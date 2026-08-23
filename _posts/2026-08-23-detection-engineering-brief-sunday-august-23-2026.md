---
layout: post
title: "Detection Engineering Brief - Sunday, August 23, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-08-23
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CI/CD pipelines
  - CVE-2026-19490
  - T1190
  - Citrix NetScaler ADC
  - Citrix NetScaler Gateway
  - T1078
  - T1566
---

## Detection Engineering Summary

This brief produced 4 detection candidates.

3 production candidates, 0 hunting-only, 1 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: CI/CD pipelines, CVE-2026-19490, T1190, Citrix NetScaler ADC, Citrix NetScaler Gateway, T1078, T1566.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Unauthorized Logon to Build or Release Systems.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Unauthorized Logon to Build or Release Systems

### Detection Opportunity

Unauthorized interactive or network logon to build and release systems from accounts not associated with expected CI/CD service identities.

### Intelligence Context

- Unit 42: Connecting the Dots: Securing the Overlooked Corners of the Software Development Lifecycle (SDLC) Supply Chain — [https://unit42.paloaltonetworks.com/sdlc-supply-chain/](https://unit42.paloaltonetworks.com/sdlc-supply-chain/)
  - Context: Unit 42 reporting highlights that attackers are targeting CI/CD pipelines and build/release systems, with unauthorized access to these systems identified as a key threat vector requiring active hunting.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1078
- Products: Not specified
- Platforms: CI/CD pipelines
- Malware: Not specified
- Tools: Not specified
- Search tags: CI/CD pipelines, T1078

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1078 Valid Accounts (medium)

### Deployment Gates

- SecurityEvent collection must be enabled on build/release hosts and forwarded to the Sentinel workspace; if the MMA/AMA agent is not deployed on those hosts, EventID 4624 rows will not appear.

**Required telemetry:**
- SecurityEvent, AuditLogs

### KQL

```kql
let buildHosts = dynamic([]);
let knownServiceAccounts = dynamic([]);
let lookback = 1h;
let postLogonWindow = 1h;
let suspiciousLogons = SecurityEvent
| where TimeGenerated >= ago(lookback)
| where EventID == 4624
| where Computer in~ (buildHosts)
| where LogonType in (2, 10)
| where TargetUserName !endswith "$"
| where TargetUserName !in~ ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
| where not(TargetUserName has_any (knownServiceAccounts))
| extend LogonTypeName = case(
    LogonType == 2, "Interactive",
    LogonType == 10, "RemoteInteractive",
    "Other"
  )
| project LogonTime = TimeGenerated, AccountName = TargetUserName, Computer, LogonType, LogonTypeName, LogonSourceIP = IpAddress;
let auditActivity = AuditLogs
| where TimeGenerated >= ago(lookback + postLogonWindow)
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| where isnotempty(Actor)
| project AuditTime = TimeGenerated, Actor, OperationName;
suspiciousLogons
| join kind=leftouter (
    auditActivity
) on $left.AccountName == $right.Actor
| where isnull(AuditTime) or AuditTime between (LogonTime .. (LogonTime + postLogonWindow))
| project LogonTime, AccountName, Computer, LogonType, LogonTypeName, LogonSourceIP, AuditTime, OperationName
| order by LogonTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrators performing maintenance on build servers via RDP or console will trigger this rule.
- Automated tooling that logs on interactively under a non-service account identity will generate alerts.
- Newly provisioned service accounts not yet added to knownServiceAccounts will appear as unauthorized.

**Tuning notes:**
- Populate buildHosts with the actual hostnames or naming patterns of your build and release infrastructure before enabling.
- Populate knownServiceAccounts with all authorized CI/CD service account names.
- Consider replacing the static buildHosts list with a Sentinel Watchlist lookup for easier maintenance.
- For scheduled rule promotion, extend lookback to 24h and add a summarize step to deduplicate repeated logons by the same account to the same host.

**Risks / caveats:**
- buildHosts must be populated with real build/release server hostnames before the query can return any results; the list is empty by design and must be filled before deployment.
- knownServiceAccounts must be populated with actual CI/CD service account names; without them the exclusion filter is ineffective.
- SecurityEvent collection must be enabled on build/release hosts and forwarded to the Sentinel workspace; if the MMA/AMA agent is not deployed on those hosts, EventID 4624 rows will not appear.
- AuditLogs.InitiatedBy.user.userPrincipalName is only populated for user-initiated Entra ID operations; service-principal-initiated operations will have a null UPN, causing the join to produce no matches for those actors.

### Triage Runbook

**First 15 minutes:**
- Confirm the target host is actually a build or release system and identify the business owner or platform owner for that host.
- Validate whether the account is a known CI/CD service account, a break-glass/admin account, or an unexpected user identity.
- Check the logon type, source IP, and time of access to see whether the activity aligns with approved maintenance or remote support.
- Look for immediate follow-on activity from the same account or host, especially changes to pipelines, build artifacts, secrets, or deployment jobs.

**Evidence to collect:**
- SecurityEvent 4624 details for the logon: Computer, TargetUserName, LogonType, IpAddress, WorkstationName, and timestamp.
- Any AuditLogs entries from the same account within the next hour, including OperationName and InitiatedBy.
- Host context for the build/release server: recent admin maintenance windows, patching, and approved remote access records.
- Identity context for the account: owner, role, group membership, MFA status, and whether the account is newly created or recently modified.

**Pivot points:**
- SecurityEvent for additional 4624, 4625, 4672, 4688, 4720, 4728, 4732, 4740, and 7045 events on the same host.
- AuditLogs for changes to applications, service principals, credentials, role assignments, and pipeline-related resources by the same actor.
- SigninLogs for the same account to identify source IPs, device details, and any concurrent risky sign-ins.
- Defender for Endpoint or host telemetry for process execution, remote tools, archive creation, or secret access on the build host.

**Benign explanations:**
- A legitimate administrator may have used RDP or console access for maintenance, patching, or troubleshooting.
- A newly provisioned CI/CD service account may not yet be included in the allowlist and can appear unauthorized.
- An automation tool may be using an interactive logon pattern under a non-service identity during deployment or testing.

**Escalation criteria:**
- The account is not an approved administrator or service identity and the access cannot be tied to a scheduled maintenance activity.
- The logon is followed by pipeline changes, credential access, new service creation, or other suspicious administrative actions.
- The source IP, time, or account behavior is inconsistent with normal operations or comes from an unmanaged or external location.

**Containment actions:**
- Disable or reset the account if it is confirmed unauthorized and not required for ongoing operations.
- Isolate the build/release host if there are signs of tampering, malicious process execution, or secret access.
- Revoke active sessions and rotate any credentials, tokens, or secrets exposed on the affected CI/CD system.

**Closure criteria:**
- The account is confirmed as authorized and the activity matches a documented maintenance or deployment window.
- No suspicious follow-on activity is found on the host, in AuditLogs, or in related identity telemetry.
- The account is added to the approved service/admin list and the detection is tuned if the event was a known false positive.

<br/>
---
<br/>

## Detection 2: CVE-2026-19490 - Unauthenticated Authentication Bypass Attempt on Citrix NetScaler

### Detection Opportunity

Remote unauthenticated exploitation of an authentication bypass vulnerability (CVE-2026-19490) targeting Citrix NetScaler ADC and Gateway appliances at the network perimeter.

### Intelligence Context

- Rapid7: CVE-2026-19490: Critical Vulnerability Affecting Citrix NetScaler ADC and NetScaler Gateway — [https://www.rapid7.com/blog/post/etr-cve-2026-19490-critical-vulnerability-affecting-citrix-netscaler-adc-and-netscaler-gateway](https://www.rapid7.com/blog/post/etr-cve-2026-19490-critical-vulnerability-affecting-citrix-netscaler-adc-and-netscaler-gateway)
  - Context: Rapid7 reported that CVE-2026-19490 allows a remote unauthenticated attacker to bypass authentication on Citrix NetScaler ADC and Gateway appliances without user interaction or elevated privileges, targeting perimeter-deployed devices.

### Search Metadata

- CVEs: CVE-2026-19490
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Citrix NetScaler ADC, Citrix NetScaler Gateway
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-19490, T1190, Citrix NetScaler ADC, Citrix NetScaler Gateway

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
let lookback = 1h;
let authBypassPaths = dynamic(["/logon/LogonPoint", "/cgi/login", "/vpn/index.html", "/gateway/"]);
CommonSecurityLog
| where TimeGenerated >= ago(lookback)
| where DeviceVendor =~ "Citrix"
| where DeviceProduct has_any ("NetScaler", "ADC", "Gateway")
| where isnotempty(RequestURL)
| where RequestURL has_any (authBypassPaths)
| summarize
    RequestCount = count(),
    DistinctURLs = dcount(RequestURL),
    DistinctActivities = dcount(Activity),
    Activities = make_set(Activity, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP, DestinationIP, DeviceVendor, DeviceProduct, DestinationPort
| where RequestCount >= 3
| extend TimeDeltaMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| project
    FirstSeen,
    LastSeen,
    TimeDeltaMinutes,
    SourceIP,
    DestinationIP,
    DestinationPort,
    DeviceVendor,
    DeviceProduct,
    RequestCount,
    DistinctURLs,
    DistinctActivities,
    Activities
| order by RequestCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate health-check or monitoring systems that poll authentication endpoints repeatedly from a single IP will trigger this rule.
- Security scanners or vulnerability assessment tools run by the organization against NetScaler appliances will match.
- Load balancer health probes targeting VPN or gateway paths may generate repeated requests from a single internal IP.

**Tuning notes:**
- Adjust authBypassPaths to match the specific authentication endpoint paths exposed by the NetScaler configuration in the environment.
- Increase RequestCount threshold above 3 if health-check or monitoring traffic generates false positives against these paths.
- Add known monitoring or scanner source IPs to a pre-filter exclusion list if they generate persistent noise.

**Risks / caveats:**
- CommonSecurityLog ingestion from Citrix NetScaler requires the CEF syslog connector to be configured on the appliance and the Sentinel CEF data connector to be active; if neither is configured, the table will contain no NetScaler rows.
- RequestURL is only populated when the NetScaler logging verbosity is set to capture HTTP request details; default syslog profiles may omit this field, causing the has_any filter to match nothing.
- The original query attempted to parse AdditionalExtensions as a response code via toint(AdditionalExtensions); AdditionalExtensions is a raw string field and this cast is unreliable. The improved query removes this unused derived field.
- The 1-hour lookback may miss slow-and-low scanning patterns; consider extending to 6h for broader coverage at the cost of increased result volume.

### Triage Runbook

**First 15 minutes:**
- Identify the source IP, destination appliance, destination port, and requested URLs to determine whether the traffic is external and focused on authentication paths.
- Check whether the source is a known scanner, monitoring system, partner network, or security assessment tool.
- Review whether the appliance is internet-facing and whether the targeted paths are enabled on that specific NetScaler deployment.
- Look for concurrent spikes in authentication failures, unusual admin logins, or configuration changes on the appliance.

**Evidence to collect:**
- CommonSecurityLog records for the source IP, destination IP, destination port, RequestURL, Activity, and timestamps.
- NetScaler appliance logs or syslog entries showing authentication events, admin actions, errors, or crashes around the same time.
- Asset inventory data confirming whether the destination is a production NetScaler ADC or Gateway instance and whether it is internet-facing.
- Change records or maintenance windows that explain repeated access to the same authentication endpoints.

**Pivot points:**
- CommonSecurityLog for additional requests from the same source IP to the same appliance or other NetScaler devices.
- Firewall or proxy logs to determine whether the source IP is external, internal, or routed through a partner network.
- NetScaler syslog and admin audit logs for authentication attempts, configuration changes, and service restarts.
- Threat intelligence or scanner allowlists to determine whether the source IP belongs to a known assessment platform.

**Benign explanations:**
- A legitimate vulnerability scanner or external security assessment may repeatedly request authentication endpoints.
- A health-check or monitoring system may poll the VPN or gateway login page at a fixed interval.
- A partner or vendor may be accessing the portal from a public IP that is not yet allowlisted.

**Escalation criteria:**
- The source is unknown, external, and repeatedly targets NetScaler authentication or management paths without a business explanation.
- There are signs of successful authentication, unexpected admin activity, or appliance instability after the requests.
- Multiple NetScaler appliances or multiple source IPs show the same pattern in a short period, suggesting active exploitation.

**Containment actions:**
- Block or rate-limit the source IP at the perimeter if the traffic is clearly malicious and not business-critical.
- Place the appliance under heightened monitoring and preserve logs if exploitation is suspected.
- If compromise indicators appear, isolate the appliance from management access and follow the vendor emergency response guidance.

**Closure criteria:**
- The source is confirmed as an approved scanner, monitor, or partner and the activity matches expected behavior.
- No authentication bypass, admin access, or service disruption is observed on the appliance.
- The source IP is documented or allowlisted and the detection is tuned to reduce repeat benign hits.

<br/>
---
<br/>

## Detection 3: CVE-2026-19490 - Inbound External Access to NetScaler Management Ports Without Prior Authentication

### Detection Opportunity

Unauthenticated inbound network connections from external IP addresses to Citrix NetScaler ADC or Gateway management interfaces, consistent with reconnaissance or exploitation of CVE-2026-19490.

### Intelligence Context

- Rapid7: CVE-2026-19490: Critical Vulnerability Affecting Citrix NetScaler ADC and NetScaler Gateway — [https://www.rapid7.com/blog/post/etr-cve-2026-19490-critical-vulnerability-affecting-citrix-netscaler-adc-and-netscaler-gateway](https://www.rapid7.com/blog/post/etr-cve-2026-19490-critical-vulnerability-affecting-citrix-netscaler-adc-and-netscaler-gateway)
  - Context: Rapid7 noted that CVE-2026-19490 targets perimeter-deployed NetScaler appliances and can be exploited remotely without authentication or user interaction, making inbound external access to management ports a key detection signal.

### Search Metadata

- CVEs: CVE-2026-19490
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Citrix NetScaler ADC, Citrix NetScaler Gateway
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-19490, T1190, Citrix NetScaler ADC, Citrix NetScaler Gateway

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
let lookback = 6h;
let netscalerPorts = dynamic([443, 8443, 9443]);
let approvedSources = dynamic(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
CommonSecurityLog
| where TimeGenerated >= ago(lookback)
| where DeviceVendor =~ "Citrix"
| where DeviceProduct has_any ("NetScaler", "ADC", "Gateway")
| where isnotempty(SourceIP)
| where isnotempty(DestinationPort)
| where DestinationPort in (netscalerPorts)
| where not(ipv4_is_in_any_range(SourceIP, approvedSources))
| summarize
    ConnectionCount = count(),
    DistinctActivities = dcount(Activity),
    ActivityList = make_set(Activity, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP, DestinationIP, DestinationPort, DeviceVendor, DeviceProduct
| where ConnectionCount >= 5
| project
    FirstSeen,
    LastSeen,
    SourceIP,
    DestinationIP,
    DestinationPort,
    DeviceVendor,
    DeviceProduct,
    ConnectionCount,
    DistinctActivities,
    ActivityList
| order by ConnectionCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate external partners or vendors accessing the NetScaler VPN portal from public IPs will trigger this rule if their IPs are not added to approvedSources.
- External monitoring or uptime-check services polling port 443 on the NetScaler will generate repeated connections from a single public IP.
- CDN or reverse-proxy infrastructure forwarding traffic may present a single external IP with high connection counts.

**Tuning notes:**
- Add known external partner, vendor, or monitoring IP ranges to the approvedSources list to reduce false positives.
- Adjust the ConnectionCount threshold based on observed baseline traffic volume to NetScaler management ports.
- Consider promoting to a scheduled rule with a 6-hour frequency and 6-hour lookback once baseline thresholds are established.

**Risks / caveats:**
- CommonSecurityLog ingestion from Citrix NetScaler requires the CEF syslog connector to be configured on the appliance and the Sentinel CEF data connector to be active; if neither is configured, the table will contain no NetScaler rows.
- DestinationPort may not be populated in all NetScaler CEF log profiles; if the field is empty, the in filter will match nothing.
- SourceIP must be populated as a parseable IPv4 address for ipv4_is_in_any_range to function; malformed or IPv6 source addresses will cause the function to return false and those rows will pass the filter regardless of origin.
- The ConnectionCount threshold of 5 over 6 hours may be too low in environments with active external user bases accessing the VPN portal; baseline normal external connection rates before scheduling.

### Triage Runbook

**First 15 minutes:**
- Confirm the destination is a NetScaler ADC or Gateway management interface and verify whether the source IP is external to the organization.
- Check whether the source IP belongs to a known partner, monitoring service, or approved scanner.
- Review the connection volume, timing, and destination port to see whether the activity is a one-off access or repeated probing.
- Look for any concurrent signs of authentication attempts, admin logins, or configuration changes on the appliance.

**Evidence to collect:**
- CommonSecurityLog entries showing SourceIP, DestinationIP, DestinationPort, Activity, and the first and last seen timestamps.
- Firewall, VPN, or reverse proxy logs that confirm whether the source is truly external and how the traffic reached the appliance.
- NetScaler logs for authentication, admin actions, errors, and service restarts during the same time window.
- Asset and exposure data showing whether the destination port is intended to be internet-facing.

**Pivot points:**
- CommonSecurityLog for additional connections from the same source IP to the same or other NetScaler devices.
- Firewall logs to identify whether the source IP is a known corporate egress, partner network, or public internet host.
- NetScaler syslog and admin audit logs for follow-on activity after the inbound connections.
- Threat intel and allowlist sources for known scanner, monitoring, or vendor IP ranges.

**Benign explanations:**
- An approved external monitoring service may repeatedly connect to the VPN or gateway port.
- A vendor or partner may be accessing the portal from a public IP that is not yet documented.
- Load balancer or health-check traffic may generate repeated connections to the same port.

**Escalation criteria:**
- The source IP is unknown, external, and repeatedly targets management ports with no business justification.
- The appliance shows signs of exploitation, authentication bypass, or unusual administrative activity after the connections.
- The same pattern appears across multiple appliances or from multiple external sources, indicating broader targeting.

**Containment actions:**
- Block the source IP if it is clearly malicious and not required for business operations.
- Increase monitoring on the appliance and preserve relevant logs for incident response.
- If compromise is suspected, restrict management access to the appliance and initiate vendor-recommended containment steps.

**Closure criteria:**
- The source is confirmed as approved monitoring, partner, or assessment traffic.
- No successful access, authentication bypass, or suspicious admin activity is found.
- The source is documented or allowlisted and the alert is tuned based on validated baseline traffic.

<br/>
---
<br/>

## Detection 4: Post-Phishing Credential Use with Elevated Risk Score Followed by Sensitive Operation

### Detection Opportunity

Successful sign-in with an elevated identity risk score following failed authentication attempts, indicative of credential theft via trusted communication channels, with subsequent audit activity suggesting account compromise.

### Intelligence Context

- Unit 42: Identity Abuse Through Trusted Communication Channels — [https://unit42.paloaltonetworks.com/communication-channel-identity-risks/](https://unit42.paloaltonetworks.com/communication-channel-identity-risks/)
  - Context: Unit 42 reporting describes attackers using enterprise collaboration tools to conduct identity phishing and credential theft, with the resulting stolen credentials used to authenticate and perform follow-on actions within the environment.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1566, T1078
- Products: Not specified
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: T1566, T1078

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1566 Phishing (low); Initial Access: T1078 Valid Accounts (medium)

### Deployment Gates

- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Required telemetry:**
- SigninLogs, AuditLogs

### KQL

```kql
let lookback = 24h;
let failWindow = 30m;
let postCompromiseWindow = 1h;
let riskLevels = dynamic(["medium", "high"]);
let riskySuccess = SigninLogs
| where TimeGenerated >= ago(lookback)
| where ResultType == 0
| where RiskLevelDuringSignIn in (riskLevels)
| project SuccessTime = TimeGenerated, UserPrincipalName, SuccessIP = IPAddress, RiskLevelDuringSignIn, AppDisplayName;
let failedSignins = SigninLogs
| where TimeGenerated >= ago(lookback)
| where ResultType != 0
| project FailTime = TimeGenerated, UserPrincipalName, FailIP = IPAddress;
let comprisedAccounts = riskySuccess
| join kind=inner (
    failedSignins
) on UserPrincipalName
| where FailTime between ((SuccessTime - failWindow) .. SuccessTime)
| summarize
    FailCount = count(),
    FailIPs = make_set(FailIP, 10),
    SuccessTime = any(SuccessTime),
    SuccessIP = any(SuccessIP),
    RiskLevelDuringSignIn = any(RiskLevelDuringSignIn),
    AppDisplayName = any(AppDisplayName)
    by UserPrincipalName;
comprisedAccounts
| join kind=inner (
    AuditLogs
    | where TimeGenerated >= ago(lookback + 1h)
    | extend Actor = tostring(InitiatedBy.user.userPrincipalName)
    | where isnotempty(Actor)
    | project AuditTime = TimeGenerated, Actor, OperationName, Category
) on $left.UserPrincipalName == $right.Actor
| where AuditTime between (SuccessTime .. (SuccessTime + postCompromiseWindow))
| project
    SuccessTime,
    UserPrincipalName,
    SuccessIP,
    FailIPs,
    FailCount,
    RiskLevelDuringSignIn,
    AppDisplayName,
    AuditTime,
    OperationName,
    Category
| order by SuccessTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Users who mistype their password and then successfully authenticate will trigger the failed-then-success pattern; the risk level filter is the primary discriminator.
- Legitimate users traveling or using VPNs may receive elevated risk scores from Entra ID Identity Protection, generating alerts when combined with prior failed attempts.
- Bulk password reset operations or MFA re-enrollment events may generate audit activity that matches the post-compromise window.

**Tuning notes:**
- Adjust riskLevels to include only 'high' if 'medium' risk generates excessive false positives in the environment.
- Narrow postCompromiseWindow from 1 hour to 30 minutes to reduce noise if audit activity is dense.
- Consider adding a filter on OperationName to restrict audit correlation to sensitive operations such as role assignments, credential changes, or application consent grants.

**Risks / caveats:**
- RiskLevelDuringSignIn is only populated when the tenant has Entra ID P2 (or Microsoft 365 E5) licensing with Identity Protection enabled; without this license the field will be empty for all rows and the riskySuccess subquery will return zero results.
- AuditLogs.InitiatedBy.user.userPrincipalName is null for service-principal-initiated operations; the isnotempty(Actor) filter correctly excludes these but means service-account post-compromise activity will not be correlated.
- The 24-hour lookback combined with a join across SigninLogs may be compute-intensive in high-volume tenants; monitor query performance and consider narrowing the lookback or adding a pre-filter on specific AppDisplayName values if needed.
- The summarize step in comprisedAccounts collapses multiple failure events per user into a single row using any() for SuccessTime; if a user has multiple risky successful sign-ins within the lookback window, only one will be represented per user. Consider deduplicating on (UserPrincipalName, SuccessTime) if multiple risky sign-ins per user are expected.

### Triage Runbook

**First 15 minutes:**
- Confirm the user, sign-in time, source IP, risk level, and application used for the successful sign-in.
- Review the preceding failed sign-ins to determine whether they were user error, password spraying, or a likely credential theft sequence.
- Identify the follow-on audit operation and assess whether it is sensitive, such as role changes, consent grants, mailbox access, or credential updates.
- Contact the user or account owner through an out-of-band method to verify whether they initiated the activity.

**Evidence to collect:**
- SigninLogs for the user: failed attempts, successful risky sign-in, IP addresses, device details, MFA status, and risk indicators.
- AuditLogs for the correlated post-sign-in activity, including OperationName, Category, TargetResources, and InitiatedBy.
- Identity Protection or Entra risk details showing whether the risk was medium or high and whether it was later remediated.
- User context such as travel status, recent password reset, MFA re-registration, or helpdesk tickets.

**Pivot points:**
- SigninLogs for the same user across the last 24 hours to identify other risky sign-ins, unfamiliar locations, or MFA prompts.
- AuditLogs for role assignments, application consent, mailbox rules, credential changes, and device registration events by the same actor.
- Entra ID Identity Protection and risk events for the account and related users.
- Microsoft Defender for Cloud Apps or email security telemetry if phishing via collaboration or email is suspected.

**Benign explanations:**
- The user may have mistyped their password and then successfully signed in from a legitimate device.
- Travel, VPN use, or a new device can trigger elevated risk scores even for legitimate users.
- The correlated audit event may be a routine administrative action, password reset, or MFA re-enrollment.

**Escalation criteria:**
- The user denies the sign-in or the follow-on action and the source IP or device is unfamiliar.
- The audit activity involves privilege escalation, consent grants, mailbox rule creation, credential changes, or data access that is not expected.
- There are additional risky sign-ins, MFA fatigue indicators, or suspicious activity from the same account or related accounts.

**Containment actions:**
- Disable the account or force sign-out if compromise is likely and the user cannot immediately verify the activity.
- Reset the password and revoke sessions/tokens if the account is confirmed or strongly suspected to be compromised.
- Require MFA re-registration and review recent consent grants, mailbox rules, and role assignments for malicious changes.

**Closure criteria:**
- The user confirms the activity and the audit action is validated as legitimate business activity.
- No additional suspicious sign-ins, risky events, or unauthorized changes are found after review.
- The account is remediated if needed and the alert is closed with documented benign cause or confirmed compromise handling.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- Unauthorized Logon to Build or Release Systems: SecurityEvent collection must be enabled on build/release hosts and forwarded to the Sentinel workspace; if the MMA/AMA agent is not deployed on those hosts, EventID 4624 rows will not appear.

**Licensing / identity risk fields:**
- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Shared-table notes:**
- AuditLogs: shared by Unauthorized Logon to Build or Release Systems; Post-Phishing Credential Use with Elevated Risk Score Followed by Sensitive Operation
- CommonSecurityLog: shared by CVE-2026-19490 - Unauthenticated Authentication Bypass Attempt on Citrix NetScaler; CVE-2026-19490 - Inbound External Access to NetScaler Management Ports Without Prior Authentication

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: CVE-2026-19490 - Unauthenticated Authentication Bypass Attempt on Citrix NetScaler; CVE-2026-19490 - Inbound External Access to NetScaler Management Ports Without Prior Authentication; Post-Phishing Credential Use with Elevated Risk Score Followed by Sensitive Operation.
2. Resolve environment-mapping detections next: Unauthorized Logon to Build or Release Systems.

### Hunting Agenda and Promotion Criteria

- Unauthorized Logon to Build or Release Systems: SecurityEvent collection must be enabled on build/release hosts and forwarded to the Sentinel workspace; if the MMA/AMA agent is not deployed on those hosts, EventID 4624 rows will not appear.; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

This run exposes an identity-risk licensing blind spot: detections using RiskLevelDuringSignIn lose fidelity in tenants without Entra ID P2 risk enrichment.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
