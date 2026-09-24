---
layout: post
title: "Detection Engineering Brief - Thursday, September 24, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-24
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-94127
  - T1190
  - F5 BIG-IP APM
  - OAuth
  - OpenID Connect
  - SAML
  - network appliance
  - Entra ID
  - T1566
  - T1566.002
---

## Detection Engineering Summary

This brief produced 3 detection candidates.

1 production candidate, 1 hunting-only, 1 require environment mapping, and 0 rejected.

3 detections include KQL. 3 include ATT&CK mappings. 3 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-94127, T1190, F5 BIG-IP APM, OAuth, OpenID Connect, SAML, network appliance, Entra ID, T1566, T1566.002.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: F5 BIG-IP APM - Anomalous Inbound Traffic Spike Consistent with CVE-2026-94127 Exploitation; Entra ID Device Code Phishing - Automated Infrastructure Targeting Multiple Users from Shared IP.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: F5 BIG-IP APM - Anomalous Inbound Traffic Spike Consistent with CVE-2026-94127 Exploitation

### Detection Opportunity

Unauthenticated crafted traffic sent to F5 BIG-IP APM virtual server resulting in potential RCE via CVE-2026-94127.

### Intelligence Context

- Rapid7: CVE-2026-94127: Critical Unauthenticated RCE in F5 BIG-IP APM — [https://www.rapid7.com/blog/post/etr-cve-2026-94127-critical-unauthenticated-rce-in-f5-big-ip-apm](https://www.rapid7.com/blog/post/etr-cve-2026-94127-critical-unauthenticated-rce-in-f5-big-ip-apm)
  - Context: Rapid7 reported that an unauthenticated attacker with network access can achieve RCE by sending specifically crafted traffic to a BIG-IP virtual server with both an APM access policy and an OAuth profile configured. The exploitation vector is inbound network traffic requiring no prior authentication.

### Search Metadata

- CVEs: CVE-2026-94127
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: F5 BIG-IP APM, OAuth, OpenID Connect, SAML
- Platforms: network appliance
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-94127, T1190, F5 BIG-IP APM, OAuth, OpenID Connect, SAML, network appliance

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.

**Required telemetry:**
- CommonSecurityLog, Syslog

### KQL

```kql
let lookback = 1h;
let errorThreshold = 20;
let apmErrors = CommonSecurityLog
    | where TimeGenerated >= ago(lookback)
    | where DeviceVendor =~ "F5"
    | where DeviceProduct has_any ("BIG-IP", "APM")
    | where Activity has_any ("error", "deny", "reject", "failed", "invalid", "malformed")
    | summarize
        EventCount = count(),
        DistinctActivities = dcount(Activity),
        DestinationPorts = make_set(DestinationPort, 20),
        SampleMessages = make_set(Message, 5)
        by SourceIP, bin(TimeGenerated, 5m)
    | where EventCount >= errorThreshold;
let syslogCorroboration = Syslog
    | where TimeGenerated >= ago(lookback)
    | where SyslogMessage has_any ("apmd", "oauth", "apm", "access_policy")
    | where SyslogMessage has_any ("error", "failed", "invalid", "exception", "crash")
    | summarize
        SyslogCount = count(),
        SyslogSamples = make_set(SyslogMessage, 3)
        by bin(TimeGenerated, 5m);
apmErrors
| join kind=leftouter syslogCorroboration on TimeGenerated
| project
    TimeGenerated,
    SourceIP,
    EventCount,
    DistinctActivities,
    DestinationPorts,
    SampleMessages,
    SyslogCount,
    SyslogSamples
| sort by EventCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate load testing or health check infrastructure generating high volumes of requests to F5 APM virtual servers may exceed the error threshold.
- Misconfigured OAuth or SAML clients repeatedly failing authentication will produce error spikes from a single IP that match the pattern without being exploitation attempts.
- Shared NAT egress IPs from large user populations may aggregate errors from multiple users into a single source IP, exceeding the threshold.

**Tuning notes:**
- Baseline F5 error event rates per source IP over 7 days before setting errorThreshold. Environments with aggressive health checks or OAuth client retries may need thresholds of 50 or higher.
- If APM daemon logs are not available in the Syslog table, the syslogCorroboration subquery can be removed without affecting the primary detection logic.
- Consider adding a known-good IP allowlist using a let statement or watchlist lookup to suppress internal scanners, health check IPs, and load balancer probes.

**Risks / caveats:**
- CommonSecurityLog ingestion of F5 BIG-IP APM events requires a CEF-compatible syslog forwarder and the F5 CEF connector to be configured. If not present, the apmErrors subquery returns no results.
- The Syslog table corroboration arm requires APM daemon logs (apmd process) to be forwarded separately via syslog to the Sentinel workspace. This is not guaranteed by the CEF connector alone.
- The join between apmErrors and syslogCorroboration uses only TimeGenerated bin as the join key. There is no shared host or device identifier, meaning syslog messages from any host in the same 5-minute bin will match, producing structurally incorrect correlations in multi-device environments.
- DeviceProduct field values for F5 BIG-IP APM in CEF vary by firmware version and connector configuration. The has_any filter on 'BIG-IP' and 'APM' may not match the actual ingested values without environment validation.

### Triage Runbook

**First 15 minutes:**
- Confirm the source IP, destination port, and affected virtual server are internet-facing and not a known scanner, health check, or load test source.
- Check whether the spike is concentrated on a single VIP or spread across multiple APM/OAuth-enabled services; a single targeted VIP increases concern for exploitation.
- Review the sample F5 messages and any correlated apmd/syslog errors for crash, exception, malformed request, or policy evaluation failures.
- Verify whether the F5 device has any concurrent indicators of compromise such as unexpected restarts, new admin sessions, config changes, or unusual outbound connections.
- If the event is active and the source is external, notify the network/security team to watch for continued exploitation attempts while triage continues.

**Evidence to collect:**
- SourceIP reputation, geolocation, ASN, and whether it belongs to a known scanner, proxy, or internal testing range.
- DestinationPort and virtual server mapping to confirm which APM/OAuth/SAML service was targeted.
- SampleMessages and SyslogSamples to identify exploit-like patterns, malformed requests, or daemon errors.
- F5 management-plane logs for admin logins, config changes, process restarts, or crashes around the same time window.
- Any network telemetry showing outbound connections from the F5 device after the spike, especially to unusual external destinations.

**Pivot points:**
- CommonSecurityLog for the same SourceIP over the prior 24 hours to see whether the activity is isolated or part of broader scanning.
- Syslog on the F5 host for apmd, oauth, access_policy, crash, exception, or restart messages around the alert time.
- Firewall, proxy, or NetFlow logs for the SourceIP to identify other targets and confirm whether this is a wider campaign.
- F5 audit or management logs to check for configuration changes, new users, or unexpected administrative actions.
- EDR or host telemetry on any connected management jump hosts used to administer the F5 appliance.

**Benign explanations:**
- Legitimate load testing or synthetic monitoring can create bursts of error-class traffic against APM virtual servers.
- Misconfigured OAuth, OpenID Connect, or SAML clients can repeatedly send malformed requests and trigger error spikes.
- Shared NAT or proxy egress from many users can aggregate into a single high-volume source IP.
- A newly deployed or changed APM policy can generate temporary error bursts during rollout or troubleshooting.

**Escalation criteria:**
- Escalate immediately if the F5 device shows crashes, restarts, unexpected admin activity, or suspicious outbound connections.
- Escalate if the source IP is external, not allowlisted, and the traffic pattern is clearly exploit-like or repeats across multiple VIPs.
- Escalate if there is evidence of successful command execution, web shell placement, configuration tampering, or credential theft.
- Escalate if multiple F5 appliances or other public-facing services are being targeted in the same time window from the same source or ASN.

**Containment actions:**
- Temporarily block or rate-limit the source IP at the perimeter if the traffic is ongoing and clearly malicious.
- If exploitation is suspected, place the affected F5 VIP into maintenance or restrict access to trusted sources until validated.
- Preserve logs and device state before rebooting or making changes, unless emergency service restoration requires immediate action.
- If compromise is confirmed, rotate any credentials or secrets stored on or used by the F5 APM integration paths.

**Closure criteria:**
- The source IP is confirmed as a benign scanner, health check, or approved test source and the traffic matches expected behavior.
- F5 logs show no crash, no unauthorized admin activity, no config changes, and no outbound suspicious activity.
- The targeted service owner confirms a known change, rollout, or misconfiguration explains the error spike.
- Any suspicious traffic has stopped and the device remains stable after monitoring through at least one additional observation window.

<br/>
---
<br/>

## Detection 2: Entra ID Device Code Phishing - Token Theft Followed by Anomalous Resource Access

### Detection Opportunity

Device code phishing flow initiated to steal Entra ID tokens, followed by downstream resource access from a different IP or location than the authentication event.

### Intelligence Context

- Microsoft Security Blog: Unmasking EvilTokens: Getting to the root of device code phishing — [https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)
  - Context: Microsoft reported that device code phishing attacks using AI-assisted lures and automated infrastructure are being used to steal Entra ID tokens. The attack flow involves a victim completing a device code authentication, after which the attacker reuses the stolen token from a different IP or location to access resources.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1566, T1566.002
- Products: Entra ID
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: Entra ID, T1566, T1566.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1566 Phishing/ T1566.002 Spearphishing Link (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- SigninLogs

### KQL

```kql
let lookback = 2h;
let replayWindow = 30m;
let deviceCodeAuths = SigninLogs
    | where TimeGenerated >= ago(lookback)
    | where AuthenticationProtocol =~ "deviceCode"
    | where ResultType == 0
    | where isnotempty(IPAddress)
    | project
        DeviceCodeTime = TimeGenerated,
        UserPrincipalName,
        AuthIP = IPAddress,
        ClientAppUsed,
        ConditionalAccessStatus;
let subsequentAccess = SigninLogs
    | where TimeGenerated >= ago(lookback)
    | where ResultType == 0
    | where AuthenticationProtocol !~ "deviceCode"
    | where isnotempty(IPAddress)
    | project
        AccessTime = TimeGenerated,
        UserPrincipalName,
        AccessIP = IPAddress,
        AccessApp = ClientAppUsed,
        AppDisplayName;
deviceCodeAuths
| join kind=inner subsequentAccess on UserPrincipalName
| where AccessTime > DeviceCodeTime
| where AccessTime <= DeviceCodeTime + replayWindow
| where AuthIP != AccessIP
| extend TimeDeltaMinutes = datetime_diff('minute', AccessTime, DeviceCodeTime)
| project
    DeviceCodeTime,
    AccessTime,
    TimeDeltaMinutes,
    UserPrincipalName,
    AuthIP,
    AccessIP,
    ClientAppUsed,
    AccessApp,
    AppDisplayName,
    ConditionalAccessStatus
| sort by DeviceCodeTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Users who authenticate via device code on a mobile device and then immediately access resources from a corporate desktop or VPN endpoint will produce IP divergence without token theft.
- Users behind dynamic NAT or split-tunnel VPN configurations may show different IPs between the device code completion and subsequent resource access.
- Legitimate automation or service accounts using device code flow followed by API access from a different egress IP will match the pattern.

**Tuning notes:**
- Baseline device code flow volume over 7 days before enabling as a scheduled rule. Environments with legitimate device code use for IoT or shared kiosk scenarios will have higher baseline rates.
- Consider adding a ConditionalAccessStatus != 'success' filter on the subsequentAccess subquery to suppress cases where Conditional Access successfully evaluated and permitted the downstream session, reducing false positives from legitimate IP changes.
- Adjust replayWindow from 30 minutes to a shorter window (e.g., 10 minutes) if the environment has low legitimate device code use and attacker token reuse is expected to be near-immediate.
- Add an IP allowlist exclusion for known corporate VPN egress IPs, split-tunnel endpoints, and mobile carrier NAT ranges to reduce false positives from legitimate IP changes.

**Risks / caveats:**
- SigninLogs requires Entra ID (Azure AD) diagnostic settings to be configured to stream sign-in logs to the Sentinel workspace or Log Analytics workspace. If this connector is not enabled, the table will be empty.
- AuthenticationProtocol field population for device code flows depends on the Entra ID sign-in log schema version. Older tenants or legacy log formats may not populate this field consistently.
- The 30-minute replay window may miss token reuse that occurs after the window closes. Attackers who delay token replay beyond 30 minutes will evade this detection.
- IP divergence alone does not confirm token theft. Analyst review of the AuthIP and AccessIP geolocation, ASN, and hosting provider context is required to distinguish attacker infrastructure from legitimate user IP changes.

### Triage Runbook

**First 15 minutes:**
- Identify the user, the original device code authentication IP, and the later access IP; confirm the two locations are materially different.
- Check whether the downstream access occurred shortly after the device code completion and whether the accessed app is sensitive or unusual for the user.
- Contact the user through a trusted channel to confirm whether they initiated a device code sign-in and whether they approved any prompt or entered a code.
- Review Conditional Access outcome, client app, and user agent to see whether the later access looks like a normal user session or attacker replay.
- If the user denies the activity or the access is to a sensitive app, begin account protection steps immediately.

**Evidence to collect:**
- DeviceCodeTime, AccessTime, AuthIP, AccessIP, ClientAppUsed, AccessApp, AppDisplayName, and ConditionalAccessStatus.
- Geolocation, ASN, and hosting-provider context for both IPs to determine whether the access IP is a VPN, mobile carrier, cloud host, or residential network.
- Sign-in details for the user around the same period, including other successful or failed logins and any MFA prompts.
- Audit or activity logs for the accessed application to see what actions were performed after the suspected replay.
- User confirmation of whether they were shown a device code prompt, entered a code, or received any suspicious lure message.

**Pivot points:**
- SigninLogs for the same UserPrincipalName over the prior and subsequent 24 hours to identify other sign-ins from the same or different IPs.
- AuditLogs or application activity logs for the accessed app to determine what the token was used to do.
- Entra ID risky sign-in and risky user data, if available, to see whether Microsoft flagged the session as suspicious.
- Mailbox, Teams, or SharePoint access logs if the accessed app is one of those services and token misuse may have expanded laterally.
- Identity protection or conditional access logs to see whether the session bypassed or satisfied MFA and policy controls.

**Benign explanations:**
- The user may have completed device code authentication on one device and then accessed resources from a different corporate endpoint or VPN egress IP.
- Dynamic NAT, split-tunnel VPN, or mobile carrier routing can make the auth IP and access IP appear different even for legitimate use.
- A service account or automation workflow may legitimately use device code flow and then access resources from a separate egress path.
- The user may have reauthenticated after a network change, causing a normal IP change within the replay window.

**Escalation criteria:**
- Escalate immediately if the user denies initiating the device code flow or denies the downstream access.
- Escalate if the access IP is a cloud host, foreign location, or known anonymizer and the accessed resource is sensitive.
- Escalate if there are signs of mailbox rules, consent grants, token abuse, privilege changes, or data access beyond normal user behavior.
- Escalate if multiple users show the same lure or if the same access IP is reused across several accounts.

**Containment actions:**
- Disable the user session or revoke refresh tokens if token theft is suspected or confirmed.
- Force password reset and require MFA re-registration if the account may be compromised.
- Block the suspicious access IP or hosting range if it is clearly attacker infrastructure and not a corporate egress point.
- Review and remove any suspicious OAuth consent grants, app registrations, or mailbox rules associated with the account.

**Closure criteria:**
- The user confirms the device code flow and the downstream access is explained by a legitimate IP change or approved workflow.
- The access IP is verified as a corporate VPN, mobile carrier, or other expected egress path and no suspicious actions occurred.
- No risky actions, privilege changes, or unusual data access are found in the application logs.
- Any suspicious tokens have been revoked and follow-up monitoring shows no further anomalous access for the user.

<br/>
---
<br/>

## Detection 3: Entra ID Device Code Phishing - Automated Infrastructure Targeting Multiple Users from Shared IP

### Detection Opportunity

Automated phishing infrastructure generates multiple device code flow authentication attempts targeting distinct users from the same source IP within a short window, consistent with scaled EvilTokens-style campaigns.

### Intelligence Context

- Microsoft Security Blog: Unmasking EvilTokens: Getting to the root of device code phishing — [https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)
  - Context: Microsoft reported that automated phishing infrastructure with AI-assisted lures is used to scale device code phishing campaigns. Automated infrastructure produces a detectable pattern of multiple device code authentications targeting multiple distinct users from the same source IP or ASN within a compressed time window.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1566, T1566.002
- Products: Entra ID
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: Entra ID, T1566, T1566.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1566 Phishing/ T1566.002 Spearphishing Link (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- ASN-level grouping referenced in the source article as a detection dimension is not available as a direct SigninLogs field in all tenants. AutonomousSystemNumber may require enrichment via external IP intelligence.

**Required telemetry:**
- SigninLogs

### KQL

```kql
let lookback = 24h;
let userThreshold = 3;
SigninLogs
| where TimeGenerated >= ago(lookback)
| where AuthenticationProtocol =~ "deviceCode"
| where isnotempty(IPAddress)
| summarize
    DistinctUsers = dcount(UserPrincipalName),
    UserList = make_set(UserPrincipalName, 20),
    AttemptCount = count(),
    SuccessCount = countif(ResultType == 0),
    FailureCount = countif(ResultType != 0),
    ResultCodes = make_set(ResultType, 10)
    by IPAddress, bin(TimeGenerated, 10m)
| where DistinctUsers >= userThreshold
| extend SuccessRate = round(todouble(SuccessCount) / todouble(AttemptCount) * 100, 1)
| project
    TimeGenerated,
    IPAddress,
    DistinctUsers,
    UserList,
    AttemptCount,
    SuccessCount,
    FailureCount,
    SuccessRate,
    ResultCodes
| sort by DistinctUsers desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Corporate NAT gateways and VPN concentrators where many users share a single egress IP will routinely exceed the userThreshold of 3 distinct users in a 10-minute window.
- Cloud access security broker (CASB) or proxy infrastructure that proxies device code flows for multiple users will appear as a single high-volume IP.
- Shared office Wi-Fi or guest network egress IPs in environments where device code is used for legitimate device enrollment will match the pattern.

**Tuning notes:**
- Before scheduling, run this query over 7 days and review the top 20 IPs by DistinctUsers. Build an allowlist of known corporate NAT, VPN, and proxy egress IPs and add a where IPAddress !in (allowlist) filter.
- Increase userThreshold from 3 to a value above the 95th percentile of legitimate per-IP device code user counts observed in the environment.
- Reduce the time bin from 10 minutes to 5 minutes to increase specificity if the environment has high device code volume and the baseline analysis shows that legitimate shared-IP scenarios do not exceed 5-minute windows.
- Consider adding a filter for SuccessRate > 80 to focus on IPs where most device code attempts succeeded, which is more consistent with automated infrastructure that has already obtained victim cooperation than with brute-force or scanning behavior.

**Risks / caveats:**
- SigninLogs requires Entra ID diagnostic settings to be configured to stream sign-in logs to the Sentinel workspace. If this connector is not enabled, the table will be empty.
- AuthenticationProtocol field population for device code flows depends on the Entra ID sign-in log schema version. Older tenants or legacy log formats may not populate this field consistently.
- The userThreshold of 3 is likely to produce significant false positives in environments with shared egress IPs. Increasing to 10 or higher may be necessary before this query is useful as a scheduled rule.
- The 10-minute bin means that automated infrastructure spreading attempts across bin boundaries will evade detection. A sliding window approach using serialize and row_window_session would provide better coverage but increases query complexity and cost.

### Triage Runbook

**First 15 minutes:**
- Check whether the source IP belongs to a corporate VPN, proxy, CASB, or other known shared egress service before treating it as malicious.
- Review the distinct users and result codes to see whether the activity is broad, repetitive, and concentrated in a short time window.
- Look for a mix of successes and failures; repeated successful device code sign-ins across multiple users from the same IP are more concerning.
- Identify whether the users are from the same department, geography, or onboarding cohort, which may indicate a legitimate shared environment.
- If the IP is not recognized, start validating whether it appears in other sign-in or threat intelligence data as suspicious infrastructure.

**Evidence to collect:**
- IPAddress, DistinctUsers, UserList, AttemptCount, SuccessCount, FailureCount, SuccessRate, and ResultCodes.
- Geolocation and ASN for the source IP to determine whether it is a cloud host, proxy, VPN, or residential network.
- The list of affected users and whether they report receiving similar device code prompts or lures.
- Any associated sign-in details such as client app, user agent, and conditional access outcomes for the affected accounts.
- Historical sign-in volume from the same IP to determine whether this is a new pattern or a known enterprise egress point.

**Pivot points:**
- SigninLogs for the same IP over 7 to 30 days to establish whether the pattern is persistent or newly emergent.
- Threat intelligence or IP reputation sources to see whether the IP is associated with phishing, hosting, or anonymization services.
- Network/security logs for the IP to identify whether it is used by internal VPN, proxy, or remote access infrastructure.
- User-reported phishing submissions or help desk tickets mentioning device code prompts, login requests, or suspicious Microsoft pages.
- Conditional Access and identity protection logs for the affected users to see whether the sign-ins triggered risk signals.

**Benign explanations:**
- A corporate VPN, proxy, or shared office egress IP can legitimately produce multiple device code sign-ins from many users.
- Shared kiosk, lab, or training environments may generate repeated device code use from one IP.
- Legitimate onboarding or device enrollment campaigns can create clustered device code activity across multiple users.
- A CASB or secure web gateway may proxy sign-ins and make many users appear to originate from the same IP.

**Escalation criteria:**
- Escalate if the IP is not a known enterprise egress point and multiple distinct users show successful device code activity from it.
- Escalate if users report suspicious lures, fake login pages, or unexpected device code requests.
- Escalate if the IP is a cloud host, anonymizer, or foreign infrastructure and the success rate is high.
- Escalate if any affected account shows downstream anomalous access, consent grants, or mailbox/application abuse.

**Containment actions:**
- Block the suspicious IP at the identity or network layer if it is confirmed to be malicious infrastructure.
- Warn affected users to ignore device code prompts and report any future requests immediately.
- If any account shows compromise indicators, revoke sessions and reset credentials for those users.
- Add confirmed benign corporate egress IPs to an allowlist to reduce repeat noise after validation.

**Closure criteria:**
- The IP is confirmed as a legitimate corporate egress, proxy, or shared environment and the activity matches expected use.
- Affected users confirm the sign-ins were expected and no suspicious lures or follow-on access occurred.
- No risky sign-ins, token misuse, or anomalous application activity is found for the affected accounts.
- Any malicious IPs are blocked and no additional users are observed authenticating from the same source.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- F5 BIG-IP APM - Anomalous Inbound Traffic Spike Consistent with CVE-2026-94127 Exploitation: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.

**Schema / correlation keys:**
- Entra ID Device Code Phishing - Automated Infrastructure Targeting Multiple Users from Shared IP: Do not schedule yet; validate as an analyst-led hunt first.
- Entra ID Device Code Phishing - Automated Infrastructure Targeting Multiple Users from Shared IP: ASN-level grouping referenced in the source article as a detection dimension is not available as a direct SigninLogs field in all tenants. AutonomousSystemNumber may require enrichment via external IP intelligence.

**Shared-table notes:**
- SigninLogs: shared by Entra ID Device Code Phishing - Token Theft Followed by Anomalous Resource Access; Entra ID Device Code Phishing - Automated Infrastructure Targeting Multiple Users from Shared IP

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Entra ID Device Code Phishing - Token Theft Followed by Anomalous Resource Access.
2. Resolve environment-mapping detections next: F5 BIG-IP APM - Anomalous Inbound Traffic Spike Consistent with CVE-2026-94127 Exploitation.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Entra ID Device Code Phishing - Automated Infrastructure Targeting Multiple Users from Shared IP.

### Hunting Agenda and Promotion Criteria

- Entra ID Device Code Phishing - Automated Infrastructure Targeting Multiple Users from Shared IP: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- F5 BIG-IP APM - Anomalous Inbound Traffic Spike Consistent with CVE-2026-94127 Exploitation: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
