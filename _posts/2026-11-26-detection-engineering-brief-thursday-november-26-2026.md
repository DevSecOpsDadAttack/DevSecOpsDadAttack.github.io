---
layout: post
title: "Detection Engineering Brief - Thursday, November 26, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-11-26
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Storm-0940
  - Storm-3358
  - Onyx Sleet
  - Pearl Sleet
  - Crystal Typhoon
  - Salt Typhoon
  - ARTEX
  - T1110
  - T1110.003
---

## Detection Engineering Summary

This brief produced 1 detection candidate.

1 production candidate, 0 hunting-only, 0 require environment mapping, and 0 rejected.

1 detection include KQL. 1 include ATT&CK mappings. 1 include triage guidance.

Search metadata extracted for this run includes: Storm-0940, Storm-3358, Onyx Sleet, Pearl Sleet, Crystal Typhoon, Salt Typhoon, ARTEX, T1110, T1110.003.

No explicit IOCs were preserved for this run.

No gate-level deployment blockers were identified.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: ARTEX Credential Attack - Burst Failed Logons Across Multiple Accounts

### Detection Opportunity

Threat actors abusing ARTEX to accelerate credential attacks, producing bursts of failed authentications across multiple accounts from a single source IP within a short time window.

### Intelligence Context

- Microsoft Security Blog: What defenders need to know about ARTEX, the agentic AI framework threat actors abuse — [https://www.microsoft.com/en-us/security/blog/2026/11/25/what-defenders-need-to-know-artex-agentic-ai-framework-threat-actors-abuse/](https://www.microsoft.com/en-us/security/blog/2026/11/25/what-defenders-need-to-know-artex-agentic-ai-framework-threat-actors-abuse/)
  - Context: Multiple named threat actor groups including Storm-0940, Onyx Sleet, and Salt Typhoon were reported abusing the ARTEX agentic AI framework to accelerate credential attacks. The framework enables high-velocity authentication attempts across accounts and services, producing burst failed logon patterns observable in authentication telemetry.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-0940, Storm-3358, Onyx Sleet, Pearl Sleet, Crystal Typhoon, Salt Typhoon
- ATT&CK tags: T1110, T1110.003
- Products: ARTEX
- Platforms: Not specified
- Malware: Not specified
- Tools: ARTEX
- Search tags: Storm-0940, Storm-3358, Onyx Sleet, Pearl Sleet, Crystal Typhoon, Salt Typhoon, ARTEX, T1110, T1110.003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Both
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1110 Brute Force/ T1110.003 Password Spraying (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- SigninLogs, SecurityEvent, DeviceLogonEvents

### KQL

```kql
let lookback = 10m;
let failThreshold = 20;
let accountThreshold = 5;
let entraFails =
    SigninLogs
    | where TimeGenerated >= ago(1h)
    | where ResultType != 0
    | where isnotempty(IPAddress)
    | summarize
        FailCount = count(),
        DistinctAccounts = dcount(UserPrincipalName),
        Accounts = make_set(UserPrincipalName, 20),
        EarliestActivity = min(TimeGenerated),
        LatestActivity = max(TimeGenerated)
        by SourceIP = IPAddress, bin(TimeGenerated, lookback)
    | where FailCount >= failThreshold and DistinctAccounts >= accountThreshold
    | extend DataSource = "EntraID_SigninLogs";
let winFails =
    SecurityEvent
    | where TimeGenerated >= ago(1h)
    | where EventID == 4625
    | where isnotempty(IpAddress)
    | summarize
        FailCount = count(),
        DistinctAccounts = dcount(TargetAccount),
        Accounts = make_set(TargetAccount, 20),
        EarliestActivity = min(TimeGenerated),
        LatestActivity = max(TimeGenerated)
        by SourceIP = IpAddress, bin(TimeGenerated, lookback)
    | where FailCount >= failThreshold and DistinctAccounts >= accountThreshold
    | extend DataSource = "SecurityEvent_4625";
let deviceFails =
    DeviceLogonEvents
    | where TimeGenerated >= ago(1h)
    | where ActionType == "LogonFailed"
    | where isnotempty(RemoteIP)
    | summarize
        FailCount = count(),
        DistinctAccounts = dcount(AccountName),
        Accounts = make_set(AccountName, 20),
        EarliestActivity = min(TimeGenerated),
        LatestActivity = max(TimeGenerated)
        by SourceIP = RemoteIP, bin(TimeGenerated, lookback)
    | where FailCount >= failThreshold and DistinctAccounts >= accountThreshold
    | extend DataSource = "DeviceLogonEvents";
union entraFails, winFails, deviceFails
| summarize
    TotalSignals = count(),
    DataSources = make_set(DataSource),
    TotalFailCount = sum(FailCount),
    MaxDistinctAccounts = max(DistinctAccounts),
    AllAccounts = make_set(Accounts, 50),
    EarliestActivity = min(EarliestActivity),
    LatestActivity = max(LatestActivity)
    by SourceIP
| sort by TotalSignals desc, TotalFailCount desc
| project
    SourceIP,
    TotalSignals,
    DataSources,
    TotalFailCount,
    MaxDistinctAccounts,
    AllAccounts,
    EarliestActivity,
    LatestActivity
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Internal vulnerability scanners or authentication health-check systems testing multiple accounts from a single IP.
- Corporate NAT or VPN egress IPs where multiple users fail authentication simultaneously.
- Automated service account rotation scripts that briefly produce multi-account failures from a single orchestration host.
- Password expiry notification systems that attempt re-authentication across a batch of accounts.

**Tuning notes:**
- Increase failThreshold to 50 or higher in environments with frequent automated authentication failures from service accounts or monitoring tools.
- Increase accountThreshold to 10 or higher if the environment has many shared-credential service accounts that legitimately fail across multiple UPNs.
- Narrow the bin window from 10m to 5m to increase sensitivity to very short burst attacks at the cost of higher FP rate.
- Add a join against a watchlist of known internal egress IPs to suppress NAT/proxy false positives: '| join kind=leftanti (watchlist → project SourceIP = SearchKey) on SourceIP'.

**Risks / caveats:**
- SigninLogs requires the Entra ID (Azure Active Directory) diagnostic settings connector to be configured and streaming to the Sentinel workspace; if not connected, the entraFails branch returns no results.
- SecurityEvent collection of EventID 4625 requires the Windows Security Events data connector (AMA or MMA) to be deployed on domain controllers or member servers; environments without this connector will have no results from the winFails branch.
- DeviceLogonEvents is a Defender XDR table available in the Defender portal and in Sentinel only when the Microsoft Defender XDR connector is enabled; environments without this connector will have no results from the deviceFails branch.
- RemoteIP in DeviceLogonEvents is populated only for network logon events where the initiating IP is captured; local interactive logons will have a null or empty RemoteIP and will not contribute to per-IP aggregation.

### Triage Runbook

**First 15 minutes:**
- Confirm the source IP and identify whether it belongs to a known corporate VPN, proxy, scanner, monitoring system, or cloud host; if it is internal or expected infrastructure, treat as potential false positive until proven otherwise.
- Review the affected accounts for commonality: same department, same application, service accounts, privileged accounts, or geographically clustered users; look for evidence of targeted spraying versus a broad noisy source.
- Check the time pattern and failure type: rapid repeated failures across many accounts in a short window, especially with no successful logons, strongly supports password spraying or brute force.
- Look for any successful authentication from the same source IP or to any of the same accounts immediately before or after the burst; a success changes priority to possible account compromise.
- Assess whether the activity is continuing in real time; if the source IP is still generating failures, preserve evidence and prepare to escalate immediately.

**Evidence to collect:**
- SourceIP, DataSources, TotalFailCount, MaxDistinctAccounts, AllAccounts, EarliestActivity, and LatestActivity from the alert.
- For each affected account, collect the last successful sign-in time, recent password reset activity, MFA prompts, and any account lockout events.
- Authentication details for the source IP across SigninLogs, SecurityEvent 4625, and DeviceLogonEvents to determine whether the activity is cloud, on-prem, or endpoint-originated.
- Any related sign-in properties such as user agent, location, device, authentication method, and conditional access result if available.
- Whether the source IP maps to a known NAT, VPN, scanner, or service host in asset inventory or watchlists.

**Pivot points:**
- SigninLogs: pivot on IPAddress = SourceIP and review ResultType, UserPrincipalName, AppDisplayName, Location, and Conditional Access outcomes.
- SecurityEvent: pivot on IpAddress = SourceIP and review EventID 4625 details, TargetAccount, workstation name, and logon type.
- DeviceLogonEvents: pivot on RemoteIP = SourceIP and review ActionType, AccountName, device name, and initiating process context if available.
- Identity and asset inventory tables or watchlists: confirm whether SourceIP is a known egress point, scanner, or managed service host.
- Recent successful sign-ins for the same accounts to identify whether any account was accessed successfully after the failed burst.

**Benign explanations:**
- A vulnerability scanner or authentication health-check system testing multiple accounts from one host.
- A corporate NAT, VPN concentrator, or proxy causing many legitimate users to appear as one source IP.
- A password rotation, onboarding, or service-account automation script that briefly retries multiple credentials.
- A password-expiry notification or SSO misconfiguration causing repeated failures across a batch of users.

**Escalation criteria:**
- Escalate immediately if the source IP is unknown, external, or not tied to approved infrastructure and the failures are still ongoing.
- Escalate if any affected account is privileged, administrative, or a service account with broad access.
- Escalate if there is any successful logon from the same source IP or to one of the targeted accounts during the same window.
- Escalate if the pattern spans multiple business units or many unrelated accounts, indicating broad password spraying rather than a localized issue.
- Escalate if there are signs of follow-on activity such as MFA fatigue prompts, password reset attempts, or new device enrollment tied to the same accounts.

**Containment actions:**
- If the source IP is confirmed malicious or highly suspicious, block it at the relevant perimeter controls, conditional access, or firewall layer.
- Force password reset and session revocation for any account that shows a successful sign-in from the suspicious source or other compromise indicators.
- Temporarily disable or protect high-risk accounts that were targeted repeatedly, especially privileged or service accounts, while investigation continues.
- Increase monitoring on the affected accounts and source IP for additional authentication attempts, token use, or mailbox/application access.
- Coordinate with identity administrators to review lockout thresholds and MFA enforcement if the attack is still active.

**Closure criteria:**
- The source IP is validated as approved infrastructure, and the activity matches expected scanner, VPN, or automation behavior.
- No successful authentications, no MFA abuse, and no secondary suspicious activity are found for the targeted accounts.
- The affected accounts are confirmed healthy after review, with no evidence of compromise, password reset abuse, or unauthorized access.
- An allowlist or suppression is documented for the known benign source, with supporting evidence and owner approval.
- The alert is closed only after the burst pattern is explained and the environment-specific threshold is confirmed to be appropriate or tuned.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

No hard pre-deployment blockers were identified.

**Shared-table notes:**
- No major shared table dependency identified across this run.

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: ARTEX Credential Attack - Burst Failed Logons Across Multiple Accounts.

### Hunting Agenda and Promotion Criteria

- No hunting-only or environment-mapping detections require a separate hunting agenda in this run.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
