---
layout: post
title: "Detection Engineering Brief - Friday, August 21, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-08-21
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Microsoft Entra
  - PowerShell
  - T1110
  - T1110.003
---

## Detection Engineering Summary

This brief produced 1 detection candidate.

1 production candidate, 0 hunting-only, 0 require environment mapping, and 0 rejected.

1 detection include KQL. 1 include ATT&CK mappings. 1 include triage guidance.

Search metadata extracted for this run includes: Microsoft Entra, PowerShell, T1110, T1110.003.

No explicit IOCs were preserved for this run.

No gate-level deployment blockers were identified.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Entra Password Spray - Many Failed Logins Across Distinct Accounts from Single IP

### Detection Opportunity

Password spray activity producing high volumes of failed Entra authentication attempts across many distinct user accounts originating from a single source IP within a short time window.

### Intelligence Context

- SANS ISC: Even MOAR Powershell, looking at Entra logins - the good, the bad and the password sprays, (Fri, Aug 21st) — [https://isc.sans.edu/diary/rss/33268](https://isc.sans.edu/diary/rss/33268)
  - Context: The SANS ISC article explicitly identifies password spray activity against Microsoft Entra logins, describing a pattern of many failed authentication attempts across distinct accounts. The article uses PowerShell to surface this pattern from Entra sign-in logs, confirming the telemetry source and the spray signature.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1110, T1110.003
- Products: Microsoft Entra
- Platforms: Not specified
- Malware: Not specified
- Tools: PowerShell
- Search tags: Microsoft Entra, PowerShell, T1110, T1110.003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1110 Brute Force/ T1110.003 Password Spraying (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- SigninLogs

### KQL

```kql
let lookback = 20m;
let failureThreshold = 10;
let privateRanges = dynamic(["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.", "127.", "::1"]);
SigninLogs
| where TimeGenerated >= ago(lookback)
| where ResultType != 0
| where isnotempty(IPAddress)
| where not(IPAddress has_any (privateRanges))
| summarize
    DistinctAccounts = dcount(UserPrincipalName),
    FailedAttempts = count(),
    AccountList = make_set(UserPrincipalName, 20),
    AppList = make_set(AppDisplayName, 10),
    UserAgentList = make_set(UserAgent, 10),
    LocationList = make_set(Location, 10),
    UniqueErrorCodes = make_set(ResultType, 20),
    UniqueErrorDescriptions = make_set(ResultDescription, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by IPAddress
| where DistinctAccounts >= failureThreshold
| where FailedAttempts >= failureThreshold
| extend SprayDurationMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| project
    IPAddress,
    DistinctAccounts,
    FailedAttempts,
    SprayDurationMinutes,
    UniqueErrorCodes,
    UniqueErrorDescriptions,
    AccountList,
    AppList,
    UserAgentList,
    LocationList,
    FirstSeen,
    LastSeen
| sort by DistinctAccounts desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Large corporate NAT or proxy egress IPs where many users share a single public IP and experience legitimate authentication failures simultaneously.
- Automated testing or CI/CD pipelines that authenticate many service accounts from a single runner IP.
- MFA enforcement rollouts that cause a burst of failures across many accounts from a helpdesk or IT admin IP.
- Third-party identity federation or SSO brokers that proxy authentication from a single IP on behalf of many users.

**Tuning notes:**
- Start with failureThreshold = 10 and review the first week of alerts to establish a baseline. Adjust upward if shared egress IPs dominate the alert queue.
- Add a where ResultType in (50126, 50053, 50055, 50056) clause to restrict to credential-failure error codes and reduce noise from infrastructure or MFA-related failures.
- Maintain a watchlist of known corporate NAT, VPN, and proxy egress IPs and add a join or anti-join to suppress those IPs from alerting.
- For slow-and-low spray detection, run a parallel scheduled rule with lookback = 4h and failureThreshold = 30 to catch distributed campaigns.

**Risks / caveats:**
- SigninLogs requires the Microsoft Entra ID (formerly Azure Active Directory) data connector to be enabled and ingesting into the Sentinel workspace. If the connector is absent, the table will not exist and the query will return no results.
- Non-interactive and service principal sign-ins appear in AADNonInteractiveUserSignInLogs and AADServicePrincipalSignInLogs respectively, not in SigninLogs. Password spray targeting service accounts or non-interactive flows will not be detected by this query.
- The 20-minute lookback window will miss slow-and-low spray campaigns that distribute attempts across hours or days. Extend the lookback or run a parallel hunting query with a longer window if slow spray is a concern.
- Ingestion latency in SigninLogs (typically 5–15 minutes) may cause the most recent events to fall outside the lookback window at query execution time. Consider extending the lookback to 30 minutes and accepting slightly stale results.

### Triage Runbook

**First 15 minutes:**
- Confirm the alert is not from a known corporate NAT, VPN, proxy, or identity broker IP by checking the source against your approved egress allowlist.
- Review the AccountList for patterns: privileged accounts, executives, helpdesk/admin accounts, or many users from the same department/tenant segment.
- Check whether any sign-ins from the same IP or nearby time window succeeded after the failures, especially for the same AppDisplayName or UserPrincipalName.
- Inspect UserAgentList and LocationList for automation fingerprints such as Python-requests, curl, PowerShell, unusual browser strings, or a single unexpected geography.
- Validate the ResultType/ResultDescription mix to confirm credential failures versus MFA, conditional access, or account lockout noise.

**Evidence to collect:**
- IPAddress, FirstSeen, LastSeen, SprayDurationMinutes, DistinctAccounts, FailedAttempts, UniqueErrorCodes, and UniqueErrorDescriptions from the alert.
- Full AccountList with account roles, group membership, and whether any are privileged or recently created.
- Any successful Entra sign-ins from the same IP, same user agent, or same location within the preceding and following 24 hours.
- Conditional Access status, app targeted, and whether failures were for a single app or multiple apps.
- Threat intelligence or reputation results for the source IP, plus any prior incidents involving the same IP or user agent.

**Pivot points:**
- SigninLogs for the source IP, the affected accounts, and any successful authentications around the alert window.
- AuditLogs for password resets, MFA method changes, consent grants, role assignments, or other account changes affecting listed users.
- IdentityProtectionRiskEvents or IdentityProtectionRiskDetections for risk flags on the impacted accounts.
- AADNonInteractiveUserSignInLogs and AADServicePrincipalSignInLogs to see whether the same source is also targeting non-interactive or service principal authentication.
- Microsoft Sentinel incident history and watchlists for prior alerts or known benign egress IPs.

**Benign explanations:**
- A shared corporate NAT, VPN concentrator, or proxy caused many legitimate users to fail authentication from one public IP.
- A helpdesk or IT admin performed bulk testing, onboarding, or MFA rollout activities that generated repeated failures.
- A third-party SSO or federation broker proxied many user authentications from a single source IP.
- A misconfigured script, automation runner, or CI/CD job attempted repeated logins with stale credentials.

**Escalation criteria:**
- Any successful sign-in for one or more targeted accounts after the spray, especially from the same IP or user agent.
- Evidence that privileged, executive, or high-impact accounts were included in the spray set.
- The source IP is external, not allowlisted, and shows clear automation indicators or threat intelligence matches.
- Follow-on activity appears, such as MFA fatigue prompts, password resets, consent abuse, mailbox access, or role changes.
- Multiple accounts show risk detections, lockouts, or suspicious sign-ins tied to the same source or timeframe.

**Containment actions:**
- Block the source IP at the relevant perimeter or identity control if it is confirmed malicious and not a shared business egress point.
- Force password reset and revoke sessions for any account that successfully authenticated or shows strong compromise indicators.
- Require MFA re-registration or authentication strength review for impacted accounts if there is evidence of credential compromise.
- Disable or temporarily protect high-value accounts that were successfully accessed until investigation is complete.
- Add the source IP and associated user agent to a watchlist or blocklist for immediate suppression and future correlation.

**Closure criteria:**
- The source IP is confirmed as a benign shared egress or approved automation source and no suspicious follow-on activity is found.
- No successful authentications occurred for any targeted accounts during or after the spray window.
- Impacted accounts were reviewed and show no risk detections, password changes, MFA changes, or anomalous activity.
- The alerting threshold or allowlist has been updated to suppress the validated benign source without hiding true spray behavior.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

No hard pre-deployment blockers were identified.

**Shared-table notes:**
- No major shared table dependency identified across this run.

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Entra Password Spray - Many Failed Logins Across Distinct Accounts from Single IP.

### Hunting Agenda and Promotion Criteria

- No hunting-only or environment-mapping detections require a separate hunting agenda in this run.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
