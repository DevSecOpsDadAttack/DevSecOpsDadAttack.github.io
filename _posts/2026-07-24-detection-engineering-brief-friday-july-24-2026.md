---
layout: post
title: "Detection Engineering Brief - Friday, July 24, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-24
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-16232
  - Check Point SmartConsole
  - Check Point Security Management
  - T1190
---

## Detection Engineering Summary

This brief produced 2 detection candidates.

0 production candidates, 0 hunting-only, 2 require environment mapping, and 0 rejected.

2 detections include KQL. 2 include ATT&CK mappings. 2 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-16232, Check Point SmartConsole, Check Point Security Management, T1190.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: CVE-2026-16232 - Check Point SmartConsole Admin Auth Followed by Policy Modification; CVE-2026-16232 - Unauthenticated Token Acquisition on Check Point SmartConsole from Novel Source IP.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: CVE-2026-16232 - Check Point SmartConsole Admin Auth Followed by Policy Modification

### Detection Opportunity

Attacker authenticates to Check Point management server with full administrative privileges after authentication bypass, then modifies security policies or configurations

### Intelligence Context

- Rapid7: CVE-2026-16232: Critical Check Point SmartConsole Authentication Bypass Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-16232-critical-check-point-smartconsole-authentication-bypass-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-16232-critical-check-point-smartconsole-authentication-bypass-exploited-in-the-wild)
  - Context: CVE-2026-16232 allows an unauthenticated remote attacker to obtain an application login token and authenticate to the Check Point management server with full administrative privileges, enabling modification of security policies and configurations. This vulnerability is actively exploited in the wild.

### Search Metadata

- CVEs: CVE-2026-16232
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Check Point SmartConsole, Check Point Security Management
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-16232, Check Point SmartConsole, Check Point Security Management, T1190

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- CommonSecurityLog Activity field values for Check Point authentication and policy change events are not standardized; the specific strings used depend on the Check Point product version, audit verbosity settings, and CEF connector configuration. If Activity values differ from those in the query, both the auth and policy change sub-queries will return no results.
- Check Point CEF connector must be deployed and actively forwarding SmartConsole and Security Management audit logs to Sentinel. Without this connector, the table will contain no relevant Check Point entries.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
let lookback = 2d;
let baselineStart = 30d;
let correlationWindowMinutes = 30;
let adminAuthEvents = CommonSecurityLog
    | where TimeGenerated >= ago(lookback)
    | where DeviceVendor has_any ("Check Point", "CheckPoint")
    | where Activity has_any ("Login", "Authenticated", "Admin login", "Management login")
    | where DeviceAction != "Failure"
    | where DestinationPort in (18190, 19009, 443)
    | summarize AuthTime = min(TimeGenerated) by SourceIP, AccountName, Activity, DeviceAction, LogSeverity, DestinationPort;
let policyChangeEvents = CommonSecurityLog
    | where TimeGenerated >= ago(lookback)
    | where DeviceVendor has_any ("Check Point", "CheckPoint")
    | where Activity has_any ("Policy install", "Rule modification", "Object modified", "Policy change", "Install policy", "Delete rule", "Add rule")
    | project ChangeTime = TimeGenerated, SourceIP, AccountName, ChangeActivity = Activity, Message;
let knownAdminIPs = CommonSecurityLog
    | where TimeGenerated between (ago(baselineStart) .. ago(lookback))
    | where DeviceVendor has_any ("Check Point", "CheckPoint")
    | where Activity has_any ("Login", "Authenticated", "Admin login", "Management login")
    | where DeviceAction != "Failure"
    | summarize by SourceIP;
adminAuthEvents
| join kind=inner policyChangeEvents on SourceIP
| where ChangeTime >= AuthTime and ChangeTime <= datetime_add('minute', correlationWindowMinutes, AuthTime)
| join kind=leftanti knownAdminIPs on SourceIP
| extend TimeDeltaMinutes = datetime_diff('minute', ChangeTime, AuthTime)
| project
    AuthTime,
    ChangeTime,
    TimeDeltaMinutes,
    SourceIP,
    AccountName,
    Activity,
    ChangeActivity,
    Message,
    LogSeverity,
    DestinationPort
| order by AuthTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrators connecting from new workstations, VPN exit nodes, or jump hosts not previously seen in the 30-day baseline will trigger this alert.
- Scheduled policy deployments or automated management tasks performed from IPs not in the baseline will generate alerts.
- First-time connections after the CEF connector is newly deployed will appear novel for all source IPs until the baseline accumulates.

**Tuning notes:**
- Validate actual Activity field values in your environment before scheduling: CommonSecurityLog → where DeviceVendor has_any ('Check Point','CheckPoint') → summarize count() by Activity → order by count_ desc
- Confirm DestinationPort values match your Check Point management interface configuration; default SmartConsole ports are 18190 and 19009.
- Adjust correlationWindowMinutes based on observed attacker dwell time patterns in your environment.
- Consider adding an allowlist of known management automation service accounts to AccountName exclusions to reduce noise from scheduled policy deployments.

**Risks / caveats:**
- CommonSecurityLog Activity field values for Check Point authentication and policy change events are not standardized; the specific strings used depend on the Check Point product version, audit verbosity settings, and CEF connector configuration. If Activity values differ from those in the query, both the auth and policy change sub-queries will return no results.
- DeviceVendor normalization between 'Check Point' and 'CheckPoint' must be confirmed in the actual ingested data; a mismatch will cause all sub-queries to return empty sets.
- The knownAdminIPs baseline requires at least 30 days of prior Check Point authentication logs in CommonSecurityLog. In environments where the connector was recently deployed, the leftanti join will produce excessive false positives as all IPs will appear novel.
- Check Point CEF connector must be deployed and actively forwarding SmartConsole and Security Management audit logs to Sentinel. Without this connector, the table will contain no relevant Check Point entries.

### Triage Runbook

**First 15 minutes:**
- Confirm the SourceIP, AccountName, AuthTime, ChangeTime, and TimeDeltaMinutes to verify the authentication and policy change are linked and occurred within the expected window.
- Review the Message and ChangeActivity fields to identify exactly what was modified, including rule additions, deletions, object changes, or policy installation.
- Check whether the source IP is a known admin workstation, VPN exit node, jump host, or automation host that was missed by the baseline.
- Validate whether the AccountName is a legitimate administrator, service account, or an unexpected identity associated with the management server.
- Assess whether the change was immediately followed by additional policy edits, new admin creation, or other management activity that suggests active compromise.

**Evidence to collect:**
- Check Point audit logs for the same SourceIP and AccountName covering at least 24 hours before and after the alert.
- The exact policy objects, rules, and configuration items changed, including before-and-after values if available.
- Authentication details for the admin login, including destination port, device action, log severity, and any session identifiers present in the Message field.
- Any concurrent logins or policy changes from other source IPs around the same time to determine whether this was a coordinated or automated action.
- Change approval records, maintenance tickets, or change window evidence for the affected time period.

**Pivot points:**
- CommonSecurityLog filtered to the same SourceIP and AccountName for all Check Point Activity values in the surrounding 24 hours.
- CommonSecurityLog filtered to policy-related Activity values such as Policy install, Rule modification, Object modified, Policy change, Install policy, Delete rule, and Add rule.
- CommonSecurityLog filtered to the same DestinationPort values to identify other management sessions from the same host.
- Identity or PAM logs for the AccountName to confirm whether the login was expected and whether MFA or jump-host controls were used.
- Change management or ticketing system records for the time of the policy modification.

**Benign explanations:**
- A legitimate administrator made an approved policy change from a new workstation, VPN pool address, or jump host not yet present in the baseline.
- An automated deployment or scheduled management task performed a policy install or rule update from a non-baselined source IP.
- Connector onboarding or incomplete historical data caused a normal admin source IP to appear novel.

**Escalation criteria:**
- The policy change was not associated with an approved change request or maintenance window.
- The SourceIP is external, unfamiliar, or geolocated outside the organization’s normal administrative footprint.
- The AccountName is unexpected, privileged beyond the user’s role, or shows signs of misuse such as multiple rapid changes.
- The alert is followed by additional suspicious management activity, new admin creation, or evidence of broader tampering.

**Containment actions:**
- If the change is unauthorized or cannot be quickly validated, isolate the Check Point management server from administrative access paths and restrict SmartConsole access to known-good admin hosts.
- Disable or reset the affected administrative account if compromise is suspected and coordinate with the firewall team to preserve access for incident response.
- Revert unauthorized policy or configuration changes using approved backup or change-control procedures.
- Preserve relevant Check Point audit logs and management server evidence before making disruptive changes.

**Closure criteria:**
- The login and policy change are confirmed as authorized and match a valid change record.
- The source IP is validated as a known administrative or automation host and the activity is consistent with normal operations.
- No additional suspicious Check Point management activity is observed during the surrounding investigation window.
- Any unauthorized changes have been reverted and the affected account or host has been remediated if needed.

<br/>
---
<br/>

## Detection 2: CVE-2026-16232 - Unauthenticated Token Acquisition on Check Point SmartConsole from Novel Source IP

### Detection Opportunity

Unauthenticated remote attacker obtains an application login token for Check Point SmartConsole from a source IP with no prior administrative session history

### Intelligence Context

- Rapid7: CVE-2026-16232: Critical Check Point SmartConsole Authentication Bypass Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-16232-critical-check-point-smartconsole-authentication-bypass-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-16232-critical-check-point-smartconsole-authentication-bypass-exploited-in-the-wild)
  - Context: CVE-2026-16232 is actively exploited in the wild and allows an unauthenticated attacker to obtain an application login token without valid credentials, bypassing normal authentication to the Check Point management server. Detection of admin-level authentication from previously unseen source IPs is a key indicator of exploitation.

### Search Metadata

- CVEs: CVE-2026-16232
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Check Point SmartConsole, Check Point Security Management
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-16232, Check Point SmartConsole, Check Point Security Management, T1190

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- CommonSecurityLog Activity field values for Check Point authentication events are not standardized; the specific strings depend on the Check Point product version, audit verbosity, and CEF connector configuration. If Activity values differ from those in the query, the detection will return no results.
- Check Point CEF connector must be deployed and actively forwarding SmartConsole and Security Management audit logs to Sentinel. Without this connector, the table will contain no relevant Check Point entries.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
let lookback = 1d;
let baselineWindow = 30d;
let historicAdminIPs = CommonSecurityLog
    | where TimeGenerated between (ago(baselineWindow) .. ago(lookback))
    | where DeviceVendor has_any ("Check Point", "CheckPoint")
    | where Activity has_any ("Login", "Authenticated", "Admin login", "Management login")
    | where DeviceAction != "Failure"
    | summarize by SourceIP;
CommonSecurityLog
| where TimeGenerated >= ago(lookback)
| where DeviceVendor has_any ("Check Point", "CheckPoint")
| where Activity has_any ("Login", "Authenticated", "Admin login", "Management login")
| where DeviceAction != "Failure"
| where DestinationPort in (18190, 19009, 443)
| join kind=leftanti historicAdminIPs on SourceIP
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    AuthAttemptCount = count(),
    AccountNames = make_set(AccountName, 10),
    Activities = make_set(Activity, 10),
    LogSeverities = make_set(LogSeverity, 5),
    DeviceActions = make_set(DeviceAction, 5)
    by SourceIP, DestinationPort
| project
    FirstSeen,
    LastSeen,
    SourceIP,
    DestinationPort,
    AuthAttemptCount,
    AccountNames,
    Activities,
    LogSeverities,
    DeviceActions
| order by FirstSeen desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrators connecting from new workstations, VPN exit nodes, or jump hosts not previously seen in the 30-day baseline.
- New administrators or contractors accessing the management server for the first time.
- Automated management tools or scripts connecting from IPs not in the historical baseline.
- All source IPs will appear novel during the first 30 days after the CEF connector is deployed.

**Tuning notes:**
- Validate actual Activity field values in your environment before scheduling: CommonSecurityLog → where DeviceVendor has_any ('Check Point','CheckPoint') → summarize count() by Activity → order by count_ desc
- Validate DeviceAction field population: CommonSecurityLog → where DeviceVendor has_any ('Check Point','CheckPoint') → summarize count() by DeviceAction
- Confirm DestinationPort values match your Check Point management interface configuration; default SmartConsole ports are 18190 and 19009.
- Extend the baselineWindow beyond 30 days if the environment has infrequent but legitimate admin access from rotating IPs.

**Risks / caveats:**
- CommonSecurityLog Activity field values for Check Point authentication events are not standardized; the specific strings depend on the Check Point product version, audit verbosity, and CEF connector configuration. If Activity values differ from those in the query, the detection will return no results.
- DeviceAction field population is not guaranteed across all Check Point CEF connector versions; if DeviceAction is null or uses non-standard values, the success/failure filter will not function correctly.
- DeviceVendor normalization between 'Check Point' and 'CheckPoint' must be confirmed in the actual ingested data.
- Check Point CEF connector must be deployed and actively forwarding SmartConsole and Security Management audit logs to Sentinel. Without this connector, the table will contain no relevant Check Point entries.

### Triage Runbook

**First 15 minutes:**
- Confirm the SourceIP, FirstSeen, LastSeen, AuthAttemptCount, AccountNames, and DestinationPort to understand the scope and repetition of the activity.
- Review the Activities and DeviceActions to verify the event reflects a successful admin-level authentication rather than a failed or routine login.
- Check whether the source IP belongs to a known VPN pool, jump host, PAM system, or newly deployed admin workstation that would legitimately appear novel.
- Look for follow-on Check Point management actions from the same SourceIP or AccountNames, especially policy changes, object edits, or additional logins.
- Determine whether the login occurred during a maintenance window or change event that would explain a first-time administrative connection.

**Evidence to collect:**
- All CommonSecurityLog entries for the SourceIP and AccountNames around the alert time, including prior failed attempts and subsequent management actions.
- The destination port and any session details to confirm the login path used to reach the management interface.
- Historical Check Point authentication activity for the SourceIP over at least 30 days to validate whether the IP is truly novel.
- Identity, VPN, PAM, or jump-host logs tied to the AccountNames to confirm whether the login was expected and whether MFA or privileged access controls were used.
- Any policy changes, object modifications, or admin actions that occurred shortly after the login.

**Pivot points:**
- CommonSecurityLog for the same SourceIP across the full lookback window to identify repeated auth attempts or later policy changes.
- CommonSecurityLog for the same AccountNames to determine whether the account is used elsewhere and whether the login pattern is normal.
- CommonSecurityLog filtered to Check Point Activity values related to policy install, rule modification, object modified, policy change, delete rule, and add rule.
- VPN, PAM, or bastion host logs to validate whether the source IP maps to an approved administrative access path.
- Asset inventory or CMDB records to determine whether the source IP is a managed admin endpoint.

**Benign explanations:**
- A legitimate administrator connected from a new workstation, VPN exit node, or jump host not yet present in the 30-day baseline.
- A new administrator, contractor, or support engineer accessed the management server for the first time.
- Automated management tooling or a scheduled task used a previously unseen source IP.
- The environment recently onboarded Check Point logs, making all historical source IPs appear novel.

**Escalation criteria:**
- The source IP is external, unrecognized, or not associated with any approved admin access path.
- The login is followed by policy changes, object edits, or other privileged management actions.
- Multiple rapid authentication events from the same novel source IP suggest automated exploitation or repeated token acquisition attempts.
- The account used is highly privileged, unexpected, or not normally used for direct management access.

**Containment actions:**
- If the login cannot be quickly validated as legitimate, block the source IP at the perimeter or management access layer while preserving evidence.
- Disable or rotate credentials for the affected administrative account if compromise is suspected.
- Restrict Check Point management access to known-good admin networks and jump hosts until the investigation is complete.
- Preserve Check Point audit logs and related identity logs before making changes that could disrupt evidence.

**Closure criteria:**
- The source IP is confirmed as a legitimate administrative or automation host and the login is authorized.
- No subsequent suspicious policy changes or privileged actions are observed from the same source IP or account.
- The activity aligns with a documented maintenance event, onboarding activity, or approved first-time access.
- Any suspicious account or host has been remediated and no further indicators of exploitation are present.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- CVE-2026-16232 - Check Point SmartConsole Admin Auth Followed by Policy Modification: CommonSecurityLog Activity field values for Check Point authentication and policy change events are not standardized; the specific strings used depend on the Check Point product version, audit verbosity settings, and CEF connector configuration. If Activity values differ from those in the query, both the auth and policy change sub-queries will return no results.
- CVE-2026-16232 - Check Point SmartConsole Admin Auth Followed by Policy Modification: Check Point CEF connector must be deployed and actively forwarding SmartConsole and Security Management audit logs to Sentinel. Without this connector, the table will contain no relevant Check Point entries.
- CVE-2026-16232 - Unauthenticated Token Acquisition on Check Point SmartConsole from Novel Source IP: CommonSecurityLog Activity field values for Check Point authentication events are not standardized; the specific strings depend on the Check Point product version, audit verbosity, and CEF connector configuration. If Activity values differ from those in the query, the detection will return no results.
- CVE-2026-16232 - Unauthenticated Token Acquisition on Check Point SmartConsole from Novel Source IP: Check Point CEF connector must be deployed and actively forwarding SmartConsole and Security Management audit logs to Sentinel. Without this connector, the table will contain no relevant Check Point entries.

**Shared-table notes:**
- CommonSecurityLog: shared by CVE-2026-16232 - Check Point SmartConsole Admin Auth Followed by Policy Modification; CVE-2026-16232 - Unauthenticated Token Acquisition on Check Point SmartConsole from Novel Source IP

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: CVE-2026-16232 - Check Point SmartConsole Admin Auth Followed by Policy Modification; CVE-2026-16232 - Unauthenticated Token Acquisition on Check Point SmartConsole from Novel Source IP.

### Hunting Agenda and Promotion Criteria

- CVE-2026-16232 - Check Point SmartConsole Admin Auth Followed by Policy Modification: CommonSecurityLog Activity field values for Check Point authentication and policy change events are not standardized; the specific strings used depend on the Check Point product version, audit verbosity settings, and CEF connector configuration. If Activity values differ from those in the query, both the auth and policy change sub-queries will return no results.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- CVE-2026-16232 - Unauthenticated Token Acquisition on Check Point SmartConsole from Novel Source IP: CommonSecurityLog Activity field values for Check Point authentication events are not standardized; the specific strings depend on the Check Point product version, audit verbosity, and CEF connector configuration. If Activity values differ from those in the query, the detection will return no results.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
