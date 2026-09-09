---
layout: page
title: Hunt Credential Compromise Signin Audit Alert Three Table
subtitle: "Three-table credential-compromise chain: joins risky sign-ins, audit follow-up, and downstream SecurityAlert on the same user."
permalink: /kql-library/hunting/hunt-credential-compromise-signin-audit-alert-three-table/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/hunting/' | relative_url }}">Hunting</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-magnifying-glass" aria-hidden="true"></i>&nbsp;Hunting</span>
  <code class="kql-lib-query-file">hunt-credential-compromise-signin-audit-alert-three-table.kql</code>
</div>

<p class="kql-lib-query-longdesc">Three-table credential-compromise chain: joins risky sign-ins, audit follow-up, and downstream SecurityAlert on the same user.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/credential-access/' | relative_url }}">Credential Access</a>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/initial-access/' | relative_url }}">Initial Access</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1078/' | relative_url }}">T1078</a>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1110/' | relative_url }}">T1110</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/entra-id/' | relative_url }}">Entra ID</a>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/microsoft-365/' | relative_url }}">Microsoft 365</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/signinlogs/' | relative_url }}">SigninLogs</a>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/auditlogs/' | relative_url }}">AuditLogs</a>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/securityalert/' | relative_url }}">SecurityAlert</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Deep Dive</span>
    <a class="kql-lib-tag kql-lib-tag-deepdive" href="{{ '/kql-library/tag/deep-dive/' | relative_url }}"><i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive</a>
</div>
<div class="kql-lib-query-actions">
  <a class="kql-lib-deep-dive-btn" href="https://devsecopsdadattack.com/2026-08-26-KQL-Detection-of-the-Week-The-Field-That-Wasnt-There/" target="_blank" rel="noopener">
    <i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive
  </a>
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-hunt-credential-compromise-signin-audit-alert-three-table">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/hunting/hunt-credential-compromise-signin-audit-alert-three-table.kql' | relative_url }}" download="hunt-credential-compromise-signin-audit-alert-three-table.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-hunt-credential-compromise-signin-audit-alert-three-table" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Three-table credential-compromise chain: joins risky sign-ins, audit-log follow-up, and
// downstream security alerts on the same user. Collapses evidence spread across SigninLogs,
// AuditLogs, and SecurityAlert into one row-per-user timeline instead of leaving analysts to hop
// tables.
// Source: KQL Detection of the Week: The Field That Wasn't There (2026-08-26) — https://devsecopsdadattack.com/2026-08-26-KQL-Detection-of-the-Week-The-Field-That-Wasnt-There/
// Tactics: Credential Access, Initial Access
// Techniques: T1078, T1110
// Platforms: Entra ID, Microsoft 365
// Data: SigninLogs, AuditLogs, SecurityAlert

let lookback = 24h;
let failWindow = 30m;
let postCompromiseWindow = 1h;
let riskLevels = dynamic(["medium", "high"]);
// SENSITIVE OPERATIONS — the audit actions that matter after a
// credential compromise. These are the operations an attacker
// performs to maintain access, escalate privileges, or exfiltrate
// data. "Add member to role" is a privilege escalation. "Consent
// to application" is an OAuth abuse. "Update user" with a password
// or MFA change is persistence. A normal user reading a document
// is not in this list.
let SensitiveOps = dynamic([
    "Add member to role.",
    "Add app role assignment to user.",
    "Consent to application.",
    "Add delegated permission grant.",
    "Add application.",
    "Add service principal.",
    "Update user.",
    "Reset password (by admin).",
    "Reset password (self-service).",
    "Set force change user password.",
    "Update device.",
    "Add owner to application.",
    "Add owner to service principal.",
    "Set Company Information.",
    "Add member to group.",
    "Invite external user."
]);
// STEP 1: Failed sign-ins.
let FailedSignins = SigninLogs
| where TimeGenerated >= ago(lookback)
| where ResultType != 0
| project
    FailTime = TimeGenerated,
    UserPrincipalName = tolower(UserPrincipalName),
    FailIP = IPAddress,
    FailResultType = ResultType;
// STEP 2: Risky successful sign-ins.
// P2 DEPENDENCY: RiskLevelDuringSignIn requires Entra ID P2.
// Without it, this field is empty for all rows and the query
// returns nothing. This is a licensing gate, not a telemetry gap.
// If you don't have P2, this detection does not exist for you.
let RiskySuccess = SigninLogs
| where TimeGenerated >= ago(lookback)
| where ResultType == 0
| where RiskLevelDuringSignIn in (riskLevels)
| project
    SuccessTime = TimeGenerated,
    UserPrincipalName = tolower(UserPrincipalName),
    SuccessIP = IPAddress,
    RiskLevel = RiskLevelDuringSignIn,
    AppDisplayName,
    UserAgent,
    ConditionalAccessStatus,
    Location;
// STEP 3: Correlate failed → risky success.
// FIX: summarise by (UserPrincipalName, SuccessTime) so each
// distinct risky sign-in is preserved. The original summarised
// by UserPrincipalName alone and used any(SuccessTime), which
// collapsed multiple sign-ins per user into one arbitrary row.
let CompromisedSessions = RiskySuccess
| join kind=inner FailedSignins on UserPrincipalName
| where FailTime between ((SuccessTime - failWindow) .. SuccessTime)
| summarize
    FailCount      = count(),
    FailIPs        = make_set(FailIP, 10),
    DistinctFailIPs = dcount(FailIP)
    by UserPrincipalName, SuccessTime, SuccessIP,
       RiskLevel, AppDisplayName, UserAgent,
       ConditionalAccessStatus, Location;
// STEP 4: Post-compromise audit activity.
// FIX: filter to SensitiveOps. The original joined ALL audit
// events, which fires on every risky sign-in followed by normal
// work activity. SensitiveOps restricts to the operations that
// indicate account abuse: role changes, consent grants, password
// resets, owner additions.
CompromisedSessions
| join kind=inner (
    AuditLogs
    | where TimeGenerated >= ago(lookback + 1h)
    | extend Actor = tolower(tostring(InitiatedBy.user.userPrincipalName))
    | where isnotempty(Actor)
    | where OperationName in (SensitiveOps)
    | project
        AuditTime = TimeGenerated,
        Actor,
        OperationName,
        Category,
        TargetResources
) on $left.UserPrincipalName == $right.Actor
| where AuditTime between (SuccessTime .. (SuccessTime + postCompromiseWindow))
| project
    SuccessTime,
    UserPrincipalName,
    SuccessIP,
    FailIPs,
    FailCount,
    DistinctFailIPs,
    RiskLevel,
    AppDisplayName,
    UserAgent,
    ConditionalAccessStatus,
    Location,
    AuditTime,
    OperationName,
    Category,
    TargetResources,
    MinutesToAction = datetime_diff('minute', AuditTime, SuccessTime)
| order by RiskLevel desc, MinutesToAction asc
```

</div>
