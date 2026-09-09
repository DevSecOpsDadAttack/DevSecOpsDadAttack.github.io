---
layout: page
title: Hunt Suspicious User Consented Oauth App Grants
subtitle: "'The backdoor you approved yourself' — OAuth application consents granting broad Graph permissions to unfamiliar apps. Focuses on CONSENT events, not the logins that follow."
permalink: /kql-library/hunting/hunt-suspicious-user-consented-oauth-app-grants/
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
  <code class="kql-lib-query-file">hunt-suspicious-user-consented-oauth-app-grants.kql</code>
</div>

<p class="kql-lib-query-longdesc">'The backdoor you approved yourself' — OAuth application consents granting broad Graph permissions to unfamiliar apps. Focuses on CONSENT events, not the logins that follow.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/persistence/' | relative_url }}">Persistence</a>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/privilege-escalation/' | relative_url }}">Privilege Escalation</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1550-001/' | relative_url }}">T1550.001</a>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1098-003/' | relative_url }}">T1098.003</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/entra-id/' | relative_url }}">Entra ID</a>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/microsoft-365/' | relative_url }}">Microsoft 365</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/auditlogs/' | relative_url }}">AuditLogs</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-hunt-suspicious-user-consented-oauth-app-grants">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/hunting/hunt-suspicious-user-consented-oauth-app-grants.kql' | relative_url }}" download="hunt-suspicious-user-consented-oauth-app-grants.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-hunt-suspicious-user-consented-oauth-app-grants" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Detects the backdoor a user approved themselves — an OAuth application consent that grants broad
// Graph permissions to an app the user has never seen before. Focuses on the CONSENT event (the
// identity backdoor being installed) rather than the login events that follow.
// Source: KQL Detection of the Week: The Login Was Never the Point (2026-07-06) — https://devsecopsdadattack.com/2026-07-06-KQL-Detection-of-the-Week_-The-Login-Was-Never-the-Point/
// Tactics: Persistence, Privilege Escalation
// Techniques: T1550.001, T1098.003
// Platforms: Entra ID, Microsoft 365
// Data: AuditLogs

let lookback = 1d;
let googleKeywords = dynamic(["google", "gmail", "googleapis", "workspace"]);
let oauthGrants = AuditLogs
| where TimeGenerated >= ago(lookback)
| where OperationName =~ "Add delegated permission grant" or OperationName =~ "Consent to application"
| extend TargetResource = tostring(TargetResources[0].displayName)
| extend TargetResourceId = tostring(TargetResources[0].id)
| extend InitiatedByUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatedByIP = tostring(InitiatedBy.user.ipAddress)
| where isnotempty(InitiatedByUPN)
| where TargetResource has_any (googleKeywords)
    or TargetResourceId has_any (googleKeywords)
    or tostring(AdditionalDetails) has_any (googleKeywords)
| project GrantTime = TimeGenerated, InitiatedByUPN, InitiatedByIP, TargetResource, TargetResourceId, OperationName, CorrelationId;
let recentSignins = SigninLogs
| where TimeGenerated >= ago(lookback)
| where ResultType == 0
| project SigninTime = TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ConditionalAccessStatus;
oauthGrants
| join kind=inner recentSignins
    on $left.InitiatedByUPN == $right.UserPrincipalName
| where SigninTime <= GrantTime and GrantTime <= SigninTime + 30m
| project GrantTime, SigninTime, InitiatedByUPN, InitiatedByIP, TargetResource, TargetResourceId, OperationName, AppDisplayName, ConditionalAccessStatus, CorrelationId
| order by GrantTime desc
```

</div>
