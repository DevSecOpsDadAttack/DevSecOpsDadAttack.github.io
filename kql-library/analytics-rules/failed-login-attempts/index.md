---
layout: page
title: Failed Login Attempts
subtitle: "3+ failed sign-ins (`ResultType == 50126` — invalid username or password) for the same UPN within a 2-minute window. Written for a demo that pairs with a Logic App to auto-disable or lock the account."
permalink: /kql-library/analytics-rules/failed-login-attempts/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/analytics-rules/' | relative_url }}">Analytics Rules</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-shield-halved" aria-hidden="true"></i>&nbsp;Analytics Rules</span>
  <span class="attack-badge attack-badge-sub">Failed Logins</span>
  <code class="kql-lib-query-file">failed-login-attempts.kql</code>
</div>

<p class="kql-lib-query-longdesc">3+ failed sign-ins (`ResultType == 50126` — invalid username or password) for the same UPN within a 2-minute window. Written for a demo that pairs with a Logic App to auto-disable or lock the account.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/credential-access/' | relative_url }}">Credential Access</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1110-001/' | relative_url }}">T1110.001</a>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1110-003/' | relative_url }}">T1110.003</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/entra-id/' | relative_url }}">Entra ID</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/signinlogs/' | relative_url }}">SigninLogs</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Deep Dive</span>
    <a class="kql-lib-tag kql-lib-tag-deepdive" href="{{ '/kql-library/tag/deep-dive/' | relative_url }}"><i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive</a>
</div>
<div class="kql-lib-query-actions">
  <a class="kql-lib-deep-dive-btn" href="https://www.hanley.cloud/2024-08-16-Logic-Apps-%26-Automation/" target="_blank" rel="noopener">
    <i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive
  </a>
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-failed-login-attempts">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/analytics-rules/failed-logins/failed-login-attempts.kql' | relative_url }}" download="failed-login-attempts.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-failed-login-attempts" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// This is the KQL behind an Analytics Rule I built for a demo to create alerts in Sentinel for 3 or more Failed Login Attempts in under 2 minutes. 
// The idea here was to create a logic app to trigger on this rule and disable/lockout the account.
// ErrorID 50126 is thrown when an invalid username or password is used: https://www.manageengine.com/products/active-directory-audit/kb/azure-error-codes/azure-ad-sign-in-error-code-50126.html
// Source: Logic Apps & Automation (2024-08-16) — https://www.hanley.cloud/2024-08-16-Logic-Apps-%26-Automation/
// Tactics: Credential Access
// Techniques: T1110.001, T1110.003
// Platforms: Entra ID
// Data: SigninLogs

SigninLogs
| where ResultType == 50126
| summarize FailedAttempts = count() by UserPrincipalName, bin(TimeGenerated, 2m)
| where FailedAttempts >= 3
```

</div>
