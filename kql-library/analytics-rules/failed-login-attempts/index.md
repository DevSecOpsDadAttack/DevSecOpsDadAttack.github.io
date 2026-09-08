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

<div class="kql-lib-query-actions">
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

SigninLogs
| where ResultType == 50126
| summarize FailedAttempts = count() by UserPrincipalName, bin(TimeGenerated, 2m)
| where FailedAttempts >= 3
```

</div>
