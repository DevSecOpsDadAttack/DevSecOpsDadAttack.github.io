---
layout: page
title: Who Deleted An AD User
subtitle: "Who deleted an AD user (`SecurityEvent` EventID `4726`) over the last 90 days."
permalink: /kql-library/identity/who-deleted-an-ad-user/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/identity/' | relative_url }}">Identity</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-user-shield" aria-hidden="true"></i>&nbsp;Identity</span>
  <code class="kql-lib-query-file">who-deleted-an-ad-user.kql</code>
</div>

<p class="kql-lib-query-longdesc">Who deleted an AD user (`SecurityEvent` EventID `4726`) over the last 90 days.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-who-deleted-an-ad-user">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/identity/who-deleted-an-ad-user.kql' | relative_url }}" download="who-deleted-an-ad-user.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-who-deleted-an-ad-user" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
SecurityEvent
| where TimeGenerated > ago (90d)
| where EventID == "4726"
| extend Actor_ = Account
| project-reorder TimeGenerated, Activity, Actor_, TargetUserName, Computer
```

</div>
