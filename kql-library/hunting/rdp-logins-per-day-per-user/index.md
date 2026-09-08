---
layout: page
title: RDP Logins Per Day Per User
subtitle: "RDP logins per user per day (30d) rendered as a timechart. Use for baselining 'normal' login volume before hunting for anomalies."
permalink: /kql-library/hunting/rdp-logins-per-day-per-user/
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
  <span class="attack-badge attack-badge-sub">User Activity</span>
  <code class="kql-lib-query-file">rdp-logins-per-day-per-user.kql</code>
</div>

<p class="kql-lib-query-longdesc">RDP logins per user per day (30d) rendered as a timechart. Use for baselining "normal" login volume before hunting for anomalies.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-rdp-logins-per-day-per-user">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/hunting/user-activity/rdp-logins-per-day-per-user.kql' | relative_url }}" download="rdp-logins-per-day-per-user.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-rdp-logins-per-day-per-user" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com

// RDP logins per user per day, rendered as a timechart. Great for identifying your
// heaviest RDP users and establishing a baseline of "normal" login volume before
// hunting for anomalies. Successful RDP logons only (EventID 4624, LogonType 10);
// machine accounts filtered out. For the underlying event-by-event feed including
// logoff/reconnect/disconnect, see whos-logging-in-and-when.kql in this same folder.

SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID == 4624  // Focus on successful logons only
| where AccountType != "Machine"
| where Account !has "SYSTEM" and Account !endswith "$"
| where LogonType == 10  // RDP only
| extend User = coalesce(TargetUserName, Account)
| summarize LoginCount = count() by
    Day = bin(TimeGenerated, 1d),
    User
| order by Day desc, LoginCount desc
| render timechart
```

</div>
