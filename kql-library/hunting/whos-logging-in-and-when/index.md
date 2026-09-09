---
layout: page
title: Whos Logging In And When
subtitle: "Timestamped feed of RDP logon (4624/LogonType 10), logoff (4634), and reconnect/disconnect (4778/4779) events over 30 days."
permalink: /kql-library/hunting/whos-logging-in-and-when/
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
  <code class="kql-lib-query-file">whos-logging-in-and-when.kql</code>
</div>

<p class="kql-lib-query-longdesc">Timestamped feed of RDP logon (4624/LogonType 10), logoff (4634), and reconnect/disconnect (4778/4779) events over 30 days.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/credential-access/' | relative_url }}">Credential Access</a>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/initial-access/' | relative_url }}">Initial Access</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1078/' | relative_url }}">T1078</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/windows/' | relative_url }}">Windows</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/securityevent/' | relative_url }}">SecurityEvent</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-whos-logging-in-and-when">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/hunting/user-activity/whos-logging-in-and-when.kql' | relative_url }}" download="whos-logging-in-and-when.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-whos-logging-in-and-when" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Tactics: Credential Access, Initial Access
// Techniques: T1078
// Platforms: Windows
// Data: SecurityEvent

// A timestamped feed of RDP logon (EventID 4624 with LogonType 10), logoff (4634), and
// session reconnect/disconnect (4778/4779) events over the last 30 days. Use for
// baselining "who's on this box and when" or as the starting point for investigating
// suspicious on-prem RDP activity.
// Machine accounts and SYSTEM/computer-account entries are filtered out. For a per-user
// daily-login-count chart based on the same underlying data (better for spotting your
// heaviest hitters), see rdp-logins-per-day-per-user.kql in this same folder.

SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID in (4624, 4634, 4778, 4779)
// Early filtering before parsing
| where AccountType != "Machine"  // More efficient than string matching
| where Account !has "SYSTEM" and Account !endswith "$"
// Filter to RDP only for logons, keep all logoff/reconnect/disconnect
| where EventID != 4624 or LogonType == 10
| project
    TimeGenerated,
    DomainController = Computer,
    Activity,
    User = coalesce(TargetUserName, Account)
| order by TimeGenerated desc
```

</div>
