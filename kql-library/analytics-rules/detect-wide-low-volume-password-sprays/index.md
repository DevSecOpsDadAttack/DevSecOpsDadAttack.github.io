---
layout: page
title: Detect Wide Low Volume Password Sprays
subtitle: "Wide, low-volume spray: from a single IP, exactly one failed attempt per user in a day, but against many different users."
permalink: /kql-library/analytics-rules/detect-wide-low-volume-password-sprays/
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
  <span class="attack-badge attack-badge-sub">Password Spray</span>
  <code class="kql-lib-query-file">detect-wide-low-volume-password-sprays.kql</code>
</div>

<p class="kql-lib-query-longdesc">Wide, low-volume spray: from a single IP, exactly one failed attempt per user in a day, but against many different users.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-detect-wide-low-volume-password-sprays">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/analytics-rules/password-spray/detect-wide-low-volume-password-sprays.kql' | relative_url }}" download="detect-wide-low-volume-password-sprays.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-detect-wide-low-volume-password-sprays" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Sentinel (SigninLogs) — detect “wide, low-volume” password sprays
// Heuristic: from a single IP, exactly one failed attempt per user in a day, but against many different users.

SigninLogs
| where ResultType != 0                             // Keep only failed sign-ins (ResultType==0 is success)
| summarize Attempts=count()
    by bin(TimeGenerated, 1d), UserPrincipalName, IPAddress, UserAgent   // Count failed attempts per day 
| where Attempts == 1                               // Keep patterns with exactly one failure per targeted user from that IP per day
                                                    // (characteristic of “one-try-per-user” low-and-slow sprays)
| summarize
    UsersTargeted = dcount(UserPrincipalName),      // How many distinct users were hit by this IP that day
    UAs = make_set(UserAgent, 20)                   // Keep up to 20 distinct UAs seen for context
  by bin(TimeGenerated, 1d), IPAddress              // Roll up to (day × IP), aggregating distinct users and UAs
| where UsersTargeted >= 10                         // Threshold: treat as suspicious only if the IP touched many users that day (tune to your baseline)
| order by TimeGenerated desc, UsersTargeted desc   // Show the most recent and broadest spray patterns first
```

</div>
