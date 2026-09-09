---
layout: page
title: Detect Low And Slow Password Spray
subtitle: "Low-and-slow spray pattern (Storm-0940-shaped): many unique users from the *same* IP in a day, with roughly one failed attempt per user; includes optional legacy-user-agent hints."
permalink: /kql-library/analytics-rules/detect-low-and-slow-password-spray/
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
  <code class="kql-lib-query-file">detect-low-and-slow-password-spray.kql</code>
</div>

<p class="kql-lib-query-longdesc">Low-and-slow spray pattern (Storm-0940-shaped): many unique users from the *same* IP in a day, with roughly one failed attempt per user; includes optional legacy-user-agent hints.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/credential-access/' | relative_url }}">Credential Access</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1110-003/' | relative_url }}">T1110.003</a>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1110-004/' | relative_url }}">T1110.004</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Actors</span>
    <a class="kql-lib-tag kql-lib-tag-actor" href="{{ '/kql-library/tag/storm-0940/' | relative_url }}">Storm-0940</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/entra-id/' | relative_url }}">Entra ID</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/signinlogs/' | relative_url }}">SigninLogs</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-detect-low-and-slow-password-spray">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/analytics-rules/password-spray/detect-low-and-slow-password-spray.kql' | relative_url }}" download="detect-low-and-slow-password-spray.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-detect-low-and-slow-password-spray" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Detect low-and-slow password spray patterns (e.g., Storm-0940) in Azure AD sign-ins via Sentinel (SigninLogs).
// Tactics: Credential Access
// Techniques: T1110.003, T1110.004
// Actors: Storm-0940
// Platforms: Entra ID
// Data: SigninLogs

// Heuristic: many unique users from the SAME IP in a day, with ~one failed attempt per user, and optional legacy UA hints.

// --- Parameters / indicators ---
let lookback = 14d;                      // How far back to search
let ua_indicators = dynamic([            // Optional: suspicious/legacy user-agent strings to flag
  "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36"
]);
SigninLogs
| where TimeGenerated >= ago(lookback)                   // Limit to the lookback window
| where ResultType != 0                                  // Keep failed sign-ins only (ResultType==0 is success)
| extend LD = todynamic(column_ifexists("LocationDetails", "{}"))  // Cast LocationDetails to dynamic (schema differs by tenant)
| extend Country = tostring(LD.countryOrRegion)          // Extract country/region for context in the output
| extend UAHit = iif(UserAgent in (ua_indicators), 1, 0) // Flag events whose UserAgent matches our legacy UA list
| summarize
    Attempts = count(),                                  // Total failed attempts from this IP on this day
    Users    = make_set(UserPrincipalName, 1000),        // Unique users targeted by this IP on this day (up to 1000)
    UAHits   = sum(UAHit)                                // Count of events that matched legacy UA indicators
  by bin(TimeGenerated, 1d), IPAddress, Country          // Aggregate per day, per source IP, per country
| extend UsersTargeted = array_length(Users)             // Convert the user set into a numeric count
| where UsersTargeted >= 10                              // Spray breadth threshold: at least 10 unique users/day/IP
  and Attempts <= UsersTargeted + 2                      // "One attempt per user per day" pattern (allow tiny slack)
| order by TimeGenerated desc, UsersTargeted desc        // Show most recent / widest sprays first 

```

</div>
