---
layout: page
title: Top 10 Security Events With Cost Enhanced
subtitle: "Top `SecurityEvent` `EventID`s (30d) with GiB, emoji cost-tier, and formatted `$X.XX` string."
permalink: /kql-library/cost-and-ingest/top-10-security-events-with-cost-enhanced/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/cost-and-ingest/' | relative_url }}">Cost &amp; Ingest</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-coins" aria-hidden="true"></i>&nbsp;Cost &amp; Ingest</span>
  <span class="attack-badge attack-badge-sub">Cost By Table</span>
  <code class="kql-lib-query-file">top-10-security-events-with-cost-enhanced.kql</code>
</div>

<p class="kql-lib-query-longdesc">Top `SecurityEvent` `EventID`s (30d) with GiB, emoji cost-tier, and formatted `$X.XX` string.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/windows/' | relative_url }}">Windows</a>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/microsoft-sentinel/' | relative_url }}">Microsoft Sentinel</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/securityevent/' | relative_url }}">SecurityEvent</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-top-10-security-events-with-cost-enhanced">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/cost-and-ingest/cost-by-table/top-10-security-events-with-cost-enhanced.kql' | relative_url }}" download="top-10-security-events-with-cost-enhanced.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-top-10-security-events-with-cost-enhanced" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Top 10 most expensive SecurityEvent EventIDs over the last 30 days, grouped by EventID only,
// with GiB, an emoji cost-tier indicator, and a formatted '$X.XX' cost column. Best for
// human-readable dashboards. For a numeric-cost variant that includes the Activity name,
// see top-10-security-events-with-cost.kql.
// Platforms: Windows, Microsoft Sentinel
// Data: SecurityEvent

SecurityEvent
| where TimeGenerated > ago(30d)
| where _IsBillable == True
| summarize EventCount=count(), GiB=round(sum(_BilledSize / 1024 / 1024 / 1024), 2) by EventID
| extend TotalCost = round(GiB * 5.16, 2)   // <-- Replace 5.16 with your region's actual Sentinel price per GB
| sort by GiB desc
| extend CostLevel = case(
                         TotalCost >= 1000,
                         '🤑🤑🤑🤑🤑',  // Most Expensive
                         TotalCost >= 750,
                         '💰💰💰💰',
                         TotalCost >= 500,
                         '💰💰💰',
                         TotalCost >= 250,
                         '💰💰',
                         TotalCost >= 100,
                         '💰',          // Least Expensive
                         '💸'                             // Fallback
                     )
| extend TotalCost=strcat('$', TotalCost, ' ', CostLevel)
| project EventID, GiB, TotalCost
| limit 10
```

</div>
