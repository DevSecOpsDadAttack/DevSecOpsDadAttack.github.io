---
layout: page
title: Cost Of Eventid By Computer
subtitle: "Breaks the cost of a specific Event ID out by originating computer (defaults to `EventID == 4672`)."
permalink: /kql-library/cost-and-ingest/cost-of-eventid-by-computer/
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
  <span class="attack-badge attack-badge-sub">Cost By Eventid</span>
  <code class="kql-lib-query-file">cost-of-eventid-by-computer.kql</code>
</div>

<p class="kql-lib-query-longdesc">Breaks the cost of a specific Event ID out by originating computer (defaults to `EventID == 4672`).</p>

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
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-cost-of-eventid-by-computer">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/cost-and-ingest/cost-by-eventid/cost-of-eventid-by-computer.kql' | relative_url }}" download="cost-of-eventid-by-computer.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-cost-of-eventid-by-computer" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Platforms: Windows, Microsoft Sentinel
// Data: SecurityEvent
WindowsEvent
| where TimeGenerated >ago(90d)
| where EventID == "4672"
| where _IsBillable == True                //<-- Filter out non-billable data
| summarize Billable_GB=round(sum(_BilledSize / 1000 / 1000 / 1000),2) by Computer, EventLevelName
| extend TotalCost = round(Billable_GB * 5.59, 2)
| extend TotalCost=strcat('$', TotalCost)
| sort by Billable_GB desc                 //<-- Display results in descending order
| limit 10
```

</div>
