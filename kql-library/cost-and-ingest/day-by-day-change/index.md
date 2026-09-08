---
layout: page
title: Day By Day Change
subtitle: "Percent change in daily ingest volume vs the previous day over the last 31 days."
permalink: /kql-library/cost-and-ingest/day-by-day-change/
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
  <span class="attack-badge attack-badge-sub">Ingest Trends</span>
  <code class="kql-lib-query-file">day-by-day-change.kql</code>
</div>

<p class="kql-lib-query-longdesc">Percent change in daily ingest volume vs the previous day over the last 31 days.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-day-by-day-change">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/cost-and-ingest/ingest-trends/day-by-day-change.kql' | relative_url }}" download="day-by-day-change.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-day-by-day-change" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// day by day change in percentage
Usage
| where TimeGenerated > startofday(ago(31d))
| summarize IngestedGB = round(sum(Quantity)/1024,3) by bin(TimeGenerated, 1d)
| sort by TimeGenerated asc 
| serialize previous_IngestedGB = prev(IngestedGB)
| extend PercentChange = round((IngestedGB - previous_IngestedGB) / previous_IngestedGB * 100, 0)
//| where PercentChange >= 100 or PercentChange <= -50
| render columnchart
```

</div>
