---
layout: page
title: Sort Function Result Comparison
subtitle: "Side-by-side of `sort by` vs `top` on a cost-per-EventID query, showing that both produce identical results in this case — a small worked example for anyone learning KQL sort semantics."
permalink: /kql-library/reference/sort-function-result-comparison/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/reference/' | relative_url }}">Reference</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-book" aria-hidden="true"></i>&nbsp;Reference</span>
  <code class="kql-lib-query-file">sort-function-result-comparison.kql</code>
</div>

<p class="kql-lib-query-longdesc">Side-by-side of `sort by` vs `top` on a cost-per-EventID query, showing that both produce identical results in this case — a small worked example for anyone learning KQL sort semantics.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/microsoft-sentinel/' | relative_url }}">Microsoft Sentinel</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/securityevent/' | relative_url }}">SecurityEvent</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-sort-function-result-comparison">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/reference/sort-function-result-comparison.kql' | relative_url }}" download="sort-function-result-comparison.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-sort-function-result-comparison" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Platforms: Microsoft Sentinel
// Data: SecurityEvent
SecurityEvent
| where _IsBillable == True                //<-- Filter out non-billable data
| summarize EventCount=count(), Billable_GB=sum(_BilledSize / 1000 / 1000 / 1000) by EventID
| extend TotalCost = round(Billable_GB * 5.22, 2)
//| sort by TotalCost desc                  //<-- identical results if you comment out line 7 and use this instead
| extend TotalCost=strcat('$', TotalCost)
| sort by Billable_GB desc                 //<-- Display results in descending order
| project-away EventCount                   //<-- comment this out for a total count of number of hits for each EventID
| limit 10
```

</div>
