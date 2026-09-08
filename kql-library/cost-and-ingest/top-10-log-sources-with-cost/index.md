---
layout: page
title: Top 10 Log Sources With Cost
subtitle: "Top log sources by `DataType` (30d) with numeric `CostUSD`. The chart-friendly default."
permalink: /kql-library/cost-and-ingest/top-10-log-sources-with-cost/
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
  <code class="kql-lib-query-file">top-10-log-sources-with-cost.kql</code>
</div>

<p class="kql-lib-query-longdesc">Top log sources by `DataType` (30d) with numeric `CostUSD`. The chart-friendly default.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-top-10-log-sources-with-cost">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/cost-and-ingest/cost-by-table/top-10-log-sources-with-cost.kql' | relative_url }}" download="top-10-log-sources-with-cost.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-top-10-log-sources-with-cost" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Top 10 most expensive log sources by DataType over the last 30 days, with a numeric CostUSD column.
// Use this variant when you want the raw numbers — CostUSD stays a float so it plays nicely with
// dashboards and downstream aggregation. For a display-friendly variant with cost-tier emojis,
// see top-10-log-sources-with-cost-enhanced.kql.

let PricePerGB = 5.16;   // <-- Replace with your region's actual Sentinel price per GB
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| summarize TotalGiB = round(sum(Quantity) / 1024.0, 2) by DataType
| extend CostUSD = round(TotalGiB * PricePerGB, 2)
| top 10 by CostUSD desc
| order by CostUSD desc
```

</div>
