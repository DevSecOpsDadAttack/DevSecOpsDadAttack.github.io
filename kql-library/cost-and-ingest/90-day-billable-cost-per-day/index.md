---
layout: page
title: 90 Day Billable Cost Per Day
subtitle: "Daily billable GB and cost over 90 days with numeric `CostUSD`. The default cost-over-time view — plottable and aggregatable."
permalink: /kql-library/cost-and-ingest/90-day-billable-cost-per-day/
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
  <span class="attack-badge attack-badge-sub">Billable Volume</span>
  <code class="kql-lib-query-file">90-day-billable-cost-per-day.kql</code>
</div>

<p class="kql-lib-query-longdesc">Daily billable GB and cost over 90 days with numeric `CostUSD`. The default cost-over-time view — plottable and aggregatable.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-90-day-billable-cost-per-day">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/cost-and-ingest/billable-volume/90-day-billable-cost-per-day.kql' | relative_url }}" download="90-day-billable-cost-per-day.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-90-day-billable-cost-per-day" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Daily billable GB and cost for the past 90 days, with CostUSD as a numeric column.
// Use this variant when you want to graph cost over time — CostUSD stays a float,
// which the chart renderers can plot directly. For a display-friendly '$X.XX / Day'
// string version, see 90-day-billable-cost-per-day-formatted.kql.

Usage                                                                                             // <--Query the Usage table
| where TimeGenerated > ago(90d)                                                                  // <--Query the last 90 days
| where IsBillable == true                                                                        // <--Only include 'billable' data
| summarize TotalVolumeGB = round(sum(Quantity) / 1024, 2) by (TimeGenerated, 1d)                 // <--Group data into 1-day buckets and convert total ingested quantity into GB
| extend CostUSD = round(TotalVolumeGB * 4.30, 2)                                                 // <--Calculate daily cost by multiplying GB/day by your region’s $/GB rate and rounding to 2 decimals
```

</div>
