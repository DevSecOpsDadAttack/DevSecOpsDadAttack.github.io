---
layout: page
title: 90 Day Billable Cost Per Day Formatted
subtitle: "Daily billable GB and cost over 90 days, formatted as human-readable strings (`$X.XX / Day`, `XGB / Day`). Table-friendly, not chart-friendly."
permalink: /kql-library/cost-and-ingest/90-day-billable-cost-per-day-formatted/
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
  <code class="kql-lib-query-file">90-day-billable-cost-per-day-formatted.kql</code>
</div>

<p class="kql-lib-query-longdesc">Daily billable GB and cost over 90 days, formatted as human-readable strings (`$X.XX / Day`, `XGB / Day`). Table-friendly, not chart-friendly.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/microsoft-sentinel/' | relative_url }}">Microsoft Sentinel</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/usage/' | relative_url }}">Usage</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Deep Dive</span>
    <a class="kql-lib-tag kql-lib-tag-deepdive" href="{{ '/kql-library/tag/deep-dive/' | relative_url }}"><i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive</a>
</div>
<div class="kql-lib-query-actions">
  <a class="kql-lib-deep-dive-btn" href="https://www.hanley.cloud/2025-12-14-KQL-Toolbox-1-Track-%26-Price-Your-Microsoft-Sentinel-Ingest-Costs/" target="_blank" rel="noopener">
    <i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive
  </a>
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-90-day-billable-cost-per-day-formatted">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/cost-and-ingest/billable-volume/90-day-billable-cost-per-day-formatted.kql' | relative_url }}" download="90-day-billable-cost-per-day-formatted.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-90-day-billable-cost-per-day-formatted" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Daily billable GB and cost for the past 90 days, formatted as human-readable strings
// ('$X.XX / Day' and 'X.XXGB / Day'). Best for tables and dashboards where readability
// matters more than plottability — the string formatting means these columns are not
// chart-friendly. For a numeric CostUSD variant, see 90-day-billable-cost-per-day.kql.
// Source: KQL Toolbox #1: Track & Price Your Microsoft Sentinel Ingest Costs (2025-12-14) — https://www.hanley.cloud/2025-12-14-KQL-Toolbox-1-Track-%26-Price-Your-Microsoft-Sentinel-Ingest-Costs/
// Platforms: Microsoft Sentinel
// Data: Usage

Usage                                                                                   // <--Query the Usage table
| where TimeGenerated > ago(90d)                                                        // <--Query the last 90 days
| where IsBillable == true                                                              // <--Only include 'billable' data
| summarize TotalVolumeGB = round(sum(Quantity) / 1024, 2) by bin(TimeGenerated, 1d)    // <--Chop it up into GB / Day
| extend  cost=strcat('$', round(TotalVolumeGB*4.30, 2), ' / Day')                      // <--Format daily cost as a readable string by prepending '$', rounding to 2 decimals, and adding '/ Day'
| extend TotalVolumeGB = strcat(TotalVolumeGB, 'GB / Day')                              // <--Convert GB value to a display string by appending 'GB / Day' for clearer, human-friendly output
```

</div>
