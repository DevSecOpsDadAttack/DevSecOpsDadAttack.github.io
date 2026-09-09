---
layout: page
title: 90 Day Billable Volume By Solution
subtitle: "Billable GB per day for the past 90 days, sliced by Solution, rendered as a column chart."
permalink: /kql-library/cost-and-ingest/90-day-billable-volume-by-solution/
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
  <code class="kql-lib-query-file">90-day-billable-volume-by-solution.kql</code>
</div>

<p class="kql-lib-query-longdesc">Billable GB per day for the past 90 days, sliced by Solution, rendered as a column chart.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/microsoft-sentinel/' | relative_url }}">Microsoft Sentinel</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/usage/' | relative_url }}">Usage</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-90-day-billable-volume-by-solution">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/cost-and-ingest/billable-volume/90-day-billable-volume-by-solution.kql' | relative_url }}" download="90-day-billable-volume-by-solution.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-90-day-billable-volume-by-solution" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Billable GB per day for the past 90 days, broken out by Solution and rendered as a column chart.
// Great for spotting which solution is driving your ingest curve over the quarter.
// Platforms: Microsoft Sentinel
// Data: Usage

Usage                                                                                   // <--Query the Usage table
| where TimeGenerated > ago(90d)                                                        // <--Query the last 90 days
| where IsBillable == true                                                              // <--Only include 'billable' data
| summarize TotalVolumeGB = sum(Quantity) / 1000 by bin(TimeGenerated, 1d), Solution    // <--Chop it up into GB / Day
| render columnchart                                                                    // <--Graph the results
```

</div>
