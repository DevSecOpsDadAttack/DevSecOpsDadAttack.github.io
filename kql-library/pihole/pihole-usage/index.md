---
layout: page
title: Pihole Usage
subtitle: "Billable ingest volume for the Pi-hole custom log over the last 90 days."
permalink: /kql-library/pihole/pihole-usage/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/pihole/' | relative_url }}">Pi-hole</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-network-wired" aria-hidden="true"></i>&nbsp;Pi-hole</span>
  <code class="kql-lib-query-file">pihole-usage.kql</code>
</div>

<p class="kql-lib-query-longdesc">Billable ingest volume for the Pi-hole custom log over the last 90 days.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-pihole-usage">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/pihole/pihole-usage.kql' | relative_url }}" download="pihole-usage.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-pihole-usage" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
Usage
| where TimeGenerated > ago(90d) 
| where IsBillable == true
| where DataType == "pihole_CL"
| summarize TotalVolumeGB = sum(Quantity) / 1000 by bin(StartTime, 1d), DataType
| render columnchart     

// Alternate Query
// Summarize Pi-hole usage statistics over time
PiHole
| summarize TotalQueries = count(), BlockedQueries = countif(QueryType == "Blocked") by bin(TimeGenerated, 1h)  // Aggregate total and blocked queries in 1-hour intervals
| extend BlockedPercentage = todouble(BlockedQueries) / todouble(TotalQueries) * 100  // Calculate the percentage of blocked queries
| render timechart  // Visualize the data as a time chart

```

</div>
