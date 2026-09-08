---
layout: page
title: Blocked Queries Over Time
subtitle: "Count of blocked DNS queries bucketed over time."
permalink: /kql-library/pihole/blocked-queries-over-time/
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
  <code class="kql-lib-query-file">blocked-queries-over-time.kql</code>
</div>

<p class="kql-lib-query-longdesc">Count of blocked DNS queries bucketed over time.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-blocked-queries-over-time">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/pihole/blocked-queries-over-time.kql' | relative_url }}" download="blocked-queries-over-time.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-blocked-queries-over-time" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com

// Summarize the count of blocked DNS queries over time

PiHole
| where QueryType == "Blocked"  // Filter for blocked queries
| summarize Count = count() by bin(TimeGenerated, 1h)  // Aggregate counts in 1-hour intervals
| render timechart  // Visualize the data as a time chart
```

</div>
