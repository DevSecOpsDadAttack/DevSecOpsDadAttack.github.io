---
layout: page
title: DNS Query Volume
subtitle: "Total DNS query volume over time — the baseline 'how loud is DNS' view."
permalink: /kql-library/pihole/dns-query-volume/
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
  <code class="kql-lib-query-file">dns-query-volume.kql</code>
</div>

<p class="kql-lib-query-longdesc">Total DNS query volume over time — the baseline "how loud is DNS" view.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/pi-hole/' | relative_url }}">Pi-hole</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/pihole-cl/' | relative_url }}">pihole_CL</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-dns-query-volume">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/pihole/dns-query-volume.kql' | relative_url }}" download="dns-query-volume.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-dns-query-volume" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Summarize the total number of DNS queries over time
// Platforms: Pi-hole
// Data: pihole_CL

PiHole
| summarize Count = count() by bin(TimeGenerated, 1h)  // Aggregate counts in 1-hour intervals
| render timechart  // Visualize the data as a time chart
```

</div>
