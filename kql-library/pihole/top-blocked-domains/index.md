---
layout: page
title: Top Blocked Domains
subtitle: "Top 10 blocked domains."
permalink: /kql-library/pihole/top-blocked-domains/
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
  <code class="kql-lib-query-file">top-blocked-domains.kql</code>
</div>

<p class="kql-lib-query-longdesc">Top 10 blocked domains.</p>

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
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-top-blocked-domains">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/pihole/top-blocked-domains.kql' | relative_url }}" download="top-blocked-domains.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-top-blocked-domains" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Identify the top 10 blocked domains
// Platforms: Pi-hole
// Data: pihole_CL
PiHole
| where QueryType == "Blocked"  // Filter for blocked queries
| summarize Count = count() by Domain  // Aggregate counts by domain
| top 10 by Count  // Select the top 10 domains by count
```

</div>
