---
layout: page
title: Success Vs Failure
subtitle: "Successful vs failed DNS query counts."
permalink: /kql-library/pihole/success-vs-failure/
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
  <code class="kql-lib-query-file">success-vs-failure.kql</code>
</div>

<p class="kql-lib-query-longdesc">Successful vs failed DNS query counts.</p>

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
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-success-vs-failure">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/pihole/success-vs-failure.kql' | relative_url }}" download="success-vs-failure.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-success-vs-failure" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Compare the number of successful versus failed DNS queries
// Platforms: Pi-hole
// Data: pihole_CL

PiHole
| summarize Count = count() by ResponseCode  // Aggregate counts by response code
| render barchart  // Visualize the data as a bar chart
```

</div>
