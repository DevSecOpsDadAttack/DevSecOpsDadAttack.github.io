---
layout: page
title: Query Type Distribution
subtitle: "Distribution of DNS query types (A, AAAA, TXT, etc.)."
permalink: /kql-library/pihole/query-type-distribution/
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
  <code class="kql-lib-query-file">query-type-distribution.kql</code>
</div>

<p class="kql-lib-query-longdesc">Distribution of DNS query types (A, AAAA, TXT, etc.).</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/pi-hole/' | relative_url }}">Pi-hole</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/pihole-cl/' | relative_url }}">pihole_CL</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Deep Dive</span>
    <a class="kql-lib-tag kql-lib-tag-deepdive" href="{{ '/kql-library/tag/deep-dive/' | relative_url }}"><i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive</a>
</div>
<div class="kql-lib-query-actions">
  <a class="kql-lib-deep-dive-btn" href="https://www.hanley.cloud/2025-03-30-Watching-the-DNS-Watcher-Pihole-Logs-in-Sentinel/" target="_blank" rel="noopener">
    <i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive
  </a>
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-query-type-distribution">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/pihole/query-type-distribution.kql' | relative_url }}" download="query-type-distribution.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-query-type-distribution" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Determine the distribution of query types
// Source: Watching The DNS Watcher: Pihole Logs In Sentinel (2025-03-30) — https://www.hanley.cloud/2025-03-30-Watching-the-DNS-Watcher-Pihole-Logs-in-Sentinel/
// Platforms: Pi-hole
// Data: pihole_CL

PiHole
| summarize Count = count() by QueryType  // Aggregate counts by query type
| render piechart  // Visualize the data as a pie chart

```

</div>
