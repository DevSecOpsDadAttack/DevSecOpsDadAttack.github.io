---
layout: page
title: How Loud Is A Table
subtitle: "Row-count-per-day graph for a given table (defaults to `Syslog`) — a quick 'is this table getting louder?' check."
permalink: /kql-library/cost-and-ingest/how-loud-is-a-table/
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
  <code class="kql-lib-query-file">how-loud-is-a-table.kql</code>
</div>

<p class="kql-lib-query-longdesc">Row-count-per-day graph for a given table (defaults to `Syslog`) — a quick "is this table getting louder?" check.</p>

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
  <a class="kql-lib-deep-dive-btn" href="https://www.hanley.cloud/2023-04-06-Anatomy-of-a-KQL-Query-Part-1/" target="_blank" rel="noopener">
    <i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive
  </a>
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-how-loud-is-a-table">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/cost-and-ingest/cost-by-table/how-loud-is-a-table.kql' | relative_url }}" download="how-loud-is-a-table.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-how-loud-is-a-table" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// This example queries the last 30 days of the syslog table, aggregates the number of hits per day, and the graphs results
// Source: Anatomy Of A KQL Query Part 1 (2023-04-06) — https://www.hanley.cloud/2023-04-06-Anatomy-of-a-KQL-Query-Part-1/
// Platforms: Microsoft Sentinel
// Data: Usage

Syslog                                          // <--Define the table to query
| where TimeGenerated > ago(30d)                // <--Query the last 30 days into the table
| summarize count() by bin(TimeGenerated,1d)    // <--Return count per day
| render columnchart                            // <--Graph a column chart
```

</div>
