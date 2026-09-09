---
layout: page
title: Top 10 Log Sources With Cost Enhanced
subtitle: "Top log sources by `DataType` (30d) with an emoji cost-tier and formatted `$X.XX` string — table/dashboard friendly."
permalink: /kql-library/cost-and-ingest/top-10-log-sources-with-cost-enhanced/
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
  <code class="kql-lib-query-file">top-10-log-sources-with-cost-enhanced.kql</code>
</div>

<p class="kql-lib-query-longdesc">Top log sources by `DataType` (30d) with an emoji cost-tier and formatted `$X.XX` string — table/dashboard friendly.</p>

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
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-top-10-log-sources-with-cost-enhanced">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/cost-and-ingest/cost-by-table/top-10-log-sources-with-cost-enhanced.kql' | relative_url }}" download="top-10-log-sources-with-cost-enhanced.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-top-10-log-sources-with-cost-enhanced" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Top 10 most expensive log sources by DataType over the last 30 days, with an emoji cost-tier
// indicator and a formatted '$X.XX' cost column. Best for tables and human-readable dashboards.
// For a numeric CostUSD variant that plays nicely with charts and downstream aggregation,
// see top-10-log-sources-with-cost.kql.
// Platforms: Microsoft Sentinel
// Data: Usage

Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| summarize GiB= round(sum(Quantity) / 1024, 2) by DataType
| extend Cost=round(GiB * 5.16, 2)   // <-- Replace 5.16 with your region's actual Sentinel price per GB
| sort by Cost desc
| extend CostLevel = case(
                         Cost >= 1000,
                         '🤑🤑🤑🤑🤑',  // Most Expensive
                         Cost >= 750,
                         '💰💰💰💰',
                         Cost >= 500,
                         '💰💰💰',
                         Cost >= 250,
                         '💰💰',
                         Cost >= 100,
                         '💰',           // Least Expensive
                         '💸'            // Fallback
                     )
| extend Cost=strcat('$', Cost, ' ', CostLevel)
| project DataType, GiB, Cost
| take 10
```

</div>
