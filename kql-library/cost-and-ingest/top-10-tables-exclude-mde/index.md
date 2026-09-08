---
layout: page
title: Top 10 Tables Exclude MDE
subtitle: "Top 10 most expensive log sources over 90 days, excluding MDE, via the fast `Usage` table."
permalink: /kql-library/cost-and-ingest/top-10-tables-exclude-mde/
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
  <code class="kql-lib-query-file">top-10-tables-exclude-mde.kql</code>
</div>

<p class="kql-lib-query-longdesc">Top 10 most expensive log sources over 90 days, excluding MDE, via the fast `Usage` table.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-top-10-tables-exclude-mde">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/cost-and-ingest/cost-by-table/top-10-tables-exclude-mde.kql' | relative_url }}" download="top-10-tables-exclude-mde.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-top-10-tables-exclude-mde" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Top 10 most expensive log sources (excluding MDE) in the last 90 days, using the Usage table.
// Much faster than the `search *` variant because it reads pre-aggregated ingest metrics
// instead of scanning every row in every table. Use this by default; only fall back to the
// `search *` variant (top-10-tables-exclude-mde-search-star.kql) if you need per-table event
// counts alongside billable volume.

let CostPerGB = 4.30;   // <-- Set to Effective Cost per GB for your region: https://azure.microsoft.com/en-ca/pricing/details/microsoft-sentinel/
Usage
| where TimeGenerated > ago(90d)
| where IsBillable == true
| summarize GB = round(sum(Quantity)/1000, 2) by DataType
| extend dollar = round(GB * CostPerGB, 2)
| extend TotalCost = strcat('$', dollar)
| sort by dollar desc
| where DataType !contains 'device'   // <-- Exclude Defender tables
| limit 10
| project DataType, GB, TotalCost
```

</div>
