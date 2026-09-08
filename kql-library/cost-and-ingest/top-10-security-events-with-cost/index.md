---
layout: page
title: Top 10 Security Events With Cost
subtitle: "Top `SecurityEvent` `EventID`s with `Activity` (30d) and numeric `CostUSD`."
permalink: /kql-library/cost-and-ingest/top-10-security-events-with-cost/
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
  <code class="kql-lib-query-file">top-10-security-events-with-cost.kql</code>
</div>

<p class="kql-lib-query-longdesc">Top `SecurityEvent` `EventID`s with `Activity` (30d) and numeric `CostUSD`.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-top-10-security-events-with-cost">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/cost-and-ingest/cost-by-table/top-10-security-events-with-cost.kql' | relative_url }}" download="top-10-security-events-with-cost.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-top-10-security-events-with-cost" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Top 10 most expensive SecurityEvent EventIDs (with Activity) over the last 30 days, with
// numeric CostUSD. Includes Activity in the grouping so you can tell 4624 (An account was
// successfully logged on) apart from 4625 etc. at a glance.
// For a display-friendly variant with cost-tier emojis (and simpler EventID-only grouping),
// see top-10-security-events-with-cost-enhanced.kql.

let PricePerGB = 5.16;   // <-- Replace with your region's actual Sentinel price per GB
SecurityEvent
| where TimeGenerated > ago(30d)
| where _IsBillable == true
| summarize TotalGiB = round(sum(_BilledSize) / 1024.0 / 1024.0 / 1024.0, 2)
          by EventID, Activity
| extend CostUSD = round(TotalGiB * PricePerGB, 2)
| top 10 by CostUSD desc
| order by CostUSD desc
```

</div>
