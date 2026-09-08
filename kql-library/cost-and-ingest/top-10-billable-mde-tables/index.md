---
layout: page
title: Top 10 Billable MDE Tables
subtitle: "Top 10 most expensive Microsoft Defender for Endpoint tables over the last 90 days."
permalink: /kql-library/cost-and-ingest/top-10-billable-mde-tables/
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
  <code class="kql-lib-query-file">top-10-billable-mde-tables.kql</code>
</div>

<p class="kql-lib-query-longdesc">Top 10 most expensive Microsoft Defender for Endpoint tables over the last 90 days.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-top-10-billable-mde-tables">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/cost-and-ingest/cost-by-table/top-10-billable-mde-tables.kql' | relative_url }}" download="top-10-billable-mde-tables.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-top-10-billable-mde-tables" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com

// This query will break down your top 10 most expensive Microsoft Defender for Endpoint (MDE) log sources in the last 90 days
// West US 2 Region Effective Cost per GB - https://azure.microsoft.com/en-ca/pricing/details/microsoft-sentinel/?cdn=disable

let cost=4.30; // <-- Set to Effective Cost per GB (URL in comments above)
search *
| where TimeGenerated >ago(90d)            //<-- Run this query against the past quarter (90 days)
| where _IsBillable == True                //<-- Filter out non-billable data
| where Type contains "Device"             //<-- Apply query to sources with "Device" (Defender Tables) 
| summarize EventCount=count(), Billable_GB=sum(_BilledSize/1000/1000/1000) by Type 
| sort by Billable_GB desc                 //<-- Display results in descending order
| extend Estimated_Cost=Billable_GB*cost   //<-- Create a column (extend) and fill it with results of "Billable_GB x cost" where cost is referenced above
| limit 10                                 //<-- Limit results to top 10 entries

// You can swap the below line into above query if you’re a stickler for Gibibytes versus Gigabytes: 
| summarize EventCount=count(), Billable_GB=sum(_BilledSize/1024/1024/1024) by Type
```

</div>
