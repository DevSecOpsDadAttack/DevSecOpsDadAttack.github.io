---
layout: page
title: Top 10 Eventids Windows Securityevents
subtitle: "Top 10 most expensive Event IDs from the `SecurityEvent` table over the last 90 days."
permalink: /kql-library/cost-and-ingest/top-10-eventids-windows-securityevents/
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
  <span class="attack-badge attack-badge-sub">Cost By Eventid</span>
  <code class="kql-lib-query-file">top-10-eventids-windows-securityevents.kql</code>
</div>

<p class="kql-lib-query-longdesc">Top 10 most expensive Event IDs from the `SecurityEvent` table over the last 90 days.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/windows/' | relative_url }}">Windows</a>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/microsoft-sentinel/' | relative_url }}">Microsoft Sentinel</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/securityevent/' | relative_url }}">SecurityEvent</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-top-10-eventids-windows-securityevents">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/cost-and-ingest/cost-by-eventid/top-10-eventids-windows-securityevents.kql' | relative_url }}" download="top-10-eventids-windows-securityevents.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-top-10-eventids-windows-securityevents" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Platforms: Windows, Microsoft Sentinel
// Data: SecurityEvent

// This query will break down your top 10 most expensive EventIDs from the Windows SecurityEvents table over the last 90 days
// East US Region | 100GB/Day commitment tier | Effective Cost per GB - https://azure.microsoft.com/en-ca/pricing/details/microsoft-sentinel/?cdn=disable

let cost=2.96; // <-- Set to Effective Cost per GB (URL in comments above)
SecurityEvent
| where TimeGenerated >ago(90d)            //<-- Run this query against the past quarter (90 days)
| where _IsBillable == True                //<-- Filter out non-billable data
| summarize EventCount=count(), Billable_GB=round(sum(_BilledSize/1000/1000/1000),2) by Activity
| sort by Billable_GB desc                 //<-- Display results in descending order
| extend Estimated_Cost=round(Billable_GB*cost, 2)   //<-- Create a column (extend) and fill it with results of "Billable_GB x cost" where cost is referenced above
| sort by Billable_GB desc 
| limit 10                                 //<-- Limit results to top 10 entries

// You can swap the below line into above query if you’re a stickler for Gibibytes versus Gigabytes: 
| summarize EventCount=count(), Billable_GB=sum(_BilledSize/1024/1024/1024) by EventID
```

</div>
