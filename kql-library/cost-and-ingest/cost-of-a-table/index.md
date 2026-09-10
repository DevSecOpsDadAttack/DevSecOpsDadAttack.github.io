---
layout: page
title: Cost Of A Table
subtitle: "Estimated dollar cost of a single table over a chosen window, given your effective per-GB rate."
permalink: /kql-library/cost-and-ingest/cost-of-a-table/
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
  <code class="kql-lib-query-file">cost-of-a-table.kql</code>
</div>

<p class="kql-lib-query-longdesc">Estimated dollar cost of a single table over a chosen window, given your effective per-GB rate.</p>

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
  <a class="kql-lib-deep-dive-btn" href="https://www.hanley.cloud/2023-05-15-Sentinel-Cost-Optimization-Part-2/" target="_blank" rel="noopener">
    <i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive
  </a>
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-cost-of-a-table">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/cost-and-ingest/cost-by-table/cost-of-a-table.kql' | relative_url }}" download="cost-of-a-table.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-cost-of-a-table" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// This query will tell you how much a given table will cost you
// For this query, the 'rate' acts like a global floating point variable which is manually defined.
// The rate for your region can be found here: https://azure.microsoft.com/en-us/pricing/details/microsoft-sentinel/
// You can calculate the LAW cost, Sentinel cost, or both (effective cost per GB) by setting the rate variable
// This doesn't have to be over 30 days, you can adjust the TimeGenerated parameter to a a week (7d), a day (1d), or even hourly (1h) etc.
// Source: Sentinel Cost Optimization Part 2 (2023-05-15) — https://www.hanley.cloud/2023-05-15-Sentinel-Cost-Optimization-Part-2/
// Platforms: Microsoft Sentinel
// Data: Usage

let rate = 4.30;                                  //<-- Effective per GB Price in EastUS (LAW & Sentinel per GB cost combined)
SecurityEvent                                     //<-- We're querying the SecurityEvent table in this one
| where TimeGenerated >ago(30d)                   //<-- Let's look at the past month, which makes sense considering we're billed monthly
| summarize GB=sum(_BilledSize)/1000/1000/1000    //<-- Summarize billable volume in GB using the _BilledSize table column
| extend cost = GB*rate                           //<-- Multiply total GBs for the month by the effective rate (defined in first line of query)

//You can change the second to last line in the above query to the following if you’re a stickler for Gibibytes versus Gigabytes: 
| summarize GB=sum(_BilledSize)/1024/1024/1024	
```

</div>
