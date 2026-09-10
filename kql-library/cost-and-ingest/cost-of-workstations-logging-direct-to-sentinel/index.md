---
layout: page
title: Cost Of Workstations Logging Direct To Sentinel
subtitle: "Find workstations shipping logs directly to Sentinel and estimate what it's costing you."
permalink: /kql-library/cost-and-ingest/cost-of-workstations-logging-direct-to-sentinel/
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
  <code class="kql-lib-query-file">cost-of-workstations-logging-direct-to-sentinel.kql</code>
</div>

<p class="kql-lib-query-longdesc">Find workstations shipping logs directly to Sentinel and estimate what it's costing you.</p>

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
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Deep Dive</span>
    <a class="kql-lib-tag kql-lib-tag-deepdive" href="{{ '/kql-library/tag/deep-dive/' | relative_url }}"><i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive</a>
</div>
<div class="kql-lib-query-actions">
  <a class="kql-lib-deep-dive-btn" href="https://www.hanley.cloud/2023-05-17-Sentinel-Cost-Optimization-Exercise-Part-2/" target="_blank" rel="noopener">
    <i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive
  </a>
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-cost-of-workstations-logging-direct-to-sentinel">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/cost-and-ingest/cost-by-table/cost-of-workstations-logging-direct-to-sentinel.kql' | relative_url }}" download="cost-of-workstations-logging-direct-to-sentinel.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-cost-of-workstations-logging-direct-to-sentinel" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Are there workstations logging directly to Sentinel and how much is this costing you? 
// For this query, the ingestioncost variable is manually configured based on the workspace's region.
// Go here for effective cost per GB based on your region: https://azure.microsoft.com/en-us/pricing/details/microsoft-sentinel/
// You can calculate the LAW cost, Sentinel cost, or both (effective cost per GB) by setting the ingestioncost variable.
// Source: Sentinel Cost Optimization Exercise Part 2 (2023-05-17) — https://www.hanley.cloud/2023-05-17-Sentinel-Cost-Optimization-Exercise-Part-2/
// Platforms: Windows, Microsoft Sentinel
// Data: SecurityEvent

let rate=3.96;                                                                  //<-- Plug in Effective per GB Rate Here)
Heartbeat                                                                       //<-- Query the Heartbeat table
| where OSName contains "Windows 10" or OSName contains "Windows 11"            //<-- Query for Win10 and 11 Workstations
| where TimeGenerated >ago(30d)                                                 //<-- Query the last 30 days
| summarize arg_max(TimeGenerated, OSName) by Computer                          //<-- Summarize by computer
| join (SecurityEvent                                                           //<-- Join results with the following query against the SecurityEvent table
| where TimeGenerated >ago(30d)) on Computer                                    //<-- Query the last 30 days
| summarize GB=sum(_BilledSize)/1000/1000/1000                                  //<-- Summarize by total _Billed Size and convert to GB
| extend cost = GB*rate                                                         //<-- Multiply total GB by the effective per GB rate
```

</div>
