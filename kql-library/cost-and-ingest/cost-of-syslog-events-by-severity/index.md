---
layout: page
title: Cost Of Syslog Events By Severity
subtitle: "Cost of Syslog events grouped by severity level."
permalink: /kql-library/cost-and-ingest/cost-of-syslog-events-by-severity/
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
  <code class="kql-lib-query-file">cost-of-syslog-events-by-severity.kql</code>
</div>

<p class="kql-lib-query-longdesc">Cost of Syslog events grouped by severity level.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/linux/' | relative_url }}">Linux</a>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/microsoft-sentinel/' | relative_url }}">Microsoft Sentinel</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/syslog/' | relative_url }}">Syslog</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-cost-of-syslog-events-by-severity">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/cost-and-ingest/cost-by-eventid/cost-of-syslog-events-by-severity.kql' | relative_url }}" download="cost-of-syslog-events-by-severity.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-cost-of-syslog-events-by-severity" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Calculate your effective Per GB Price https://azure.microsoft.com/en-ca/pricing/details/microsoft-sentinel/?cdn=disable
// If your environment has different commitment tiers for your workspace and sentinel instances, follow this guide to calculate your effective Per GB rate: 
// https://www.hanley.cloud/2023-05-15-Sentinel-Cost-Optimization-Part-2/
// Platforms: Linux, Microsoft Sentinel
// Data: Syslog

let rate = 2.53;  //<-- Effective Cost per GB (500GB / Day Commitment Tier in EastUS)
Syslog                                            //<-- Query the Syslog table
| where TimeGenerated > ago(30d)                  //<-- Query the last 30 Days in the table
| where SeverityLevel == 'info'                   //<-- Query for events of SecurityLevel 'info'
| summarize GB=sum(_BilledSize)/1000/1000/1000    //<-- Summarize billable volume in GB using the _BilledSize column
| extend cost = GB*rate                           //<-- Multiple the total GBs by Effective Price per GB

//You can change the last line in the above query to the following if you’re a stickler for Gibibytes versus Gigabytes: 
| summarize GB=sum(_BilledSize)/1024/1024/1024	

++++++++++++++++++++++++++++++++++++++++++++++++++++++

Syslog
| where TimeGenerated >ago(90d)
| where _IsBillable == True
| summarize Billable_GB=round(sum(_BilledSize / 1000 / 1000 / 1000),2) by SeverityLevel
| extend TotalCost = round(Billable_GB * 5.16, 2)
| extend TotalCost=strcat('$', TotalCost)
| sort by Billable_GB desc
| limit 10
```

</div>
