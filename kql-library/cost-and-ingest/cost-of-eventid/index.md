---
layout: page
title: Cost Of Eventid
subtitle: "Estimated cost of a single Event ID over a time window, using your effective per-GB rate."
permalink: /kql-library/cost-and-ingest/cost-of-eventid/
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
  <code class="kql-lib-query-file">cost-of-eventid.kql</code>
</div>

<p class="kql-lib-query-longdesc">Estimated cost of a single Event ID over a time window, using your effective per-GB rate.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/windows/' | relative_url }}">Windows</a>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/microsoft-sentinel/' | relative_url }}">Microsoft Sentinel</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/securityevent/' | relative_url }}">SecurityEvent</a>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/windowsevent/' | relative_url }}">WindowsEvent</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-cost-of-eventid">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/cost-and-ingest/cost-by-eventid/cost-of-eventid.kql' | relative_url }}" download="cost-of-eventid.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-cost-of-eventid" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// This query will tell you how much any EventID is costing you over a given time
// For this query, the 'rate' acts like a global floating point variable which is manually defined
// You can calculate the LAW cost and Sentinel cost separately, or both (effective cost per GB) by setting the rate variable
// The rate for your region can be found here: https://azure.microsoft.com/en-us/pricing/details/microsoft-sentinel/
// This doesn't have to be over the last hour, you can adjust the TimeGenerated parameter to a week (7d), a day (1d), or even a month (30d) etc.
// Platforms: Windows, Microsoft Sentinel
// Data: SecurityEvent, WindowsEvent

let rate = 4.30;                                        //<-- Effective Cost per GB
SecurityEvent		             		        //<-- Query the SecurityEvent table
| where TimeGenerated > ago(1h)		            	//<-- Query the last hour
| where EventID == 8002			                //<-- Query for EventID 8002
| summarize GB=sum(_BilledSize)/1000/1000/1000	        //<-- Summarize billable volume in GB using the _BilledSize table column
| extend cost = GB*rate                                 //<-- Multiply total GBs for the month by the effective rate (defined in first line of query)

//You can change the last line in the above query to the following if you’re a stickler for Gibibytes versus Gigabytes: 
| summarize GB=sum(_BilledSize)/1024/1024/1024	

+++++++++++++++++++++++++++++++++++++++++++++++++

SecurityEvent
| where TimeGenerated >ago(90d)
| where EventID == "5156"
| where _IsBillable == True
| summarize Billable_GB=round(sum(_BilledSize / 1000 / 1000 / 1000),2) by Computer
| extend TotalCost = round(Billable_GB * 2.74, 2)
| extend TotalCost=strcat('$', TotalCost)
| sort by Billable_GB desc
| limit 10
```

</div>
