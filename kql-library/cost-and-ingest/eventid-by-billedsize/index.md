---
layout: page
title: Eventid By Billedsize
subtitle: "Ingest volume in GB per Event ID from the `SecurityEvent` table."
permalink: /kql-library/cost-and-ingest/eventid-by-billedsize/
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
  <code class="kql-lib-query-file">eventid-by-billedsize.kql</code>
</div>

<p class="kql-lib-query-longdesc">Ingest volume in GB per Event ID from the `SecurityEvent` table.</p>

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
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-eventid-by-billedsize">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/cost-and-ingest/cost-by-eventid/eventid-by-billedsize.kql' | relative_url }}" download="eventid-by-billedsize.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-eventid-by-billedsize" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
//Return the ingest volume in GB for a given EventID from the SecurityEvent table
// Platforms: Windows, Microsoft Sentinel
// Data: SecurityEvent

SecurityEvent		             		        //<-- Query the SecurityEvent table
| where TimeGenerated > ago(1h)		            	//<-- Query the last hour
| where EventID == 8002			                //<-- Query for EventID 8002
| summarize GB=sum(_BilledSize)/1000/1000/1000	        //<-- Summarize billable volume in GB

//You can change the last line in the above query to the following if you’re a stickler for Gibibytes versus Gigabytes: 

| summarize GB=sum(_BilledSize)/1024/1024/1024	
```

</div>
