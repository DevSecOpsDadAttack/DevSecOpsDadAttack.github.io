---
layout: page
title: How Many Times Does This Eventid Fire From This Machine
subtitle: "Count of a specific Event ID from a specific machine, bucketed daily and rendered as a column chart."
permalink: /kql-library/hunting/how-many-times-does-this-eventid-fire-from-this-machine/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/hunting/' | relative_url }}">Hunting</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-magnifying-glass" aria-hidden="true"></i>&nbsp;Hunting</span>
  <span class="attack-badge attack-badge-sub">Eventid Forensics</span>
  <code class="kql-lib-query-file">how-many-times-does-this-eventid-fire-from-this-machine.kql</code>
</div>

<p class="kql-lib-query-longdesc">Count of a specific Event ID from a specific machine, bucketed daily and rendered as a column chart.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/discovery/' | relative_url }}">Discovery</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/windows/' | relative_url }}">Windows</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/securityevent/' | relative_url }}">SecurityEvent</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-how-many-times-does-this-eventid-fire-from-this-machine">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/hunting/eventid-forensics/how-many-times-does-this-eventid-fire-from-this-machine.kql' | relative_url }}" download="how-many-times-does-this-eventid-fire-from-this-machine.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-how-many-times-does-this-eventid-fire-from-this-machine" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
//How Many Times Has This Machine Thrown This Event Today?
// Tactics: Discovery
// Platforms: Windows
// Data: SecurityEvent

SecurityEvent                                                                               // <--Define the table to query
| where EventID == "EventID"                                                                // <--Define the EventID to query for
| where Computer == "ThisDevice"                                                            // <--Define the scope (which machine)
| where TimeGenerated >= startofday(ago(1d)) and TimeGenerated <= startofday(now())         // <--Define the time span to query
| summarize count() by bin(TimeGenerated,1d)                                                // <--Return results by frequency per day
| render columnchart                                                                        // <--(Optional) Graph results to chart
```

</div>
