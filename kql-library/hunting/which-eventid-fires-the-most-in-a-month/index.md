---
layout: page
title: Which Eventid Fires The Most In A Month
subtitle: "Noisiest Event IDs across the last month — good for spotting new noise sources."
permalink: /kql-library/hunting/which-eventid-fires-the-most-in-a-month/
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
  <code class="kql-lib-query-file">which-eventid-fires-the-most-in-a-month.kql</code>
</div>

<p class="kql-lib-query-longdesc">Noisiest Event IDs across the last month — good for spotting new noise sources.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-which-eventid-fires-the-most-in-a-month">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/hunting/eventid-forensics/which-eventid-fires-the-most-in-a-month.kql' | relative_url }}" download="which-eventid-fires-the-most-in-a-month.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-which-eventid-fires-the-most-in-a-month" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Ever wonder which Event IDs bring the most noise?

SecurityEvent                       // <--Define the table to query
| where TimeGenerated > ago(30d)    // <--Query the last 30 days
| summarize count() by EventID      // <--Return number of hits per EventID
| sort by count_ desc               // <--Bring heaviest hitters to the top
| take 10                           // <--Take the top 10
| render columnchart                // <--Helps visualize which EventIDs are the heavy hitters
```

</div>
