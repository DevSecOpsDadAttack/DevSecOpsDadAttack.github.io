---
layout: page
title: Top 10 Alerts
subtitle: "Top 10 alert names over 90 days with percentage of total and color-coded impact level (High / Moderate / Low)."
permalink: /kql-library/health-checks/top-10-alerts/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/health-checks/' | relative_url }}">Health Checks</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-heart-pulse" aria-hidden="true"></i>&nbsp;Health Checks</span>
  <code class="kql-lib-query-file">top-10-alerts.kql</code>
</div>

<p class="kql-lib-query-longdesc">Top 10 alert names over 90 days with percentage of total and color-coded impact level (High / Moderate / Low).</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-top-10-alerts">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/health-checks/top-10-alerts.kql' | relative_url }}" download="top-10-alerts.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-top-10-alerts" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Top 10 Alerts with Percentage of Total Alerts - Updated/Advanced

let totalAlerts = toscalar(SecurityAlert
    | where TimeGenerated > ago(90d)
    | summarize TotalCount = count());
SecurityAlert
| where TimeGenerated > ago(90d)
| summarize Count = count() by AlertName
| top 10 by Count desc
| extend PercentageValue = round((Count * 100.0) / totalAlerts, 2)
| extend Percentage = strcat(PercentageValue, '%')
| extend Alert_Severity = case(
                              PercentageValue > 20,
                              '🔥 High Impact', 
                              PercentageValue > 10,
                              '⚠️ Moderate', 
                              '✅ Low Impact'
                          )
| project AlertName, Count, Percentage, ["Impact Level"] = Alert_Severity
```

</div>
