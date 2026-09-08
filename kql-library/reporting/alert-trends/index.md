---
layout: page
title: Alert Trends
subtitle: "Alerts with significant increases vs the previous 90-day period, with severity categorized."
permalink: /kql-library/reporting/alert-trends/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/reporting/' | relative_url }}">Reporting</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-chart-line" aria-hidden="true"></i>&nbsp;Reporting</span>
  <code class="kql-lib-query-file">alert-trends.kql</code>
</div>

<p class="kql-lib-query-longdesc">Alerts with significant increases vs the previous 90-day period, with severity categorized.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-alert-trends">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/reporting/alert-trends.kql' | relative_url }}" download="alert-trends.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-alert-trends" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Identifies alerts with significant increases compared to the previous period and categorizes severity levels.
let timeRange = 90d;
SecurityAlert
| where TimeGenerated > ago(timeRange)
| summarize CurrentCount = count() by AlertName
| join kind=fullouter (
    SecurityAlert
    | where TimeGenerated > ago(2 * timeRange) and TimeGenerated <= ago(timeRange)
    | summarize PreviousCount = count() by AlertName
) on AlertName
| project AlertName, 
          CurrentCount = coalesce(CurrentCount, 0), 
          PreviousCount = coalesce(PreviousCount, 0),
          PercentChange = iff(PreviousCount == 0, 100.0, (CurrentCount - PreviousCount) * 100.0 / PreviousCount)
// Apply filters to focus on meaningful trends
| where CurrentCount > 10 
| where PercentChange > 50 
// Assign severity level indicators
| extend SeverityIndicator = case(
    PercentChange >= 500, "🔥 Extreme Spike",
    PercentChange >= 200, "🔴 Critical Increase",
    PercentChange >= 100, "🟠 Major Increase",
    PercentChange >= 50, "🟡 Moderate Increase",
    "🟢 Low Increase"
)
// Apply color coding to % Change
| extend ChangeColor = case(
    PercentChange > 200, "🔴",
    PercentChange > 100, "🟠",
    PercentChange > 50, "🟡",
    "🟢"
)
// Sort by absolute % change in descending order to highlight most significant shifts
| sort by abs(PercentChange) desc
| top 10 by abs(PercentChange) desc
// Improve column naming for readability
| project ["Alert Type"] = AlertName, 
          ["Current Period Alerts"] = CurrentCount, 
          ["Previous Period Alerts"] = PreviousCount, 
          ["% Change"] = strcat(ChangeColor, " ", round(PercentChange, 2), "%"),
          ["Severity"] = SeverityIndicator
```

</div>
