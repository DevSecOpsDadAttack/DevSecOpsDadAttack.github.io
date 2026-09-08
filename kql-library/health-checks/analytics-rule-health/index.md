---
layout: page
title: Analytics Rule Health
subtitle: "Analytics Rules that ran successfully in the last 90 days but never produced an alert — candidates for review or tuning."
permalink: /kql-library/health-checks/analytics-rule-health/
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
  <code class="kql-lib-query-file">analytics-rule-health.kql</code>
</div>

<p class="kql-lib-query-longdesc">Analytics Rules that ran successfully in the last 90 days but never produced an alert — candidates for review or tuning.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-analytics-rule-health">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/health-checks/analytics-rule-health.kql' | relative_url }}" download="analytics-rule-health.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-analytics-rule-health" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
let activeRules = SentinelHealth
| where TimeGenerated >= ago(90d)
| where SentinelResourceType == "Analytics Rule" and Status == "Success"
| summarize by SentinelResourceName;
let alertingRules = SecurityAlert
| where TimeGenerated >= ago(90d)
| distinct AlertName;
activeRules
| where SentinelResourceName !in (alertingRules)
```

</div>
