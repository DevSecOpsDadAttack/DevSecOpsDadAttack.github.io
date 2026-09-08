---
layout: page
title: Top 10 Common Security Logs By Reason With Cost Enhanced
subtitle: "Top `CommonSecurityLog` rows by `Reason` and `LogSeverity` (90d), ranked by event count, with an emoji cost-tier column. Filters out empty/`N/A` reasons."
permalink: /kql-library/cost-and-ingest/top-10-common-security-logs-by-reason-with-cost-enhanced/
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
  <code class="kql-lib-query-file">top-10-common-security-logs-by-reason-with-cost-enhanced.kql</code>
</div>

<p class="kql-lib-query-longdesc">Top `CommonSecurityLog` rows by `Reason` and `LogSeverity` (90d), ranked by event count, with an emoji cost-tier column. Filters out empty/`N/A` reasons.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-top-10-common-security-logs-by-reason-with-cost-enhanced">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/cost-and-ingest/cost-by-table/top-10-common-security-logs-by-reason-with-cost-enhanced.kql' | relative_url }}" download="top-10-common-security-logs-by-reason-with-cost-enhanced.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-top-10-common-security-logs-by-reason-with-cost-enhanced" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Top 10 CommonSecurityLog reasons by event count over the last 90 days, grouped by Reason and
// LogSeverity, with total GB, event count, and an emoji cost-tier indicator.
// Ranked by event volume (which is often more actionable than raw dollar cost when Reason values
// contain common noise like "N/A" — those are filtered out here).
// For a DeviceVendor/DeviceProduct-focused variant with numeric cost, see
// top-10-common-security-logs-by-severity-with-cost.kql.

CommonSecurityLog
| where TimeGenerated > ago(90d)
| where isnotempty(Reason) and Reason != "N/A"
| summarize TotalEvents = count(),
            TotalBytes = sum(_BilledSize)
            by Reason, LogSeverity
| extend TotalGB = round(TotalBytes / (1024.0 * 1024.0 * 1024.0), 4)
| extend RawCost = round(TotalGB * 5.16, 2)   // <-- Replace 5.16 with your region's actual Sentinel price per GB
| extend CostLevel = case(
                         RawCost >= 1000, '🤑🤑🤑🤑🤑',
                         RawCost >= 750, '💰💰💰💰',
                         RawCost >= 500, '💰💰💰',
                         RawCost >= 250, '💰💰',
                         RawCost >= 100, '💰',
                         '💸')
| extend IngestCost = strcat('$', tostring(RawCost), ' ', CostLevel)
| project Reason, LogSeverity, TotalEvents, TotalGB, IngestCost
| top 10 by TotalEvents desc
```

</div>
