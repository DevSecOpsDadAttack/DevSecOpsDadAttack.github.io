---
layout: page
title: Which Eventids Are Suddenly Acting Weird
subtitle: "Which Event IDs have recently spiked (7d) versus their 90-day baseline, sorted by deviation ratio. Basic variant — just EventID + counts."
permalink: /kql-library/hunting/which-eventids-are-suddenly-acting-weird/
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
  <code class="kql-lib-query-file">which-eventids-are-suddenly-acting-weird.kql</code>
</div>

<p class="kql-lib-query-longdesc">Which Event IDs have recently spiked (7d) versus their 90-day baseline, sorted by deviation ratio. Basic variant — just EventID + counts.</p>

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
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Deep Dive</span>
    <a class="kql-lib-tag kql-lib-tag-deepdive" href="{{ '/kql-library/tag/deep-dive/' | relative_url }}"><i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive</a>
</div>
<div class="kql-lib-query-actions">
  <a class="kql-lib-deep-dive-btn" href="https://www.hanley.cloud/2026-01-10-KQL-Toolbox-3-Which-Event-ID-Noises-Up-Your-Logs-%28and-Who-s-Causing-It%29/" target="_blank" rel="noopener">
    <i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive
  </a>
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-which-eventids-are-suddenly-acting-weird">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/hunting/eventid-forensics/which-eventids-are-suddenly-acting-weird.kql' | relative_url }}" download="which-eventids-are-suddenly-acting-weird.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-which-eventids-are-suddenly-acting-weird" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// GitHub: https://github.com/EEN421 | Blog: Hanley.cloud / DevSecOpsDad.com
// Source: KQL Toolbox #3: Which Event ID Noises Up Your Logs (and Who’s Causing It)? (2026-01-10) — https://www.hanley.cloud/2026-01-10-KQL-Toolbox-3-Which-Event-ID-Noises-Up-Your-Logs-%28and-Who-s-Causing-It%29/
// Tactics: Discovery
// Platforms: Windows
// Data: SecurityEvent

// Which Event IDs have recently spiked well beyond their 90-day historical baseline?
// Returns EventID, baseline avg daily count, recent avg daily count, and the deviation
// ratio — sorted by biggest deviation first. Use this to spot noisy/unexpected changes
// in your SecurityEvent telemetry. For a variant that also tells you which
// Computer/Account combinations are behind the spike, see the -with-context file
// in this same folder.
// If you spot unexpected deviations and need help determining whether it’s signal,
// noise, or misconfiguration, check out the KQL Detective series at hanley.cloud.

let BaselineWindow = 90d;
let RecentWindow = 7d;
let ThresholdMultiplier = 2.0;
let Baseline =
SecurityEvent
| where TimeGenerated > ago(BaselineWindow)
| summarize DailyCount=count() by EventID, Day=bin(TimeGenerated, 1d)
| summarize BaselineAvgDaily=round(avg(DailyCount),2) by EventID;
let Recent =
SecurityEvent
| where TimeGenerated > ago(RecentWindow)
| summarize RecentDailyCount=count() by EventID, Day=bin(TimeGenerated, 1d)
| summarize RecentAvgDaily=round(avg(RecentDailyCount),2) by EventID;
Baseline
| join kind=inner Recent on EventID
| extend DeviationRatio=round(RecentAvgDaily / BaselineAvgDaily, 2)
| where DeviationRatio >= ThresholdMultiplier
| project EventID, BaselineAvgDaily, RecentAvgDaily, DeviationRatio
| sort by DeviationRatio desc
| take 10
```

</div>
