---
layout: page
title: Which Eventids Are Suddenly Acting Weird With Context
subtitle: "Same deviation analysis as the basic variant, joined with `Computer` and `Account` so you can see which host or user is driving the spike in one shot. Uses a 30-day recent window to reduce join noise."
permalink: /kql-library/hunting/which-eventids-are-suddenly-acting-weird-with-context/
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
  <code class="kql-lib-query-file">which-eventids-are-suddenly-acting-weird-with-context.kql</code>
</div>

<p class="kql-lib-query-longdesc">Same deviation analysis as the basic variant, joined with `Computer` and `Account` so you can see which host or user is driving the spike in one shot. Uses a 30-day recent window to reduce join noise.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-which-eventids-are-suddenly-acting-weird-with-context">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/hunting/eventid-forensics/which-eventids-are-suddenly-acting-weird-with-context.kql' | relative_url }}" download="which-eventids-are-suddenly-acting-weird-with-context.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-which-eventids-are-suddenly-acting-weird-with-context" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// GitHub: https://github.com/EEN421 | Blog: Hanley.cloud / DevSecOpsDad.com

// Which Event IDs have recently spiked, AND which Computer/Account combinations are behind
// the spike? Same baseline-vs-recent deviation approach as
// which-eventids-are-suddenly-acting-weird.kql, but joins in per-actor context to help
// answer "which host or account is driving this?" in one shot.
// Uses a 30-day recent window (vs 7 days in the basic variant) to reduce noise from the
// join. Tune BaselineWindow, RecentWindow, and ThresholdMultiplier for your environment.

let BaselineWindow = 90d;
let RecentWindow = 30d;
let ThresholdMultiplier = 2.0;
let Baseline =
    SecurityEvent
    | where TimeGenerated > ago(BaselineWindow)
    | summarize DailyCount = count() by EventID, Day = bin(TimeGenerated, 1d)
    | summarize AvgDailyCount = round(avg(DailyCount),2) by EventID;
let Recent =
    SecurityEvent
    | where TimeGenerated > ago(RecentWindow)
    | summarize RecentCount = count() by EventID;
Baseline
| join kind=inner Recent on EventID
| extend DeviationRatio = round(RecentCount / AvgDailyCount, 2)
| where DeviationRatio >= ThresholdMultiplier
| project EventID, AvgDailyCount, RecentCount, DeviationRatio
| join (
    SecurityEvent
    | where TimeGenerated > ago(RecentWindow)
    | summarize count() by EventID, Account, Computer
) on EventID
| take 10
| sort by DeviationRatio desc
```

</div>
