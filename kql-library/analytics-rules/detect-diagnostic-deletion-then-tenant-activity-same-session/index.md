---
layout: page
title: Detect Diagnostic Deletion Then Tenant Activity Same Session
subtitle: "Enhanced log-suppression sequence detection that further requires the follow-on activity to share the same CallerIpAddress — same session, not just same identity."
permalink: /kql-library/analytics-rules/detect-diagnostic-deletion-then-tenant-activity-same-session/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/analytics-rules/' | relative_url }}">Analytics Rules</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-shield-halved" aria-hidden="true"></i>&nbsp;Analytics Rules</span>
  <code class="kql-lib-query-file">detect-diagnostic-deletion-then-tenant-activity-same-session.kql</code>
</div>

<p class="kql-lib-query-longdesc">Enhanced log-suppression sequence detection that further requires the follow-on activity to share the same CallerIpAddress — same session, not just same identity.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/defense-evasion/' | relative_url }}">Defense Evasion</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1562-008/' | relative_url }}">T1562.008</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/azure/' | relative_url }}">Azure</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/azureactivity/' | relative_url }}">AzureActivity</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-detect-diagnostic-deletion-then-tenant-activity-same-session">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/analytics-rules/detect-diagnostic-deletion-then-tenant-activity-same-session.kql' | relative_url }}" download="detect-diagnostic-deletion-then-tenant-activity-same-session.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-detect-diagnostic-deletion-then-tenant-activity-same-session" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Enhanced variant of the log-suppression sequence detection that further requires the follow-on
// activity to share the same CallerIpAddress as the deletion — same session, not just same
// identity. Reduces false positives when the same admin identity is legitimately active in an
// unrelated session at the same time.
// Source: KQL Detection of the Week: Detecting Cloud Logging Suppression (T1562.008) (2026-06-12) — https://devsecopsdadattack.com/2026-06-12-KQL-of-the-Week_-Detecting-Cloud-Logging-Suppression-T1562-008/
// Tactics: Defense Evasion
// Techniques: T1562.008
// Platforms: Azure
// Data: AzureActivity

let followOnActivity = AzureActivity
    | where TimeGenerated > ago(lookback)
    | where ActivityStatus in ("Succeeded", "Success")
    | where tolower(OperationName) !in (deletionOps)
    | summarize FollowOnTime = min(TimeGenerated),
        FollowOnOperation = take_any(OperationName),
        FollowOnResource = take_any(ResourceId),
        FollowOnIp = take_any(CallerIpAddress)            // carry the IP through
        by Caller, bin(TimeGenerated, 1m)
    | project FollowOnTime, Caller, FollowOnResource, FollowOnOperation, FollowOnIp;
loggingDeletions
| join kind=inner followOnActivity on Caller
| where FollowOnTime >= DeletionTime and FollowOnTime <= DeletionTime + followOnWindow
| where FollowOnResource != DeletedResource
| where FollowOnIp == CallerIpAddress                     // same session, not just same person
| extend TimeDeltaMinutes = datetime_diff('minute', FollowOnTime, DeletionTime)
| project DeletionTime, FollowOnTime, TimeDeltaMinutes, Caller, CallerIpAddress, DeletedResource, FollowOnResource, FollowOnOperation
| order by DeletionTime desc
```

</div>
