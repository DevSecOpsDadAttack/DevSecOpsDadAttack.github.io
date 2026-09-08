---
layout: page
title: Detect Diagnostic Deletion Then Tenant Activity Sequence
subtitle: "T1562.008 sequence: Azure diagnostic-setting deletion followed by any activity from the same Caller within 60 minutes."
permalink: /kql-library/analytics-rules/detect-diagnostic-deletion-then-tenant-activity-sequence/
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
  <code class="kql-lib-query-file">detect-diagnostic-deletion-then-tenant-activity-sequence.kql</code>
</div>

<p class="kql-lib-query-longdesc">T1562.008 sequence: Azure diagnostic-setting deletion followed by any activity from the same Caller within 60 minutes.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-detect-diagnostic-deletion-then-tenant-activity-sequence">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/analytics-rules/detect-diagnostic-deletion-then-tenant-activity-sequence.kql' | relative_url }}" download="detect-diagnostic-deletion-then-tenant-activity-sequence.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-detect-diagnostic-deletion-then-tenant-activity-sequence" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Sequence detection for T1562.008 cloud-logging suppression: pairs an Azure diagnostic-setting
// deletion with any follow-on activity by the same Caller within 60 minutes. Separates admins from
// attackers by shape rather than event content — one modifies logging and goes to lunch, the other
// modifies logging and starts touching things.
// Source: KQL Detection of the Week: Detecting Cloud Logging Suppression (T1562.008) (2026-06-12) — https://devsecopsdadattack.com/2026-06-12-KQL-of-the-Week_-Detecting-Cloud-Logging-Suppression-T1562-008/

let lookback = 4h;
let followOnWindow = 60m;
let deletionOps = dynamic([
    "microsoft.insights/diagnosticsettings/delete",
    "microsoft.insights/logprofiles/delete",
    "microsoft.operationalinsights/workspaces/delete"
]);
let loggingDeletions = AzureActivity
    | where TimeGenerated > ago(lookback)
    | where tolower(OperationName) in (deletionOps)
    | where ActivityStatus in ("Succeeded", "Success")
    | project DeletionTime = TimeGenerated, Caller, DeletedResource = ResourceId, CallerIpAddress;
let followOnActivity = AzureActivity
    | where TimeGenerated > ago(lookback)
    | where ActivityStatus in ("Succeeded", "Success")
    | where tolower(OperationName) !in (deletionOps)
    | summarize FollowOnTime = min(TimeGenerated), FollowOnOperation = take_any(OperationName), FollowOnResource = take_any(ResourceId) by Caller, bin(TimeGenerated, 1m)
    | project FollowOnTime, Caller, FollowOnResource, FollowOnOperation;
loggingDeletions
| join kind=inner followOnActivity on Caller
| where FollowOnTime >= DeletionTime and FollowOnTime <= DeletionTime + followOnWindow
| where FollowOnResource != DeletedResource
| extend TimeDeltaMinutes = datetime_diff('minute', FollowOnTime, DeletionTime)
| project DeletionTime, FollowOnTime, TimeDeltaMinutes, Caller, CallerIpAddress, DeletedResource, FollowOnResource, FollowOnOperation
| order by DeletionTime desc
```

</div>
