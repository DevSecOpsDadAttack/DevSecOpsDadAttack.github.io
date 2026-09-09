---
layout: page
title: Detect Smartconnect Session Without Signin
subtitle: "Microsoft SmartConnect (CVE-2026-55040) sessions lacking a corresponding sign-in event — absence-detection with windowed leftouter + countif."
permalink: /kql-library/analytics-rules/detect-smartconnect-session-without-signin/
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
  <code class="kql-lib-query-file">detect-smartconnect-session-without-signin.kql</code>
</div>

<p class="kql-lib-query-longdesc">Microsoft SmartConnect (CVE-2026-55040) sessions lacking a corresponding sign-in event — absence-detection with windowed leftouter + countif.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/defense-evasion/' | relative_url }}">Defense Evasion</a>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/initial-access/' | relative_url }}">Initial Access</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1550/' | relative_url }}">T1550</a>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1078-004/' | relative_url }}">T1078.004</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/microsoft-365/' | relative_url }}">Microsoft 365</a>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/sharepoint/' | relative_url }}">SharePoint</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/officeactivity/' | relative_url }}">OfficeActivity</a>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/signinlogs/' | relative_url }}">SigninLogs</a>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/aadnoninteractiveusersigninlogs/' | relative_url }}">AADNonInteractiveUserSignInLogs</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Deep Dive</span>
    <a class="kql-lib-tag kql-lib-tag-deepdive" href="{{ '/kql-library/tag/deep-dive/' | relative_url }}"><i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive</a>
</div>
<div class="kql-lib-query-actions">
  <a class="kql-lib-deep-dive-btn" href="https://devsecopsdadattack.com/2026-07-20-KQL-Detection-of-the-Week_-The-Dog-That-Didn_t-Bark/" target="_blank" rel="noopener">
    <i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive
  </a>
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-detect-smartconnect-session-without-signin">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/analytics-rules/detect-smartconnect-session-without-signin.kql' | relative_url }}" download="detect-smartconnect-session-without-signin.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-detect-smartconnect-session-without-signin" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Detects Microsoft SmartConnect (CVE-2026-55040) sessions that lack a corresponding sign-in event
// — the classic absence-detection pattern applied to the SmartConnect auth-bypass. Uses windowed
// leftouter + countif for reliable time-bounded absence.
// Source: KQL Detection of the Week: The Dog That Didn't Bark (2026-07-20) — https://devsecopsdadattack.com/2026-07-20-KQL-Detection-of-the-Week_-The-Dog-That-Didn_t-Bark/
// Tactics: Defense Evasion, Initial Access
// Techniques: T1550, T1078.004
// Platforms: Microsoft 365, SharePoint
// Data: OfficeActivity, SigninLogs, AADNonInteractiveUserSignInLogs

let accessWindow = 1d;
let signinWindow = 2d;
let sharepoint_access = OfficeActivity
| where TimeGenerated > ago(accessWindow)
| where OfficeWorkload == "SharePoint"
| where ResultStatus =~ "Succeeded"
| extend CompositeKey = strcat(tolower(UserId), "|", ClientIP)
| project SPTime = TimeGenerated, UserId, ClientIP, Operation, SiteUrl, CompositeKey;
let all_signins = union
    (SigninLogs
    | where TimeGenerated > ago(signinWindow)
    | where ResultType == 0
    | project CompositeKey = strcat(tolower(UserPrincipalName), "|", IPAddress)),
    (AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(signinWindow)
    | where ResultType == 0
    | project CompositeKey = strcat(tolower(UserPrincipalName), "|", IPAddress))
| distinct CompositeKey;
sharepoint_access
| join kind=leftanti all_signins on CompositeKey
| project SPTime, UserId, ClientIP, Operation, SiteUrl
| order by SPTime desc
```

</div>
