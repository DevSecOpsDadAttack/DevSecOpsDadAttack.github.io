---
layout: page
title: Hunt First Time Admin Operation User Baseline
subtitle: "Baselines identities that have ever executed admin operations, then alerts when an account outside that set succeeds — 'the admin who has never administered.'"
permalink: /kql-library/hunting/hunt-first-time-admin-operation-user-baseline/
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
  <code class="kql-lib-query-file">hunt-first-time-admin-operation-user-baseline.kql</code>
</div>

<p class="kql-lib-query-longdesc">Baselines identities that have ever executed admin operations, then alerts when an account outside that set succeeds — 'the admin who has never administered.'</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-hunt-first-time-admin-operation-user-baseline">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/hunting/hunt-first-time-admin-operation-user-baseline.kql' | relative_url }}" download="hunt-first-time-admin-operation-user-baseline.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-hunt-first-time-admin-operation-user-baseline" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Baselines which identities have ever executed admin operations, then alerts when an account
// outside that set successfully performs one — 'the admin who has never administered.' First-seen
// baseline structurally similar to first-country-seen for OAuth tokens.
// Source: KQL Detection of the Week: The Query That Wrote Itself Eight Times (2026-08-18) — https://devsecopsdadattack.com/2026-08-18-KQL-Detection-of-the-Week-The-Query-That-Wrote-Itself-Eight-Times/

let baseline_window = 60d;
let detection_window = 1d;
let admin_ops = dynamic([
    "SiteCollectionAdminAdded","PermissionLevelAdded","PermissionLevelModified",
    "AddedToGroup","SiteAdminChangeRequest","SiteCollectionCreated"
]);
// Baseline: who has performed admin operations in the past, and how often?
// Frequency matters: an account that did it once in 60 days is not the same
// risk profile as one that does it daily.
let AdminBaseline = OfficeActivity
| where TimeGenerated between (ago(baseline_window) .. ago(detection_window))
| where OfficeWorkload == "SharePoint"
| where Operation in (admin_ops)
| where ResultStatus == "Succeeded"
| summarize
    BaselineOps   = count(),
    BaselineDays  = dcount(bin(TimeGenerated, 1d)),
    LastBaseline   = max(TimeGenerated),
    BaselineOpsSet = make_set(Operation, 10)
    by UserId;
// Detection window: privileged operations from accounts not in the baseline.
let RecentOps = OfficeActivity
| where TimeGenerated > ago(detection_window)
| where OfficeWorkload == "SharePoint"
| where Operation in (admin_ops)
| where ResultStatus == "Succeeded"
| project TimeGenerated, UserId, ClientIP, Operation, SiteUrl, ResultStatus;
// NEW admins: accounts with zero baseline history.
let NewAdmins = RecentOps
| join kind=leftanti AdminBaseline on UserId
| extend AdminType = "NeverSeenBefore";
// RARE admins: accounts IN the baseline but with very low frequency.
// A "known admin" who performed one operation 58 days ago is not the same
// as a daily operator, and the leftanti would have let them through.
let RareAdmins = RecentOps
| join kind=inner AdminBaseline on UserId
| where BaselineOps <= 2 and BaselineDays <= 1
| extend AdminType = "RarelySeenBefore";
// Union both. NeverSeenBefore is a stronger signal; RarelySeenBefore is
// a hunt. Both appear in the output, ranked.
union NewAdmins, RareAdmins
| summarize
    Ops             = count(),
    Operations      = make_set(Operation, 10),
    SourceIPs       = make_set(ClientIP, 10),
    SiteUrls        = make_set(SiteUrl, 10),
    FirstSeen       = min(TimeGenerated),
    LastSeen        = max(TimeGenerated)
    by UserId, AdminType
| order by AdminType asc, Ops desc
```

</div>
