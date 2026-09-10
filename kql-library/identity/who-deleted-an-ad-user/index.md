---
layout: page
title: Who Deleted An AD User
subtitle: "Who deleted an AD user (`SecurityEvent` EventID `4726`) over the last 90 days."
permalink: /kql-library/identity/who-deleted-an-ad-user/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/identity/' | relative_url }}">Identity</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-user-shield" aria-hidden="true"></i>&nbsp;Identity</span>
  <code class="kql-lib-query-file">who-deleted-an-ad-user.kql</code>
</div>

<p class="kql-lib-query-longdesc">Who deleted an AD user (`SecurityEvent` EventID `4726`) over the last 90 days.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/impact/' | relative_url }}">Impact</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1531/' | relative_url }}">T1531</a>
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
  <a class="kql-lib-deep-dive-btn" href="https://www.hanley.cloud/2026-01-31-KQL-Toolbox-6-From-Junk-Clicks-to-Identity-%26-Privilege-Control/" target="_blank" rel="noopener">
    <i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive
  </a>
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-who-deleted-an-ad-user">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/identity/who-deleted-an-ad-user.kql' | relative_url }}" download="who-deleted-an-ad-user.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-who-deleted-an-ad-user" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Source: KQL Toolbox #6: From Junk Clicks To Identity & Privilege Control (2026-01-31) — https://www.hanley.cloud/2026-01-31-KQL-Toolbox-6-From-Junk-Clicks-to-Identity-%26-Privilege-Control/
// Tactics: Impact
// Techniques: T1531
// Platforms: Windows
// Data: SecurityEvent
SecurityEvent
| where TimeGenerated > ago (90d)
| where EventID == "4726"
| extend Actor_ = Account
| project-reorder TimeGenerated, Activity, Actor_, TargetUserName, Computer
```

</div>
