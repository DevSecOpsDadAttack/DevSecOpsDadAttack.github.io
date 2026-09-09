---
layout: page
title: Which Devices Are Throwing This Eventid
subtitle: "Which computers fire a specific Event ID and how often, per day."
permalink: /kql-library/hunting/which-devices-are-throwing-this-eventid/
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
  <code class="kql-lib-query-file">which-devices-are-throwing-this-eventid.kql</code>
</div>

<p class="kql-lib-query-longdesc">Which computers fire a specific Event ID and how often, per day.</p>

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
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-which-devices-are-throwing-this-eventid">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/hunting/eventid-forensics/which-devices-are-throwing-this-eventid.kql' | relative_url }}" download="which-devices-are-throwing-this-eventid.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-which-devices-are-throwing-this-eventid" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Ever wonder how many times each computer in your environment throws a specific EventID per day?
// Tactics: Discovery
// Platforms: Windows
// Data: SecurityEvent

SecurityEvent                     // <--Define the table to query
| where EventID == "8002"         // <--Declare which EventID you're looking for
| summarize count() by Computer   // <--Show how many times that EventID was thrown per device
| render columnchart              // <--Optional, but helps quickly visualize potential outliers
```

</div>
