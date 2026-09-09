---
layout: page
title: File Activity Audit
subtitle: "Timestamped file activity (open, read, modify, delete, create) by user and device. Written for a client that needed to demonstrate this capability to an auditor."
permalink: /kql-library/hunting/file-activity-audit/
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
  <span class="attack-badge attack-badge-sub">File Activity</span>
  <code class="kql-lib-query-file">file-activity-audit.kql</code>
</div>

<p class="kql-lib-query-longdesc">Timestamped file activity (open, read, modify, delete, create) by user and device. Written for a client that needed to demonstrate this capability to an auditor.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/discovery/' | relative_url }}">Discovery</a>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/collection/' | relative_url }}">Collection</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1083/' | relative_url }}">T1083</a>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1005/' | relative_url }}">T1005</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/windows/' | relative_url }}">Windows</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/devicefileevents/' | relative_url }}">DeviceFileEvents</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-file-activity-audit">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/hunting/file-activity/file-activity-audit.kql' | relative_url }}" download="file-activity-audit.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-file-activity-audit" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// I wrote this up for a client that needed to prove to an auditor that they could track file activities (open, read, modify, delete, create, etc.) by user and device with timestamps. 
// Tactics: Discovery, Collection
// Techniques: T1083, T1005
// Platforms: Windows
// Data: DeviceFileEvents

union DeviceEvents,DeviceNetworkEvents,DeviceFileEvents    //<-- query Device Events, DeviceNetworkEvents, and DeviceFileEvents tables and combine the results.
| where RemoteUrl contains '' or FileOriginUrl != '' or FileOriginReferrerUrl != ''    //<-- show me every website URL, file URL, etc. that this user has touched.
| where InitiatingProcessAccountName contains 'InitiatingProcessAccountName'  //<-- swap out InitiatingProcessAccountName for a user you want to track activity for, like 'john.smith' for example.
| where ActionType contains "File" and ActionType !contains "Shell"
| summarize count() by InitiatingProcessAccountName,ActionType,FileName,RemoteUrl,FileOriginUrl,FileOriginReferrerUrl, TimeGenerated, DeviceName  //<-- Return time-stamped results for each action.
| project-away count_
```

</div>
