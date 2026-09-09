---
layout: page
title: Whats This User Doing
subtitle: "Unions `DeviceEvents`, `DeviceNetworkEvents`, and `DeviceFileEvents` to give a timestamped activity trace for a single user, including URLs touched. Swiss-army knife for user investigations — includes a Facebook-usage example."
permalink: /kql-library/hunting/whats-this-user-doing/
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
  <span class="attack-badge attack-badge-sub">User Activity</span>
  <code class="kql-lib-query-file">whats-this-user-doing.kql</code>
</div>

<p class="kql-lib-query-longdesc">Unions `DeviceEvents`, `DeviceNetworkEvents`, and `DeviceFileEvents` to give a timestamped activity trace for a single user, including URLs touched. Swiss-army knife for user investigations — includes a Facebook-usage example.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/discovery/' | relative_url }}">Discovery</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/microsoft-365/' | relative_url }}">Microsoft 365</a>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/entra-id/' | relative_url }}">Entra ID</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/officeactivity/' | relative_url }}">OfficeActivity</a>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/signinlogs/' | relative_url }}">SigninLogs</a>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/auditlogs/' | relative_url }}">AuditLogs</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-whats-this-user-doing">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/hunting/user-activity/whats-this-user-doing.kql' | relative_url }}" download="whats-this-user-doing.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-whats-this-user-doing" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// This is great for tracking down activity for 'those' users (every company has one). 
// Be warned, this is a powerful query that could get you into GDPR trouble as it returns a detailed account of user activity history, including browser URLs etc. 
// Tactics: Discovery
// Platforms: Microsoft 365, Entra ID
// Data: OfficeActivity, SigninLogs, AuditLogs

union DeviceEvents,DeviceNetworkEvents,DeviceFileEvents    //<-- query Device Events, DeviceNetworkEvents, and DeviceFileEvents tables and combine the results.
| where RemoteUrl contains '' or FileOriginUrl != '' or FileOriginReferrerUrl != ''    //<-- show me every website URL, file URL, etc. that this user has touched.
| where InitiatingProcessAccountName contains 'InitiatingProcessAccountName'  //<-- swap out InitiatingProcessAccountName for a user you want to track activity for (leave the '').
| summarize count() by Type,ActionType,RemoteUrl,FileOriginUrl,FileOriginReferrerUrl, TimeGenerated, DeviceName  //<-- Return time-stamped results for each action.


// The below example has been tweaked to show time-stamped Facebook usage by device. This query is like a swiss army knife given you can potentially do with it. Keep it in your toolbelt. 

union DeviceEvents,DeviceNetworkEvents,DeviceFileEvents    //<-- query Device Events, DeviceNetworkEvents, and DeviceFileEvents tables and combine the results.
| where RemoteUrl contains 'facebook'    //<-- show me every instance where this user visited Facebook.
| where InitiatingProcessAccountName contains 'InitiatingProcessAccountName'  //<-- swap out InitiatingProcessAccountName for an user you want to track activity for (leave the '').
| summarize count() by Type,ActionType,RemoteUrl,FileOriginUrl,FileOriginReferrerUrl, TimeGenerated, DeviceName  //<-- Return time-stamped results for each action and the Device it was performed from.
```

</div>
