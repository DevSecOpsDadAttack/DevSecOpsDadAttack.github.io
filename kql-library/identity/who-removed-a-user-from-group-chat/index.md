---
layout: page
title: Who Removed A User From Group Chat
subtitle: "Teams-related removal actions performed by a specific user in the last 7 days, from `OfficeActivity` / Unified Audit Log."
permalink: /kql-library/identity/who-removed-a-user-from-group-chat/
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
  <code class="kql-lib-query-file">who-removed-a-user-from-group-chat.kql</code>
</div>

<p class="kql-lib-query-longdesc">Teams-related removal actions performed by a specific user in the last 7 days, from `OfficeActivity` / Unified Audit Log.</p>

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
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/microsoft-365/' | relative_url }}">Microsoft 365</a>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/teams/' | relative_url }}">Teams</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/officeactivity/' | relative_url }}">OfficeActivity</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-who-removed-a-user-from-group-chat">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/identity/who-removed-a-user-from-group-chat.kql' | relative_url }}" download="who-removed-a-user-from-group-chat.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-who-removed-a-user-from-group-chat" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
//This is a targeted audit query for: “Show me all Teams-related removal actions performed by a specific user in the last 7 days.”
// Tactics: Impact
// Techniques: T1531
// Platforms: Microsoft 365, Teams
// Data: OfficeActivity

OfficeActivity                             // Pull from Office 365 activity logs (Unified Audit Log)
| where TimeGenerated > ago(7d)            // Scope to last 7 days → keeps query performant and relevant
| where OfficeWorkload == "MicrosoftTeams" // Focus only on Microsoft Teams workload events
| where Operation has_any ("MemberRemoved", "Removed") // Look for removal-type actions
| where UserId == "first.last@domain.com" // Filter to a specific user (target of investigation)
| project   // Select only the fields we care about for triage
    TimeGenerated,   // When the action occurred
    UserId,          // Who performed the action (important distinction)
    Operation,       // Type of removal event
    TeamName,        // Team context (if applicable)
    ChannelName,     // Channel context (may be empty for chats)
    Members          // Often contains the affected users (key field for investigation)
| order by TimeGenerated desc // Show most recent events first for analyst workflow
```

</div>
