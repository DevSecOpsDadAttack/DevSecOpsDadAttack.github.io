---
layout: page
title: Whos Activating Roles Via PIM
subtitle: "PIM role activations from `AuditLogs` — useful for tracking privileged-role usage."
permalink: /kql-library/identity/whos-activating-roles-via-pim/
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
  <code class="kql-lib-query-file">whos-activating-roles-via-pim.kql</code>
</div>

<p class="kql-lib-query-longdesc">PIM role activations from `AuditLogs` — useful for tracking privileged-role usage.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/privilege-escalation/' | relative_url }}">Privilege Escalation</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1078-004/' | relative_url }}">T1078.004</a>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1098-003/' | relative_url }}">T1098.003</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/entra-id/' | relative_url }}">Entra ID</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/auditlogs/' | relative_url }}">AuditLogs</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Deep Dive</span>
    <a class="kql-lib-tag kql-lib-tag-deepdive" href="{{ '/kql-library/tag/deep-dive/' | relative_url }}"><i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive</a>
</div>
<div class="kql-lib-query-actions">
  <a class="kql-lib-deep-dive-btn" href="https://www.hanley.cloud/2026-01-31-KQL-Toolbox-6-From-Junk-Clicks-to-Identity-%26-Privilege-Control/" target="_blank" rel="noopener">
    <i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive
  </a>
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-whos-activating-roles-via-pim">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/identity/whos-activating-roles-via-pim.kql' | relative_url }}" download="whos-activating-roles-via-pim.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-whos-activating-roles-via-pim" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Source: KQL Toolbox #6: From Junk Clicks To Identity & Privilege Control (2026-01-31) — https://www.hanley.cloud/2026-01-31-KQL-Toolbox-6-From-Junk-Clicks-to-Identity-%26-Privilege-Control/
// Great for tracking PIM activations
// Tactics: Privilege Escalation
// Techniques: T1078.004, T1098.003
// Platforms: Entra ID
// Data: AuditLogs

AuditLogs
| where Category == "RoleManagement"
| where ActivityDisplayName == "Add member to role completed (PIM activation)"
| extend Actor = tostring(parse_json(InitiatedBy).user.displayName)
| extend IP = tostring(parse_json(InitiatedBy).user.ipAddress)
| extend Role = tostring(parse_json(TargetResources)[0].displayName)
| extend ActivationTime = TimeGenerated
| project Actor, Role, ActivationTime, IP
```

</div>
