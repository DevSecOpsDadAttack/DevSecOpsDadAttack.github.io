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

<div class="kql-lib-query-actions">
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
// Great for tracking PIM activations

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
