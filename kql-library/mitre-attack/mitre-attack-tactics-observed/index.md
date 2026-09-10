---
layout: page
title: Mitre Attack Tactics Observed
subtitle: "Events mapped against MITRE ATT&CK Tactics that have been observed in the environment, with percentage of total."
permalink: /kql-library/mitre-attack/mitre-attack-tactics-observed/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/mitre-attack/' | relative_url }}">MITRE ATT&amp;CK</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-crosshairs" aria-hidden="true"></i>&nbsp;MITRE ATT&amp;CK</span>
  <code class="kql-lib-query-file">mitre-attack-tactics-observed.kql</code>
</div>

<p class="kql-lib-query-longdesc">Events mapped against MITRE ATT&amp;CK Tactics that have been observed in the environment, with percentage of total.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/microsoft-sentinel/' | relative_url }}">Microsoft Sentinel</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/securityalert/' | relative_url }}">SecurityAlert</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Deep Dive</span>
    <a class="kql-lib-tag kql-lib-tag-deepdive" href="{{ '/kql-library/tag/deep-dive/' | relative_url }}"><i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive</a>
</div>
<div class="kql-lib-query-actions">
  <a class="kql-lib-deep-dive-btn" href="https://www.hanley.cloud/2026-02-08-KQL-Toolbox-7-From-Detection-Coverage-to-Response-Reality/" target="_blank" rel="noopener">
    <i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive
  </a>
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-mitre-attack-tactics-observed">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/mitre-attack/mitre-attack-tactics-observed.kql' | relative_url }}" download="mitre-attack-tactics-observed.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-mitre-attack-tactics-observed" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Source: KQL Toolbox #7: From Detection Coverage To Response Reality (2026-02-08) — https://www.hanley.cloud/2026-02-08-KQL-Toolbox-7-From-Detection-Coverage-to-Response-Reality/
// This query identifies events mapped against the MITRE ATT&CK Matrix that have been observed in the environment
// Platforms: Microsoft Sentinel
// Data: SecurityAlert

let totalCount = toscalar(
    SecurityAlert
    | where TimeGenerated > ago(90d)
    | where isnotempty(Tactics)
    | mv-expand tactic = split(Tactics, ", ")
    | summarize Total = count()
    );
SecurityAlert
| where TimeGenerated > ago(90d)
| where isnotempty(Tactics)
| mv-expand tactic = split(Tactics, ", ")
| summarize Count = count() by tostring(tactic)
| extend Percentage = strcat(round(Count * 100.0 / totalCount, 2), '%')
| extend TacticEmoji = case(
                           tactic == "InitialAccess",
                           "🚪",
                           tactic == "Execution",
                           "💥",
                           tactic == "Persistence",
                           "📌",
                           tactic == "PrivilegeEscalation",
                           "🚀",
                           tactic == "DefenseEvasion",
                           "🕵️",
                           tactic == "CredentialAccess",
                           "🔑",
                           tactic == "Discovery",
                           "🔍",
                           tactic == "LateralMovement",
                           "🔄",
                           tactic == "Collection",
                           "📂",
                           tactic == "Exfiltration",
                           "📤",
                           tactic == "Impact",
                           "⚡",
                           tactic == "CommandAndControl",
                           "📡",
                           "❓"  // Default emoji for unknown tactics
                       )
| project Tactic = strcat(TacticEmoji, " ", tactic), Count, Percentage
| sort by Count desc
| top 10 by Count
```

</div>
