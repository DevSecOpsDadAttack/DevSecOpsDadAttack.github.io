---
layout: page
title: Hunt Azure Diagnostic Setting Deletions
subtitle: "Deletions of Azure diagnostic settings — the moment an attacker turns off logging (T1562.008). Step 1 of a two-step sequence."
permalink: /kql-library/hunting/hunt-azure-diagnostic-setting-deletions/
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
  <code class="kql-lib-query-file">hunt-azure-diagnostic-setting-deletions.kql</code>
</div>

<p class="kql-lib-query-longdesc">Deletions of Azure diagnostic settings — the moment an attacker turns off logging (T1562.008). Step 1 of a two-step sequence.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/defense-evasion/' | relative_url }}">Defense Evasion</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1562-008/' | relative_url }}">T1562.008</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/azure/' | relative_url }}">Azure</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/azureactivity/' | relative_url }}">AzureActivity</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-hunt-azure-diagnostic-setting-deletions">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/hunting/hunt-azure-diagnostic-setting-deletions.kql' | relative_url }}" download="hunt-azure-diagnostic-setting-deletions.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-hunt-azure-diagnostic-setting-deletions" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Detects deletions of Azure diagnostic settings — the moment an attacker turns off logging before
// touching resources (T1562.008). Step 1 of a two-step sequence: this is the event, the follow-on
// activity is the sequence detection.
// Source: KQL Detection of the Week: Detecting Cloud Logging Suppression (T1562.008) (2026-06-12) — https://devsecopsdadattack.com/2026-06-12-KQL-of-the-Week_-Detecting-Cloud-Logging-Suppression-T1562-008/
// Tactics: Defense Evasion
// Techniques: T1562.008
// Platforms: Azure
// Data: AzureActivity

AzureActivity
| where TimeGenerated > ago(1d)
| where tolower(OperationName) has_any (
    "microsoft.insights/diagnosticsettings/delete",
    "microsoft.insights/diagnosticsettings/write",
    "microsoft.operationalinsights/workspaces/delete",
    "microsoft.operationalinsights/workspaces/write"
  )
| where ActivityStatusValue =~ "Success" or ActivityStatus =~ "Succeeded"
| extend InitiatorUPN = tostring(parse_json(tostring(parse_json(InitiatedBy).user)).userPrincipalName)
| extend InitiatorApp = tostring(parse_json(tostring(parse_json(InitiatedBy).app)).displayName)
| extend ActorType = case(
    isnotempty(InitiatorUPN), "User",
    isnotempty(InitiatorApp), "ServicePrincipal",
    "Unknown"
  )
| project TimeGenerated, OperationName, ActivityStatus, CallerIpAddress, ResourceId, ResourceGroup, SubscriptionId, InitiatorUPN, InitiatorApp, ActorType
| order by TimeGenerated desc
```

</div>
