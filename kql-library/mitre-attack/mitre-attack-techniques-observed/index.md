---
layout: page
title: Mitre Attack Techniques Observed
subtitle: "Events mapped against MITRE ATT&CK Techniques that have been observed in the environment, with percentage of total."
permalink: /kql-library/mitre-attack/mitre-attack-techniques-observed/
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
  <code class="kql-lib-query-file">mitre-attack-techniques-observed.kql</code>
</div>

<p class="kql-lib-query-longdesc">Events mapped against MITRE ATT&amp;CK Techniques that have been observed in the environment, with percentage of total.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-mitre-attack-techniques-observed">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/mitre-attack/mitre-attack-techniques-observed.kql' | relative_url }}" download="mitre-attack-techniques-observed.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-mitre-attack-techniques-observed" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// This query identifies events mapped against the MITRE ATT&CK Matrix that have been observed in the environment

let TotalCount = toscalar(
    SecurityAlert
    | where TimeGenerated > ago(90d)
    | where isnotempty(Techniques)
    | mv-expand technique = split(Techniques, ", ")
    | summarize TotalCount = count()
    );
SecurityAlert
| where TimeGenerated > ago(90d)
| where isnotempty(Techniques)
| mv-expand technique = split(Techniques, ", ")
| summarize Count = count() by tostring(technique)
| extend Percentage = strcat(round(Count * 100.0 / TotalCount, 2), '%')
| sort by Count desc
| top 10 by Count
| project ["MITRE Technique"] = technique, Count, Percentage
```

</div>
