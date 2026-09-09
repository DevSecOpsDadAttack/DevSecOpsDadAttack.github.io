---
layout: page
title: Which Devices Or Software Are EOL
subtitle: "Devices running at least one end-of-support / end-of-life software title or version, from `DeviceTvmSoftwareInventory`."
permalink: /kql-library/posture/which-devices-or-software-are-eol/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/posture/' | relative_url }}">Posture</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-server" aria-hidden="true"></i>&nbsp;Posture</span>
  <code class="kql-lib-query-file">which-devices-or-software-are-eol.kql</code>
</div>

<p class="kql-lib-query-longdesc">Devices running at least one end-of-support / end-of-life software title or version, from `DeviceTvmSoftwareInventory`.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/reconnaissance/' | relative_url }}">Reconnaissance</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/endpoint/' | relative_url }}">Endpoint</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/devicetvmsoftwareinventory/' | relative_url }}">DeviceTvmSoftwareInventory</a>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/devicetvmsoftwarevulnerabilities/' | relative_url }}">DeviceTvmSoftwareVulnerabilities</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Deep Dive</span>
    <a class="kql-lib-tag kql-lib-tag-deepdive" href="{{ '/kql-library/tag/deep-dive/' | relative_url }}"><i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive</a>
</div>
<div class="kql-lib-query-actions">
  <a class="kql-lib-deep-dive-btn" href="https://www.hanley.cloud/2025-11-03-The-Ghosts-Hiding-in-Every-Network-End-of-Life-Devices-and-Software/" target="_blank" rel="noopener">
    <i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive
  </a>
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-which-devices-or-software-are-eol">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/posture/which-devices-or-software-are-eol.kql' | relative_url }}" download="which-devices-or-software-are-eol.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-which-devices-or-software-are-eol" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Devices that have at least one end-of-support (EOL/EOS) title or version
// Source: The Ghosts Hiding In Every Network: End Of Life Devices And Software (2025-11-03) — https://www.hanley.cloud/2025-11-03-The-Ghosts-Hiding-in-Every-Network-End-of-Life-Devices-and-Software/
// Tactics: Reconnaissance
// Platforms: Endpoint
// Data: DeviceTvmSoftwareInventory, DeviceTvmSoftwareVulnerabilities

DeviceTvmSoftwareInventory
| where isnotempty(DeviceName)
| where isnotempty(EndOfSupportDate) and EndOfSupportDate <= now()
| project DeviceName, SoftwareName, SoftwareVersion, SoftwareVendor, EndOfSupportDate
| order by DeviceName asc, SoftwareName asc

DeviceTvmSoftwareInventory
| where isnotempty(DeviceName)
| where isnotempty(EndOfSupportDate) and EndOfSupportDate <= now()
| summarize 
    EOLSoftwareCount = count(),
    EOLSoftwareList = make_set(SoftwareName, 100),
    OldestEOLDate = min(EndOfSupportDate)
  by DeviceName
| order by EOLSoftwareCount desc
```

</div>
