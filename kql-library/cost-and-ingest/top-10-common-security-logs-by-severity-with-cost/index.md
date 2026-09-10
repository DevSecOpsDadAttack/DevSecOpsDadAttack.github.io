---
layout: page
title: Top 10 Common Security Logs By Severity With Cost
subtitle: "Top `CommonSecurityLog` groupings by `DeviceVendor`, `DeviceProduct`, and `LogSeverity` (30d), with numeric `CostUSD`."
permalink: /kql-library/cost-and-ingest/top-10-common-security-logs-by-severity-with-cost/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/cost-and-ingest/' | relative_url }}">Cost &amp; Ingest</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-coins" aria-hidden="true"></i>&nbsp;Cost &amp; Ingest</span>
  <span class="attack-badge attack-badge-sub">Cost By Table</span>
  <code class="kql-lib-query-file">top-10-common-security-logs-by-severity-with-cost.kql</code>
</div>

<p class="kql-lib-query-longdesc">Top `CommonSecurityLog` groupings by `DeviceVendor`, `DeviceProduct`, and `LogSeverity` (30d), with numeric `CostUSD`.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/network/' | relative_url }}">Network</a>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/microsoft-sentinel/' | relative_url }}">Microsoft Sentinel</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/commonsecuritylog/' | relative_url }}">CommonSecurityLog</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Deep Dive</span>
    <a class="kql-lib-tag kql-lib-tag-deepdive" href="{{ '/kql-library/tag/deep-dive/' | relative_url }}"><i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive</a>
</div>
<div class="kql-lib-query-actions">
  <a class="kql-lib-deep-dive-btn" href="https://www.hanley.cloud/2026-01-05-KQL-Toolbox-2-Find-Your-Noisiest-Log-Sources-%28with-Cost-%29/" target="_blank" rel="noopener">
    <i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive
  </a>
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-top-10-common-security-logs-by-severity-with-cost">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/cost-and-ingest/cost-by-table/top-10-common-security-logs-by-severity-with-cost.kql' | relative_url }}" download="top-10-common-security-logs-by-severity-with-cost.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-top-10-common-security-logs-by-severity-with-cost" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Top 10 most expensive CommonSecurityLog groupings by DeviceVendor, DeviceProduct, and LogSeverity
// over the last 30 days, with numeric CostUSD. Best for spotting which vendor/product/severity
// combos are driving your CEF/Syslog appliance cost.
// For a Reason-focused enhanced variant with cost-tier emojis, see the -enhanced-by-reason file
// in the same folder.
// Source: KQL Toolbox #2: Find Your Noisiest Log Sources (with Cost) (2026-01-05) — https://www.hanley.cloud/2026-01-05-KQL-Toolbox-2-Find-Your-Noisiest-Log-Sources-%28with-Cost-%29/
// Platforms: Network, Microsoft Sentinel
// Data: CommonSecurityLog

let PricePerGB = 5.16;   // <-- Replace with your region's actual Sentinel price per GB
CommonSecurityLog
| where TimeGenerated > ago(30d)
| where _IsBillable == true
| summarize TotalGiB = round(sum(_BilledSize) / 1024.0 / 1024.0 / 1024.0, 2)
          by DeviceVendor, DeviceProduct, LogSeverity
| extend CostUSD = round(TotalGiB * PricePerGB, 2)
| top 10 by CostUSD desc
| order by CostUSD desc
```

</div>
