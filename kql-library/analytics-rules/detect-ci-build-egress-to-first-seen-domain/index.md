---
layout: page
title: Detect Ci Build Egress To First Seen Domain
subtitle: "CI/CD build process reaching out to a domain never seen from your build fleet before — 'the build that called a stranger.'"
permalink: /kql-library/analytics-rules/detect-ci-build-egress-to-first-seen-domain/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/analytics-rules/' | relative_url }}">Analytics Rules</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-shield-halved" aria-hidden="true"></i>&nbsp;Analytics Rules</span>
  <code class="kql-lib-query-file">detect-ci-build-egress-to-first-seen-domain.kql</code>
</div>

<p class="kql-lib-query-longdesc">CI/CD build process reaching out to a domain never seen from your build fleet before — 'the build that called a stranger.'</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/command-and-control/' | relative_url }}">Command and Control</a>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/exfiltration/' | relative_url }}">Exfiltration</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1071-001/' | relative_url }}">T1071.001</a>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1567/' | relative_url }}">T1567</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/linux/' | relative_url }}">Linux</a>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/azure/' | relative_url }}">Azure</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/devicenetworkevents/' | relative_url }}">DeviceNetworkEvents</a>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/azurediagnostics/' | relative_url }}">AzureDiagnostics</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-detect-ci-build-egress-to-first-seen-domain">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/analytics-rules/detect-ci-build-egress-to-first-seen-domain.kql' | relative_url }}" download="detect-ci-build-egress-to-first-seen-domain.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-detect-ci-build-egress-to-first-seen-domain" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Detects a CI/CD build process reaching out to a domain never seen from your build fleet before —
// 'the build that called a stranger.' Baselines the fleet's egress destinations over 30 days and
// alerts on first-seen contacts during builds.
// Source: KQL Detection of the Week: The Dog That Didn't Bark (2026-07-20) — https://devsecopsdadattack.com/2026-07-20-KQL-Detection-of-the-Week_-The-Dog-That-Didn_t-Bark/
// Tactics: Command and Control, Exfiltration
// Techniques: T1071.001, T1567
// Platforms: Linux, Azure
// Data: DeviceNetworkEvents, AzureDiagnostics

let KnownRegistries = dynamic([
    "registry.npmjs.org",
    "registry.yarnpkg.com"
]);
let BuildEvents = DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where InitiatingProcessCommandLine has_any ("npm install", "npm ci", "npm run")
| project DeviceName, BuildTime = TimeGenerated, BuildCommandLine = InitiatingProcessCommandLine;
DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName in~ ("npm", "node", "node.exe", "npm.cmd")
| where not(ipv4_is_private(RemoteIP))
    and not(ipv4_is_in_range(RemoteIP, "127.0.0.0/8"))
    and not(ipv4_is_in_range(RemoteIP, "100.64.0.0/10"))
| where (isnotempty(RemoteUrl) and not(RemoteUrl has_any (KnownRegistries)))
    or isempty(RemoteUrl)
| join kind=inner BuildEvents on DeviceName
| where abs(datetime_diff('second', TimeGenerated, BuildTime)) < 120
| summarize
    NearbyBuilds = dcount(BuildTime),
    BuildCommandLine = take_any(BuildCommandLine)
    by TimeGenerated, DeviceName, InitiatingProcessFileName,
       InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by TimeGenerated desc
```

</div>
