---
layout: page
title: Detect Vpn Session Without Prior Authentication
subtitle: "PAN-OS GlobalProtect VPN sessions established without a matching auth event in the preceding 5 minutes — the shape of CVE-2026-0257. Uses windowed leftouter, not range-predicate leftanti."
permalink: /kql-library/analytics-rules/detect-vpn-session-without-prior-authentication/
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
  <code class="kql-lib-query-file">detect-vpn-session-without-prior-authentication.kql</code>
</div>

<p class="kql-lib-query-longdesc">PAN-OS GlobalProtect VPN sessions established without a matching auth event in the preceding 5 minutes — the shape of CVE-2026-0257. Uses windowed leftouter, not range-predicate leftanti.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/defense-evasion/' | relative_url }}">Defense Evasion</a>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/initial-access/' | relative_url }}">Initial Access</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1556/' | relative_url }}">T1556</a>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1078/' | relative_url }}">T1078</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/network/' | relative_url }}">Network</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/commonsecuritylog/' | relative_url }}">CommonSecurityLog</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-detect-vpn-session-without-prior-authentication">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/analytics-rules/detect-vpn-session-without-prior-authentication.kql' | relative_url }}" download="detect-vpn-session-without-prior-authentication.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-detect-vpn-session-without-prior-authentication" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Detects PAN-OS GlobalProtect VPN sessions established without a matching authentication event in
// the preceding 5 minutes — the shape of CVE-2026-0257 auth-bypass exploitation. Uses leftouter
// join + windowed countif instead of leftanti with range predicates (the latter silently
// suppresses alerts when any same-IP auth exists anywhere in the lookback).
// Source: KQL Detection of the Week: Argamal Beaconing (2026-06-05) — https://devsecopsdadattack.com/2026-06-05-Kql-of-the-Week_-Argamal-Beaconing/
// Tactics: Defense Evasion, Initial Access
// Techniques: T1556, T1078
// Platforms: Network
// Data: CommonSecurityLog

let lookback = 1d;
let window = 5m;
let AuthEvents = CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where DeviceVendor =~ "Palo Alto Networks"
| where DeviceProduct has_any ("GlobalProtect", "PAN-OS")
| where Activity has_any ("login", "authenticate", "auth-success", "prelogin")
    or Message has_any ("login", "authenticate", "prelogin")
| project AuthTime = TimeGenerated, SourceIP;
CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where DeviceVendor =~ "Palo Alto Networks"
| where DeviceProduct has_any ("GlobalProtect", "PAN-OS")
| where Activity has_any ("connected", "tunnel-established", "gateway-connected")
    or Message has_any ("connected", "tunnel established")
| where not(ipv4_is_private(SourceIP))
| project SessionTime = TimeGenerated, SourceIP, DeviceProduct, Activity, DeviceAction, Message, LogSeverity, DestinationIP
| join kind=leftouter (AuthEvents) on SourceIP
| extend AuthInWindow = AuthTime between ((SessionTime - window) .. SessionTime)
| summarize PriorAuthCount = countif(AuthInWindow == true)
    by SessionTime, SourceIP, DeviceProduct, Activity, DeviceAction, Message, LogSeverity, DestinationIP
| where PriorAuthCount == 0
| sort by SessionTime desc
```

</div>
