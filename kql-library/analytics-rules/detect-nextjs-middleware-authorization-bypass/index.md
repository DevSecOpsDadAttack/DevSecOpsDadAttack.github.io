---
layout: page
title: Detect Nextjs Middleware Authorization Bypass
subtitle: "Next.js middleware authorization-bypass pattern — successful requests to authenticated routes without going through the expected auth path."
permalink: /kql-library/analytics-rules/detect-nextjs-middleware-authorization-bypass/
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
  <code class="kql-lib-query-file">detect-nextjs-middleware-authorization-bypass.kql</code>
</div>

<p class="kql-lib-query-longdesc">Next.js middleware authorization-bypass pattern — successful requests to authenticated routes without going through the expected auth path.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/initial-access/' | relative_url }}">Initial Access</a>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/defense-evasion/' | relative_url }}">Defense Evasion</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1190/' | relative_url }}">T1190</a>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1550/' | relative_url }}">T1550</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/web/' | relative_url }}">Web</a>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/linux/' | relative_url }}">Linux</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/im-websession/' | relative_url }}">_Im_WebSession</a>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/commonsecuritylog/' | relative_url }}">CommonSecurityLog</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-detect-nextjs-middleware-authorization-bypass">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/analytics-rules/detect-nextjs-middleware-authorization-bypass.kql' | relative_url }}" download="detect-nextjs-middleware-authorization-bypass.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-detect-nextjs-middleware-authorization-bypass" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Detects the Next.js middleware authorization-bypass pattern by counting who successfully reached
// authenticated routes without going through the expected auth path. Catches the exploitation of
// the specific middleware weakness by shape rather than by known payload.
// Source: KQL Detection of the Week: A Name Is a Claim, Not a Fact (2026-06-29) — https://devsecopsdadattack.com/2026-06-29-KQL-Detection-of-the-Week_-A-Name-Is-a-Claim_-Not-a-Fact/
// Tactics: Initial Access, Defense Evasion
// Techniques: T1190, T1550
// Platforms: Web, Linux
// Data: _Im_WebSession, CommonSecurityLog

CommonSecurityLog
| where TimeGenerated > ago(24h)
| where RequestURL has_any ("/_next/", "/api/", "/middleware")
| where RequestMethod in ("GET", "POST", "HEAD")
| summarize
    TotalRequests = count(),
    Codes200 = countif(ResponseCode == 200),
    Codes401 = countif(ResponseCode == 401),
    Codes403 = countif(ResponseCode == 403),
    UserAgents = make_set(UserAgent),
    Paths = make_set(RequestURL)
    by SourceIP, DeviceVendor, DeviceProduct, DestinationPort, bin(TimeGenerated, 5m)
| where TotalRequests > 10 and Codes401 > 0 and Codes200 > 0
| extend BypassRatio = todouble(Codes200) / todouble(TotalRequests)
| where BypassRatio > 0.3
| order by TotalRequests desc
```

</div>
