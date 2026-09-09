---
layout: page
title: Top Phishing Domains
subtitle: "Top phishing *sender domains* with severity categorized by volume."
permalink: /kql-library/email-and-phishing/top-phishing-domains/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/email-and-phishing/' | relative_url }}">Email &amp; Phishing</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-envelope-open-text" aria-hidden="true"></i>&nbsp;Email &amp; Phishing</span>
  <code class="kql-lib-query-file">top-phishing-domains.kql</code>
</div>

<p class="kql-lib-query-longdesc">Top phishing *sender domains* with severity categorized by volume.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/initial-access/' | relative_url }}">Initial Access</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1566-002/' | relative_url }}">T1566.002</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/microsoft-365/' | relative_url }}">Microsoft 365</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/emailevents/' | relative_url }}">EmailEvents</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-top-phishing-domains">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/email-and-phishing/top-phishing-domains.kql' | relative_url }}" download="top-phishing-domains.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-top-phishing-domains" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Identifies top phishing sender domains and categorizes severity based on volume
// Tactics: Initial Access
// Techniques: T1566.002
// Platforms: Microsoft 365
// Data: EmailEvents

EmailEvents
| where ThreatTypes has "Phish"
| summarize PhishCount = count() by SenderFromDomain
// Assign severity level indicators based on PhishCount
| extend SeverityIndicator = case(
                                 PhishCount >= 1000,
                                 "🔥 Extreme Threat Domain",
                                 PhishCount >= 500,
                                 "🔴 Critical Threat Domain",
                                 PhishCount >= 200,
                                 "🟠 Major Threat Domain",
                                 PhishCount >= 100,
                                 "🟡 Moderate Threat Domain",
                                 "🟢 Low Threat Domain"
                             )
// Apply color coding to PhishCount
| extend CountColor = case(
                          PhishCount >= 1000,
                          "🔥",
                          PhishCount >= 500,
                          "🔴",
                          PhishCount >= 200,
                          "🟠",
                          PhishCount >= 100,
                          "🟡",
                          "🟢"
                      )
// Sort by the highest volume of phishing emails sent from a domain
| top 10 by PhishCount desc
// Improve column naming for readability
| project
    ["Sender Domain"] = SenderFromDomain, 
    ["Phishing Emails Sent"] = strcat(CountColor, " ", PhishCount),
    ["Severity"] = SeverityIndicator
```

</div>
