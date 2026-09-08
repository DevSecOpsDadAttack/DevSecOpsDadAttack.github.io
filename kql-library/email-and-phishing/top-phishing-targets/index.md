---
layout: page
title: Top Phishing Targets
subtitle: "Top *recipients* of phishing emails (targeted individuals) with severity by volume."
permalink: /kql-library/email-and-phishing/top-phishing-targets/
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
  <code class="kql-lib-query-file">top-phishing-targets.kql</code>
</div>

<p class="kql-lib-query-longdesc">Top *recipients* of phishing emails (targeted individuals) with severity by volume.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-top-phishing-targets">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/email-and-phishing/top-phishing-targets.kql' | relative_url }}" download="top-phishing-targets.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-top-phishing-targets" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Identifies top recipients of phishing emails and categorizes severity based on volume

EmailEvents
| where ThreatTypes has "Phish"
| summarize PhishCount = count() by RecipientEmailAddress
// Assign severity level indicators based on PhishCount
| extend SeverityIndicator = case(
                                 PhishCount >= 500,
                                 "🔥 Extreme Target",
                                 PhishCount >= 200,
                                 "🔴 Critical Target",
                                 PhishCount >= 100,
                                 "🟠 Major Target",
                                 PhishCount >= 50,
                                 "🟡 Moderate Target",
                                 "🟢 Low Target"
                             )
// Apply color coding to PhishCount
| extend CountColor = case(
                          PhishCount >= 500,
                          "🔥",
                          PhishCount >= 200,
                          "🔴",
                          PhishCount >= 100,
                          "🟠",
                          PhishCount >= 50,
                          "🟡",
                          "🟢"
                      )
// Sort by the highest volume of phishing emails received
| top 10 by PhishCount desc
// Improve column naming for readability
| project
    ["Recipient Email"] = RecipientEmailAddress, 
    ["Phishing Emails Received"] = strcat(CountColor, " ", PhishCount),
    ["Severity"] = SeverityIndicator
```

</div>
