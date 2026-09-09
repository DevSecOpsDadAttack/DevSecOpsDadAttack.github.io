---
layout: page
title: Whos Clicking On Junk Mail
subtitle: "Users who clicked links in messages that landed in the Junk folder — a strong 'who needs training' signal."
permalink: /kql-library/email-and-phishing/whos-clicking-on-junk-mail/
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
  <code class="kql-lib-query-file">whos-clicking-on-junk-mail.kql</code>
</div>

<p class="kql-lib-query-longdesc">Users who clicked links in messages that landed in the Junk folder — a strong "who needs training" signal.</p>

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
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/urlclickevents/' | relative_url }}">UrlClickEvents</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-whos-clicking-on-junk-mail">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/email-and-phishing/whos-clicking-on-junk-mail.kql' | relative_url }}" download="whos-clicking-on-junk-mail.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-whos-clicking-on-junk-mail" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Tactics: Initial Access
// Techniques: T1566.002
// Platforms: Microsoft 365
// Data: UrlClickEvents
let JunkedEmails = EmailEvents
| where DeliveryLocation == "Junk folder"
| distinct NetworkMessageId;
UrlClickEvents
| where NetworkMessageId in(JunkedEmails)
```

</div>
