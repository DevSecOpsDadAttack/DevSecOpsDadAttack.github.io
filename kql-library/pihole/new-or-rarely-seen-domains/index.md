---
layout: page
title: New Or Rarely Seen Domains
subtitle: "Domains seen in the last 24h that haven't been seen recently — a classic new-domain-observed hunt."
permalink: /kql-library/pihole/new-or-rarely-seen-domains/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/pihole/' | relative_url }}">Pi-hole</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-network-wired" aria-hidden="true"></i>&nbsp;Pi-hole</span>
  <code class="kql-lib-query-file">new-or-rarely-seen-domains.kql</code>
</div>

<p class="kql-lib-query-longdesc">Domains seen in the last 24h that haven't been seen recently — a classic new-domain-observed hunt.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-new-or-rarely-seen-domains">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/pihole/new-or-rarely-seen-domains.kql' | relative_url }}" download="new-or-rarely-seen-domains.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-new-or-rarely-seen-domains" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
//New or Rarely Seen Domains
let cutoff = ago(24h);
let recent = pihole_CL
| where TimeGenerated > cutoff
| summarize count() by DnsQuery_s;
let historic = pihole_CL
| where TimeGenerated <= cutoff
| summarize count() by DnsQuery_s;
recent
| join kind=leftanti historic on DnsQuery_s
| top 20 by count_

// Alternate query:
// Identify domains that have been queried for the first time or are rarely seen
PiHole
| summarize Count = count(), FirstSeen = min(TimeGenerated) by Domain  // Aggregate counts and first seen time by domain
| where Count < 5  // Filter for domains queried less than 5 times
| order by FirstSeen desc  // Order by the first seen time in descending order
```

</div>
