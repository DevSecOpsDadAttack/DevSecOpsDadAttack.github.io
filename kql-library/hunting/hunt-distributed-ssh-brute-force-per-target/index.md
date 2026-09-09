---
layout: page
title: Hunt Distributed Ssh Brute Force Per Target
subtitle: "SSH brute-force hunt that pivots on the target host, not the source IP — catches distributed attacks that stay under per-source thresholds by using thousands of IPs."
permalink: /kql-library/hunting/hunt-distributed-ssh-brute-force-per-target/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{ '/kql-library/' | relative_url }}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{ '/kql-library/hunting/' | relative_url }}">Hunting</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas fa-magnifying-glass" aria-hidden="true"></i>&nbsp;Hunting</span>
  <code class="kql-lib-query-file">hunt-distributed-ssh-brute-force-per-target.kql</code>
</div>

<p class="kql-lib-query-longdesc">SSH brute-force hunt that pivots on the target host, not the source IP — catches distributed attacks that stay under per-source thresholds by using thousands of IPs.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/credential-access/' | relative_url }}">Credential Access</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1110-003/' | relative_url }}">T1110.003</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/linux/' | relative_url }}">Linux</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/syslog/' | relative_url }}">Syslog</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Deep Dive</span>
    <a class="kql-lib-tag kql-lib-tag-deepdive" href="{{ '/kql-library/tag/deep-dive/' | relative_url }}"><i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive</a>
</div>
<div class="kql-lib-query-actions">
  <a class="kql-lib-deep-dive-btn" href="https://devsecopsdadattack.com/2026-06-19-KQL-of-the-Week_-The-Attack-That-Stayed-Under-the-Threshold/" target="_blank" rel="noopener">
    <i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive
  </a>
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-hunt-distributed-ssh-brute-force-per-target">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/hunting/hunt-distributed-ssh-brute-force-per-target.kql' | relative_url }}" download="hunt-distributed-ssh-brute-force-per-target.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-hunt-distributed-ssh-brute-force-per-target" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// SSH brute-force hunt that pivots on the *target host* instead of the source IP — catches
// distributed attacks that stay under per-source thresholds by using thousands of IPs, one attempt
// each. Counts distinct source IPs failing against the same destination, which is the signature of
// the botnet-scale spray.
// Source: KQL Detection of the Week: The Attack That Stayed Under the Threshold (2026-06-19) — https://devsecopsdadattack.com/2026-06-19-KQL-of-the-Week_-The-Attack-That-Stayed-Under-the-Threshold/
// Tactics: Credential Access
// Techniques: T1110.003
// Platforms: Linux
// Data: Syslog

let WindowMinutes = 10;
let DistinctIPThreshold = 10;
let FailedSSHSyslog = Syslog
| where (Facility == "auth" or SyslogMessage has "sshd")
| where SyslogMessage has_any ("Failed password", "Invalid user", "authentication failure")
| extend SourceIP = extract(@"from ([\d\.a-fA-F:]+)", 1, SyslogMessage)
| extend TargetUser = extract(@"(?:for|user) (\S+) from", 1, SyslogMessage)
| where isnotempty(SourceIP)
| project TimeGenerated, Computer, SourceIP, TargetUser, SyslogMessage;
FailedSSHSyslog
| summarize
    DistinctSourceIPs = dcount(SourceIP),
    TotalFailures = count(),
    SourceIPList = make_set(SourceIP, 20),
    SampleUsernames = make_set(TargetUser, 10)
    by Computer, bin(TimeGenerated, totimespan(strcat(tostring(WindowMinutes), "m")))
| where DistinctSourceIPs >= DistinctIPThreshold
| project TimeGenerated, Computer, DistinctSourceIPs, TotalFailures, SourceIPList, SampleUsernames
| order by DistinctSourceIPs desc, TimeGenerated desc
```

</div>
