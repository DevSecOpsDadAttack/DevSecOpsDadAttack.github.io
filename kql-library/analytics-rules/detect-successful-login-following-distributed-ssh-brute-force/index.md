---
layout: page
title: Detect Successful Login Following Distributed Ssh Brute Force
subtitle: "Successful SSH login against a host that just weathered a distributed brute-force campaign. Pair with the Act-I hunt to know if the lightning hit anything."
permalink: /kql-library/analytics-rules/detect-successful-login-following-distributed-ssh-brute-force/
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
  <code class="kql-lib-query-file">detect-successful-login-following-distributed-ssh-brute-force.kql</code>
</div>

<p class="kql-lib-query-longdesc">Successful SSH login against a host that just weathered a distributed brute-force campaign. Pair with the Act-I hunt to know if the lightning hit anything.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-detect-successful-login-following-distributed-ssh-brute-force">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/analytics-rules/detect-successful-login-following-distributed-ssh-brute-force.kql' | relative_url }}" download="detect-successful-login-following-distributed-ssh-brute-force.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-detect-successful-login-following-distributed-ssh-brute-force" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Correlates a successful SSH login against a host that just weathered a distributed brute-force
// campaign (Act I's shape). The Act-I hunt tells you the storm is happening; this rule tells you
// if the lightning hit anything.
// Source: KQL Detection of the Week: The Attack That Stayed Under the Threshold (2026-06-19) — https://devsecopsdadattack.com/2026-06-19-KQL-of-the-Week_-The-Attack-That-Stayed-Under-the-Threshold/

let lookback = 1h;
let failThreshold = 10;
let failedSSH =
    Syslog
    | where TimeGenerated > ago(lookback)
    | where Facility in ("auth", "authpriv") and SyslogMessage has "Failed password"
    | extend SourceIP = extract(@"from ([\d\.]+)", 1, SyslogMessage)
    | where isnotempty(SourceIP)
    | summarize
        FailCount = count(),
        FirstFail = min(TimeGenerated),
        LastFail = max(TimeGenerated)
        by SourceIP, Computer;
let successSSH =
    Syslog
    | where TimeGenerated > ago(lookback)
    | where Facility in ("auth", "authpriv") and SyslogMessage has "Accepted password"
    | extend SourceIP = extract(@"from ([\d\.]+)", 1, SyslogMessage)
    | extend User = extract(@"for (\S+) from", 1, SyslogMessage)
    | extend SSHPort = extract(@"port (\d+)", 1, SyslogMessage)
    | where isnotempty(SourceIP);
successSSH
| join kind=inner failedSSH on SourceIP, Computer
| where FailCount >= failThreshold
| where TimeGenerated > LastFail
| project
    TimeGenerated,
    Computer,
    SourceIP,
    User,
    SSHPort,
    FailCount,
    FirstFail,
    LastFail,
    AlertDetail = strcat("SSH success after ", tostring(FailCount), " failures from ", SourceIP)
```

</div>
