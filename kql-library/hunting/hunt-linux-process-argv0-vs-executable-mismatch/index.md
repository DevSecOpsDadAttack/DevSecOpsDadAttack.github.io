---
layout: page
title: Hunt Linux Process Argv0 Vs Executable Mismatch
subtitle: "Linux processes where argv[0] doesn't match the actual binary that was executed — a process wearing another process's name tag."
permalink: /kql-library/hunting/hunt-linux-process-argv0-vs-executable-mismatch/
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
  <code class="kql-lib-query-file">hunt-linux-process-argv0-vs-executable-mismatch.kql</code>
</div>

<p class="kql-lib-query-longdesc">Linux processes where argv[0] doesn't match the actual binary that was executed — a process wearing another process's name tag.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/defense-evasion/' | relative_url }}">Defense Evasion</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1036-005/' | relative_url }}">T1036.005</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/linux/' | relative_url }}">Linux</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/deviceprocessevents/' | relative_url }}">DeviceProcessEvents</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Deep Dive</span>
    <a class="kql-lib-tag kql-lib-tag-deepdive" href="{{ '/kql-library/tag/deep-dive/' | relative_url }}"><i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive</a>
</div>
<div class="kql-lib-query-actions">
  <a class="kql-lib-deep-dive-btn" href="https://devsecopsdadattack.com/2026-06-29-KQL-Detection-of-the-Week_-A-Name-Is-a-Claim_-Not-a-Fact/" target="_blank" rel="noopener">
    <i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive
  </a>
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-hunt-linux-process-argv0-vs-executable-mismatch">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/hunting/hunt-linux-process-argv0-vs-executable-mismatch.kql' | relative_url }}" download="hunt-linux-process-argv0-vs-executable-mismatch.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-hunt-linux-process-argv0-vs-executable-mismatch" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Detects Linux processes where argv[0] (the string the process picked as its name) doesn't match
// the actual binary that was executed. Catches processes wearing another process's name tag — a
// classic Linux masquerading move. Compares InitiatingProcessCommandLine's argv[0] against the
// resolved FileName.
// Source: KQL Detection of the Week: A Name Is a Claim, Not a Fact (2026-06-29) — https://devsecopsdadattack.com/2026-06-29-KQL-Detection-of-the-Week_-A-Name-Is-a-Claim_-Not-a-Fact/
// Tactics: Defense Evasion
// Techniques: T1036.005
// Platforms: Linux
// Data: DeviceProcessEvents

let LegitPaths = datatable(ProcName: string, ExpectedPathPrefix: string)[
    "sshd", "/usr/sbin/",
    "cron", "/usr/sbin/",
    "systemd", "/lib/systemd/",
    "bash", "/bin/",
    "sh", "/bin/",
    "python", "/usr/bin/",
    "python3", "/usr/bin/",
    "perl", "/usr/bin/",
    "nginx", "/usr/sbin/",
    "apache2", "/usr/sbin/"
];
Syslog
| where Facility in ("kern", "daemon", "user", "authpriv") or ProcessName in (LegitPaths | project ProcName)
| where SyslogMessage has "exe="
| extend ExePath = extract(@'exe="([^"]+)"', 1, SyslogMessage)
| where isnotempty(ExePath)
| extend ExeBasename = tostring(split(ExePath, "/")[-1])
| join kind=inner LegitPaths on $left.ExeBasename == $right.ProcName
| where not(ExePath startswith ExpectedPathPrefix)
| where not(ExePath startswith "/usr/local/")
| where not(ExePath startswith "/snap/")
| where not(ExePath startswith "/opt/")
| project TimeGenerated, Computer, ProcessName, ExeBasename, ExePath, ExpectedPathPrefix, SyslogMessage
| order by TimeGenerated desc
```

</div>
