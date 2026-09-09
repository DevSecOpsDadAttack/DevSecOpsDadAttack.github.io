---
layout: page
title: Detect Peoplesoft Process Spawning Unexpected Shell
subtitle: "Oracle PeopleSoft server processes (psadmin, psappsrv, java) spawning cmd, bash, whoami, curl, or net — post-exploitation shape of a PeopleSoft RCE."
permalink: /kql-library/analytics-rules/detect-peoplesoft-process-spawning-unexpected-shell/
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
  <code class="kql-lib-query-file">detect-peoplesoft-process-spawning-unexpected-shell.kql</code>
</div>

<p class="kql-lib-query-longdesc">Oracle PeopleSoft server processes (psadmin, psappsrv, java) spawning cmd, bash, whoami, curl, or net — post-exploitation shape of a PeopleSoft RCE.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/execution/' | relative_url }}">Execution</a>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/initial-access/' | relative_url }}">Initial Access</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1190/' | relative_url }}">T1190</a>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1059/' | relative_url }}">T1059</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/linux/' | relative_url }}">Linux</a>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/windows/' | relative_url }}">Windows</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/deviceprocessevents/' | relative_url }}">DeviceProcessEvents</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-detect-peoplesoft-process-spawning-unexpected-shell">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/analytics-rules/detect-peoplesoft-process-spawning-unexpected-shell.kql' | relative_url }}" download="detect-peoplesoft-process-spawning-unexpected-shell.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-detect-peoplesoft-process-spawning-unexpected-shell" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Detects Oracle PeopleSoft server processes (psadmin, psappsrv, pswatchsrv, java) spawning an
// unexpected shell or reconnaissance binary — the post-exploitation shape of a webapp RCE.
// Honorable-mention detection built around the fact that a legitimate PeopleSoft process has no
// business launching cmd, bash, whoami, curl, or net.
// Source: KQL Detection of the Week: Detecting Cloud Logging Suppression (T1562.008) (2026-06-12) — https://devsecopsdadattack.com/2026-06-12-KQL-of-the-Week_-Detecting-Cloud-Logging-Suppression-T1562-008/
// Tactics: Execution, Initial Access
// Techniques: T1190, T1059
// Platforms: Linux, Windows
// Data: DeviceProcessEvents

DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("psadmin.exe", "psadmin", "java.exe", "java", "psappsrv.exe", "psappsrv", "pswatchsrv.exe", "pswatchsrv")
| where FileName in~ (
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "sh", "bash", "dash", "zsh",
    "python.exe", "python", "python3",
    "perl.exe", "perl",
    "wget", "curl", "curl.exe",
    "whoami.exe", "whoami",
    "id",
    "net.exe", "net1.exe"
)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath
| order by Timestamp desc
```

</div>
