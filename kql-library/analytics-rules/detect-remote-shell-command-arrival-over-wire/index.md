---
layout: page
title: Detect Remote Shell Command Arrival Over Wire
subtitle: "Shell command that arrived over the network — outbound-then-inbound-executed script pattern uncommon in legitimate remote code execution."
permalink: /kql-library/analytics-rules/detect-remote-shell-command-arrival-over-wire/
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
  <code class="kql-lib-query-file">detect-remote-shell-command-arrival-over-wire.kql</code>
</div>

<p class="kql-lib-query-longdesc">Shell command that arrived over the network — outbound-then-inbound-executed script pattern uncommon in legitimate remote code execution.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/execution/' | relative_url }}">Execution</a>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/lateral-movement/' | relative_url }}">Lateral Movement</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1021-002/' | relative_url }}">T1021.002</a>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1059/' | relative_url }}">T1059</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/windows/' | relative_url }}">Windows</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/deviceprocessevents/' | relative_url }}">DeviceProcessEvents</a>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/devicelogonevents/' | relative_url }}">DeviceLogonEvents</a>
  </div>
</div>
<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-detect-remote-shell-command-arrival-over-wire">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/analytics-rules/detect-remote-shell-command-arrival-over-wire.kql' | relative_url }}" download="detect-remote-shell-command-arrival-over-wire.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-detect-remote-shell-command-arrival-over-wire" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Detects a shell command that arrived over the network — a fresh detection built around the
// observation that legitimate remote code execution rarely originates from an
// outbound-then-inbound-executed script. Third-listener honorable mention pattern.
// Source: KQL Detection of the Week: The Login Was Never the Point (2026-07-06) — https://devsecopsdadattack.com/2026-07-06-KQL-Detection-of-the-Week_-The-Login-Was-Never-the-Point/
// Tactics: Execution, Lateral Movement
// Techniques: T1021.002, T1059
// Platforms: Windows
// Data: DeviceProcessEvents, DeviceLogonEvents

let psexec_shells = DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("psexec.exe", "psexec64.exe")
| where FileName in~ ("cmd.exe", "powershell.exe")
| project ShellTime = Timestamp, DeviceName, AccountName, AccountDomain,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessParentFileName, ChildProcess = FileName, ProcessCommandLine;
let smb_logons = DeviceLogonEvents
| where Timestamp > ago(7d)
| where LogonType == 3
| where isnotempty(RemoteIP)
| where RemoteIP !in ("127.0.0.1", "::1")
| project LogonTime = Timestamp, DeviceName, AccountName, AccountDomain, RemoteIP;
smb_logons
| join kind=inner psexec_shells on DeviceName, AccountName, AccountDomain
| where ShellTime >= LogonTime and datetime_diff('second', ShellTime, LogonTime) <= 120
| project ShellTime, LogonTime, DeviceName, AccountName, AccountDomain,
    RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessParentFileName, ChildProcess, ProcessCommandLine
| order by ShellTime desc
```

</div>
