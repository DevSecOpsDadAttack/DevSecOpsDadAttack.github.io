---
layout: page
title: Hunt C2 Beacon By Connection Window Rhythm
subtitle: "Low-and-slow C2 beacon hunt that counts distinct hourly time windows a process was connected in — not raw connection volume."
permalink: /kql-library/hunting/hunt-c2-beacon-by-connection-window-rhythm/
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
  <code class="kql-lib-query-file">hunt-c2-beacon-by-connection-window-rhythm.kql</code>
</div>

<p class="kql-lib-query-longdesc">Low-and-slow C2 beacon hunt that counts distinct hourly time windows a process was connected in — not raw connection volume.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-hunt-c2-beacon-by-connection-window-rhythm">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/hunting/hunt-c2-beacon-by-connection-window-rhythm.kql' | relative_url }}" download="hunt-c2-beacon-by-connection-window-rhythm.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-hunt-c2-beacon-by-connection-window-rhythm" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Low-and-slow C2 beacon hunt that counts distinct hourly time windows a process was connected in
// (dcount(bin(Timestamp, 1h))) rather than raw connection volume. Catches implants that beacon
// spread-over-time and hide under any volume threshold. Filters to user-writable paths
// (Downloads/Temp/AppData) with an allowlist for legit beacons (Slack, VS Code, Teams, etc.).
// Source: KQL Detection of the Week: Argamal Beaconing (2026-06-05) — https://devsecopsdadattack.com/2026-06-05-Kql-of-the-Week_-Argamal-Beaconing/

let lookback = 24h;
let beaconCandidates = DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where (RemoteIPType == "Public") or (isempty(RemoteIPType) and not(ipv4_is_private(RemoteIP)))
| where isnotempty(InitiatingProcessFolderPath)
| where InitiatingProcessFolderPath has_any ("\\Downloads\\", "\\Temp\\", "\\AppData\\Local\\Temp\\", "\\AppData\\Roaming\\")
| where not (InitiatingProcessFileName in~ (
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
    "MicrosoftEdge.exe", "OneDrive.exe", "Teams.exe",
    "Slack.exe", "Code.exe", "Discord.exe", "Spotify.exe",
    "Update.exe", "squirrel.exe"
))
| summarize
    ConnectionWindows = dcount(bin(Timestamp, 1h)),
    TotalConnections = count(),
    RemoteIPs = make_set(RemoteIP, 10),
    RemotePorts = make_set(RemotePort, 10)
    by DeviceId, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath
| where ConnectionWindows >= 4 and TotalConnections >= 8;
let procContext = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FolderPath has_any ("\\Downloads\\", "\\Temp\\", "\\AppData\\Local\\Temp\\", "\\AppData\\Roaming\\")
| summarize ProcessCommandLine = arg_max(Timestamp, ProcessCommandLine) by DeviceId, FileName, FolderPath
| project DeviceId, FileName, FolderPath, ProcessCommandLine;
beaconCandidates
| join kind=leftouter procContext on DeviceId
| where FileName =~ InitiatingProcessFileName
| project
    DeviceId, DeviceName, AccountName,
    InitiatingProcessFileName, InitiatingProcessFolderPath, ProcessCommandLine,
    ConnectionWindows, TotalConnections, RemoteIPs, RemotePorts
| order by ConnectionWindows desc
```

</div>
