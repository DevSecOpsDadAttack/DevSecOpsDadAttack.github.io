---
layout: page
title: Hunt Inflated File Payload Evading Size Based Av Scan
subtitle: "File downloads anomalously large for their kind — Vidar's null-byte padding trick to slip past AV scanners that skip files above a size ceiling."
permalink: /kql-library/hunting/hunt-inflated-file-payload-evading-size-based-av-scan/
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
  <code class="kql-lib-query-file">hunt-inflated-file-payload-evading-size-based-av-scan.kql</code>
</div>

<p class="kql-lib-query-longdesc">File downloads anomalously large for their kind — Vidar's null-byte padding trick to slip past AV scanners that skip files above a size ceiling.</p>

<div class="kql-lib-tags-block">
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Tactics</span>
    <a class="kql-lib-tag kql-lib-tag-tactic" href="{{ '/kql-library/tag/defense-evasion/' | relative_url }}">Defense Evasion</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Techniques</span>
    <a class="kql-lib-tag kql-lib-tag-technique" href="{{ '/kql-library/tag/t1027-001/' | relative_url }}">T1027.001</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Actors</span>
    <a class="kql-lib-tag kql-lib-tag-actor" href="{{ '/kql-library/tag/vidar-stealer/' | relative_url }}">Vidar Stealer</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Platforms</span>
    <a class="kql-lib-tag kql-lib-tag-platform" href="{{ '/kql-library/tag/windows/' | relative_url }}">Windows</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Data</span>
    <a class="kql-lib-tag kql-lib-tag-data" href="{{ '/kql-library/tag/devicefileevents/' | relative_url }}">DeviceFileEvents</a>
  </div>
  <div class="kql-lib-tag-row">
    <span class="kql-lib-tag-label">Deep Dive</span>
    <a class="kql-lib-tag kql-lib-tag-deepdive" href="{{ '/kql-library/tag/deep-dive/' | relative_url }}"><i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive</a>
</div>
<div class="kql-lib-query-actions">
  <a class="kql-lib-deep-dive-btn" href="https://devsecopsdadattack.com/2026-07-13-KQL-Detection-of-the-Week_-Nice-Costume_-Wrong-Address/" target="_blank" rel="noopener">
    <i class="fas fa-bolt" aria-hidden="true"></i>&nbsp;Deep Dive
  </a>
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-hunt-inflated-file-payload-evading-size-based-av-scan">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/hunting/hunt-inflated-file-payload-evading-size-based-av-scan.kql' | relative_url }}" download="hunt-inflated-file-payload-evading-size-based-av-scan.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-hunt-inflated-file-payload-evading-size-based-av-scan" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Hunts for file downloads that are anomalously large for their kind — Vidar's second costume
// where the payload is padded with null bytes to slip past AV scanners that skip files above a
// size ceiling. Ranks downloads whose size:entropy ratio suggests inflation.
// Source: KQL Detection of the Week: Nice Costume, Wrong Address (2026-07-13) — https://devsecopsdadattack.com/2026-07-13-KQL-Detection-of-the-Week_-Nice-Costume_-Wrong-Address/
// Tactics: Defense Evasion
// Techniques: T1027.001
// Actors: Vidar Stealer
// Platforms: Windows
// Data: DeviceFileEvents

DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified")
| where FileName endswith ".exe" or FileName endswith ".dll"
| where isnotnull(FileSize) and FileSize > 52428800
| where not (
    InitiatingProcessFileName has_any (
        "msiexec.exe", "setup.exe", "install.exe", "winget.exe",
        "MicrosoftEdgeUpdate.exe", "WindowsUpdateBox.exe",
        "wuauclt.exe", "TiWorker.exe", "TrustedInstaller.exe"
    )
)
| where not (
    FolderPath startswith @"C:\Windows\"
    or FolderPath startswith @"C:\Program Files\"
    or FolderPath startswith @"C:\Program Files (x86)\"
)
| extend HighRiskPath = (
    FolderPath has_any ("AppData", "Temp", "Downloads", "Desktop", "Public")
)
| project
    Timestamp,
    DeviceName,
    DeviceId,
    FileName,
    FolderPath,
    FileSize,
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessSHA256,
    HighRiskPath
| order by FileSize desc
```

</div>
