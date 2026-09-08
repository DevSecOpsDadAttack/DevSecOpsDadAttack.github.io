---
layout: page
title: Detect Excel Xll Addin Spawning Shell Or Network
subtitle: "Excel loading an XLL add-in that then spawns a shell or beacons out — the spreadsheet-as-shell malware delivery vector."
permalink: /kql-library/analytics-rules/detect-excel-xll-addin-spawning-shell-or-network/
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
  <code class="kql-lib-query-file">detect-excel-xll-addin-spawning-shell-or-network.kql</code>
</div>

<p class="kql-lib-query-longdesc">Excel loading an XLL add-in that then spawns a shell or beacons out — the spreadsheet-as-shell malware delivery vector.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-detect-excel-xll-addin-spawning-shell-or-network">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/analytics-rules/detect-excel-xll-addin-spawning-shell-or-network.kql' | relative_url }}" download="detect-excel-xll-addin-spawning-shell-or-network.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-detect-excel-xll-addin-spawning-shell-or-network" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Detects Excel loading an XLL add-in that then spawns a shell or beacons out — the
// spreadsheet-as-shell malware delivery vector. Weekly-freshest detection built around Excel.exe
// as InitiatingProcess and XLL file activity as the trigger.
// Source: KQL Detection of the Week: Nice Costume, Wrong Address (2026-07-13) — https://devsecopsdadattack.com/2026-07-13-KQL-Detection-of-the-Week_-Nice-Costume_-Wrong-Address/

let lookback = 1h;
let csvUploads = DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType == "FileCreated"
| where FileName endswith ".csv"
| where FolderPath has_any ("flowise", "uploads", "tmp")
| project DeviceName, CSVCreatedTime = Timestamp, CSVFile = FileName, FolderPath;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ ("python", "python3", "python3.exe", "python.exe")
| where InitiatingProcessFileName has_any ("node", "flowise")
| project
    DeviceName,
    PythonSpawnTime = Timestamp,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    SHA256,
    InitiatingProcessSHA256
| join kind=leftouter csvUploads on DeviceName
| where isnull(CSVCreatedTime) or PythonSpawnTime between (CSVCreatedTime .. (CSVCreatedTime + 5min))
| project
    DeviceName,
    AccountName,
    PythonSpawnTime,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    SHA256,
    InitiatingProcessSHA256,
    CSVCreatedTime,
    CSVFile,
    FolderPath
| order by PythonSpawnTime desc
```

</div>
