---
layout: page
title: Detect Dll Masquerading As Microsoft Defender
subtitle: "DLLs pretending to be Microsoft Defender via resource-level publisher/original-filename metadata — a Vidar Stealer TTP."
permalink: /kql-library/analytics-rules/detect-dll-masquerading-as-microsoft-defender/
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
  <code class="kql-lib-query-file">detect-dll-masquerading-as-microsoft-defender.kql</code>
</div>

<p class="kql-lib-query-longdesc">DLLs pretending to be Microsoft Defender via resource-level publisher/original-filename metadata — a Vidar Stealer TTP.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-detect-dll-masquerading-as-microsoft-defender">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/analytics-rules/detect-dll-masquerading-as-microsoft-defender.kql' | relative_url }}" download="detect-dll-masquerading-as-microsoft-defender.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-detect-dll-masquerading-as-microsoft-defender" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Detects DLLs pretending to be Microsoft Defender by inspecting the resource-level
// publisher/original-filename metadata against the signing certificate — a Vidar Stealer TTP. The
// disguise fools name-based checks but not certificate-chain inspection.
// Source: KQL Detection of the Week: Nice Costume, Wrong Address (2026-07-13) — https://devsecopsdadattack.com/2026-07-13-KQL-Detection-of-the-Week_-Nice-Costume_-Wrong-Address/

DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where FileName =~ "MpClient.dll"
| where not (
    FolderPath startswith @"C:\Program Files\Windows Defender"
    or FolderPath startswith @"C:\ProgramData\Microsoft\Windows Defender"
    or FolderPath startswith @"C:\Windows\System32"
    or FolderPath startswith @"C:\Windows\SysWOW64"
)
| project
    Timestamp,
    DeviceId,
    DeviceName,
    FolderPath,
    FileName,
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessSHA256,
    InitiatingProcessAccountName,
    InitiatingProcessAccountDomain
| order by Timestamp desc
```

</div>
