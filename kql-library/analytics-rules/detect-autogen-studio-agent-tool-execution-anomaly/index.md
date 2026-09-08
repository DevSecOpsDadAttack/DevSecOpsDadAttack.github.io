---
layout: page
title: Detect Autogen Studio Agent Tool Execution Anomaly
subtitle: "AutoGen Studio-hosted AI agent taking code-execution or sensitive-tool actions outside its baseline set — the 'AutoJack' agent-abuse shape."
permalink: /kql-library/analytics-rules/detect-autogen-studio-agent-tool-execution-anomaly/
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
  <code class="kql-lib-query-file">detect-autogen-studio-agent-tool-execution-anomaly.kql</code>
</div>

<p class="kql-lib-query-longdesc">AutoGen Studio-hosted AI agent taking code-execution or sensitive-tool actions outside its baseline set — the 'AutoJack' agent-abuse shape.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-detect-autogen-studio-agent-tool-execution-anomaly">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/analytics-rules/detect-autogen-studio-agent-tool-execution-anomaly.kql' | relative_url }}" download="detect-autogen-studio-agent-tool-execution-anomaly.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-detect-autogen-studio-agent-tool-execution-anomaly" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Detects AutoGen Studio-hosted AI agent taking a code-execution or sensitive-tool action outside
// its baseline set — the 'AutoJack' agent-abuse shape where a legitimately-hosted agent becomes
// the exploit primitive.
// Source: KQL Detection of the Week: The Attack That Stayed Under the Threshold (2026-06-19) — https://devsecopsdadattack.com/2026-06-19-KQL-of-the-Week_-The-Attack-That-Stayed-Under-the-Threshold/

let autogenProcesses = dynamic(["autogenstudio", "autogen_studio", "python.exe", "python", "python3"]);
let autogenCmdlineTerms = dynamic(["autogen", "autogenstudio", "mcp", "websocket"]);
let suspawnedProcs = dynamic([
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "bash", "sh", "zsh",
    "curl", "wget", "certutil.exe", "bitsadmin.exe",
    "whoami.exe", "whoami", "net.exe", "net1.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "regsvr32.exe", "rundll32.exe"
]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (autogenProcesses)
| where InitiatingProcessCommandLine has_any (autogenCmdlineTerms)
| where FileName in~ (suspawnedProcs)
| project
    Timestamp, DeviceId, DeviceName, AccountName,
    InitiatingProcessParentFileName, InitiatingProcessFileName,
    InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256,
    AlertDetail = strcat("AutoGen process spawned ", FileName, " | Parent cmdline: ", InitiatingProcessCommandLine)
```

</div>
