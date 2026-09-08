---
layout: page
title: Hunt Npm Postinstall Config Modification No User Context
subtitle: "npm postinstall/lifecycle scripts that modified config without a corresponding interactive user command — AsyncAPI-shaped supply-chain compromise."
permalink: /kql-library/hunting/hunt-npm-postinstall-config-modification-no-user-context/
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
  <code class="kql-lib-query-file">hunt-npm-postinstall-config-modification-no-user-context.kql</code>
</div>

<p class="kql-lib-query-longdesc">npm postinstall/lifecycle scripts that modified config without a corresponding interactive user command — AsyncAPI-shaped supply-chain compromise.</p>

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-hunt-npm-postinstall-config-modification-no-user-context">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn" href="{{ '/assets/kql/hunting/hunt-npm-postinstall-config-modification-no-user-context.kql' | relative_url }}" download="hunt-npm-postinstall-config-modification-no-user-context.kql">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-hunt-npm-postinstall-config-modification-no-user-context" markdown="1">

```kusto
// Author: Ian D. Hanley (DevSecOpsDad) | linkedin.com/in/ianhanley | devsecopsdad.com | devsecopsdadattack.com
// Hunts npm postinstall/lifecycle scripts that modified config files without a corresponding
// interactive user command — the AsyncAPI-shaped supply-chain compromise where the config change
// is real but no human ever asked for it.
// Source: KQL Detection of the Week: The Dog That Didn't Bark (2026-07-20) — https://devsecopsdadattack.com/2026-07-20-KQL-Detection-of-the-Week_-The-Dog-That-Didn_t-Bark/

DeviceFileEvents
| where TimeGenerated > ago(1d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where
    FolderPath has_any (
        @".github\workflows", ".github/workflows",
        ".gitlab-ci", ".circleci", ".travis",
        "azure-pipelines"
    )
    or FileName in~ (
        ".gitlab-ci.yml", "Jenkinsfile", ".travis.yml",
        "circle.yml", "azure-pipelines.yml", ".drone.yml"
    )
| where InitiatingProcessFileName !in~ (
    "git", "git.exe",
    "code", "code.exe",
    "idea", "idea64.exe",
    "vim", "nano", "emacs",
    "runner", "runner.exe",
    "agent", "agent.exe"
)
| project
    TimeGenerated,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    ActionType,
    FolderPath,
    FileName,
    SHA256
| order by TimeGenerated desc
```

</div>
