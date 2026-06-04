---
layout: post
title: "Detection Engineering Brief - Thursday, June 4, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-04
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - npm
  - GitHub
  - CI/CD environments
  - developer workstations
  - cloud platforms
  - Argamal
  - Windows
  - T1552
  - T1552.001
  - T1041
  - T1071
  - T1071.001
  - T1547
  - T1547.001
---

## Executive Signal

This brief produced 4 detection candidates.

0 production candidates, 3 hunting-only, 1 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: npm, GitHub, CI/CD environments, developer workstations, cloud platforms, Argamal, Windows, T1552, T1552.001, T1041, T1071, T1071.001, T1547, T1547.001.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: npm Preinstall Script Spawning Shell or Writing Outside node_modules; Node.js Process Reading Credential Files Followed by Outbound Network Connection; Trojanized Game Installer Spawning Persistent Outbound-Connecting Child Process; Argamal RAT C2 Beaconing from User-Writable Directory Process.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: npm Preinstall Script Spawning Shell or Writing Outside node_modules

### Detection Opportunity

Compromised npm packages execute malicious preinstall scripts that spawn shells or write files outside node_modules during package installation on CI/CD or developer systems.

### Intelligence Context

- Microsoft Security Blog: Preinstall to persistence: Inside the Red Hat npm Miasma credential-stealing campaign — [https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-the-red-hat-npm-miasma-credential-stealing-campaign/](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-the-red-hat-npm-miasma-credential-stealing-campaign/)
  - Context: Over 90 versions of @redhat-cloud-services npm packages were compromised with malicious preinstall hooks that silently executed on CI/CD and developer systems, spawning shells and enabling credential theft.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1552, T1552.001, T1041
- Products: npm, GitHub
- Platforms: CI/CD environments, developer workstations, cloud platforms
- Malware: Not specified
- Tools: Not specified
- Search tags: npm, GitHub, CI/CD environments, developer workstations, cloud platforms, T1552, T1552.001, T1041

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1552 Unsecured Credentials/ T1552.001 Credentials In Files (high); Exfiltration: T1041 Exfiltration Over C2 Channel (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let lookback = 1h;
let shellSpawns = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName in~ ("node.exe", "npm.cmd", "npm", "node")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "bash", "sh", "dash", "zsh")
| where InitiatingProcessCommandLine has_any ("install", " ci ", "preinstall")
| project
    ShellSpawnTime = Timestamp,
    DeviceId,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SpawnedShell = FileName,
    SpawnedShellCommandLine = ProcessCommandLine;
let suspiciousWrites = DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType in ("FileCreated", "FileModified")
| where InitiatingProcessFileName in~ ("node.exe", "npm.cmd", "npm", "node")
| where not (FolderPath has "node_modules")
| where FolderPath has_any (".ssh", ".aws", ".config", ".npmrc", ".gitconfig", "AppData", "/tmp", "/home", "/root")
| project
    WriteTime = Timestamp,
    DeviceId,
    DeviceName,
    AccountName,
    WrittenFileName = FileName,
    WrittenFolderPath = FolderPath,
    WriteInitiatingProcess = InitiatingProcessFileName;
shellSpawns
| join kind=inner suspiciousWrites on DeviceId
| where abs(datetime_diff('minute', ShellSpawnTime, WriteTime)) <= 5
| project
    ShellSpawnTime,
    WriteTime,
    DeviceId,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SpawnedShell,
    SpawnedShellCommandLine,
    WrittenFileName,
    WrittenFolderPath
| order by ShellSpawnTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- CI/CD agents running npm install with native module compilation (node-gyp) that spawn sh/bash and write to /tmp.
- Developer machines running npm publish or npm run build scripts that invoke shell commands as part of the build lifecycle.
- Electron or NW.js applications that use node as a runtime and spawn shells for legitimate application features.

Tuning notes:
- Scope to specific device groups representing CI/CD agents or developer workstations to reduce volume before broader rollout.
- Add AccountName exclusions for known CI/CD service accounts if those accounts legitimately run npm install with shell invocations.
- Consider extending FolderPath sensitive path list to include .config/gcloud, .kube/config, and .azure for cloud-heavy environments.

Risks / caveats:
- DeviceFileEvents ActionType coverage for file writes depends on Defender for Endpoint sensor configuration; environments with reduced telemetry profiles may not capture all write events from node processes.
- The 5-minute correlation window between shell spawn and file write may be too wide in high-activity CI/CD environments; reduce to 2 minutes if noise is high.
- InitiatingProcessFileName matching on 'npm' and 'node' without path validation may match unrelated processes with similar names on non-standard installations.
- The FolderPath filter list for sensitive paths is not exhaustive; cloud provider credential paths such as .config/gcloud or .kube are not included in this detection's file write leg.

### Triage Runbook

First 15 minutes:
- Confirm the host role: CI/CD agent, developer workstation, or cloud build runner; if it is a known build host, identify the pipeline/job and package being installed.
- Review the spawned shell process command line and parent/initiating npm command to see whether the activity aligns with a specific package install, preinstall hook, or unexpected script execution.
- Inspect the written file path(s) and determine whether they target sensitive locations such as .npmrc, .ssh, .aws, .gitconfig, .config/gcloud, .kube, AppData, /tmp, /home, or /root.
- Check whether the same account or device shows follow-on outbound connections, additional script execution, or repeated file writes shortly after the alert.
- If the package name/version is visible in surrounding telemetry or build logs, identify whether it is a known-good dependency, a newly added dependency, or a recently updated package.

Evidence to collect:
- DeviceProcessEvents for the shell spawn: process name, command line, parent process, and timestamp.
- DeviceFileEvents for the write: full folder path, file name, action type, and initiating process lineage.
- DeviceNetworkEvents around the same time for outbound connections from node/npm or the spawned shell.
- Build logs, npm install output, package-lock.json, and CI job metadata if the host is a pipeline runner.
- AccountName and DeviceName to determine whether the activity came from a service account or an interactive user.

Pivot points:
- DeviceProcessEvents filtered to the same DeviceId and AccountName for node.exe, npm, cmd.exe, powershell.exe, bash, sh, or pwsh.exe around the alert time.
- DeviceFileEvents filtered to the same DeviceId for FileCreated/FileModified events outside node_modules and in sensitive paths.
- DeviceNetworkEvents filtered to the same DeviceId and initiating process to look for outbound connections immediately after the shell spawn.
- If available, pivot to package manager logs or CI/CD audit logs to identify the exact npm package and install command.
- Review recent process ancestry on the host to see whether the shell was launched by npm, node, or another installer wrapper.

Benign explanations:
- Legitimate npm lifecycle scripts such as node-gyp compilation or package postinstall steps may spawn shells and write temporary files.
- CI/CD agents often run npm install/ci jobs that create files in temp directories or AppData-like workspace paths.
- Developer machines may legitimately run build scripts that invoke shell commands during package installation.

Escalation criteria:
- The written file targets credential locations, startup locations, or other sensitive paths outside the expected build workspace.
- The shell command line shows suspicious download, credential access, or obfuscation behavior, or the process immediately follows with outbound connections.
- The activity occurs on a developer workstation or CI/CD agent that should not be installing untrusted packages, or the package version is unexpected/recently compromised.
- Multiple hosts or accounts show the same pattern within a short time window, suggesting a broader supply-chain event.

Containment actions:
- Pause or isolate the affected CI/CD job or developer endpoint if the package install is still in progress and the host is not required for critical production work.
- Revoke or rotate any credentials stored in files that may have been accessed, especially npm tokens, cloud keys, SSH keys, and Git credentials.
- Block the suspicious package version in the build pipeline or package manager allowlist until the source is validated.
- Preserve the host state and relevant logs before remediation if there is evidence of credential theft or lateral movement.

Closure criteria:
- The package and script are confirmed legitimate for the environment and the file writes are limited to expected build artifacts or temp paths.
- No sensitive files were accessed or written, and no suspicious outbound activity or follow-on execution is observed.
- The host is a known CI/CD or developer system with an approved npm workflow that explains the shell spawn and file writes.
- Any exposed credentials have been rotated and there is no evidence of additional compromise on the host or adjacent systems.

---

## Detection 2: Node.js Process Reading Credential Files Followed by Outbound Network Connection

### Detection Opportunity

Malicious npm package code reads local credential files (AWS, git, npm tokens) and immediately initiates outbound network connections, indicating credential exfiltration.

### Intelligence Context

- Microsoft Security Blog: Preinstall to persistence: Inside the Red Hat npm Miasma credential-stealing campaign — [https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-the-red-hat-npm-miasma-credential-stealing-campaign/](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-the-red-hat-npm-miasma-credential-stealing-campaign/)
  - Context: The Miasma campaign's malicious npm packages accessed credential files from GitHub, cloud platforms, and local machine paths, then exfiltrated the stolen credentials outbound.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1552, T1552.001, T1041
- Products: npm, GitHub
- Platforms: CI/CD environments, developer workstations, cloud platforms
- Malware: Not specified
- Tools: Not specified
- Search tags: npm, GitHub, CI/CD environments, developer workstations, cloud platforms, T1552, T1552.001, T1041

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1552 Unsecured Credentials/ T1552.001 Credentials In Files (high); Exfiltration: T1041 Exfiltration Over C2 Channel (medium)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

Required telemetry:
- DeviceFileEvents, DeviceNetworkEvents

### KQL

```kql
let lookback = 1h;
let credFileAccess = DeviceFileEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName in~ ("node.exe", "node")
| where ActionType in~ ("FileRead", "FileAccessed", "FileCreated", "FileModified")
| where (
    FileName in~ ("credentials", ".npmrc", ".gitconfig", ".netrc", "id_rsa", "id_ed25519")
    or (FileName =~ "config" and FolderPath has_any (".aws", ".ssh", ".config/gcloud", ".azure", ".kube"))
    or FolderPath has_any (".aws", ".ssh", ".config/gcloud", ".azure", ".kube")
)
| project
    CredAccessTime = Timestamp,
    DeviceId,
    DeviceName,
    AccountName,
    AccessedFileName = FileName,
    AccessedFolderPath = FolderPath,
    AccessActionType = ActionType,
    CredInitiatingProcess = InitiatingProcessFileName;
let outboundConns = DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName in~ ("node.exe", "node")
| where (RemoteIPType == "Public") or (isempty(RemoteIPType) and not(ipv4_is_private(RemoteIP)))
| project
    NetTime = Timestamp,
    DeviceId,
    DeviceName,
    AccountName,
    RemoteIP,
    RemoteUrl,
    NetInitiatingProcess = InitiatingProcessFileName;
credFileAccess
| join kind=inner outboundConns on DeviceId
| where NetTime >= CredAccessTime and datetime_diff('minute', NetTime, CredAccessTime) <= 3
| project
    CredAccessTime,
    NetTime,
    DeviceId,
    DeviceName,
    AccountName,
    AccessedFileName,
    AccessedFolderPath,
    AccessActionType,
    RemoteIP,
    RemoteUrl
| order by CredAccessTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- npm publish workflows where node reads .npmrc and connects to the npm registry.
- AWS SDK or GCP SDK calls from node applications that read credential files as part of normal authenticated API usage.
- Git operations invoked from node scripts that read .gitconfig and connect to GitHub or GitLab.

Tuning notes:
- Run a preliminary query against DeviceFileEvents filtering on InitiatingProcessFileName in~ ('node.exe','node') and summarize ActionType values to confirm which file access event types are captured in your environment before deploying.
- Add a RemoteUrl exclusion for registry.npmjs.org and known cloud provider API endpoints to reduce false positives from legitimate SDK usage.
- Consider joining on InitiatingProcessId in addition to DeviceId if the sensor captures that field in both tables, to tighten the correlation to the same process instance.

Risks / caveats:
- DeviceFileEvents does not reliably capture file read events (as opposed to file create/modify) for node processes in all Defender for Endpoint sensor configurations. Confirm ActionType values available in your environment before relying on this query.
- RemoteIPType is an enrichment field populated by Defender for Endpoint's IP classification service and may be absent or empty in some deployments, causing the Public IP filter to drop legitimate hits.
- If DeviceFileEvents does not capture FileRead or FileAccessed ActionType values in the target environment, the credential access leg will only fire on file creation or modification, significantly reducing detection coverage.
- The 3-minute correlation window may be too tight for environments with high ingestion latency; consider extending to 5 minutes if events are frequently missed.

### Triage Runbook

First 15 minutes:
- Confirm whether the host is a developer workstation, CI/CD runner, or cloud build system and whether Node.js activity is expected on that system.
- Review the accessed file path(s) to identify the credential type: .npmrc, .gitconfig, .netrc, AWS keys, SSH keys, gcloud, Azure, or kubeconfig.
- Check the outbound connection details immediately after file access, including RemoteIP, RemoteUrl, and whether the destination is a known registry, cloud API, or unknown external host.
- Determine whether the same process or account accessed multiple credential files or made repeated outbound connections in a short period.
- If the host is a build runner, verify whether the access aligns with a known authentication step or whether it occurred outside the normal pipeline context.

Evidence to collect:
- DeviceFileEvents showing the credential file access, including ActionType, FolderPath, FileName, and timestamp.
- DeviceNetworkEvents showing the outbound connection, including RemoteIP, RemoteUrl, RemoteIPType, and timestamp.
- DeviceProcessEvents for the Node.js process ancestry and command line to identify the script or package involved.
- AccountName, DeviceName, and DeviceId to determine whether the activity is tied to a service account or interactive user.
- Any available package manager logs, CI job logs, or application logs that explain why Node.js touched the credential file.

Pivot points:
- DeviceFileEvents on the same DeviceId for additional reads of .aws, .ssh, .config/gcloud, .azure, .kube, .npmrc, .gitconfig, or .netrc.
- DeviceNetworkEvents on the same DeviceId and AccountName for other outbound connections from node.exe or related child processes.
- DeviceProcessEvents for node.exe and its children to identify the exact script, package, or repository action that preceded the access.
- If available, pivot to proxy, firewall, or DNS logs for the RemoteIP/RemoteUrl to determine whether data left the environment.
- Search for the same file access pattern across other hosts to identify whether this is isolated or part of a broader campaign.

Benign explanations:
- npm publish or package management workflows may legitimately read .npmrc and then connect to the npm registry.
- Node-based applications and SDKs may read cloud credential files as part of normal authenticated API usage.
- Git operations or automation scripts may read .gitconfig or SSH-related files and then connect to GitHub or GitLab.

Escalation criteria:
- The destination is an unknown or suspicious external host, especially if it is not a known registry or cloud API endpoint.
- Multiple sensitive credential files are accessed, or the process reads keys and then makes repeated outbound connections.
- The activity occurs on a host that should not be handling secrets, or the access is outside an approved build/authentication workflow.
- There is evidence of credential theft, such as subsequent use of the same credentials from another host or unusual cloud/Git activity.

Containment actions:
- Rotate or revoke any credentials that may have been accessed, starting with npm tokens, cloud access keys, SSH keys, and Git credentials.
- Isolate the host if the outbound destination is unknown or if there is evidence of active exfiltration.
- Disable or suspend the affected service account or pipeline identity until the scope of access is understood.
- Preserve process, file, and network telemetry for incident response before cleaning up the host.

Closure criteria:
- The file access is confirmed to be part of a documented and expected authentication or build workflow.
- The outbound connection is to a known and approved endpoint such as a registry or cloud API, with no evidence of data theft.
- No additional sensitive files were accessed and no suspicious follow-on activity is present on the host or related accounts.
- Any potentially exposed secrets have been rotated and there is no sign of misuse.

---

## Detection 3: Trojanized Game Installer Spawning Persistent Outbound-Connecting Child Process

### Detection Opportunity

A trojanized game installer drops and executes a RAT payload from user-writable directories, which then establishes repeated outbound connections consistent with C2 beaconing.

### Intelligence Context

- Securelist: Argamal: Malware hidden in hentai games — [https://securelist.com/argamal-rat-distributed-with-hentai-games/119999/](https://securelist.com/argamal-rat-distributed-with-hentai-games/119999/)
  - Context: The Argamal RAT is distributed via trojanized game installers. Once executed, it establishes remote control over the infected Windows host, with the payload typically dropped from user-accessible paths such as Downloads or Temp.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1071.001, T1547, T1547.001
- Products: Not specified
- Platforms: Windows
- Malware: Argamal
- Tools: Not specified
- Search tags: Argamal, Windows, T1071, T1071.001, T1547, T1547.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium); Persistence: T1547 Boot or Logon Autostart Execution/ T1547.001 Registry Run Keys / Startup Folder (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- If InitiatingProcessFolderPath is not populated in DeviceNetworkEvents in the target environment, the outbound leg will return no results due to the isnotempty() filter.

Required telemetry:
- DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents

### KQL

```kql
let lookback = 24h;
let childProcs = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FolderPath has_any ("\\Downloads\\", "\\Temp\\", "\\AppData\\Local\\Temp\\", "\\AppData\\Roaming\\")
| where InitiatingProcessFileName has_any ("setup", "install", "installer", "game", "launcher", "patch")
| project
    ProcTime = Timestamp,
    DeviceId,
    DeviceName,
    AccountName,
    ChildProcessFileName = FileName,
    ChildProcessFolderPath = FolderPath,
    ProcessCommandLine,
    InstallerParentProcess = InitiatingProcessFileName;
let outbound = DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where (RemoteIPType == "Public") or (isempty(RemoteIPType) and not(ipv4_is_private(RemoteIP)))
| where isnotempty(InitiatingProcessFolderPath)
| where InitiatingProcessFolderPath has_any ("\\Downloads\\", "\\Temp\\", "\\AppData\\Local\\Temp\\", "\\AppData\\Roaming\\")
| summarize
    ConnectionCount = count(),
    RemoteIPs = make_set(RemoteIP, 10)
    by DeviceId, InitiatingProcessFileName, InitiatingProcessFolderPath, BeaconWindow = bin(Timestamp, 10m)
| where ConnectionCount >= 4;
childProcs
| join kind=inner outbound on DeviceId
| where ChildProcessFileName =~ InitiatingProcessFileName
| where BeaconWindow >= ProcTime and datetime_diff('minute', BeaconWindow, ProcTime) <= 30
| project
    ProcTime,
    BeaconWindow,
    DeviceId,
    DeviceName,
    AccountName,
    ChildProcessFileName,
    ChildProcessFolderPath,
    ProcessCommandLine,
    InstallerParentProcess,
    ConnectionCount,
    RemoteIPs
| order by ProcTime desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Steam, Epic Games, GOG, or similar game platform launchers that run from AppData and make repeated outbound connections to CDN or update infrastructure.
- Electron-based applications installed to AppData that make frequent outbound connections.
- Corporate software deployed to AppData\Roaming by IT management tools that make periodic check-in connections.

Tuning notes:
- Add known-safe game launcher and updater process names (Steam.exe, EpicGamesLauncher.exe, GalaxyClient.exe, etc.) to an exclusion filter on ChildProcessFileName to reduce noise.
- Verify InitiatingProcessFolderPath population in DeviceNetworkEvents by running a count query before deploying: DeviceNetworkEvents | where isnotempty(InitiatingProcessFolderPath) | count.
- Increase ConnectionCount threshold to 6 or higher if legitimate software updaters in the environment generate 4-5 connections per 10-minute window from AppData paths.

Risks / caveats:
- InitiatingProcessFolderPath in DeviceNetworkEvents is not guaranteed to be populated in all Defender for Endpoint sensor versions; verify field availability before relying on the path-based filter in the outbound leg.
- The InitiatingProcessFileName has_any filter for installer parent names is a heuristic that will miss installers with non-standard naming and match many benign installers.
- The 30-minute correlation window between process launch and beaconing window is wide; reduce to 15 minutes if noise is high.
- If InitiatingProcessFolderPath is not populated in DeviceNetworkEvents in the target environment, the outbound leg will return no results due to the isnotempty() filter.

### Triage Runbook

First 15 minutes:
- Confirm the parent installer name, file path, and user context to determine whether this was a game installer, launcher, or another user-launched application.
- Inspect the child process path and command line to verify whether it executed from Downloads, Temp, AppData\Local\Temp, or AppData\Roaming.
- Review the outbound connection pattern for repeated connections, unusual ports, or destinations that are not associated with a legitimate updater or game service.
- Check whether the same host shows additional dropped executables, persistence artifacts, or other suspicious child processes.
- Determine whether the user recently downloaded or executed software from an unofficial source, torrent, or third-party game site.

Evidence to collect:
- DeviceProcessEvents for the installer and child process, including parent/child lineage, command lines, and timestamps.
- DeviceNetworkEvents for the child process, including RemoteIP, RemotePort, RemoteIPType, and connection frequency.
- DeviceFileEvents for any dropped executables or supporting files in user-writable directories.
- User download history, browser history, and any installer metadata if available.
- AccountName and DeviceName to establish whether the activity was initiated by an interactive user.

Pivot points:
- DeviceProcessEvents on the same DeviceId for other processes launched from Downloads, Temp, or AppData paths.
- DeviceNetworkEvents for the same DeviceId and child process name to identify additional beaconing or alternate destinations.
- DeviceFileEvents for recent FileCreated events in user-writable directories that may indicate the payload drop location.
- If available, pivot to browser download logs or endpoint web history to identify the source of the installer.
- Search for the same child process name across other hosts to determine whether this is isolated or part of a wider campaign.

Benign explanations:
- Legitimate game installers and launchers often run from user-writable directories and make repeated outbound connections for updates or telemetry.
- Software updaters and self-extracting installers may drop executables into Temp or AppData and then connect to vendor infrastructure.
- Electron-based applications can resemble this pattern when installed outside standard program directories.

Escalation criteria:
- The child process is unsigned, newly created, or has no clear vendor association and is making repeated outbound connections.
- The process path or command line indicates persistence, credential theft, remote control, or suspicious scripting.
- The installer source is untrusted, unofficial, or associated with known trojanized software distribution.
- Additional hosts show the same installer or child process behavior, suggesting a broader infection set.

Containment actions:
- Isolate the host if the child process is actively beaconing to unknown infrastructure or if the installer source is clearly untrusted.
- Terminate the suspicious child process and preserve the dropped files for analysis if containment is authorized.
- Block the installer source or hash in endpoint controls and web filtering if a malicious source is confirmed.
- Reset credentials used on the host if there is any indication of remote control or secondary payload activity.

Closure criteria:
- The installer and child process are confirmed to be legitimate and tied to a known vendor updater or game platform.
- Outbound connections are to approved vendor infrastructure and the process behavior matches documented application activity.
- No persistence, dropped malicious files, or additional suspicious processes are found on the host.
- The user action and software source are validated, and no other hosts show the same pattern.

---

## Detection 4: Argamal RAT C2 Beaconing from User-Writable Directory Process

### Detection Opportunity

Argamal RAT achieves remote control by running from user-writable paths and maintaining persistent low-frequency outbound connections to attacker-controlled infrastructure.

### Intelligence Context

- Securelist: Argamal: Malware hidden in hentai games — [https://securelist.com/argamal-rat-distributed-with-hentai-games/119999/](https://securelist.com/argamal-rat-distributed-with-hentai-games/119999/)
  - Context: Argamal RAT provides the attacker with persistent remote control over the infected Windows host. RAT implants typically maintain this control through periodic C2 beaconing from the dropped payload location.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1071.001, T1547, T1547.001
- Products: Not specified
- Platforms: Windows
- Malware: Argamal
- Tools: Not specified
- Search tags: Argamal, Windows, T1071, T1071.001, T1547, T1547.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium); Persistence: T1547 Boot or Logon Autostart Execution/ T1547.001 Registry Run Keys / Startup Folder (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- If InitiatingProcessFolderPath is not populated in DeviceNetworkEvents, the isnotempty() guard will cause the entire beaconCandidates result set to be empty.

Required telemetry:
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
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
    DeviceId,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    ProcessCommandLine,
    ConnectionWindows,
    TotalConnections,
    RemoteIPs,
    RemotePorts
| order by ConnectionWindows desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Electron applications (Slack.exe, Code.exe, Discord.exe) running from AppData\Local with persistent outbound connections.
- Software update agents (e.g., vendor-specific updaters) installed to AppData that check for updates on a regular schedule.
- Security or monitoring agents deployed to non-standard paths that make periodic check-in connections.

Tuning notes:
- Run a baseline query to identify the top process names making outbound connections from AppData paths in your environment and add legitimate ones to the exclusion list before hunting.
- Increase ConnectionWindows to 6 and TotalConnections to 12 if the 4/8 thresholds produce excessive volume in your environment.
- Add RemotePort filters to focus on non-standard ports (not 80, 443) if your environment enforces egress policies that would make standard-port beaconing less suspicious.
- Verify InitiatingProcessFolderPath availability with: DeviceNetworkEvents | where Timestamp > ago(1h) | summarize Populated = countif(isnotempty(InitiatingProcessFolderPath)), Total = count().

Risks / caveats:
- InitiatingProcessFolderPath in DeviceNetworkEvents may not be populated in all Defender for Endpoint sensor configurations; if empty, the path-based filter will exclude all results.
- The process exclusion list is not exhaustive; any Electron-based or auto-updating application installed to AppData that is not listed will generate false positives.
- The arg_max aggregation in procContext retrieves the most recent ProcessCommandLine but may not reflect the command line at the time of the beaconing activity if the process was restarted.
- If InitiatingProcessFolderPath is not populated in DeviceNetworkEvents, the isnotempty() guard will cause the entire beaconCandidates result set to be empty.

### Triage Runbook

First 15 minutes:
- Confirm the process name, full path, and command line to see whether it is executing from Downloads, Temp, or AppData.
- Review the connection pattern for periodic, low-frequency outbound traffic to one or more external IPs or ports.
- Check whether the process is a known browser, updater, chat client, or other legitimate application that commonly runs from AppData.
- Look for companion indicators on the host such as new autoruns, scheduled tasks, registry run keys, or additional suspicious child processes.
- Determine whether the user recently installed or launched a game, crack, or unofficial application that could have delivered the payload.

Evidence to collect:
- DeviceProcessEvents for the beaconing process and its parent lineage, including command line and folder path.
- DeviceNetworkEvents showing the repeated outbound connections, RemoteIP, RemotePort, and timing pattern.
- DeviceFileEvents for recent file creation in the same directory to identify dropped payloads or supporting components.
- Any autorun, scheduled task, or startup folder evidence if available from endpoint telemetry.
- AccountName, DeviceName, and any user activity context that explains how the process was launched.

Pivot points:
- DeviceNetworkEvents for the same DeviceId and process name to measure connection frequency and identify all remote destinations.
- DeviceProcessEvents for other processes launched from the same user-writable directory.
- DeviceFileEvents for recent FileCreated events in Downloads, Temp, or AppData paths that may represent the original dropper or payload.
- If available, pivot to autorun, scheduled task, and registry telemetry to look for persistence mechanisms.
- Search across the environment for the same process name, folder path, or command line to identify additional affected hosts.

Benign explanations:
- Legitimate applications such as Electron-based tools, chat clients, and auto-updaters may run from AppData and maintain periodic connections.
- Some enterprise software is deployed to non-standard user-writable paths and checks in regularly to management infrastructure.
- Browsers and sync clients can generate repeated outbound connections, though they are usually recognizable by process name and destination.

Escalation criteria:
- The process is unknown, unsigned, or newly created and is making periodic outbound connections to suspicious infrastructure.
- There are signs of persistence, such as startup entries, scheduled tasks, or registry run keys, associated with the process.
- The process is linked to a trojanized installer, cracked software, or other untrusted source.
- Multiple hosts show the same process path or beaconing pattern, indicating a broader malware campaign.

Containment actions:
- Isolate the host if the process is unknown and beaconing to external infrastructure, especially if persistence is present.
- Terminate the suspicious process and remove any associated persistence only after preserving evidence if incident response procedures allow.
- Block the remote IPs/domains if they are confirmed malicious and not shared with legitimate services.
- Reset credentials used on the host if there is any sign of remote control or secondary malicious activity.

Closure criteria:
- The process is identified as a legitimate application with a documented reason to run from the observed path and to beacon periodically.
- No persistence, dropped payloads, or additional suspicious processes are found on the host.
- The remote destinations are confirmed as approved vendor or enterprise infrastructure.
- No other hosts exhibit the same process/path/connection pattern and the alert is attributable to benign software behavior.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Schema / correlation keys:
- npm Preinstall Script Spawning Shell or Writing Outside node_modules: Do not schedule yet; validate as an analyst-led hunt first.
- Trojanized Game Installer Spawning Persistent Outbound-Connecting Child Process: Do not schedule yet; validate as an analyst-led hunt first.
- Argamal RAT C2 Beaconing from User-Writable Directory Process: Do not schedule yet; validate as an analyst-led hunt first.

Other deployment dependency:
- Node.js Process Reading Credential Files Followed by Outbound Network Connection: Defender for Endpoint file-event coverage must be confirmed on the target host population.

Environment scope / baselines:
- Trojanized Game Installer Spawning Persistent Outbound-Connecting Child Process: If InitiatingProcessFolderPath is not populated in DeviceNetworkEvents in the target environment, the outbound leg will return no results due to the isnotempty() filter.
- Argamal RAT C2 Beaconing from User-Writable Directory Process: If InitiatingProcessFolderPath is not populated in DeviceNetworkEvents, the isnotempty() guard will cause the entire beaconCandidates result set to be empty.

Shared-table notes:
- DeviceProcessEvents: shared by npm Preinstall Script Spawning Shell or Writing Outside node_modules; Trojanized Game Installer Spawning Persistent Outbound-Connecting Child Process; Argamal RAT C2 Beaconing from User-Writable Directory Process
- DeviceFileEvents: shared by npm Preinstall Script Spawning Shell or Writing Outside node_modules; Node.js Process Reading Credential Files Followed by Outbound Network Connection; Trojanized Game Installer Spawning Persistent Outbound-Connecting Child Process
- DeviceNetworkEvents: shared by Node.js Process Reading Credential Files Followed by Outbound Network Connection; Trojanized Game Installer Spawning Persistent Outbound-Connecting Child Process; Argamal RAT C2 Beaconing from User-Writable Directory Process

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: Node.js Process Reading Credential Files Followed by Outbound Network Connection.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: npm Preinstall Script Spawning Shell or Writing Outside node_modules; Trojanized Game Installer Spawning Persistent Outbound-Connecting Child Process; Argamal RAT C2 Beaconing from User-Writable Directory Process.

### Hunting Agenda and Promotion Criteria

- npm Preinstall Script Spawning Shell or Writing Outside node_modules: Do not schedule yet; validate as an analyst-led hunt first..
- Trojanized Game Installer Spawning Persistent Outbound-Connecting Child Process: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Argamal RAT C2 Beaconing from User-Writable Directory Process: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Node.js Process Reading Credential Files Followed by Outbound Network Connection: Defender for Endpoint file-event coverage must be confirmed on the target host population.; confirm required file-access telemetry exists and produces representative events; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

This run exposes a file-access telemetry blind spot: browser cookie theft and resource-file loader behaviors depend on file-read style events that may not be emitted in every Defender deployment. Validate that coverage before treating these as scheduled analytics.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
