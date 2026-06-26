---
layout: post
title: "Detection Engineering Brief - Friday, June 26, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-26
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - T1059
  - Windows
  - Node.js
  - Cobalt Strike
  - SharkLoader
  - Cobalt Strike Beacon
  - StealC
  - Amadey
  - T1547.001
  - T1055
  - T1555.003
  - T1041
---

## Executive Signal

This brief produced 5 detection candidates.

2 production candidates, 3 hunting-only, 0 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: T1059, Windows, Node.js, Cobalt Strike, SharkLoader, Cobalt Strike Beacon, StealC, Amadey, T1547.001, T1055, T1555.003, T1041.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Photo ZIP Campaign - LNK File Created in ZIP Extraction Path with Image-Themed Name; StrikeShark - Cobalt Strike Beacon C2 Beaconing from Injected Process; StrikeShark - SharkLoader Staging Cobalt Strike via Unsigned Process Injection into Windows Host Process.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: Photo ZIP Campaign - LNK File Created in ZIP Extraction Path with Image-Themed Name

### Detection Opportunity

ZIP archive delivered via phishing contains fake image shortcut (.lnk) files extracted to disk on Windows endpoints

### Intelligence Context

- Microsoft Security Blog: Photo ZIP campaign targeting hospitality industry delivers Node.js implant for persistent access — [https://www.microsoft.com/en-us/security/blog/2026/06/25/photo-zip-campaign-targeting-hospitality-industry-delivers-node-js-implant-persistent-access/](https://www.microsoft.com/en-us/security/blog/2026/06/25/photo-zip-campaign-targeting-hospitality-industry-delivers-node-js-implant-persistent-access/)
  - Context: The campaign delivers photo-themed ZIP archives containing fake image shortcut (.lnk) files. When extracted and executed, these LNK files trigger script execution leading to a persistent Node.js implant. Detection targets the LNK file creation event within ZIP extraction paths bearing image-themed filenames.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1547.001
- Products: Not specified
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: T1059, Windows, Node.js, T1547.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: execution: T1059 Command and Scripting Interpreter (medium); persistence: T1547.001 Boot or Logon Autostart Execution/ T1547.001 Registry Run Keys / Startup Folder (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let ImageKeywords = dynamic(["photo", "img", "picture", "jpg", "jpeg", "image"]);
let ScriptInterpreters = dynamic(["cmd.exe", "wscript.exe", "cscript.exe", "powershell.exe", "node.exe", "mshta.exe"]);
let LnkCreations = DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith ".lnk"
| where FolderPath has_any ("Temp", "Downloads", "AppData")
| where FileName has_any (ImageKeywords)
| project LnkTime = Timestamp, DeviceId, DeviceName, AccountName = InitiatingProcessAccountName, LnkFile = FileName, LnkPath = FolderPath;
let ScriptExec = DeviceProcessEvents
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ (ScriptInterpreters)
| project ExecTime = Timestamp, DeviceId, SpawnedProcess = FileName, ProcessCommandLine, InitiatingProcessCommandLine;
LnkCreations
| join kind=inner ScriptExec on DeviceId
| where ExecTime between (LnkTime .. (LnkTime + 5m))
| project LnkTime, ExecTime, DeviceName, AccountName, LnkFile, LnkPath, SpawnedProcess, ProcessCommandLine, InitiatingProcessCommandLine
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate LNK files with image-themed names created by photo management or desktop shortcut tools in Temp or Downloads paths.
- Developer or IT tooling that extracts ZIP archives containing .lnk shortcuts with generic names matching the keyword list.
- Automated test or deployment scripts that create image-named shortcuts and subsequently invoke script interpreters.

Tuning notes:
- Extend the time window from 5 minutes to 15 minutes if the campaign shows delayed user interaction.
- Add environment-specific photo management process names to an exclusion list for InitiatingProcessFileName in the ScriptExec sub-query.
- Consider adding a FolderPath depth check to restrict to first-level extraction directories rather than any subdirectory containing the keyword.

Risks / caveats:
- The 5-minute correlation window may miss cases where the user delays double-clicking the LNK after extraction; consider extending to 15 minutes if hunting across longer sessions.
- explorer.exe as the initiating process for script execution is a common pattern in many benign scenarios; results will require analyst triage to confirm campaign context.
- The image-themed keyword list is intentionally broad; environments with photo management software may see elevated false positives and should baseline before scheduling.

### Triage Runbook

First 15 minutes:
- Confirm the file path, filename, and timestamp to see whether the LNK was created in Temp, Downloads, or AppData shortly after a ZIP extraction or email attachment open.
- Check whether the same user account later launched the LNK or whether explorer.exe spawned cmd.exe, powershell.exe, wscript.exe, cscript.exe, node.exe, or mshta.exe within the correlation window.
- Review the LNK name and surrounding files for photo-themed lure patterns such as photo, img, jpg, jpeg, image, or picture and look for adjacent archive contents that suggest a phishing delivery.
- Identify whether the host is a hospitality or other high-risk user workstation and whether similar LNK creation events occurred on other endpoints from the same sender or campaign timeframe.

Evidence to collect:
- LnkTime, ExecTime, DeviceName, AccountName, LnkFile, LnkPath, SpawnedProcess, ProcessCommandLine, and InitiatingProcessCommandLine from the alert.
- The original ZIP or email attachment source, including sender, subject, and download path if available.
- Process tree for the spawned interpreter and any child processes, plus any follow-on registry, scheduled task, or startup folder changes.
- Any user-reported action such as double-clicking the file, opening the archive, or seeing a fake image icon.

Pivot points:
- DeviceFileEvents for other .lnk creations by the same AccountName, DeviceId, or sender-related timeframe.
- DeviceProcessEvents for explorer.exe child processes and any script interpreter launches shortly after the LNK creation.
- DeviceRegistryEvents and DeviceEvents for persistence actions such as Run keys, startup folder writes, or suspicious child process chains.
- Email or download telemetry to identify the delivery source and whether other recipients received the same archive.

Benign explanations:
- Legitimate photo management or image viewer software creating shortcut files in Temp or Downloads.
- Developer, IT, or packaging tools extracting ZIP archives that contain .lnk shortcuts for testing or deployment.
- User-created desktop shortcuts or automation scripts that happen to use image-themed names.

Escalation criteria:
- The LNK is followed by script interpreter execution from explorer.exe and the command line is suspicious or obfuscated.
- The same archive or sender is seen on multiple hosts or multiple users.
- The host shows additional persistence, credential access, or outbound network activity after the LNK event.
- The user did not intentionally open the archive or cannot explain the file origin.

Containment actions:
- If suspicious execution is confirmed, isolate the host from the network and preserve volatile evidence before remediation.
- Disable or reset the affected user account if there are signs of broader compromise or repeated malicious activity.
- Quarantine the archive, LNK, and any dropped scripts or payloads from the endpoint and email platform.
- Block the sender, attachment hash, or delivery path if campaign-wide indicators are identified.

Closure criteria:
- The LNK is attributable to a known benign workflow and no suspicious script execution or persistence is present.
- The archive source is verified as legitimate and no other hosts or users are affected.
- Follow-on process, registry, and network review shows no malicious activity beyond normal shortcut usage.

---

## Detection 2: Photo ZIP Campaign - Node.js Implant Persistence via Registry Run Key from Non-Standard Path

### Detection Opportunity

Node.js process spawned as a persistent implant from a user-writable or non-standard path, with a registry run key set for persistence on Windows

### Intelligence Context

- Microsoft Security Blog: Photo ZIP campaign targeting hospitality industry delivers Node.js implant for persistent access — [https://www.microsoft.com/en-us/security/blog/2026/06/25/photo-zip-campaign-targeting-hospitality-industry-delivers-node-js-implant-persistent-access/](https://www.microsoft.com/en-us/security/blog/2026/06/25/photo-zip-campaign-targeting-hospitality-industry-delivers-node-js-implant-persistent-access/)
  - Context: The campaign deploys a persistent Node.js implant on Windows endpoints. The implant achieves persistence, likely via registry run keys or scheduled tasks. node.exe running from non-standard or user-writable paths combined with registry persistence activity is the compound signal targeted here.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1547.001
- Products: Not specified
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: T1059, Windows, Node.js, T1547.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: execution: T1059 Command and Scripting Interpreter (medium); persistence: T1547.001 Boot or Logon Autostart Execution/ T1547.001 Registry Run Keys / Startup Folder (high)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceProcessEvents, DeviceRegistryEvents

### KQL

```kql
let RunKeyPaths = dynamic([
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
]);
let NodeExec = DeviceProcessEvents
| where FileName =~ "node.exe"
| where not(FolderPath has_any ("Program Files", "Program Files (x86)", "nodejs"))
| where FolderPath has_any ("Temp", "AppData", "Downloads", "Users\\Public")
| project NodeTime = Timestamp, DeviceId, DeviceName, AccountName, FolderPath, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine;
let RegPersist = DeviceRegistryEvents
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has_any (RunKeyPaths)
| project RegTime = Timestamp, DeviceId, RegistryKey, RegistryValueName, RegistryValueData, ActionType;
NodeExec
| join kind=inner RegPersist on DeviceId
| where RegTime between ((NodeTime - 2m) .. (NodeTime + 10m))
| project NodeTime, RegTime, DeviceName, AccountName, FolderPath, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    RegistryKey, RegistryValueName, RegistryValueData, ActionType
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Developer workstations where node.exe is installed in AppData (e.g., via nvm or nodenv) and the developer also sets a run key for a personal startup script.
- CI/CD agents or build servers that run node.exe from temporary build directories and configure run keys as part of build artifact setup.
- Node-based Electron applications installed to AppData that register themselves in run keys during first launch.

Tuning notes:
- After initial deployment, build an allowlist of AccountName or DeviceName values corresponding to known developer workstations and add a where AccountName !in (allowlist) filter.
- If Electron application installs generate noise, add a check that ProcessCommandLine does not reference known Electron app script paths.
- Reduce the forward time window from 10 minutes to 5 minutes if implant behavior is confirmed to set the run key immediately after node.exe starts.

Risks / caveats:
- RegistryValueName and RegistryValueData are standard DeviceRegistryEvents fields in Defender XDR but must be confirmed populated for run key writes in the specific MDE sensor version deployed; some older sensor versions may not populate RegistryValueData for all write types.
- Developer environments using nvm, nodenv, or Volta may install node.exe under AppData by design; an allowlist of known developer machine hostnames or AccountNames should be applied after initial baselining.
- The 10-minute forward window between node.exe execution and registry write may produce cross-process false positives if another process writes a run key in the same window on the same device; consider adding InitiatingProcessFileName from the registry event to the join if that field is reliably populated.
- Electron-based applications (e.g., VS Code, Slack) that bundle node.exe in AppData and register run keys during installation will match this rule.

### Triage Runbook

First 15 minutes:
- Validate the node.exe path and command line to determine whether it is running from AppData, Temp, Downloads, or another user-writable location rather than a standard Program Files installation.
- Inspect the registry key, value name, and value data to confirm whether the write targets a canonical Run or RunOnce location and whether it points back to the suspicious node.exe or a related script.
- Review the process lineage for the node.exe launch, including InitiatingProcessFileName, InitiatingProcessCommandLine, and parent process to identify the initial execution vector.
- Check for immediate follow-on activity such as outbound connections, child processes, or additional persistence changes from the same account and device.

Evidence to collect:
- NodeTime, RegTime, DeviceName, AccountName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, RegistryKey, RegistryValueName, RegistryValueData, and ActionType from the alert.
- Full process tree for node.exe and any child processes, including script files or downloaded payloads.
- Registry export or screenshots of the Run/RunOnce entry and any related startup folder or scheduled task artifacts.
- Network connections, DNS lookups, and file writes occurring within the same time window.

Pivot points:
- DeviceProcessEvents for node.exe executions from the same DeviceId or AccountName across the last several days.
- DeviceRegistryEvents for additional Run, RunOnce, StartupApproved, or scheduled task persistence on the same host.
- DeviceNetworkEvents for outbound connections from node.exe or its child processes to unusual IPs or domains.
- DeviceFileEvents for dropped scripts, archives, or payloads in the same user-writable path.

Benign explanations:
- Developer environments using nvm, nodenv, Volta, or similar tools that place node.exe under AppData by design.
- Electron-based applications or portable Node.js apps that install into user-writable directories and register startup behavior.
- CI/CD or build agents that run node.exe from temporary directories as part of legitimate automation.

Escalation criteria:
- The registry value points to a suspicious script, encoded command, or non-standard executable in a user-writable path.
- node.exe is launched from an unusual location and is followed by outbound C2-like traffic or additional persistence.
- The same account or host shows repeated Run/RunOnce modifications or multiple suspicious node.exe instances.
- The activity is observed on a non-developer workstation or on multiple endpoints with the same pattern.

Containment actions:
- Isolate the host if the node.exe path, command line, or registry value indicates malicious persistence.
- Disable or reset the affected account if the execution appears tied to phishing or unauthorized access.
- Remove the malicious Run/RunOnce entry and quarantine the node.exe binary, scripts, and related payloads after evidence capture.
- Block known malicious destinations if outbound traffic is observed and confirmed suspicious.

Closure criteria:
- The node.exe installation is verified as a sanctioned developer or application install and the registry entry is expected.
- No suspicious child processes, network activity, or additional persistence is present after review.
- The host and account are baselined as legitimate for this pattern and no broader campaign indicators are found.

---

## Detection 3: StrikeShark - Cobalt Strike Beacon C2 Beaconing from Injected Process

### Detection Opportunity

Cobalt Strike Beacon establishes periodic C2 communication from a process that was injected into by SharkLoader

### Intelligence Context

- Securelist: StrikeShark: investigating a new campaign delivering Cobalt Strike through SharkLoader — [https://securelist.com/strikeshark-campaign/120326/](https://securelist.com/strikeshark-campaign/120326/)
  - Context: The StrikeShark campaign uses a custom loader called SharkLoader to stage and execute Cobalt Strike Beacon in memory. After loader execution, the Beacon establishes C2 communication. Detection targets outbound network connections from common injection target processes on non-standard or high-numbered ports, consistent with Cobalt Strike beaconing behavior.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1055
- Products: Not specified
- Platforms: Not specified
- Malware: Cobalt Strike Beacon, SharkLoader
- Tools: Cobalt Strike
- Search tags: Cobalt Strike, SharkLoader, Cobalt Strike Beacon, T1055

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: defense-evasion: T1055 Process Injection (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceNetworkEvents

### KQL

```kql
let LookbackStart = ago(24h);
let InjectionTargets = dynamic(["rundll32.exe", "svchost.exe", "explorer.exe", "notepad.exe", "msbuild.exe", "regsvr32.exe"]);
let BeaconPorts = dynamic([80, 443, 8080, 8443, 4444]);
DeviceNetworkEvents
| where Timestamp >= LookbackStart
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName has_any (InjectionTargets)
| where RemotePort in (BeaconPorts)
| where not(ipv4_is_private(RemoteIP))
| where isnotempty(RemoteIP)
| summarize
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Ports = make_set(RemotePort),
    RemoteIPs = make_set(RemoteIP),
    RemoteUrls = make_set(RemoteUrl)
    by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| where ConnectionCount >= 5
| where array_length(RemoteIPs) <= 3
| project FirstSeen, LastSeen, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessParentFileName, ConnectionCount, Ports, RemoteIPs, RemoteUrls
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- svchost.exe making repeated connections to Windows Update or telemetry endpoints will match the connection count and low-cardinality IP heuristic.
- explorer.exe making repeated connections to OneDrive or SharePoint sync endpoints on port 443.
- msbuild.exe in CI/CD environments making repeated connections to build artifact servers.
- rundll32.exe used by legitimate software for periodic license or update checks.

Tuning notes:
- After initial hunting runs, identify recurring false-positive process and command-line combinations and add them as exclusion filters.
- Consider joining results with the SharkLoader injection detection to create a higher-confidence compound alert.
- Increase ConnectionCount threshold to 10 or higher in environments with frequent legitimate periodic connectivity from the listed processes.

Risks / caveats:
- ipv4_is_private() does not handle IPv6-mapped IPv4 addresses or link-local addresses; if RemoteIP contains IPv6 format addresses, those rows will not be filtered and may produce noise.
- The 24-hour lookback window is a starting point; beaconing with long sleep intervals may require extending to 48-72 hours to accumulate sufficient connection count.
- The connection count threshold of 5 and IP cardinality of 3 are heuristic values that require environment-specific baselining to avoid excessive false positives from legitimate periodic processes.
- No injection event correlation is included in this query; the beaconing signal alone cannot confirm SharkLoader involvement without cross-referencing DeviceEvents injection actions separately.

### Triage Runbook

First 15 minutes:
- Review the initiating process name, command line, and parent process to see whether the traffic originates from a common injection target such as svchost.exe, rundll32.exe, explorer.exe, or notepad.exe.
- Check the connection pattern for periodicity, low destination diversity, and unusual ports to assess whether it resembles beaconing rather than normal application traffic.
- Identify the first and last seen times, remote IPs, ports, and any remote URLs to determine whether the activity is ongoing and whether multiple hosts contact the same infrastructure.
- Look for corroborating signs of injection or loader activity on the same device, including suspicious process creation, memory tampering, or unsigned binaries in user-writable paths.

Evidence to collect:
- FirstSeen, LastSeen, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, ConnectionCount, Ports, RemoteIPs, and RemoteUrls from the alert.
- Process tree and any available injection or memory-related telemetry for the initiating process.
- DNS, proxy, and firewall logs for the remote IPs and URLs to determine whether the destination is known or newly registered.
- Any related file, registry, or scheduled task activity on the same host around the first seen time.

Pivot points:
- DeviceNetworkEvents for the same InitiatingProcessFileName or RemoteIP across the last 24-72 hours.
- DeviceProcessEvents for suspicious parent-child chains, especially unsigned processes launching common Windows host processes.
- DeviceEvents for injection-related actions or other defense-evasion behavior on the same DeviceId.
- Proxy, firewall, and DNS telemetry to identify additional hosts contacting the same infrastructure.

Benign explanations:
- Legitimate Windows services such as svchost.exe making repeated connections to update, telemetry, or management endpoints.
- Explorer.exe or other common processes repeatedly connecting to cloud sync or collaboration services.
- Build, update, or licensing software that uses periodic outbound connections from standard Windows processes.

Escalation criteria:
- The same remote IPs or URLs are contacted by multiple hosts or by a process with clear injection indicators.
- The process tree shows an unsigned or user-writable-path parent associated with the beaconing process.
- The beaconing is accompanied by other malicious behavior such as credential theft, lateral movement, or persistence.
- The destination infrastructure is confirmed malicious or matches known Cobalt Strike patterns.

Containment actions:
- Isolate the host if beaconing is confirmed or strongly suspected to prevent further command-and-control activity.
- Block the remote IPs, domains, or URLs at the proxy, firewall, or DNS layer if they are confirmed malicious.
- Preserve memory and process artifacts before remediation if your response process supports it.
- Disable the affected account if there is evidence of interactive compromise or lateral movement.

Closure criteria:
- The periodic connections are attributed to a known benign application or service and no injection evidence is found.
- The remote destinations are verified as legitimate enterprise infrastructure or sanctioned cloud services.
- No additional malicious telemetry, persistence, or lateral movement is identified after pivoting.

---

## Detection 4: StealC or Amadey Infostealer - Unsigned Process Accessing Browser Credential Stores with Outbound Exfiltration

### Detection Opportunity

StealC or Amadey infostealer accesses browser credential storage files and makes outbound network connections consistent with data exfiltration

### Intelligence Context

- Microsoft Security Blog: StealC and Amadey: Breaking down infostealers and the cybercrime services that deliver them — [https://www.microsoft.com/en-us/security/blog/2026/06/24/stealc-and-amadey-breaking-down-infostealers-and-the-cybercrime-services-that-deliver-them/](https://www.microsoft.com/en-us/security/blog/2026/06/24/stealc-and-amadey-breaking-down-infostealers-and-the-cybercrime-services-that-deliver-them/)
  - Context: StealC and Amadey are infostealers delivered via cybercrime-as-a-service infrastructure. Their core behavior involves accessing browser credential stores on Windows and exfiltrating collected data to attacker-controlled infrastructure. The detection correlates file access to known browser credential paths with subsequent outbound network connections from the same process.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1555.003, T1041
- Products: Not specified
- Platforms: Windows
- Malware: StealC, Amadey
- Tools: Not specified
- Search tags: Windows, StealC, Amadey, T1555.003, T1041

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: credential-access: T1555.003 Credentials from Web Browsers/ T1555.003 Credentials from Web Browsers (high); exfiltration: T1041 Exfiltration Over C2 Channel (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceFileEvents, DeviceNetworkEvents

### KQL

```kql
let BrowserProcesses = dynamic(["chrome.exe", "firefox.exe", "msedge.exe", "brave.exe", "opera.exe", "vivaldi.exe"]);
let BrowserInstallPaths = dynamic(["Google\\Chrome", "Mozilla Firefox", "Microsoft\\Edge", "BraveSoftware", "Opera"]);
let CredFiles = dynamic(["Login Data", "logins.json", "key4.db", "cookies.sqlite", "Web Data", "Cookies"]);
let CredPaths = dynamic(["AppData\\Local\\Google", "AppData\\Roaming\\Mozilla", "AppData\\Local\\Microsoft\\Edge", "AppData\\Local\\BraveSoftware"]);
let CredAccess = DeviceFileEvents
| where ActionType in ("FileRead", "FileAccessed", "FileCreated")
| where FileName has_any (CredFiles)
| where FolderPath has_any (CredPaths)
| where not(InitiatingProcessFileName has_any (BrowserProcesses))
| where not(InitiatingProcessFolderPath has_any (BrowserInstallPaths))
| project CredTime = Timestamp, DeviceId, DeviceName,
    InitiatingProcessFileName, InitiatingProcessFolderPath,
    InitiatingProcessAccountName, FolderPath, FileName;
let NetOut = DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where not(ipv4_is_private(RemoteIP))
| where isnotempty(RemoteIP)
| project NetTime = Timestamp, DeviceId, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl;
CredAccess
| join kind=inner NetOut on DeviceId, InitiatingProcessFileName
| where NetTime between (CredTime .. (CredTime + 5m))
| project CredTime, NetTime, DeviceName, InitiatingProcessAccountName,
    InitiatingProcessFileName, InitiatingProcessFolderPath,
    FolderPath, FileName, RemoteIP, RemotePort, RemoteUrl
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Password manager applications (e.g., Bitwarden, 1Password) that read browser credential files as part of import functionality and then make outbound connections.
- Browser backup or sync utilities that access credential files and upload to cloud storage.
- Security scanning tools or EDR agents that read credential files during forensic collection and subsequently make telemetry connections.

Tuning notes:
- After initial deployment, identify recurring false-positive InitiatingProcessFileName values (password managers, backup tools) and add them to the BrowserProcesses exclusion list.
- Consider adding a join on InitiatingProcessId if that field is available in both tables to eliminate cross-process false correlations.
- Extend CredFiles and CredPaths arrays to cover additional browsers deployed in the environment (e.g., Opera, Vivaldi credential paths).

Risks / caveats:
- DeviceFileEvents ActionType 'FileAccessed' may not be populated in all MDE sensor configurations; 'FileRead' is the more reliably captured action type for credential file access. Environments where neither is captured for browser credential paths will produce no results from the CredAccess sub-query.
- DeviceFileEvents does not always capture reads of files locked by another process (e.g., Chrome's Login Data while Chrome is running); infostealers that copy the file first before reading may generate a FileCreated event rather than FileRead.
- FileRead and FileAccessed ActionType availability depends on MDE sensor configuration and file access auditing settings; if these are not captured, only FileCreated (copy-before-read pattern) will fire.
- The 5-minute exfiltration window may miss infostealers that batch and delay exfiltration; consider extending to 15 minutes if hunting across known slow-exfil variants.

### Triage Runbook

First 15 minutes:
- Validate the initiating process name and folder path to determine whether it is a non-browser process running from AppData, Temp, Downloads, or another suspicious location.
- Review the accessed file names and paths to confirm browser credential artifacts such as Login Data, logins.json, key4.db, cookies.sqlite, Web Data, or Cookies.
- Check the outbound network activity for the same process to see whether it connected to an external IP, unusual port, or suspicious URL shortly after file access.
- Determine whether the affected user recently opened a phishing attachment, downloaded software, or installed a password manager, backup tool, or browser sync utility.

Evidence to collect:
- CredTime, NetTime, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, FolderPath, FileName, RemoteIP, RemotePort, and RemoteUrl from the alert.
- Process tree for the initiating process and any child processes or dropped files.
- Any browser profile artifacts, recent downloads, and user activity around the time of access.
- Proxy, DNS, and firewall logs for the destination and any repeated connections from the same process or host.

Pivot points:
- DeviceFileEvents for additional reads or copies of browser credential files by the same process or account.
- DeviceNetworkEvents for other outbound connections from the same InitiatingProcessFileName or DeviceId.
- DeviceProcessEvents for suspicious parent processes, script interpreters, or archive extractors preceding the credential access.
- DeviceFileEvents and DeviceRegistryEvents for dropped payloads or persistence after the credential access event.

Benign explanations:
- Password manager applications importing browser credentials or syncing vault data.
- Browser backup, migration, or profile management tools accessing credential stores as part of legitimate maintenance.
- Security or forensic tools reading browser files during authorized investigation or endpoint scanning.

Escalation criteria:
- The process is unsigned or runs from a user-writable path and is not a known enterprise tool.
- Outbound traffic follows credential access and targets unknown or newly observed infrastructure.
- The same pattern appears on multiple hosts or multiple user accounts.
- Additional malicious behavior is present, such as persistence, browser session theft, or suspicious child processes.

Containment actions:
- Isolate the host if the process is confirmed or strongly suspected to be an infostealer.
- Reset affected browser, SSO, and password manager credentials for the user and any accounts exposed on the device.
- Quarantine the suspicious executable and any dropped files after evidence capture.
- Block the destination IPs, domains, or URLs if they are confirmed malicious.

Closure criteria:
- The process is verified as a sanctioned password manager, backup, or security tool and the access is expected.
- No suspicious outbound traffic, persistence, or additional malicious activity is found.
- The file access pattern is consistent with normal browser maintenance and not with credential theft.

---

## Detection 5: StrikeShark - SharkLoader Staging Cobalt Strike via Unsigned Process Injection into Windows Host Process

### Detection Opportunity

Custom SharkLoader stages Cobalt Strike Beacon in memory by injecting into a legitimate Windows host process

### Intelligence Context

- Securelist: StrikeShark: investigating a new campaign delivering Cobalt Strike through SharkLoader — [https://securelist.com/strikeshark-campaign/120326/](https://securelist.com/strikeshark-campaign/120326/)
  - Context: SharkLoader is a custom loader used in the StrikeShark campaign to stage Cobalt Strike Beacon in memory. The loader executes as an unsigned process and performs process injection into a legitimate Windows host process to evade detection. This detection targets the injection-type action from an unsigned or anomalous parent process into common Windows targets.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1055
- Products: Not specified
- Platforms: Not specified
- Malware: Cobalt Strike Beacon, SharkLoader
- Tools: Cobalt Strike
- Search tags: Cobalt Strike, SharkLoader, Cobalt Strike Beacon, T1055

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: defense-evasion: T1055 Process Injection (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceEvents

### KQL

```kql
let InjectionActions = dynamic([
    "CreateRemoteThreadApiCall",
    "WriteProcessMemoryApiCall",
    "QueueUserApcRemoteApiCall",
    "SetThreadContextRemoteApiCall"
]);
let HostTargets = dynamic([
    "svchost.exe", "rundll32.exe", "explorer.exe", "notepad.exe",
    "msbuild.exe", "regsvr32.exe", "dllhost.exe", "werfault.exe"
]);
let KnownSafeInjectors = dynamic([
    "MsMpEng.exe", "SenseIR.exe", "csrss.exe", "lsass.exe", "services.exe",
    "SenseCncProxy.exe", "MsSense.exe", "CylanceSvc.exe", "CrowdStrike",
    "mbam.exe", "avgnt.exe"
]);
let UserWritablePaths = dynamic(["Temp", "AppData", "Downloads", "Users\\Public"]);
DeviceEvents
| where ActionType in (InjectionActions)
| where FileName has_any (HostTargets)
| where not(InitiatingProcessFileName has_any (KnownSafeInjectors))
| where InitiatingProcessFolderPath has_any (UserWritablePaths)
| project
    Timestamp,
    DeviceId,
    DeviceName,
    ActionType,
    TargetProcess = FileName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    InitiatingProcessAccountName
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Security tools not covered by the exclusion list that perform injection-like operations for memory scanning or hooking.
- Software installers or updaters running from Temp or AppData that use CreateRemoteThread for legitimate inter-process communication.
- Game anti-cheat software or DRM systems that inject into host processes from AppData paths.
- Development tools such as debuggers or profilers running from user-writable paths.

Tuning notes:
- After initial hunting runs, add security tool process names observed in results to the KnownSafeInjectors list.
- Consider adding a time-based join to the beaconing detection (StrikeShark C2 query) to create a higher-confidence compound alert linking injection to subsequent C2 activity.
- Restrict UserWritablePaths to the specific subdirectories most relevant to observed SharkLoader staging behavior as additional reporting becomes available.

Risks / caveats:
- API-level injection ActionType values (CreateRemoteThreadApiCall, WriteProcessMemoryApiCall, QueueUserApcRemoteApiCall, SetThreadContextRemoteApiCall) are only available when MDE is operating in block or audit mode with advanced hunting telemetry enabled. Environments without this sensor capability will produce no results.
- The FileName field in DeviceEvents for injection actions refers to the target process binary, not a file on disk; this field name reuse may cause confusion but is standard for Defender XDR DeviceEvents injection rows.
- The KnownSafeInjectors exclusion list covers common AV and EDR processes but cannot be exhaustive; security tools not listed will generate false positives until the list is tuned for the specific environment.
- API-level injection telemetry requires MDE advanced hunting sensor capability; absence of this telemetry will silently produce zero results with no error.

### Triage Runbook

First 15 minutes:
- Review the target process, injecting process name, path, command line, and parent process to determine whether the injector is unsigned or launched from Temp, AppData, Downloads, or Users\Public.
- Confirm the injection action type and whether it targets a common host process such as svchost.exe, rundll32.exe, explorer.exe, dllhost.exe, or regsvr32.exe.
- Check whether the injector has any related network activity, dropped files, or persistence changes that would support loader behavior.
- Look for multiple injection events from the same account or device, especially if they occur shortly after a phishing or download event.

Evidence to collect:
- Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName, TargetProcess, and ActionType from the alert.
- Process tree and any available signature or reputation information for the injector and target process.
- Memory, module, and injection-related telemetry if available from the endpoint platform.
- File, registry, and network activity from the same device around the injection time.

Pivot points:
- DeviceEvents for additional injection actions on the same DeviceId or by the same InitiatingProcessFileName.
- DeviceProcessEvents for suspicious executables launched from user-writable paths and their child processes.
- DeviceNetworkEvents for outbound connections from the injector or target process after injection.
- DeviceFileEvents and DeviceRegistryEvents for dropped payloads, Run keys, or startup folder changes.

Benign explanations:
- Security tools, EDR components, or system processes performing legitimate hooking or memory inspection.
- Software installers, updaters, debuggers, or profilers that use injection-like techniques for valid functionality.
- Game anti-cheat, DRM, or accessibility software that injects into host processes from user-writable locations.

Escalation criteria:
- The injector is unsigned, user-writable, and followed by beaconing, credential theft, or persistence.
- The same injector or target process appears on multiple hosts with the same suspicious pattern.
- The target process is a common Windows host and the injection is accompanied by other malware indicators.
- The activity aligns with known SharkLoader or Cobalt Strike staging behavior.

Containment actions:
- Isolate the host if the injection is not attributable to a trusted security or system component.
- Terminate the suspicious injector and any related child processes after preserving evidence.
- Quarantine the injector binary and any dropped files, and block known malicious destinations if present.
- Disable the affected account if the injection originated from a user session tied to phishing or unauthorized execution.

Closure criteria:
- The injection is attributable to a trusted security product, installer, or sanctioned tool and no other malicious indicators are present.
- No follow-on beaconing, persistence, or credential theft is observed after pivoting.
- The process path, signature, and behavior are consistent with approved software in the environment.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Schema / correlation keys:
- Photo ZIP Campaign - LNK File Created in ZIP Extraction Path with Image-Themed Name: Do not schedule yet; validate as an analyst-led hunt first.
- StrikeShark - Cobalt Strike Beacon C2 Beaconing from Injected Process: Do not schedule yet; validate as an analyst-led hunt first.
- StrikeShark - SharkLoader Staging Cobalt Strike via Unsigned Process Injection into Windows Host Process: Do not schedule yet; validate as an analyst-led hunt first.

Shared-table notes:
- DeviceFileEvents: shared by Photo ZIP Campaign - LNK File Created in ZIP Extraction Path with Image-Themed Name; StealC or Amadey Infostealer - Unsigned Process Accessing Browser Credential Stores with Outbound Exfiltration
- DeviceProcessEvents: shared by Photo ZIP Campaign - LNK File Created in ZIP Extraction Path with Image-Themed Name; Photo ZIP Campaign - Node.js Implant Persistence via Registry Run Key from Non-Standard Path
- DeviceNetworkEvents: shared by StrikeShark - Cobalt Strike Beacon C2 Beaconing from Injected Process; StealC or Amadey Infostealer - Unsigned Process Accessing Browser Credential Stores with Outbound Exfiltration

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Photo ZIP Campaign - Node.js Implant Persistence via Registry Run Key from Non-Standard Path; StealC or Amadey Infostealer - Unsigned Process Accessing Browser Credential Stores with Outbound Exfiltration.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Photo ZIP Campaign - LNK File Created in ZIP Extraction Path with Image-Themed Name; StrikeShark - Cobalt Strike Beacon C2 Beaconing from Injected Process; StrikeShark - SharkLoader Staging Cobalt Strike via Unsigned Process Injection into Windows Host Process.

### Hunting Agenda and Promotion Criteria

- Photo ZIP Campaign - LNK File Created in ZIP Extraction Path with Image-Themed Name: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- StrikeShark - Cobalt Strike Beacon C2 Beaconing from Injected Process: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- StrikeShark - SharkLoader Staging Cobalt Strike via Unsigned Process Injection into Windows Host Process: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

This run exposes a file-access telemetry blind spot: browser cookie theft and resource-file loader behaviors depend on file-read style events that may not be emitted in every Defender deployment. Validate that coverage before treating these as scheduled analytics.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
