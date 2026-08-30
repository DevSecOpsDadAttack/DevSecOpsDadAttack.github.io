---
layout: post
title: "Detection Engineering Brief - Sunday, August 30, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-08-30
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - T1574
  - Microsoft
  - Windows
  - T1204
  - CVE-2026-81578
  - CVE-2026-82078
  - T1190
  - PaperCut NG
  - PaperCut MF
  - Linux
  - macOS
  - T1090
  - T1090.001
  - T1204.001
---

## Detection Engineering Summary

This brief produced 4 detection candidates.

1 production candidate, 2 hunting-only, 1 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: T1574, Microsoft, Windows, T1204, CVE-2026-81578, CVE-2026-82078, T1190, PaperCut NG, PaperCut MF, Linux, macOS, T1090, T1090.001, T1204.001.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: TerminalFix - Unsigned DLL Loaded from User-Writable Path by Legitimate Binary; TerminalFix - Outbound Connection on Uncommon Port from Non-Browser Process Indicating Reverse Tunnel C2; PaperCut Exploitation - Anomalous Child Process Spawned from PaperCut Server Process.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: TerminalFix - Unsigned DLL Loaded from User-Writable Path by Legitimate Binary

### Detection Opportunity

DLL sideloading via legitimate signed executables loading unsigned DLLs from user-writable directories during the TerminalFix intrusion chain

### Intelligence Context

- Microsoft Security Blog: TerminalFix campaign deploys a reverse tunnel through multistage intrusion — [https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/)
  - Context: The TerminalFix campaign performs DLL sideloading as part of its multistage intrusion chain, using legitimate binaries to load malicious DLLs. This technique was explicitly identified in the reporting as a core component of the attack.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1574, T1090, T1090.001, T1204, T1204.001
- Products: Microsoft
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: T1574, Microsoft, Windows, T1090, T1090.001, T1204, T1204.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1090 Proxy/ T1090.001 Internal Proxy (medium); Execution: T1204 User Execution/ T1204.001 Malicious Link (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- DeviceImageLoadEvents is not available in all Defender XDR licensing tiers; confirm table presence before relying on this query.

**Required telemetry:**
- DeviceImageLoadEvents, DeviceProcessEvents

### KQL

```kql
let UserWritablePaths = dynamic(["\\AppData\\", "\\Temp\\", "\\Downloads\\", "\\Public\\"]);
let ExcludedInitiators = dynamic(["svchost.exe", "MsMpEng.exe", "TrustedInstaller.exe", "wuauclt.exe"]);
let SuspectLoads = DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where IsSigned == false
| where isnotempty(FolderPath)
| where FolderPath has_any (UserWritablePaths)
| where InitiatingProcessFileName !in~ (ExcludedInitiators)
| project
    LoadTimestamp = Timestamp,
    DeviceId,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessSHA256,
    DllPath = FolderPath,
    DllName = FileName,
    DllSHA256 = SHA256;
let RecentProcesses = DeviceProcessEvents
| where Timestamp > ago(7d)
| where isnotempty(ProcessCommandLine)
| project
    ProcTimestamp = Timestamp,
    DeviceId,
    AccountName,
    ChildProcess = FileName,
    ProcessCommandLine,
    InitiatingProcessParentFileName;
SuspectLoads
| join kind=inner RecentProcesses on DeviceId
| where abs(datetime_diff('second', LoadTimestamp, ProcTimestamp)) < 60
| project
    LoadTimestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessSHA256,
    DllName,
    DllPath,
    DllSHA256,
    ChildProcess,
    ProcessCommandLine,
    InitiatingProcessParentFileName
| order by LoadTimestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Software update installers that stage unsigned DLLs in AppData or Temp before loading them via a signed host process.
- Electron-based applications that load unsigned native modules from user-profile directories.
- Browser extension loaders that use signed browser binaries to load unsigned helper DLLs from AppData.

**Tuning notes:**
- Add known-good initiating process names (e.g., update.exe, setup.exe, electron.exe) to ExcludedInitiators after baseline review.
- Consider adding a distinct count of DllSHA256 per DeviceName over the lookback window to surface mass-sideloading events.
- Reduce lookback to 1d when promoting to a scheduled rule to limit join fan-out.

**Risks / caveats:**
- IsSigned and Signer fields in DeviceImageLoadEvents require Defender for Endpoint Plan 2 with image load telemetry enabled; these fields may be empty or absent if the sensor is not configured to collect image load events.
- DeviceImageLoadEvents is not available in all Defender XDR licensing tiers; confirm table presence before relying on this query.
- The 60-second correlation window between image load and process creation is a heuristic and may miss delayed execution or produce false correlations in high-process-volume environments.
- The many-to-many join on DeviceId alone will still produce multiple rows per load event on busy endpoints; analysts should group by DllSHA256 and InitiatingProcessFileName during triage.

### Triage Runbook

**First 15 minutes:**
- Confirm the initiating process name, SHA256, and signer; verify it is a known application and not a renamed copy or unexpected binary.
- Inspect the DLL path and hash; treat DLLs from AppData, Temp, Downloads, or Public as suspicious unless tied to a known installer or updater.
- Check whether the same host or user also triggered browser-to-script execution or unusual outbound connections around the same time.
- Review the process command line and parent process to understand whether the load occurred during installation, update, or normal application startup.

**Evidence to collect:**
- DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessSHA256, and InitiatingProcessParentFileName.
- DllName, DllPath, DllSHA256, IsSigned, and Signer for the loaded module.
- ProcessCommandLine for the loading process and any child process spawned shortly after.
- Timestamp correlation between the DLL load and any nearby process creation or network events on the same host.

**Pivot points:**
- DeviceImageLoadEvents for the same DeviceName and DllSHA256 to see if the DLL loaded on other hosts.
- DeviceProcessEvents for the same DeviceId to identify child processes, unusual parents, or repeated launches of the same binary.
- DeviceNetworkEvents for the same DeviceName and InitiatingProcessFileName to look for reverse tunnel or proxy behavior.
- If available, file reputation or threat intel lookups on DllSHA256 and InitiatingProcessSHA256.

**Benign explanations:**
- Software installers and updaters that stage unsigned DLLs in user-profile directories before loading them.
- Electron-based applications that legitimately load native modules from AppData or profile folders.
- Browser extension or plugin loaders that use a signed host process to load helper DLLs from user-writable paths.

**Escalation criteria:**
- The DLL is unsigned, unknown, or matches a known malicious hash or reputation hit.
- The initiating process is not a recognized updater/installer and the DLL path is clearly user-writable.
- There is nearby evidence of script execution, suspicious child processes, or outbound connections on uncommon ports.
- Multiple hosts show the same DLL hash or the same initiating process loading from user-writable paths.

**Containment actions:**
- Isolate the host if the DLL is unknown and there is any follow-on execution or network activity consistent with compromise.
- Terminate the suspicious process tree if it is still active and capture volatile evidence first if your workflow supports it.
- Quarantine the DLL and related binaries only after preserving hashes and paths for investigation.
- Reset credentials for the affected user if the activity appears tied to user-driven execution and the host is confirmed compromised.

**Closure criteria:**
- The DLL and initiating binary are confirmed as legitimate software with matching vendor reputation and expected install/update behavior.
- No suspicious child processes, persistence, or outbound connections are associated with the event.
- The same pattern is observed across a known-good software deployment and added to the local allowlist or baseline.
- Threat intel and hash review do not indicate malicious activity, and the event is attributable to a documented installer or updater run.

<br/>
---
<br/>

## Detection 2: TerminalFix - Script Interpreter Spawned by Browser Process Indicating Fake CAPTCHA Lure Execution

### Detection Opportunity

Script interpreter process spawned as a child of a browser process, consistent with user execution triggered by a fake CAPTCHA prompt in the TerminalFix campaign

### Intelligence Context

- Microsoft Security Blog: TerminalFix campaign deploys a reverse tunnel through multistage intrusion — [https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/)
  - Context: The TerminalFix campaign uses fake CAPTCHA prompts to socially engineer users into executing a payload. This lure pattern reliably results in script interpreter processes being spawned from browser parent processes, which is the detectable artifact of the social engineering stage.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1204, T1090, T1090.001, T1204.001
- Products: Microsoft
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: T1204, Microsoft, Windows, T1090, T1090.001, T1204.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1090 Proxy/ T1090.001 Internal Proxy (medium); Execution: T1204 User Execution/ T1204.001 Malicious Link (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let BrowserProcesses = dynamic(["chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe"]);
let ScriptInterpreters = dynamic(["mshta.exe", "wscript.exe", "cscript.exe", "powershell.exe", "pwsh.exe", "cmd.exe"]);
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName has_any (BrowserProcesses)
| where FileName has_any (ScriptInterpreters)
| project
    Timestamp,
    DeviceName,
    AccountName,
    ParentBrowser = InitiatingProcessFileName,
    ParentBrowserCommandLine = InitiatingProcessCommandLine,
    InitiatingProcessSHA256,
    ScriptEngine = FileName,
    ScriptEnginePath = FolderPath,
    ScriptEngineSHA256 = SHA256,
    ProcessCommandLine
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- cmd.exe or powershell.exe launched by browser-integrated developer tools or browser automation frameworks such as Selenium or Playwright.
- Enterprise browser management extensions that invoke PowerShell for policy enforcement.
- Electron-based applications that embed Chromium and spawn cmd.exe for shell integration.

**Tuning notes:**
- After initial deployment, review results for recurring ParentBrowser and ScriptEngine combinations that are environment-specific false positives and add them to an exclusion filter.
- If cmd.exe generates excessive noise, consider splitting into a separate lower-severity rule and retaining mshta.exe, wscript.exe, and cscript.exe in the high-severity rule.
- Consider adding a filter for ScriptEnginePath has_any (dynamic(["\\AppData\\", "\\Temp\\", "\\Downloads\\"])) to increase specificity when FP volume is high.

**Risks / caveats:**
- Electron-based applications embedding Chromium will appear as browser parents and may generate false positives; these should be identified during baseline review and their executable names added to an exclusion list.
- Browser automation frameworks used in developer or QA environments will match this pattern; consider scoping to non-developer device groups if volume is high.

### Triage Runbook

**First 15 minutes:**
- Validate the parent browser, child interpreter, and command line; treat mshta, wscript, cscript, powershell, pwsh, and cmd spawned from a browser as suspicious until explained.
- Check the user account and device context to see whether the activity aligns with a known developer, automation, or browser-management workflow.
- Review the browser command line and recent browsing context if available to identify lure pages, downloads, or redirected content.
- Look for immediate follow-on activity such as additional child processes, file writes, or outbound connections from the script interpreter.

**Evidence to collect:**
- DeviceName, AccountName, ParentBrowser, ParentBrowserCommandLine, ScriptEngine, ScriptEnginePath, ScriptEngineSHA256, and ProcessCommandLine.
- InitiatingProcessSHA256 for the browser and any available SHA256 for the script engine.
- Timestamp and sequence of browser-to-script launch, including any child processes spawned by the script engine.
- Any related downloads, temporary files, or user profile paths referenced in the command line or folder path.

**Pivot points:**
- DeviceProcessEvents on the same DeviceName for the script engine SHA256 to find repeated executions or additional child processes.
- DeviceNetworkEvents for the same DeviceName and AccountName to identify outbound connections after script launch.
- DeviceFileEvents or related file telemetry to identify dropped payloads, scripts, or downloaded archives.
- Browser history or web proxy logs, if available, to confirm whether a fake CAPTCHA or lure page was visited.

**Benign explanations:**
- Browser developer tools or automation frameworks such as Selenium or Playwright launching cmd.exe or PowerShell.
- Enterprise browser management or policy enforcement extensions that invoke scripts.
- Electron-based applications that embed Chromium and legitimately spawn shell commands for integration features.

**Escalation criteria:**
- The script command line references encoded content, remote URLs, download cradle behavior, or suspicious script execution flags.
- The browser parent is not associated with a known automation or management workflow and the user did not expect the action.
- The script interpreter spawns additional payloads, creates persistence, or initiates unusual outbound connections.
- Multiple users or hosts show the same browser-to-script pattern, suggesting a broader campaign.

**Containment actions:**
- Isolate the host if the script command line or follow-on activity indicates active compromise.
- Suspend or reset the affected user account if the execution appears user-driven and malicious.
- Terminate the browser and script process tree if it is still active and preserve evidence first when possible.
- Block any identified malicious URLs, domains, or downloaded files if they are discovered during triage.

**Closure criteria:**
- The browser-parented script execution is confirmed as a legitimate automation, management, or developer workflow.
- No suspicious command-line arguments, downloads, child processes, or network activity are present.
- The event is tied to a known benign application or approved enterprise extension and matches baseline behavior.
- Any related files or hashes are verified as trusted and no additional alerts are generated from the same host or user.

<br/>
---
<br/>

## Detection 3: TerminalFix - Outbound Connection on Uncommon Port from Non-Browser Process Indicating Reverse Tunnel C2

### Detection Opportunity

Non-browser process establishing outbound network connections on uncommon ports, consistent with reverse tunnel C2 infrastructure deployed in the TerminalFix campaign

### Intelligence Context

- Microsoft Security Blog: TerminalFix campaign deploys a reverse tunnel through multistage intrusion — [https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/)
  - Context: The TerminalFix campaign explicitly establishes a reverse tunnel for C2 connectivity as part of its multistage intrusion. Reverse tunnels produce detectable outbound network patterns from non-browser processes on ports outside standard web traffic ranges.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1204, T1574, T1090, T1090.001, T1204.001
- Products: Microsoft
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: T1204, T1574, Microsoft, Windows, T1090, T1090.001, T1204.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1090 Proxy/ T1090.001 Internal Proxy (medium); Execution: T1204 User Execution/ T1204.001 Malicious Link (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents, DeviceProcessEvents

### KQL

```kql
let CommonPorts = dynamic([80, 443, 8080, 8443, 53, 22, 3389, 445, 135, 139, 5985, 5986, 25, 587, 993, 995]);
let ExcludedProcesses = dynamic(["svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "MsMpEng.exe", "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe", "OneDrive.exe", "Teams.exe"]);
let SuspectConnections = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| where isnotempty(RemoteIP)
| where not(ipv4_is_private(RemoteIP))
| where RemotePort !in (CommonPorts)
| where InitiatingProcessFileName !in~ (ExcludedProcesses)
| project
    ConnTimestamp = Timestamp,
    DeviceId,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessSHA256,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemotePort,
    Protocol;
let RecentDrops = DeviceProcessEvents
| where Timestamp > ago(7d)
| project
    ProcTimestamp = Timestamp,
    DeviceId,
    SpawnedFileName = FileName,
    SpawnedProcessCommandLine = ProcessCommandLine,
    SpawnedProcessSHA256 = SHA256,
    AccountName,
    SpawnParent = InitiatingProcessFileName;
SuspectConnections
| join kind=inner RecentDrops on DeviceId
| where SpawnedFileName =~ InitiatingProcessFileName
| where ConnTimestamp > ProcTimestamp
| where datetime_diff('minute', ConnTimestamp, ProcTimestamp) < 10
| extend MinutesSinceSpawn = datetime_diff('minute', ConnTimestamp, ProcTimestamp)
| project
    ConnTimestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessSHA256,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemotePort,
    Protocol,
    ProcessSpawnTimestamp = ProcTimestamp,
    SpawnedProcessCommandLine,
    SpawnedProcessSHA256,
    SpawnParent,
    MinutesSinceSpawn
| order by ConnTimestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate remote access tools (e.g., AnyDesk, TeamViewer, Zoom) that connect on non-standard ports and are recently installed.
- Software update agents that download from CDN endpoints on non-standard ports shortly after installation.
- VPN clients and network monitoring agents that establish persistent outbound connections on uncommon ports.
- Development tools such as ngrok or SSH clients used legitimately by developers.

**Tuning notes:**
- Add approved remote access tool executable names (e.g., anydesk.exe, teamviewer.exe, zoom.exe) to ExcludedProcesses after baseline review.
- Expand CommonPorts to include any additional approved outbound ports identified during environment baselining.
- Consider adding a summarize step grouping by InitiatingProcessFileName and RemotePort to identify repeated connection patterns before scheduling.
- Reduce lookback to 1d when promoting to a scheduled rule.

**Risks / caveats:**
- The 172.x RFC1918 exclusion in the original query is incomplete; the private range is 172.16.0.0/12 (172.16.x.x through 172.31.x.x). A simple startswith '172.' will incorrectly exclude public IPs in the 172.0.0.0/8 range outside the private block. The improved query corrects this with an ipv4_is_private() function.
- The 10-minute process-to-connection window is a heuristic; legitimate software that installs and immediately phones home will match. Baseline common initiating process names in the environment before scheduling.
- ipv4_is_private() does not exclude link-local (169.254.x.x) or APIPA ranges; add explicit exclusions if these appear in telemetry.
- The join on DeviceId and FileName will still produce multiple rows per connection event if the same process name appears multiple times in the process event table within the lookback window; use summarize to deduplicate during triage.

### Triage Runbook

**First 15 minutes:**
- Confirm the initiating process name, SHA256, and command line; verify whether it is a known remote access tool, updater, VPN client, or developer utility.
- Check the remote IP and port for reputation, geolocation, and whether the destination is expected for the application.
- Review whether the process was recently spawned and whether it has a parent-child chain consistent with user execution or sideloading.
- Look for concurrent signs of compromise on the same host, including suspicious DLL loads, script execution, or persistence creation.

**Evidence to collect:**
- DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessCommandLine, RemoteIP, RemotePort, and Protocol.
- ProcessSpawnTimestamp, SpawnedProcessCommandLine, SpawnedProcessSHA256, and MinutesSinceSpawn if a related process launch is present.
- Any RemoteUrl or domain information available for the connection.
- Timestamp correlation with other process, file, or network events on the same host.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceName and InitiatingProcessSHA256 to identify repeated connections, beaconing, or multiple remote endpoints.
- DeviceProcessEvents for the same DeviceName to identify the process tree and any suspicious child processes.
- DeviceImageLoadEvents for the same host to look for sideloaded DLLs or unsigned modules loaded by the same process.
- Proxy, firewall, or VPN logs to determine whether the destination is a known service or an approved remote access endpoint.

**Benign explanations:**
- Legitimate remote access tools such as AnyDesk, TeamViewer, or Zoom using non-standard ports.
- Software update agents or installers that contact CDN or vendor endpoints shortly after installation.
- VPN clients, network monitoring agents, or developer tools such as ngrok or SSH clients used by authorized staff.

**Escalation criteria:**
- The process is unknown, unsigned, or not associated with an approved application and the destination is not expected.
- The connection is followed by suspicious child processes, persistence, or additional reverse-tunnel-like traffic.
- The same process or hash appears on multiple hosts with similar uncommon-port connections.
- The remote IP or domain is malicious, newly registered, or associated with prior intrusion activity.

**Containment actions:**
- Isolate the host if the process is unapproved and the connection appears to be active C2 or reverse tunneling.
- Terminate the suspicious process tree if confirmed malicious and capture memory or network evidence first when feasible.
- Block the remote IP, domain, or port at the network edge if it is validated as malicious.
- Disable or reset the affected user account if the activity is tied to user-driven execution and compromise is confirmed.

**Closure criteria:**
- The process is confirmed as an approved remote access, VPN, or update component with matching hash and expected destination.
- The remote endpoint is validated as benign and the connection pattern matches documented application behavior.
- No additional suspicious process, file, or network activity is found on the host during the investigation window.
- The event is attributable to a known maintenance or developer workflow and is added to the local baseline or allowlist.

<br/>
---
<br/>

## Detection 4: PaperCut Exploitation - Anomalous Child Process Spawned from PaperCut Server Process

### Detection Opportunity

PaperCut NG/MF server process spawning unexpected child processes, consistent with post-exploitation activity following active exploitation of CVE-2026-81578 or CVE-2026-82078

### Intelligence Context

- Rapid7: PaperCut NG/MF Critical Zero-Day Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild)
  - Context: Rapid7 confirmed active exploitation of critical vulnerabilities in PaperCut NG and PaperCut MF with vendor-confirmed customer incidents. While the exploit path is undisclosed, post-exploitation activity is expected to manifest as anomalous child processes or outbound connections from the PaperCut server process, which is the recommended watchlist approach given the lack of technical detail.

### Search Metadata

- CVEs: CVE-2026-81578, CVE-2026-82078
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: PaperCut NG, PaperCut MF
- Platforms: Windows, Linux, macOS
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-81578, CVE-2026-82078, T1190, PaperCut NG, PaperCut MF, Windows, Linux, macOS

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: watchlist
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let PaperCutParents = dynamic(["pc-app.exe", "pc-pdl-to-image.exe", "PCAppServer.exe", "pc-print-deploy-client.exe"]);
let ExpectedChildren = dynamic(["java.exe", "javaw.exe"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any (PaperCutParents)
| where isnotempty(FileName)
| where FileName !in~ (ExpectedChildren)
| project
    Timestamp,
    DeviceName,
    AccountName,
    ParentProcess = InitiatingProcessFileName,
    ParentProcessCommandLine = InitiatingProcessCommandLine,
    InitiatingProcessSHA256,
    ChildProcess = FileName,
    ChildProcessPath = FolderPath,
    ChildProcessSHA256 = SHA256,
    ProcessCommandLine
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- PaperCut version-specific subprocesses not included in the ExpectedChildren list that are legitimate but unknown at query authoring time.
- Administrative scripts or monitoring agents that are legitimately invoked by the PaperCut service account and spawn child processes.

**Tuning notes:**
- Run DeviceProcessEvents → where DeviceName in~ (<PaperCut server hostnames>) → summarize by InitiatingProcessFileName to discover the actual parent process names in the environment before deploying.
- Run a baseline of child processes spawned by PaperCut parents over 30 days to build a complete ExpectedChildren exclusion list before scheduling.
- Consider adding a DeviceName filter scoped to known PaperCut server hostnames to reduce noise from unrelated devices where process name collisions could occur.

**Risks / caveats:**
- Defender for Endpoint agent must be deployed on PaperCut print servers for DeviceProcessEvents to contain PaperCut process telemetry; print servers are frequently excluded from EDR deployment scope.
- PaperCut server executable names vary by product version and installation path; the PaperCutParents list in the query may not match the installed version and would produce zero results without validation against the environment's PaperCut deployment.
- The PaperCutParents list must be validated against the installed PaperCut version before deployment; incorrect parent names will produce zero results without any error indication.
- The ExpectedChildren list may be incomplete for the installed PaperCut version; additional legitimate subprocesses should be identified during baseline review and added to the exclusion list.

### Triage Runbook

**First 15 minutes:**
- Confirm the PaperCut parent process name and command line against the installed version and server role; verify the host is actually a PaperCut server.
- Inspect the child process name, path, and command line for signs of shell spawning, scripting, archive extraction, or remote tooling.
- Check whether the server recently received exploit traffic, authentication anomalies, or other alerts around the same time.
- Determine whether the child process is expected for this PaperCut deployment or whether it represents a deviation from baseline.

**Evidence to collect:**
- DeviceName, AccountName, ParentProcess, ParentProcessCommandLine, InitiatingProcessSHA256, ChildProcess, ChildProcessPath, ChildProcessSHA256, and ProcessCommandLine.
- Timestamp of the child process spawn and any nearby network or file activity on the same server.
- PaperCut version, installation path, and whether the server is internet-facing or reachable from untrusted networks.
- Any related authentication logs, web logs, or reverse proxy logs for the PaperCut server.

**Pivot points:**
- DeviceProcessEvents on the PaperCut server host to enumerate all child processes spawned by the PaperCut parent over the last 24-72 hours.
- DeviceNetworkEvents for the same host to identify outbound connections from the PaperCut process tree or child process.
- Web server, reverse proxy, and authentication logs for the PaperCut application to identify exploit attempts or suspicious requests.
- File and service creation telemetry on the server to look for persistence, dropped tools, or new scheduled tasks.

**Benign explanations:**
- Version-specific PaperCut subprocesses not included in the expected child list.
- Administrative scripts or monitoring agents legitimately invoked by the PaperCut service account.
- Maintenance or backup tooling that is launched during server administration windows.

**Escalation criteria:**
- The child process is a shell, scripting engine, downloader, or remote administration tool not expected on the server.
- The PaperCut server is internet-facing and there is evidence of exploit traffic or additional suspicious activity.
- The same parent-child pattern appears on multiple PaperCut servers or coincides with other compromise indicators.
- The server shows outbound connections, new services, scheduled tasks, or other post-exploitation artifacts.

**Containment actions:**
- Isolate the PaperCut server if the child process is clearly malicious or if exploitation is strongly suspected.
- Stop the suspicious child process and any related service only after preserving evidence and confirming operational impact.
- Restrict external access to the PaperCut service until the vulnerability status and exposure are validated.
- Engage the server/application owner immediately because print infrastructure compromise can affect multiple users and systems.

**Closure criteria:**
- The child process is confirmed as a documented and expected PaperCut subprocess for the installed version.
- No exploit indicators, suspicious network activity, or persistence artifacts are found on the server.
- The event is attributable to approved administrative activity or maintenance and matches the server baseline.
- The PaperCut deployment is validated, and any version-specific expected children are added to the allowlist or baseline.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- TerminalFix - Unsigned DLL Loaded from User-Writable Path by Legitimate Binary: Do not schedule yet; validate as an analyst-led hunt first.
- TerminalFix - Outbound Connection on Uncommon Port from Non-Browser Process Indicating Reverse Tunnel C2: Do not schedule yet; validate as an analyst-led hunt first.

**Licensing / identity risk fields:**
- TerminalFix - Unsigned DLL Loaded from User-Writable Path by Legitimate Binary: DeviceImageLoadEvents is not available in all Defender XDR licensing tiers; confirm table presence before relying on this query.

**Telemetry availability:**
- PaperCut Exploitation - Anomalous Child Process Spawned from PaperCut Server Process: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.

**Shared-table notes:**
- DeviceProcessEvents: shared by TerminalFix - Unsigned DLL Loaded from User-Writable Path by Legitimate Binary; TerminalFix - Script Interpreter Spawned by Browser Process Indicating Fake CAPTCHA Lure Execution; TerminalFix - Outbound Connection on Uncommon Port from Non-Browser Process Indicating Reverse Tunnel C2; PaperCut Exploitation - Anomalous Child Process Spawned from PaperCut Server Process

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: TerminalFix - Script Interpreter Spawned by Browser Process Indicating Fake CAPTCHA Lure Execution.
2. Resolve environment-mapping detections next: PaperCut Exploitation - Anomalous Child Process Spawned from PaperCut Server Process.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: TerminalFix - Unsigned DLL Loaded from User-Writable Path by Legitimate Binary; TerminalFix - Outbound Connection on Uncommon Port from Non-Browser Process Indicating Reverse Tunnel C2.

### Hunting Agenda and Promotion Criteria

- TerminalFix - Unsigned DLL Loaded from User-Writable Path by Legitimate Binary: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- TerminalFix - Outbound Connection on Uncommon Port from Non-Browser Process Indicating Reverse Tunnel C2: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- PaperCut Exploitation - Anomalous Child Process Spawned from PaperCut Server Process: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
