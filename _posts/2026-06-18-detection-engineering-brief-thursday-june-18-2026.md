---
layout: post
title: "Detection Engineering Brief - Thursday, June 18, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-18
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Dropping Elephant
  - T1574.002
  - T1055
  - Fondue.exe
  - Windows
  - RAT
  - Donut
  - Tor
  - npm
  - Mastra
  - developer endpoints
  - CI/CD
  - SSH
  - Linux
  - T1110
---

## Executive Signal

This brief produced 5 detection candidates.

4 production candidates, 1 hunting-only, 0 require environment mapping, and 0 rejected.

5 detections include KQL. 3 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Dropping Elephant, T1574.002, T1055, Fondue.exe, Windows, RAT, Donut, Tor, npm, Mastra, developer endpoints, CI/CD, SSH, Linux, T1110.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: npm Supply Chain - Node.exe Dropping Executables or Scripts to Hidden or Temp Paths During Package Install.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: Dropping Elephant - Fondue.exe DLL Side-Loading with Child Process or Injection Activity

### Detection Opportunity

Legitimate Microsoft binary Fondue.exe used for DLL side-loading followed by process injection of Donut-generated shellcode into memory

### Intelligence Context

- Rapid7: Malware à la Mode: Tracking Dropping Elephant Tradecraft Through a China-Themed Loader Chain — [https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
  - Context: Dropping Elephant used Fondue.exe, a legitimate Microsoft binary, for DLL side-loading as part of a loader chain that subsequently injected a RAT into memory using Donut-generated shellcode. Fondue.exe has no legitimate operational role outside Windows Optional Features installation, making any child process or injection activity from it highly anomalous.

### Search Metadata

- CVEs: Not specified
- Threat actors: Dropping Elephant
- ATT&CK tags: T1574.002, T1055
- Products: Fondue.exe
- Platforms: Windows
- Malware: RAT
- Tools: Donut
- Search tags: Dropping Elephant, T1574.002, T1055, Fondue.exe, Windows, RAT, Donut

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Defense Evasion: T1574.002 Hijack Execution Flow/ T1574.002 DLL Side-Loading (high)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

Required telemetry:
- DeviceProcessEvents, DeviceEvents

### KQL

```kql
let FondueChildProc = DeviceProcessEvents
| where InitiatingProcessFileName =~ "fondue.exe"
| project Timestamp, DeviceName, DetectionSource = "ChildProcess", ChildProcess = FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, ActionType = "", ReportId;
let FondueInjection = DeviceEvents
| where InitiatingProcessFileName =~ "fondue.exe"
| where ActionType in ("CreateRemoteThreadApiCall", "WriteToLsassMemory", "QueueUserApcRemoteApiCall", "NtAllocateVirtualMemoryApiCall")
| project Timestamp, DeviceName, DetectionSource = "Injection", ChildProcess = FileName, ProcessCommandLine = InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, ActionType, ReportId;
union FondueChildProc, FondueInjection
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Automated Windows Optional Features installation workflows where Fondue.exe is legitimately invoked by svchost.exe or TiWorker.exe and spawns conhost.exe or cmd.exe as a child. These can be excluded by filtering InitiatingProcessFileName of Fondue.exe's own parent if needed.

Tuning notes:
- To reduce false positives from legitimate Windows Optional Features workflows, add a filter excluding cases where InitiatingProcessFolderPath of Fondue.exe's parent is 'C:\Windows\System32\' combined with parent process names svchost.exe or TiWorker.exe.
- Expand the ActionType list in the injection branch as new MDE sensor versions document additional injection-related event types.

Risks / caveats:
- ActionType values 'ShellcodeInjection' and 'ProcessInjection' are not standard MDE DeviceEvents ActionType strings; if the deployed MDE sensor version does not emit these, the injection branch will return no results for those action types. Validated ActionType values for injection in MDE are 'CreateRemoteThreadApiCall' and 'WriteToLsassMemory'.
- If Fondue.exe is legitimately invoked during Windows Optional Features installation in the environment, child processes such as conhost.exe may generate low-volume false positives from the ChildProcess branch. Validate against historical Fondue.exe activity before scheduling.
- The injection ActionType list should be reviewed against the specific MDE sensor version deployed; additional or renamed ActionTypes may exist in newer sensor releases.

### Triage Runbook

First 15 minutes:
- Verify the Fondue.exe path and parent process; Fondue.exe should normally only appear during Windows Optional Features installation and should be launched by svchost.exe or TiWorker.exe.
- Check whether the alert is from the child-process branch or the injection branch; injection activity from Fondue.exe should be treated as highly suspicious.
- Review the initiating process command line and the child process name for signs of a document lure, unusual script execution, or a non-system path.
- Identify the user account and recent logon activity on the host to determine whether the activity aligns with a user-opening-document scenario or an automated system workflow.

Evidence to collect:
- DeviceProcessEvents for Fondue.exe, its parent, and any child processes around the alert time.
- DeviceEvents for injection-related actions such as CreateRemoteThreadApiCall, QueueUserApcRemoteApiCall, and NtAllocateVirtualMemoryApiCall.
- Process command lines, folder paths, and ReportId values to confirm execution path and correlate related telemetry.
- Any file hashes or dropped DLLs associated with the Fondue.exe execution chain.

Pivot points:
- DeviceProcessEvents for the same DeviceName and a time window before and after the alert.
- DeviceEvents filtered on the same DeviceName and InitiatingProcessFileName = fondue.exe.
- Recent file creation events for the same host to look for dropped DLLs or payloads.
- If available, correlate with email, document, or download telemetry for the user who launched the lure.

Benign explanations:
- Legitimate Windows Optional Features installation initiated by svchost.exe or TiWorker.exe.
- Rare administrative or software deployment workflows that invoke Fondue.exe from a standard system path.
- A lab or test environment intentionally reproducing the loader chain for validation.

Escalation criteria:
- Fondue.exe is launched by a document reader, browser, or other user-space process instead of a Windows servicing process.
- Fondue.exe is observed from a non-standard path or followed by injection actions.
- A suspicious child process, shellcode-like behavior, or additional malware artifacts are present on the host.
- The same user or host shows other compromise indicators such as persistence, credential access, or outbound C2 traffic.

Containment actions:
- Isolate the host from the network if Fondue.exe is confirmed to be abused or injection is observed.
- Terminate the suspicious process tree only after preserving volatile evidence if your response process allows it.
- Block or quarantine any dropped DLLs or payloads identified in the chain.
- Reset credentials for the affected user if there is evidence of interactive compromise.

Closure criteria:
- Fondue.exe execution is confirmed to be a legitimate Windows servicing workflow with a standard parent process and no injection or suspicious child activity.
- No suspicious DLLs, payloads, or follow-on processes are found on the host.
- Historical review shows the event matches an approved software deployment or maintenance pattern.
- The alert is documented with the verified benign parent-child chain and closed as false positive.

---

## Detection 2: Crypto Clipper - Non-Browser Process Initiating Tor Port Network Connections

### Detection Opportunity

Non-browser process establishing outbound network connections to Tor relay ports (9001, 9030) consistent with Tor-based C2 communications used by clipboard-hijacking crypto stealer

### Intelligence Context

- Microsoft Security Blog: Crypto Clipper uses Tor and worm-like propagation for persistence and control — [https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/](https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/)
  - Context: The campaign uses Tor-based communications for C2 control alongside clipboard wallet address replacement. Detecting non-browser processes connecting to Tor relay ports provides a compound signal combining the C2 channel with the non-standard initiating process context.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: Not specified
- Products: Not specified
- Platforms: Windows
- Malware: Not specified
- Tools: Tor
- Search tags: Tor, Windows

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Not mapped

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

Required telemetry:
- DeviceNetworkEvents, DeviceEvents

### KQL

```kql
let TorConnections = DeviceNetworkEvents
| where RemotePort in (9001, 9030)
| where InitiatingProcessFileName !in~ (
    "firefox.exe", "chrome.exe", "msedge.exe", "brave.exe",
    "tor.exe", "torbrowser.exe", "opera.exe", "iexplore.exe"
)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemotePort, RemoteIP;
let ClipboardSummary = DeviceEvents
| where ActionType in ("ClipboardRead", "SetClipboard", "GetClipboard")
| summarize ClipTimestamp = max(Timestamp), ClipProcess = any(InitiatingProcessFileName) by DeviceName;
TorConnections
| join kind=leftouter (ClipboardSummary) on DeviceName
| extend ClipboardCorrelated = iff(
    isnotnull(ClipTimestamp) and abs(datetime_diff('minute', Timestamp, ClipTimestamp)) <= 30,
    true, false
)
| where ClipboardCorrelated == true or isnull(ClipTimestamp)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemotePort, RemoteIP, ClipTimestamp, ClipProcess, ClipboardCorrelated
| order by ClipboardCorrelated desc, Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Security research tools, penetration testing frameworks, or privacy-focused applications that connect to Tor ports from non-browser processes.
- Legitimate Tor relay operators running relay software on endpoints.
- VPN or proxy clients that happen to use ports 9001 or 9030 for unrelated purposes.

Tuning notes:
- Add any additional approved browser executables to the exclusion list based on the environment's software inventory.
- Adjust the 30-minute window in the ClipboardCorrelated extend expression based on observed malware dwell patterns.
- Consider adding a RemoteIP threat intelligence lookup to further prioritize results where the destination IP is a known Tor exit node or relay.

Risks / caveats:
- Clipboard-related ActionType values in DeviceEvents ('ClipboardRead', 'SetClipboard', 'GetClipboard') are not standard documented MDE ActionType strings. If the MDE sensor does not emit these, the clipboard correlation branch will return no rows, and the leftouter join will still surface Tor connection events with null ClipTimestamp values, preserving core detection value.
- The 30-minute clipboard correlation window is a starting point; if the malware's clipboard hijacking and C2 beaconing are temporally separated by more than 30 minutes, correlated events will not be flagged as ClipboardCorrelated but will still appear with ClipboardCorrelated=false.
- The browser exclusion list may need expansion if additional approved browsers are deployed in the environment.
- Ports 9001 and 9030 are standard Tor relay ports but are not exclusively used by Tor; other applications may use these ports.

### Triage Runbook

First 15 minutes:
- Identify the initiating process and confirm whether it is expected to use Tor ports 9001 or 9030; treat unknown processes as suspicious.
- Check whether the alert is clipboard-correlated; if yes, prioritize as stronger evidence of crypto-stealer behavior.
- Review the process path and command line for Tor binaries, packed executables, or unusual parent-child chains.
- Assess whether the host is a developer workstation, privacy tool endpoint, or security research system that could legitimately use Tor.

Evidence to collect:
- DeviceNetworkEvents for the initiating process, destination IP, remote port, and connection frequency.
- DeviceEvents for clipboard-related activity on the same host and time window.
- Process command line, folder path, and parent process information for the initiating process.
- Any related file hashes, persistence artifacts, or additional suspicious network destinations.

Pivot points:
- DeviceNetworkEvents on the same DeviceName for other unusual outbound connections from the same process.
- DeviceEvents for clipboard actions and nearby process creation events on the same host.
- DeviceProcessEvents to identify the parent process and any spawned children of the initiating process.
- If available, threat intelligence or reputation checks on the RemoteIP.

Benign explanations:
- Tor Browser or approved privacy tooling running on the endpoint.
- Security research, penetration testing, or malware analysis activity.
- A legitimate relay or proxy application that happens to use ports 9001 or 9030.
- A non-malicious application with an unusual but documented use of those ports.

Escalation criteria:
- The initiating process is not an approved Tor-capable application and the host also shows clipboard manipulation or wallet-related user activity.
- The process path, command line, or parent process is suspicious or inconsistent with approved software.
- The same host shows additional indicators such as persistence, credential theft, or repeated outbound connections to multiple Tor-related endpoints.
- The user reports wallet address changes, clipboard anomalies, or unauthorized crypto activity.

Containment actions:
- Isolate the host if the process is unknown or the clipboard correlation is present and no benign explanation exists.
- Terminate the suspicious process and any child processes after evidence capture.
- Block the destination IPs if they are confirmed malicious and not required for business use.
- Reset credentials and review browser/session activity if the host is used for crypto or financial operations.

Closure criteria:
- The process is verified as an approved Tor-capable application with matching path, parent, and user intent.
- Clipboard correlation is absent or explained by legitimate software behavior.
- No additional suspicious network, process, or persistence activity is found.
- The event is documented as benign Tor usage or approved research activity.

---

## Detection 3: Dropping Elephant - Office or PDF Process Spawning Fondue.exe as Decoy Document Lure

### Detection Opportunity

Office or PDF reader process spawning Fondue.exe as a child process, consistent with a China-themed decoy document used by Dropping Elephant to initiate the DLL side-loading loader chain

### Intelligence Context

- Rapid7: Malware à la Mode: Tracking Dropping Elephant Tradecraft Through a China-Themed Loader Chain — [https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
  - Context: Dropping Elephant delivered the loader chain via a China-themed decoy document. The document caused an Office or PDF process to spawn Fondue.exe, which then performed DLL side-loading. This parent-child chain from a document reader to Fondue.exe is a specific and rarely legitimate process relationship.

### Search Metadata

- CVEs: Not specified
- Threat actors: Dropping Elephant
- ATT&CK tags: T1574.002
- Products: Fondue.exe
- Platforms: Windows
- Malware: RAT
- Tools: Donut
- Search tags: Dropping Elephant, T1574.002, Fondue.exe, Windows, RAT, Donut

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Defense Evasion: T1574.002 Hijack Execution Flow/ T1574.002 DLL Side-Loading (high)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where FileName =~ "fondue.exe"
| where InitiatingProcessFileName in~ (
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "acrord32.exe", "acrobat.exe", "foxitpdfeditor.exe", "foxitreader.exe",
    "sumatrapdf.exe", "mspub.exe", "onenote.exe", "msaccess.exe"
)
| extend NonStandardPath = iff(
    FolderPath !startswith @"C:\Windows\System32" and
    FolderPath !startswith @"C:\Windows\SysWOW64",
    true, false
)
| project Timestamp, DeviceName, AccountName, AccountDomain,
    InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
    FileName, FolderPath, ProcessCommandLine, NonStandardPath, ReportId
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Extremely unlikely given the specificity of the parent-child relationship. Potential edge case: automated document processing pipelines that invoke Windows Optional Features tooling, though this would not involve document reader processes as parents.

Tuning notes:
- Add any additional document viewer or PDF reader executables present in the environment to the InitiatingProcessFileName list.
- If the environment uses automated document processing pipelines, review InitiatingProcessCommandLine values in results to identify any legitimate automation that should be excluded.

Risks / caveats:
- If non-standard PDF readers or document processing applications are deployed in the environment that are not in the parent process list, those spawn paths will not be detected. Validate the parent process list against the environment's software inventory.
- Fondue.exe running from its standard System32 path spawned by a document reader is still malicious; the NonStandardPath flag is additive context, not a filter.

### Triage Runbook

First 15 minutes:
- Treat any Office or PDF process spawning Fondue.exe as suspicious and verify the parent process name and path immediately.
- Check the initiating process command line for the document path or lure file that triggered the spawn.
- Determine whether the user recently opened a document, especially one with a China-themed or unexpected attachment source.
- Look for follow-on child processes, unusual DLL loads, or injection activity from Fondue.exe on the same host.

Evidence to collect:
- DeviceProcessEvents showing the parent process, Fondue.exe execution, and any child processes.
- InitiatingProcessCommandLine and InitiatingProcessFolderPath to identify the source document and parent binary location.
- AccountName and AccountDomain to identify the user involved.
- Any related file hashes, downloaded documents, or dropped payloads from the same time window.

Pivot points:
- DeviceProcessEvents for the same DeviceName and user around the alert time.
- Recent file download or email attachment telemetry for the triggering document if available.
- DeviceEvents for injection-related actions initiated by Fondue.exe.
- Search for other hosts where the same document name, sender, or hash appears.

Benign explanations:
- Extremely unlikely; this parent-child relationship is generally not expected in normal operations.
- A controlled security test or malware simulation in a lab environment.
- An automated document-processing workflow that is explicitly approved and documented, though this should still be validated carefully.

Escalation criteria:
- Any Office or PDF reader is confirmed as the parent of Fondue.exe outside a known test environment.
- Fondue.exe is followed by injection, suspicious child processes, or a non-standard execution path.
- The triggering document is suspicious, externally sourced, or associated with other malicious activity.
- Additional hosts show the same lure or related payload behavior.

Containment actions:
- Isolate the host immediately if the parent-child chain is confirmed and not part of an approved test.
- Quarantine the lure document and any related attachments or downloads.
- Terminate the process tree after preserving evidence if your response process supports it.
- Reset the affected user’s credentials if there is evidence of interactive compromise.

Closure criteria:
- The event is confirmed to be a sanctioned security test or lab reproduction.
- No follow-on malicious activity, injection, or payload execution is found.
- The document source and process chain are fully explained and approved by the business owner.
- The alert is documented and closed as a validated test or rare but benign automation only if independently verified.

---

## Detection 4: npm Supply Chain - Node.exe Dropping Executables or Scripts to Hidden or Temp Paths During Package Install

### Detection Opportunity

node.exe or npm writing executable or script files to hidden or temporary directories during package installation, consistent with the hidden postinstall payload delivery observed in the Mastra npm supply chain compromise

### Intelligence Context

- Microsoft Security Blog: From package to postinstall payload: Inside the Mastra npm supply chain compromise — [https://www.microsoft.com/en-us/security/blog/2026/06/17/postinstall-payload-inside-mastra-npm-supply-chain-compromise/](https://www.microsoft.com/en-us/security/blog/2026/06/17/postinstall-payload-inside-mastra-npm-supply-chain-compromise/)
  - Context: A poisoned npm package infected 140+ downstream projects by executing a hidden postinstall payload. The payload was dropped to disk during package installation by node.exe or npm. Detecting executables or scripts written to temp or hidden paths by these processes during install phases identifies the delivery mechanism directly.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: Not specified
- Products: npm, Mastra
- Platforms: developer endpoints, CI/CD
- Malware: Not specified
- Tools: Not specified
- Search tags: npm, Mastra, developer endpoints, CI/CD

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Not mapped

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceFileEvents

### KQL

```kql
DeviceFileEvents
| where InitiatingProcessFileName in~ ("node.exe", "npm.exe", "npx.cmd", "npx.exe")
| where ActionType in ("FileCreated", "FileModified")
| where FileName matches regex @"(?i)\.(exe|dll|bat|ps1|sh|py|vbs|cmd)$"
| where FolderPath matches regex @"(?i)(\\temp\\|\\tmp\\|\/tmp\/|\/var\/tmp\/|\\AppData\\Local\\Temp\\|\\AppData\\Roaming\\)"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
    FileName, FolderPath, ActionType, SHA256
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate npm packages that use postinstall scripts to compile native modules and write intermediate binaries to temp directories.
- Build toolchains such as electron-builder, pkg, or nexe that bundle node.exe applications and write executables to temp paths.
- CI/CD pipeline steps that use npm to install and execute build tools that write scripts to workspace temp directories.

Tuning notes:
- Run over a 7-day historical window on developer endpoints to establish baseline volume before considering promotion to scheduled rule.
- Add SHA256 lookups against available threat intelligence feeds to prioritize results.
- Restrict FolderPath regex to AppData\Roaming and system temp paths if node_modules/.bin writes generate excessive noise.
- Consider adding a filter to exclude FolderPath values containing 'node_modules' if legitimate package compilation generates high volume.

Risks / caveats:
- DeviceFileEvents InitiatingProcessFileName may not reliably capture 'npm.cmd' as a distinct process name on Windows; npm.cmd is a batch wrapper that invokes node.exe, so the actual initiating process visible in MDE telemetry is typically node.exe. Relying on 'npm.cmd' as an InitiatingProcessFileName may produce no results.
- High expected false positive volume on developer endpoints and CI/CD runners where legitimate npm postinstall scripts write to temp paths. A 7-day baseline run is recommended before any alerting use.
- The detection does not distinguish between malicious and legitimate postinstall scripts without SHA256 threat intelligence enrichment or behavioral follow-on analysis.
- npm.cmd as an initiating process is excluded because MDE typically records node.exe as the actual process; if the environment's MDE telemetry captures npm.cmd directly, it can be re-added.

### Triage Runbook

First 15 minutes:
- Identify the initiating process and command line to confirm whether the activity occurred during a package install, build, or CI job.
- Review the file name, extension, and destination path to see whether the write is a normal temporary artifact or a suspicious executable/script drop.
- Check whether the host is a developer endpoint or CI/CD runner and whether the activity matches the expected project workflow.
- Look for immediate execution of the dropped file or any subsequent network activity from the same process tree.

Evidence to collect:
- DeviceFileEvents for the created or modified file, including SHA256 and FolderPath.
- InitiatingProcessCommandLine to capture the npm, node, or npx context.
- DeviceProcessEvents for the same host to see whether the dropped file was executed.
- Any package-lock, install logs, or build pipeline context available from the endpoint or CI system.

Pivot points:
- DeviceFileEvents on the same DeviceName for other files written by node.exe, npm.exe, or npx.
- DeviceProcessEvents for child processes spawned after the install activity.
- Threat intelligence or hash reputation checks for any SHA256 values observed.
- If available, CI/CD job logs or developer activity records for the same time window.

Benign explanations:
- Legitimate npm postinstall scripts that compile native modules or stage build artifacts.
- Build tools such as electron-builder, pkg, or nexe writing temporary executables.
- CI/CD pipeline steps that create scripts or binaries in workspace temp directories.
- Developer workflows that unpack dependencies into AppData or temp locations.

Escalation criteria:
- The dropped file is executable or script content and is later executed by the same or another process.
- The SHA256 is known malicious or the file path and command line are inconsistent with the expected build.
- The activity occurs on a non-developer endpoint or outside an approved CI/CD context.
- Additional indicators such as persistence, outbound C2, or credential theft appear on the host.

Containment actions:
- If malicious execution is confirmed, isolate the endpoint or runner to prevent further spread.
- Quarantine the dropped file and any related package artifacts.
- Block the package source or repository if the compromise is tied to a specific dependency and your process allows it.
- Rotate credentials or tokens used by the affected build environment if there is evidence of supply-chain compromise.

Closure criteria:
- The file write is matched to a known legitimate build or install workflow.
- The SHA256 and command line are consistent with approved package behavior and no execution follows.
- The activity is confined to expected developer or CI/CD systems with no additional suspicious telemetry.
- The alert is documented as benign build activity after validation against the project workflow.

---

## Detection 5: Coordinated Distributed SSH Brute-Force - High Volume Failed Logons from Multiple Source IPs Against Single Host

### Detection Opportunity

High count of SSH authentication failures originating from multiple distinct source IP addresses targeting a single Linux host within a short time window, consistent with coordinated distributed brute-force campaigns observed over a three-month tracking period

### Intelligence Context

- SANS ISC: The Behavior of Coordinated SSH Brute Force Attacks over the last three months [Guest Diary], (Wed, Jun 17th) — [https://isc.sans.edu/diary/rss/33086](https://isc.sans.edu/diary/rss/33086)
  - Context: SANS ISC documented coordinated SSH brute-force campaigns using distributed source IPs to evade per-source thresholds. The key distinguishing characteristic is many distinct source IPs targeting the same host in a compressed timeframe, which is detectable via aggregation across source IPs rather than per-IP thresholds.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1110
- Products: SSH
- Platforms: Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: SSH, Linux, T1110

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1110 Brute Force (high)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- Syslog

### KQL

```kql
let WindowMinutes = 10;
let DistinctIPThreshold = 10;
let FailedSSHSyslog = Syslog
| where (Facility == "auth" or SyslogMessage has "sshd")
| where SyslogMessage has_any ("Failed password", "Invalid user", "authentication failure")
| extend SourceIP = extract(@"from ([\d\.a-fA-F:]+)", 1, SyslogMessage)
| extend TargetUser = extract(@"(?:for|user) (\S+) from", 1, SyslogMessage)
| where isnotempty(SourceIP)
| project TimeGenerated, Computer, SourceIP, TargetUser, SyslogMessage;
FailedSSHSyslog
| summarize
    DistinctSourceIPs = dcount(SourceIP),
    TotalFailures = count(),
    SourceIPList = make_set(SourceIP, 20),
    SampleUsernames = make_set(TargetUser, 10)
    by Computer, bin(TimeGenerated, totimespan(strcat(tostring(WindowMinutes), "m")))
| where DistinctSourceIPs >= DistinctIPThreshold
| project TimeGenerated, Computer, DistinctSourceIPs, TotalFailures, SourceIPList, SampleUsernames
| order by DistinctSourceIPs desc, TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Internet-exposed SSH hosts will generate high baseline noise from opportunistic distributed scanners that are not targeted campaigns. The DistinctIPThreshold should be raised for such hosts.
- Honeypot or canary SSH hosts intentionally exposed to the internet will trigger this detection continuously.

Tuning notes:
- Increase DistinctIPThreshold to 25 or higher for internet-exposed SSH hosts to reduce noise from opportunistic distributed scanners.
- Reduce WindowMinutes to 5 for higher-sensitivity detection of fast distributed campaigns, or increase to 30 for slower low-and-slow campaigns.
- Consider adding a lookup against known scanner IP ranges or threat intelligence watchlists to enrich SourceIPList entries.
- If the bin() totimespan expression causes issues in the workspace, replace with the hardcoded literal: bin(TimeGenerated, 10m).

Risks / caveats:
- Syslog data from Linux SSH hosts must be forwarded to the Microsoft Sentinel workspace with the 'auth' facility configured in the AMA Syslog data source or legacy Log Analytics agent Syslog configuration. If this forwarding is not configured, the query will return no results.
- The DistinctIPThreshold of 10 is a starting point; internet-exposed SSH hosts may require a significantly higher threshold to avoid alert fatigue from opportunistic scanners.
- The SourceIP regex extracts the first IP-like string after 'from' in the sshd message; non-standard sshd log formats or custom log prefixes may cause extraction failures, resulting in rows being dropped by the isnotempty(SourceIP) filter.
- The bin() timespan expression using totimespan(strcat()) is valid KQL but should be validated against the workspace's Sentinel version if issues arise; a direct literal such as bin(TimeGenerated, 10m) can be substituted with WindowMinutes hardcoded.

### Triage Runbook

First 15 minutes:
- Confirm the target host is internet-facing or otherwise reachable from the source IPs and determine whether the failures are ongoing.
- Check whether any successful SSH logons occurred before or after the failure burst for the same host or usernames.
- Identify the targeted usernames from the sample usernames and determine whether they are privileged, service, or default accounts.
- Assess whether the host is a production server, bastion, or honeypot, since that changes the expected baseline and response urgency.

Evidence to collect:
- Syslog messages for the same host around the alert window, including failed and successful SSH logons.
- Source IP list and any available geolocation or reputation data for the attacking addresses.
- Target usernames and any corresponding account lockout or authentication logs.
- Host exposure details such as public IP, firewall rules, and whether SSH is intended to be internet-accessible.

Pivot points:
- Syslog on the same Computer for successful logons, password changes, or sudo activity around the alert time.
- Authentication or identity logs for the targeted usernames if the host is integrated with centralized auth.
- Network telemetry or firewall logs to see whether the source IPs are still attempting connections.
- Historical Syslog baselines for the same host to compare normal SSH failure volume and source diversity.

Benign explanations:
- Internet-exposed SSH servers commonly receive opportunistic distributed scanning and brute-force noise.
- Honeypots or canary systems are expected to trigger this detection repeatedly.
- Administrative testing or vulnerability assessment activity from multiple approved scanners.
- A misconfigured automation system repeatedly attempting SSH with invalid credentials from multiple nodes.

Escalation criteria:
- Any successful SSH login is observed during or shortly after the failure burst.
- The targeted account is privileged, shared, or service-related and the host is production.
- The source IPs are associated with known malicious infrastructure or the activity is sustained and coordinated.
- There are signs of post-authentication activity such as new users, sudo usage, persistence, or file changes.

Containment actions:
- Temporarily restrict SSH exposure at the firewall or security group if the host is not required to be internet-accessible.
- Disable or lock targeted accounts if there is evidence of successful compromise or repeated targeting of privileged accounts.
- Increase rate limiting, MFA, or key-based authentication enforcement where possible.
- Isolate the host if successful access or post-authentication activity is confirmed.

Closure criteria:
- No successful logons or post-authentication activity are found and the event matches expected internet noise or approved scanning.
- The host is a honeypot, canary, or intentionally exposed system and the alert aligns with its purpose.
- The source IPs are confirmed to be benign scanners or internal assessment tools.
- The alert is documented with the observed baseline and any tuning changes needed for the host class.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Other deployment dependency:
- Dropping Elephant - Fondue.exe DLL Side-Loading with Child Process or Injection Activity: Defender for Endpoint file-event coverage must be confirmed on the target host population.
- Crypto Clipper - Non-Browser Process Initiating Tor Port Network Connections: Defender for Endpoint file-event coverage must be confirmed on the target host population.

Schema / correlation keys:
- npm Supply Chain - Node.exe Dropping Executables or Scripts to Hidden or Temp Paths During Package Install: Do not schedule yet; validate as an analyst-led hunt first.

Shared-table notes:
- DeviceProcessEvents: shared by Dropping Elephant - Fondue.exe DLL Side-Loading with Child Process or Injection Activity; Dropping Elephant - Office or PDF Process Spawning Fondue.exe as Decoy Document Lure
- DeviceEvents: shared by Dropping Elephant - Fondue.exe DLL Side-Loading with Child Process or Injection Activity; Crypto Clipper - Non-Browser Process Initiating Tor Port Network Connections

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Dropping Elephant - Fondue.exe DLL Side-Loading with Child Process or Injection Activity; Crypto Clipper - Non-Browser Process Initiating Tor Port Network Connections; Dropping Elephant - Office or PDF Process Spawning Fondue.exe as Decoy Document Lure; Coordinated Distributed SSH Brute-Force - High Volume Failed Logons from Multiple Source IPs Against Single Host.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: npm Supply Chain - Node.exe Dropping Executables or Scripts to Hidden or Temp Paths During Package Install.

### Hunting Agenda and Promotion Criteria

- npm Supply Chain - Node.exe Dropping Executables or Scripts to Hidden or Temp Paths During Package Install: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
