---
layout: post
title: "Detection Engineering Brief - Monday, August 31, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-08-31
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Windows
  - CVE-2026-81578
  - CVE-2026-82078
  - T1190
  - PaperCut NG
  - PaperCut MF
  - Linux
  - Microsoft Teams
  - ValleyRAT
  - T1095
  - T1071
  - T1071.001
  - T1059
  - T1059.001
  - T1204
  - T1204.002
  - T1547
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 4 hunting-only, 0 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Windows, CVE-2026-81578, CVE-2026-82078, T1190, PaperCut NG, PaperCut MF, Linux, Microsoft Teams, ValleyRAT, T1095, T1071, T1071.001, T1059, T1059.001, T1204, T1204.002, T1547.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: TerminalFix - DLL Sideloading via Unsigned DLL Loaded by Signed Binary from Writable Path; TerminalFix - Persistent Outbound Connection Establishing Reverse Tunnel from Non-Browser Process; Spring Ring - Suspicious Process Execution Spawned Shortly After Microsoft Teams Activity; ValleyRAT - Installer Process Dropping Executable to Writable Path Followed by Outbound Connection.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: TerminalFix - DLL Sideloading via Unsigned DLL Loaded by Signed Binary from Writable Path

### Detection Opportunity

Signed binary loads an unsigned DLL from a user-writable path, consistent with DLL sideloading used in the TerminalFix multistage intrusion campaign.

### Intelligence Context

- Microsoft Security Blog: TerminalFix campaign deploys a reverse tunnel through multistage intrusion — [https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/)
  - Context: The TerminalFix campaign explicitly uses DLL sideloading as part of its multistage intrusion chain. Signed binaries loading unsigned DLLs from user-writable directories such as AppData or Temp are a reliable artifact of this technique.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1095, T1071, T1071.001
- Products: Not specified
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Windows, T1095, T1071, T1071.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Command and Control: T1095 Non-Application Layer Protocol (medium); Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- DeviceImageLoadEvents requires Microsoft Defender for Endpoint Plan 2 or equivalent licensing with image load telemetry enabled; availability must be confirmed before running.

**Required telemetry:**
- DeviceImageLoadEvents, DeviceProcessEvents

### KQL

```kql
let LookbackWindow = 7d;
let WritablePaths = dynamic(["\\AppData\\", "\\Temp\\", "\\ProgramData\\"]);
let ExcludedParents = dynamic(["svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "smss.exe"]);
let SignedLoaders = DeviceProcessEvents
| where Timestamp > ago(LookbackWindow)
| where InitiatingProcessIntegrityLevel in ("Medium", "High", "System")
| where InitiatingProcessFileName !in~ (ExcludedParents)
| project DeviceId, InitiatingProcessFileName, ProcessCommandLine, ProcTimestamp = Timestamp;
DeviceImageLoadEvents
| where Timestamp > ago(LookbackWindow)
| where ActionType == "ImageLoaded"
| where IsTrusted == false
| where FolderPath has_any (WritablePaths)
| where InitiatingProcessFileName !in~ (ExcludedParents)
| join kind=inner SignedLoaders on DeviceId, InitiatingProcessFileName
| where abs(datetime_diff('minute', Timestamp, ProcTimestamp)) <= 30
| project
    Timestamp,
    DeviceId,
    DeviceName,
    InitiatingProcessFileName,
    LoadedDLL = FileName,
    DLLFolderPath = FolderPath,
    SHA256,
    ProcessCommandLine
| summarize
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    LoadCount = count(),
    DLLPaths = make_set(DLLFolderPath, 20),
    SHA256s = make_set(SHA256, 20)
    by DeviceId, DeviceName, InitiatingProcessFileName, LoadedDLL, ProcessCommandLine
| order by LastSeen desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate software that ships unsigned DLLs to AppData or ProgramData during installation or update cycles.
- Developer tools and IDEs that load unsigned plugin DLLs from user profile directories.
- Electron-based applications that extract unsigned native modules to Temp or AppData at runtime.

**Tuning notes:**
- Extend WritablePaths to include additional writable directories observed in the environment such as Downloads or Public.
- Add InitiatingProcessFileName exclusions for legitimate signed applications known to load unsigned DLLs in the environment after initial review.
- Consider adding a SHA256 allowlist of known-good unsigned DLLs to reduce recurring false positives.

**Risks / caveats:**
- IsSigned is not a documented field in DeviceImageLoadEvents in Defender XDR; the correct field for trust status is IsTrusted. Queries using IsSigned will return no results or a schema error.
- DeviceImageLoadEvents requires Microsoft Defender for Endpoint Plan 2 or equivalent licensing with image load telemetry enabled; availability must be confirmed before running.
- The 30-minute join window between DeviceProcessEvents and DeviceImageLoadEvents is a heuristic; processes that run for extended periods will generate repeated matches.
- ProgramData is not exclusively user-writable; some legitimate software installs unsigned DLLs there during normal operation.

### Triage Runbook

**First 15 minutes:**
- Confirm the initiating signed binary, loaded DLL name, and folder path; prioritize cases where the DLL is in AppData, Temp, ProgramData, Downloads, or Public.
- Check whether the signed loader is a known application, installer, or updater on this endpoint and whether the DLL hash is expected for that software.
- Review the process command line and parent process chain to see how the loader was launched and whether the activity aligns with user action or software installation.
- Look for nearby signs of follow-on activity on the same host such as new outbound connections, additional child processes, or repeated DLL loads from the same writable directory.

**Evidence to collect:**
- DeviceName, DeviceId, Timestamp, InitiatingProcessFileName, FileName, FolderPath, SHA256, ProcessCommandLine.
- Signer/trust details for the loader and any available file reputation or hash intelligence for the DLL.
- Process tree around the event, including parent process and any child processes spawned by the loader.
- Any related network activity from the same process or host within the same time window.

**Pivot points:**
- DeviceImageLoadEvents for other unsigned DLL loads from the same host or same initiating process.
- DeviceProcessEvents for the loader process, its parent, and any child processes around the event time.
- DeviceNetworkEvents for outbound connections from the same initiating process or host after the DLL load.
- File reputation or threat intelligence lookup using the DLL SHA256.

**Benign explanations:**
- Legitimate software installers or updaters that stage unsigned DLLs in user-writable directories.
- Developer tools, plugins, or Electron-based applications that extract native modules to AppData or Temp.
- Known enterprise applications that ship unsigned helper DLLs during installation or first-run setup.

**Escalation criteria:**
- The DLL hash is unknown or malicious, or matches known sideloading tradecraft.
- The signed loader is not an approved application for the endpoint or is executing from an unusual path.
- There is correlated outbound C2-like traffic, suspicious child processes, or repeated loads from the same writable directory.
- Multiple hosts show the same loader/DLL pair or the same DLL hash appears across endpoints.

**Containment actions:**
- If maliciousness is confirmed or strongly suspected, isolate the host from the network.
- Terminate the suspicious loader and any related child processes if they are still active.
- Quarantine or collect the unsigned DLL and the signed loader for analysis.
- Block the DLL hash and any confirmed related hashes across the environment.

**Closure criteria:**
- The loader and DLL are confirmed as approved software behavior and the hash is known-good.
- No related suspicious process, network, or persistence activity is found on the host.
- The event is documented as an allowlisted application or known installer pattern with supporting evidence.

<br/>
---
<br/>

## Detection 2: TerminalFix - Persistent Outbound Connection Establishing Reverse Tunnel from Non-Browser Process

### Detection Opportunity

Non-browser process establishes a persistent outbound network connection consistent with reverse tunnel establishment observed in the TerminalFix campaign.

### Intelligence Context

- Microsoft Security Blog: TerminalFix campaign deploys a reverse tunnel through multistage intrusion — [https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/)
  - Context: The TerminalFix campaign establishes a reverse tunnel as a core post-exploitation capability. Reverse tunnels produce persistent outbound connections from unexpected non-browser processes, often on ports 443 or 80 to blend with legitimate traffic.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1095, T1071, T1071.001
- Products: Not specified
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Windows, T1095, T1071, T1071.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1095 Non-Application Layer Protocol (medium); Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents, DeviceProcessEvents

### KQL

```kql
let LookbackWindow = 1d;
let BrowserProcesses = dynamic(["chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe", "brave.exe", "safari.exe"]);
let SystemProcesses = dynamic(["svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "smss.exe", "csrss.exe", "winlogon.exe"]);
let TunnelPorts = dynamic([80, 443, 8080, 8443]);
let FrequentConnectors = DeviceNetworkEvents
| where Timestamp > ago(LookbackWindow)
| where ActionType == "ConnectionSuccess"
| where RemotePort in (TunnelPorts)
| where InitiatingProcessFileName !in~ (BrowserProcesses)
| where InitiatingProcessFileName !in~ (SystemProcesses)
| where RemoteIPType == "Public"
| summarize
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceId, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| extend DurationMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| where ConnectionCount >= 10 and DurationMinutes <= 60 and DurationMinutes >= 1;
FrequentConnectors
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(LookbackWindow)
    | project DeviceId, InitiatingProcessFileName, ProcessCommandLine, ProcTimestamp = Timestamp
) on DeviceId, InitiatingProcessFileName
| where ProcTimestamp <= LastSeen and ProcTimestamp >= (FirstSeen - 10m)
| summarize
    ProcessCommandLine = take_any(ProcessCommandLine),
    ConnectionCount = take_any(ConnectionCount),
    FirstSeen = take_any(FirstSeen),
    LastSeen = take_any(LastSeen),
    DurationMinutes = take_any(DurationMinutes)
    by DeviceId, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| project
    DeviceName,
    DeviceId,
    InitiatingProcessFileName,
    RemoteIP,
    RemotePort,
    ConnectionCount,
    DurationMinutes,
    FirstSeen,
    LastSeen,
    ProcessCommandLine
| order by ConnectionCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Endpoint agents, telemetry collectors, and backup clients that make frequent outbound connections to fixed remote IPs on port 443.
- VPN or remote access clients that maintain persistent connections to gateway IPs.
- Update services and cloud sync clients with high-frequency heartbeat connections.
- Custom line-of-business applications with persistent polling connections to cloud APIs.

**Tuning notes:**
- If RemoteIPType is not available, replace the RemoteIPType == 'Public' filter with: → where not(ipv4_is_private(RemoteIP)).
- Expand BrowserProcesses and SystemProcesses lists based on the software inventory in the environment.
- Add a destination IP or domain allowlist for known legitimate high-frequency outbound services after initial review.
- Increase ConnectionCount threshold if legitimate agents in the environment exceed 10 connections per 60 minutes to fixed IPs.

**Risks / caveats:**
- ActionType value ConnectionSuccess must be confirmed as present in the environment's DeviceNetworkEvents; some tenants may only have ConnectionAttempt or ConnectionFound depending on sensor version.
- RemoteIPType field availability should be confirmed; if not present in the environment, the public IP filter must be removed and replaced with an explicit RFC1918 exclusion using ipv4_is_private().
- The ConnectionCount threshold of 10 in 60 minutes is a starting heuristic and will require adjustment based on observed baseline outbound connection rates for non-browser processes in the environment.
- The process join window of 10 minutes before FirstSeen may miss processes that were started significantly earlier and are long-running tunnel processes.

### Triage Runbook

**First 15 minutes:**
- Identify the initiating process, remote IP, remote port, and connection count; treat repeated connections to a single public IP on 80/443/8080/8443 as suspicious until explained.
- Check whether the process is a known browser, VPN client, endpoint agent, backup tool, or cloud sync client; if not, treat as higher risk.
- Review the process command line, parent process, and creation time to understand how the process started and whether it matches user or software activity.
- Look for concurrent signs of compromise on the host such as DLL sideloading, suspicious child processes, or recent credential or script activity.

**Evidence to collect:**
- DeviceName, DeviceId, InitiatingProcessFileName, RemoteIP, RemotePort, ConnectionCount, FirstSeen, LastSeen, DurationMinutes, ProcessCommandLine.
- Process tree and signer information for the initiating process.
- Any related DeviceNetworkEvents showing the same process talking to the same IP or additional suspicious destinations.
- Host context such as logged-on user, recent software installs, and whether the destination IP is known or newly observed.

**Pivot points:**
- DeviceNetworkEvents for all connections from the same process, host, or remote IP in the last 24 hours.
- DeviceProcessEvents for the initiating process and any child processes around the first observed connection.
- DeviceImageLoadEvents for unsigned DLL loads or other suspicious activity on the same host.
- Threat intelligence or proxy logs for the remote IP and any associated domains if available.

**Benign explanations:**
- VPN, remote access, telemetry, or backup agents that maintain persistent connections to fixed public IPs.
- Legitimate line-of-business applications that poll cloud APIs at high frequency.
- Endpoint management or update services that use 443 or 80 for long-lived sessions.

**Escalation criteria:**
- The process is unknown, unsigned, or not approved for persistent outbound connectivity.
- The remote IP is unrecognized, newly registered, or associated with other suspicious hosts.
- The connection pattern is consistent with tunnel keepalive behavior and there is no legitimate business explanation.
- Additional host activity suggests post-exploitation behavior, such as script execution, DLL sideloading, or credential access.

**Containment actions:**
- If the connection is confirmed malicious, isolate the host from the network.
- Terminate the suspicious process and any related child processes.
- Block the remote IP or domain at the proxy/firewall if it is confirmed malicious.
- Collect process memory and network artifacts if your IR process supports it before rebooting the host.

**Closure criteria:**
- The process is identified as a legitimate approved agent or application with documented behavior.
- The destination is a known business service and the connection pattern matches baseline.
- No additional suspicious host activity is found and the event is recorded as benign or allowlisted.

<br/>
---
<br/>

## Detection 3: PaperCut Exploitation - Anomalous Child Process Spawned from PaperCut Service

### Detection Opportunity

PaperCut NG/MF service process spawns an unexpected child process, consistent with post-exploitation activity following active exploitation of CVE-2026-81578 or CVE-2026-82078.

### Intelligence Context

- Rapid7: PaperCut NG/MF Critical Zero-Day Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild)
  - Context: Rapid7 confirmed active exploitation of critical vulnerabilities in PaperCut NG and MF with vendor-confirmed customer incidents. Post-exploitation child process spawning from the PaperCut service is a reliable indicator of successful exploitation of internet-facing print management software.

### Search Metadata

- CVEs: CVE-2026-81578, CVE-2026-82078
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059, T1059.001
- Products: PaperCut NG, PaperCut MF
- Platforms: Windows, Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-81578, CVE-2026-82078, T1190, PaperCut NG, PaperCut MF, Windows, Linux, T1059, T1059.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter/ T1059.001 PowerShell (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let LookbackWindow = 1d;
let SuspiciousChildProcs = dynamic(["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe", "net.exe", "net1.exe", "whoami.exe", "nltest.exe", "bitsadmin.exe", "curl.exe", "wget.exe"]);
let PaperCutParents = dynamic(["pc-app.exe", "pc-pdl-to-image.exe", "pc-print-deploy-client.exe"]);
let ChildProcs = DeviceProcessEvents
| where Timestamp > ago(LookbackWindow)
| where InitiatingProcessFileName has_any (PaperCutParents)
| where FileName in~ (SuspiciousChildProcs)
| project
    DeviceId,
    DeviceName,
    SpawnTimestamp = Timestamp,
    PaperCutParent = InitiatingProcessFileName,
    ChildProcess = FileName,
    ProcessCommandLine,
    AccountName,
    AccountDomain;
ChildProcs
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp > ago(LookbackWindow)
    | where ActionType == "ConnectionSuccess"
    | project
        DeviceId,
        NetTimestamp = Timestamp,
        RemoteIP,
        RemotePort,
        NetInitiatingProcess = InitiatingProcessFileName
) on DeviceId
| where isempty(NetTimestamp) or NetTimestamp between (SpawnTimestamp .. (SpawnTimestamp + 5m))
| project
    DeviceName,
    DeviceId,
    SpawnTimestamp,
    PaperCutParent,
    ChildProcess,
    ProcessCommandLine,
    AccountName,
    AccountDomain,
    RemoteIP,
    RemotePort
| order by SpawnTimestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate PaperCut administrative scripts that invoke cmd.exe or powershell.exe for maintenance tasks.
- Automated PaperCut health check or monitoring integrations that spawn net.exe or whoami.exe.
- Software update processes initiated by the PaperCut service that invoke msiexec.exe or certutil.exe.

**Tuning notes:**
- Add InitiatingProcessFolderPath has_any with the PaperCut installation directory paths observed in the environment to prevent false matches on unrelated processes named pc-app.exe.
- Expand PaperCutParents to include additional PaperCut service executable names if non-default installations are present.
- Build a ProcessCommandLine exclusion list for known-good PaperCut administrative commands after reviewing initial results.
- For Linux PaperCut deployments, a separate query targeting the Linux PaperCut service process name is required.

**Risks / caveats:**
- The PaperCut service executable name on Linux deployments is not pc-app.exe; Linux process names differ and DeviceProcessEvents coverage for Linux endpoints requires Defender for Endpoint Linux agent deployment.
- ActionType value ConnectionSuccess must be confirmed as present in DeviceNetworkEvents for the monitored tenant; some sensor versions emit ConnectionAttempt instead.
- The PaperCut parent process name list is based on Windows executable names; Linux deployments use different process names and will not be detected by this query without modification.
- The 5-minute network correlation window may miss delayed C2 connections initiated by the child process after an initial sleep or jitter period.

### Triage Runbook

**First 15 minutes:**
- Confirm the PaperCut parent process name, child process name, and command line; prioritize cmd.exe, powershell.exe, wscript.exe, cscript.exe, mshta.exe, certutil.exe, net.exe, and curl.exe.
- Check whether the PaperCut server is internet-facing and whether the event occurred on a known PaperCut NG/MF host.
- Review the child process command line for download, execution, discovery, or credential-related activity and note any remote IPs contacted shortly after spawn.
- Validate whether the child process is expected for PaperCut administration on this host and whether the account context matches a known admin workflow.

**Evidence to collect:**
- DeviceName, DeviceId, Timestamp, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName, AccountDomain, RemoteIP, RemotePort.
- PaperCut installation path and parent process folder path if available.
- Process tree for the PaperCut service and the spawned child process.
- Any network events within 5 minutes of the child process start, especially to public IPs.

**Pivot points:**
- DeviceProcessEvents for additional child processes spawned by the PaperCut service on the same host.
- DeviceNetworkEvents for outbound connections from the child process or the PaperCut service.
- DeviceProcessEvents across other PaperCut servers for the same child process pattern.
- Vulnerability management or asset inventory data to confirm PaperCut version and exposure.

**Benign explanations:**
- Legitimate PaperCut administrative scripts that use cmd.exe or powershell.exe.
- Monitoring or health-check integrations that invoke net.exe or whoami.exe.
- Software update or maintenance tasks initiated by the PaperCut service.

**Escalation criteria:**
- The child process is a known post-exploitation tool or shows suspicious command-line content.
- The PaperCut host is internet-facing and the activity is not an approved admin workflow.
- There are outbound connections, additional suspicious processes, or evidence of lateral movement after the spawn.
- Multiple PaperCut servers show the same pattern or the host is running a vulnerable version.

**Containment actions:**
- If exploitation is suspected, isolate the PaperCut server from the network.
- Stop the suspicious child process and preserve the PaperCut service state for investigation.
- Disable external access to the PaperCut service until patching and validation are complete.
- Engage vulnerability management and IR to patch or rebuild the server as needed.

**Closure criteria:**
- The child process is confirmed as an approved administrative action with matching command line and account context.
- The PaperCut host is not vulnerable or not exposed, and no follow-on suspicious activity is present.
- The event is documented with a known-good admin exception or maintenance window.

<br/>
---
<br/>

## Detection 4: Spring Ring - Suspicious Process Execution Spawned Shortly After Microsoft Teams Activity

### Detection Opportunity

Suspicious interpreter or script host process spawned on a host shortly after Microsoft Teams activity, consistent with malware deployment following Teams-based voice phishing observed in the Spring Ring campaign.

### Intelligence Context

- Unit 42: Spring Ring: An Inside Look at Voice Phishing Campaigns in Microsoft Teams — [https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/](https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/)
  - Context: The Spring Ring campaign abuses Microsoft Teams voice phishing to socially engineer victims into executing malware. The post-social-engineering execution of script interpreters or loaders on the same host where Teams is active is the primary detectable artifact of this campaign.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1204, T1204.002
- Products: Microsoft Teams
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Microsoft Teams, Windows, T1059, T1204, T1204.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (medium); Execution: T1204 User Execution/ T1204.002 Malicious File (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let LookbackWindow = 7d;
let CorrelationWindowMinutes = 10;
let SuspiciousProcs = dynamic(["powershell.exe", "mshta.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe", "cmd.exe"]);
let ExcludedParents = dynamic(["svchost.exe", "services.exe", "msiexec.exe", "Teams.exe", "ms-teams.exe", "wininit.exe", "smss.exe"]);
let TeamsActivity = DeviceProcessEvents
| where Timestamp > ago(LookbackWindow)
| where FileName in~ ("Teams.exe", "ms-teams.exe")
| summarize TeamsTimestamp = max(Timestamp) by DeviceId;
DeviceProcessEvents
| where Timestamp > ago(LookbackWindow)
| where FileName in~ (SuspiciousProcs)
| where InitiatingProcessFileName !in~ (ExcludedParents)
| join kind=inner TeamsActivity on DeviceId
| where Timestamp between (TeamsTimestamp .. (TeamsTimestamp + CorrelationWindowMinutes * 1m))
| project
    DeviceName,
    DeviceId,
    AccountName,
    AccountDomain,
    TeamsTimestamp,
    SuspiciousProcessTime = Timestamp,
    SuspiciousProcess = FileName,
    InitiatingProcessFileName,
    ProcessCommandLine
| order by SuspiciousProcessTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- IT administrators who run PowerShell or cmd.exe scripts during or shortly after Teams meetings.
- Endpoint management tools that trigger script execution on a schedule that coincides with Teams activity.
- Software update processes that invoke msiexec.exe or rundll32.exe during active Teams sessions.
- Developers who use Teams and run script interpreters as part of normal workflow.

**Tuning notes:**
- Consider filtering ProcessCommandLine for encoded commands, download cradles, or suspicious flags on powershell.exe and cmd.exe to reduce false positive volume.
- Adjust CorrelationWindowMinutes based on observed attacker dwell time between social engineering and execution if threat intelligence provides more specific timing.
- Add AccountName-based exclusions for known IT administrator accounts that routinely run scripts during Teams sessions.
- Consider extending TeamsActivity to capture all Teams timestamps per device rather than only the most recent, using a join with multiple time windows if the campaign is known to involve delayed execution.

**Risks / caveats:**
- The new Microsoft Teams client may run as ms-teams.exe rather than Teams.exe depending on the deployment version; both process names should be included to ensure coverage across Teams Classic and Teams New client deployments.
- Using max(Timestamp) for TeamsActivity means only the most recent Teams session per device is used as the correlation anchor; earlier Teams sessions within the lookback window are not evaluated.
- The correlation window of 10 minutes is a heuristic; vishing attacks may involve a longer delay between the Teams call and victim-initiated execution.
- cmd.exe is included in SuspiciousProcs but is spawned legitimately by many processes; it will be the primary source of false positives and may need to be removed or further filtered by ProcessCommandLine content.

### Triage Runbook

**First 15 minutes:**
- Confirm the Teams timestamp and the suspicious process start time; assess whether the process was launched within the correlation window after Teams activity.
- Review the suspicious process name and command line, especially for powershell.exe, cmd.exe, mshta.exe, wscript.exe, cscript.exe, rundll32.exe, regsvr32.exe, or msiexec.exe.
- Check the account context and whether the user was in a meeting, call, or chat session that could plausibly align with a vishing scenario.
- Look for signs of user-driven execution such as downloads, attachments, browser activity, or recent file creation on the same host.

**Evidence to collect:**
- DeviceName, DeviceId, AccountName, AccountDomain, TeamsTimestamp, SuspiciousProcessTime, FileName, InitiatingProcessFileName, ProcessCommandLine.
- Process tree for the suspicious process and any child processes it spawned.
- Any related file downloads, recent file writes, or browser activity around the same time.
- Endpoint alerts or network activity that indicate payload retrieval or command-and-control after execution.

**Pivot points:**
- DeviceProcessEvents for the same account or host to find additional script interpreters or loaders.
- DeviceFileEvents for recent downloads or file creations around the suspicious process time.
- DeviceNetworkEvents for outbound connections from the suspicious process or host.
- Microsoft Teams activity or audit logs if available to validate the user interaction context.

**Benign explanations:**
- IT or helpdesk staff running scripts during or after Teams meetings.
- Scheduled endpoint management or software update tasks that happen to coincide with Teams usage.
- Developer or power-user workflows where Teams is open while scripts are executed.

**Escalation criteria:**
- The process command line shows encoded commands, download cradles, or other malicious indicators.
- The user reports a suspicious Teams call, file, or instruction that preceded the execution.
- There are additional signs of compromise such as outbound C2, persistence, or credential access.
- The same pattern appears on multiple hosts or accounts, suggesting a broader campaign.

**Containment actions:**
- If malicious execution is confirmed, isolate the host from the network.
- Terminate the suspicious process and any child processes.
- Reset credentials for the affected user if there is evidence of credential theft or phishing.
- Block any confirmed malicious hashes, URLs, or IPs associated with the execution chain.

**Closure criteria:**
- The process is confirmed as a legitimate admin or user action with supporting command line and context.
- No malicious follow-on activity is found on the host or account.
- The event is documented as a benign Teams-adjacent workflow or approved maintenance activity.

<br/>
---
<br/>

## Detection 5: ValleyRAT - Installer Process Dropping Executable to Writable Path Followed by Outbound Connection

### Detection Opportunity

Installer process drops an executable to a user-writable path and subsequently initiates an outbound network connection, consistent with the ValleyRAT malicious installer delivery chain.

### Intelligence Context

- Securelist: ValleyRAT masquerading as adware — [https://securelist.com/valleyrat-backdoor-adware/121175/](https://securelist.com/valleyrat-backdoor-adware/121175/)
  - Context: ValleyRAT is distributed via a malicious installer disguised as adware. The installer drops the RAT payload to a writable path and initiates C2 connectivity. This compound behavior of file drop followed by outbound connection from an installer process is the primary detectable artifact.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1071.001, T1547
- Products: Not specified
- Platforms: Windows
- Malware: ValleyRAT
- Tools: Not specified
- Search tags: ValleyRAT, Windows, T1071, T1071.001, T1547

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (low); Persistence: T1547 Boot or Logon Autostart Execution (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents, DeviceNetworkEvents

### KQL

```kql
let LookbackWindow = 7d;
let InstallerProcs = dynamic(["setup.exe", "install.exe", "installer.exe", "msiexec.exe", "update.exe"]);
let WritablePaths = dynamic(["\\AppData\\", "\\Temp\\", "\\ProgramData\\"]);
let DroppedFiles = DeviceFileEvents
| where Timestamp > ago(LookbackWindow)
| where ActionType == "FileCreated"
| where InitiatingProcessFileName in~ (InstallerProcs)
| where FolderPath has_any (WritablePaths)
| where FileName endswith ".exe" or FileName endswith ".dll"
| project
    DeviceId,
    DeviceName,
    FileDropTime = Timestamp,
    InitiatingProcessFileName,
    DroppedFileName = FileName,
    FolderPath,
    SHA256;
DroppedFiles
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(LookbackWindow)
    | where ActionType == "ConnectionSuccess"
    | where RemoteIPType == "Public"
    | project
        DeviceId,
        NetTimestamp = Timestamp,
        RemoteIP,
        RemotePort,
        NetInitiatingProcess = InitiatingProcessFileName
) on DeviceId
| where NetInitiatingProcess =~ InitiatingProcessFileName
| where NetTimestamp between (FileDropTime .. (FileDropTime + 5m))
| summarize
    FirstNetworkConnection = min(NetTimestamp),
    RemoteIPs = make_set(RemoteIP, 10),
    RemotePorts = make_set(RemotePort, 10),
    NetworkEventCount = count()
    by DeviceId, DeviceName, FileDropTime, InitiatingProcessFileName, DroppedFileName, FolderPath, SHA256
| project
    DeviceName,
    DeviceId,
    FileDropTime,
    FirstNetworkConnection,
    InitiatingProcessFileName,
    DroppedFileName,
    FolderPath,
    SHA256,
    RemoteIPs,
    RemotePorts,
    NetworkEventCount
| order by FileDropTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate software installers that extract components to AppData and then connect to vendor update or license servers.
- Package managers and application stores that download and install components to user-writable paths.
- Enterprise software deployment tools that stage executables in Temp before installation.
- Browser extension installers that drop helper executables to AppData.

**Tuning notes:**
- If RemoteIPType is not available, replace the RemoteIPType filter with: → where not(ipv4_is_private(RemoteIP)).
- Consider removing msiexec.exe from InstallerProcs and handling it in a separate query with additional ProcessCommandLine filters to reduce noise.
- Add a SHA256 allowlist of known-good installer-dropped executables after initial review to suppress recurring false positives.
- Narrow FolderPath to the most specific writable paths observed in ValleyRAT reporting if additional intelligence becomes available.

**Risks / caveats:**
- ActionType value FileCreated must be confirmed as present in DeviceFileEvents for the monitored device population; some sensor configurations may emit FileCreated only for specific directories.
- ActionType value ConnectionSuccess must be confirmed as present in DeviceNetworkEvents; some sensor versions emit ConnectionAttempt instead.
- RemoteIPType field availability should be confirmed; if not present, replace with: → where not(ipv4_is_private(RemoteIP)) and RemoteIP != "127.0.0.1".
- The InstallerProcs list uses generic naming conventions; ValleyRAT's specific installer name is not disclosed in reporting, so the detection relies on behavioral pattern rather than specific process name matching.

### Triage Runbook

**First 15 minutes:**
- Identify the installer process, dropped file name, folder path, and SHA256; prioritize executables dropped into AppData, Temp, or ProgramData.
- Check whether the installer is expected on this endpoint and whether the file hash matches a known vendor package or internal software deployment.
- Review the remote IPs and ports contacted after the drop and determine whether they are public, newly observed, or associated with the software vendor.
- Look for additional payloads, persistence artifacts, or subsequent process launches from the dropped executable.

**Evidence to collect:**
- DeviceName, DeviceId, FileDropTime, FirstNetworkConnection, InitiatingProcessFileName, DroppedFileName, FolderPath, SHA256, RemoteIPs, RemotePorts.
- Installer command line and any available parent process information.
- File reputation results for the dropped SHA256 and any related hashes.
- Network logs showing the first outbound destination and any repeated connections from the same process.

**Pivot points:**
- DeviceFileEvents for other files dropped by the same installer or on the same host.
- DeviceNetworkEvents for all connections from the installer and the dropped executable.
- DeviceProcessEvents for execution of the dropped file or any child processes it spawns.
- Threat intelligence or sandbox results for the SHA256 and destination IPs/domains.

**Benign explanations:**
- Legitimate software installers that stage components in user-writable paths before installation.
- Package managers, application stores, or enterprise deployment tools that extract executables to Temp or AppData.
- Browser extension or application installers that contact vendor update or license servers after setup.

**Escalation criteria:**
- The dropped file hash is unknown, malicious, or matches known RAT behavior.
- The installer is not approved for the endpoint or the command line is inconsistent with a normal installation.
- The outbound destination is suspicious and there is no clear vendor or business justification.
- The dropped executable later runs, persists, or begins additional suspicious network activity.

**Containment actions:**
- If maliciousness is confirmed, isolate the host from the network.
- Quarantine the dropped executable and preserve the installer for analysis.
- Terminate the installer or dropped payload if still active.
- Block the malicious hash and any confirmed related destinations.

**Closure criteria:**
- The installer and dropped file are confirmed as approved software with matching hashes or vendor provenance.
- The outbound connection is to a known legitimate service and no other suspicious behavior is present.
- The event is documented as a benign installation or update pattern.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- TerminalFix - DLL Sideloading via Unsigned DLL Loaded by Signed Binary from Writable Path: Do not schedule yet; validate as an analyst-led hunt first.
- TerminalFix - Persistent Outbound Connection Establishing Reverse Tunnel from Non-Browser Process: Do not schedule yet; validate as an analyst-led hunt first.
- Spring Ring - Suspicious Process Execution Spawned Shortly After Microsoft Teams Activity: Do not schedule yet; validate as an analyst-led hunt first.
- ValleyRAT - Installer Process Dropping Executable to Writable Path Followed by Outbound Connection: Do not schedule yet; validate as an analyst-led hunt first.

**Licensing / identity risk fields:**
- TerminalFix - DLL Sideloading via Unsigned DLL Loaded by Signed Binary from Writable Path: DeviceImageLoadEvents requires Microsoft Defender for Endpoint Plan 2 or equivalent licensing with image load telemetry enabled; availability must be confirmed before running.

**Shared-table notes:**
- DeviceProcessEvents: shared by TerminalFix - DLL Sideloading via Unsigned DLL Loaded by Signed Binary from Writable Path; TerminalFix - Persistent Outbound Connection Establishing Reverse Tunnel from Non-Browser Process; PaperCut Exploitation - Anomalous Child Process Spawned from PaperCut Service; Spring Ring - Suspicious Process Execution Spawned Shortly After Microsoft Teams Activity
- DeviceNetworkEvents: shared by TerminalFix - Persistent Outbound Connection Establishing Reverse Tunnel from Non-Browser Process; PaperCut Exploitation - Anomalous Child Process Spawned from PaperCut Service; ValleyRAT - Installer Process Dropping Executable to Writable Path Followed by Outbound Connection

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: PaperCut Exploitation - Anomalous Child Process Spawned from PaperCut Service.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: TerminalFix - DLL Sideloading via Unsigned DLL Loaded by Signed Binary from Writable Path; TerminalFix - Persistent Outbound Connection Establishing Reverse Tunnel from Non-Browser Process; Spring Ring - Suspicious Process Execution Spawned Shortly After Microsoft Teams Activity; ValleyRAT - Installer Process Dropping Executable to Writable Path Followed by Outbound Connection.

### Hunting Agenda and Promotion Criteria

- TerminalFix - DLL Sideloading via Unsigned DLL Loaded by Signed Binary from Writable Path: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- TerminalFix - Persistent Outbound Connection Establishing Reverse Tunnel from Non-Browser Process: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Spring Ring - Suspicious Process Execution Spawned Shortly After Microsoft Teams Activity: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- ValleyRAT - Installer Process Dropping Executable to Writable Path Followed by Outbound Connection: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
