---
layout: post
title: "Detection Engineering Brief - Saturday, August 29, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-08-29
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-81578
  - CVE-2026-82078
  - T1190
  - PaperCut NG
  - PaperCut MF
  - T1090.001
  - T1090
  - T1071
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

2 production candidates, 2 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-81578, CVE-2026-82078, T1190, PaperCut NG, PaperCut MF, T1090.001, T1090, T1071.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: TerminalFix - Unsigned DLL Loaded by Legitimate Binary from User-Writable Path; TerminalFix - Outbound Reverse Tunnel Connection from Non-Browser Process to High Port; PaperCut Authentication Bypass - Unauthenticated Access to Admin Endpoints from External IP.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: TerminalFix - Unsigned DLL Loaded by Legitimate Binary from User-Writable Path

### Detection Opportunity

DLL sideloading via unsigned DLL loaded by a legitimate process from a user-writable directory during multistage intrusion

### Intelligence Context

- Microsoft Security Blog: TerminalFix campaign deploys a reverse tunnel through multistage intrusion — [https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/)
  - Context: The TerminalFix campaign uses DLL sideloading as part of a multistage intrusion chain. Unsigned DLLs loaded by legitimate binaries from user-writable directories are a reliable artifact of this technique.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1090.001, T1090
- Products: Not specified
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: T1090.001, T1090

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Command and Control: T1090 Proxy/ T1090.001 Internal Proxy (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- DeviceImageLoadEvents requires Defender for Endpoint Plan 2 or Microsoft 365 Defender with advanced hunting enabled; it is not available under all license tiers.

**Required telemetry:**
- DeviceImageLoadEvents, DeviceProcessEvents

### KQL

```kql
let userWritablePaths = dynamic(["\\AppData\\", "\\Temp\\", "\\ProgramData\\"]);
let abusedLegitBinaries = dynamic(["explorer.exe", "svchost.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe", "dllhost.exe"]);
let shellProcesses = dynamic(["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"]);
let suspiciousDllLoads = DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where ActionType == "ImageLoaded"
| where FolderPath has_any (userWritablePaths)
| where (isempty(SHA256) or SHA256 == "") and InitiatingProcessFileName in~ (abusedLegitBinaries)
| project
    DeviceName,
    DllLoadTime = Timestamp,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    DllFileName = FileName,
    DllPath = FolderPath,
    SHA256;
let followOnExec = DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ (shellProcesses)
| project
    DeviceName,
    ExecTime = Timestamp,
    SpawnedProcess = FileName,
    ProcessCommandLine,
    AccountName,
    AccountDomain;
suspiciousDllLoads
| join kind=inner followOnExec on DeviceName
| where ExecTime between (DllLoadTime .. (DllLoadTime + 2m))
| project
    DeviceName,
    DllLoadTime,
    DllFileName,
    DllPath,
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    ExecTime,
    SpawnedProcess,
    ProcessCommandLine,
    AccountName,
    AccountDomain
| order by DllLoadTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate software installers that drop and load unsigned DLLs from AppData or Temp during installation.
- Developer toolchains that load unsigned build artifacts from user-writable paths.
- Antivirus or EDR products that inject unsigned helper DLLs into monitored processes.
- Legitimate automation scripts that invoke cmd.exe or powershell.exe shortly after application startup.

**Tuning notes:**
- Extend the userWritablePaths list if the environment uses non-standard writable directories for application data.
- Adjust the 2-minute follow-on window based on observed staging patterns during threat hunting exercises.
- Add environment-specific legitimate binaries to abusedLegitBinaries exclusions after baselining.
- Consider adding a minimum DllPath depth filter to exclude root-level AppData drops from known installers.

**Risks / caveats:**
- DeviceImageLoadEvents requires Defender for Endpoint Plan 2 or Microsoft 365 Defender with advanced hunting enabled; it is not available under all license tiers.
- SHA256 field population in DeviceImageLoadEvents is not guaranteed for all DLL load events; absent SHA256 does not reliably indicate an unsigned binary and may reflect telemetry gaps rather than signing status.
- Absent SHA256 is an imprecise unsigned-DLL signal; environments with telemetry gaps will produce false positives unrelated to DLL sideloading.
- The 2-minute follow-on execution window may miss slow-staged payloads or generate false positives from coincidental shell invocations.

### Triage Runbook

**First 15 minutes:**
- Confirm the DLL path is in a user-writable location such as AppData, Temp, or ProgramData and note the initiating binary and account.
- Check whether the initiating process is a known legitimate loader for the host and whether the DLL was loaded shortly before shell or script execution.
- Review the process command line and parent process context for installer, update, or automation activity that would explain the load.
- Look for any immediate follow-on network connections, child processes, or repeated DLL loads from the same host and account.

**Evidence to collect:**
- Device name, user account, DLL file name, full DLL path, SHA256 if present, and initiating process file name/folder path.
- Process command line for the initiating process and any spawned shell or scripting process within the same time window.
- Any file reputation, signing, or prevalence data for the DLL and initiating binary.
- Nearby process creation and network events on the same host within a few minutes of the DLL load.

**Pivot points:**
- DeviceImageLoadEvents for the same DeviceName, DllPath, and InitiatingProcessFileName over the prior 24 hours.
- DeviceProcessEvents for the same DeviceName and AccountName around the DllLoadTime to identify child shells or installers.
- DeviceNetworkEvents for the same DeviceName and time window to check for outbound connections after the DLL load.
- File or reputation lookups for the DLL hash or filename if SHA256 is available.

**Benign explanations:**
- Software installers or updaters that drop unsigned helper DLLs into AppData or Temp during installation.
- Developer toolchains or build systems loading unsigned artifacts from user-writable paths.
- Security products or endpoint agents injecting helper DLLs into monitored processes.
- Legitimate automation that starts cmd.exe or powershell.exe immediately after application startup.

**Escalation criteria:**
- The DLL is unknown, unsigned, or rare in the environment and the initiating process is a commonly abused binary such as explorer.exe, svchost.exe, rundll32.exe, regsvr32.exe, msiexec.exe, or dllhost.exe.
- A shell or scripting process starts within minutes of the DLL load and the command line shows download, execution, or encoded content.
- The host shows additional suspicious network activity, persistence, or repeated DLL loads from the same writable path.
- The user account is unusual for the host or the activity occurs outside expected software installation or maintenance windows.

**Containment actions:**
- If the DLL and follow-on activity are suspicious, isolate the host from the network.
- Suspend or terminate the initiating process and any spawned shell or script processes if operationally safe.
- Preserve the DLL, parent process command line, and related telemetry before remediation.
- Reset credentials for the involved account if there is evidence of interactive compromise or credential misuse.

**Closure criteria:**
- The DLL is confirmed to be part of a known installer, updater, developer workflow, or approved security product activity.
- No suspicious follow-on execution, network activity, or persistence is found on the host.
- The DLL hash or filename is validated as benign and matches expected software provenance.
- The activity is added to an environment-specific allowlist or tuning note with supporting evidence.

<br/>
---
<br/>

## Detection 2: TerminalFix - Outbound Reverse Tunnel Connection from Non-Browser Process to High Port

### Detection Opportunity

Reverse tunnel deployment via outbound connections from non-browser processes to uncommon high ports

### Intelligence Context

- Microsoft Security Blog: TerminalFix campaign deploys a reverse tunnel through multistage intrusion — [https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/)
  - Context: The TerminalFix campaign deploys a reverse tunnel as a core capability. Reverse tunnels produce persistent outbound network connections from unusual processes to high or non-standard ports, which is detectable via process-to-network correlation.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1090.001, T1090
- Products: Not specified
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: T1090.001, T1090

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1090 Proxy/ T1090.001 Internal Proxy (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents, DeviceProcessEvents

### KQL

```kql
let knownBrowsers = dynamic(["chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe", "brave.exe"]);
let knownUpdaters = dynamic(["MsMpEng.exe", "svchost.exe", "wuauclt.exe", "OneDrive.exe", "Teams.exe", "outlook.exe"]);
let commonPorts = dynamic([80, 443, 8080, 8443, 53, 25, 587, 993, 995, 22, 3389]);
let suspiciousConnections = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| where RemotePort !in (commonPorts)
| where RemotePort > 1024
| where not(InitiatingProcessFileName in~ (knownBrowsers))
| where not(InitiatingProcessFileName in~ (knownUpdaters))
| where not(RemoteIP in ("127.0.0.1", "::1"))
| project
    DeviceName,
    ConnTime = Timestamp,
    InitiatingProcessFileName,
    RemoteIP,
    RemotePort;
let recentProcesses = DeviceProcessEvents
| where Timestamp > ago(7d)
| project
    DeviceName,
    ProcTime = Timestamp,
    FileName,
    ProcessCommandLine,
    AccountName,
    AccountDomain;
suspiciousConnections
| join kind=inner recentProcesses on DeviceName
| where FileName =~ InitiatingProcessFileName
| where ProcTime between ((ConnTime - 5m) .. ConnTime)
| summarize
    ConnectionCount = count(),
    DistinctRemoteIPs = dcount(RemoteIP),
    RemotePorts = make_set(RemotePort),
    RemoteIPs = make_set(RemoteIP),
    ProcessCommandLine = take_any(ProcessCommandLine),
    AccountName = take_any(AccountName),
    AccountDomain = take_any(AccountDomain),
    ConnTimeBin = min(ConnTime)
    by DeviceName, InitiatingProcessFileName, bin(ConnTime, 1h)
| where ConnectionCount >= 3
| project
    DeviceName,
    InitiatingProcessFileName,
    ProcessCommandLine,
    ConnectionCount,
    DistinctRemoteIPs,
    RemotePorts,
    RemoteIPs,
    AccountName,
    AccountDomain,
    ConnTimeBin
| order by ConnectionCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate remote management tools such as VPN clients, RMM agents, and backup agents that connect to high ports.
- Development tools such as git clients, package managers, and IDE extensions that connect to non-standard ports.
- Custom enterprise applications that use high ports for internal service communication.
- Telemetry and monitoring agents that maintain persistent outbound connections.

**Tuning notes:**
- Add environment-specific legitimate remote management and VPN client process names to knownUpdaters before running at scale.
- Adjust the ConnectionCount threshold and time bin after a 7-day baseline review of the query output.
- Consider adding a DistinctRemoteIPs >= 2 filter to focus on multi-destination tunnel patterns rather than single-server keepalives.
- For scheduled rule promotion, scope to specific device groups or OUs where reverse tunnel activity is unexpected.

**Risks / caveats:**
- ActionType value 'ConnectionSuccess' must be confirmed present in the environment's DeviceNetworkEvents schema; some tenants may observe 'NetworkConnectionEvents' action type variants depending on sensor version.
- The knownBrowsers and knownUpdaters exclusion lists require environment-specific expansion to cover legitimate RMM, VPN, and backup agents before the signal-to-noise ratio is acceptable for regular review.
- The ConnectionCount threshold of 3 per hour is arbitrary and requires baselining against the environment to avoid suppressing real tunnels or flooding with legitimate traffic.
- The 5-minute process-spawn-to-connection window may miss tunnels deployed via scheduled tasks or services that were created well before the connection.

### Triage Runbook

**First 15 minutes:**
- Identify the initiating process, its command line, and whether it recently spawned from a suspicious parent or from a DLL sideloading event.
- Check the destination IPs and ports for repetition, unusual geography, hosting providers, or multiple remote endpoints.
- Confirm whether the process is a known browser, updater, VPN, RMM, backup, or enterprise application allowed to use high ports.
- Look for concurrent signs of staging such as recent file drops, script execution, or persistence on the same host.

**Evidence to collect:**
- Device name, initiating process file name, process command line, remote IPs, remote ports, connection count, and distinct remote IP count.
- Process creation timeline for the initiating process and any parent or child processes around the first connection.
- Network metadata showing whether the traffic is persistent, beacon-like, or directed to multiple destinations.
- Any related file, registry, scheduled task, or service changes on the host.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceName and InitiatingProcessFileName over 24 hours to map destination patterns.
- DeviceProcessEvents for the same DeviceName and process name to identify spawn time and parent process.
- DeviceFileEvents, DeviceRegistryEvents, and DeviceServiceEvents for the same host to look for persistence or staging.
- If available, proxy or firewall logs for the remote IPs and ports to validate whether the traffic is expected.

**Benign explanations:**
- Legitimate VPN clients, RMM agents, backup agents, or monitoring tools that maintain outbound high-port sessions.
- Development tools, package managers, or internal service clients that use non-standard ports.
- Custom enterprise applications that communicate over proprietary high ports.
- One-off maintenance or troubleshooting sessions initiated by IT staff.

**Escalation criteria:**
- The process is not an approved browser, updater, VPN, RMM, backup, or enterprise application and the connections are persistent or multi-destination.
- The activity follows recent DLL sideloading, script execution, or other staging behavior on the same host.
- The remote IPs are external, unfamiliar, or associated with infrastructure that is not expected for the business.
- The host also shows credential access, lateral movement, or additional command-and-control indicators.

**Containment actions:**
- If the traffic is suspicious, isolate the host and block the remote IPs or ports at the perimeter if appropriate.
- Terminate the suspicious process if it is not required for business operations.
- Preserve process, network, and file evidence before cleanup.
- Escalate to incident response if the host is a server or contains sensitive data and the tunnel appears active.

**Closure criteria:**
- The initiating process is confirmed as an approved business application or management agent with documented high-port use.
- The destination IPs and ports match known internal services, update infrastructure, or sanctioned remote access.
- No corroborating evidence of staging, persistence, or malicious child processes is found.
- The detection is tuned with environment-specific exclusions for the approved process and destination patterns.

<br/>
---
<br/>

## Detection 3: PaperCut Exploitation - Shell Process Spawned by PaperCut Application Service

### Detection Opportunity

Post-exploitation child process spawning from PaperCut application server process following active exploitation of CVE-2026-81578 or CVE-2026-82078

### Intelligence Context

- Rapid7: PaperCut NG/MF Critical Zero-Day Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild)
  - Context: Rapid7 confirmed active in-the-wild exploitation of PaperCut NG and MF servers via CVE-2026-81578 (authentication bypass) and CVE-2026-82078. Post-exploitation activity is expected to manifest as shell or scripting engine processes spawned by the PaperCut application service process.

### Search Metadata

- CVEs: CVE-2026-81578, CVE-2026-82078
- Threat actors: Not specified
- ATT&CK tags: T1190, T1071
- Products: PaperCut NG, PaperCut MF
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-81578, CVE-2026-82078, T1190, PaperCut NG, PaperCut MF, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let papercutParents = dynamic(["pc-app.exe", "pc-pdl-to-image.exe", "PCAppServer.exe", "java.exe"]);
let shellProcesses = dynamic(["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe"]);
let privateRanges = dynamic(["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.", "127."]);
let suspiciousChildProcs = DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ (papercutParents)
| where FileName in~ (shellProcesses)
| project
    DeviceName,
    ProcTime = Timestamp,
    ParentProcess = InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    ChildProcess = FileName,
    ProcessCommandLine,
    AccountName,
    AccountDomain;
let followOnNetwork = DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName in~ (shellProcesses)
| where not(RemoteIP has_any (privateRanges))
| project
    DeviceName,
    NetTime = Timestamp,
    RemoteIP,
    RemotePort,
    NetInitiatingProcess = InitiatingProcessFileName;
suspiciousChildProcs
| join kind=leftouter followOnNetwork on DeviceName
| where isempty(NetTime) or (NetTime between (ProcTime .. (ProcTime + 5m)) and NetInitiatingProcess =~ ChildProcess)
| summarize
    RemoteIPs = make_set(RemoteIP),
    RemotePorts = make_set(RemotePort),
    FirstNetTime = min(NetTime)
    by DeviceName, ProcTime, ParentProcess, InitiatingProcessFolderPath, InitiatingProcessCommandLine, ChildProcess, ProcessCommandLine, AccountName, AccountDomain
| project
    DeviceName,
    ProcTime,
    ParentProcess,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    ChildProcess,
    ProcessCommandLine,
    AccountName,
    AccountDomain,
    FirstNetTime,
    RemoteIPs,
    RemotePorts
| order by ProcTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate PaperCut administrative scripts that invoke cmd.exe or powershell.exe for maintenance tasks.
- Java-based application servers co-hosted with PaperCut that spawn shell processes for legitimate automation.
- Scheduled maintenance tasks configured to run under the PaperCut service account.

**Tuning notes:**
- Confirm the PaperCut service executable name on enrolled hosts by querying DeviceProcessEvents for pc-app.exe, PCAppServer.exe, and java.exe before the first scheduled run.
- If java.exe false positives are observed, add a filter on InitiatingProcessFolderPath containing the PaperCut installation directory to scope the java.exe entry.
- Add a DeviceInfo join filtered to the PaperCut server hostname pattern to reduce blast radius if the rule is deployed broadly.
- Build a ProcessCommandLine exclusion list from observed legitimate PaperCut maintenance activity after the first week of operation.

**Risks / caveats:**
- The PaperCut host must be enrolled in Defender for Endpoint and actively sending process creation telemetry; if the PaperCut server is not onboarded, the query will produce no results.
- java.exe as a parent process is shared with many Java-based applications; if the PaperCut server runs on a host with other Java services, this entry will generate false positives until scoped to PaperCut-specific hosts.
- java.exe as a PaperCut parent will generate false positives on hosts running other Java-based services; scope the query to known PaperCut server hostnames via a DeviceInfo join or watchlist if java.exe false positives are observed.
- The 1-day lookback window is appropriate for a scheduled rule but should be extended to 7 days for initial retrospective hunting after a confirmed exploitation event.

### Triage Runbook

**First 15 minutes:**
- Verify the host is a real PaperCut NG or MF server and identify the exact parent process path and command line.
- Inspect the child shell or LOLBin command line for download, execution, encoded commands, or remote access behavior.
- Check whether the shell spawn aligns with a known maintenance window or approved administrative script.
- Review any outbound network activity from the child process and any other suspicious processes on the same host.

**Evidence to collect:**
- Device name, parent process name, parent folder path, parent command line, child process name, child command line, account name, and account domain.
- Any associated remote IPs, ports, and timestamps from the follow-on network events.
- PaperCut service version, patch level, and whether the server is internet-facing or reachable from untrusted networks.
- Recent process tree and any file or registry changes made by the child process.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and ParentProcess to enumerate all child processes in the last 24 hours.
- DeviceNetworkEvents for the same DeviceName and ChildProcess to identify outbound connections after shell spawn.
- DeviceFileEvents and DeviceRegistryEvents on the same host for dropped payloads, persistence, or configuration changes.
- If available, PaperCut application logs and web access logs to correlate with the suspected exploitation window.

**Benign explanations:**
- Authorized PaperCut maintenance scripts that invoke cmd.exe or powershell.exe.
- Co-hosted Java applications or automation jobs that legitimately spawn shell processes on the same server.
- Administrative troubleshooting performed by IT staff under the PaperCut service account.
- Backup, monitoring, or deployment tooling installed on the server that uses shell wrappers.

**Escalation criteria:**
- The shell command line contains download, encoded, obfuscated, or remote execution content.
- The child process makes external network connections or is followed by additional suspicious processes.
- The PaperCut server is internet-facing, unpatched, or shows signs of exploitation beyond a single admin action.
- Multiple child shells or LOLBins are spawned from the PaperCut service process.

**Containment actions:**
- If suspicious, isolate the PaperCut server from the network to stop further exploitation.
- Terminate the shell process and any obvious follow-on payloads if operationally safe.
- Disable external access to PaperCut admin interfaces until the server is assessed and patched.
- Preserve logs, process trees, and any dropped files for incident response and forensics.

**Closure criteria:**
- The shell activity is confirmed as a documented and expected PaperCut administrative task.
- No malicious command line content, external connections, or follow-on payloads are found.
- The server is patched or otherwise validated as not exposed to the exploited condition.
- A clear allowlist or maintenance procedure explains the activity and is recorded for future triage.

<br/>
---
<br/>

## Detection 4: PaperCut Authentication Bypass - Unauthenticated Access to Admin Endpoints from External IP

### Detection Opportunity

Authentication bypass against PaperCut admin endpoints returning successful HTTP responses from external source IPs, consistent with CVE-2026-81578 exploitation

### Intelligence Context

- Rapid7: PaperCut NG/MF Critical Zero-Day Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild)
  - Context: CVE-2026-81578 is described as an authentication bypass in the PaperCut exploit chain. This produces a detectable pattern of unauthenticated HTTP requests to privileged admin endpoints that return successful 200 responses from external IP addresses.

### Search Metadata

- CVEs: CVE-2026-81578, CVE-2026-82078
- Threat actors: Not specified
- ATT&CK tags: T1190, T1071
- Products: PaperCut NG, PaperCut MF
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-81578, CVE-2026-82078, T1190, PaperCut NG, PaperCut MF, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol (low)

### Deployment Gates

- The RequestURL field is not populated by all CEF-forwarding devices; some appliances map URL data to cs-uri or other custom fields, requiring schema-specific field remapping before the query is valid.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
let privateRanges = dynamic(["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.", "127."]);
let papercutAdminPaths = dynamic(["/app", "/admin", "/api/health", "/rpc/api"]);
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where RequestURL has_any (papercutAdminPaths)
| where not(SourceIP has_any (privateRanges))
| extend ExtractedResponseCode = coalesce(
    extract(@"(?:responseCode|cs1|outcome|sc-status)=([0-9]{3})", 1, AdditionalExtensions),
    extract(@"(?:responseCode|cs1|outcome|sc-status)=([0-9]{3})", 1, tostring(AdditionalExtensions))
  )
| where ExtractedResponseCode == "200"
| summarize
    RequestCount = count(),
    RequestPaths = make_set(RequestURL),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    DeviceVendor = take_any(DeviceVendor),
    DeviceProduct = take_any(DeviceProduct)
    by SourceIP, DeviceName
| where RequestCount >= 2
| project
    SourceIP,
    DeviceName,
    DeviceVendor,
    DeviceProduct,
    RequestCount,
    RequestPaths,
    FirstSeen,
    LastSeen
| order by RequestCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate external administrators accessing PaperCut admin interfaces from non-RFC1918 addresses such as corporate VPN exit nodes with public IPs.
- Security scanners and vulnerability assessment tools probing PaperCut admin endpoints.
- Monitoring systems performing health checks against PaperCut API endpoints from external addresses.

**Tuning notes:**
- Before running, execute a count query against CommonSecurityLog filtered to DeviceVendor and DeviceProduct of the forwarding appliance to confirm RequestURL and AdditionalExtensions are populated.
- Validate the ExtractedResponseCode extract pattern against 10-20 sample rows from the forwarding appliance to confirm the regex matches the actual field format.
- Extend papercutAdminPaths with any custom admin endpoint paths configured in the environment.
- Add known legitimate external admin source IPs to an exclusion list after baselining to reduce false positives from authorized remote administration.

**Risks / caveats:**
- CommonSecurityLog must be populated by a network appliance or proxy that captures HTTP request URLs and response codes for PaperCut traffic; if no such appliance is forwarding logs to Sentinel, the query will return no results.
- The AdditionalExtensions field format for HTTP response codes is vendor-specific; the patterns 'cs1=200' and 'responseCode=200' may not match the actual field format produced by the forwarding appliance, causing the response code filter to silently drop all events.
- The RequestURL field is not populated by all CEF-forwarding devices; some appliances map URL data to cs-uri or other custom fields, requiring schema-specific field remapping before the query is valid.
- The extract pattern for response codes covers common CEF field names but will not match all appliance-specific AdditionalExtensions formats; the pattern must be validated against actual log samples from the forwarding device before the query is trusted.

### Triage Runbook

**First 15 minutes:**
- Confirm the source IP is external and identify whether it belongs to a known VPN, admin, scanner, or monitoring service.
- Review the requested URLs and response codes to see whether the traffic targets admin or API endpoints repeatedly.
- Check whether the requests occurred during a planned maintenance or vulnerability assessment window.
- Correlate the source IP with any subsequent shell spawning, file changes, or outbound connections on the PaperCut server.

**Evidence to collect:**
- Source IP, destination host name, request URLs, request count, first and last seen times, and extracted response code.
- Device vendor and product for the forwarding appliance to understand how the HTTP logs were generated.
- Any authentication or session logs from PaperCut that show whether the requests were authenticated or bypassed auth.
- Related server-side process and network telemetry from the same time window.

**Pivot points:**
- CommonSecurityLog for the same SourceIP and DeviceName to expand the request path set and timing.
- PaperCut application or web logs, if available, to confirm whether the requests were authenticated.
- DeviceProcessEvents and DeviceNetworkEvents on the PaperCut host for post-request shell activity or outbound connections.
- Proxy, WAF, or firewall logs to validate whether the source IP is a known administrator or scanner.

**Benign explanations:**
- Authorized administrators accessing PaperCut from a public VPN exit node or other external management IP.
- Security scanners or vulnerability assessment tools probing admin endpoints.
- Monitoring systems performing health checks against PaperCut APIs.
- Misconfigured reverse proxies or load balancers generating repeated requests during troubleshooting.

**Escalation criteria:**
- The source IP is unknown, the requests target privileged endpoints, and the activity is not tied to an approved admin or scanner.
- The requests are followed by shell spawning, outbound connections, or other post-exploitation behavior on the PaperCut server.
- The response pattern suggests successful access to admin functionality from an untrusted external source.
- Multiple external IPs or repeated requests indicate active exploitation rather than a single benign check.

**Containment actions:**
- Block the source IP at the perimeter if it is confirmed malicious or part of active exploitation.
- Restrict or disable external access to PaperCut admin endpoints until the server is assessed.
- If exploitation is suspected, isolate the PaperCut server and preserve logs before remediation.
- Coordinate with the application owner before making changes that could disrupt legitimate remote administration.

**Closure criteria:**
- The source IP is confirmed as an approved administrator, scanner, or monitoring system.
- The requested URLs and response codes are consistent with expected health checks or maintenance.
- No server-side post-exploitation activity is found after the requests.
- The request pattern is documented and, if needed, added to an allowlist or tuning exception.

<br/>
---
<br/>

## Detection 5: PaperCut Server Identification and Anomalous Outbound Network Activity

### Detection Opportunity

Anomalous outbound network connections from devices identified as running PaperCut services, consistent with post-exploitation C2 activity following active exploitation

### Intelligence Context

- Rapid7: PaperCut NG/MF Critical Zero-Day Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-papercut-ng-mf-critical-zero-day-exploited-in-the-wild)
  - Context: Rapid7 confirmed active exploitation of PaperCut NG and MF servers. Identifying PaperCut hosts via process telemetry and then scoping network anomaly detection to those hosts reduces false positives and surfaces post-exploitation C2 or lateral movement activity.

### Search Metadata

- CVEs: CVE-2026-81578, CVE-2026-82078
- Threat actors: Not specified
- ATT&CK tags: T1190, T1071
- Products: PaperCut NG, PaperCut MF
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-81578, CVE-2026-82078, T1190, PaperCut NG, PaperCut MF, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let papercutHosts = DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("pc-app.exe", "PCAppServer.exe", "pc-pdl-to-image.exe")
| distinct DeviceName;
let privateRanges = dynamic(["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.", "127."]);
let commonPorts = dynamic([80, 443, 8080, 8443, 9191, 9192, 53, 25, 587, 22, 3389]);
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "ConnectionSuccess"
| where DeviceName in (papercutHosts)
| where not(RemoteIP has_any (privateRanges))
| where RemotePort !in (commonPorts)
| summarize
    ConnectionCount = count(),
    DistinctRemoteIPs = dcount(RemoteIP),
    RemotePorts = make_set(RemotePort),
    RemoteIPs = make_set(RemoteIP),
    InitiatingProcessCommandLine = take_any(InitiatingProcessCommandLine),
    TimeBin = min(Timestamp)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| project
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ConnectionCount,
    DistinctRemoteIPs,
    RemotePorts,
    RemoteIPs,
    TimeBin
| order by ConnectionCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- PaperCut servers that connect to external update or telemetry endpoints on non-standard ports.
- Legitimate remote management or monitoring agents running on the PaperCut server that maintain outbound connections.
- Backup agents or cloud sync clients installed on the PaperCut server that connect to external services on high ports.

**Tuning notes:**
- Run the papercutHosts subquery independently over a 7-day window to confirm it returns the expected PaperCut server devices before executing the full query.
- Review RemoteIPs and RemotePorts output against known PaperCut update, licensing, and telemetry endpoints to build an environment-specific port and IP exclusion list.
- Add a ConnectionCount >= 2 or DistinctRemoteIPs >= 2 filter after baselining to reduce single-connection noise.
- Extend the lookback window from 1 day to 7 days for retrospective hunting following a confirmed exploitation event.

**Risks / caveats:**
- PaperCut server hosts must be enrolled in Defender for Endpoint and actively sending process creation telemetry; if the PaperCut server is not onboarded, the papercutHosts subquery will return an empty set and the query will produce no results.
- The papercutHosts subquery uses a 1-day lookback; if the PaperCut service was stopped after exploitation, the host will not appear in the subquery and post-exploitation network activity will be missed. Extend the lookback for retrospective hunting.
- The commonPorts exclusion list may need expansion to cover PaperCut update or telemetry endpoints that use non-standard ports in the environment.
- No minimum ConnectionCount threshold is applied; single anomalous connections will surface, which may require analyst triage to distinguish from legitimate one-off connections.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a PaperCut server and identify the initiating process and command line responsible for the outbound connections.
- Review the remote IPs and ports for unusual destinations, repeated beaconing, or connections to infrastructure not used by PaperCut.
- Check whether the activity follows recent exploitation indicators such as admin endpoint access, shell spawning, or suspicious file drops.
- Determine whether the connections are to known update, licensing, telemetry, or support services for PaperCut or related enterprise tooling.

**Evidence to collect:**
- Device name, initiating process file name, initiating process command line, connection count, distinct remote IP count, remote IPs, remote ports, and time bin.
- PaperCut service identification evidence from process telemetry, including the exact executable names and paths.
- Any related process creation, file creation, registry, or scheduled task activity on the same host.
- Network logs or proxy logs that show whether the remote destinations are sanctioned services or unknown external infrastructure.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName to confirm PaperCut service processes and any suspicious child processes.
- DeviceNetworkEvents for the same DeviceName and time window to expand destination history and connection frequency.
- DeviceFileEvents, DeviceRegistryEvents, and DeviceServiceEvents on the host to look for persistence or payload staging.
- If available, DNS, proxy, or firewall logs for the remote IPs to identify domains and service ownership.

**Benign explanations:**
- PaperCut update, licensing, telemetry, or support traffic to vendor or enterprise-managed services.
- Legitimate remote management, backup, or monitoring agents installed on the server.
- Internal application integrations or cloud sync clients that use non-standard ports.
- One-off administrative troubleshooting or vendor support sessions.

**Escalation criteria:**
- The outbound destinations are external, unfamiliar, or inconsistent with PaperCut or approved enterprise services.
- The activity is persistent, multi-destination, or resembles beaconing rather than normal service traffic.
- The host also shows shell spawning, file drops, or other signs of exploitation.
- The PaperCut server is internet-facing or recently exposed to the authentication bypass condition.

**Containment actions:**
- If the traffic is suspicious, isolate the PaperCut server from the network to prevent further command-and-control or lateral movement.
- Block the remote IPs or domains if they are confirmed malicious and blocking will not disrupt business-critical services.
- Suspend nonessential remote management agents on the host if they are contributing to the activity and are not required for containment.
- Preserve process and network evidence before remediation or reboot.

**Closure criteria:**
- The outbound traffic is confirmed as expected PaperCut, vendor, or enterprise management communication.
- The destination IPs and ports are documented and match approved services.
- No corroborating exploitation, persistence, or malicious child process activity is found.
- The host is patched, monitored, and the detection is tuned with environment-specific exclusions if needed.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- TerminalFix - Unsigned DLL Loaded by Legitimate Binary from User-Writable Path: Do not schedule yet; validate as an analyst-led hunt first.
- TerminalFix - Outbound Reverse Tunnel Connection from Non-Browser Process to High Port: Do not schedule yet; validate as an analyst-led hunt first.
- PaperCut Authentication Bypass - Unauthenticated Access to Admin Endpoints from External IP: The RequestURL field is not populated by all CEF-forwarding devices; some appliances map URL data to cs-uri or other custom fields, requiring schema-specific field remapping before the query is valid.

**Licensing / identity risk fields:**
- TerminalFix - Unsigned DLL Loaded by Legitimate Binary from User-Writable Path: DeviceImageLoadEvents requires Defender for Endpoint Plan 2 or Microsoft 365 Defender with advanced hunting enabled; it is not available under all license tiers.

**Shared-table notes:**
- DeviceProcessEvents: shared by TerminalFix - Unsigned DLL Loaded by Legitimate Binary from User-Writable Path; TerminalFix - Outbound Reverse Tunnel Connection from Non-Browser Process to High Port; PaperCut Exploitation - Shell Process Spawned by PaperCut Application Service; PaperCut Server Identification and Anomalous Outbound Network Activity
- DeviceNetworkEvents: shared by TerminalFix - Outbound Reverse Tunnel Connection from Non-Browser Process to High Port; PaperCut Exploitation - Shell Process Spawned by PaperCut Application Service; PaperCut Server Identification and Anomalous Outbound Network Activity

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: PaperCut Exploitation - Shell Process Spawned by PaperCut Application Service; PaperCut Server Identification and Anomalous Outbound Network Activity.
2. Resolve environment-mapping detections next: PaperCut Authentication Bypass - Unauthenticated Access to Admin Endpoints from External IP.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: TerminalFix - Unsigned DLL Loaded by Legitimate Binary from User-Writable Path; TerminalFix - Outbound Reverse Tunnel Connection from Non-Browser Process to High Port.

### Hunting Agenda and Promotion Criteria

- TerminalFix - Unsigned DLL Loaded by Legitimate Binary from User-Writable Path: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- TerminalFix - Outbound Reverse Tunnel Connection from Non-Browser Process to High Port: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- PaperCut Authentication Bypass - Unauthenticated Access to Admin Endpoints from External IP: The RequestURL field is not populated by all CEF-forwarding devices; some appliances map URL data to cs-uri or other custom fields, requiring schema-specific field remapping before the query is valid.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
