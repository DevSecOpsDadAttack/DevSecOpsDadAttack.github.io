---
layout: post
title: "Detection Engineering Brief - Tuesday, November 17, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-11-17
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-90436
  - T1190
  - Atlassian Confluence Data Center
  - N-able N-central
  - Apache Axis 1.x
  - Java
  - GitHub
  - cloud services
  - GitDoor
  - HTTP/3
  - QUIC
  - PerfectPioneer RAT
  - KUKURAT
  - GraphDoor
  - T1071
  - T1071.001
  - T1055
  - T1055.012
  - T1095
  - T1102
  - T1102.001
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 4 hunting-only, 0 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-90436, T1190, Atlassian Confluence Data Center, N-able N-central, Apache Axis 1.x, Java, GitHub, cloud services, GitDoor, HTTP/3, QUIC, PerfectPioneer RAT, KUKURAT, GraphDoor, T1071, T1071.001, T1055, T1055.012, T1095, T1102, ....

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: CVE-2026-90436 Exploitation Attempt - Inbound Network Connection to Confluence or N-central Followed by Outbound Callback; GitDoor Backdoor - Shellcode Injection or Memory Allocation by Unknown Process (Operation ShadowCloud); KUKURAT/PerfectPioneer RAT - Sustained UDP/443 QUIC Outbound from Non-Browser Process; GraphDoor Backdoor - Cloud API Access from Non-Standard Process (Operation ShadowCloud).

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: CVE-2026-90436 RCE - Suspicious Child Process Spawned by Java Web Service Account

### Detection Opportunity

Unauthenticated RCE via Apache Axis 1.x unsafe reflection spawning shell or interpreter processes under Java web service accounts on Confluence or N-central hosts

### Intelligence Context

- Rapid7: Rapid7 Detected Exploitation of CVE-2026-90436 against Atlassian Confluence Data Center, N-able N-central also Exploited — [https://www.rapid7.com/blog/post/etr-rapid7-detected-exploitation-of-cve-2026-90436-against-atlassian-confluence-data-center-n-able-n-central-also-exploited](https://www.rapid7.com/blog/post/etr-rapid7-detected-exploitation-of-cve-2026-90436-against-atlassian-confluence-data-center-n-able-n-central-also-exploited)
  - Context: Rapid7 confirmed active in-the-wild exploitation of CVE-2026-90436, a critical unsafe reflection vulnerability in Apache Axis 1.x, against Atlassian Confluence Data Center and N-able N-central. Successful exploitation enables unauthenticated RCE, which reliably produces anomalous child processes spawned under the Java web service account.

### Search Metadata

- CVEs: CVE-2026-90436
- Threat actors: Not specified
- ATT&CK tags: T1190, T1071, T1071.001
- Products: Atlassian Confluence Data Center, N-able N-central, Apache Axis 1.x
- Platforms: Java
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-90436, T1190, Atlassian Confluence Data Center, N-able N-central, Apache Axis 1.x, Java, T1071, T1071.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ ("java.exe", "java", "tomcat.exe", "tomcat9.exe", "tomcat10.exe")
| where FileName in~ (
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "sh", "bash", "dash", "zsh",
    "curl", "wget",
    "whoami", "id",
    "net.exe", "net1.exe"
  )
| where FileName !in~ ("conhost.exe")
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    FileName,
    FolderPath,
    ProcessCommandLine
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Java-based build servers or CI/CD agents that legitimately invoke shell commands from java/tomcat processes.
- Scheduled maintenance scripts executed under the Tomcat service account.
- Application health-check scripts that invoke curl or wget from within the JVM.

**Tuning notes:**
- Add a DeviceName filter against a watchlist of Confluence and N-central hosts to reduce scope.
- Exclude known service account names used by deployment pipelines via an AccountName not in filter.
- Consider adding InitiatingProcessFolderPath contains conditions (e.g., 'confluence', 'ncentral', 'tomcat') as an additional anchor if host scoping is not feasible.

**Risks / caveats:**
- Without scoping DeviceName to known Confluence or N-central hosts, any Java application server in the environment will generate alerts; a host inventory watchlist or device group is strongly recommended.
- On Linux endpoints, java may spawn sh or bash for legitimate JVM subprocess operations; baseline the environment before scheduling.
- The 24-hour lookback window may miss detections if ingestion lag exceeds a few hours; adjust to ago(48h) if ingestion delays are observed.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a known Confluence Data Center or N-able N-central server and that the alerting parent process is java/tomcat from the expected install path.
- Review the child process name, command line, and parent command line for shell spawning, command execution, download activity, or recon commands such as whoami/id/net.
- Check whether the service account is a normal application identity or an unexpected account, and whether the child process ran with elevated or unusual privileges.
- Look for nearby network activity, file writes, or additional child processes from the same parent within the same time window to assess post-exploitation activity.

**Evidence to collect:**
- DeviceProcessEvents for the parent and child process chain, including command lines and folder paths.
- DeviceNetworkEvents from the same host around the alert time to identify outbound callbacks or downloads.
- Recent DeviceFileEvents for new or modified files in web app, temp, or program data locations.
- Host inventory details showing whether the device is a sanctioned Confluence or N-central server and which service account should be running the application.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and AccountName over the prior 24 hours to find repeated shell or interpreter spawns.
- DeviceNetworkEvents for the same DeviceName and InitiatingProcessFileName to identify outbound connections from java/tomcat.
- DeviceFileEvents for the same DeviceName to look for dropped scripts, web shells, or staged payloads.
- If available, correlate with authentication and service logs from the application to identify suspicious requests preceding the process spawn.

**Benign explanations:**
- Planned maintenance or deployment scripts executed under the Tomcat or application service account.
- Legitimate application health checks or backup jobs that invoke curl, wget, or similar utilities from the JVM.
- Java-based build or automation servers that are not actually Confluence or N-central hosts and legitimately spawn shell commands.

**Escalation criteria:**
- The child process is cmd.exe, powershell.exe, sh, bash, or another interpreter with suspicious arguments or download/execution behavior.
- The host is confirmed to be a Confluence or N-central server and the process chain is not part of an approved maintenance window.
- You find evidence of follow-on activity such as outbound callbacks, file drops, credential access, or additional suspicious child processes.
- The service account or parent process path does not match the known baseline for the application server.

**Containment actions:**
- Isolate the host from the network if the child process shows active exploitation or post-exploitation behavior.
- Disable or rotate the affected service account credentials if there is evidence the account was abused.
- Preserve volatile evidence and collect process, network, and file telemetry before rebooting or remediating the server.

**Closure criteria:**
- The host is verified as a known Confluence or N-central server and the process activity matches an approved maintenance or automation pattern.
- No suspicious network, file, or follow-on process activity is found around the alert window.
- The child process is a known benign exception such as conhost.exe or an approved deployment/health-check utility.
- The event is documented and the allowlist or host scoping is updated if this is a recurring benign pattern.

<br/>
---
<br/>

## Detection 2: CVE-2026-90436 Exploitation Attempt - Inbound Network Connection to Confluence or N-central Followed by Outbound Callback

### Detection Opportunity

Inbound exploitation attempt against Confluence or N-central via Axis 1.x followed by an outbound network connection from the same host, indicating successful RCE and callback

### Intelligence Context

- Rapid7: Rapid7 Detected Exploitation of CVE-2026-90436 against Atlassian Confluence Data Center, N-able N-central also Exploited — [https://www.rapid7.com/blog/post/etr-rapid7-detected-exploitation-of-cve-2026-90436-against-atlassian-confluence-data-center-n-able-n-central-also-exploited](https://www.rapid7.com/blog/post/etr-rapid7-detected-exploitation-of-cve-2026-90436-against-atlassian-confluence-data-center-n-able-n-central-also-exploited)
  - Context: Active exploitation of CVE-2026-90436 enables unauthenticated RCE. A compound detection correlating inbound connections to service ports with subsequent outbound connections from java/tomcat processes on the same host provides higher-fidelity evidence of successful exploitation versus a failed probe.

### Search Metadata

- CVEs: CVE-2026-90436
- Threat actors: Not specified
- ATT&CK tags: T1190, T1071, T1071.001
- Products: Atlassian Confluence Data Center, N-able N-central, Apache Axis 1.x
- Platforms: Java
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-90436, T1190, Atlassian Confluence Data Center, N-able N-central, Apache Axis 1.x, Java, T1071, T1071.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
let InboundToService = DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType == "InboundConnectionAccepted"
| where LocalPort in (8090, 8091, 443, 8443, 80)
| project InboundTime = Timestamp, DeviceName, InboundSourceIP = RemoteIP;
let OutboundFromJava = DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName in~ ("java.exe", "java", "tomcat.exe", "tomcat9.exe", "tomcat10.exe")
| where not(ipv4_is_private(RemoteIP))
| project OutboundTime = Timestamp, DeviceName, OutboundRemoteIP = RemoteIP, OutboundRemotePort = RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath;
InboundToService
| join kind=inner OutboundFromJava on DeviceName
| where OutboundTime between (InboundTime .. (InboundTime + 10m))
| project
    InboundTime,
    OutboundTime,
    DeviceName,
    InboundSourceIP,
    OutboundRemoteIP,
    OutboundRemotePort,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath
| order by InboundTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate inbound user requests to Confluence followed by java-initiated outbound calls to internal microservices or databases.
- Health-check or monitoring systems that poll Confluence ports and trigger java-initiated metric reporting connections.
- Software update checks initiated by the Tomcat or Confluence process shortly after receiving any inbound connection.

**Tuning notes:**
- Scope DeviceName to a watchlist of known Confluence and N-central hosts before using this query in a scheduled context.
- Adjust LocalPort values to match the actual configured service ports in the environment.
- Consider extending the correlation window to 30 minutes if staged payloads with sleep timers are observed.
- Add known update and telemetry destination IPs to an exclusion list for OutboundRemoteIP.

**Risks / caveats:**
- InboundConnectionAccepted ActionType availability depends on MDE network inspection mode and host OS; it may not be present on all enrolled devices, causing the inbound leg of the join to return no rows.
- RemoteUrl field is not projected from DeviceNetworkEvents in this query; if RemoteUrl is needed for triage it must be explicitly selected, but it is not always populated for raw TCP connections.
- InboundConnectionAccepted events may not be generated on all MDE-enrolled hosts depending on OS and network sensor configuration; validate telemetry availability before relying on this query.
- The join on DeviceName without a shared session identifier means a high-traffic Confluence host will produce many spurious correlations; analyst review of each result is required.

### Triage Runbook

**First 15 minutes:**
- Confirm the device is a known Confluence or N-central host and verify the inbound port matches the exposed application service.
- Review the inbound source IP, timing, and frequency to determine whether this was a single user request or a suspicious external probe.
- Inspect the outbound destination IP and port for signs of internet callback, especially if it is not a known update, telemetry, or internal service endpoint.
- Check whether the outbound connection was initiated by java/tomcat and whether there are accompanying process-spawn or file-write alerts on the same host.

**Evidence to collect:**
- DeviceNetworkEvents showing the inbound accepted connection and the subsequent outbound connection from the same host.
- DeviceProcessEvents for java/tomcat child processes around the same time to confirm execution after the inbound event.
- Any available web or application access logs for the Confluence or N-central service to identify the request path and source IP.
- Host inventory and baseline network destinations for the server to distinguish normal service traffic from callback behavior.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceName over the prior 24 hours to identify repeated inbound probes or repeated outbound callbacks.
- DeviceProcessEvents for the same DeviceName and InitiatingProcessFileName to find shell, interpreter, or downloader activity.
- DeviceFileEvents for the same host to look for dropped payloads or modified web content after the inbound event.
- If available, proxy or firewall logs for the outbound RemoteIP to determine whether the destination is known or suspicious.

**Benign explanations:**
- Normal user traffic to Confluence followed by legitimate application calls to internal microservices or databases.
- Monitoring or health-check systems that connect to the service port and trigger routine outbound telemetry.
- Software update checks or license validation traffic initiated by the application shortly after an inbound request.

**Escalation criteria:**
- The outbound destination is external and not a known update, telemetry, or business service endpoint.
- The same host also shows suspicious child processes, file modifications, or repeated inbound/outbound correlation events.
- The inbound source IP is untrusted and the timing aligns with other exploitation indicators on the host.
- The server is internet-facing and the callback occurs within minutes of the inbound connection with no benign explanation.

**Containment actions:**
- Isolate the host if the outbound callback or process telemetry indicates likely successful exploitation.
- Block the suspicious source and destination IPs at the network edge if they are confirmed malicious.
- Preserve logs and memory/process evidence before restarting or patching the application server.

**Closure criteria:**
- The outbound connection is confirmed as legitimate application behavior to an approved internal or vendor endpoint.
- No corroborating process, file, or repeated network indicators of compromise are found.
- The inbound event is attributable to normal user or monitoring activity and the callback is benign and expected.
- The host is added to the known Confluence/N-central scope and the event is documented as benign if appropriate.

<br/>
---
<br/>

## Detection 3: GitDoor Backdoor - Shellcode Injection or Memory Allocation by Unknown Process (Operation ShadowCloud)

### Detection Opportunity

GitDoor backdoor loading shellcode families via process injection or virtual memory allocation from an unknown or unsigned initiating process

### Intelligence Context

- Securelist: Operation ShadowCloud: cloud service-based backdoors targeting government networks in Asia and Africa. Part 1 — [https://securelist.com/operation-shadowcloud-gitdoor/122004/](https://securelist.com/operation-shadowcloud-gitdoor/122004/)
  - Context: Securelist reported that the GitDoor backdoor, part of Operation ShadowCloud targeting government networks, loads shellcode families at runtime. This produces process injection telemetry signals including memory allocation and write events that are detectable via MDE DeviceEvents regardless of the specific shellcode family name.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1055, T1055.012
- Products: GitHub
- Platforms: cloud services
- Malware: GitDoor
- Tools: Not specified
- Search tags: GitHub, cloud services, GitDoor, T1055, T1055.012

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Defense Evasion: T1055 Process Injection (high); Defense Evasion: T1055 Process Injection/ T1055.012 Process Hollowing (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- If ShellcodeInjection and ProcessInjection ActionTypes are not available in the environment, the injection leg will rely solely on CreateRemoteThreadApiCall and WriteProcessMemoryApiCall, which are noisier signals.

**Required telemetry:**
- DeviceEvents, DeviceNetworkEvents

### KQL

```kql
let InjectionEvents = DeviceEvents
| where Timestamp > ago(24h)
| where ActionType in ("CreateRemoteThreadApiCall", "WriteProcessMemoryApiCall", "ShellcodeInjection", "ProcessInjection")
| where InitiatingProcessFileName !in~ (
    "MsMpEng.exe", "SenseIR.exe", "SenseCncProxy.exe", "MsSense.exe",
    "csrss.exe", "lsass.exe", "services.exe", "svchost.exe",
    "WerFault.exe", "WerFaultSecure.exe"
  )
| project
    InjectionTime = Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessSHA256,
    ActionType,
    ProcessCommandLine;
let GitHubConnections = DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteUrl has_any ("github.com", "api.github.com", "raw.githubusercontent.com", "codeload.github.com")
| where InitiatingProcessFileName !in~ (
    "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe",
    "git.exe", "gh.exe", "Code.exe", "devenv.exe", "rider64.exe",
    "GitHubDesktop.exe", "SourceTree.exe"
  )
| project
    NetTime = Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessSHA256,
    RemoteUrl,
    RemoteIP;
InjectionEvents
| join kind=inner GitHubConnections on DeviceName, InitiatingProcessFileName
| where NetTime between ((InjectionTime - 30m) .. (InjectionTime + 30m))
| project
    InjectionTime,
    NetTime,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessSHA256,
    ActionType,
    RemoteUrl,
    RemoteIP,
    ProcessCommandLine
| order by InjectionTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Developer workstations running debuggers (e.g., WinDbg, x64dbg) that perform memory writes and also access GitHub.
- Security tools performing memory scanning that coincide with GitHub API calls from the same process.
- Software update agents that inject into processes and separately check GitHub release endpoints.

**Tuning notes:**
- Narrow the correlation window to 5-10 minutes if the environment has low developer GitHub activity.
- Add InitiatingProcessFolderPath not startswith conditions for 'C:\\Program Files' and 'C:\\Windows\\System32' to reduce noise from signed system binaries.
- Expand the developer tool exclusion list in GitHubConnections to match the software inventory of the environment.
- Consider adding a file signature check via DeviceFileCertificateInfo join on InitiatingProcessSHA256 to filter signed binaries.

**Risks / caveats:**
- ShellcodeInjection and ProcessInjection ActionType values in DeviceEvents require MDE Plan 2 with advanced hunting telemetry enabled; they may not appear in all environments.
- WriteProcessMemoryApiCall and CreateRemoteThreadApiCall availability depends on MDE sensor verbosity settings and may require specific API call auditing to be enabled.
- If ShellcodeInjection and ProcessInjection ActionTypes are not available in the environment, the injection leg will rely solely on CreateRemoteThreadApiCall and WriteProcessMemoryApiCall, which are noisier signals.
- The 30-minute bidirectional window is wide; on developer workstations with frequent GitHub access, spurious correlations are likely.

### Triage Runbook

**First 15 minutes:**
- Identify the initiating process name, path, and hash and determine whether it is signed, user-launched, or running from a writable location.
- Review the injection action type and target process to see whether the activity is consistent with malicious hollowing, remote thread creation, or memory tampering.
- Check for concurrent network connections from the same process or host to GitHub or other cloud services that may indicate staging or C2.
- Look for additional suspicious child processes, persistence artifacts, or security tool tampering on the same endpoint.

**Evidence to collect:**
- DeviceEvents for the injection telemetry, including action type, initiating process path, and hash.
- DeviceNetworkEvents for the same process and host to identify cloud service access or suspicious outbound traffic.
- DeviceFileEvents for recent writes in temp, app data, program data, or other writable paths.
- File reputation and certificate information for the initiating process hash if available.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceName and InitiatingProcessSHA256 to find related outbound connections.
- DeviceFileEvents for the same DeviceName and InitiatingProcessFileName to identify dropped modules or staging files.
- DeviceEvents for the same host to look for repeated injection, credential access, or security product interference.
- If available, DeviceImageLoadEvents or certificate data to determine whether the process is signed and what modules it loaded.

**Benign explanations:**
- Developer tools, debuggers, or test harnesses that legitimately perform memory writes or remote thread creation.
- Security products that scan or instrument processes and generate injection-like telemetry.
- Software updaters or enterprise agents that use process manipulation as part of normal operation.

**Escalation criteria:**
- The process is unsigned, runs from a user-writable path, or has no clear business justification.
- The same host shows suspicious cloud connections, dropped files, or additional malicious behavior.
- The target process is a security tool, browser, or system process and the injection is not expected.
- There is evidence of persistence, credential theft, or command execution beyond the injection event.

**Containment actions:**
- Isolate the host if the process is unknown or the injection is accompanied by suspicious network activity.
- Terminate the malicious process only after preserving evidence if the endpoint is actively compromised.
- Quarantine the file or block the hash if the process is confirmed malicious and the environment supports it.

**Closure criteria:**
- The process is identified as a known approved tool with a documented reason for injection-like behavior.
- No related suspicious network, file, or persistence activity is found on the host.
- The alert is attributable to a sanctioned security or development workflow and the hash/path is added to an allowlist if needed.
- The investigation confirms no compromise and the event is documented with supporting evidence.

<br/>
---
<br/>

## Detection 4: KUKURAT/PerfectPioneer RAT - Sustained UDP/443 QUIC Outbound from Non-Browser Process

### Detection Opportunity

RAT malware (PerfectPioneer or KUKURAT) communicating over HTTP/3 via QUIC protocol on UDP/443 from a non-browser process

### Intelligence Context

- Unit 42: QUIC and Covert: Novel HTTP/3-Powered RATs Target Southeast Asian Governments — [https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/](https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/)
  - Context: Unit 42 reported that PerfectPioneer RAT and modular KUKURAT use HTTP/3 over QUIC (UDP/443) as their C2 channel. This is detectable by identifying sustained outbound UDP/443 connections initiated by non-browser processes, which is anomalous outside of legitimate browser QUIC usage.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1071.001, T1095
- Products: Not specified
- Platforms: HTTP/3, QUIC
- Malware: PerfectPioneer RAT, KUKURAT
- Tools: Not specified
- Search tags: HTTP/3, QUIC, PerfectPioneer RAT, KUKURAT, T1071, T1071.001, T1095

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium); Command and Control: T1095 Non-Application Layer Protocol (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort == 443
| where Protocol == "Udp"
| where InitiatingProcessFileName !in~ (
    "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe",
    "iexplore.exe", "safari.exe",
    "MicrosoftEdgeUpdate.exe", "GoogleUpdate.exe",
    "Teams.exe", "Slack.exe", "Discord.exe", "zoom.exe",
    "ms-teams.exe"
  )
| summarize
    ConnectionCount = count(),
    DistinctRemoteIPs = dcount(RemoteIP),
    sample_RemoteIPs = make_set(RemoteIP, 10),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    InitiatingProcessFolderPath = take_any(InitiatingProcessFolderPath),
    InitiatingProcessSHA256 = take_any(InitiatingProcessSHA256)
    by DeviceName, InitiatingProcessFileName
| where ConnectionCount >= 5
| extend DurationMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| project
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessSHA256,
    ConnectionCount,
    DistinctRemoteIPs,
    sample_RemoteIPs,
    DurationMinutes,
    FirstSeen,
    LastSeen
| order by ConnectionCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Electron-based applications (Slack, Teams, Discord) that implement QUIC natively outside of the browser process.
- VPN or network overlay clients that use UDP/443 for tunneling.
- Game clients or streaming applications using QUIC for low-latency transport.
- Custom enterprise applications with embedded QUIC libraries.

**Tuning notes:**
- Validate Protocol field values for UDP/443 events in the environment before scheduling; consider removing the Protocol filter and relying solely on RemotePort == 443 with a non-TCP protocol check if Protocol is unreliable.
- Raise ConnectionCount threshold to 20 or higher after baselining non-browser UDP/443 activity in the environment.
- Add additional QUIC-capable enterprise applications to the exclusion list based on software inventory.
- Consider adding a filter for InitiatingProcessFolderPath not starting with standard application install paths to reduce noise from legitimate software.

**Risks / caveats:**
- The Protocol field in DeviceNetworkEvents may not be populated as 'Udp' for QUIC connections on all MDE sensor versions; validate that UDP/443 events appear with Protocol == 'Udp' in the target environment before relying on this filter.
- Protocol field population for QUIC/UDP events must be validated in the target environment; if the field is absent or uses a different value, the query returns no results.
- The ConnectionCount threshold of 5 is a starting point; environments with non-browser QUIC applications will require a higher threshold.
- take_any() for InitiatingProcessFolderPath and InitiatingProcessSHA256 returns one representative value per group; if the process has multiple instances with different paths, only one is surfaced.

### Triage Runbook

**First 15 minutes:**
- Confirm the initiating process is not a browser or approved QUIC-capable enterprise application.
- Review the process path and hash to determine whether it is signed, user-installed, or running from an unusual location.
- Inspect the destination IP set and connection duration to see whether the traffic is sustained beaconing rather than a one-off connection.
- Check for other suspicious activity on the host such as process injection, persistence, or file drops that would support malware execution.

**Evidence to collect:**
- DeviceNetworkEvents showing the UDP/443 connections, destination IPs, and duration pattern.
- Process metadata for the initiating binary, including path, hash, and parent process.
- Recent DeviceFileEvents and DeviceProcessEvents on the same host to identify staging, persistence, or follow-on execution.
- Any proxy, firewall, or DNS telemetry that can confirm whether the destination is external and unusual.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceName and InitiatingProcessSHA256 to identify all remote destinations and frequency.
- DeviceProcessEvents for the same host to find suspicious parent-child chains or command lines.
- DeviceFileEvents for the same host to look for dropped executables, scripts, or autoruns.
- If available, DeviceRegistryEvents or scheduled task data to check for persistence mechanisms.

**Benign explanations:**
- Legitimate Electron-based or collaboration applications that use QUIC outside the browser process.
- VPN, overlay, gaming, or streaming clients that use UDP/443 for low-latency transport.
- Enterprise software with embedded QUIC libraries that has been approved in the environment.

**Escalation criteria:**
- The process is unknown, unsigned, or running from a user-writable or temporary directory.
- The destination IPs are external and not associated with an approved application or vendor.
- There is corroborating evidence of malware behavior such as persistence, injection, or suspicious file creation.
- The connection pattern is sustained and repeated across multiple intervals with no business justification.

**Containment actions:**
- Isolate the host if the process is unapproved or additional malware indicators are present.
- Block the suspicious destination IPs or domains if they are confirmed malicious and not business-critical.
- Collect the binary and preserve network evidence before remediation or reimaging.

**Closure criteria:**
- The process is confirmed as an approved QUIC-capable application and the traffic matches expected behavior.
- The destination IPs are validated as legitimate vendor or enterprise endpoints.
- No additional compromise indicators are found on the host.
- The event is documented and the allowlist or threshold is adjusted if this is a recurring benign pattern.

<br/>
---
<br/>

## Detection 5: GraphDoor Backdoor - Cloud API Access from Non-Standard Process (Operation ShadowCloud)

### Detection Opportunity

GraphDoor backdoor making outbound connections to cloud service API endpoints (such as Microsoft Graph) from non-standard or unsigned processes outside expected enterprise tooling

### Intelligence Context

- Securelist: Operation ShadowCloud: cloud service-based backdoors targeting government networks in Asia and Africa. Part 2 — [https://securelist.com/operation-shadowcloud-graphdoor/122005/](https://securelist.com/operation-shadowcloud-graphdoor/122005/)
  - Context: Securelist analyzed the GraphDoor backdoor as part of Operation ShadowCloud, which uses cloud services for C2. The backdoor name and campaign context strongly suggest use of Microsoft Graph API or similar cloud service endpoints as C2 channels, detectable by correlating cloud API network connections from unexpected initiating processes with subsequent plugin module loads from writable paths.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1102, T1102.001, T1071, T1071.001
- Products: Not specified
- Platforms: cloud services
- Malware: GraphDoor
- Tools: Not specified
- Search tags: cloud services, GraphDoor, T1102, T1102.001, T1071, T1071.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1102 Web Service/ T1102.001 Dead Drop Resolver (low); Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents, DeviceFileEvents

### KQL

```kql
let CloudC2 = DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteUrl has_any (
    "graph.microsoft.com",
    "graph.windows.net",
    "onedrive.live.com",
    "sharepoint.com",
    "1drv.ms"
  )
| where InitiatingProcessFileName !in~ (
    "onedrive.exe", "OneDriveSetup.exe",
    "Teams.exe", "ms-teams.exe",
    "outlook.exe", "olk.exe",
    "msedge.exe", "chrome.exe", "firefox.exe",
    "MicrosoftEdgeUpdate.exe",
    "svchost.exe",
    "powershell.exe", "pwsh.exe",
    "MicrosoftTeams.exe"
  )
| project
    C2Time = Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessSHA256,
    RemoteUrl;
let PluginLoad = DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath has_any (
    "\\Temp\\",
    "\\AppData\\Local\\",
    "\\AppData\\Roaming\\",
    "\\ProgramData\\"
  )
| where FolderPath !has "\\Microsoft\\Windows\\INetCache\\"
| where FileName endswith ".dll"
    or FileName endswith ".dat"
    or FileName endswith ".bin"
| project
    FileTime = Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    FileName,
    FolderPath,
    ActionType;
CloudC2
| join kind=inner PluginLoad on DeviceName, InitiatingProcessFileName
| where FileTime between (C2Time .. (C2Time + 1h))
| project
    C2Time,
    FileTime,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessSHA256,
    RemoteUrl,
    FileName,
    FolderPath,
    ActionType
| order by C2Time desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Enterprise applications with embedded Microsoft Graph SDK that write plugin or configuration files to AppData during normal operation.
- Software deployment agents that download components from OneDrive or SharePoint and write them to ProgramData.
- Security tools that access Graph API for identity enrichment and write cached data to local writable paths.
- Custom scripts or automation tools that use Graph API and write output files to Temp directories.

**Tuning notes:**
- Expand the InitiatingProcessFileName exclusion list to include all enterprise tools in the environment that legitimately access Microsoft Graph.
- Add additional FolderPath exclusions for known software installer and update staging directories to reduce noise.
- Consider joining with DeviceFileCertificateInfo on InitiatingProcessSHA256 to filter signed binaries from the cloud C2 leg.
- If RemoteUrl is frequently null in the environment, consider supplementing with RemoteIP-based filtering using known Microsoft Graph IP ranges as an alternative signal.

**Risks / caveats:**
- RemoteUrl field in DeviceNetworkEvents is not always populated for all connection types; connections resolved via IP without a URL may not match the has_any filter, causing the cloud C2 leg to miss events.
- The Microsoft Graph API C2 channel is inferred from the backdoor name and campaign context; if GraphDoor uses a different cloud endpoint, this query will not detect it.
- RemoteUrl may be null for connections where DNS resolution is not captured by the MDE sensor, causing legitimate GraphDoor C2 connections to be missed.
- The 1-hour forward window may miss plugin loads that occur after a longer sleep interval.

### Triage Runbook

**First 15 minutes:**
- Verify the initiating process is not a known enterprise tool, browser, or approved Microsoft 365 client.
- Review the remote URL and process path to determine whether the cloud API access is consistent with normal business use or suspicious automation.
- Inspect the file write activity for newly created or modified DLL, DAT, or BIN files in writable locations that could indicate plugin staging.
- Check whether the same host shows other suspicious activity such as persistence, injection, or unusual outbound connections.

**Evidence to collect:**
- DeviceNetworkEvents for the cloud API access, including RemoteUrl, process path, and hash.
- DeviceFileEvents for the same host and time window to identify plugin or staging file creation.
- Process metadata for the initiating binary, including parent process and command line.
- If available, certificate and reputation data for the initiating process hash and any written files.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceName and InitiatingProcessSHA256 to find all cloud endpoints contacted.
- DeviceFileEvents for the same host to identify additional files written to temp, app data, or program data.
- DeviceProcessEvents for the same host to look for suspicious child processes or script execution.
- If available, identity or cloud audit logs to determine whether the API access aligns with a legitimate account or application registration.

**Benign explanations:**
- Legitimate enterprise software, MDM agents, or collaboration tools that use Microsoft Graph or related cloud APIs.
- Approved automation or scripting that downloads components and writes cache or plugin files to writable directories.
- Security or identity tools that query cloud APIs for enrichment or synchronization.

**Escalation criteria:**
- The process is unsigned, unknown, or running from an unusual writable path.
- The cloud API access is paired with suspicious file writes, especially to temp or app data locations.
- The host shows additional indicators of compromise such as persistence, injection, or suspicious outbound traffic.
- The remote URL or process behavior does not match any approved enterprise application or automation.

**Containment actions:**
- Isolate the host if the process is unapproved and the file writes suggest active malware staging.
- Block the process hash or quarantine the written files if confirmed malicious.
- Preserve the binary, written files, and network evidence before remediation.

**Closure criteria:**
- The process is identified as an approved enterprise tool with a documented business purpose.
- The file writes are confirmed to be legitimate cache, installer, or plugin activity.
- No additional suspicious network or host behavior is found.
- The event is documented and any necessary allowlist updates are made.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- CVE-2026-90436 Exploitation Attempt - Inbound Network Connection to Confluence or N-central Followed by Outbound Callback: Do not schedule yet; validate as an analyst-led hunt first.
- GitDoor Backdoor - Shellcode Injection or Memory Allocation by Unknown Process (Operation ShadowCloud): Do not schedule yet; validate as an analyst-led hunt first.
- KUKURAT/PerfectPioneer RAT - Sustained UDP/443 QUIC Outbound from Non-Browser Process: Do not schedule yet; validate as an analyst-led hunt first.
- GraphDoor Backdoor - Cloud API Access from Non-Standard Process (Operation ShadowCloud): Do not schedule yet; validate as an analyst-led hunt first.

**Environment scope / baselines:**
- GitDoor Backdoor - Shellcode Injection or Memory Allocation by Unknown Process (Operation ShadowCloud): If ShellcodeInjection and ProcessInjection ActionTypes are not available in the environment, the injection leg will rely solely on CreateRemoteThreadApiCall and WriteProcessMemoryApiCall, which are noisier signals.

**Shared-table notes:**
- DeviceNetworkEvents: shared by CVE-2026-90436 Exploitation Attempt - Inbound Network Connection to Confluence or N-central Followed by Outbound Callback; GitDoor Backdoor - Shellcode Injection or Memory Allocation by Unknown Process (Operation ShadowCloud); KUKURAT/PerfectPioneer RAT - Sustained UDP/443 QUIC Outbound from Non-Browser Process; GraphDoor Backdoor - Cloud API Access from Non-Standard Process (Operation ShadowCloud)

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: CVE-2026-90436 RCE - Suspicious Child Process Spawned by Java Web Service Account.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: CVE-2026-90436 Exploitation Attempt - Inbound Network Connection to Confluence or N-central Followed by Outbound Callback; GitDoor Backdoor - Shellcode Injection or Memory Allocation by Unknown Process (Operation ShadowCloud); KUKURAT/PerfectPioneer RAT - Sustained UDP/443 QUIC Outbound from Non-Browser Process; GraphDoor Backdoor - Cloud API Access from Non-Standard Process (Operation ShadowCloud).

### Hunting Agenda and Promotion Criteria

- CVE-2026-90436 Exploitation Attempt - Inbound Network Connection to Confluence or N-central Followed by Outbound Callback: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- GitDoor Backdoor - Shellcode Injection or Memory Allocation by Unknown Process (Operation ShadowCloud): Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- KUKURAT/PerfectPioneer RAT - Sustained UDP/443 QUIC Outbound from Non-Browser Process: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- GraphDoor Backdoor - Cloud API Access from Non-Standard Process (Operation ShadowCloud): Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
