---
layout: post
title: "Detection Engineering Brief - Thursday, November 12, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-11-12
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - GSocket
  - Linux
  - Falcon C2
  - Antino
  - Windows
  - CVE-2026-102895
  - GPUStack
  - Citrus Ransomware
  - Sn00py
  - T1095
  - T1547
  - T1176
  - T1547.015
  - T1190
  - T1486
  - T1485
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

2 production candidates, 2 hunting-only, 1 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: GSocket, Linux, Falcon C2, Antino, Windows, CVE-2026-102895, GPUStack, Citrus Ransomware, Sn00py, T1095, T1547, T1176, T1547.015, T1190, T1486, T1485.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: GSocket Binary Execution on Linux Host; GSocket Outbound C2 Connection Persisting After Patch Window; GPUStack Authentication Bypass Exploit Attempt (CVE-2026-102895).

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: GSocket Binary Execution on Linux Host

### Detection Opportunity

Deploying GSocket binary on compromised Linux servers for persistent encrypted remote access.

### Intelligence Context

- Microsoft Security Blog: The global socket: how threat actors are weaponizing GSocket for stealthy C2 — [https://www.microsoft.com/en-us/security/blog/2026/11/11/global-socket-how-threat-actors-weaponizing-gsocket-stealthy-c2/](https://www.microsoft.com/en-us/security/blog/2026/11/11/global-socket-how-threat-actors-weaponizing-gsocket-stealthy-c2/)
  - Context: Threat actors deployed GSocket binaries on compromised Linux servers to maintain encrypted remote access channels that persist after the original vulnerability is patched.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1095, T1547
- Products: Not specified
- Platforms: Linux
- Malware: Not specified
- Tools: GSocket
- Search tags: GSocket, Linux, T1095, T1547

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Both
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1095 Non-Application Layer Protocol (high); Persistence: T1547 Boot or Logon Autostart Execution (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents, Syslog

### KQL

```kql
let lookback = 1d;
let gsocket_names = dynamic(["gs-netcat", "gsocket", "gs-sftp", "gs-mount"]);
let gsocket_procs = DeviceProcessEvents
| where TimeGenerated >= ago(lookback)
| where FileName in~ (gsocket_names)
    or ProcessCommandLine has_any (gsocket_names)
| project DeviceName, ProcessTime = TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName;
let gsocket_net = DeviceNetworkEvents
| where TimeGenerated >= ago(lookback)
| where InitiatingProcessFileName in~ (gsocket_names)
    or InitiatingProcessCommandLine has_any (gsocket_names)
| project DeviceName, NetTime = TimeGenerated, RemoteIP, RemotePort, InitiatingProcessFileName;
let mde_hits = gsocket_procs
| join kind=inner gsocket_net on DeviceName
| where NetTime >= ProcessTime and NetTime <= ProcessTime + 5m
| project
    Source = "MDE",
    TimeGenerated = ProcessTime,
    DeviceName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    AccountName,
    RemoteIP,
    RemotePort;
let syslog_hits = Syslog
| where TimeGenerated >= ago(lookback)
| where SyslogMessage has_any (gsocket_names)
| project
    Source = "Syslog",
    TimeGenerated,
    DeviceName = Computer,
    FileName = "",
    ProcessCommandLine = "",
    InitiatingProcessFileName = "",
    AccountName = "",
    RemoteIP = "",
    RemotePort = int(null),
    SyslogMessage
| extend RemotePort = toint(RemotePort);
union mde_hits, syslog_hits
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate use of GSocket by security researchers or network engineers on Linux hosts.
- Syslog messages containing the string 'gsocket' in unrelated contexts such as log file paths or configuration references.

**Tuning notes:**
- Extend the 5-minute NetTime window if GSocket startup latency in the environment exceeds that threshold.
- Extend lookback beyond 1 day for broader hunting sweeps.
- Add known-good GSocket users (security team hosts) to an exclusion list by DeviceName if legitimate use exists.

**Risks / caveats:**
- Syslog free-text matching for GSocket process execution depends on auditd or execve syslog forwarding being configured on Linux hosts; if only standard syslog daemons are forwarded, process execution events will not appear in SyslogMessage.
- DeviceNetworkEvents.InitiatingProcessCommandLine field availability on Linux MDE agents should be verified; it is not guaranteed to be populated for all Linux kernel versions and agent versions.
- The 5-minute correlation window between process start and network connection may miss GSocket instances that delay outbound connection establishment beyond that window.
- The Syslog branch produces no structured process or network fields; hits require manual log review.

### Triage Runbook

**First 15 minutes:**
- Identify the host, user, and process lineage from the alert; confirm whether the execution came from a shell, cron, service, or another parent process.
- Check whether the same host shows outbound connections from the GSocket process and whether those connections are to unfamiliar or external IPs.
- Correlate the first and last seen times with patching, maintenance, or change windows to see if the activity persisted after remediation.
- Look for repeated execution across multiple days or repeated network sessions from the same binary name or command line.

**Evidence to collect:**
- Process command line, parent process, account name, and execution timestamps for the GSocket binary.
- Remote IPs, ports, and connection frequency associated with the process.
- Any Linux syslog/auditd entries showing how the binary was launched or whether it was installed as a service, cron job, or startup script.
- Host context: recent patch status, admin activity, and whether the system is internet-facing.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and FileName/process command line over the last 7 days.
- DeviceNetworkEvents for the same DeviceName and initiating process fields to identify remote IPs and repeated sessions.
- Syslog for the host to find service creation, cron changes, shell history, or audit events referencing gsocket or related names.
- If available, pivot to other hosts using the same account name or remote IPs to determine spread or reuse.

**Benign explanations:**
- Security research, red-team activity, or approved remote administration using GSocket on a lab or engineering host.
- A legitimate troubleshooting session by a network or platform engineer using a known GSocket binary.
- A false positive from syslog text containing 'gsocket' in a path, config, or log reference rather than actual execution.

**Escalation criteria:**
- Escalate immediately if the host is production, internet-facing, or shows repeated GSocket execution after patching.
- Escalate if the process is associated with an unknown account, suspicious parent process, or outbound connections to unrecognized external IPs.
- Escalate if the binary is not approved, the host owner cannot explain it, or there is evidence of persistence such as cron, systemd, or startup script use.

**Containment actions:**
- If unauthorized, isolate the Linux host from the network while preserving evidence.
- Terminate the GSocket process only after capturing process details and confirming the host is not part of an approved admin workflow.
- Block or restrict the observed remote IPs at the perimeter if they are clearly malicious and not business-related.
- Disable or reset the involved account if there is evidence of unauthorized use.

**Closure criteria:**
- Confirmed approved use by a known team with matching change ticket or maintenance record.
- No suspicious persistence, no unauthorized remote access, and network activity matches expected admin behavior.
- The binary, account, and remote endpoints are validated as legitimate and documented for future allowlisting if needed.

<br/>
---
<br/>

## Detection 2: GSocket Outbound C2 Connection Persisting After Patch Window

### Detection Opportunity

GSocket maintaining encrypted C2 channel via outbound network connections after the original vulnerability was remediated.

### Intelligence Context

- Microsoft Security Blog: The global socket: how threat actors are weaponizing GSocket for stealthy C2 — [https://www.microsoft.com/en-us/security/blog/2026/11/11/global-socket-how-threat-actors-weaponizing-gsocket-stealthy-c2/](https://www.microsoft.com/en-us/security/blog/2026/11/11/global-socket-how-threat-actors-weaponizing-gsocket-stealthy-c2/)
  - Context: Threat actors maintained GSocket-based encrypted C2 access on Linux servers even after the original exploited vulnerability was patched, indicating deliberate persistence beyond initial compromise.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1095, T1547
- Products: Not specified
- Platforms: Linux
- Malware: Not specified
- Tools: GSocket
- Search tags: GSocket, Linux, T1095, T1547

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1095 Non-Application Layer Protocol (high); Persistence: T1547 Boot or Logon Autostart Execution (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let lookback = 7d;
let gsocket_names = dynamic(["gs-netcat", "gsocket", "gs-sftp", "gs-mount"]);
let gsocket_exec = DeviceProcessEvents
| where TimeGenerated >= ago(lookback)
| where FileName in~ (gsocket_names)
    or ProcessCommandLine has_any (gsocket_names)
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    ExecCount = count(),
    DistinctDays = dcount(bin(TimeGenerated, 1d)),
    AccountName = any(AccountName)
    by DeviceName, FileName, ProcessCommandLine;
let gsocket_net = DeviceNetworkEvents
| where TimeGenerated >= ago(lookback)
| where InitiatingProcessFileName in~ (gsocket_names)
    or InitiatingProcessCommandLine has_any (gsocket_names)
| summarize
    NetCount = count(),
    DistinctRemoteIPs = dcount(RemoteIP),
    SampleRemoteIPs = make_set(RemoteIP, 5)
    by DeviceName, InitiatingProcessFileName;
gsocket_exec
| join kind=inner gsocket_net on DeviceName
| extend DaySpan = datetime_diff('day', LastSeen, FirstSeen)
| where ExecCount > 1 or DistinctDays > 1
| project
    DeviceName,
    FileName,
    ProcessCommandLine,
    AccountName,
    FirstSeen,
    LastSeen,
    DaySpan,
    DistinctDays,
    ExecCount,
    NetCount,
    DistinctRemoteIPs,
    SampleRemoteIPs
| sort by DistinctDays desc, ExecCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate GSocket use by network engineers or security teams running repeated sessions.
- Automated scripts invoking GSocket binaries for legitimate tunneling in environments where GSocket is an approved tool.

**Tuning notes:**
- Extend lookback beyond 7 days if patch cycles in the environment exceed one week.
- Raise ExecCount threshold above 1 if GSocket is legitimately used and single-day repeated invocations are expected.
- Filter by DistinctDays > 1 exclusively if single-day burst activity from legitimate tools generates noise at the ExecCount > 1 threshold.

**Risks / caveats:**
- DeviceNetworkEvents.InitiatingProcessCommandLine field population on Linux MDE agents is not guaranteed across all agent versions; if unpopulated, the network-side filter will rely solely on InitiatingProcessFileName.
- The query cannot independently confirm post-patch persistence; analyst must correlate FirstSeen/LastSeen against patch management records.
- A 7-day lookback may not cover environments with patch cycles longer than one week.
- Summarization by ProcessCommandLine may split results for the same binary invoked with different arguments, inflating ExecCount.

### Triage Runbook

**First 15 minutes:**
- Verify the patch timeline for the affected host and compare it to the first and last GSocket execution times.
- Check whether outbound connections are still occurring now or whether the alert reflects historical activity only.
- Review the initiating process and account context to determine whether the activity is tied to a known admin workflow or an unknown user/process.
- Look for evidence of repeated sessions across multiple days or multiple remote IPs from the same host.

**Evidence to collect:**
- FirstSeen, LastSeen, ExecCount, DistinctDays, and any sample remote IPs from the alert.
- Process command line, initiating process name, and account name for the GSocket execution.
- Patch management records, maintenance tickets, and host ownership information.
- Any related network telemetry showing ongoing encrypted outbound connections from the host.

**Pivot points:**
- DeviceProcessEvents for the host to identify all GSocket-related executions and their parent processes.
- DeviceNetworkEvents for the host to enumerate remote IPs, ports, and session frequency tied to the initiating process.
- Change management or patch records to confirm whether activity continued after remediation.
- If available, pivot to other hosts using the same account or same remote IPs to identify broader compromise.

**Benign explanations:**
- Authorized remote administration or troubleshooting that legitimately uses GSocket across multiple days.
- A long-running maintenance session that spans patch windows and is documented by the operations team.
- Repeated execution caused by an automation script or service wrapper in an approved environment.

**Escalation criteria:**
- Escalate if the host is patched but GSocket activity continues afterward without a documented business reason.
- Escalate if the host shows multiple days of activity, repeated outbound sessions, or unknown remote IPs.
- Escalate if the account or parent process is suspicious, or if the host is a server with no approved GSocket use.

**Containment actions:**
- Isolate the host if unauthorized post-patch activity is confirmed.
- Block the observed remote IPs or domains if they are clearly malicious and not required for business operations.
- Disable the involved account or remove the unauthorized service, cron entry, or startup mechanism after evidence capture.
- Preserve volatile evidence before rebooting or reimaging the system.

**Closure criteria:**
- Patch timeline and host activity align with an approved maintenance or admin workflow.
- No ongoing outbound GSocket sessions are present and no persistence mechanism is found.
- The activity is documented as legitimate and, if necessary, added to an approved exception list.

<br/>
---
<br/>

## Detection 3: Malicious Browser Extension Written to Profile Directory Outside Update Process

### Detection Opportunity

Loading malicious browser extensions as part of the Falcon C2 compromise chain targeting Windows hosts.

### Intelligence Context

- Unit 42: The XG Files: Falcon C2 Flying Under The (Browser) Radar — [https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/](https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/)
  - Context: Falcon C2 targeted government entities by deploying malicious browser extensions and the Antino implant as part of a browser-based compromise chain on Windows systems.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1176, T1547.015, T1547
- Products: Not specified
- Platforms: Windows
- Malware: Not specified
- Tools: Falcon C2, Antino
- Search tags: Falcon C2, Antino, Windows, T1176, T1547.015, T1547

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1176 Browser Session Hijacking (medium); Persistence: T1547 Boot or Logon Autostart Execution/ T1547.015 Browser Session Hijacking (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
DeviceFileEvents
| where TimeGenerated >= ago(7d)
| where ActionType in ("FileCreated", "FileModified")
| where (
    FileName in~ ("manifest.json", "background.js", "content.js")
    or FolderPath contains "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\"
    or FolderPath contains "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Extensions\\"
    or FolderPath contains "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\"
)
| where InitiatingProcessFileName !in~ (
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "GoogleUpdate.exe",
    "MicrosoftEdgeUpdate.exe",
    "setup.exe",
    "msiexec.exe"
)
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    FolderPath,
    FileName,
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ActionType
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Enterprise extension deployment via GPO or MDM using a management agent process not in the exclusion list.
- Developer workstations where extensions are manually loaded from local directories using non-browser processes.
- Software packaging tools that unpack browser extension bundles as part of application installation.

**Tuning notes:**
- Add enterprise extension deployment agent process names to the InitiatingProcessFileName exclusion list if managed extension pushes generate false positives.
- Narrow FileName filter to manifest.json only if background.js and content.js generate excessive volume from legitimate web application caching.
- Consider adding a DeviceType or DeviceTag filter to exclude developer workstations if they generate high volumes of legitimate extension file writes.

**Risks / caveats:**
- DeviceFileEvents coverage of AppData paths depends on MDE file monitoring policy; if file monitoring is scoped to exclude user profile directories, writes to extension paths will not appear.
- Enterprise extension management processes (MDM agents, GPO enforcement tools, custom deployment scripts) may not be covered by the default exclusion list and will require environment-specific additions.
- The query matches on FolderPath substring for extension directories; deeply nested subdirectory paths within extension folders will also match, which is the intended behavior but increases result volume on active developer machines.
- SHA256 may be empty for some file write events depending on MDE agent version and file size thresholds.

### Triage Runbook

**First 15 minutes:**
- Identify the browser profile path, file names, and initiating process to confirm whether the write came from a browser, updater, installer, or unknown process.
- Check whether the extension files were created or modified in a user profile directory without a corresponding browser update event.
- Determine whether the affected user is a standard user, developer, or administrator and whether extension deployment is expected on this device.
- Assess whether the extension files are still present and whether the browser is currently running on the host.

**Evidence to collect:**
- DeviceFileEvents details: file name, folder path, SHA256, initiating process, account name, and timestamps.
- Browser profile path and extension directory contents, including manifest.json and related JavaScript files.
- User context and any recent software deployment or MDM/GPO activity that could explain the write.
- If available, browser history, installed extension inventory, and any related process tree around the file write.

**Pivot points:**
- DeviceFileEvents for the same DeviceName and AccountName to find other extension-related writes or modifications.
- DeviceProcessEvents to identify the parent process that wrote the files and any follow-on browser launches.
- DeviceNetworkEvents or browser telemetry, if available, to see whether the browser contacted suspicious domains after the write.
- Search across other hosts for the same SHA256 or same folder path pattern to determine whether this is widespread.

**Benign explanations:**
- Legitimate enterprise extension deployment through GPO, MDM, or a software packaging tool not covered by the exclusion list.
- Developer activity on a test machine where extensions are manually loaded or unpacked for testing.
- A browser updater or installer writing extension files during a normal update cycle that was not fully excluded.

**Escalation criteria:**
- Escalate if the initiating process is not a known browser, updater, or approved deployment tool.
- Escalate if the extension files are present in a user profile and there is no approved deployment record.
- Escalate if the same extension artifacts appear on multiple hosts or if the user reports unexpected browser behavior.

**Containment actions:**
- Disable or remove the suspicious extension from the affected browser profile if confirmed malicious.
- Isolate the host if the extension appears tied to active compromise or credential theft.
- Reset browser sessions and credentials for the affected user if the extension may have captured authentication data.
- Block the associated file hash or deployment mechanism if it is confirmed malicious.

**Closure criteria:**
- The file writes are explained by an approved deployment, update, or developer workflow.
- No suspicious extension remains installed or active in the browser profile.
- The SHA256, path, and initiating process are documented as benign or added to an exception list if appropriate.

<br/>
---
<br/>

## Detection 4: GPUStack Authentication Bypass Exploit Attempt (CVE-2026-102895)

### Detection Opportunity

Exploitation attempts targeting the GPUStack authentication bypass vulnerability, followed by successful access to the management interface.

### Intelligence Context

- SANS ISC: Exploit Attempts for GPUStack Authentication Bypass (CVE-2026-102895), (Thu, Nov 12th) — [https://isc.sans.edu/diary/rss/33514](https://isc.sans.edu/diary/rss/33514)
  - Context: Active exploitation attempts against CVE-2026-102895, a trivial authentication bypass in GPUStack, were observed targeting management interfaces. Successful bypass grants unauthorized admin access.

### Search Metadata

- CVEs: CVE-2026-102895
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: GPUStack
- Platforms: Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-102895, GPUStack, Linux, T1190

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- CommonSecurityLog does not natively receive GPUStack logs; a custom syslog forwarder or connector must be deployed and configured to map GPUStack HTTP log fields to RequestURL, ResponseCode, and SourceIP in the CommonSecurityLog schema.

**Required telemetry:**
- CommonSecurityLog, Syslog

### KQL

```kql
let lookback = 1d;
let gpustack_errors = CommonSecurityLog
| where TimeGenerated >= ago(lookback)
| where RequestURL has_any ("/api/", "/admin", "/v1/")
| where tostring(ResponseCode) in ("401", "403")
| summarize
    ErrorCount = count(),
    FirstError = min(TimeGenerated),
    LastError = max(TimeGenerated)
    by SourceIP, DeviceName;
let gpustack_success = CommonSecurityLog
| where TimeGenerated >= ago(lookback)
| where RequestURL has_any ("/api/", "/admin", "/v1/")
| where tostring(ResponseCode) == "200"
| summarize
    SuccessCount = count(),
    FirstSuccess = min(TimeGenerated)
    by SourceIP, DeviceName;
let csl_hits = gpustack_errors
| join kind=inner gpustack_success on SourceIP, DeviceName
| where FirstSuccess > LastError
| where ErrorCount >= 3
| project
    Source = "CommonSecurityLog",
    TimeGenerated = FirstSuccess,
    DeviceName,
    SourceIP,
    ErrorCount,
    FirstError,
    LastError,
    SuccessCount,
    FirstSuccess;
let syslog_hits = Syslog
| where TimeGenerated >= ago(lookback)
| where SyslogMessage has "gpustack"
    and SyslogMessage has_any ("401", "403", "bypass", "unauthorized")
| project
    Source = "Syslog",
    TimeGenerated,
    DeviceName = Computer,
    SourceIP = "",
    ErrorCount = int(null),
    FirstError = datetime(null),
    LastError = datetime(null),
    SuccessCount = int(null),
    FirstSuccess = datetime(null),
    SyslogMessage;
union csl_hits, syslog_hits
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrators who mistype credentials multiple times before successfully authenticating.
- Automated health check or monitoring scripts that probe the API and then authenticate successfully.

**Tuning notes:**
- Validate that RequestURL path prefixes match the actual GPUStack API routes in the deployed version before scheduling.
- Adjust ErrorCount threshold based on observed legitimate authentication failure rates for GPUStack admin users.
- Extend lookback to 7 days for broader hunting if exploit attempts are expected to be low-and-slow.

**Risks / caveats:**
- CommonSecurityLog does not natively receive GPUStack logs; a custom syslog forwarder or connector must be deployed and configured to map GPUStack HTTP log fields to RequestURL, ResponseCode, and SourceIP in the CommonSecurityLog schema.
- ResponseCode in CommonSecurityLog is typed as string in some connector implementations and as integer in others; the query uses integer comparison (401, 403, 200) which will fail if the field is ingested as string.
- The Syslog branch relies on GPUStack emitting log lines containing the literal string 'gpustack' alongside HTTP status codes; this is log-format-dependent and not guaranteed across GPUStack versions.
- RequestURL path prefixes (/api/, /admin, /v1/) are assumed to match GPUStack management endpoints; actual path structure must be confirmed against the deployed GPUStack version.

### Triage Runbook

**First 15 minutes:**
- Verify whether the source IP is external, unfamiliar, or associated with scanning activity.
- Check the sequence of errors and success to confirm the success followed the failure burst and was not a normal login retry.
- Determine whether the target GPUStack instance is internet-facing and whether the affected endpoint is a management/admin route.
- Assess whether any administrative actions, configuration changes, or new sessions occurred immediately after the successful request.

**Evidence to collect:**
- Source IP, request URLs, response codes, and timestamps for the error and success sequence.
- GPUStack access logs or forwarded syslog entries showing the exact endpoints accessed.
- Authentication and admin activity around the same time, including any new sessions or configuration changes.
- Host and service exposure details: whether the interface is public, proxied, or restricted to internal networks.

**Pivot points:**
- CommonSecurityLog for the same SourceIP and DeviceName to find additional requests, user agents, or repeated attempts.
- Syslog for GPUStack-related messages if the CommonSecurityLog branch is incomplete or unavailable.
- Firewall, reverse proxy, or load balancer logs to confirm whether the source IP reached the management interface directly.
- If available, pivot to other services targeted by the same source IP to determine whether this is part of broader scanning.

**Benign explanations:**
- A legitimate administrator mistyping credentials several times before successfully logging in.
- An automated health check or monitoring tool that probes the interface and then authenticates successfully.
- A test or validation activity performed by an internal security team against a lab or staging system.

**Escalation criteria:**
- Escalate immediately if the source IP is external and the success event indicates unauthorized access to the management interface.
- Escalate if there are post-success administrative actions, new accounts, or configuration changes.
- Escalate if the GPUStack instance is internet-facing and the activity is not tied to a known internal user or change ticket.

**Containment actions:**
- Restrict access to the GPUStack management interface to trusted networks or temporarily disable external exposure.
- Block the source IP if it is clearly malicious and not a business partner or internal scanner.
- Force credential resets or session invalidation if unauthorized access is suspected.
- Preserve logs before making changes so the exploit sequence remains available for investigation.

**Closure criteria:**
- The source activity is confirmed as legitimate admin or monitoring traffic with supporting records.
- No unauthorized access, configuration change, or follow-on activity is found.
- Exposure is reduced or access controls are updated if the interface was unnecessarily reachable.

<br/>
---
<br/>

## Detection 5: Sn00py Ransomware Mass File Encryption Activity

### Detection Opportunity

Mass file encryption activity consistent with the Sn00py encryption component of Citrus Ransomware performing high-rate file modification across multiple directories.

### Intelligence Context

- Securelist: Citrus Ransomware: VLESS for traffic, Sn00py for encryption, and LLMs lending a hand — [https://securelist.com/citrus-ransomware/121879/](https://securelist.com/citrus-ransomware/121879/)
  - Context: Citrus Ransomware uses the Sn00py component to perform mass file encryption across victim systems. High-rate file rename and overwrite operations across multiple directories are the primary behavioral signature of this encryption stage.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1486, T1485
- Products: Not specified
- Platforms: Windows, Linux
- Malware: Citrus Ransomware
- Tools: Sn00py
- Search tags: Citrus Ransomware, Sn00py, Windows, Linux, T1486, T1485

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Impact: T1486 Data Encrypted for Impact (high); Impact: T1485 Data Destruction (low)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
let window = 5m;
let windowedEvents = DeviceFileEvents
| where TimeGenerated >= ago(1h)
| where ActionType in ("FileRenamed", "FileModified", "FileCreated")
| where not (
    FolderPath startswith @"C:\Windows\"
    or FolderPath startswith @"C:\Program Files\"
    or FolderPath startswith @"C:\Program Files (x86)\"
    or FolderPath startswith "/proc/"
    or FolderPath startswith "/sys/"
    or FolderPath startswith "/run/"
    or FolderPath startswith "/dev/"
);
windowedEvents
| summarize
    FileCount = count(),
    DistinctFolders = dcount(FolderPath),
    SampleFiles = make_set(FileName, 5),
    AccountName = any(AccountName),
    InitiatingProcessCommandLine = any(InitiatingProcessCommandLine)
    by DeviceName, InitiatingProcessFileName, bin(TimeGenerated, window)
| where FileCount > 100 and DistinctFolders > 5
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileCount,
    DistinctFolders,
    SampleFiles
| sort by FileCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Backup agents performing scheduled full backups that read and rewrite large numbers of files across multiple directories.
- Antivirus or EDR remediation processes that rename or quarantine large numbers of files simultaneously.
- File migration or bulk copy utilities run by administrators.
- Indexing services such as Windows Search or Elasticsearch performing bulk file operations.

**Tuning notes:**
- Raise FileCount threshold above 100 if backup or antivirus processes trigger the rule during scheduled operations.
- Add known backup agent and indexer process names to a not in exclusion on InitiatingProcessFileName after baselining.
- Reduce the bin window from 5 minutes to 2 minutes if the environment shows that ransomware encryption completes faster than the current window captures.
- Schedule this rule to run every 5 minutes with a 1-hour lookback to ensure continuous coverage without gap.

**Risks / caveats:**
- ActionType value 'FileModified' may not be populated in DeviceFileEvents on all MDE agent versions and operating systems; 'FileRenamed' and 'FileCreated' have broader coverage. Validate ActionType population for Linux hosts specifically before relying on FileModified as a signal.
- FolderPath exclusions use startswith which is case-sensitive in KQL string comparisons on some data; on Linux hosts, paths are case-sensitive by default and the exclusion patterns use Windows-style backslash separators which will not match Linux paths.
- ActionType 'FileModified' coverage on Linux MDE agents should be validated; if not populated, the detection relies on FileRenamed and FileCreated only, which may reduce sensitivity for in-place encryption patterns.
- Backup agents and bulk file migration tools may trigger the rule during scheduled operations; process name exclusions should be added after baselining.

### Triage Runbook

**First 15 minutes:**
- Confirm whether file activity is still ongoing and whether the initiating process is still running.
- Identify the process name, command line, and account responsible for the mass file modifications.
- Check whether the affected directories include user data, shared drives, or backup locations, and whether file extensions or filenames are changing rapidly.
- Look for signs of lateral spread or additional hosts showing similar file activity in the same time window.

**Evidence to collect:**
- FileCount, DistinctFolders, sample file names, and timestamps from the alert.
- InitiatingProcessFileName, command line, account name, and parent process details.
- Affected folder paths and whether they include critical business data or network shares.
- Any ransom note files, unusual archive files, or concurrent process/network activity tied to the same host.

**Pivot points:**
- DeviceFileEvents for the same DeviceName to identify the full scope of file renames, modifications, and creations.
- DeviceProcessEvents to trace the parent process and any spawned utilities used for encryption or deletion.
- DeviceNetworkEvents to look for command-and-control or staging activity from the same host.
- Search other hosts for the same initiating process name or similar file activity to determine whether the campaign is broader.

**Benign explanations:**
- Backup, migration, or indexing tools performing large-scale file operations during a scheduled job.
- Antivirus or EDR remediation activity that is renaming or quarantining many files.
- Administrative bulk copy or file transformation tasks that legitimately touch many directories.

**Escalation criteria:**
- Escalate immediately if the process is still active and file changes are continuing.
- Escalate if user data, shared drives, or backup repositories are being modified.
- Escalate if multiple hosts show similar behavior or if ransom notes, deleted shadow copies, or other ransomware indicators are present.

**Containment actions:**
- Isolate the host from the network immediately if ransomware is active or strongly suspected.
- Terminate the malicious process only after capturing process details and confirming the host is not running an approved bulk operation.
- Disable the involved account and block access to shared storage if spread is suspected.
- Preserve evidence and coordinate with backup/restore teams before any cleanup or reimaging.

**Closure criteria:**
- The activity is confirmed to be a legitimate bulk operation, backup, or remediation task.
- No ongoing encryption-like file activity remains and no additional hosts are affected.
- The host is either restored or documented as non-malicious after full investigation and recovery steps.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- GSocket Binary Execution on Linux Host: Do not schedule yet; validate as an analyst-led hunt first.
- GSocket Outbound C2 Connection Persisting After Patch Window: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- GPUStack Authentication Bypass Exploit Attempt (CVE-2026-102895): CommonSecurityLog does not natively receive GPUStack logs; a custom syslog forwarder or connector must be deployed and configured to map GPUStack HTTP log fields to RequestURL, ResponseCode, and SourceIP in the CommonSecurityLog schema.

**Other deployment dependency:**
- Sn00py Ransomware Mass File Encryption Activity: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Shared-table notes:**
- DeviceProcessEvents: shared by GSocket Binary Execution on Linux Host; GSocket Outbound C2 Connection Persisting After Patch Window
- DeviceNetworkEvents: shared by GSocket Binary Execution on Linux Host; GSocket Outbound C2 Connection Persisting After Patch Window
- Syslog: shared by GSocket Binary Execution on Linux Host; GPUStack Authentication Bypass Exploit Attempt (CVE-2026-102895)
- DeviceFileEvents: shared by Malicious Browser Extension Written to Profile Directory Outside Update Process; Sn00py Ransomware Mass File Encryption Activity

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Malicious Browser Extension Written to Profile Directory Outside Update Process; Sn00py Ransomware Mass File Encryption Activity.
2. Resolve environment-mapping detections next: GPUStack Authentication Bypass Exploit Attempt (CVE-2026-102895).
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: GSocket Binary Execution on Linux Host; GSocket Outbound C2 Connection Persisting After Patch Window.

### Hunting Agenda and Promotion Criteria

- GSocket Binary Execution on Linux Host: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- GSocket Outbound C2 Connection Persisting After Patch Window: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- GPUStack Authentication Bypass Exploit Attempt (CVE-2026-102895): CommonSecurityLog does not natively receive GPUStack logs; a custom syslog forwarder or connector must be deployed and configured to map GPUStack HTTP log fields to RequestURL, ResponseCode, and SourceIP in the CommonSecurityLog schema.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
