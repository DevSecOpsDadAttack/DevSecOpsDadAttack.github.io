---
layout: post
title: "Detection Engineering Brief - Wednesday, September 16, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-16
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-85706
  - T1190
  - GitLab CE
  - GitLab EE
  - NightEagle
  - GhostContainer
  - RDP
  - CVE-2026-76461
  - T1059
  - Cisco Secure Email Gateway
  - Cisco AsyncOS
  - AMOS
  - macOS
  - T1133
  - T1021.001
  - T1021
  - T1555.001
  - T1555.003
  - T1555
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 1 hunting-only, 3 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-85706, T1190, GitLab CE, GitLab EE, NightEagle, GhostContainer, RDP, CVE-2026-76461, T1059, Cisco Secure Email Gateway, Cisco AsyncOS, AMOS, macOS, T1133, T1021.001, T1021, T1555.001, T1555.003, T1555.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: GitLab Repository Commits API Path Traversal Attempt; GhostContainer Backdoor - Suspicious Process Spawning Outbound Connections on Compromised Host; Cisco Secure Email Gateway - Anomalous Command Execution via AsyncOS Syslog; AMOS Stealer - macOS Process Accessing Keychain or Browser Credential Stores Outside Known Applications.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: GitLab Repository Commits API Path Traversal Attempt

### Detection Opportunity

Unauthenticated path traversal requests targeting the GitLab repository commits API, consistent with CVE-2026-85706 exploitation observed in the wild

### Intelligence Context

- Rapid7: CVE-2026-85706: Critical GitLab Path Traversal Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-85706-critical-gitlab-path-traversal-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-85706-critical-gitlab-path-traversal-exploited-in-the-wild)
  - Context: Unauthenticated attackers exploited a path traversal vulnerability in the GitLab repository commits API to read arbitrary files from affected servers. The vulnerability was added to CISA's KEV catalog based on confirmed active exploitation.

### Search Metadata

- CVEs: CVE-2026-85706
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: GitLab CE, GitLab EE
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-85706, T1190, GitLab CE, GitLab EE

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated >= ago(24h)
| where DeviceProduct has_any ("GitLab", "gitlab")
| where RequestURL has "/api/" and RequestURL has "commits"
| where RequestMethod in ("GET", "HEAD")
| where RequestURL has_any ("../", "%2e%2e%2f", "%2e%2e/", ".%2f", "..%2f", "%2e%2e%5c", "%252e%252e%252f", "%252e%252e/")
| extend DecodedURL = url_decode(RequestURL)
| where DecodedURL has "../"
| extend IsSuccessful = (EventOutcome == "200")
| project TimeGenerated, SourceIP, RequestURL, DecodedURL, RequestMethod, EventOutcome, IsSuccessful, DeviceProduct, DeviceVendor, AdditionalExtensions
| order by IsSuccessful desc, TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Internal vulnerability scanners or penetration testing tools targeting GitLab APIs may generate traversal-pattern URLs without malicious intent.
- Legitimate API clients that URL-encode path components may produce partial matches on encoded sequences; the post-decode '../' filter reduces but does not eliminate this.

**Tuning notes:**
- After confirming the exact DeviceProduct string emitted by the forwarding appliance, replace the has_any filter with an exact match to reduce false positives from unrelated appliances.
- Add a SourceIP exclusion for known internal scanner ranges once baseline scanning behavior is established.
- If EventOutcome is not populated, consider parsing the HTTP response code from AdditionalExtensions using extract() with the appropriate CEF key.

**Risks / caveats:**
- GitLab does not natively produce CEF/CommonSecurityLog output. DeviceProduct values depend entirely on the forwarding appliance (WAF, reverse proxy, or custom syslog agent) and must be confirmed before the DeviceProduct filter will return any results.
- RequestURL field population in CommonSecurityLog is appliance-dependent. If the forwarding device does not include the raw URI in the CEF RequestURL field, the path traversal filter will never match.
- url_decode() is a valid KQL function in Sentinel but its output for double-encoded sequences may differ from server-side decoding; sequences like %252e%252e%252f will not be caught by the post-decode '../' filter.
- The 24-hour lookback window may miss slow-and-low traversal campaigns; consider extending to 7 days for hunting runs.

### Triage Runbook

**First 15 minutes:**
- Confirm the alert is tied to a real GitLab-facing log source and not a mis-tagged reverse proxy or unrelated web application.
- Check whether EventOutcome indicates HTTP 200 versus blocked or error responses; prioritize any successful reads as likely exploitation.
- Review the exact RequestURL and DecodedURL for traversal patterns and whether the request targets repository commits API paths on a public-facing GitLab endpoint.
- Identify whether the SourceIP is external, a known scanner, or an internal admin/testing system.
- If the request was successful, immediately notify the GitLab service owner and incident lead for potential exposure of sensitive files.

**Evidence to collect:**
- TimeGenerated, SourceIP, RequestURL, DecodedURL, RequestMethod, EventOutcome, DeviceProduct, DeviceVendor, AdditionalExtensions
- Web server, reverse proxy, or WAF logs for the same SourceIP and time window to confirm request sequence and response codes
- GitLab application and system logs around the alert time for signs of file access, errors, or follow-on activity
- Asset inventory details for the targeted GitLab host, including version, exposure to the internet, and patch status for CVE-2026-85706

**Pivot points:**
- CommonSecurityLog filtered on the same SourceIP, DeviceProduct, and a 24-72 hour window to find repeated traversal attempts or other GitLab API abuse
- CommonSecurityLog for the same DeviceProduct and RequestURL patterns to identify additional affected GitLab endpoints
- GitLab server logs or reverse proxy logs to pivot on the source IP and confirm whether any authenticated sessions or file downloads followed the request
- Threat intel or scanner watchlists to determine whether the SourceIP is associated with routine vulnerability scanning

**Benign explanations:**
- An internal vulnerability scanner or penetration test may generate traversal-pattern URLs without malicious intent.
- A misconfigured API client or security tool may URL-encode path components in a way that resembles traversal.
- A blocked request with non-200 outcome may represent opportunistic internet noise rather than successful exploitation.

**Escalation criteria:**
- Escalate immediately if EventOutcome is 200 or other evidence suggests arbitrary file read succeeded.
- Escalate if the SourceIP is external and the same host shows multiple traversal attempts or other suspicious GitLab API requests.
- Escalate if the GitLab instance is internet-facing and unpatched or the version is confirmed vulnerable to CVE-2026-85706.
- Escalate if sensitive file paths, configuration files, or credential material appear in logs or downstream telemetry.

**Containment actions:**
- Block the SourceIP at the perimeter or WAF if the activity is confirmed malicious and ongoing.
- Temporarily restrict public access to the GitLab instance or the affected API path if exploitation appears successful.
- Coordinate emergency patching or compensating controls for the affected GitLab deployment.
- Preserve relevant logs and snapshots before making disruptive changes.

**Closure criteria:**
- The request is confirmed as blocked, benign scanner activity, or a false positive from a known testing source.
- No evidence of successful file read, follow-on access, or additional suspicious GitLab activity is found.
- The source is documented as an approved scanner or internal test system and the alert is added to an allowlist or suppression rule.
- If exploitation was successful, the case remains open until containment, patching, and impact assessment are complete.

<br/>
---
<br/>

## Detection 2: GhostContainer Backdoor - Suspicious Process Spawning Outbound Connections on Compromised Host

### Detection Opportunity

GhostContainer backdoor execution producing unknown processes with persistent outbound network connections or shell spawning, consistent with NightEagle APT post-compromise activity

### Intelligence Context

- Securelist: NightEagle targets Russian companies — [https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
  - Context: The NightEagle APT deployed the GhostContainer backdoor against targeted organizations. The backdoor establishes post-compromise persistence and command-and-control. No IOCs were available, requiring behavioral heuristics based on process and network anomalies.

### Search Metadata

- CVEs: Not specified
- Threat actors: NightEagle
- ATT&CK tags: T1133, T1021.001, T1021
- Products: Not specified
- Platforms: Not specified
- Malware: GhostContainer
- Tools: Not specified
- Search tags: NightEagle, GhostContainer, T1133, T1021.001, T1021

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1133 External Remote Services (high); Lateral Movement: T1021 Remote Services/ T1021.001 Remote Desktop Protocol (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents

### KQL

```kql
let SuspiciousProcesses = DeviceProcessEvents
| where TimeGenerated >= ago(7d)
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash", "wscript.exe", "cscript.exe", "mshta.exe")
| where InitiatingProcessName !in~ ("explorer.exe", "svchost.exe", "services.exe", "msiexec.exe", "setup.exe", "TiWorker.exe", "wuauclt.exe")
| project DeviceName, InitiatingProcessName, InitiatingProcessFolderPath, InitiatingProcessSHA256, SpawnedShell = FileName, ProcessCommandLine, ProcessCreationTime = TimeGenerated;
let OutboundConns = DeviceNetworkEvents
| where TimeGenerated >= ago(7d)
| where RemoteIPType == "Public"
| where RemotePort !in (80, 443, 53, 8080, 8443)
| project DeviceName, InitiatingProcessName, RemoteIP, RemotePort, NetworkTime = TimeGenerated;
let StagedFiles = DeviceFileEvents
| where TimeGenerated >= ago(7d)
| where FolderPath has_any ("\\Temp\\", "\\AppData\\Roaming\\", "\\Startup\\", "\\ProgramData\\")
| where ActionType == "FileCreated"
| project DeviceName, InitiatingProcessName, StagedFileName = FileName, StagedFilePath = FolderPath, FileTime = TimeGenerated;
SuspiciousProcesses
| join kind=inner OutboundConns on DeviceName, InitiatingProcessName
| where NetworkTime >= ProcessCreationTime and datetime_diff('minute', NetworkTime, ProcessCreationTime) <= 10
| join kind=leftouter StagedFiles on DeviceName, InitiatingProcessName
| where isnull(FileTime) or (FileTime >= ProcessCreationTime and datetime_diff('minute', FileTime, ProcessCreationTime) <= 30)
| project DeviceName, InitiatingProcessName, InitiatingProcessFolderPath, InitiatingProcessSHA256, SpawnedShell, ProcessCommandLine, RemoteIP, RemotePort, StagedFilePath, StagedFileName, ProcessCreationTime, NetworkTime, FileTime
| order by ProcessCreationTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Software installers and update agents that spawn cmd.exe or powershell.exe and make outbound connections during installation will match this pattern.
- Developer tools, build systems, and CI/CD agents frequently spawn shells and write to temp paths while making outbound connections.
- Remote management tools such as remote desktop agents or endpoint management clients may match the outbound connection and shell spawn pattern.

**Tuning notes:**
- Run over a 7-day baseline and review InitiatingProcessName values to build an environment-specific exclusion list before promoting to a scheduled rule.
- Consider adding a prevalence filter using DeviceProcessEvents summarized by InitiatingProcessName to exclude processes seen on more than a threshold number of devices.
- Adjust RemotePort exclusion list to match the environment's known-good outbound port profile.

**Risks / caveats:**
- RemoteIPType field classification as 'Public' depends on Defender for Endpoint's IP classification logic and may not correctly classify all external IPs in environments with non-standard routing or split-tunnel VPNs.
- DeviceFileEvents ActionType 'FileCreated' coverage on Windows depends on Defender for Endpoint agent version and audit policy; not all file creation events in ProgramData or AppData paths are guaranteed to be captured.
- The 7-day lookback with three joined tables may be slow or time out on high-volume environments; consider reducing to 24-48 hours for scheduled runs.
- The InitiatingProcessName exclusion list is not exhaustive and will require environment-specific expansion before noise is manageable.

### Triage Runbook

**First 15 minutes:**
- Identify the host, initiating process, spawned shell, remote IP, and any staged file path from the alert details.
- Check whether the initiating process is a known software installer, endpoint management agent, build tool, or remote support utility.
- Review the process command line and parent process path for signs of script execution, encoded commands, or unusual launch locations such as Temp, AppData, or ProgramData.
- Validate whether the outbound connection is to a known-good service, update server, or internal management endpoint.
- If the process is unknown and the network destination is suspicious, treat the host as potentially compromised and notify incident response.

**Evidence to collect:**
- DeviceName, InitiatingProcessName, InitiatingProcessFolderPath, InitiatingProcessSHA256, SpawnedShell, ProcessCommandLine
- RemoteIP, RemotePort, NetworkTime, and any repeated outbound connections from the same process
- StagedFilePath, StagedFileName, FileTime, and file hashes if available
- DeviceProcessEvents, DeviceNetworkEvents, and DeviceFileEvents for the host over at least the prior 24 hours

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and InitiatingProcessSHA256 to find child processes, repeated shell launches, or unusual parent-child chains
- DeviceNetworkEvents for the same DeviceName to identify additional remote IPs, ports, and connection frequency
- DeviceFileEvents for the same DeviceName and InitiatingProcessName to find dropped files in Temp, AppData, Startup, or ProgramData
- DeviceProcessEvents across the environment for the same InitiatingProcessSHA256 to determine prevalence and whether it is widespread or isolated

**Benign explanations:**
- Software installers often spawn cmd.exe, powershell.exe, or mshta.exe and make outbound connections during setup.
- Developer tools, CI/CD agents, and build systems can create temp files and open network connections as part of normal operations.
- Remote management or support tools may legitimately spawn shells and connect externally during maintenance.

**Escalation criteria:**
- Escalate if the initiating process is unknown, unsigned, or launched from a user-writable path and makes persistent outbound connections.
- Escalate if there is evidence of staged files in Temp, AppData, Startup, or ProgramData alongside shell spawning.
- Escalate if the remote IP is public, unusual for the environment, or associated with repeated callbacks.
- Escalate if multiple hosts show the same initiating process hash or similar behavior, indicating broader compromise.

**Containment actions:**
- Isolate the host from the network if the process and destination are not clearly benign.
- Terminate the suspicious process tree if containment is approved and the activity is confirmed malicious.
- Block the remote IP or domain at network controls if it is confirmed to be malicious.
- Preserve volatile evidence and collect the staged files before remediation.

**Closure criteria:**
- The process is identified as a legitimate installer, management agent, or approved administrative tool.
- No suspicious child processes, staged files, or malicious network destinations are found after review.
- The behavior matches known baseline activity for the host role and the process hash is prevalent and trusted.
- Any suspicious artifacts are removed or explained and the alert is documented as benign.

<br/>
---
<br/>

## Detection 3: NightEagle - Anomalous RDP Logon from External Source Following Failed Attempts

### Detection Opportunity

Successful RDP logon from an external or unusual source IP following multiple failed attempts, consistent with NightEagle exploitation of RDP for initial access or lateral movement

### Intelligence Context

- Securelist: NightEagle targets Russian companies — [https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
  - Context: NightEagle exploited RDP vulnerabilities as part of its campaign against targeted organizations. RDP exploitation was confirmed alongside Active Directory abuse and GhostContainer backdoor deployment, indicating RDP as an initial access or lateral movement vector.

### Search Metadata

- CVEs: Not specified
- Threat actors: NightEagle
- ATT&CK tags: T1133, T1021.001, T1021
- Products: RDP
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: NightEagle, RDP, T1133, T1021.001, T1021

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1133 External Remote Services (high); Lateral Movement: T1021 Remote Services/ T1021.001 Remote Desktop Protocol (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- SecurityEvent

### KQL

```kql
let FailedRDP = SecurityEvent
| where TimeGenerated >= ago(2h)
| where EventID == 4625 and LogonType == 10
| where IpAddress !in ("-", "", "::1", "127.0.0.1")
| where not(IpAddress matches regex @"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)")
| summarize FailCount = count(), FirstFail = min(TimeGenerated), LastFail = max(TimeGenerated) by IpAddress, Computer
| where FailCount >= 5;
let SuccessRDP = SecurityEvent
| where TimeGenerated >= ago(2h)
| where EventID == 4624 and LogonType == 10
| where IpAddress !in ("-", "", "::1", "127.0.0.1")
| project SuccessTime = TimeGenerated, IpAddress, AccountName, Computer, WorkstationName;
SuccessRDP
| join kind=inner FailedRDP on IpAddress, Computer
| where SuccessTime > LastFail
| where datetime_diff('minute', SuccessTime, FirstFail) <= 60
| extend MinutesBetweenFirstFailAndSuccess = datetime_diff('minute', SuccessTime, FirstFail)
| project SuccessTime, IpAddress, AccountName, Computer, WorkstationName, FailCount, FirstFail, LastFail, MinutesBetweenFirstFailAndSuccess
| order by SuccessTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate users who mistype passwords multiple times before successfully authenticating via RDP from home or travel IPs will match this pattern.
- Jump hosts and bastion servers that aggregate RDP connections from multiple users may generate high failure counts followed by successes.
- Automated RDP health-check or monitoring tools that test connectivity with retry logic may produce the failed-then-success pattern.

**Tuning notes:**
- Calibrate the FailCount threshold against the environment's baseline RDP failure rate per source IP before production deployment.
- Add known jump host and VPN concentrator IPs to an exclusion list or Sentinel watchlist and reference it in both subqueries.
- If internal lateral movement via RDP is also in scope, remove the RFC1918 exclusion and add a separate detection or tag for internal source IPs.

**Risks / caveats:**
- IpAddress field in SecurityEvent EventID 4625 and 4624 is only populated when the logon originates from a network source; local or console logons will have a null or '-' IpAddress and will be excluded by the join on IpAddress.
- SecurityEvent collection requires the Windows Security Events data connector (AMA or legacy MMA) to be configured and collecting Security event log; if only minimal event collection is enabled, EventID 4625 may not be forwarded.
- The RFC1918 regex exclusion covers standard private ranges but will not exclude APIPA (169.254.x.x) or other non-routable ranges; add these if relevant to the environment.
- The 2-hour lookback window for a scheduled rule running on a 1-hour cadence creates a 1-hour overlap; duplicate alerts are possible if the same event pair falls in two consecutive windows. Consider using a 1-hour lookback with a 1-hour schedule or implementing deduplication.

### Triage Runbook

**First 15 minutes:**
- Confirm the source IP, target computer, account name, and timing of failed versus successful logons.
- Check whether the source IP belongs to a known VPN, jump host, remote workforce range, or approved administrator location.
- Review whether the account is privileged, service-related, or a normal user account and whether the logon time is expected.
- Look for additional failed logons from the same IP or account across other hosts in the same time window.
- If the source is external and unapproved, notify the incident lead and begin account and host containment planning.

**Evidence to collect:**
- SuccessTime, IpAddress, AccountName, Computer, WorkstationName, FailCount, FirstFail, LastFail, MinutesBetweenFirstFailAndSuccess
- SecurityEvent 4624 and 4625 records for the same account, source IP, and host over 24 hours
- Any correlated sign-in, VPN, or identity logs for the account to validate whether the session was expected
- Host logs on the target computer for post-logon activity such as new services, scheduled tasks, or remote tool execution

**Pivot points:**
- SecurityEvent for the same IpAddress and AccountName to find additional failed or successful RDP logons
- SecurityEvent for the same Computer to identify other accounts accessed from the same source IP
- Identity, VPN, or remote access logs to validate whether the source IP maps to an approved access path
- Endpoint telemetry on the target host to look for post-logon execution, persistence, or lateral movement

**Benign explanations:**
- A user may have mistyped a password several times before successfully authenticating.
- A jump host or bastion server may aggregate multiple users and generate failed-then-success patterns.
- Automated monitoring or health-check tools may retry RDP connections and eventually succeed.

**Escalation criteria:**
- Escalate if the source IP is external, unrecognized, and not tied to an approved remote access path.
- Escalate if the account is privileged, shared, or service-related.
- Escalate if there are signs of post-logon activity such as new processes, persistence, or lateral movement.
- Escalate if multiple hosts or accounts are targeted from the same source IP.

**Containment actions:**
- Disable or reset the affected account if unauthorized access is suspected.
- Block the source IP at the perimeter or remote access gateway if malicious activity is confirmed.
- Isolate the target host if there is evidence of post-compromise activity.
- Force MFA revalidation or revoke active sessions for the affected identity if supported.

**Closure criteria:**
- The source IP is verified as an approved VPN, jump host, or administrator endpoint.
- The failed attempts are explained by user error, maintenance, or a known automated system.
- No suspicious post-logon activity is observed on the target host.
- The event is documented with the approved source and account context and no further action is required.

<br/>
---
<br/>

## Detection 4: Cisco Secure Email Gateway - Anomalous Command Execution via AsyncOS Syslog

### Detection Opportunity

Unauthenticated remote command execution as root on Cisco Secure Email Gateway, consistent with active exploitation of CVE-2026-76461 observed in the wild

### Intelligence Context

- Rapid7: CVE-2026-76461: Critical Cisco Secure Email Gateway Vulnerability Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-76461-critical-cisco-secure-email-gateway-vulnerability-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-76461-critical-cisco-secure-email-gateway-vulnerability-exploited-in-the-wild)
  - Context: Unauthenticated remote attackers exploited CVE-2026-76461 to execute arbitrary commands with root privileges on Cisco Secure Email Gateway appliances. The gateway processes externally delivered email as part of normal operation, making crafted inbound email a plausible exploitation trigger. Active exploitation was confirmed in the wild.

### Search Metadata

- CVEs: CVE-2026-76461
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Cisco Secure Email Gateway, Cisco AsyncOS
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-76461, T1190, T1059, Cisco Secure Email Gateway, Cisco AsyncOS

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.

**Required telemetry:**
- CommonSecurityLog, Syslog

### KQL

```kql
let CiscoEmailEvents = CommonSecurityLog
| where TimeGenerated >= ago(24h)
| where DeviceVendor has_any ("Cisco", "cisco")
| where DeviceProduct has_any ("Email Security", "AsyncOS", "IronPort", "Secure Email")
| where Message has_any ("/bin/sh", "/bin/bash") or (Message has "exec" and Message has "root")
| project TimeGenerated, HostName = DeviceName, SourceIP, DeviceProduct, Message, Activity, LogSource = "CommonSecurityLog";
let SyslogCiscoEmail = Syslog
| where TimeGenerated >= ago(24h)
| where ProcessName has_any ("asyncos", "ironport", "cisco")
| where SyslogMessage has_any ("/bin/sh", "/bin/bash") or (SyslogMessage has "exec" and SyslogMessage has "root")
| project TimeGenerated, HostName = Computer, SourceIP = "", DeviceProduct = ProcessName, Message = SyslogMessage, Activity = "", LogSource = "Syslog";
CiscoEmailEvents
| union SyslogCiscoEmail
| project TimeGenerated, HostName, SourceIP, DeviceProduct, Message, Activity, LogSource
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- AsyncOS system maintenance tasks and scheduled jobs may log messages containing 'root', 'exec', or 'command' in non-malicious contexts.
- Administrative CLI sessions on the appliance may produce log entries matching the keyword list during legitimate configuration changes.
- Log rotation, health check, and monitoring scripts running as root on the appliance may generate matching syslog messages.

**Tuning notes:**
- After confirming the exact ProcessName and DeviceProduct values emitted by the AsyncOS appliance in the environment, replace the has_any filters with exact matches.
- Review 30 days of baseline AsyncOS syslog messages to identify legitimate log patterns containing the keyword list and add exclusions before scheduling.
- If the appliance emits structured syslog with a defined facility for audit events, add a Facility filter to narrow results to audit-class messages only.

**Risks / caveats:**
- Cisco AsyncOS does not natively emit CEF-formatted logs. CommonSecurityLog ingestion requires a custom syslog-to-CEF translation layer or a supported connector; without this, CommonSecurityLog will contain no AsyncOS records.
- Root-level command execution events are only present in AsyncOS logs if enhanced audit logging is explicitly enabled on the appliance. Default AsyncOS logging does not capture shell-level command execution.
- ProcessName values in Syslog for AsyncOS vary by appliance firmware version and syslog configuration; the has_any filter on 'asyncos', 'ironport', 'cisco' may not match the actual ProcessName emitted by the appliance.
- The union of CommonSecurityLog and Syslog with a projected empty SourceIP for Syslog records means Syslog-sourced alerts will have no source IP for triage, limiting response capability.

### Triage Runbook

**First 15 minutes:**
- Confirm the log source is the actual Cisco Secure Email Gateway or AsyncOS appliance and not a generic Cisco syslog source.
- Review the message for shell paths, execution terms, root context, and any indication of command execution rather than routine maintenance.
- Check whether the source IP is external, internal management, or absent due to Syslog-only records.
- Determine whether the appliance has enhanced audit logging enabled and whether the event aligns with known admin activity or maintenance windows.
- If the message suggests root-level command execution from an untrusted source, escalate immediately to the email security owner and incident response.

**Evidence to collect:**
- TimeGenerated, HostName, SourceIP, DeviceProduct, Message, Activity, LogSource
- SyslogMessage or CommonSecurityLog Message fields around the same timestamp for surrounding context
- Appliance firmware version, patch level, and exposure details for CVE-2026-76461
- Administrative access logs and change records for the appliance during the alert window

**Pivot points:**
- Syslog for the same HostName to find repeated command-execution-like messages or related audit events
- CommonSecurityLog for the same SourceIP or DeviceProduct to identify inbound traffic patterns preceding the alert
- Change management or admin activity records to validate whether the message corresponds to a planned maintenance action
- Network logs for the appliance to identify suspicious inbound connections or unusual management access

**Benign explanations:**
- Legitimate administrative CLI activity may generate messages containing root, exec, or command terms.
- Scheduled maintenance, health checks, or log rotation tasks may resemble execution activity in syslog.
- Some syslog translations may overstate normal appliance actions as command execution.

**Escalation criteria:**
- Escalate if the message indicates shell execution or root command activity that is not tied to approved administration.
- Escalate if the appliance is internet-facing and unpatched for CVE-2026-76461.
- Escalate if there are repeated suspicious messages, unexpected reboots, or signs of configuration tampering.
- Escalate if the source IP is external or the appliance shows concurrent anomalous network activity.

**Containment actions:**
- Restrict management access to the appliance if unauthorized command execution is suspected.
- Isolate the appliance from untrusted networks if exploitation appears active and the business impact is acceptable.
- Preserve logs and configuration state before rebooting or applying emergency changes.
- Coordinate emergency patching or vendor guidance if the appliance is confirmed vulnerable.

**Closure criteria:**
- The event is confirmed as routine administrative or maintenance activity with change record support.
- No evidence of unauthorized access, shell execution, or configuration tampering is found.
- The appliance is patched or otherwise protected and the alert maps to a known benign log pattern.
- The message is documented as a false positive and any necessary exclusions are approved.

<br/>
---
<br/>

## Detection 5: AMOS Stealer - macOS Process Accessing Keychain or Browser Credential Stores Outside Known Applications

### Detection Opportunity

Non-browser macOS process accessing keychain files or browser credential databases, consistent with AMOS stealer credential theft following delivery via deceptive installer lures

### Intelligence Context

- Unit 42: Atomic macOS (AMOS) Stealer Activity — [https://unit42.paloaltonetworks.com/atomic-macos-amos-stealer-activity/](https://unit42.paloaltonetworks.com/atomic-macos-amos-stealer-activity/)
  - Context: AMOS stealer uses deceptive setup guides as lures to execute on macOS and then steals credentials and sensitive user data. Credential theft from macOS keychain and browser credential stores is a primary post-execution behavior. The stealer is delivered via fake installers, producing detectable process and file access patterns.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1555.001, T1555.003, T1555
- Products: Not specified
- Platforms: macOS
- Malware: AMOS
- Tools: Not specified
- Search tags: AMOS, macOS, T1555.001, T1555.003, T1555

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1555 Credentials from Password Stores/ T1555.001 Keychain (high); Credential Access: T1555 Credentials from Password Stores/ T1555.003 Credentials from Web Browsers (high)

### Deployment Gates

- File-read style telemetry must be confirmed before scheduling detections that depend on FileRead, FileAccessed, or SensitiveFileRead-style events.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let CredentialPaths = dynamic(["/Library/Keychains", "/login.keychain", "Chrome/Default/Login Data", "Firefox/Profiles", "Safari/Databases", "Cookies", "Web Data"]);
let LegitBrowsers = dynamic(["Google Chrome", "firefox", "Safari", "Brave Browser", "Microsoft Edge", "1Password", "Keychain Access"]);
let CredAccess = DeviceFileEvents
| where TimeGenerated >= ago(7d)
| where OSPlatform == "macOS"
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath has_any (CredentialPaths)
| where not(InitiatingProcessName has_any (LegitBrowsers))
| project DeviceName, InitiatingProcessName, InitiatingProcessFolderPath, FolderPath, FileName, CredTime = TimeGenerated;
let InstallerSpawn = DeviceProcessEvents
| where TimeGenerated >= ago(7d)
| where OSPlatform == "macOS"
| where InitiatingProcessFolderPath has_any ("/Downloads", "/tmp", "/var/folders")
| project DeviceName, SpawnedProcess = FileName, ParentProcess = InitiatingProcessName, SpawnTime = TimeGenerated;
CredAccess
| join kind=inner InstallerSpawn on DeviceName
| where InitiatingProcessName == SpawnedProcess
| where CredTime >= SpawnTime and datetime_diff('minute', CredTime, SpawnTime) <= 30
| join kind=leftouter (
    DeviceNetworkEvents
    | where TimeGenerated >= ago(7d)
    | where OSPlatform == "macOS"
    | where RemoteIPType == "Public"
    | project DeviceName, InitiatingProcessName, RemoteIP, RemotePort, NetTime = TimeGenerated
) on DeviceName, InitiatingProcessName
| project DeviceName, InitiatingProcessName, InitiatingProcessFolderPath, FolderPath, FileName, ParentProcess, RemoteIP, RemotePort, CredTime, SpawnTime, NetTime
| order by CredTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate password managers and credential synchronization tools that access keychain or browser credential database paths will match the non-browser process filter.
- macOS system backup agents and Time Machine may access credential store paths during backup operations.
- Software installers that create configuration files in browser profile directories may match the file creation filter in credential store paths.

**Tuning notes:**
- Before running, confirm that DeviceFileEvents contains macOS records with FolderPath values matching keychain or browser credential paths by querying for OSPlatform == 'macOS' and known credential store paths without the ActionType filter.
- Expand the LegitBrowsers exclusion list with any credential management tools deployed in the environment after reviewing baseline results.
- If OSPlatform is not populated in DeviceFileEvents for macOS endpoints, consider using DeviceName-based filtering against a list of known macOS hostnames as an alternative scoping mechanism.

**Risks / caveats:**
- DeviceFileEvents ActionType values 'FileRead' and 'FileAccessed' are not standard MDE macOS ActionType values. MDE on macOS captures FileCreated, FileModified, FileDeleted, and FileRenamed but does not reliably capture file read access events for keychain or browser credential database files. The primary detection signal may produce zero results.
- OSPlatform field availability in DeviceFileEvents and DeviceNetworkEvents depends on the MDE agent version deployed on macOS endpoints; older agent versions may not populate this field.
- macOS keychain file access by non-browser processes may not generate any DeviceFileEvents telemetry if the access occurs through macOS Security framework APIs rather than direct file system operations.
- The primary detection signal relies on FileCreated and FileModified ActionType values as a substitute for file read access, which is the actual AMOS behavior. Stealers that read credential files without creating or modifying them will not be detected.

### Triage Runbook

**First 15 minutes:**
- Identify the initiating process, its folder path, the credential store path, and whether the process was spawned from Downloads, temp, or another user-writable location.
- Check whether the process is a known browser, password manager, backup agent, or enterprise security tool that legitimately touches credential-related files.
- Review the process command line and parent process to see whether the activity followed a recent installer or lure execution.
- Look for any outbound network connections from the same process or host around the same time.
- If the process is unknown and the credential path is sensitive, treat the host as potentially compromised and escalate.

**Evidence to collect:**
- DeviceName, InitiatingProcessName, InitiatingProcessFolderPath, FolderPath, FileName, ParentProcess, RemoteIP, RemotePort, CredTime, SpawnTime, NetTime
- DeviceProcessEvents for the same host to identify the parent-child chain and any installer-like execution
- DeviceNetworkEvents for the same host and process to identify public outbound connections
- Any file hashes or reputation data for the initiating process and related binaries

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and InitiatingProcessName to find the full process tree and any suspicious parent process
- DeviceFileEvents for the same host and credential store paths to determine whether access is repeated or isolated
- DeviceNetworkEvents for the same host to identify callback behavior or data exfiltration indicators
- Prevalence checks across DeviceProcessEvents to see whether the process is rare or common in the environment

**Benign explanations:**
- Password managers and browser processes may legitimately access keychain or browser credential stores.
- Backup agents or migration tools may touch credential-related files during sync or backup operations.
- A legitimate installer may create or modify files in browser profile directories during setup.

**Escalation criteria:**
- Escalate if the process is not a known browser, password manager, or approved enterprise tool.
- Escalate if the process originated from Downloads, temp, or another user-writable path and then touched credential stores.
- Escalate if there is concurrent outbound network activity from the same process or host.
- Escalate if multiple credential store paths are accessed or the behavior repeats across endpoints.

**Containment actions:**
- Isolate the macOS host if the process is unknown and credential theft is suspected.
- Terminate the suspicious process if containment is approved and the activity is confirmed malicious.
- Reset exposed credentials and revoke active sessions for the affected user if compromise is likely.
- Collect the suspicious binary and preserve relevant telemetry before remediation.

**Closure criteria:**
- The process is identified as a legitimate browser, password manager, backup, or enterprise management tool.
- The file access aligns with expected behavior and no suspicious network activity is observed.
- The process is prevalent and trusted in the environment and the credential paths match approved use cases.
- Any suspicious artifacts are explained or removed and the alert is documented as benign.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- GitLab Repository Commits API Path Traversal Attempt: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.
- Cisco Secure Email Gateway - Anomalous Command Execution via AsyncOS Syslog: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.
- File-read style telemetry must be confirmed before scheduling detections that depend on FileRead, FileAccessed, or SensitiveFileRead-style events.

**Schema / correlation keys:**
- GhostContainer Backdoor - Suspicious Process Spawning Outbound Connections on Compromised Host: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- CommonSecurityLog: shared by GitLab Repository Commits API Path Traversal Attempt; Cisco Secure Email Gateway - Anomalous Command Execution via AsyncOS Syslog
- DeviceProcessEvents: shared by GhostContainer Backdoor - Suspicious Process Spawning Outbound Connections on Compromised Host; AMOS Stealer - macOS Process Accessing Keychain or Browser Credential Stores Outside Known Applications
- DeviceNetworkEvents: shared by GhostContainer Backdoor - Suspicious Process Spawning Outbound Connections on Compromised Host; AMOS Stealer - macOS Process Accessing Keychain or Browser Credential Stores Outside Known Applications
- DeviceFileEvents: shared by GhostContainer Backdoor - Suspicious Process Spawning Outbound Connections on Compromised Host; AMOS Stealer - macOS Process Accessing Keychain or Browser Credential Stores Outside Known Applications

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: NightEagle - Anomalous RDP Logon from External Source Following Failed Attempts.
2. Resolve environment-mapping detections next: GitLab Repository Commits API Path Traversal Attempt; Cisco Secure Email Gateway - Anomalous Command Execution via AsyncOS Syslog; AMOS Stealer - macOS Process Accessing Keychain or Browser Credential Stores Outside Known Applications.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: GhostContainer Backdoor - Suspicious Process Spawning Outbound Connections on Compromised Host.

### Hunting Agenda and Promotion Criteria

- GhostContainer Backdoor - Suspicious Process Spawning Outbound Connections on Compromised Host: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- GitLab Repository Commits API Path Traversal Attempt: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- Cisco Secure Email Gateway - Anomalous Command Execution via AsyncOS Syslog: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- AMOS Stealer - macOS Process Accessing Keychain or Browser Credential Stores Outside Known Applications: File-read style telemetry must be confirmed before scheduling detections that depend on FileRead, FileAccessed, or SensitiveFileRead-style events.; confirm required file-access telemetry exists and produces representative events; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

This run exposes a file-access telemetry blind spot: browser cookie theft and resource-file loader behaviors depend on file-read style events that may not be emitted in every Defender deployment. Validate that coverage before treating these as scheduled analytics.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
