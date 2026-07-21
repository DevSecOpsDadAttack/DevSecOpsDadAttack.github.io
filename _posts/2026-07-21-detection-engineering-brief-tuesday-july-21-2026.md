---
layout: post
title: "Detection Engineering Brief - Tuesday, July 21, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-21
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-58644
  - T1190
  - Microsoft SharePoint Server
  - Microsoft Defender
  - AMSI
  - CVE-2026-63030
  - T1059
  - WordPress
  - WordPress REST API
  - T1071.003
  - T1071.004
  - Outlook
  - Microsoft Graph
  - Project CAV3RN
  - DNS
  - Microsoft 365
  - T1071
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

3 production candidates, 2 hunting-only, 0 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-58644, T1190, Microsoft SharePoint Server, Microsoft Defender, AMSI, CVE-2026-63030, T1059, WordPress, WordPress REST API, T1071.003, T1071.004, Outlook, Microsoft Graph, Project CAV3RN, DNS, Microsoft 365, T1071.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: SharePoint CVE-2026-58644 - Defender or AMSI Alert on SharePoint Host; Project CAV3RN - Programmatic Outlook Calendar Access via Microsoft Graph for C2.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: SharePoint RCE - w3wp.exe Spawning Unexpected Child Process (CVE-2026-58644)

### Detection Opportunity

Unauthenticated remote code execution against SharePoint Server via CVE-2026-58644 resulting in w3wp.exe spawning unexpected child processes

### Intelligence Context

- Rapid7: CVE-2026-58644: Microsoft SharePoint Server Unauthenticated Remote Code Execution Vulnerability Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-58644-microsoft-sharepoint-server-unauthenticated-remote-code-execution-vulnerability-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-58644-microsoft-sharepoint-server-unauthenticated-remote-code-execution-vulnerability-exploited-in-the-wild)
  - Context: Microsoft confirmed active exploitation of CVE-2026-58644 in the wild. The vulnerability allows an unauthenticated attacker to execute arbitrary code on SharePoint Server. Spawned child processes from w3wp.exe on SharePoint hosts are identified as a reliable exploitation signal.

### Search Metadata

- CVEs: CVE-2026-58644
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Microsoft SharePoint Server, Microsoft Defender, AMSI
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-58644, T1190, Microsoft SharePoint Server, Microsoft Defender, AMSI

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ (
    "cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe",
    "mshta.exe", "certutil.exe", "bitsadmin.exe", "net.exe", "whoami.exe",
    "ipconfig.exe", "nltest.exe", "rundll32.exe", "regsvr32.exe"
)
| where ProcessCommandLine !contains "SPTimerV4"
| where FileName !in~ ("OSearch15", "noderunner.exe")
| project
    Timestamp,
    DeviceName,
    DeviceId,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    FileName,
    FolderPath,
    ProcessCommandLine,
    ProcessId
| top 500 by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate SharePoint administrative scripts executed via scheduled tasks under IIS worker process context.
- Monitoring or backup agents that spawn cmd.exe or powershell.exe under w3wp.exe on IIS hosts not running SharePoint.
- Software deployment tools that invoke certutil.exe or bitsadmin.exe through IIS application pools.

**Tuning notes:**
- Add a filter such as 'DeviceName in~ (<sharepoint_host_list>)' once SharePoint Server hostnames are known, to reduce noise from other IIS servers.
- Extend the FileName exclusion list with any additional legitimate SharePoint worker process names observed in your environment.
- Consider adding an InitiatingProcessCommandLine filter scoped to known SharePoint application pool identities if multiple application pools exist.

**Risks / caveats:**
- Microsoft Defender for Endpoint must be onboarded on SharePoint Server hosts and process-level telemetry must be enabled; if MDE is not deployed on SharePoint servers, DeviceProcessEvents will return no results for those hosts.
- Without scoping DeviceName to confirmed SharePoint Server hosts, the query will fire on any IIS-hosting system where w3wp.exe spawns these child processes, increasing false positive volume.
- The 24-hour lookback window may miss slow-burn exploitation; consider extending to 48 hours during active incident response.
- Ingestion delay in DeviceProcessEvents can cause events near the lookback boundary to be missed; schedule with a 5-minute overlap if supported.

### Triage Runbook

**First 15 minutes:**
- Confirm the device is a SharePoint Server host, not just any IIS server, using hostname, asset inventory, or server role data.
- Review the child process name and command line for obvious attacker tooling or post-exploitation activity such as cmd.exe, powershell.exe, certutil.exe, bitsadmin.exe, or net.exe.
- Check whether the parent w3wp.exe command line maps to a SharePoint application pool or unusual request context, and note the initiating process ID for correlation.
- Look for nearby process activity on the same host within the last hour that suggests staging, persistence, or discovery, such as archive creation, script execution, or service changes.
- If the host is confirmed SharePoint and the child process is not a known benign SharePoint worker, treat as likely exploitation and escalate immediately.

**Evidence to collect:**
- DeviceName, DeviceId, Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, ProcessId, and InitiatingProcessId.
- Any related Microsoft Defender alerts, AMSI detections, or blocked actions on the same host around the same time.
- Recent IIS, SharePoint, and Windows event logs showing the request path, user agent, source IP, and any authentication anomalies.
- A short timeline of all child processes spawned by w3wp.exe on the host in the preceding and following 2 hours.
- If available, evidence of file writes in web directories, suspicious DLLs, or newly created scheduled tasks or services.

**Pivot points:**
- DeviceProcessEvents for all child processes of w3wp.exe on the same DeviceId over the last 24 to 48 hours.
- DeviceNetworkEvents for the same DeviceId to identify outbound connections from the spawned child process.
- AlertEvidence and DeviceEvents for Defender or AMSI detections tied to the same host and time window.
- SharePoint/IIS server logs to identify the originating client IP, URL, and request pattern that preceded the process spawn.

**Benign explanations:**
- Legitimate SharePoint administrative or timer-job activity that spawns known worker processes such as OSearch15, noderunner.exe, or SPTimerV4-related commands.
- Backup, monitoring, or deployment tooling running under IIS context on a server that is not actually a SharePoint host.
- Approved maintenance scripts executed by administrators through SharePoint-related application pools.

**Escalation criteria:**
- The host is confirmed as SharePoint Server and the child process is a shell, scripting interpreter, or living-off-the-land binary not expected for SharePoint operations.
- The child process command line shows download, execution, credential discovery, or web shell behavior.
- There are multiple w3wp.exe child process events, repeated across short intervals, or evidence of follow-on activity such as persistence or outbound connections.
- Defender, AMSI, or server logs indicate exploitation attempts from an external source IP against SharePoint endpoints.

**Containment actions:**
- Isolate the SharePoint server from the network if exploitation is confirmed or strongly suspected.
- Preserve volatile evidence before rebooting, including running processes, network connections, and relevant logs.
- Block the source IPs or URLs at the perimeter if they are clearly malicious and still active.
- Disable or restrict external access to the affected SharePoint service until patching and validation are complete.

**Closure criteria:**
- The host is verified as non-SharePoint IIS infrastructure and the spawned process is explained by approved application behavior.
- The child process is a documented SharePoint worker or maintenance process and no other suspicious activity is present.
- No evidence of exploitation, web shell deployment, outbound beaconing, or persistence is found after reviewing logs and process history.
- The detection is attributed to a known benign administrative action with change-ticket evidence.

<br/>
---
<br/>

## Detection 2: SharePoint CVE-2026-58644 - Defender or AMSI Alert on SharePoint Host

### Detection Opportunity

Microsoft Defender or AMSI telemetry indicating a blocked or detected exploit attempt targeting SharePoint Server for CVE-2026-58644

### Intelligence Context

- Rapid7: CVE-2026-58644: Microsoft SharePoint Server Unauthenticated Remote Code Execution Vulnerability Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-58644-microsoft-sharepoint-server-unauthenticated-remote-code-execution-vulnerability-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-58644-microsoft-sharepoint-server-unauthenticated-remote-code-execution-vulnerability-exploited-in-the-wild)
  - Context: Rapid7 identified AMSI and Microsoft Defender as secondary detection layers for CVE-2026-58644 exploitation attempts against SharePoint Server. Defender alerts referencing SharePoint or the CVE are a detection pivot when process telemetry is incomplete.

### Search Metadata

- CVEs: CVE-2026-58644
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Microsoft SharePoint Server, Microsoft Defender, AMSI
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-58644, T1190, Microsoft SharePoint Server, Microsoft Defender, AMSI

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceEvents, AlertEvidence

### KQL

```kql
let amsiHits = DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "AmsiScriptDetection"
| where InitiatingProcessFileName =~ "w3wp.exe"
| extend AlertId = "", AlertName = "", ThreatName = "", EntityType = ""
| project
    Timestamp,
    DeviceName,
    DeviceId,
    ActionType,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AdditionalFields,
    AlertId,
    AlertName,
    ThreatName,
    EntityType;
let defenderAlerts = AlertEvidence
| where Timestamp > ago(7d)
| where AlertName has_any ("SharePoint", "CVE-2026-58644")
    or ThreatName has_any ("SharePoint", "CVE-2026-58644")
| extend InitiatingProcessFileName = "", InitiatingProcessCommandLine = "", AdditionalFields = ""
| project
    Timestamp,
    DeviceName,
    DeviceId,
    ActionType = "DefenderAlert",
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AdditionalFields,
    AlertId,
    AlertName,
    ThreatName,
    EntityType;
amsiHits
| union defenderAlerts
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Any host with 'sp' or 'sharepoint' in its hostname that runs IIS but is not a SharePoint Server will appear in AMSI results.
- Defender alerts with 'SharePoint' in the alert name that are unrelated to CVE-2026-58644 exploitation will surface in the AlertEvidence branch.
- Legitimate AMSI detections from security testing or red team activity on SharePoint hosts.

**Tuning notes:**
- Once SharePoint Server hostnames are known, add a DeviceName filter to the amsiHits branch to eliminate non-SharePoint IIS hosts.
- Monitor Defender threat intelligence updates and add additional ThreatName or AlertName keywords as Microsoft releases CVE-specific signatures.
- Consider splitting this into two separate hunting queries once the environment-specific hostname list is available.

**Risks / caveats:**
- AmsiScriptDetection ActionType availability in DeviceEvents depends on MDE agent version and AMSI integration being enabled on the host; this ActionType may not be present in all tenants.
- AlertEvidence ThreatName field is not always populated for all alert types; queries filtering on ThreatName may return no results if Defender uses a different field for CVE attribution.
- AlertEvidence AlertName matching on 'CVE-2026-58644' depends on Microsoft releasing a signature with that string in the alert name; this may not exist at time of deployment.
- The DeviceName hostname pattern filter was removed from the AMSI branch in favor of the w3wp.exe initiating process filter; hosts running IIS for non-SharePoint purposes will still appear and require analyst triage.

### Triage Runbook

**First 15 minutes:**
- Open the underlying Defender or AMSI alert and confirm the alert name, threat name, affected device, and timestamp.
- Verify the device is a SharePoint Server host and not a generic IIS server with a misleading hostname.
- Check whether the alert was blocked, detected only, or accompanied by a process spawn from w3wp.exe or other suspicious activity.
- Review the initiating process command line and any AMSI script content for exploit indicators, encoded commands, or web shell behavior.
- If the alert is on a real SharePoint host, begin scoping for additional alerts, process activity, and network connections on the same device.

**Evidence to collect:**
- AlertId, AlertName, ThreatName, EntityType, DeviceName, DeviceId, Timestamp, and any available alert evidence details.
- AMSI content or script fragments, if present, including the initiating process command line and any decoded payloads.
- Related DeviceProcessEvents and DeviceNetworkEvents on the same host within a 24-hour window.
- Any IIS, SharePoint, or Windows security logs showing the source IP, URL, and request sequence leading to the alert.
- Whether the alert was blocked, remediated, or only detected, and whether the same host has repeated detections.

**Pivot points:**
- AlertEvidence for the full alert record and related entities.
- DeviceEvents for AMSI detections tied to w3wp.exe on the same DeviceId.
- DeviceProcessEvents for child processes spawned by w3wp.exe on the same host.
- DeviceNetworkEvents for outbound connections or suspicious DNS activity from the same device.

**Benign explanations:**
- A security test, red team exercise, or vulnerability validation performed on the SharePoint server.
- A Defender or AMSI signature match on a benign script or request that resembles exploit behavior but was not malicious.
- An alert on a host with 'sharepoint' or 'sp' in the name that is not actually running SharePoint Server.

**Escalation criteria:**
- The alert is on a confirmed SharePoint Server host and is accompanied by suspicious child processes, script execution, or outbound connections.
- AMSI content shows exploit payloads, encoded commands, or web shell activity.
- Multiple alerts or detections occur on the same host within a short time window.
- The alert indicates detection only, not blocking, and there is evidence of post-exploitation behavior.

**Containment actions:**
- Isolate the host if the alert is confirmed malicious or if post-exploitation activity is observed.
- Preserve alert details and AMSI content before any remediation actions that could destroy evidence.
- Temporarily restrict external access to the SharePoint server if exploitation is ongoing.
- Coordinate with server owners to patch or take the service offline if compromise is likely.

**Closure criteria:**
- The device is not a SharePoint Server host and the alert is attributable to unrelated activity.
- The alert is confirmed as a benign security test or approved validation with change evidence.
- No corroborating process, network, or log evidence supports exploitation.
- The alert was blocked and subsequent review shows no follow-on malicious activity.

<br/>
---
<br/>

## Detection 3: WordPress RCE - Shell Spawned by Web Server Process Post-Exploitation (CVE-2026-63030)

### Detection Opportunity

Command interpreter or shell process spawned by apache2 or nginx following exploitation of WordPress REST API batch endpoint via CVE-2026-63030

### Intelligence Context

- Rapid7: CVE-2026-63030: wp2shell a Critical Remote Code Execution Vulnerability in WordPress Core — [https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core](https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core)
  - Context: CVE-2026-63030 allows an unauthenticated attacker to execute code via the WordPress REST API batch endpoint (/wp-json/batch/v1), potentially resulting in complete compromise. Rapid7 identified shell or command interpreter processes spawned by web server processes (apache2, nginx) as a high-confidence post-exploitation signal.

### Search Metadata

- CVEs: CVE-2026-63030
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: WordPress, WordPress REST API
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-63030, T1190, T1059, WordPress, WordPress REST API

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let webServerShellSpawn = DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ (
    "apache2", "httpd", "nginx", "php", "php-fpm",
    "php8.0", "php8.1", "php8.2", "php8.3"
)
| where FileName in~ (
    "bash", "sh", "dash", "python", "python3",
    "perl", "ruby", "curl", "wget", "nc", "ncat", "netcat"
)
| project
    Timestamp,
    DeviceName,
    DeviceId,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    FileName,
    FolderPath,
    ProcessCommandLine,
    ProcessId;
let recentNetworkActivity = DeviceNetworkEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ ("apache2", "httpd", "nginx", "php", "php-fpm")
| where RemotePort in (80, 443, 8080, 8443)
| summarize
    RecentOutboundIP = take_any(RemoteIP),
    RecentOutboundPort = take_any(RemotePort),
    NetEventCount = count()
    by DeviceName, bin(Timestamp, 5m);
webServerShellSpawn
| join kind=leftouter (
    recentNetworkActivity
) on DeviceName
| where abs(datetime_diff('minute', Timestamp, Timestamp1)) <= 5 or isnull(Timestamp1)
| project
    Timestamp,
    DeviceName,
    DeviceId,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    FileName,
    FolderPath,
    ProcessCommandLine,
    ProcessId,
    RecentOutboundIP,
    RecentOutboundPort
| top 500 by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate cron jobs or maintenance scripts that invoke bash or python under a PHP-FPM process context.
- Container environments where apache2 or nginx spawns shell processes as part of entrypoint scripts.
- Development or staging servers where developers run shell commands through web-accessible scripts.

**Tuning notes:**
- Scope DeviceName to confirmed WordPress hosting servers once the asset list is available to reduce false positives from other PHP-based web applications.
- Add ProcessCommandLine exclusions for known legitimate maintenance scripts that run under web server process context in your environment.
- Consider adding a FolderPath filter scoped to /var/www/ or the WordPress installation directory to increase precision.

**Risks / caveats:**
- Microsoft Defender for Endpoint Linux agent must be deployed on WordPress hosting servers; if not deployed, DeviceProcessEvents will contain no records for those hosts.
- DeviceNetworkEvents on Linux hosts requires MDE Linux agent version supporting network telemetry; older agent versions may not emit this table for Linux processes.
- The network enrichment join uses a 5-minute time bin correlation which may not align precisely with the process spawn timestamp; this is an enrichment approximation, not a detection gate.
- PHP version binary names beyond php8.3 will not be caught; extend the InitiatingProcessFileName list as new PHP versions are released.

### Triage Runbook

**First 15 minutes:**
- Confirm the host runs WordPress and that the parent process is apache2, nginx, httpd, or php-fpm on a production web server.
- Inspect the child process name and command line for shells, scripting interpreters, downloaders, or network utilities such as bash, sh, curl, wget, nc, python, or perl.
- Review the parent and child process command lines for signs of web shell execution, encoded payloads, or commands that enumerate the system.
- Check for recent outbound connections from the same host, especially to unfamiliar IPs or ports, and note any recent DNS activity.
- If the host is a real WordPress server and the child process is not a known maintenance action, escalate as likely compromise.

**Evidence to collect:**
- DeviceName, DeviceId, Timestamp, AccountName, AccountDomain, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, ProcessId, and InitiatingProcessId.
- Recent outbound IPs and ports from DeviceNetworkEvents for the same host and time window.
- Any web server access logs showing requests to /wp-json/batch/v1 or other suspicious WordPress endpoints.
- Any file creation or modification events in the WordPress web root or temporary directories.
- Any evidence of persistence such as cron entries, new services, or modified startup scripts.

**Pivot points:**
- DeviceProcessEvents for all child processes spawned by apache2, nginx, php, or php-fpm on the same DeviceId.
- DeviceNetworkEvents for outbound connections from the host in the 24 hours around the alert.
- DeviceFileEvents or equivalent file telemetry for changes in the WordPress installation path.
- Web server access logs to identify the source IP, request URI, and user agent associated with the exploit.

**Benign explanations:**
- Legitimate WordPress maintenance, backup, or plugin activity that invokes shell commands under PHP-FPM.
- Container entrypoint or orchestration scripts that spawn shells during startup on a web container host.
- Developer or staging environment activity where shell commands are intentionally executed through web-accessible scripts.

**Escalation criteria:**
- The host is confirmed as a production WordPress server and the child process is a shell, scripting interpreter, or network utility not expected in normal operations.
- The command line shows download-and-execute behavior, system discovery, or web shell indicators.
- There are outbound connections, new files in the web root, or persistence artifacts following the process spawn.
- Multiple related process spawns occur from the same web server process within a short period.

**Containment actions:**
- Isolate the WordPress host if exploitation is confirmed or strongly suspected.
- Preserve process, network, and web log evidence before restarting services or applying cleanup.
- Block the source IPs or malicious URLs if they are still active and clearly associated with the attack.
- Disable external access to the affected WordPress site until the vulnerability is patched and the host is validated.

**Closure criteria:**
- The host is not a production WordPress server or the activity is explained by approved maintenance.
- The spawned process is a documented administrative script with change-ticket evidence.
- No additional malicious activity, outbound connections, or persistence is found after review.
- The event is attributable to a known benign container or staging workflow.

<br/>
---
<br/>

## Detection 4: Project CAV3RN - Programmatic Outlook Calendar Access via Microsoft Graph for C2

### Detection Opportunity

Malware using Microsoft Graph API to programmatically create or read Outlook calendar events as a command-and-control channel

### Intelligence Context

- Securelist: New Project CAV3RN module abuses Outlook calendar events for C2 and DNS AAAA records for configuration recovery — [https://securelist.com/project-cav3rn-cyberespionage-framework-using-outlook-and-dns/120757/](https://securelist.com/project-cav3rn-cyberespionage-framework-using-outlook-and-dns/120757/)
  - Context: Project CAV3RN malware uses Outlook calendar events as a C2 channel by communicating via Microsoft Graph API. The malware also uses DNS AAAA record responses as a backup configuration recovery mechanism. Programmatic calendar event creation or reading by non-user principals at unusual frequency is the primary detection signal.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071.003, T1071.004, T1071
- Products: Outlook, Microsoft Graph
- Platforms: DNS, Microsoft 365
- Malware: Project CAV3RN
- Tools: Not specified
- Search tags: T1071.003, T1071.004, Outlook, Microsoft Graph, Project CAV3RN, DNS, Microsoft 365, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Both
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.003 Mail Protocols (medium); Command and Control: T1071 Application Layer Protocol/ T1071.004 DNS (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- CloudAppEvents requires Microsoft Defender for Cloud Apps licensing or Microsoft 365 Defender with the appropriate connector enabled; without this, the table will be empty.

**Required telemetry:**
- CloudAppEvents, DeviceNetworkEvents

### KQL

```kql
let calendarGraphAccess = CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Exchange Online"
| where ActionType in~ (
    "Create", "Update", "CalendarItemCreated", "CalendarItemUpdated",
    "FileAccessed", "CalendarItemAccessed"
)
| where ObjectType has_any ("Calendar", "Event")
| where AccountType != "Regular"
| summarize
    CalendarOps = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    ActionTypes = make_set(ActionType)
    by AccountId, AccountType, IPAddress, Application
| where CalendarOps > 20
| extend DetectionBranch = "CalendarGraphAccess";
let aaaaQueries = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort == 53
| where AdditionalFields has "AAAA"
| summarize
    AAAAQueryCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    ProcessNames = make_set(InitiatingProcessFileName)
    by DeviceName, DeviceId
| where AAAAQueryCount > 50
| extend DetectionBranch = "AAAADNSSpike", AccountId = "", AccountType = "", IPAddress = "", Application = "", CalendarOps = 0, ActionTypes = dynamic([]);
calendarGraphAccess
| union aaaaQueries
| project
    DetectionBranch,
    FirstSeen,
    LastSeen,
    AccountId,
    AccountType,
    IPAddress,
    Application,
    ActionTypes,
    CalendarOps,
    DeviceName,
    DeviceId,
    AAAAQueryCount
| order by FirstSeen desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate Microsoft 365 automation tools, Power Automate flows, or third-party calendar sync applications that access calendar objects via Graph API as a service principal.
- Monitoring or backup solutions that perform high-frequency calendar reads.
- Hosts with legitimate high-frequency IPv6 DNS resolution such as CDN-connected endpoints.

**Tuning notes:**
- Validate CloudAppEvents ActionType values for calendar operations in your tenant by running a broad query without the ActionType filter and reviewing the distinct values present.
- Baseline CalendarOps and AAAAQueryCount thresholds against 30 days of historical data before using this query for alerting.
- If a device inventory or watchlist mapping IP addresses to hostnames is available, add a join to correlate the two branches on the same device.
- Consider splitting into two separate hunting queries once each branch is independently validated.

**Risks / caveats:**
- CloudAppEvents requires Microsoft Defender for Cloud Apps licensing or Microsoft 365 Defender with the appropriate connector enabled; without this, the table will be empty.
- CloudAppEvents ActionType values for calendar operations such as 'CalendarItemCreated' and 'CalendarItemUpdated' are not guaranteed to exist in all tenants; the available ActionType values depend on the audit log configuration and connector version.
- DeviceNetworkEvents AdditionalFields does not have a documented standard field for DNS query type; filtering on AdditionalFields has 'AAAA' is an undocumented heuristic that may not work across all MDE agent versions.
- The join on IPAddress == DeviceName is a type mismatch; IPAddress is a client IP from CloudAppEvents and DeviceName is a hostname from DeviceNetworkEvents; these cannot be directly equated without a device inventory lookup.

### Triage Runbook

**First 15 minutes:**
- Identify which branch fired: Microsoft Graph calendar access or DNS AAAA query spike, and review the associated account or device.
- For calendar activity, confirm whether the account is a service principal, application, or other non-interactive identity and whether the volume is unusual for that identity.
- For DNS activity, verify whether the device is expected to generate high AAAA query volume and whether the initiating process is a known resolver, browser, or application.
- Check whether the activity aligns with a known business application, automation workflow, or scheduled integration.
- If both branches are present for the same environment or identity pattern, treat the combination as higher risk and escalate for deeper review.

**Evidence to collect:**
- AccountId, AccountType, IPAddress, Application, ActionTypes, CalendarOps, FirstSeen, LastSeen, DeviceName, DeviceId, InitiatingProcessFileName, and AAAAQueryCount.
- The exact Microsoft Graph action types and object types involved in the calendar activity.
- The initiating process and any parent process context for the DNS activity.
- Any tenant audit logs, application registrations, or service principal details tied to the account.
- Historical baseline for the same account or device over the last 30 days to compare frequency and timing.

**Pivot points:**
- CloudAppEvents for all Microsoft Exchange Online calendar-related actions by the same AccountId or IPAddress.
- DeviceNetworkEvents for DNS traffic from the same DeviceId and initiating process.
- Entra ID sign-in and audit logs for the account or service principal involved.
- Microsoft 365 audit logs to identify whether the calendar operations are part of a known integration.

**Benign explanations:**
- Legitimate calendar synchronization, scheduling, or workflow automation using Microsoft Graph.
- Power Automate, third-party calendar integrations, or service principals that create or read events at high frequency.
- Normal IPv6 DNS resolution on CDN-heavy or cloud-connected endpoints that naturally generate many AAAA queries.

**Escalation criteria:**
- A non-user principal performs unusually frequent calendar operations with no approved business justification.
- The same identity or host shows both suspicious calendar access and abnormal DNS AAAA activity.
- The activity occurs from an unexpected IP address, device, or application registration.
- There is evidence of persistence, token abuse, or other suspicious Microsoft 365 activity around the same time.

**Containment actions:**
- Disable or suspend the suspicious service principal or application if abuse is confirmed.
- Revoke active sessions or tokens associated with the suspicious identity.
- Coordinate with identity administrators to restrict the application or integration until validated.
- If DNS activity is clearly malicious and tied to a compromised host, isolate the endpoint.

**Closure criteria:**
- The activity is matched to a documented business automation or approved integration.
- Baseline review shows the volume and timing are normal for the account or device.
- No corroborating signs of compromise are found in audit, sign-in, or endpoint telemetry.
- The DNS branch is explained by normal resolver behavior or a known application process.

<br/>
---
<br/>

## Detection 5: WordPress CVE-2026-63030 - PHP or Shell Process Spawned by Web Server on Linux Host

### Detection Opportunity

SQL injection exploitation of WordPress core leading to unauthenticated RCE, evidenced by PHP or shell processes spawned by web server parent processes on Linux

### Intelligence Context

- SANS ISC: WordPress Exploitation Underway (CVE-2026-63030), (Mon, Jul 20th) — [https://isc.sans.edu/diary/rss/33168](https://isc.sans.edu/diary/rss/33168)
  - Context: SANS ISC reported active exploitation of CVE-2026-63030 beginning shortly after public disclosure. The vulnerability is a SQL injection in WordPress Core that can lead to unauthenticated remote code execution. Web shell or shell spawn from web server processes is identified as a high-confidence post-exploitation signal.

### Search Metadata

- CVEs: CVE-2026-63030
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: WordPress
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-63030, T1190, WordPress

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ (
    "apache2", "httpd", "nginx", "php", "php-fpm",
    "php8.0", "php8.1", "php8.2", "php8.3"
)
| where (
    FileName in~ ("bash", "sh", "dash", "nc", "ncat", "netcat", "python", "python3", "perl")
    or ProcessCommandLine has_any (
        "whoami", "id ", "uname", "cat /etc/passwd",
        "wget ", "curl ", "chmod ", "chmod +x",
        "base64 ", "/tmp/", "/dev/shm",
        "/bin/sh", "python -c", "perl -e"
    )
)
| project
    Timestamp,
    DeviceName,
    DeviceId,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    FileName,
    FolderPath,
    ProcessCommandLine,
    ProcessId
| top 500 by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate PHP-based administrative scripts that invoke bash or python for maintenance tasks under the web server process.
- WordPress CLI (wp-cli) operations that invoke shell commands through PHP-FPM.
- Container health check scripts that run under apache2 or nginx process context.
- Development or staging environments where developers execute shell commands through web-accessible PHP scripts.

**Tuning notes:**
- Scope DeviceName to confirmed WordPress hosting servers once the asset list is available to reduce false positives from other PHP-based web applications.
- Add ProcessCommandLine exclusions for known legitimate maintenance scripts that run under web server process context in your environment.
- Consider adding a FolderPath filter scoped to /var/www/ or the WordPress installation directory to increase precision.
- The 'id ' pattern with a trailing space reduces false positives from 'id' appearing as a substring in legitimate paths but should still be reviewed in context.

**Risks / caveats:**
- Microsoft Defender for Endpoint Linux agent must be deployed on WordPress hosting servers; if not deployed, DeviceProcessEvents will contain no records for those hosts.
- Without scoping DeviceName to confirmed WordPress hosting servers, the query will fire on any Linux host running apache2, nginx, or PHP where these child process patterns occur.
- The ProcessCommandLine has_any list uses short strings such as 'id ' and 'curl ' that may match legitimate administrative activity; analyst review is required for each hit.
- PHP version binary names beyond php8.3 will not be caught; extend the InitiatingProcessFileName list as new PHP versions are released.

### Triage Runbook

**First 15 minutes:**
- Verify the host is a WordPress server and that the parent process is a web server or PHP runtime expected to serve the site.
- Inspect the child process and command line for shell execution, downloaders, discovery commands, or suspicious temporary paths such as /tmp or /dev/shm.
- Check whether the process command line includes indicators of exploitation such as /bin/sh, chmod +x, python -c, perl -e, or base64 decoding.
- Review recent process history on the same host for repeated child spawns, web shells, or unusual account context.
- If the host is a production WordPress server and the child process is not a known maintenance action, escalate immediately.

**Evidence to collect:**
- DeviceName, DeviceId, Timestamp, AccountName, AccountDomain, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, ProcessId, and InitiatingProcessId.
- Any nearby process events showing additional child processes or repeated execution from the same parent.
- Recent outbound network connections from the host, especially to unfamiliar IPs or ports.
- Web server access logs and WordPress logs showing the request path, source IP, and user agent preceding the event.
- Any file creation or modification events in the WordPress web root, temporary directories, or cron locations.

**Pivot points:**
- DeviceProcessEvents for all child processes from apache2, nginx, httpd, php, or php-fpm on the same DeviceId.
- DeviceNetworkEvents for outbound connections from the same host during the alert window.
- DeviceFileEvents for changes in the WordPress installation directory, /tmp, /dev/shm, or cron paths.
- Web server access logs to identify exploit requests and source IPs.

**Benign explanations:**
- Approved WordPress maintenance scripts or wp-cli operations that invoke shell commands under PHP-FPM.
- Container startup or health-check scripts that legitimately spawn shells on web hosts.
- Developer or staging activity where shell commands are intentionally executed through web-accessible PHP code.

**Escalation criteria:**
- The host is confirmed as production WordPress and the child process is a shell, scripting interpreter, or network utility not expected in normal operations.
- The command line shows exploit-like behavior, such as downloading payloads, decoding base64, or changing file permissions for execution.
- There are outbound connections, new files, or persistence artifacts following the process spawn.
- Multiple suspicious child processes are spawned by the same web server process in a short time window.

**Containment actions:**
- Isolate the host if exploitation is confirmed or strongly suspected.
- Preserve process, network, and web log evidence before remediation.
- Block malicious source IPs or URLs if they are still active and clearly associated with the attack.
- Temporarily disable external access to the WordPress site until patching and validation are complete.

**Closure criteria:**
- The host is not a production WordPress server or the activity is explained by approved maintenance.
- The process is a documented administrative action with supporting change evidence.
- No additional malicious activity, outbound connections, or persistence is found after review.
- The event is attributable to a known benign container or staging workflow.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Other deployment dependency:**
- SharePoint RCE - w3wp.exe Spawning Unexpected Child Process (CVE-2026-58644): Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Schema / correlation keys:**
- SharePoint CVE-2026-58644 - Defender or AMSI Alert on SharePoint Host: Do not schedule yet; validate as an analyst-led hunt first.
- Project CAV3RN - Programmatic Outlook Calendar Access via Microsoft Graph for C2: Do not schedule yet; validate as an analyst-led hunt first.

**Licensing / identity risk fields:**
- Project CAV3RN - Programmatic Outlook Calendar Access via Microsoft Graph for C2: CloudAppEvents requires Microsoft Defender for Cloud Apps licensing or Microsoft 365 Defender with the appropriate connector enabled; without this, the table will be empty.

**Shared-table notes:**
- DeviceProcessEvents: shared by SharePoint RCE - w3wp.exe Spawning Unexpected Child Process (CVE-2026-58644); WordPress RCE - Shell Spawned by Web Server Process Post-Exploitation (CVE-2026-63030); WordPress CVE-2026-63030 - PHP or Shell Process Spawned by Web Server on Linux Host
- DeviceNetworkEvents: shared by WordPress RCE - Shell Spawned by Web Server Process Post-Exploitation (CVE-2026-63030); Project CAV3RN - Programmatic Outlook Calendar Access via Microsoft Graph for C2

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: SharePoint RCE - w3wp.exe Spawning Unexpected Child Process (CVE-2026-58644); WordPress RCE - Shell Spawned by Web Server Process Post-Exploitation (CVE-2026-63030); WordPress CVE-2026-63030 - PHP or Shell Process Spawned by Web Server on Linux Host.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: SharePoint CVE-2026-58644 - Defender or AMSI Alert on SharePoint Host; Project CAV3RN - Programmatic Outlook Calendar Access via Microsoft Graph for C2.

### Hunting Agenda and Promotion Criteria

- SharePoint CVE-2026-58644 - Defender or AMSI Alert on SharePoint Host: Do not schedule yet; validate as an analyst-led hunt first..
- Project CAV3RN - Programmatic Outlook Calendar Access via Microsoft Graph for C2: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
