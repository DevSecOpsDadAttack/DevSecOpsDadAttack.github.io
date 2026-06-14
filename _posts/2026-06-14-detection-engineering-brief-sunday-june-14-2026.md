---
layout: post
title: "Detection Engineering Brief - Sunday, June 14, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-06-14
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-10520
  - Ivanti Sentry
  - MobileIron Sentry
  - T1190
  - T1059
  - CVE-2026-10523
  - CVE-2026-35273
  - Oracle PeopleSoft
  - PeopleTools
---

## Executive Signal

This brief produced 4 detection candidates.

0 production candidates, 0 hunting-only, 4 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-10520, Ivanti Sentry, MobileIron Sentry, T1190, T1059, CVE-2026-10523, CVE-2026-35273, Oracle PeopleSoft, PeopleTools.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Ivanti Sentry - Shell Spawned by Web Service Process (CVE-2026-10520 RCE); Ivanti Sentry - Unauthenticated POST to Admin API Endpoint (CVE-2026-10523 Auth Bypass); Oracle PeopleSoft - Unexpected Child Process Spawned by PeopleSoft Web Service (CVE-2026-35273 RCE); Oracle PeopleSoft - SSRF-Induced Outbound Connections to Internal Addresses (CVE-2026-35273).

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: Ivanti Sentry - Shell Spawned by Web Service Process (CVE-2026-10520 RCE)

### Detection Opportunity

Root-level shell process spawned by Ivanti Sentry web service account following unauthenticated command injection exploitation.

### Intelligence Context

- Rapid7: CVE-2026-10520, CVE-2026-10523 - Multiple critical vulnerabilities affecting Ivanti Sentry — [https://www.rapid7.com/blog/post/etr-cve-2026-10520-cve-2026-10523-multiple-critical-vulnerabilities-affecting-ivanti-sentry](https://www.rapid7.com/blog/post/etr-cve-2026-10520-cve-2026-10523-multiple-critical-vulnerabilities-affecting-ivanti-sentry)
  - Context: CVE-2026-10520 is an OS command injection vulnerability allowing a remote unauthenticated attacker to achieve RCE with root privileges on Ivanti Sentry. Exploitation produces shell processes spawned under the Sentry web service account.

### Search Metadata

- CVEs: CVE-2026-10520
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Ivanti Sentry, MobileIron Sentry
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-10520, Ivanti Sentry, MobileIron Sentry, T1190, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Both
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Both: DeviceProcessEvents, Syslog before scheduling.

Required telemetry:
- DeviceProcessEvents, Syslog

### KQL

```kql
let sentryParents = dynamic(["mics", "tomcat", "java", "sentry"]);
let shells = dynamic(["sh", "bash", "dash", "ksh", "zsh"]);
let lookback = 24h;
union isfuzzy=true
(
    DeviceProcessEvents
    | where TimeGenerated >= ago(lookback)
    | where tolower(FileName) in (shells)
    | where tolower(InitiatingProcessFileName) has_any (sentryParents)
    | project
        TimeGenerated,
        DeviceName,
        InitiatingProcessFileName,
        InitiatingProcessAccountName,
        InitiatingProcessCommandLine,
        FileName,
        ProcessCommandLine,
        DetectionSource = "DeviceProcessEvents"
),
(
    Syslog
    | where TimeGenerated >= ago(lookback)
    | where tolower(ProcessName) has_any ("mics", "sentry", "mobileiron")
        or SyslogMessage has_any ("sentry", "mics", "mobileiron")
    | where SyslogMessage matches regex @"\b(sh|bash|dash|ksh|zsh)\b"
    | project
        TimeGenerated,
        Computer,
        ProcessName,
        SyslogMessage,
        Facility,
        DetectionSource = "Syslog"
)
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Java and Tomcat processes are common on many application servers; without device-level scoping the DeviceProcessEvents branch will match non-Sentry hosts.
- Routine Sentry health-check or diagnostic scripts may spawn short-lived shell processes that match the detection logic.

Tuning notes:
- sentryParents: validate the exact process name used by the Sentry web service in the deployed environment; mics is the documented Sentry process name but may differ across versions.
- Add a DeviceName filter such as '| where DeviceName in (known_sentry_hosts)' once Sentry host names are confirmed to eliminate cross-host false positives from java/tomcat.
- Consider adding InitiatingProcessAccountName filters to restrict to the Sentry service account after identifying it in the environment.

Risks / caveats:
- DeviceProcessEvents is only populated if the Ivanti Sentry appliance is enrolled in Microsoft Defender for Endpoint; network appliances are rarely onboarded and this table may be empty for this host.
- Syslog ingestion from Ivanti Sentry requires a configured syslog forwarder or CEF connector; if not deployed, the Syslog branch returns no results.
- The Syslog table schema does not include a SeverityLevel field in all Sentinel workspace configurations; this field may be absent depending on the syslog connector version.
- Without scoping DeviceProcessEvents to known Sentry device names, any host running java or tomcat will match; a DeviceName allowlist or watchlist should be applied after environment mapping.

### Triage Runbook

First 15 minutes:
- Confirm the alert is on a known Ivanti Sentry or MobileIron Sentry host and not a generic java/tomcat server.
- Review the parent process, account, and command line to see whether the shell was launched by the Sentry web service account versus a known maintenance script.
- Check for nearby signs of exploitation such as unusual inbound requests, repeated admin/API access, or other suspicious child processes on the same host.
- Determine whether the shell is still running and whether it is interactive, short-lived, or spawning follow-on commands.

Evidence to collect:
- DeviceName or Computer, alert timestamp, parent process name, parent command line, child shell name, and initiating account.
- Any related SyslogMessage or DeviceProcessEvents entries within 30-60 minutes before and after the alert.
- Recent inbound web requests to the Sentry appliance, especially unauthenticated or unusual POST activity.
- Any additional child processes, file writes, or network connections initiated by the shell.

Pivot points:
- DeviceProcessEvents for the same DeviceName around the alert time to identify parent/child process chains.
- Syslog for the same host to find exploitation indicators, service errors, or account-creation activity.
- DeviceNetworkEvents for the Sentry host to look for outbound connections from the shell or web service process.
- If available, web access logs or reverse proxy logs for the Sentry appliance to correlate inbound requests.

Benign explanations:
- A scheduled Sentry health check or diagnostic script may spawn a shell briefly.
- Legitimate maintenance or patching activity may invoke shell commands from the web service account.
- A non-Sentry application server running java or tomcat may have matched if host scoping is incomplete.

Escalation criteria:
- The shell is running as root or under the Sentry service account with no approved maintenance window.
- You find unauthenticated or suspicious inbound requests immediately preceding the shell spawn.
- The shell launches additional commands, creates files, or makes outbound connections.
- The host shows multiple suspicious process events or signs of persistence after the initial shell spawn.

Containment actions:
- If exploitation is likely, isolate the Sentry appliance from the network or restrict inbound access to the management interface.
- Preserve volatile evidence before rebooting or patching, including process list, network connections, and relevant logs.
- Disable or rotate any administrative credentials created or exposed during the incident if compromise is confirmed.

Closure criteria:
- The process tree is confirmed to be a documented maintenance action with matching change record and expected command line.
- No suspicious inbound activity, follow-on processes, or outbound connections are found.
- The host is patched or otherwise protected, and the event is attributed to benign administrative activity with evidence.

---

## Detection 2: Ivanti Sentry - Unauthenticated POST to Admin API Endpoint (CVE-2026-10523 Auth Bypass)

### Detection Opportunity

Unauthenticated POST requests to Ivanti Sentry administrative API endpoints consistent with exploitation of the authentication bypass to create arbitrary admin accounts.

### Intelligence Context

- Rapid7: CVE-2026-10520, CVE-2026-10523 - Multiple critical vulnerabilities affecting Ivanti Sentry — [https://www.rapid7.com/blog/post/etr-cve-2026-10520-cve-2026-10523-multiple-critical-vulnerabilities-affecting-ivanti-sentry](https://www.rapid7.com/blog/post/etr-cve-2026-10520-cve-2026-10523-multiple-critical-vulnerabilities-affecting-ivanti-sentry)
  - Context: CVE-2026-10523 is an authentication bypass allowing a remote unauthenticated attacker to create arbitrary administrative accounts on Ivanti Sentry by sending POST requests to the admin management API without valid credentials.

### Search Metadata

- CVEs: CVE-2026-10523
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Ivanti Sentry, MobileIron Sentry
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-10523, Ivanti Sentry, MobileIron Sentry, T1190

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.

Required telemetry:
- CommonSecurityLog, Syslog

### KQL

```kql
let lookback = 24h;
let adminPaths = dynamic(["/mics/services/", "/admin/", "/api/v1/admin", "/mics/admin"]);
let successCodes = dynamic(["200", "201", "204"]);
let cslAdminPosts =
    CommonSecurityLog
    | where TimeGenerated >= ago(lookback)
    | where DeviceVendor in~ ("Ivanti", "MobileIron")
    | where RequestMethod == "POST"
    | where RequestURL has_any (adminPaths)
    | where tostring(EventOutcome) in (successCodes)
        or extract(@"(?:outcome|status)=(\d{3})", 1, AdditionalExtensions) in (successCodes)
    | extend TimeBin = bin(TimeGenerated, 5m)
    | project TimeBin, TimeGenerated, SourceIP, RequestURL, RequestMethod, EventOutcome, DeviceVendor, DeviceProduct;
let syslogAccountCreation =
    Syslog
    | where TimeGenerated >= ago(lookback)
    | where SyslogMessage has_any ("account created", "user added", "admin account", "useradd", "adduser")
    | where SyslogMessage has_any ("sentry", "mics", "mobileiron")
        or tolower(ProcessName) has_any ("mics", "sentry", "mobileiron")
    | extend TimeBin = bin(TimeGenerated, 5m)
    | project TimeBin, TimeGenerated, Computer, SyslogMessage, ProcessName;
cslAdminPosts
| join kind=leftouter (
    syslogAccountCreation
) on TimeBin
| project
    TimeGenerated,
    SourceIP,
    RequestURL,
    RequestMethod,
    EventOutcome,
    DeviceVendor,
    DeviceProduct,
    SyslogMessage,
    Computer,
    ProcessName,
    TimeBin
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate administrative POST requests from authorized management workstations to the Sentry admin API will match if those workstations use RFC1918 addresses that are not excluded.
- Automated health-check or monitoring tools that POST to admin API paths will generate matches.

Tuning notes:
- Add '| where not(ipv4_is_private(SourceIP))' to the cslAdminPosts branch if the goal is to detect only external unauthenticated exploitation; remove this filter if internal lateral movement is also in scope.
- Validate the AdditionalExtensions field format from the Sentry CEF connector and adjust the extract() regex to match the actual key name used for HTTP response codes.
- Consider reducing TimeBin to 2m if Sentry logs account creation events quickly after the API call, or increase to 10m if log forwarding introduces delay.

Risks / caveats:
- CommonSecurityLog is only populated if Ivanti Sentry web access logs are forwarded via a CEF/syslog connector; this connector is not a default Sentinel data connector and requires manual configuration.
- The RequestURL and RequestMethod fields in CommonSecurityLog are populated only if the CEF log format from Sentry includes cs-uri-stem and cs-method mappings; these fields may be empty depending on the syslog format configured on the appliance.
- The original join syntax 'on $left.TimeGenerated between (TimeGenerated .. TimeGenerated + 5m)' is invalid KQL; a corrected approach using a time-bucketed join or lookup is required.
- EventOutcome in CommonSecurityLog may be a string or integer depending on the CEF sender; tostring() normalization is required for reliable comparison.

### Triage Runbook

First 15 minutes:
- Confirm the source IP is external or otherwise not an approved management address.
- Review the request URL, method, response outcome, and timing to determine whether the POST targeted an admin path and succeeded.
- Check for correlated syslog entries indicating account creation, user addition, or admin changes on the same appliance.
- Identify whether the activity is isolated or part of a burst of requests from the same source.

Evidence to collect:
- SourceIP, RequestURL, RequestMethod, EventOutcome, DeviceVendor, DeviceProduct, and alert timestamp.
- Any SyslogMessage entries on the same host showing account creation, admin changes, or authentication anomalies.
- Whether the source IP belongs to a known management subnet, VPN, proxy, or monitoring system.
- Any subsequent logins, privilege changes, or configuration changes on the Sentry appliance.

Pivot points:
- CommonSecurityLog for the same DeviceProduct and SourceIP to see the full request sequence.
- Syslog for the same Computer to find account-creation or admin-change messages.
- Authentication or admin audit logs from the Sentry appliance if available.
- Network/security device logs to determine whether the source IP is a known administrator or scanner.

Benign explanations:
- A legitimate administrator or automation tool may POST to the admin API from an approved management host.
- Health checks or monitoring systems may generate POST requests to management endpoints.
- The alert may be caused by a version-specific admin path match that is not actually sensitive in your deployment.

Escalation criteria:
- The source IP is external and not an approved management system.
- You find evidence of a new admin account, privilege change, or configuration change after the POST.
- Multiple POSTs or follow-on requests indicate active exploitation rather than a single benign transaction.
- The appliance shows concurrent suspicious activity such as shell spawn, unusual outbound traffic, or authentication bypass attempts.

Containment actions:
- Block the source IP at the perimeter if it is clearly malicious and external.
- Restrict access to the Sentry admin interface to approved management networks only.
- If unauthorized account creation is confirmed, disable the account and rotate affected administrative credentials.
- Preserve logs and configuration state before making disruptive changes if compromise is suspected.

Closure criteria:
- The POST is tied to a known administrator, approved automation, or documented maintenance activity.
- No account creation, privilege change, or other malicious follow-on activity is found.
- The request path is validated as non-sensitive for the deployed Sentry version or the alert is otherwise explained by environment-specific behavior.

---

## Detection 3: Oracle PeopleSoft - Unexpected Child Process Spawned by PeopleSoft Web Service (CVE-2026-35273 RCE)

### Detection Opportunity

Unexpected shell or system utility process spawned by the PeopleSoft web application service account following unauthenticated remote exploitation leading to RCE.

### Intelligence Context

- Rapid7: Active Exploitation of Oracle PeopleSoft Zero-Day (CVE-2026-35273) — [https://www.rapid7.com/blog/post/etr-active-exploitation-of-oracle-peoplesoft-zero-day-cve-2026-35273](https://www.rapid7.com/blog/post/etr-active-exploitation-of-oracle-peoplesoft-zero-day-cve-2026-35273)
  - Context: CVE-2026-35273 is an actively exploited zero-day in Oracle PeopleSoft that is remotely exploitable without authentication and may result in RCE. Successful exploitation is expected to produce anomalous child processes under the PeopleSoft web service account.

### Search Metadata

- CVEs: CVE-2026-35273
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Oracle PeopleSoft, PeopleTools
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-35273, Oracle PeopleSoft, PeopleTools, T1190

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Both
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Both: DeviceProcessEvents, Syslog before scheduling.

Required telemetry:
- DeviceProcessEvents, Syslog

### KQL

```kql
let lookback = 48h;
let psParents = dynamic(["psappsrv", "psweb", "psadmin", "java", "tomcat"]);
let suspiciousChildren = dynamic(["sh", "bash", "cmd", "powershell", "whoami", "net", "curl", "wget", "python", "perl"]);
union isfuzzy=true
(
    DeviceProcessEvents
    | where TimeGenerated >= ago(lookback)
    | where tolower(InitiatingProcessFileName) has_any (psParents)
    | where tolower(FileName) in (suspiciousChildren)
    | project
        TimeGenerated,
        DeviceName,
        InitiatingProcessFileName,
        InitiatingProcessAccountName,
        InitiatingProcessCommandLine,
        FileName,
        ProcessCommandLine,
        DetectionSource = "DeviceProcessEvents"
),
(
    Syslog
    | where TimeGenerated >= ago(lookback)
    | where tolower(ProcessName) has_any ("psappsrv", "psweb", "psadmin", "peoplesoft")
        or SyslogMessage has_any ("psappsrv", "psweb", "psadmin", "peoplesoft")
    | where SyslogMessage matches regex @"\b(sh|bash|curl|wget|python|perl|whoami)\b"
    | project
        TimeGenerated,
        Computer,
        ProcessName,
        SyslogMessage,
        DetectionSource = "Syslog"
)
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- PeopleSoft batch processing and scheduled jobs may legitimately invoke shell scripts or system utilities under the service account.
- Java and tomcat are ubiquitous; without device-level scoping, any enrolled host running these processes will match.
- Deployment and patching automation may spawn curl or wget from the PeopleSoft service account.

Tuning notes:
- Add '| where DeviceName in (known_peoplesoft_hosts)' to the DeviceProcessEvents branch once PeopleSoft host names are confirmed to eliminate cross-host false positives.
- After baselining, add InitiatingProcessAccountName filters to restrict to the PeopleSoft service account (commonly psadm or oracle) to reduce noise from other java/tomcat services.
- Consider adding InitiatingProcessCommandLine exclusions for known legitimate PeopleSoft batch job patterns after reviewing baseline output.

Risks / caveats:
- DeviceProcessEvents is only populated for hosts enrolled in Microsoft Defender for Endpoint; on-premises Oracle PeopleSoft servers are typically not onboarded and this table may be empty for these hosts.
- Syslog ingestion from PeopleSoft requires a configured syslog forwarder; PeopleSoft does not natively forward process execution events via syslog without OS-level auditd or equivalent configuration.
- Without a DeviceName filter scoped to confirmed PeopleSoft hosts, the DeviceProcessEvents branch will match any enrolled host running java or tomcat.
- The Syslog branch depends on OS-level process execution logging (auditd or equivalent) being configured on the PeopleSoft host and forwarded to Sentinel; standard PeopleSoft application logs do not include child process execution events.

### Triage Runbook

First 15 minutes:
- Confirm the host is a known PeopleSoft application server and not another java/tomcat system.
- Review the parent process, service account, and child command line to determine whether the process is expected for batch jobs or administration.
- Check for nearby signs of exploitation such as unusual inbound web requests, errors, or multiple suspicious child processes.
- Assess whether the child process is interactive, spawning network activity, or executing system utilities not normally used by PeopleSoft.

Evidence to collect:
- DeviceName or Computer, alert timestamp, parent process name, child process name, initiating account, and full command line.
- Any SyslogMessage or DeviceProcessEvents entries around the alert time showing related process chains.
- Recent inbound requests to the PeopleSoft web tier, especially unauthenticated or unusual requests.
- Any file creation, script execution, or outbound connections initiated by the child process.

Pivot points:
- DeviceProcessEvents for the same host to reconstruct the parent-child chain and identify additional spawned processes.
- Syslog for the PeopleSoft host to find application errors, suspicious requests, or process execution logs.
- DeviceNetworkEvents for the host to identify outbound connections from the child process or service account.
- Web server or load balancer logs for the PeopleSoft front end if available.

Benign explanations:
- PeopleSoft batch jobs and scheduled maintenance can legitimately spawn shell scripts or utilities.
- Deployment, patching, or integration jobs may invoke curl, wget, or other system tools.
- The alert may be caused by another java/tomcat application if host scoping is incomplete.

Escalation criteria:
- The child process is not part of a documented PeopleSoft job or maintenance task.
- You see multiple unexpected child processes, especially shells or download utilities.
- There are suspicious inbound requests or other exploitation indicators near the same time.
- The process launches outbound connections, writes files, or attempts privilege escalation.

Containment actions:
- If compromise is likely, isolate the PeopleSoft server or restrict inbound access to the application tier.
- Preserve process, network, and web logs before restarting services or applying patches.
- Suspend or review any suspicious scheduled jobs or service accounts involved in the process chain.

Closure criteria:
- The process is confirmed as a documented PeopleSoft batch, maintenance, or integration activity.
- No suspicious inbound activity, follow-on processes, or outbound connections are found.
- The host is scoped correctly and the event is explained by expected application behavior with supporting evidence.

---

## Detection 4: Oracle PeopleSoft - SSRF-Induced Outbound Connections to Internal Addresses (CVE-2026-35273)

### Detection Opportunity

PeopleSoft application server initiating outbound HTTP connections to internal RFC1918 addresses or cloud metadata endpoints, consistent with server-side request forgery exploitation.

### Intelligence Context

- Rapid7: Active Exploitation of Oracle PeopleSoft Zero-Day (CVE-2026-35273) — [https://www.rapid7.com/blog/post/etr-active-exploitation-of-oracle-peoplesoft-zero-day-cve-2026-35273](https://www.rapid7.com/blog/post/etr-active-exploitation-of-oracle-peoplesoft-zero-day-cve-2026-35273)
  - Context: CVE-2026-35273 has been classified as a server-side request forgery (CWE-918). SSRF exploitation causes the PeopleSoft server to initiate outbound HTTP requests to attacker-controlled internal targets, RFC1918 addresses, or cloud metadata endpoints, which is anomalous for a PeopleSoft application server.

### Search Metadata

- CVEs: CVE-2026-35273
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Oracle PeopleSoft, PeopleTools
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-35273, Oracle PeopleSoft, PeopleTools, T1190

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Both
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- The ActionType value 'ConnectionSuccess' must be validated against the actual ActionType values present in DeviceNetworkEvents for the environment; some connector versions use 'NetworkConnectionEvents' action type naming.

Required telemetry:
- DeviceNetworkEvents

### KQL

```kql
let lookback = 48h;
let psProcesses = dynamic(["psappsrv", "psweb", "psadmin", "java", "tomcat"]);
let metadataIPs = dynamic(["169.254.169.254"]);
let httpPorts = dynamic([80, 443, 8080, 8443]);
DeviceNetworkEvents
| where TimeGenerated >= ago(lookback)
| where tolower(InitiatingProcessFileName) has_any (psProcesses)
| where RemotePort in (httpPorts)
| where ActionType == "ConnectionSuccess"
| where
    RemoteIP in (metadataIPs)
    or RemoteIP == "fd00:ec2::254"
    or ipv4_is_private(RemoteIP)
| project
    TimeGenerated,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessAccountName,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    ActionType
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Normal PeopleSoft inter-service communication to internal database servers (Oracle DB, SQL Server) over RFC1918 addresses will match without exclusions.
- Integration with internal LDAP, SMTP, or middleware services will generate matches.
- Cloud-hosted PeopleSoft instances may legitimately contact the metadata endpoint 169.254.169.254 for instance identity; this should be baselined.

Tuning notes:
- Add '| where DeviceName in (known_peoplesoft_hosts)' once PeopleSoft host names are confirmed to eliminate cross-host false positives.
- After baselining, add '| where RemoteIP !in (known_legitimate_internal_destinations)' with a populated exclusion list covering database servers, LDAP, and integration middleware.
- Validate ActionType values in the environment by running 'DeviceNetworkEvents | where InitiatingProcessFileName has "java" | summarize by ActionType' before scheduling.
- Consider summarizing by RemoteIP and DeviceName with a count threshold to surface repeated SSRF probing rather than individual connection events.

Risks / caveats:
- DeviceNetworkEvents is only populated for hosts enrolled in Microsoft Defender for Endpoint; on-premises Oracle PeopleSoft servers are typically not onboarded and this table may be empty for these hosts.
- ipv4_is_private() does not handle IPv6 RFC1918 equivalents (ULA fc00::/7) or link-local IPv6 (fe80::/10); the metadataIPs list includes an IPv6 metadata address (fd00:ec2::254) but DeviceNetworkEvents RemoteIP is a string field and ipv6 comparison requires explicit handling.
- RemoteUrl may be empty in DeviceNetworkEvents for non-HTTP connections; its presence should not be assumed for all matched records.
- Without a DeviceName filter scoped to confirmed PeopleSoft hosts, any enrolled host running java or tomcat will match; this is the primary source of false positives.

### Triage Runbook

First 15 minutes:
- Confirm the destination IP or URL is not a known PeopleSoft dependency such as a database, LDAP, or middleware server.
- Review the initiating process and account to verify the traffic came from the PeopleSoft web tier or service account.
- Check whether the destination is a metadata endpoint, unusual internal host, or an unexpected port/protocol for the application.
- Look for repeated connections to multiple internal targets, which can indicate probing or exploitation.

Evidence to collect:
- DeviceName, initiating process, initiating account, RemoteIP, RemotePort, RemoteUrl, ActionType, and alert timestamp.
- A list of known legitimate PeopleSoft internal destinations for comparison.
- Any related inbound web requests or application errors around the same time.
- Any additional network events from the same host showing repeated internal connections or metadata access.

Pivot points:
- DeviceNetworkEvents for the same host to identify all internal destinations contacted by the PeopleSoft process.
- DeviceProcessEvents to see whether the network activity is paired with suspicious child processes.
- Web server or reverse proxy logs to correlate inbound requests that may have triggered SSRF.
- DNS or firewall logs to determine whether the destination is a normal application dependency.

Benign explanations:
- PeopleSoft commonly communicates with internal databases, LDAP, SMTP, and middleware over private IP space.
- Cloud-hosted systems may legitimately contact instance metadata endpoints for identity or configuration.
- Integration jobs or scheduled tasks may create internal connections that look unusual without environment context.

Escalation criteria:
- The destination is a metadata service, admin interface, or internal host that PeopleSoft should not contact.
- The connection pattern is new, repeated, or targets multiple internal systems in a short period.
- You find concurrent signs of exploitation such as suspicious inbound requests or unexpected child processes.
- The traffic reaches sensitive internal services or is followed by authentication, data access, or lateral movement indicators.

Containment actions:
- If SSRF exploitation is likely, restrict the PeopleSoft server's outbound access to only approved destinations.
- Block access to metadata endpoints and other sensitive internal targets from the application tier.
- Preserve logs and network evidence before making changes if you suspect active compromise.

Closure criteria:
- The destination is confirmed as a documented and expected PeopleSoft dependency.
- The traffic pattern matches known integration or maintenance behavior and no other suspicious activity is present.
- A baseline of approved internal destinations is established and the event is explained by normal application communication.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Telemetry availability:
- Ivanti Sentry - Shell Spawned by Web Service Process (CVE-2026-10520 RCE): Environment-specific telemetry or field mapping must be resolved for Both: DeviceProcessEvents, Syslog before scheduling.
- Ivanti Sentry - Unauthenticated POST to Admin API Endpoint (CVE-2026-10523 Auth Bypass): Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.
- Oracle PeopleSoft - Unexpected Child Process Spawned by PeopleSoft Web Service (CVE-2026-35273 RCE): Environment-specific telemetry or field mapping must be resolved for Both: DeviceProcessEvents, Syslog before scheduling.
- Oracle PeopleSoft - SSRF-Induced Outbound Connections to Internal Addresses (CVE-2026-35273): The ActionType value 'ConnectionSuccess' must be validated against the actual ActionType values present in DeviceNetworkEvents for the environment; some connector versions use 'NetworkConnectionEvents' action type naming.

Shared-table notes:
- DeviceProcessEvents: shared by Ivanti Sentry - Shell Spawned by Web Service Process (CVE-2026-10520 RCE); Oracle PeopleSoft - Unexpected Child Process Spawned by PeopleSoft Web Service (CVE-2026-35273 RCE)
- Syslog: shared by Ivanti Sentry - Shell Spawned by Web Service Process (CVE-2026-10520 RCE); Ivanti Sentry - Unauthenticated POST to Admin API Endpoint (CVE-2026-10523 Auth Bypass); Oracle PeopleSoft - Unexpected Child Process Spawned by PeopleSoft Web Service (CVE-2026-35273 RCE)

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: Ivanti Sentry - Shell Spawned by Web Service Process (CVE-2026-10520 RCE); Ivanti Sentry - Unauthenticated POST to Admin API Endpoint (CVE-2026-10523 Auth Bypass); Oracle PeopleSoft - Unexpected Child Process Spawned by PeopleSoft Web Service (CVE-2026-35273 RCE); Oracle PeopleSoft - SSRF-Induced Outbound Connections to Internal Addresses (CVE-2026-35273).

### Hunting Agenda and Promotion Criteria

- Ivanti Sentry - Shell Spawned by Web Service Process (CVE-2026-10520 RCE): Environment-specific telemetry or field mapping must be resolved for Both: DeviceProcessEvents, Syslog before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- Ivanti Sentry - Unauthenticated POST to Admin API Endpoint (CVE-2026-10523 Auth Bypass): Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.; prove correlation keys join correctly on real tenant telemetry.
- Oracle PeopleSoft - Unexpected Child Process Spawned by PeopleSoft Web Service (CVE-2026-35273 RCE): Environment-specific telemetry or field mapping must be resolved for Both: DeviceProcessEvents, Syslog before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- Oracle PeopleSoft - SSRF-Induced Outbound Connections to Internal Addresses (CVE-2026-35273): The ActionType value 'ConnectionSuccess' must be validated against the actual ActionType values present in DeviceNetworkEvents for the environment; some connector versions use 'NetworkConnectionEvents' action type naming.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
