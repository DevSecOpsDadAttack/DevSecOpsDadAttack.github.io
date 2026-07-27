---
layout: post
title: "Detection Engineering Brief - Monday, July 27, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-27
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-16232
  - T1190
  - Check Point SmartConsole
  - Check Point Security Management
  - Check Point Multi-Domain Management
  - Spring Boot
  - Java
  - actuator heapdump
  - T1005
---

## Detection Engineering Summary

This brief produced 4 detection candidates.

0 production candidates, 1 hunting-only, 3 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-16232, T1190, Check Point SmartConsole, Check Point Security Management, Check Point Multi-Domain Management, Spring Boot, Java, actuator heapdump, T1005.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Check Point SmartConsole Auth Bypass - Token Issued Without Valid Credentials; Check Point SmartConsole - Security Policy Modification Following Anomalous Admin Login; Spring Boot Actuator Heapdump Endpoint Access Detected; Spring Boot Heapdump File Creation on Application Host.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Check Point SmartConsole Auth Bypass - Token Issued Without Valid Credentials

### Detection Opportunity

Unauthenticated remote attacker obtains application login token via SmartConsole authentication bypass (CVE-2026-16232).

### Intelligence Context

- Rapid7: CVE-2026-16232: Critical Check Point SmartConsole Authentication Bypass Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-16232-critical-check-point-smartconsole-authentication-bypass-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-16232-critical-check-point-smartconsole-authentication-bypass-exploited-in-the-wild)
  - Context: CVE-2026-16232 allows an unauthenticated remote attacker to obtain a valid application login token through the SmartConsole login process without supplying credentials, then authenticate to the management server with full administrative privileges.

### Search Metadata

- CVEs: CVE-2026-16232
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Check Point SmartConsole, Check Point Security Management, Check Point Multi-Domain Management
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-16232, T1190, Check Point SmartConsole, Check Point Security Management, Check Point Multi-Domain Management

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
let lookback = 1h;
let correlationWindow = 30m;
let authBypass =
    CommonSecurityLog
    | where TimeGenerated >= ago(lookback)
    | where DeviceVendor == "Check Point"
    | where Activity has_any ("login", "authentication", "token") or Message has_any ("login", "token issued", "authenticated")
    | where DeviceAction has_any ("accept", "success", "allow")
    | where isempty(SourceUserName) or SourceUserName in ("", "-", "N/A", "unknown")
    | where isnotempty(SourceIP)
    | project
        BypassTime = TimeGenerated,
        SourceIP,
        DestinationIP,
        BypassActivity = Activity,
        BypassMessage = Message,
        BypassAction = DeviceAction,
        BypassSeverity = LogSeverity;
let adminActivity =
    CommonSecurityLog
    | where TimeGenerated >= ago(lookback)
    | where DeviceVendor == "Check Point"
    | where Activity has_any ("policy", "install", "admin", "management", "configuration") or Message has_any ("policy install", "admin login", "management access")
    | where DeviceAction has_any ("accept", "success", "allow")
    | where isnotempty(SourceIP)
    | project
        AdminTime = TimeGenerated,
        SourceIP,
        AdminActivity = Activity,
        AdminMessage = Message,
        AdminUser = SourceUserName;
authBypass
| join kind=inner (
    adminActivity
) on SourceIP
| where AdminTime >= BypassTime and AdminTime <= (BypassTime + correlationWindow)
| project
    BypassTime,
    AdminTime,
    SourceIP,
    DestinationIP,
    BypassActivity,
    BypassMessage,
    BypassAction,
    BypassSeverity,
    AdminActivity,
    AdminMessage,
    AdminUser
| sort by BypassTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Service accounts or automation tools that authenticate to Check Point management without a human username may trigger the empty-username condition.
- Legitimate admin sessions from IPs that also appear in the authBypass set due to shared NAT or proxy infrastructure.
- Check Point internal health-check or API polling processes that emit successful auth events without a username.

**Tuning notes:**
- Adjust correlationWindow from 30m to a value reflecting observed attacker dwell time in your environment after confirming baseline admin session patterns.
- After confirming the exact Activity and Message field values emitted by your Check Point firmware, narrow the has_any keyword lists to reduce false positive join matches.
- Consider adding a DeviceProduct filter (e.g., DeviceProduct has_any ('SmartConsole', 'Security Management')) if your Check Point syslog profile populates this field, to scope the query away from gateway events.

**Risks / caveats:**
- CommonSecurityLog requires the Check Point syslog connector to be configured and actively forwarding events with DeviceVendor='Check Point'; if this connector is absent or misconfigured, the query returns no results.
- The SourceUserName field in CommonSecurityLog is only populated if the Check Point syslog profile is configured to emit the username field; many default Check Point syslog profiles omit this field, making the empty-username bypass signal unreliable.
- The Activity field in CommonSecurityLog is mapped from the Check Point DeviceEventClassID or Name field; the specific string values ('login', 'authentication', 'token') must match the actual event names emitted by the deployed Check Point firmware version.
- The 30-minute correlation window between bypass and admin activity is a heuristic; fast-moving attackers may act within seconds while slow-moving ones may exceed 30 minutes.

### Triage Runbook

**First 15 minutes:**
- Confirm the alert is tied to a Check Point management system, not a gateway or unrelated syslog source.
- Review the bypass event details for empty or unknown SourceUserName, the source IP, destination IP, and the exact message text indicating token issuance or successful authentication.
- Check whether the same source IP performed policy install, configuration change, admin login, or other management actions within the correlation window.
- Look for concurrent signs of management-plane abuse such as new admin creation, policy pushes, object changes, or repeated login attempts from the same source.
- Determine whether the source IP belongs to a known jump host, VPN pool, NAT device, or automation system before treating it as hostile.

**Evidence to collect:**
- BypassTime, AdminActivityTime, SourceIP, DestinationIP, BypassActivity, BypassMessage, AdminActivity, AdminMessage, and any admin username present.
- Check Point audit logs around the alert window showing login, token issuance, policy install, object modification, and configuration change events.
- Source IP ownership details from VPN, proxy, NAT, or jump-host records to determine whether the IP is expected for administrators.
- Any recent change tickets or maintenance records that explain management activity from that source.
- If available, management server logs showing session creation, token use, or admin account changes.

**Pivot points:**
- CommonSecurityLog for all Check Point events from the same SourceIP and DestinationIP in the 1 hour before and after the alert.
- CommonSecurityLog for the same SourceIP across the last 24 hours to identify repeated login or policy activity.
- CommonSecurityLog filtered to DeviceVendor = Check Point and Activity or Message containing policy install, admin login, configuration change, object modify, or management access.
- If available, VPN, proxy, or firewall logs to map the source IP to a user, host, or network segment.

**Benign explanations:**
- A service account or automation tool may authenticate without a human username and then perform legitimate management actions.
- A shared NAT or proxy IP may make a legitimate admin session appear to come from the same source as the bypass event.
- Internal health checks or API polling processes may emit successful auth events without a populated username field.

**Escalation criteria:**
- Any policy install, rule change, object modification, or admin account change follows the bypass event from the same source IP.
- The source IP is external, unknown, or not associated with approved admin infrastructure.
- Multiple management actions occur in a short period, especially if they are outside normal change windows.
- There is evidence of new admin creation, privilege changes, or attempts to disable logging or security controls.

**Containment actions:**
- If the source is untrusted and admin activity is confirmed, block the source IP at the perimeter or management access layer.
- Disable or rotate affected Check Point admin credentials and revoke active sessions or tokens if the platform supports it.
- Preserve management server and audit logs before making disruptive changes.
- If compromise is likely, restrict management-plane access to approved admin networks until the investigation is complete.

**Closure criteria:**
- The source IP is verified as a known admin, automation, or maintenance system and the activity matches an approved change record.
- No subsequent administrative actions are found after the token issuance event.
- The event is attributable to a known benign process such as internal health checking or a documented API workflow.
- Evidence shows the alert was caused by schema noise or a misparsed syslog field rather than a real bypass.

<br/>
---
<br/>

## Detection 2: Check Point SmartConsole - Security Policy Modification Following Anomalous Admin Login

### Detection Opportunity

Security policy or configuration modification on Check Point management systems following an admin login from an unexpected source IP, consistent with post-exploitation activity after CVE-2026-16232 abuse.

### Intelligence Context

- Rapid7: CVE-2026-16232: Critical Check Point SmartConsole Authentication Bypass Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-16232-critical-check-point-smartconsole-authentication-bypass-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-16232-critical-check-point-smartconsole-authentication-bypass-exploited-in-the-wild)
  - Context: After obtaining a valid admin token via the SmartConsole authentication bypass, the attacker can modify security policies and configurations on the management server. Policy install and rule modification events in Check Point audit logs represent high-impact post-exploitation activity.

### Search Metadata

- CVEs: CVE-2026-16232
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Check Point SmartConsole, Check Point Security Management, Check Point Multi-Domain Management
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-16232, T1190, Check Point SmartConsole, Check Point Security Management, Check Point Multi-Domain Management

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
let lookback = 1d;
let baseline_window = 14d;
let knownAdminIPs =
    CommonSecurityLog
    | where TimeGenerated between (ago(baseline_window) .. ago(lookback))
    | where DeviceVendor == "Check Point"
    | where Activity has_any ("policy install", "policy push", "rule modify", "object modify", "configuration change")
        or Message has_any ("policy install", "install policy", "rule modify", "object modified", "configuration changed")
    | where isnotempty(SourceIP)
    | summarize by SourceIP;
CommonSecurityLog
| where TimeGenerated >= ago(lookback)
| where DeviceVendor == "Check Point"
| where Activity has_any ("policy install", "policy push", "rule modify", "object modify", "configuration change")
    or Message has_any ("policy install", "install policy", "rule modify", "object modified", "configuration changed")
| where DeviceAction has_any ("accept", "success", "allow")
| where isnotempty(SourceIP)
| join kind=leftanti (
    knownAdminIPs
) on SourceIP
| project
    TimeGenerated,
    SourceIP,
    SourceUserName,
    Activity,
    Message,
    LogSeverity,
    DeviceAction
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- New legitimate admin workstations or jump hosts added to the environment within the last 14 days will alert until they accumulate baseline history.
- VPN or NAT infrastructure changes that cause legitimate admins to appear from new source IPs.
- Automated policy deployment pipelines running from CI/CD infrastructure with rotating or ephemeral IPs.

**Tuning notes:**
- Extend baseline_window beyond 14 days if your environment has sufficient log retention and admin activity is infrequent, to reduce new-IP false positives.
- After confirming the exact Activity and Message field values emitted by your Check Point firmware for policy change events, narrow the keyword lists to reduce false positive matches on unrelated management traffic.
- Consider supplementing the IP-based baseline with a SourceUserName-based baseline to detect token theft scenarios where a known IP is used with an unexpected username.

**Risks / caveats:**
- CommonSecurityLog requires the Check Point syslog connector to be configured and actively forwarding events with DeviceVendor='Check Point'; if absent, both the baseline and detection queries return no results.
- If the environment has fewer than 14 days of Check Point logs in CommonSecurityLog, the knownAdminIPs baseline will be empty and every policy change event will generate an alert, making the detection operationally unusable until sufficient history accumulates.
- The Activity and Message field values used to identify policy change events must match the exact strings emitted by the deployed Check Point firmware; mismatches will cause the detection query to return no results.
- The 14-day baseline window is a heuristic; environments where legitimate admins connect infrequently may have gaps in the baseline that cause false positives.

### Triage Runbook

**First 15 minutes:**
- Identify the SourceIP, SourceUserName, Activity, Message, and LogSeverity for the policy change event.
- Check whether the source IP is new for this admin account or absent from the 14-day baseline of known admin IPs.
- Review surrounding events for login, token issuance, policy install, object modification, or configuration changes from the same source.
- Validate whether the change occurred during an approved maintenance window or change ticket.
- Determine whether the modified policy could expose the environment, such as allowing new inbound access, disabling protections, or changing management access.

**Evidence to collect:**
- The exact policy or configuration change details from Check Point audit logs.
- SourceIP and SourceUserName history for the last 14 days or longer if available.
- Change management records, maintenance approvals, and admin roster information.
- Any related login events, especially from unusual geographies, VPNs, or jump hosts.
- Screenshots or exported audit records showing the before-and-after policy state if available.

**Pivot points:**
- CommonSecurityLog for the same SourceIP and SourceUserName over the last 14 days to determine whether this is a known admin path.
- CommonSecurityLog for policy install, rule modify, object modify, and configuration change events around the alert time.
- CommonSecurityLog for admin login or token issuance events from the same source IP in the preceding hour.
- If available, VPN, proxy, or identity logs to validate whether the account and source host are expected.

**Benign explanations:**
- A newly deployed admin workstation or jump host may not yet exist in the 14-day baseline.
- A legitimate admin may connect through a new VPN exit node or NAT address.
- Automated policy deployment pipelines may use ephemeral infrastructure that appears as a new source IP.
- A scheduled change by a valid administrator may be the first time that IP has performed policy work.

**Escalation criteria:**
- The source IP is external, unrecognized, or not tied to approved admin infrastructure.
- The policy change is outside a change window or lacks a corresponding ticket.
- The change materially weakens security, opens management access, or disables logging or protections.
- There is evidence of multiple suspicious admin actions from the same source or account.

**Containment actions:**
- If the change is unauthorized, revert the policy or configuration to the last known good state.
- Disable the affected admin account and revoke active sessions or tokens.
- Block the suspicious source IP from management access until legitimacy is confirmed.
- Preserve audit logs and configuration backups before rollback if possible.

**Closure criteria:**
- The source IP and account are confirmed as legitimate and match an approved change record.
- The policy change is validated as expected maintenance with no additional suspicious activity.
- The baseline gap is explained by a new but authorized admin host or automation path.
- No evidence suggests unauthorized access, privilege escalation, or malicious policy weakening.

<br/>
---
<br/>

## Detection 3: Spring Boot Actuator Heapdump Endpoint Access Detected

### Detection Opportunity

External scanning or retrieval of the Spring Boot /actuator/heapdump endpoint, which exposes JVM heap memory including application secrets.

### Intelligence Context

- SANS ISC: Java Spring Boot "heapdump" scans, (Mon, Jul 27th) — [https://isc.sans.edu/diary/rss/33188](https://isc.sans.edu/diary/rss/33188)
  - Context: Active scanning for exposed Spring Boot /actuator/heapdump endpoints has been observed. Successful retrieval returns a heapdump.hprof file containing JVM heap memory, which frequently includes application secrets such as credentials and API keys.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1005
- Products: Spring Boot, actuator heapdump
- Platforms: Java
- Malware: Not specified
- Tools: Not specified
- Search tags: Spring Boot, Java, actuator heapdump, T1005

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: medium
- MITRE ATT&CK: Collection: T1005 Data from Local System (medium)

### Deployment Gates

- The Syslog table SourceIP assignment is hardcoded to an empty string in the original query because Syslog does not have a native SourceIP field; this means source IP attribution is unavailable for the Syslog branch unless the IP is parsed from SyslogMessage.

**Required telemetry:**
- CommonSecurityLog, Syslog

### KQL

```kql
let lookback = 1d;
let heapdumpPath = "/actuator/heapdump";
union
    (
        CommonSecurityLog
        | where TimeGenerated >= ago(lookback)
        | where RequestURL has heapdumpPath or Message has heapdumpPath
        | project
            TimeGenerated,
            SourceIP,
            RequestURL,
            Message,
            DeviceAction,
            LogSeverity,
            DeviceName,
            Source = "CommonSecurityLog"
    ),
    (
        Syslog
        | where TimeGenerated >= ago(lookback)
        | where SyslogMessage has heapdumpPath
        | extend SourceIP = extract(@"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", 1, SyslogMessage)
        | project
            TimeGenerated,
            SourceIP,
            RequestURL = "",
            Message = SyslogMessage,
            DeviceAction = "",
            LogSeverity = SeverityLevel,
            DeviceName = HostName,
            Source = "Syslog"
    )
| summarize
    AccessCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SampleMessages = make_set(Message, 3)
    by SourceIP, DeviceName, Source
| sort by AccessCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Internal security scanning tools or vulnerability scanners that probe for exposed actuator endpoints as part of authorized assessments.
- Developer workstations accessing heapdump endpoints on non-production Spring Boot instances forwarded through the same log pipeline.
- Load balancer or health-check probes that include the actuator path in their request URIs.

**Tuning notes:**
- If your CommonSecurityLog source includes HTTP response codes in the Message or AdditionalExtensions field, add a filter for response code 200 to prioritise confirmed successful retrievals.
- Scope DeviceName to known internet-facing Java application hosts using a watchlist or explicit DeviceName filter to reduce noise from internal scanning tools.
- Adjust the lookback window based on your environment's ingestion latency and the expected frequency of scanning activity.

**Risks / caveats:**
- The RequestURL field in CommonSecurityLog is only populated when the log source is a web proxy, WAF, or application delivery controller configured to emit HTTP request details; generic firewall or IDS sources typically do not populate this field.
- The Syslog table SourceIP assignment is hardcoded to an empty string in the original query because Syslog does not have a native SourceIP field; this means source IP attribution is unavailable for the Syslog branch unless the IP is parsed from SyslogMessage.
- If neither CommonSecurityLog nor Syslog sources in the environment include full HTTP request URIs, the query will return no results regardless of actual heapdump access attempts.
- The IP extraction regex in the Syslog branch extracts the first IPv4 address found in SyslogMessage, which may be the server IP rather than the client IP depending on the log format.

### Triage Runbook

**First 15 minutes:**
- Identify the source IP, target host, access count, and first and last seen times.
- Check whether the request path is exactly /actuator/heapdump and whether the response appears successful or blocked.
- Determine whether the target host is internet-facing and whether it is a production Java application.
- Look for repeated requests from the same source or multiple hosts, which would indicate scanning rather than a single accidental hit.
- Verify whether the source belongs to an approved scanner, vulnerability assessment, or internal testing team.

**Evidence to collect:**
- AccessCount, FirstSeen, LastSeen, SourceIP, DeviceName, Source, and SampleMessages from the alert.
- Raw web, proxy, WAF, or syslog records showing the request URI, response status, and user agent if available.
- Host inventory data confirming whether the target is a production Spring Boot application.
- Any change tickets or authorized scan windows covering the source IP or target host.
- If available, adjacent logs showing follow-on requests for other actuator endpoints or sensitive files.

**Pivot points:**
- CommonSecurityLog for the same SourceIP and DeviceName to identify other actuator or sensitive path requests.
- Syslog or proxy logs for the target host to confirm whether the request was allowed, denied, or returned a file.
- Web server or WAF logs for response codes, user agents, and request frequency from the same source.
- Asset inventory or CMDB data to confirm whether the host is a production Java application.

**Benign explanations:**
- An authorized vulnerability scan may probe /actuator/heapdump as part of routine testing.
- A developer or operator may access a non-production Spring Boot instance during troubleshooting.
- A load balancer, health check, or monitoring tool may include the path in a probe or misconfigured request.
- A single request may be an accidental browser or crawler hit rather than deliberate exploitation.

**Escalation criteria:**
- The source IP is external and not associated with approved testing or administration.
- Multiple requests or multiple hosts indicate active scanning for heapdump exposure.
- The target is a production internet-facing application and the request appears successful.
- There are signs of follow-on activity such as additional sensitive endpoint probing or credential harvesting.

**Containment actions:**
- If the host is exposed and the access appears malicious, block the source IP at the WAF, proxy, or firewall.
- Disable or restrict the actuator heapdump endpoint if it is not required.
- If a successful retrieval is suspected, rotate application secrets and credentials that may be present in memory.
- Preserve web and application logs before making configuration changes.

**Closure criteria:**
- The activity is confirmed as an approved scan, test, or internal troubleshooting action.
- The target host is non-production and the access aligns with expected developer or operator behavior.
- The request was blocked and there is no evidence of successful retrieval or follow-on exploitation.
- The source and target are explained by a documented monitoring or health-check workflow.

<br/>
---
<br/>

## Detection 4: Spring Boot Heapdump File Creation on Application Host

### Detection Opportunity

Creation of a heapdump.hprof file on a production Java application host, indicating successful exploitation or triggering of the Spring Boot actuator heapdump endpoint.

### Intelligence Context

- SANS ISC: Java Spring Boot "heapdump" scans, (Mon, Jul 27th) — [https://isc.sans.edu/diary/rss/33188](https://isc.sans.edu/diary/rss/33188)
  - Context: When the /actuator/heapdump endpoint is successfully accessed, Spring Boot generates and returns a heapdump.hprof file containing the full JVM heap, which may include secrets, credentials, and API keys used by the application.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1005
- Products: Spring Boot, actuator heapdump
- Platforms: Java
- Malware: Not specified
- Tools: Not specified
- Search tags: Spring Boot, Java, actuator heapdump, T1005

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Collection: T1005 Data from Local System (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
DeviceFileEvents
| where TimeGenerated >= ago(7d)
| where ActionType == "FileCreated"
| where FileName endswith ".hprof" or FileName has "heapdump"
| where InitiatingProcessFileName has_any ("java", "java.exe", "javaw", "javaw.exe")
| project
    TimeGenerated,
    DeviceName,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    ActionType
| sort by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Authorized heap dump generation by operations teams using JVM diagnostic tools such as jmap or jcmd running under a Java process.
- Application performance monitoring agents that trigger periodic heap dumps for memory analysis.
- CI/CD build agents running Java test suites that generate heap dumps on out-of-memory errors.

**Tuning notes:**
- Scope DeviceName to a watchlist of known internet-facing Java application servers to reduce hits from developer workstations and CI/CD agents.
- If converting to a scheduled rule, reduce the lookback window to match the rule execution interval and add a deduplication step on DeviceName and FileName.
- Consider correlating DeviceFileEvents hits with DeviceNetworkEvents for inbound HTTP connections to the same host within a short time window to increase confidence that the file creation was triggered by an external request.

**Risks / caveats:**
- DeviceFileEvents requires Microsoft Defender for Endpoint (MDE) agent deployment on the Java application hosts; Linux hosts without the MDE agent will not appear in this table.
- Spring Boot's heapdump endpoint in many configurations streams the heap dump directly to the HTTP response without writing a persistent file to disk; in such configurations, this detection will produce no results even when the endpoint is successfully accessed.
- If Spring Boot is configured to stream the heap dump directly without writing to disk, this detection will not fire even on successful endpoint access.
- The 7-day lookback is a hunting window; if converted to a scheduled rule, the lookback should be reduced to match the rule execution frequency to avoid duplicate alerts.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a production Java application server and not a developer workstation, CI runner, or test system.
- Review the file path, file name, initiating process, and command line to see whether the heap dump was created by java, jmap, jcmd, or another diagnostic tool.
- Check whether the file creation time aligns with a known maintenance window, incident response activity, or performance investigation.
- Look for concurrent inbound web requests or process activity that could indicate the file was created after external access to /actuator/heapdump.
- Assess whether the file still exists and whether it may contain sensitive application memory, credentials, or API keys.

**Evidence to collect:**
- TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, and ActionType.
- Any web or proxy logs showing requests to /actuator/heapdump on the same host around the same time.
- Process creation and command-line logs for the Java process or diagnostic utilities that created the file.
- File metadata such as size, location, and whether the file was subsequently accessed, copied, or deleted.
- Change records or operator notes explaining any intentional heap dump collection.

**Pivot points:**
- DeviceFileEvents for other .hprof or heapdump-related file creations on the same host or by the same account.
- DeviceProcessEvents for jmap, jcmd, java, or other diagnostic commands around the alert time.
- DeviceNetworkEvents for inbound connections to the host that may have triggered the heap dump request.
- Web server, reverse proxy, or WAF logs for requests to /actuator/heapdump on the same host.

**Benign explanations:**
- Operations staff may intentionally generate a heap dump during troubleshooting or memory analysis.
- Application performance monitoring tools may trigger heap dumps as part of diagnostics.
- A Java test or build process may create .hprof files on non-production systems.
- A controlled incident response activity may intentionally collect a heap dump for analysis.

**Escalation criteria:**
- The host is production and the heap dump was not authorized.
- The file creation is paired with suspicious inbound web activity or external scanning.
- The heap dump was created by an unexpected process, account, or command line.
- The file was copied, compressed, or accessed by another process shortly after creation.

**Containment actions:**
- If unauthorized, isolate the host from the network if business impact allows and preserve the heap dump and related logs.
- Rotate application secrets, API keys, and credentials that may be present in memory if exposure is suspected.
- Remove or secure the heapdump file after evidence preservation to prevent further access.
- Disable the actuator heapdump endpoint or restrict access if the host remains exposed.

**Closure criteria:**
- The heap dump was created by an approved diagnostic or monitoring workflow.
- The host is non-production and the file creation is expected for testing or development.
- No evidence links the file creation to external access or unauthorized activity.
- The file was created and handled according to documented change or incident procedures.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- Check Point SmartConsole Auth Bypass - Token Issued Without Valid Credentials: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.
- Check Point SmartConsole - Security Policy Modification Following Anomalous Admin Login: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.
- Spring Boot Actuator Heapdump Endpoint Access Detected: The Syslog table SourceIP assignment is hardcoded to an empty string in the original query because Syslog does not have a native SourceIP field; this means source IP attribution is unavailable for the Syslog branch unless the IP is parsed from SyslogMessage.

**Schema / correlation keys:**
- Spring Boot Heapdump File Creation on Application Host: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- CommonSecurityLog: shared by Check Point SmartConsole Auth Bypass - Token Issued Without Valid Credentials; Check Point SmartConsole - Security Policy Modification Following Anomalous Admin Login; Spring Boot Actuator Heapdump Endpoint Access Detected

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: Check Point SmartConsole Auth Bypass - Token Issued Without Valid Credentials; Check Point SmartConsole - Security Policy Modification Following Anomalous Admin Login; Spring Boot Actuator Heapdump Endpoint Access Detected.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Spring Boot Heapdump File Creation on Application Host.

### Hunting Agenda and Promotion Criteria

- Spring Boot Heapdump File Creation on Application Host: Do not schedule yet; validate as an analyst-led hunt first..
- Check Point SmartConsole Auth Bypass - Token Issued Without Valid Credentials: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Check Point SmartConsole - Security Policy Modification Following Anomalous Admin Login: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- Spring Boot Actuator Heapdump Endpoint Access Detected: The Syslog table SourceIP assignment is hardcoded to an empty string in the original query because Syslog does not have a native SourceIP field; this means source IP attribution is unavailable for the Syslog branch unless the IP is parsed from SyslogMessage..

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
