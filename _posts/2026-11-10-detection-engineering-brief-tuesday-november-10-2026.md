---
layout: post
title: "Detection Engineering Brief - Tuesday, November 10, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-11-10
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-123158
  - SSH
  - Cowrie
  - SAP NetWeaver
  - T1595
---

## Detection Engineering Summary

This brief produced 2 detection candidates.

0 production candidates, 0 hunting-only, 2 require environment mapping, and 0 rejected.

2 detections include KQL. 2 include ATT&CK mappings. 2 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-123158, SSH, Cowrie, SAP NetWeaver, T1595.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: SSH Exploitation Scanning - High Frequency Inbound Connections CVE-2026-123158; SAP NetWeaver Webshell Scanning - Inbound HTTP Requests to JSP and WAR Paths.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: SSH Exploitation Scanning - High Frequency Inbound Connections CVE-2026-123158

### Detection Opportunity

High-frequency inbound SSH connection attempts from distinct external IPs targeting port 22, consistent with active exploitation scanning observed for CVE-2026-123158.

### Intelligence Context

- SANS ISC: Scans for Sshole Vulnerability (CVE-2026-123158), (Sun, Nov 8th) — [https://isc.sans.edu/diary/rss/33498](https://isc.sans.edu/diary/rss/33498)
  - Context: Honeypots observed an increase in exploitation attempts targeting SSH services via CVE-2026-123158. Cowrie honeypot telemetry confirmed volumetric scanning activity against port 22 from external sources.

### Search Metadata

- CVEs: CVE-2026-123158
- Threat actors: Not specified
- ATT&CK tags: T1595
- Products: Not specified
- Platforms: SSH
- Malware: Not specified
- Tools: Cowrie
- Search tags: CVE-2026-123158, SSH, Cowrie, T1595

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Both
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Reconnaissance: T1595 Active Scanning (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Both: DeviceNetworkEvents, DeviceLogonEvents before scheduling.

**Required telemetry:**
- DeviceNetworkEvents, DeviceLogonEvents

### KQL

```kql
let timeWindow = 10m;
let connectionThreshold = 20;
let failureThreshold = 10;
let highFreqSSH =
    DeviceNetworkEvents
    | where TimeGenerated >= ago(1h)
    | where LocalPort == 22
    | where ActionType in ("InboundConnectionAccepted", "ConnectionRequest")
    | where not(RemoteIP startswith "10."
        or RemoteIP startswith "192.168."
        or (RemoteIP startswith "172." and
            toint(split(RemoteIP, ".")[1]) between (16 .. 31)))
    | summarize
        ConnectionCount = count(),
        DeviceList = make_set(DeviceName),
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated)
        by RemoteIP, bin(TimeGenerated, timeWindow)
    | where ConnectionCount >= connectionThreshold;
let sshFailures =
    DeviceLogonEvents
    | where TimeGenerated >= ago(1h)
    | where LogonType == "Network"
    | where LogonResult == "Failed"
    | where ProcessName has_any ("ssh", "sshd")
    | summarize
        FailureCount = count(),
        AffectedDevices = make_set(DeviceName),
        Accounts = make_set(AccountName)
        by RemoteIP, bin(TimeGenerated, timeWindow)
    | where FailureCount >= failureThreshold;
highFreqSSH
| join kind=leftouter sshFailures on RemoteIP
| where isnotempty(FailureCount) or ConnectionCount >= connectionThreshold
| project
    TimeGenerated,
    RemoteIP,
    ConnectionCount,
    FailureCount = coalesce(FailureCount, 0),
    DeviceList,
    AffectedDevices = coalesce(AffectedDevices, dynamic([])),
    Accounts = coalesce(Accounts, dynamic([])),
    FirstSeen,
    LastSeen
| order by ConnectionCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate security scanners or vulnerability assessment tools run from external IPs against internet-facing SSH services.
- Cloud provider health check IPs that probe SSH availability at high frequency.
- Misconfigured SSH clients retrying authentication against the wrong host.

**Tuning notes:**
- Increase connectionThreshold if legitimate external SSH monitoring or jump hosts generate high connection counts.
- Reduce timeWindow to 5m for higher sensitivity in environments with fast-moving scanning campaigns.
- Add a known-safe IP allowlist using a let statement and a where RemoteIP !in (allowlist) filter to suppress recurring FPs from authorized scanners.
- If DeviceLogonEvents SSH coverage is confirmed absent, consider running the network-only leg as a standalone hunting query without the join.

**Risks / caveats:**
- DeviceNetworkEvents inbound connection ActionType values ('InboundConnectionAccepted', 'ConnectionRequest') may not be populated for SSH on Linux hosts depending on MDE Linux agent version and network telemetry configuration — confirm these ActionType values exist in the environment before scheduling.
- DeviceLogonEvents does not consistently surface SSH PAM authentication failures as LogonType 'Network' with LogonResult 'Failed' on Linux across all MDE agent versions — validate that SSH failures appear in this table before relying on the join.
- The 1-hour lookback window may miss slow-and-low scanning campaigns that distribute attempts over longer periods.
- Ingestion delay between DeviceNetworkEvents and DeviceLogonEvents may cause the join to miss correlated events at the boundary of the time window.

### Triage Runbook

**First 15 minutes:**
- Confirm the target host is internet-facing and whether SSH on port 22 should be reachable from the source IPs observed.
- Review the alert for RemoteIP, ConnectionCount, FailureCount, DeviceList, AffectedDevices, Accounts, FirstSeen, and LastSeen to determine whether the activity is concentrated on one host or spread across multiple hosts.
- Check whether the source IPs belong to an approved vulnerability scanner, cloud health check, jump host, or managed service provider.
- Look for any successful SSH logons, unusual accounts, or follow-on activity from the same source IPs around the alert window.

**Evidence to collect:**
- Source IPs, connection rate, and whether attempts were distributed across one or many destination hosts.
- Any correlated failed SSH logons, successful logons, or account names associated with the same RemoteIP.
- Host exposure details: public IP, security group/firewall rules, and whether SSH is expected to be open.
- Historical frequency of similar alerts from the same source IPs or against the same host.
- Any change tickets or scanner schedules that explain the traffic.

**Pivot points:**
- DeviceNetworkEvents filtered on the same RemoteIP, LocalPort 22, and a wider time range to see scan duration and spread.
- DeviceLogonEvents for the same RemoteIP and affected hosts to check for failed or successful SSH authentication.
- DeviceInfo or asset inventory to confirm whether the destination host is a server, bastion, or exposed management system.
- Firewall, load balancer, or network appliance logs to validate whether the traffic was blocked, allowed, or rate-limited.

**Benign explanations:**
- Authorized vulnerability scanning or external security testing against exposed SSH services.
- Cloud provider or ISP health checks that probe SSH availability.
- Misconfigured automation or monitoring that retries SSH connections repeatedly.
- A known external management system or jump host generating expected connection bursts.

**Escalation criteria:**
- Any successful SSH authentication from the same source IPs, especially with privileged or unexpected accounts.
- Evidence that the source IPs are not authorized and the target host is a critical or sensitive system.
- Multiple hosts receiving the same pattern of SSH attempts, indicating broader scanning or worm-like activity.
- Any post-authentication activity, new processes, or lateral movement indicators on the target host.

**Containment actions:**
- None documented.

**Closure criteria:**
- Source IPs are confirmed as authorized scanner or health-check infrastructure.
- No successful logons, no suspicious follow-on activity, and the target host is expected to receive this traffic.
- The activity matches a documented maintenance or assessment window and is consistent with baseline behavior.
- The alert is attributable to benign retry behavior or a known misconfiguration and has been documented.

<br/>
---
<br/>

## Detection 2: SAP NetWeaver Webshell Scanning - Inbound HTTP Requests to JSP and WAR Paths

### Detection Opportunity

External actors sending HTTP GET requests to SAP NetWeaver URL paths associated with webshell artifacts, consistent with active scanning for previously deployed webshells.

### Intelligence Context

- SANS ISC: Attackers Searching for SAP Netweaver Webshells, (Mon, Nov 9th) — [https://isc.sans.edu/diary/rss/33502](https://isc.sans.edu/diary/rss/33502)
  - Context: Honeypot data revealed attackers actively scanning for SAP NetWeaver webshells via HTTP requests. A novel suspicious URL was observed targeting SAP NetWeaver infrastructure, indicating adversaries are probing for previously implanted webshells.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1595
- Products: SAP NetWeaver
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: SAP NetWeaver, T1595

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Reconnaissance: T1595 Active Scanning (high)

### Deployment Gates

- CommonSecurityLog.RequestURL and CommonSecurityLog.RequestMethod are not populated by all CEF-sending devices — these fields must be confirmed non-null in the ingested data from the specific WAF or proxy connector before the query produces meaningful results.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated >= ago(24h)
| where RequestMethod == "GET"
| where DestinationPort in (80, 443, 8080, 8443, 50000, 50001)
| where RequestURL has_any ("/irj/", "/webdynpro/", "/sap/", "/nwa/", "/bc/", "/servlet/")
    and RequestURL has_any (".jsp", ".war", ".jspx", "shell", "webshell", "cmd", "exec")
| where isnotempty(SourceIP)
| where not(SourceIP startswith "10."
    or SourceIP startswith "192.168."
    or (SourceIP startswith "172." and
        toint(split(SourceIP, ".")[1]) between (16 .. 31)))
| summarize
    RequestCount = count(),
    URLsSeen = make_set(RequestURL),
    Ports = make_set(DestinationPort),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP, DeviceProduct, DeviceVendor, bin(TimeGenerated, 1h)
| where RequestCount >= 3
| project
    TimeGenerated,
    SourceIP,
    DeviceProduct,
    DeviceVendor,
    RequestCount,
    URLsSeen,
    Ports,
    FirstSeen,
    LastSeen
| order by RequestCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate external SAP portal users accessing JSP-based SAP web applications through the same URL paths.
- Security researchers or authorized penetration testers probing SAP endpoints.
- Web crawlers or search engine bots indexing publicly accessible SAP web interfaces.
- Vulnerability scanners performing scheduled assessments against SAP infrastructure.

**Tuning notes:**
- Increase RequestCount threshold to 10 or more if legitimate external SAP portal users generate frequent JSP requests from the same IP.
- Add a DeviceProduct filter such as where DeviceProduct in ('known-waf-product-name') if multiple CEF sources are ingested and only WAF traffic is relevant.
- Extend URLsSeen make_set limit if analysts need to review more than the default 128 distinct URLs per source IP.
- Add a known-safe IP allowlist using a let statement and where SourceIP !in (allowlist) to suppress recurring FPs from authorized scanners or SAP support IPs.

**Risks / caveats:**
- CommonSecurityLog.RequestURL and CommonSecurityLog.RequestMethod are not populated by all CEF-sending devices — these fields must be confirmed non-null in the ingested data from the specific WAF or proxy connector before the query produces meaningful results.
- If no WAF, reverse proxy, or network security appliance fronting SAP NetWeaver is connected to Microsoft Sentinel via the CEF/CommonSecurityLog connector, this query will return no relevant results.
- SAP NetWeaver port 50000 and 50001 (ICM HTTP/HTTPS) are non-standard web ports that may not be forwarded by all proxy configurations — confirm whether traffic on these ports is captured by the upstream device.
- The 24-hour lookback window may surface historical scanning activity that has already been investigated — analysts should note FirstSeen and LastSeen to assess recency.

### Triage Runbook

**First 15 minutes:**
- Confirm whether the destination is a SAP NetWeaver system exposed through a WAF, reverse proxy, or security appliance and whether the observed ports and paths are expected.
- Review SourceIP, RequestURL, DestinationPort, RequestMethod, DeviceProduct, RequestCount, URLsSeen, Ports, FirstSeen, and LastSeen to understand scope and recency.
- Check whether the source IP belongs to an approved scanner, SAP support, or a known external testing provider.
- Look for related requests to other SAP administrative or upload paths, and determine whether the same source IP is probing multiple SAP hosts.

**Evidence to collect:**
- Exact RequestURL values and whether they contain webshell-related keywords such as shell, webshell, cmd, or exec.
- Source IP reputation and whether the source is external, known-safe, or previously seen in similar activity.
- Destination port and appliance details to confirm the traffic is actually reaching SAP NetWeaver front-end infrastructure.
- Any correlated WAF blocks, 4xx/5xx responses, or repeated requests from the same source IP.
- Historical occurrences of the same URL patterns against the same SAP environment.

**Pivot points:**
- CommonSecurityLog for the same SourceIP across a wider time window to identify other SAP-related paths or additional targets.
- CommonSecurityLog filtered on the destination host or appliance to see whether the same source is probing other management or application endpoints.
- WAF or reverse proxy logs for response codes, blocks, and request frequency from the same SourceIP.
- SAP application or web server logs, if available, to verify whether the requests reached the NetWeaver layer and whether any suspicious files were requested or served.

**Benign explanations:**
- Authorized vulnerability scanning or penetration testing against SAP NetWeaver.
- Search engine crawlers or web scanners indexing publicly accessible SAP web content.
- Legitimate external users accessing JSP-based SAP web applications through the same front-end appliance.
- Routine monitoring or support activity from a trusted external IP range.

**Escalation criteria:**
- The same source IP is probing multiple SAP hosts or repeatedly targeting sensitive SAP paths.
- Requests are followed by signs of webshell execution, unusual file creation, or suspicious server-side activity in SAP logs.
- The source IP is untrusted and the SAP system is internet-facing with no compensating controls or WAF blocks.
- There is evidence of successful access to administrative, upload, or execution-capable SAP endpoints.

**Containment actions:**
- None documented.

**Closure criteria:**
- The source IP is confirmed as authorized testing, support, or a known benign scanner.
- Requests were blocked or did not reach the SAP application layer, and no suspicious server-side activity is observed.
- The URL patterns match normal SAP application behavior in this environment and are consistent with baseline traffic.
- No additional indicators of compromise, webshell execution, or unauthorized access are found after log review.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- SSH Exploitation Scanning - High Frequency Inbound Connections CVE-2026-123158: Environment-specific telemetry or field mapping must be resolved for Both: DeviceNetworkEvents, DeviceLogonEvents before scheduling.
- SAP NetWeaver Webshell Scanning - Inbound HTTP Requests to JSP and WAR Paths: CommonSecurityLog.RequestURL and CommonSecurityLog.RequestMethod are not populated by all CEF-sending devices — these fields must be confirmed non-null in the ingested data from the specific WAF or proxy connector before the query produces meaningful results.

**Shared-table notes:**
- No major shared table dependency identified across this run.

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: SSH Exploitation Scanning - High Frequency Inbound Connections CVE-2026-123158; SAP NetWeaver Webshell Scanning - Inbound HTTP Requests to JSP and WAR Paths.

### Hunting Agenda and Promotion Criteria

- SSH Exploitation Scanning - High Frequency Inbound Connections CVE-2026-123158: Environment-specific telemetry or field mapping must be resolved for Both: DeviceNetworkEvents, DeviceLogonEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- SAP NetWeaver Webshell Scanning - Inbound HTTP Requests to JSP and WAR Paths: CommonSecurityLog.RequestURL and CommonSecurityLog.RequestMethod are not populated by all CEF-sending devices — these fields must be confirmed non-null in the ingested data from the specific WAF or proxy connector before the query produces meaningful results.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
