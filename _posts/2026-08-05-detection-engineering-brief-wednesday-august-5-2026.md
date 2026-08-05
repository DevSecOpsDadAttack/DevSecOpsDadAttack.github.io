---
layout: post
title: "Detection Engineering Brief - Wednesday, August 5, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-08-05
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-18577
  - CVE-2026-18556
  - T1190
  - N-able N-central
  - network traffic
  - endpoint
  - T1095
---

## Detection Engineering Summary

This brief produced 3 detection candidates.

0 production candidates, 1 hunting-only, 2 require environment mapping, and 0 rejected.

3 detections include KQL. 3 include ATT&CK mappings. 3 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-18577, CVE-2026-18556, T1190, N-able N-central, network traffic, endpoint, T1095.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: N-central Auth Bypass - Unauthenticated Admin Endpoint Access (CVE-2026-18577); N-central Post-Exploitation - Privileged Logon on Management Host Following Auth Bypass (CVE-2026-18577); Direct-to-IP C2 Communication - Outbound Connection Without DNS Resolution from Suspicious Process.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: N-central Auth Bypass - Unauthenticated Admin Endpoint Access (CVE-2026-18577)

### Detection Opportunity

Remote unauthenticated attacker accessed N-central administrative endpoints without prior authentication, consistent with active exploitation of CVE-2026-18577.

### Intelligence Context

- Rapid7: CVE-2026-18577: N-able N-central Authentication Bypass Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-18577-n-able-n-central-authentication-bypass-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-18577-n-able-n-central-authentication-bypass-exploited-in-the-wild)
  - Context: Rapid7 reported active in-the-wild exploitation of CVE-2026-18577, allowing remote unauthenticated attackers to bypass authentication and obtain administrative control of N-central servers. No prior authentication events precede the admin access in exploitation scenarios.

### Search Metadata

- CVEs: CVE-2026-18577, CVE-2026-18556
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: N-able N-central
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-18577, CVE-2026-18556, T1190, N-able N-central

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- CommonSecurityLog is only populated if N-central logs are forwarded to Sentinel via a CEF/Syslog connector with DeviceProduct set to 'N-central' or 'N-able'. This connector is not a default Sentinel data connector and must be configured explicitly.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
let lookback = 30m;
let adminPaths = dynamic(["/app", "/admin", "/api/admin", "/management"]);
let successCodes = dynamic(["200", "201", "302"]);
let authPaths = dynamic(["/login", "/auth", "/session"]);
let adminAccess = CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DeviceProduct has_any ("N-central", "N-able")
| where RequestURL has_any (adminPaths)
| where tostring(ResponseCode) has_any (successCodes)
| where ipv4_is_private(SourceIP) == false
| project AdminTime = TimeGenerated, SourceIP, RequestURL, ResponseCode, DeviceName;
let priorAuth = CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DeviceProduct has_any ("N-central", "N-able")
| where RequestURL has_any (authPaths)
| where tostring(ResponseCode) has_any (successCodes)
| project AuthTime = TimeGenerated, SourceIP;
adminAccess
| join kind=leftouter (
    priorAuth
) on SourceIP
| where isempty(AuthTime) or AuthTime < (AdminTime - lookback) or AuthTime > AdminTime
| summarize
    AdminTime = min(AdminTime),
    RequestURLs = make_set(RequestURL, 20),
    ResponseCodes = make_set(ResponseCode, 10),
    DeviceName = any(DeviceName)
    by SourceIP
| project AdminTime, SourceIP, RequestURLs, ResponseCodes, DeviceName
| order by AdminTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Automated monitoring or health-check agents that access admin endpoints from external IPs without a preceding login flow.
- API integrations that authenticate via token headers rather than a login endpoint, meaning no auth-path hit is recorded.
- Load balancer or reverse proxy health probes hitting admin paths from external-facing IPs.

**Tuning notes:**
- Extend lookback beyond 30 minutes if N-central session tokens persist longer before admin actions are taken.
- Add environment-specific admin URI paths to adminPaths after reviewing N-central access logs.
- Consider adding a minimum request count threshold to reduce noise from single accidental hits.

**Risks / caveats:**
- CommonSecurityLog is only populated if N-central logs are forwarded to Sentinel via a CEF/Syslog connector with DeviceProduct set to 'N-central' or 'N-able'. This connector is not a default Sentinel data connector and must be configured explicitly.
- RequestURL and ResponseCode fields in CommonSecurityLog are populated only if the forwarding device includes HTTP request metadata in the CEF payload. N-central may not emit these fields depending on version and logging configuration.
- The 30-minute lookback window may miss authentication events if the attacker's session was established earlier in the day; consider extending lookback for longer-lived sessions.
- Token-based or header-based authentication flows will not produce auth-path hits, causing legitimate API clients to appear as unauthenticated.

### Triage Runbook

**First 15 minutes:**
- Confirm the source IP is external and not a proxy, load balancer, monitoring system, or internal NAT address.
- Review the RequestURL sequence for the same SourceIP to verify admin-path access occurred without any preceding login/auth/session request in the lookback window.
- Check whether the response codes are successful and whether the access targeted sensitive admin or management functions rather than a harmless page load.
- Identify the affected N-central DeviceName and determine whether the access occurred on a production management server or a test/lab instance.

**Evidence to collect:**
- All CommonSecurityLog events for the SourceIP and DeviceName covering at least 1 hour before and after AdminTime.
- The exact RequestURL values, ResponseCode values, and timestamps for the admin-path hits and any prior auth-path hits.
- Any correlated N-central application or web server logs showing authenticated sessions, admin actions, or configuration changes from the same source.
- Network context for the SourceIP, including whether it belongs to a known scanner, monitoring platform, or cloud provider.

**Pivot points:**
- CommonSecurityLog filtered by SourceIP, DeviceName, RequestURL, and TimeGenerated around the alert window.
- N-central application or reverse-proxy logs for the same host and time range to validate session creation and admin actions.
- Firewall, proxy, or WAF logs to determine whether the source IP is associated with known infrastructure or repeated probing.
- If available, endpoint or server audit logs on the N-central host for process creation, service changes, or file modifications after the access.

**Benign explanations:**
- A legitimate monitoring or health-check system accessed the admin endpoint without a visible login flow.
- An API integration authenticated through headers or tokens, so no login-path request appears in logs.
- A reverse proxy, load balancer, or external scanner generated the request from a public IP.
- The admin path list may not match the exact N-central deployment, causing a normal page to look suspicious.

**Escalation criteria:**
- No prior authentication is found for the same source IP and the admin access is successful on a production N-central host.
- The same source IP performs multiple admin-path requests or follows up with configuration, user, or service changes.
- There are signs of post-access activity such as new accounts, altered settings, unusual downloads, or process execution on the host.
- The source IP is unrecognized and the activity aligns with known exploitation patterns for CVE-2026-18577.

**Containment actions:**
- Block the source IP at the perimeter or WAF if the activity is confirmed malicious and the IP is not required for business operations.
- Restrict external access to N-central management interfaces until the exposure is reviewed.
- Preserve relevant logs and snapshots before making changes to the N-central server.
- If compromise is confirmed, rotate administrative credentials and review all privileged accounts and API tokens.

**Closure criteria:**
- The source IP is validated as a known benign system and the access is consistent with approved behavior.
- A legitimate authenticated flow is found outside the current lookback and explains the admin access.
- No follow-on suspicious activity is present on the N-central host or adjacent systems.
- The alert is explained by environment-specific URL structure or logging behavior and documented for tuning.

<br/>
---
<br/>

## Detection 2: N-central Post-Exploitation - Privileged Logon on Management Host Following Auth Bypass (CVE-2026-18577)

### Detection Opportunity

Following authentication bypass on N-central, attacker obtained administrative control of the server, observable as privileged logon events on N-central hosts from unexpected source IPs or outside business hours.

### Intelligence Context

- Rapid7: CVE-2026-18577: N-able N-central Authentication Bypass Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-cve-2026-18577-n-able-n-central-authentication-bypass-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-cve-2026-18577-n-able-n-central-authentication-bypass-exploited-in-the-wild)
  - Context: Rapid7 confirmed that successful exploitation of CVE-2026-18577 results in the attacker obtaining administrative control of N-central servers. Post-exploitation admin logon activity on the N-central host is a high-fidelity indicator of compromise following the authentication bypass.

### Search Metadata

- CVEs: CVE-2026-18577, CVE-2026-18556
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: N-able N-central
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-18577, CVE-2026-18556, T1190, N-able N-central

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Both
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Both: SecurityEvent, DeviceProcessEvents before scheduling.

**Required telemetry:**
- SecurityEvent, DeviceProcessEvents

### KQL

```kql
let nCentralHosts = dynamic([]);
let businessStart = 7;
let businessEnd = 19;
let postExploitWindow = 10m;
let suspiciousProcs = dynamic(["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "net.exe", "whoami.exe", "nltest.exe"]);
let privLogons = SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID in (4624, 4672)
| where LogonType in (10, 3)
| where Computer has_any (nCentralHosts)
| where (
    (isnotempty(IpAddress) and IpAddress != "-" and ipv4_is_private(IpAddress) == false)
    or (hourofday(TimeGenerated) < businessStart or hourofday(TimeGenerated) >= businessEnd)
  )
| project LogonTime = TimeGenerated, AccountName, SourceIP = IpAddress, Computer;
let adminProcs = DeviceProcessEvents
| where TimeGenerated > ago(1d)
| where DeviceName has_any (nCentralHosts)
| where FileName has_any (suspiciousProcs)
| project ProcTime = TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName;
privLogons
| join kind=inner (adminProcs) on $left.Computer == $right.DeviceName
| where ProcTime between (LogonTime .. (LogonTime + postExploitWindow))
| project LogonTime, ProcTime, AccountName, SourceIP, Computer, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by LogonTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate remote administration sessions by IT staff outside business hours on N-central hosts.
- Automated patching or backup agents that spawn cmd.exe or powershell.exe after a scheduled logon.
- Security scanning tools that log on remotely and execute enumeration commands as part of authorized assessments.

**Tuning notes:**
- Populate nCentralHosts with actual server hostnames or replace with a Sentinel watchlist lookup: _GetWatchlist('NCentralHosts') → project SearchKey.
- Adjust businessStart and businessEnd to match the organization's local operating hours, accounting for UTC offset.
- Consider adding InitiatingProcessFileName filters to require that suspicious processes are spawned by the N-central service process specifically, reducing false positives from unrelated admin activity.

**Risks / caveats:**
- The nCentralHosts list contains 'ncentral-server' as a placeholder. The query will match no real hosts until replaced with actual hostnames.
- DeviceProcessEvents requires Microsoft Defender for Endpoint onboarding of the N-central host. N-central servers running on Windows may not be MDE-onboarded in all environments.
- SecurityEvent ingestion requires the Windows Security Events data connector or AMA agent configured on N-central hosts. This is not guaranteed for server workloads.
- IpAddress in SecurityEvent (EventID 4624/4672) is only populated for network logon types (Type 3, 10); local interactive logons will have a null or '-' IpAddress, causing the ipv4_is_private filter to drop them.

### Triage Runbook

**First 15 minutes:**
- Validate the target host is an actual N-central server and not a placeholder, lab system, or unrelated Windows host.
- Review the logon type, source IP, account name, and time of day to determine whether the logon is expected for that account.
- Inspect the spawned process and command line to see whether the activity is consistent with interactive administration or suspicious post-exploitation tooling.
- Check whether the process was launched within 10 minutes of the privileged logon and whether the parent process is the N-central service or an unusual binary.

**Evidence to collect:**
- SecurityEvent records for EventID 4624 and 4672 on the host, including LogonType, IpAddress, AccountName, and TimeGenerated.
- DeviceProcessEvents for the same host and time window, including FileName, ProcessCommandLine, and InitiatingProcessFileName.
- Any N-central application, service, or audit logs showing administrative actions, account changes, or configuration edits.
- Host identity details such as hostname, IP, timezone, and whether the server is managed by IT or a third party.

**Pivot points:**
- SecurityEvent for the affected Computer to review all logons, privilege assignments, and source IPs around the alert.
- DeviceProcessEvents for the same DeviceName to identify additional child processes, scripts, or command shells.
- Windows event logs or EDR telemetry for service creation, scheduled task creation, registry changes, or file writes after the logon.
- N-central logs or admin audit trails to confirm whether the account and source IP match an approved administrator or automation account.

**Benign explanations:**
- An IT administrator performed legitimate remote maintenance outside business hours.
- A backup, patching, or monitoring agent logged on and launched administrative utilities.
- A security assessment or vulnerability scan triggered a remote logon and follow-on commands.
- The host name list or timezone is misconfigured, causing normal activity to appear suspicious.

**Escalation criteria:**
- The source IP is external or unknown and the account is privileged or unexpected for the host.
- The spawned process is a shell, scripting engine, recon tool, or other suspicious binary not used by normal operations.
- There are additional signs of compromise such as new services, scheduled tasks, credential access, or lateral movement.
- The logon and process activity occur on a production N-central server with no approved maintenance window.

**Containment actions:**
- Isolate the N-central host from the network if suspicious post-exploitation activity is confirmed.
- Disable or reset the affected account if it is not an approved administrative or service account.
- Preserve volatile evidence and collect EDR triage data before rebooting or remediating.
- Block the source IP and review other management hosts for the same account or source.

**Closure criteria:**
- The logon is confirmed as an approved administrative or automation session and the process activity matches expected behavior.
- No suspicious child processes, persistence, or follow-on actions are found on the host.
- The host list, timezone, or business-hours logic explains the alert and is documented for tuning.
- The account and source IP are validated against change records or maintenance tickets.

<br/>
---
<br/>

## Detection 3: Direct-to-IP C2 Communication - Outbound Connection Without DNS Resolution from Suspicious Process

### Detection Opportunity

Malware initiated outbound network connections directly to IP addresses without preceding DNS queries, bypassing DNS-based detection controls.

### Intelligence Context

- Unit 42: Almost Half of Malware Samples Communicate Direct to IP — [https://unit42.paloaltonetworks.com/malware-bypass-dns-direct-to-ip/](https://unit42.paloaltonetworks.com/malware-bypass-dns-direct-to-ip/)
  - Context: Unit 42 research found that nearly half of C2 malware bypasses DNS entirely by connecting directly to IP addresses. This pattern is detectable in endpoint network telemetry by identifying outbound connections where the remote URL field contains a raw IP address rather than a hostname, particularly from processes that do not typically make direct-IP connections.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1095
- Products: Not specified
- Platforms: network traffic, endpoint
- Malware: Not specified
- Tools: Not specified
- Search tags: network traffic, endpoint, T1095

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Command and Control: T1095 Non-Application Layer Protocol (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
let excludedProcs = dynamic(["MsMpEng.exe", "svchost.exe", "lsass.exe", "services.exe", "WaAppAgent.exe", "WindowsAzureGuestAgent.exe", "Teams.exe", "OneDrive.exe", "msedge.exe", "chrome.exe", "firefox.exe"]);
let suspectProcs = dynamic(["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "python.exe", "pythonw.exe", "node.exe", "wmic.exe"]);
DeviceNetworkEvents
| where TimeGenerated > ago(1d)
| where ActionType == "ConnectionSuccess"
| where ipv4_is_private(RemoteIP) == false
| where InitiatingProcessFileName has_any (suspectProcs)
| where not(InitiatingProcessFileName in~ (excludedProcs))
| where (
    isempty(RemoteUrl)
    or RemoteUrl matches regex @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?(/.*)?$"
  )
| summarize
    ConnectionCount = count(),
    Ports = make_set(RemotePort, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SampleCommandLine = any(InitiatingProcessCommandLine),
    SampleParentProcess = any(InitiatingProcessParentFileName)
    by DeviceName, InitiatingProcessFileName, RemoteIP
| where ConnectionCount >= 3
| extend BeaconDurationMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| project DeviceName, InitiatingProcessFileName, RemoteIP, ConnectionCount, Ports, FirstSeen, LastSeen, BeaconDurationMinutes, SampleCommandLine, SampleParentProcess
| order by ConnectionCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate software update clients (e.g., package managers, agent updaters) that connect directly to CDN or update server IPs without hostname resolution visible in RemoteUrl.
- Development tools such as python.exe or node.exe used by developers making direct API calls to IP-addressed test endpoints.
- Security agents and EDR tools that make direct-IP telemetry uploads.
- Remote desktop or VPN clients that establish direct-IP connections through scripting wrappers.

**Tuning notes:**
- Baseline the query over 7 days before scheduling to identify recurring legitimate direct-IP connections from suspectProcs and add them to excludedProcs or a per-device allowlist.
- Increase ConnectionCount threshold above 3 in environments with high legitimate scripting activity.
- Consider adding a RemotePort filter to focus on non-standard ports (exclude 80, 443) if direct-IP HTTPS connections are common and legitimate in the environment.
- Add InitiatingProcessParentFileName filters to prioritize cases where suspectProcs are spawned by Office applications, browsers, or other unusual parents.

**Risks / caveats:**
- RemoteUrl in DeviceNetworkEvents is frequently empty for non-HTTP connections and for many TCP connections regardless of whether DNS was used. Relying on an empty RemoteUrl as a DNS-bypass signal will produce high false-positive volume and may miss HTTP-based direct-IP C2 where RemoteUrl is populated with the IP.
- RemoteUrl being empty is the default state for many non-HTTP TCP connections in DeviceNetworkEvents regardless of DNS usage; this signal alone does not confirm DNS bypass and will generate noise from legitimate non-HTTP direct-IP connections.
- The ConnectionCount threshold of 3 is a starting point; environments with high scripting activity will require a higher threshold to reduce noise.
- The 1-day lookback may miss low-and-slow beaconing patterns; extend to 7 days for hunting sessions.

### Triage Runbook

**First 15 minutes:**
- Identify the initiating process, parent process, and command line to determine whether the binary is expected on the host.
- Check whether the remote IP is a known cloud service, vendor endpoint, update server, or internal business service.
- Review the connection pattern for repetition, timing, and port usage to see whether it resembles beaconing or normal application traffic.
- Confirm whether the host is a developer workstation, server, or user endpoint, since legitimate direct-IP traffic is more common on some systems.

**Evidence to collect:**
- DeviceNetworkEvents for the DeviceName, InitiatingProcessFileName, and RemoteIP over a longer window to establish frequency and duration.
- Process telemetry for the initiating binary, including hash, signer, parent process, and command line.
- DNS query logs from the host or network to verify whether the same destination was resolved by name at any point.
- Proxy, firewall, or secure web gateway logs to determine whether the destination IP is associated with known services or suspicious infrastructure.

**Pivot points:**
- DeviceNetworkEvents for the same host and process to identify all remote IPs, ports, and connection timing.
- DeviceProcessEvents to inspect the parent-child process chain and any script or Office-based launch context.
- DNS logs or resolver telemetry to check whether the destination IP maps to a hostname in the environment.
- Threat intelligence or asset inventory to determine whether the remote IP belongs to a sanctioned vendor, CDN, or internal service.

**Benign explanations:**
- Software update clients, EDR agents, or backup tools connect directly to IPs by design.
- Developer tools such as Python or Node are used for legitimate API testing against IP-addressed endpoints.
- Remote desktop, VPN, or telemetry software uses direct-IP connections without visible DNS resolution.
- The RemoteUrl field is empty for normal non-HTTP traffic, so the alert may reflect telemetry limitations rather than malicious behavior.

**Escalation criteria:**
- The process is unsigned, unknown, or launched from an unusual parent such as Office, script hosts, or browser helpers.
- The connection pattern is periodic, low-volume, and persistent in a way that resembles beaconing.
- The remote IP is unrecognized, external, and not tied to any approved service or vendor.
- Multiple hosts show the same suspicious process connecting directly to the same IP.

**Containment actions:**
- Isolate the host if the process is confirmed malicious or if additional compromise indicators are present.
- Block the remote IP at the firewall or proxy if it is not business-critical and appears malicious.
- Terminate the suspicious process only after preserving process and network evidence when possible.
- If malware is suspected, collect the binary and initiate endpoint containment and credential review.

**Closure criteria:**
- The process and destination are validated as legitimate and consistent with known software behavior.
- DNS or application logs explain the direct-IP traffic as expected for the application.
- No additional suspicious processes, persistence, or lateral movement are found on the host.
- The alert is attributed to a known benign tool and added to an allowlist or tuning list as appropriate.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- N-central Auth Bypass - Unauthenticated Admin Endpoint Access (CVE-2026-18577): CommonSecurityLog is only populated if N-central logs are forwarded to Sentinel via a CEF/Syslog connector with DeviceProduct set to 'N-central' or 'N-able'. This connector is not a default Sentinel data connector and must be configured explicitly.
- N-central Post-Exploitation - Privileged Logon on Management Host Following Auth Bypass (CVE-2026-18577): Environment-specific telemetry or field mapping must be resolved for Both: SecurityEvent, DeviceProcessEvents before scheduling.

**Schema / correlation keys:**
- Direct-to-IP C2 Communication - Outbound Connection Without DNS Resolution from Suspicious Process: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- No major shared table dependency identified across this run.

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: N-central Auth Bypass - Unauthenticated Admin Endpoint Access (CVE-2026-18577); N-central Post-Exploitation - Privileged Logon on Management Host Following Auth Bypass (CVE-2026-18577).
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Direct-to-IP C2 Communication - Outbound Connection Without DNS Resolution from Suspicious Process.

### Hunting Agenda and Promotion Criteria

- Direct-to-IP C2 Communication - Outbound Connection Without DNS Resolution from Suspicious Process: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- N-central Auth Bypass - Unauthenticated Admin Endpoint Access (CVE-2026-18577): CommonSecurityLog is only populated if N-central logs are forwarded to Sentinel via a CEF/Syslog connector with DeviceProduct set to 'N-central' or 'N-able'. This connector is not a default Sentinel data connector and must be configured explicitly.; baseline expected benign activity and define an alert-volume threshold.
- N-central Post-Exploitation - Privileged Logon on Management Host Following Auth Bypass (CVE-2026-18577): Environment-specific telemetry or field mapping must be resolved for Both: SecurityEvent, DeviceProcessEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
