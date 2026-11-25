---
layout: post
title: "Detection Engineering Brief - Wednesday, November 25, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-11-25
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-123890
  - T1190
  - VMware vCenter
  - vCenter Server Appliance
  - DCE/RPC
  - CVE-2026-123633
  - NGINX
  - HTTP/2
---

## Detection Engineering Summary

This brief produced 3 detection candidates.

1 production candidate, 0 hunting-only, 2 require environment mapping, and 0 rejected.

3 detections include KQL. 3 include ATT&CK mappings. 3 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-123890, T1190, VMware vCenter, vCenter Server Appliance, DCE/RPC, CVE-2026-123633, NGINX, HTTP/2.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: CVE-2026-123890 - Inbound Connection to vCenter DCE/RPC Port 2012 from Non-Management Host; CVE-2026-123890 - vCenter DCE/RPC Session Key Theft Followed by Successful Admin Logon (Compound).

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: CVE-2026-123890 - Inbound Connection to vCenter DCE/RPC Port 2012 from Non-Management Host

### Detection Opportunity

Attacker abuses exposed DCE/RPC service on TCP port 2012 to initiate authentication bypass against VMware vCenter.

### Intelligence Context

- Rapid7: Rapid7 Analysis: VMware vCenter SRP Authentication Bypass to Root (CVE-2026-123890) — [https://www.rapid7.com/blog/post/ra-rapid7-analysis-vmware-vcenter-srp-authentication-bypass-to-root-cve-2026-123890](https://www.rapid7.com/blog/post/ra-rapid7-analysis-vmware-vcenter-srp-authentication-bypass-to-root-cve-2026-123890)
  - Context: Rapid7 confirmed that CVE-2026-123890 is exploited via the DCE/RPC interface exposed on TCP port 2012 of the vCenter Server Appliance. An unauthenticated attacker connects to this port to intercept an in-progress administrator session key and complete login without a password.

### Search Metadata

- CVEs: CVE-2026-123890
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: VMware vCenter, vCenter Server Appliance
- Platforms: DCE/RPC
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-123890, T1190, VMware vCenter, vCenter Server Appliance, DCE/RPC

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceNetworkEvents before scheduling.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
// Scope this query to confirmed vCenter Server Appliance hosts.
// Recommended: join against a Sentinel watchlist named 'vCenterHosts' containing DeviceName values,
// or apply a DeviceTag filter in the MDE portal and use: | where DeviceName in~ (toscalar(...))
// Until scoping is applied this query will match any device accepting TCP 2012.
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where LocalPort == 2012
| where Protocol == "TCP"
| where ActionType == "InboundConnectionAccepted"
| summarize
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    InitiatingProcesses = make_set(InitiatingProcessName, 5)
    by RemoteIP, RemoteIPType, LocalIP, DeviceName, bin(Timestamp, 10m)
| where ConnectionCount >= 3
| extend BucketStart = Timestamp
| project
    BucketStart,
    FirstSeen,
    LastSeen,
    DeviceName,
    LocalIP,
    RemoteIP,
    RemoteIPType,
    ConnectionCount,
    InitiatingProcesses
| order by ConnectionCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate vCenter management tools and backup agents that connect to TCP 2012 from authorized management hosts.
- Internal vulnerability scanners that probe TCP 2012 as part of scheduled assessments.
- vCenter-to-vCenter replication or linked-mode traffic on TCP 2012.

**Tuning notes:**
- Add a DeviceName filter or watchlist join to restrict results to vCenter Server Appliance hosts before scheduling.
- Add '| where RemoteIP !in ("<mgmt_ip_1>", "<mgmt_ip_2>")' after populating management IP allowlist from the environment.
- Adjust the bin() window and ConnectionCount threshold after baselining normal TCP 2012 traffic volume on vCenter hosts.
- Consider adding a RemoteIPType == 'Public' filter to prioritize external attacker traffic over internal lateral movement.

**Risks / caveats:**
- ActionType value 'InboundConnectionAccepted' is only populated when the Defender for Endpoint sensor is deployed on the vCenter host or a network sensor covers that traffic. vCenter Server Appliance runs on Linux; MDE Linux agent must be onboarded for this telemetry to exist.
- DeviceNetworkEvents does not natively tag devices by role. Scoping to vCenter hosts requires either a DeviceName filter, a DeviceTag applied in the MDE portal, or a Sentinel watchlist — none of which exist in the query as written.
- Without vCenter host scoping the query will produce false positives on any device that accepts TCP 2012 connections.
- ConnectionCount threshold of 3 per 10-minute bucket is a starting point; baseline the environment to determine the appropriate value.

### Triage Runbook

**First 15 minutes:**
- Confirm the target is a real vCenter Server Appliance host and not a non-vCenter system accepting TCP 2012.
- Check whether the source IP is in the approved management, backup, replication, or vulnerability-scanning allowlist.
- Review the connection burst pattern: multiple connections in a short window are more concerning than a single probe.
- Look for any concurrent vCenter authentication, admin session creation, or unusual logon activity from the same source IP.
- If the source is external or unknown, treat as likely exploitation attempt and move to incident handling.

**Evidence to collect:**
- DeviceName, LocalIP, RemoteIP, RemoteIPType, ConnectionCount, FirstSeen, LastSeen, and InitiatingProcessName from the alert.
- vCenter appliance logs around the same time window for authentication, session, or admin activity.
- Firewall or network telemetry showing whether the source IP reached TCP 2012 repeatedly or only once.
- Asset context proving whether the destination host is a production vCenter appliance and who owns it.
- Any recent change records, patch status, or maintenance windows for the vCenter host.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceName and RemoteIP over the prior 24 hours.
- Syslog from the vCenter appliance for login, session, or service errors around the alert time.
- CommonSecurityLog or firewall logs to confirm whether the source IP is external, internal, or a known scanner.
- Asset inventory or watchlist data to validate vCenter host scoping and management IP allowlists.
- Recent admin activity logs for the vCenter environment if available.

**Benign explanations:**
- Authorized vCenter administration from a known management workstation.
- Scheduled vulnerability scanning or validation testing against TCP 2012.
- Replication, linked-mode, or backup tooling that legitimately contacts the service.
- A misconfigured internal monitoring tool repeatedly probing the port.

**Escalation criteria:**
- The source IP is not in an approved management or scanner allowlist.
- The connection pattern shows repeated attempts or a burst consistent with exploitation.
- There is any matching evidence of successful vCenter authentication or session creation from the same source.
- The destination host is a production vCenter appliance exposed to untrusted networks.

**Containment actions:**
- Block the source IP at the firewall or edge if it is confirmed malicious and not business-critical.
- Restrict TCP 2012 exposure to approved management networks only if the service is reachable from broader networks.
- If compromise is suspected, isolate the vCenter appliance from nonessential network access while preserving management connectivity for responders.
- Preserve logs and snapshots before making disruptive changes.

**Closure criteria:**
- The source IP is verified as an approved management or scanning system and the activity matches expected behavior.
- No follow-on authentication, session creation, or other suspicious vCenter activity is found.
- The destination host is confirmed not to be a vCenter appliance or the alert is attributable to known benign traffic.
- Any necessary allowlist or scoping changes have been documented and implemented.

<br/>
---
<br/>

## Detection 2: CVE-2026-123890 - vCenter DCE/RPC Session Key Theft Followed by Successful Admin Logon (Compound)

### Detection Opportunity

Unauthenticated attacker retrieves vCenter administrator session key via TCP 2012 and subsequently completes an administrator login without a password challenge.

### Intelligence Context

- Rapid7: Rapid7 Analysis: VMware vCenter SRP Authentication Bypass to Root (CVE-2026-123890) — [https://www.rapid7.com/blog/post/ra-rapid7-analysis-vmware-vcenter-srp-authentication-bypass-to-root-cve-2026-123890](https://www.rapid7.com/blog/post/ra-rapid7-analysis-vmware-vcenter-srp-authentication-bypass-to-root-cve-2026-123890)
  - Context: Rapid7 described a two-stage attack: an unauthenticated attacker first connects to TCP 2012 to steal an in-progress administrator session key, then uses that key to complete the administrator login without knowing the password. Correlating a TCP 2012 inbound connection with a subsequent successful admin logon from the same source IP is a high-fidelity compound signal.

### Search Metadata

- CVEs: CVE-2026-123890
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: VMware vCenter, vCenter Server Appliance
- Platforms: DCE/RPC
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-123890, T1190, VMware vCenter, vCenter Server Appliance, DCE/RPC

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.

**Required telemetry:**
- CommonSecurityLog, Syslog

### KQL

```kql
let tcp2012_hits = CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DestinationPort == 2012 and Protocol == "TCP"
| where DeviceAction !in~ ("deny", "drop", "block", "reset", "reject")
| where isnotempty(SourceIP)
| project ConnectionTime = TimeGenerated, SourceIP, DestinationHostName;
let vcenter_logons = Syslog
| where TimeGenerated > ago(1d)
| where ProcessName has_any ("vpxd", "vmafd", "vmware-sts")
| where SyslogMessage has_any ("Login successful", "authenticated", "session created")
| where tolower(SyslogMessage) has "administrator"
| extend ExtractedIP = extract(@"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", 1, SyslogMessage)
| where isnotempty(ExtractedIP)
| project
    LogonTime = TimeGenerated,
    LogonHost = HostName,
    LogonMessage = SyslogMessage,
    SourceIP = ExtractedIP;
tcp2012_hits
| join kind=inner vcenter_logons on SourceIP
| where LogonTime between (ConnectionTime .. (ConnectionTime + 10m))
| summarize
    LogonMessages = make_set(LogonMessage, 5),
    EarliestLogon = min(LogonTime),
    LatestLogon = max(LogonTime)
    by ConnectionTime, SourceIP, DestinationHostName, LogonHost
| extend LogonTimeDeltaSeconds = datetime_diff('second', EarliestLogon, ConnectionTime)
| project
    ConnectionTime,
    EarliestLogon,
    LogonTimeDeltaSeconds,
    SourceIP,
    DestinationHostName,
    LogonHost,
    LogonMessages
| order by ConnectionTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate vCenter administrators connecting from management workstations that also appear in firewall logs for TCP 2012 traffic.
- Automated vCenter management scripts or orchestration tools that authenticate as administrator and generate TCP 2012 traffic as part of normal operation.
- Vulnerability scanners that probe TCP 2012 and are followed by a coincidental administrator logon from the same subnet.

**Tuning notes:**
- Validate that CommonSecurityLog DestinationHostName is populated for the firewall covering vCenter; if not, switch to DestinationIP and correlate on IP.
- Adjust the join time window from 10 minutes based on observed authentication flow timing in the environment.
- Refine the SyslogMessage keyword list to match the exact authentication success strings emitted by the deployed vCenter version.
- Add a SourceIP !in() exclusion for known management IPs after populating the allowlist from the environment.

**Risks / caveats:**
- CommonSecurityLog DestinationHostName field is not reliably populated by all firewall vendors; some vendors populate DestinationIP instead. If DestinationHostName is empty the join context is lost.
- Syslog ProcessName field population depends on the syslog facility and forwarding configuration on the vCenter appliance. If vCenter logs under a different facility or process name the query returns no results.
- The regex extract of SourceIP from SyslogMessage assumes the IP appears as a bare IPv4 address in the message body. vCenter log formats vary by version and may embed IPs in structured fields or with different surrounding text.
- CommonSecurityLog DeviceAction field values ('deny', 'drop', 'block') are vendor-specific strings. The exclusion filter may not match the actual strings emitted by the firewall in the environment.

### Triage Runbook

**First 15 minutes:**
- Treat this as likely compromise until disproven because it correlates exploitation traffic with successful admin authentication.
- Confirm the source IP, destination host, and exact time delta between the TCP 2012 connection and the admin logon.
- Check whether the admin logon was expected from that source, user, and time of day.
- Review vCenter logs for the account used, session creation details, and any privilege changes immediately after login.
- Identify whether the source IP is external, a jump host, or a known management workstation.

**Evidence to collect:**
- ConnectionTime, EarliestLogon, LogonTimeDeltaSeconds, SourceIP, DestinationHostName, LogonHost, and LogonMessages from the alert.
- Firewall or network logs showing the TCP 2012 connection and whether it was allowed or blocked.
- vCenter Syslog entries for the successful login, account name, session identifiers, and any subsequent administrative actions.
- Authentication logs from identity providers or SSO systems tied to the vCenter admin account.
- Change history for the vCenter appliance, including recent patches, configuration changes, and admin access approvals.

**Pivot points:**
- CommonSecurityLog for all traffic from the SourceIP to the vCenter host before and after the alert.
- Syslog on the vCenter appliance for the same SourceIP, account name, and any session creation or privilege events.
- Identity and access logs for the administrator account used in the successful logon.
- vCenter audit or task logs for actions performed after the login, such as role changes, VM access, or configuration edits.
- Endpoint or jump-host telemetry for the source system if it is an internal workstation.

**Benign explanations:**
- A legitimate administrator using a management workstation that also generated the TCP 2012 connection.
- An automated orchestration or backup tool that authenticates as an admin account as part of normal operations.
- A vulnerability scanner or test harness that coincidentally preceded a real admin login from the same IP.
- Log parsing or time synchronization issues causing the connection and login to appear more closely related than they are.

**Escalation criteria:**
- The source IP is not a known management system and the admin login was not expected.
- The admin account is privileged and the login was followed by any configuration, privilege, or access changes.
- The login occurred from an external or unusual network location.
- There is evidence of additional suspicious activity on the vCenter host or related identity systems.

**Containment actions:**
- Disable or reset the affected administrator account if unauthorized use is confirmed or strongly suspected.
- Block the source IP and any related source infrastructure at the firewall or proxy.
- Isolate the vCenter appliance from untrusted networks while preserving responder access if compromise is likely.
- Preserve relevant logs, session data, and system state before remediation.

**Closure criteria:**
- The source IP and admin login are confirmed to be authorized and consistent with documented operations.
- No unauthorized actions occurred after the login and the account owner validates the activity.
- The alert is attributable to a known test, maintenance, or scanner workflow with supporting evidence.
- Any suspicious account activity has been remediated and documented.

<br/>
---
<br/>

## Detection 3: CVE-2026-123633 - Repeated NGINX Worker Process Crashes Indicating HTTP/2 Use-After-Free Exploitation

### Detection Opportunity

NGINX worker processes crash repeatedly or emit segfault entries in Syslog following HTTP/2 exploitation attempts, indicating memory corruption consistent with CVE-2026-123633.

### Intelligence Context

- Unit 42: NGINX HTTP/2 Use-After-Free: CVE-2026-123633 — [https://unit42.paloaltonetworks.com/cve-2026-123633-nginx-http2-vulnerability/](https://unit42.paloaltonetworks.com/cve-2026-123633-nginx-http2-vulnerability/)
  - Context: Unit 42 reported that exploitation of CVE-2026-123633 may trigger crash or sanitizer-like anomalies in the NGINX process. Repeated NGINX worker crashes or segfault messages in system logs are identified as a detectable post-exploitation signal.

### Search Metadata

- CVEs: CVE-2026-123633
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: NGINX
- Platforms: HTTP/2
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-123633, T1190, NGINX, HTTP/2

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- Syslog

### KQL

```kql
Syslog
| where TimeGenerated > ago(1d)
| where (
    ProcessName has_any ("nginx", "nginx:")
    or (ProcessName == "kernel" and SyslogMessage has "nginx")
)
| where SyslogMessage has_any (
    "segfault",
    "signal 11",
    "worker process exited on signal",
    "core dumped",
    "exited on signal 11"
)
| extend BucketStart = bin(TimeGenerated, 30m)
| summarize
    CrashCount = count(),
    FirstCrash = min(TimeGenerated),
    LastCrash = max(TimeGenerated),
    SampleMessages = make_set(SyslogMessage, 3)
    by HostName, BucketStart
| where CrashCount >= 3
| extend TimespanMinutes = datetime_diff('minute', LastCrash, FirstCrash)
| project
    BucketStart,
    FirstCrash,
    LastCrash,
    HostName,
    CrashCount,
    TimespanMinutes,
    SampleMessages
| order by CrashCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- NGINX hosts with pre-existing instability or known bugs unrelated to CVE-2026-123633 that crash at a rate exceeding the threshold.
- Hosts undergoing NGINX upgrades or configuration reloads that trigger worker process restarts logged as signal exits.
- Load testing or chaos engineering activities that intentionally stress NGINX workers.

**Tuning notes:**
- Increase CrashCount threshold above 3 if the environment has NGINX instances with known instability unrelated to exploitation.
- Add a HostName filter to restrict results to known internet-facing NGINX hosts to reduce noise from internal or development instances.
- Adjust the bin() window from 30 minutes to a shorter window (e.g., 10 minutes) if faster burst detection is preferred for active exploitation scenarios.
- Add a SyslogMessage !has 'graceful' or !has 'reload' exclusion if graceful reload log lines match the keyword list in the environment.

**Risks / caveats:**
- Kernel segfault messages on Linux are typically emitted by the kernel under ProcessName 'kernel' rather than 'nginx'. The query may miss kernel-logged segfaults for NGINX worker PIDs if ProcessName filtering excludes kernel-sourced entries. A secondary filter on SyslogMessage containing 'nginx' with ProcessName == 'kernel' may be needed to capture those events.
- The crash-count threshold of 3 per 30-minute bucket may be too low for NGINX hosts with pre-existing instability; baseline crash rates per host before scheduling.
- Kernel segfault messages may appear under facility 'kern' with ProcessName 'kernel'; validate that the Syslog connector forwards kernel facility messages to Sentinel.
- NGINX worker restart messages from graceful reloads (SIGUSR1, SIGQUIT) may share similar log patterns; validate that the keyword list does not match graceful reload events in the environment.

### Triage Runbook

**First 15 minutes:**
- Confirm the affected host is internet-facing or otherwise reachable by untrusted clients.
- Review the crash messages to verify they reference NGINX worker failures, segfaults, or signal 11 events rather than routine reloads.
- Check whether the crash burst aligns with a spike in inbound HTTP/2 traffic or unusual request patterns.
- Determine whether the host recently changed versions, modules, or configuration, which could explain instability.
- If the host is production-facing and crashes are ongoing, escalate immediately for possible active exploitation.

**Evidence to collect:**
- FirstCrash, LastCrash, CrashCount, TimespanMinutes, SampleMessages, and HostName from the alert.
- Syslog entries around the crash window, including kernel messages and any NGINX error output.
- Web server access logs showing HTTP/2 request volume, source IPs, and unusual request patterns before the crashes.
- Version and configuration details for the NGINX instance, including recent upgrades or module changes.
- Host health data showing whether the process restarted, core dumps were generated, or service availability was impacted.

**Pivot points:**
- Syslog for the same HostName over a wider time range to identify earlier or later crash events.
- Web access logs or reverse proxy logs for HTTP/2 traffic spikes and suspicious client behavior.
- Change management records for NGINX upgrades, reloads, or configuration deployments.
- Host monitoring or EDR telemetry for process restarts, core dumps, or service degradation.
- Firewall or load balancer logs to identify the source IPs generating the traffic.

**Benign explanations:**
- A known NGINX bug or unstable module unrelated to exploitation.
- A recent upgrade, reload, or configuration change causing worker restarts.
- Load testing, chaos testing, or synthetic traffic generation against the host.
- Kernel or application logging noise that resembles crash output but is not exploit-driven.

**Escalation criteria:**
- The host is internet-facing and crash events are repeated within a short time window.
- Crash messages coincide with unusual HTTP/2 traffic or suspicious client behavior.
- There is evidence of service disruption, core dumps, or repeated worker restarts.
- No benign operational change explains the crashes.

**Containment actions:**
- Temporarily remove the host from public traffic or place it behind a maintenance page if service impact is acceptable.
- Block or rate-limit suspicious source IPs if a clear attack source is identified.
- If exploitation is strongly suspected, isolate the host for forensic preservation and recovery planning.
- Preserve logs and core dumps before restarting or patching the service.

**Closure criteria:**
- The crashes are attributed to a documented benign cause such as maintenance, testing, or a known non-security bug.
- The host is patched or otherwise remediated and crash activity stops.
- No suspicious inbound HTTP/2 traffic or exploit indicators are found.
- Service owners confirm the behavior matches expected operational activity.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- CVE-2026-123890 - Inbound Connection to vCenter DCE/RPC Port 2012 from Non-Management Host: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceNetworkEvents before scheduling.
- CVE-2026-123890 - vCenter DCE/RPC Session Key Theft Followed by Successful Admin Logon (Compound): Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.

**Shared-table notes:**
- Syslog: shared by CVE-2026-123890 - vCenter DCE/RPC Session Key Theft Followed by Successful Admin Logon (Compound); CVE-2026-123633 - Repeated NGINX Worker Process Crashes Indicating HTTP/2 Use-After-Free Exploitation

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: CVE-2026-123633 - Repeated NGINX Worker Process Crashes Indicating HTTP/2 Use-After-Free Exploitation.
2. Resolve environment-mapping detections next: CVE-2026-123890 - Inbound Connection to vCenter DCE/RPC Port 2012 from Non-Management Host; CVE-2026-123890 - vCenter DCE/RPC Session Key Theft Followed by Successful Admin Logon (Compound).

### Hunting Agenda and Promotion Criteria

- CVE-2026-123890 - Inbound Connection to vCenter DCE/RPC Port 2012 from Non-Management Host: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceNetworkEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- CVE-2026-123890 - vCenter DCE/RPC Session Key Theft Followed by Successful Admin Logon (Compound): Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
