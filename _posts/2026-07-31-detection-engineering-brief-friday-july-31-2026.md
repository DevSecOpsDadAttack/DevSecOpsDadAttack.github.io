---
layout: post
title: "Detection Engineering Brief - Friday, July 31, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-31
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - OctLurk
  - SilkLurk
  - T1059
  - Windows
  - Linux
  - T1046
  - T1003
  - CVE-2026-59309
  - CVE-2026-59310
  - T1190
  - VMware vCenter Server
  - VMware Directory Service
  - vCenter Syslog
  - Metasploit Framework
  - Meterpreter
  - Java
  - Python
  - PHP
  - HTTP
  - T1003.001
  - T1071.001
  - T1071
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

0 production candidates, 3 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: OctLurk, SilkLurk, T1059, Windows, Linux, T1046, T1003, CVE-2026-59309, CVE-2026-59310, T1190, VMware vCenter Server, VMware Directory Service, vCenter Syslog, Metasploit Framework, Meterpreter, Java, Python, PHP, HTTP, T1003.001, ....

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: OctLurk_SilkLurk_Shell_Spawned_From_Unusual_Parent; OctLurk_SilkLurk_Network_Scan_With_Concurrent_LSASS_Access; VMware_vCenter_Auth_Bypass_Successful_Logon_No_Prior_Failure; VMware_vCenter_Syslog_Directory_Traversal_Request; Meterpreter_Interpreter_Process_Outbound_C2_After_Webserver_Spawn.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: OctLurk_SilkLurk_Shell_Spawned_From_Unusual_Parent

### Detection Opportunity

Shell process spawned by unusual parent process consistent with injected plugin launching shells in memory

### Intelligence Context

- Securelist: OctLurk and SilkLurk: newly identified tailored backdoors in cyber-espionage campaign in Central Asia — [https://securelist.com/octlurk-silklurk-backdoors-central-asia/120840/](https://securelist.com/octlurk-silklurk-backdoors-central-asia/120840/)
  - Context: OctLurk and SilkLurk inject plugins to launch shells from memory-resident processes. Shell child processes spawned by non-standard parents with no disk image are a key indicator of this technique.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1046, T1003.001, T1003
- Products: Not specified
- Platforms: Windows
- Malware: OctLurk, SilkLurk
- Tools: Not specified
- Search tags: OctLurk, SilkLurk, T1059, Windows, Linux, T1046, T1003.001, T1003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Discovery: T1046 Network Service Scanning (high); Credential Access: T1003 OS Credential Dumping/ T1003.001 LSASS Memory (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where ActionType == "ProcessCreated"
| where FileName in~ ("cmd.exe", "powershell.exe")
| where InitiatingProcessFileName !in~ (
    "explorer.exe", "svchost.exe", "services.exe", "taskmgr.exe",
    "msiexec.exe", "wscript.exe", "cscript.exe", "rundll32.exe",
    "cmd.exe", "powershell.exe", "conhost.exe", "userinit.exe",
    "winlogon.exe", "lsass.exe"
  )
| where (
    isempty(InitiatingProcessFolderPath)
    or (
        InitiatingProcessFolderPath !startswith @"C:\Windows\"
        and InitiatingProcessFolderPath !startswith @"C:\Program Files"
        and InitiatingProcessFolderPath !startswith @"C:\Program Files (x86)"
        and InitiatingProcessFolderPath !startswith @"C:\ProgramData"
    )
  )
| project
    Timestamp,
    DeviceName,
    AccountName,
    AccountDomain,
    FileName,
    ProcessId,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessId,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Software installed in user-profile directories or custom application directories will trigger this rule.
- Scripting engines invoked by deployment tools, RMM agents, or developer toolchains installed outside standard paths.
- Legitimate automation frameworks that spawn cmd.exe or powershell.exe from non-standard parent paths.

**Tuning notes:**
- Baseline the InitiatingProcessFileName values in the environment before scheduling to build an accurate exclusion list.
- Consider adding InitiatingProcessFolderPath startswith checks for any additional trusted software roots specific to the environment.
- Cross-reference flagged events with DeviceEvents for OpenProcessApiCall or WriteProcessMemory ActionTypes on the same device within a short window to increase confidence.

**Risks / caveats:**
- InitiatingProcessFolderPath being empty does not exclusively indicate memory-only execution; it can also reflect telemetry gaps or processes where path resolution failed.
- The exclusion list for initiating process names requires baselining against the specific environment to avoid both over-exclusion and under-exclusion.
- Software installed in user home directories or non-standard application roots will produce false positives until an allowlist is established.
- 7-day lookback may miss low-frequency activity; consider extending for initial hunting runs.

### Triage Runbook

**First 15 minutes:**
- Confirm the parent process name, command line, and folder path; treat empty or non-standard InitiatingProcessFolderPath as suspicious but not definitive.
- Check whether the shell command line is interactive, encoded, or launches additional scripts, downloads, or remote admin tools.
- Review the same host for nearby LSASS access, process injection, network scanning, or other unusual child processes within the last 30 minutes.
- Identify the user account and whether the activity occurred on a server, admin workstation, or user endpoint; validate whether the account normally runs automation from that host.

**Evidence to collect:**
- DeviceProcessEvents for the shell process and its parent, including ProcessId, InitiatingProcessId, command lines, and timestamps.
- Any DeviceEvents showing OpenProcessApiCall, WriteProcessMemory, or other suspicious process access on the same device around the alert time.
- Recent DeviceNetworkEvents from the same host to identify outbound connections, unusual destinations, or port scanning behavior.
- A short process tree for the host to determine whether the shell was spawned by a legitimate application, script host, or an unknown parent.

**Pivot points:**
- DeviceProcessEvents filtered on the same DeviceName, ProcessId, and InitiatingProcessId around the alert timestamp.
- DeviceEvents on the same DeviceName for lsass.exe access or memory-related actions within +/- 30 minutes.
- DeviceNetworkEvents on the same DeviceName for unusual outbound connections from the shell or its parent process.
- If available, correlate with DeviceFileEvents for dropped scripts, binaries, or temporary files created near the alert time.

**Benign explanations:**
- Legitimate software installed in user-profile or custom application directories can spawn shells and trigger the rule.
- RMM, deployment, or developer tooling may launch cmd.exe or powershell.exe from non-standard paths.
- Telemetry gaps can make InitiatingProcessFolderPath appear empty even when the parent is not memory-resident.

**Escalation criteria:**
- Escalate immediately if the shell command line is encoded, downloads payloads, or launches additional suspicious processes.
- Escalate if the same host shows LSASS access, process injection, or network scanning near the alert time.
- Escalate if the parent process is unknown, unsigned, or running from a user-writable or temporary directory.
- Escalate if the account is privileged or the host is a server, jump box, or security tooling endpoint.

**Containment actions:**
- If corroborating evidence suggests compromise, isolate the host from the network.
- Suspend or disable the involved account if it is privileged and not expected to be performing automation.
- Preserve volatile evidence before rebooting or killing processes, especially if memory-resident execution is suspected.

**Closure criteria:**
- The parent process is identified as approved software or automation from a known non-standard path and no other suspicious activity is found.
- No supporting evidence exists in process, network, or credential-access telemetry after reviewing the surrounding time window.
- The activity is explained by a documented admin task, software deployment, or developer workflow and matches the account and host baseline.

<br/>
---
<br/>

## Detection 2: OctLurk_SilkLurk_Network_Scan_With_Concurrent_LSASS_Access

### Detection Opportunity

High-volume outbound connections across multiple ports correlated with LSASS open-process events on the same device, consistent with combined network scanning and credential dumping

### Intelligence Context

- Securelist: OctLurk and SilkLurk: newly identified tailored backdoors in cyber-espionage campaign in Central Asia — [https://securelist.com/octlurk-silklurk-backdoors-central-asia/120840/](https://securelist.com/octlurk-silklurk-backdoors-central-asia/120840/)
  - Context: OctLurk and SilkLurk scan networks and dump credentials as part of their post-exploitation capability. The combination of high-volume multi-port scanning and concurrent LSASS access from the same device is a strong compound indicator.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1046, T1003, T1003.001
- Products: Not specified
- Platforms: Windows
- Malware: OctLurk, SilkLurk
- Tools: Not specified
- Search tags: OctLurk, SilkLurk, T1046, T1003, Windows, T1003.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Discovery: T1046 Network Service Scanning (high); Credential Access: T1003 OS Credential Dumping/ T1003.001 LSASS Memory (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- DeviceEvents ActionType 'OpenProcessApiCall' requires Defender for Endpoint advanced telemetry (process access auditing) to be enabled. If this telemetry is not collected, the LSASS access leg of the join will return no results and the detection will produce no output.

**Required telemetry:**
- DeviceNetworkEvents, DeviceEvents

### KQL

```kql
let ScanWindow = 10m;
let ScanThreshold = 20;
let CorrelationWindowMinutes = 10;
let Scanners = DeviceNetworkEvents
| where Timestamp >= ago(7d)
| where ActionType in ("ConnectionAttempted", "ConnectionSuccess")
| summarize
    DistinctPorts = dcount(RemotePort),
    FirstSeen = min(Timestamp),
    SampleRemoteIP = any(RemoteIP)
    by DeviceName, bin(Timestamp, ScanWindow), ScanningProcess = InitiatingProcessFileName
| where DistinctPorts >= ScanThreshold;
let LsassAccess = DeviceEvents
| where Timestamp >= ago(7d)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| project
    DeviceName,
    LsassTime = Timestamp,
    LsassAccessProcess = InitiatingProcessFileName,
    LsassAccessProcessId = InitiatingProcessId,
    LsassAccessCommandLine = InitiatingProcessCommandLine;
Scanners
| join kind=inner LsassAccess on DeviceName
| extend TimeDeltaMinutes = abs(datetime_diff('minute', FirstSeen, LsassTime))
| where TimeDeltaMinutes <= CorrelationWindowMinutes
| project
    DeviceName,
    ScanTime = FirstSeen,
    LsassTime,
    TimeDeltaMinutes,
    ScanningProcess,
    DistinctPorts,
    SampleRemoteIP,
    LsassAccessProcess,
    LsassAccessProcessId,
    LsassAccessCommandLine
| order by ScanTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Network management or vulnerability scanning hosts that legitimately connect to many ports.
- Security tools and EDR agents that access LSASS for legitimate monitoring purposes.
- Backup agents that open LSASS handles during VSS or credential-aware backup operations.

**Tuning notes:**
- Raise ScanThreshold if the environment has legitimate services that connect to many ports in short windows.
- Narrow CorrelationWindowMinutes from 10 to 5 to increase specificity once baseline is established.
- Add an exclusion for known network management or vulnerability scanner device names to reduce noise.
- Cross-reference LsassAccessProcess against an approved list of security tools and backup agents in the environment.

**Risks / caveats:**
- DeviceEvents ActionType 'OpenProcessApiCall' requires Defender for Endpoint advanced telemetry (process access auditing) to be enabled. If this telemetry is not collected, the LSASS access leg of the join will return no results and the detection will produce no output.
- ScanThreshold of 20 distinct ports in 10 minutes requires baselining against the environment; legitimate services on multi-homed hosts may exceed this threshold.
- The 10-minute correlation window between scanning and LSASS access is heuristic; a shorter window increases specificity but may miss temporally separated activity.
- The bin(Timestamp, ScanWindow) grouping means scans that straddle a bin boundary may be undercounted; this is a known limitation of bin-based summarization.

### Triage Runbook

**First 15 minutes:**
- Confirm the scan is not from a known vulnerability scanner, network management host, or security tool before treating it as malicious.
- Review the LSASS access process name, command line, and parent process; determine whether it is an approved security or backup component.
- Check whether the scan and LSASS access occurred within the same short window on the same device and whether the scanning process is unusual for that host.
- Look for additional signs of compromise on the host, including suspicious child processes, service creation, or outbound connections to unfamiliar IPs.

**Evidence to collect:**
- DeviceNetworkEvents showing the distinct ports, remote IPs, and initiating process for the scan activity.
- DeviceEvents showing OpenProcessApiCall against lsass.exe, including the accessing process name, process ID, and command line.
- DeviceProcessEvents for the scanning process and the LSASS-accessing process to reconstruct the process tree and execution timeline.
- Any nearby authentication, privilege escalation, or lateral movement events from the same host and account.

**Pivot points:**
- DeviceNetworkEvents on the same DeviceName to enumerate all remote ports and destinations contacted in the scan window.
- DeviceEvents on the same DeviceName for lsass.exe access, process injection, or suspicious handle activity.
- DeviceProcessEvents for the scanning process and any child processes spawned before or after the alert.
- If available, correlate with sign-in or identity logs for the same account to see whether the host was used interactively or by automation.

**Benign explanations:**
- A legitimate vulnerability scanner or network management system may connect to many ports and also run security tooling that touches LSASS.
- EDR, backup, or credential-aware security tools can legitimately access LSASS for monitoring or protection.
- High-activity servers may generate broad connection patterns that resemble scanning during maintenance or health checks.

**Escalation criteria:**
- Escalate if the LSASS-accessing process is not an approved security, backup, or administrative tool.
- Escalate if the scanning host is not a known scanner or management system and the activity is outbound to many unrelated ports.
- Escalate if the host also shows suspicious logon activity, privilege escalation, or lateral movement attempts.
- Escalate if the process command line indicates credential dumping, injection, or post-exploitation tooling.

**Containment actions:**
- Isolate the host if the LSASS access is unauthorized or accompanied by other compromise indicators.
- Disable or reset the involved account if it is privileged and appears to be used for malicious activity.
- Block suspicious outbound destinations only after confirming they are not part of approved scanning or management infrastructure.

**Closure criteria:**
- The scanning host is confirmed as an approved scanner or management system and the LSASS access is from a documented security or backup tool.
- The timing correlation is explained by legitimate maintenance activity and no other suspicious host behavior is present.
- The alert is attributable to a known benign process baseline and the host shows no evidence of credential theft or lateral movement.

<br/>
---
<br/>

## Detection 3: VMware_vCenter_Auth_Bypass_Successful_Logon_No_Prior_Failure

### Detection Opportunity

Successful authentication to vCenter from an external IP with no preceding failed authentication attempt, consistent with CVE-2026-59309 authentication bypass in VMware Directory Service

### Intelligence Context

- Rapid7: Critical VMware vCenter Vulnerabilities Allow Authentication Bypass and Remote Code Execution (CVE-2026-59309, CVE-2026-59310) — [https://www.rapid7.com/blog/post/etr-critical-vmware-vcenter-vulnerabilities-allow-authentication-bypass-and-remote-code-execution-cve-2026-59309-cve-2026-59310](https://www.rapid7.com/blog/post/etr-critical-vmware-vcenter-vulnerabilities-allow-authentication-bypass-and-remote-code-execution-cve-2026-59309-cve-2026-59310)
  - Context: CVE-2026-59309 allows unauthenticated attackers to bypass authentication in VMware Directory Service. A successful logon to vCenter from an external IP with no prior failed attempt in the same session window is a strong indicator of bypass exploitation.

### Search Metadata

- CVEs: CVE-2026-59309, CVE-2026-59310
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: VMware vCenter Server, VMware Directory Service, vCenter Syslog
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-59309, CVE-2026-59310, T1190, VMware vCenter Server, VMware Directory Service, vCenter Syslog

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
let LookbackWindow = 15m;
let SuccessfulLogons = CommonSecurityLog
| where TimeGenerated >= ago(7d)
| where DeviceVendor has "VMware"
| where Activity has_any ("logon", "login", "authentication") and Activity has_any ("success", "accepted")
| where isnotempty(SourceIP)
| project SuccessTime = TimeGenerated, SourceIP, DestinationHostName, SourceUserName, Activity, DeviceProduct;
let FailedLogons = CommonSecurityLog
| where TimeGenerated >= ago(7d)
| where DeviceVendor has "VMware"
| where Activity has_any ("logon", "login", "authentication") and Activity has_any ("fail", "denied", "invalid")
| where isnotempty(SourceIP)
| project FailTime = TimeGenerated, SourceIP;
SuccessfulLogons
| join kind=leftanti (
    FailedLogons
  ) on SourceIP
| project SuccessTime, SourceIP, DestinationHostName, SourceUserName, Activity, DeviceProduct
| order by SuccessTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrator logons from IPs that have never previously failed authentication will appear as bypasses.
- Service accounts or automated processes that authenticate successfully on first attempt without prior failures.
- Any SourceIP for which failure events are not forwarded to Sentinel due to upstream filtering.

**Tuning notes:**
- Validate actual DeviceVendor and Activity field values in CommonSecurityLog by running: CommonSecurityLog → where DeviceVendor has 'VMware' → summarize count() by DeviceVendor, Activity → order by count_ desc
- Add a SourceIP exclusion for known vCenter admin subnets to reduce false positives from legitimate administrative access.
- If the environment uses a time-bounded failure check, implement a per-event time-window join using a lookup or inner join with time delta filtering instead of the lifetime leftanti join.

**Risks / caveats:**
- CommonSecurityLog DeviceVendor and Activity field values for VMware vCenter authentication events are determined by the CEF connector or syslog forwarder configuration. If the actual ingested values differ from 'VMware' and the logon/success/fail keyword patterns used in the query, the query will return no results.
- If the syslog or CEF forwarder filters out authentication failure events before ingestion, the leftanti join will incorrectly flag all successful logons as bypasses, producing high false-positive volume.
- CVE-2026-59309 and CVE-2026-59310 are not recognized CVE identifiers in public databases as of the knowledge cutoff; the detection logic is sound but the CVE references should be verified against the actual advisory.
- The leftanti join excludes any SourceIP that has ever had a failure in the 7-day window, not just failures within LookbackWindow before the specific success. This is intentional to maximize sensitivity for bypass detection but will suppress results for IPs with any historical failure.

### Triage Runbook

**First 15 minutes:**
- Verify the SourceIP against approved administrator, VPN, jump host, or management subnet ranges.
- Confirm that failure events for the same SourceIP are actually being ingested; absence of failures may be a logging gap rather than a bypass.
- Review the account, destination host, and time of access to determine whether the login aligns with normal admin activity or maintenance windows.
- Check for follow-on activity on vCenter after the login, such as configuration changes, new accounts, role changes, or plugin installation.

**Evidence to collect:**
- CommonSecurityLog events for the same SourceIP and DestinationHostName before and after the success event.
- Any vCenter audit or administrative logs showing configuration changes, privilege changes, or session actions after the login.
- Identity logs for the SourceUserName to confirm whether the account is expected to access vCenter from that IP.
- Network or firewall logs to validate whether the SourceIP is external, VPN-based, or from an internal management network.

**Pivot points:**
- CommonSecurityLog filtered on DestinationHostName and SourceIP to review the full authentication sequence.
- vCenter audit or syslog records for the same host and time window to identify post-login actions.
- Identity and VPN logs for SourceUserName and SourceIP to confirm the origin of the session.
- If available, endpoint or proxy logs for the SourceIP to determine whether the connection came through an approved path.

**Benign explanations:**
- A legitimate administrator may successfully log in on the first attempt without any prior failures.
- Service accounts or automation may authenticate successfully without failed attempts.
- Failure events may be filtered upstream or not forwarded, making the success appear bypass-like when it is not.

**Escalation criteria:**
- Escalate if the SourceIP is external, unapproved, or not associated with a known admin path.
- Escalate if the login is followed by configuration changes, new credentials, or privilege modifications in vCenter.
- Escalate if the account is privileged and the login occurs outside normal maintenance windows or from an unusual geography.
- Escalate if failure events are missing broadly for the same source and the environment normally forwards them, suggesting a telemetry issue that must be investigated.

**Containment actions:**
- If the login is suspicious, disable the account or revoke active sessions after confirming it is not a critical automation identity.
- Restrict access to vCenter from the suspicious SourceIP or network segment while investigation is ongoing.
- Preserve vCenter logs and related identity telemetry before making changes that could destroy evidence.

**Closure criteria:**
- The SourceIP is confirmed as an approved admin or automation source and the login matches expected behavior.
- No suspicious post-login activity is observed in vCenter audit logs or related identity telemetry.
- The absence of failures is explained by known logging gaps or connector filtering, and the event is consistent with normal operations.

<br/>
---
<br/>

## Detection 4: VMware_vCenter_Syslog_Directory_Traversal_Request

### Detection Opportunity

Directory traversal sequences in requests to vCenter Syslog service endpoints, consistent with CVE-2026-59310 exploitation

### Intelligence Context

- Rapid7: Critical VMware vCenter Vulnerabilities Allow Authentication Bypass and Remote Code Execution (CVE-2026-59309, CVE-2026-59310) — [https://www.rapid7.com/blog/post/etr-critical-vmware-vcenter-vulnerabilities-allow-authentication-bypass-and-remote-code-execution-cve-2026-59309-cve-2026-59310](https://www.rapid7.com/blog/post/etr-critical-vmware-vcenter-vulnerabilities-allow-authentication-bypass-and-remote-code-execution-cve-2026-59309-cve-2026-59310)
  - Context: CVE-2026-59310 is a directory traversal vulnerability in the vCenter Syslog service. Requests containing path traversal sequences targeting vCenter syslog endpoints from unauthenticated sources are the primary exploitation indicator.

### Search Metadata

- CVEs: CVE-2026-59309, CVE-2026-59310
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: VMware vCenter Server, VMware Directory Service, vCenter Syslog
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-59309, CVE-2026-59310, T1190, VMware vCenter Server, VMware Directory Service, vCenter Syslog

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

**Required telemetry:**
- CommonSecurityLog, Syslog

### KQL

```kql
let TraversalPatterns = dynamic(["../", "%2e%2e", "%2f%2e%2e", "..%2f", "%252e%252e", "..%5c", "%2e%2e%2f"]);
CommonSecurityLog
| where TimeGenerated >= ago(7d)
| where DeviceVendor has "VMware"
| where isnotempty(RequestURL)
| where RequestURL has_any (TraversalPatterns)
| project
    TimeGenerated,
    SourceIP,
    DestinationHostName,
    RequestURL,
    RequestMethod,
    SourceUserName,
    DeviceProduct,
    LogSource = "CommonSecurityLog"
| union (
    Syslog
    | where TimeGenerated >= ago(7d)
    | where SyslogMessage has_any (TraversalPatterns)
    | where Computer has_any ("vcenter", "vCenter")
    | project
        TimeGenerated,
        SourceIP = iff(isnotempty(HostIP), HostIP, ""),
        DestinationHostName = Computer,
        RequestURL = SyslogMessage,
        RequestMethod = "",
        SourceUserName = "",
        DeviceProduct = "VMware-Syslog",
        LogSource = "Syslog"
  )
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Web application scanners or vulnerability assessment tools running against vCenter will generate traversal pattern matches.
- Penetration testing activity targeting vCenter infrastructure.
- Syslog messages containing path strings with traversal-like sequences that are not HTTP requests.

**Tuning notes:**
- Validate that CommonSecurityLog RequestURL is populated for vCenter events by running: CommonSecurityLog → where DeviceVendor has 'VMware' → summarize count() by isnotempty(RequestURL)
- Validate actual vCenter Computer field values in Syslog by running: Syslog → where Computer has_any ('vcenter', 'vCenter') → summarize count() by Computer
- Add additional encoding variants to TraversalPatterns if WAF or proxy logs show additional obfuscation techniques in the environment.
- If upstream normalization decodes URL encoding, remove encoded variants from TraversalPatterns and rely only on the literal '../' pattern.

**Risks / caveats:**
- CommonSecurityLog RequestURL field is only populated when the CEF connector forwards HTTP request logs from vCenter. If vCenter is not configured to emit HTTP access logs in CEF format, this field will be empty and the CommonSecurityLog leg will return no results.
- Syslog HostIP field is not reliably populated across all syslog forwarder configurations; the SourceIP projection from this field may be empty for many events.
- The Computer field filter using has_any('vcenter', 'vCenter') requires vCenter hostnames in the environment to contain the string 'vcenter'. Environments using numeric or non-descriptive hostnames will not match.
- CVE-2026-59309 and CVE-2026-59310 are not recognized CVE identifiers in public databases as of the knowledge cutoff; the detection logic is sound but the CVE references should be verified against the actual advisory.

### Triage Runbook

**First 15 minutes:**
- Confirm the RequestURL or SyslogMessage contains actual traversal sequences targeting vCenter-specific paths, not just a generic string match.
- Validate whether the SourceIP is a known scanner, penetration test source, or an external untrusted address.
- Check for nearby successful authentication, configuration changes, or service restarts on the same vCenter host.
- Determine whether the request pattern is repeated, automated, or paired with other exploit indicators from the same source.

**Evidence to collect:**
- CommonSecurityLog entries for the same SourceIP, DestinationHostName, RequestURL, and RequestMethod around the alert time.
- Syslog entries from the same vCenter host to see whether the traversal pattern appears in service logs or only in forwarded request logs.
- Any vCenter audit events showing authentication, privilege changes, or administrative actions after the request.
- Firewall, proxy, or WAF logs to confirm the request path, source, and whether the traffic was blocked or allowed.

**Pivot points:**
- CommonSecurityLog filtered on SourceIP and DestinationHostName to enumerate all requests from the source.
- Syslog filtered on the same vCenter hostname to identify related service errors or exploit artifacts.
- Firewall or proxy logs for the SourceIP to determine whether the request was internet-originated or internal.
- If available, correlate with vCenter authentication logs to see whether the same source later authenticated successfully.

**Benign explanations:**
- Vulnerability scanners and penetration tests often generate traversal patterns against exposed services.
- Security validation or red-team activity may intentionally probe vCenter endpoints.
- Non-HTTP syslog messages can contain traversal-like strings that are not exploit attempts.

**Escalation criteria:**
- Escalate if the SourceIP is external or unknown and the request targets a vCenter-specific endpoint.
- Escalate if the request is followed by authentication bypass, configuration changes, or service instability on vCenter.
- Escalate if multiple traversal variants or repeated attempts are observed from the same source.
- Escalate if the host is internet-facing and not protected by a WAF or reverse proxy that would normally block such requests.

**Containment actions:**
- Block the SourceIP at the perimeter if the request is confirmed malicious and not part of approved testing.
- Place the vCenter service behind tighter access controls or a WAF rule if exposure is ongoing.
- Preserve relevant request and syslog evidence before restarting services or applying mitigations.

**Closure criteria:**
- The source is confirmed as an approved scanner, tester, or internal validation system.
- The request is not directed at a vulnerable vCenter endpoint or is blocked by compensating controls with no impact.
- No authentication, configuration, or service anomalies are found on the vCenter host after review.

<br/>
---
<br/>

## Detection 5: Meterpreter_Interpreter_Process_Outbound_C2_After_Webserver_Spawn

### Detection Opportunity

Interpreter process (Python, PHP, Java) spawned by a web server parent initiating outbound network connections shortly after creation, consistent with Meterpreter staged or stageless payload delivery

### Intelligence Context

- Rapid7: Metasploit Framework 6.5 Released — [https://www.rapid7.com/blog/post/pt-metasploit-framework-6-5-released](https://www.rapid7.com/blog/post/pt-metasploit-framework-6-5-released)
  - Context: Metasploit Framework 6.5 extends Malleable C2 profile support to all Meterpreter payloads including Windows, Java, Python, PHP, and Linux variants. Interpreter processes spawned by web server parents that immediately initiate outbound connections are a key behavioral indicator of Meterpreter delivery.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1071.001, T1071
- Products: Not specified
- Platforms: Windows, Linux, Java, Python, PHP, HTTP
- Malware: Not specified
- Tools: Metasploit Framework, Meterpreter
- Search tags: Metasploit Framework, Meterpreter, Windows, Linux, Java, Python, PHP, HTTP, T1059, T1071.001, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (high); Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let SpawnWindow = 2m;
let WebServerParents = dynamic([
    "w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe",
    "php-fpm.exe", "apache2", "httpd"
]);
let InterpreterNames = dynamic([
    "python.exe", "python3", "python", "python3.exe",
    "php.exe", "php",
    "java.exe", "java"
]);
let SuspiciousSpawns = DeviceProcessEvents
| where Timestamp >= ago(7d)
| where ActionType == "ProcessCreated"
| where FileName has_any (InterpreterNames)
| where InitiatingProcessFileName has_any (WebServerParents)
| project
    DeviceName,
    SpawnTime = Timestamp,
    ProcessId,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath;
let OutboundConns = DeviceNetworkEvents
| where Timestamp >= ago(7d)
| where ActionType in ("ConnectionSuccess", "ConnectionAttempted")
| where RemotePort !in (80, 443, 53, 8080, 8443, 8000, 8888)
| where RemoteIP !startswith "127."
| where RemoteIP != "::1"
| project
    DeviceName,
    ConnTime = Timestamp,
    InitiatingProcessId,
    RemoteIP,
    RemotePort,
    RemoteUrl;
SuspiciousSpawns
| join kind=inner OutboundConns
    on DeviceName, $left.ProcessId == $right.InitiatingProcessId
| where ConnTime between (SpawnTime .. (SpawnTime + SpawnWindow))
| project
    DeviceName,
    SpawnTime,
    ConnTime,
    FileName,
    ProcessId,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    RemoteIP,
    RemotePort,
    RemoteUrl
| order by SpawnTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate web applications that spawn Python or PHP interpreters for request processing and make outbound API calls.
- Java-based application servers that spawn child Java processes for legitimate inter-service communication.
- Development or CI/CD environments where web servers routinely spawn interpreter processes with outbound connectivity.
- Package managers or update mechanisms invoked by web server processes that make outbound connections.

**Tuning notes:**
- Extend WebServerParents with any additional web server process names present in the environment.
- Extend the RemotePort exclusion list with additional legitimate service ports used by interpreter processes in the environment.
- Narrow SpawnWindow from 2 minutes to 30 seconds if the environment has frequent legitimate interpreter spawning that generates noise.
- Add an InitiatingProcessFolderPath filter to restrict web server parents to known installation paths if the environment has consistent deployment standards.

**Risks / caveats:**
- ProcessId in DeviceProcessEvents and InitiatingProcessId in DeviceNetworkEvents are both 32-bit integers that can be reused by the OS within the SpawnWindow. On high-activity systems, a ProcessId collision between an unrelated process and the spawned interpreter could produce a false correlation. The time-window join mitigates but does not eliminate this risk.
- ProcessId reuse within the SpawnWindow on high-activity systems could produce false correlations between unrelated processes sharing the same ProcessId value.
- Linux process names for interpreters and web servers vary by distribution and installation method; the dynamic lists may need extension for specific environments.
- The RemotePort exclusion list covers common web and DNS ports but does not cover all legitimate outbound ports used by interpreters in all environments.

### Triage Runbook

**First 15 minutes:**
- Validate the web server parent process and its installation path to confirm it is a real web service and not a benign application using similar names.
- Inspect the interpreter command line for encoded payloads, reverse shell arguments, downloaders, or unusual script paths.
- Review the outbound destination IP, port, and timing to see whether the connection is consistent with a callback or staged payload delivery.
- Check for additional web exploitation indicators on the host, including dropped files, new services, suspicious child processes, or repeated interpreter launches.

**Evidence to collect:**
- DeviceProcessEvents for the web server parent and spawned interpreter, including command lines, process IDs, and timestamps.
- DeviceNetworkEvents for the interpreter process to identify remote IPs, ports, and any repeated outbound attempts.
- Any file creation or modification events near the spawn time that could indicate payload staging or web shell deployment.
- Web server access logs, if available, to correlate the interpreter spawn with a specific request or client IP.

**Pivot points:**
- DeviceProcessEvents on the same DeviceName for all interpreter spawns from the same web server parent within the last 24 hours.
- DeviceNetworkEvents for the same ProcessId to enumerate all outbound connections from the interpreter.
- DeviceFileEvents or equivalent file telemetry for dropped scripts, temporary files, or web shell artifacts.
- Web server logs or reverse proxy logs to identify the request that preceded the interpreter spawn.

**Benign explanations:**
- Legitimate web applications may spawn Python, PHP, or Java interpreters for request handling or backend processing.
- Development, CI/CD, or automation environments may legitimately create outbound connections from interpreter processes.
- Package updates or service orchestration can cause web server parents to launch child processes that connect externally.

**Escalation criteria:**
- Escalate if the interpreter command line is suspicious, encoded, or references a web shell, downloader, or reverse shell.
- Escalate if the outbound destination is unknown, newly registered, or associated with malicious infrastructure.
- Escalate if the web server parent runs from an unusual path or the host also shows file drops, service creation, or persistence artifacts.
- Escalate if the activity occurs on an internet-facing server and aligns with a recent web request or exploit attempt.

**Containment actions:**
- Isolate the server if the interpreter appears to be executing attacker-controlled code or making C2 callbacks.
- Disable the affected web application or virtual host if exploitation is confirmed and business impact can be managed.
- Preserve web logs, process telemetry, and any dropped files before remediation actions.

**Closure criteria:**
- The spawned interpreter is tied to a documented application workflow and the outbound connection is to an approved service.
- No suspicious command-line arguments, file drops, or follow-on processes are found after reviewing the surrounding time window.
- The parent web server and interpreter behavior match the environment baseline and there is no evidence of exploitation or C2.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- OctLurk_SilkLurk_Shell_Spawned_From_Unusual_Parent: Do not schedule yet; validate as an analyst-led hunt first.
- OctLurk_SilkLurk_Network_Scan_With_Concurrent_LSASS_Access: Do not schedule yet; validate as an analyst-led hunt first.
- Meterpreter_Interpreter_Process_Outbound_C2_After_Webserver_Spawn: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- OctLurk_SilkLurk_Network_Scan_With_Concurrent_LSASS_Access: DeviceEvents ActionType 'OpenProcessApiCall' requires Defender for Endpoint advanced telemetry (process access auditing) to be enabled. If this telemetry is not collected, the LSASS access leg of the join will return no results and the detection will produce no output.
- VMware_vCenter_Auth_Bypass_Successful_Logon_No_Prior_Failure: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.
- VMware_vCenter_Syslog_Directory_Traversal_Request: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.

**Shared-table notes:**
- DeviceProcessEvents: shared by OctLurk_SilkLurk_Shell_Spawned_From_Unusual_Parent; Meterpreter_Interpreter_Process_Outbound_C2_After_Webserver_Spawn
- DeviceNetworkEvents: shared by OctLurk_SilkLurk_Network_Scan_With_Concurrent_LSASS_Access; Meterpreter_Interpreter_Process_Outbound_C2_After_Webserver_Spawn
- CommonSecurityLog: shared by VMware_vCenter_Auth_Bypass_Successful_Logon_No_Prior_Failure; VMware_vCenter_Syslog_Directory_Traversal_Request

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: VMware_vCenter_Auth_Bypass_Successful_Logon_No_Prior_Failure; VMware_vCenter_Syslog_Directory_Traversal_Request.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: OctLurk_SilkLurk_Shell_Spawned_From_Unusual_Parent; OctLurk_SilkLurk_Network_Scan_With_Concurrent_LSASS_Access; Meterpreter_Interpreter_Process_Outbound_C2_After_Webserver_Spawn.

### Hunting Agenda and Promotion Criteria

- OctLurk_SilkLurk_Shell_Spawned_From_Unusual_Parent: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- OctLurk_SilkLurk_Network_Scan_With_Concurrent_LSASS_Access: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Meterpreter_Interpreter_Process_Outbound_C2_After_Webserver_Spawn: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- VMware_vCenter_Auth_Bypass_Successful_Logon_No_Prior_Failure: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- VMware_vCenter_Syslog_Directory_Traversal_Request: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
