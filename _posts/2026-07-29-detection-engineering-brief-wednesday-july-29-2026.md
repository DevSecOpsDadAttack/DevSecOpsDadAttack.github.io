---
layout: post
title: "Detection Engineering Brief - Wednesday, July 29, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-29
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-16232
  - T1190
  - Check Point SmartConsole
  - Check Point Security Management Server
  - Check Point Multi-Domain Security Management Server
  - MDS
  - T1055
  - Windows
  - AutoIT
  - T1059
  - T1059.004
---

## Detection Engineering Summary

This brief produced 4 detection candidates.

1 production candidate, 1 hunting-only, 2 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-16232, T1190, Check Point SmartConsole, Check Point Security Management Server, Check Point Multi-Domain Security Management Server, MDS, T1055, Windows, AutoIT, T1059, T1059.004.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: CVE-2026-16232 - Check Point SmartConsole Admin Login Followed by Policy Modification; CVE-2026-16232 - Unexpected Inbound Connection to Check Point Management Server Port; AutoIT Script Execution from Suspicious User-Writable Paths on Windows.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: CVE-2026-16232 - Check Point SmartConsole Admin Login Followed by Policy Modification

### Detection Opportunity

Unauthenticated token abuse enabling admin login to SmartConsole followed by security policy modification.

### Intelligence Context

- Rapid7: Check Point SmartConsole Authentication Bypass Technical Analysis (CVE-2026-16232) — [https://www.rapid7.com/blog/post/ra-check-point-smartconsole-authentication-bypass-technical-analysis-cve-2026-16232](https://www.rapid7.com/blog/post/ra-check-point-smartconsole-authentication-bypass-technical-analysis-cve-2026-16232)
  - Context: CVE-2026-16232 allows an unauthenticated attacker to obtain an application login token and use it to authenticate to SmartConsole with full administrator privileges, then modify security policy or configuration. Rapid7 confirmed exploitation requires only network access to the Management Server.

### Search Metadata

- CVEs: CVE-2026-16232
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Check Point SmartConsole, Check Point Security Management Server, Check Point Multi-Domain Security Management Server, MDS
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-16232, T1190, Check Point SmartConsole, Check Point Security Management Server, Check Point Multi-Domain Security Management Server, MDS

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
let lookback = 14d;
let correlationWindow = 30m;
let recentWindow = 1h;
let knownAdminIPs =
    CommonSecurityLog
    | where TimeGenerated between (ago(lookback) .. ago(recentWindow))
    | where DeviceVendor =~ "Check Point"
    | where DeviceProduct has_any ("SmartCenter", "Security Management")
    | where Activity has_any ("Log In", "login", "Administrator logged in")
    | summarize by SourceIP;
let newAdminLogins =
    CommonSecurityLog
    | where TimeGenerated > ago(recentWindow)
    | where DeviceVendor =~ "Check Point"
    | where DeviceProduct has_any ("SmartCenter", "Security Management")
    | where Activity has_any ("Log In", "login", "Administrator logged in")
    | where isnotempty(SourceIP)
    | where SourceIP !in (knownAdminIPs)
    | project LoginTime = TimeGenerated, SourceIP, DestinationUserName, LoginActivity = Activity, LoginMessage = Message, Computer;
let policyChanges =
    CommonSecurityLog
    | where TimeGenerated > ago(recentWindow)
    | where DeviceVendor =~ "Check Point"
    | where DeviceProduct has_any ("SmartCenter", "Security Management")
    | where Activity has_any ("Policy installed", "Install Policy", "Object modified", "Rule modified", "policy change")
    | where isnotempty(SourceIP)
    | project ChangeTime = TimeGenerated, SourceIP, DestinationUserName, ChangeActivity = Activity, ChangeMessage = Message;
newAdminLogins
| join kind=inner policyChanges on SourceIP, DestinationUserName
| where ChangeTime between (LoginTime .. (LoginTime + correlationWindow))
| extend TimeDeltaMinutes = datetime_diff('minute', ChangeTime, LoginTime)
| project
    LoginTime,
    ChangeTime,
    TimeDeltaMinutes,
    SourceIP,
    DestinationUserName,
    LoginActivity,
    ChangeActivity,
    LoginMessage,
    ChangeMessage,
    Computer
| sort by LoginTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrators connecting from a new IP address such as a new VPN endpoint, home office, or travel location will trigger this detection.
- First-time logins after the 14-day lookback window resets will appear as novel even for known admins.
- Scheduled policy pushes or automated management tasks executed shortly after a legitimate new-IP login will correlate and alert.

**Tuning notes:**
- Extend the lookback window beyond 14 days if admin login frequency is low in your environment to reduce false positives from infrequent legitimate admins.
- Validate exact DeviceProduct strings emitted by your Check Point version by running: CommonSecurityLog → where DeviceVendor =~ 'Check Point' → summarize count() by DeviceProduct.
- Validate exact Activity strings by running: CommonSecurityLog → where DeviceVendor =~ 'Check Point' → summarize count() by Activity → sort by count_ desc.
- Consider adding a watchlist of known management jump hosts or bastion IPs to exclude from novelty detection.

**Risks / caveats:**
- CommonSecurityLog requires a CEF or Syslog connector forwarding Check Point Security Management Server logs to Microsoft Sentinel. If this connector is not configured, the query returns no results.
- The DeviceProduct values 'SmartCenter' and 'Security Management' and Activity string values for login and policy change events must match what Check Point actually emits. These vary by firmware version and log profile; mismatches cause the query to silently return no results.
- SourceIP in CommonSecurityLog for Check Point management logs may not represent the SmartConsole client IP depending on log forwarding topology; this must be validated before the correlation is trusted.
- The 14-day lookback baseline will not capture admin IPs that have not logged in during that window, causing false positives for infrequent but legitimate admins.

### Triage Runbook

**First 15 minutes:**
- Confirm the login and policy change are from the same SourceIP and DestinationUserName, and note the time delta between events.
- Check whether the SourceIP is a known admin VPN, jump host, bastion, or other approved management source before treating it as malicious.
- Review the LoginMessage and ChangeMessage for the exact admin account used, the policy object or rule modified, and whether the change was installed.
- Identify the Computer/management server receiving the events and verify whether it is the expected Check Point Security Management Server or MDS instance.
- If the change appears unauthorized or the account is unexpected, immediately notify the incident lead and Check Point administrator.

**Evidence to collect:**
- LoginTime, ChangeTime, TimeDeltaMinutes, SourceIP, DestinationUserName, LoginActivity, ChangeActivity, LoginMessage, ChangeMessage, Computer.
- Any additional CommonSecurityLog entries from the same SourceIP and DestinationUserName before and after the alert window.
- Check Point audit or administrator activity logs showing policy installation, object edits, or configuration exports.
- VPN, jump host, or bastion logs to validate whether the source IP belongs to an approved administrator path.
- Account history for DestinationUserName, including recent password resets, MFA changes, or privilege modifications.

**Pivot points:**
- CommonSecurityLog for all Check Point management logins, policy installs, object modifications, and admin actions from the same SourceIP or DestinationUserName.
- CommonSecurityLog for the same Computer to identify other admin sessions or concurrent changes.
- Identity and VPN logs to determine whether the source IP maps to a legitimate administrator session.
- Firewall or proxy logs for inbound connections to the management server from the same SourceIP around the alert time.

**Benign explanations:**
- A legitimate administrator connected from a new VPN endpoint, home network, or travel location.
- A scheduled policy push or routine configuration change performed shortly after a valid first-time login.
- A newly onboarded administrator or a reset admin workstation that has not appeared in the 14-day baseline.

**Escalation criteria:**
- The SourceIP is not associated with any approved admin path and the login is followed by policy installation or rule modification.
- The DestinationUserName is privileged and the change affects security policy, management access, or logging settings.
- Multiple admin actions occur from the same new source IP, especially if followed by additional suspicious management-server activity.
- There is evidence of other exploitation indicators on the management server, such as unusual inbound connections or repeated login attempts.

**Containment actions:**
- Disable or reset the affected administrator account if unauthorized use is suspected.
- Block the SourceIP at the perimeter or management access layer if it is confirmed malicious and not a shared corporate egress point.
- Revoke active SmartConsole sessions and force reauthentication for privileged accounts involved in the alert.
- Coordinate with the Check Point administrator to review and, if needed, revert unauthorized policy or configuration changes.

**Closure criteria:**
- The source IP is validated as an approved administrator path and the policy change is confirmed to be authorized and expected.
- No additional suspicious management-server activity is found for the account or source IP during the surrounding time window.
- The policy change is documented as a legitimate maintenance action with change ticket or approval evidence.
- Any unauthorized changes have been reverted and the account/source has been remediated or ruled benign.

<br/>
---
<br/>

## Detection 2: CVE-2026-16232 - Unexpected Inbound Connection to Check Point Management Server Port

### Detection Opportunity

Network access to Check Point Management Server from a source IP with no prior connection history, consistent with unauthenticated token retrieval exploitation.

### Intelligence Context

- Rapid7: Check Point SmartConsole Authentication Bypass Technical Analysis (CVE-2026-16232) — [https://www.rapid7.com/blog/post/ra-check-point-smartconsole-authentication-bypass-technical-analysis-cve-2026-16232](https://www.rapid7.com/blog/post/ra-check-point-smartconsole-authentication-bypass-technical-analysis-cve-2026-16232)
  - Context: Exploitation of CVE-2026-16232 requires network access to the Management Server. An unauthenticated attacker sends a crafted request to obtain a login token. Detecting novel source IPs connecting to management server ports provides an early-stage signal before token use.

### Search Metadata

- CVEs: CVE-2026-16232
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Check Point SmartConsole, Check Point Security Management Server, Check Point Multi-Domain Security Management Server, MDS
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-16232, T1190, Check Point SmartConsole, Check Point Security Management Server, Check Point Multi-Domain Security Management Server, MDS

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Both
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Both: DeviceNetworkEvents before scheduling.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
let mgmtPorts = dynamic([18190, 19009, 443]);
let lookback = 14d;
let recentWindow = 1h;
let historicConnections =
    DeviceNetworkEvents
    | where Timestamp between (ago(lookback) .. ago(recentWindow))
    | where LocalPort in (mgmtPorts)
    | where isnotempty(RemoteIP)
    | summarize by RemoteIP, LocalPort;
DeviceNetworkEvents
| where Timestamp > ago(recentWindow)
| where LocalPort in (mgmtPorts)
| where ActionType in ("InboundConnectionAccepted", "ConnectionSuccess")
| where isnotempty(RemoteIP)
| join kind=leftanti historicConnections on RemoteIP, LocalPort
| project
    Timestamp,
    DeviceName,
    RemoteIP,
    RemotePort,
    LocalPort,
    ActionType,
    InitiatingProcessFileName
| sort by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- New SmartConsole client workstations added to the environment will trigger this detection on first connection.
- VPN IP pool changes causing admin workstations to appear with new source IPs will generate false positives.
- Port 443 matches will be extremely noisy if DeviceName is not scoped to the management server.

**Tuning notes:**
- Add a DeviceName filter scoped to the Check Point Management Server hostname to make this query meaningful and reduce noise from port 443 on unrelated devices.
- Consider removing port 443 from mgmtPorts if web-based management is not used in your environment, as it significantly increases noise.
- Validate that ports 18190 and 19009 appear in historical DeviceNetworkEvents for the management server before relying on absence-based baselining.
- If the management server is not onboarded to MDE, consider using CommonSecurityLog with Check Point firewall logs or network flow data from a NGFW as an alternative telemetry source.

**Risks / caveats:**
- DeviceNetworkEvents only contains telemetry from devices onboarded to Microsoft Defender for Endpoint. Check Point Security Management Server appliances running Gaia OS are not supported MDE targets, so this table is unlikely to contain inbound connection data for the management server unless a network sensor or proxy is onboarded and has visibility.
- ActionType value 'InboundConnectionAccepted' availability depends on the OS and MDE sensor version; this value may not be present for all platforms.
- Port 443 without DeviceName scoping to the management server will match any HTTPS connection on any onboarded device, producing extremely high volume results.
- This query is only useful if the Check Point Management Server or a network sensor with visibility to it is onboarded to MDE and appears in DeviceNetworkEvents. Validate this before using the query.

### Triage Runbook

**First 15 minutes:**
- Verify the DeviceName is the actual Check Point management server or MDS host and not another HTTPS listener.
- Check whether the RemoteIP belongs to a known SmartConsole client, VPN pool, jump host, or management subnet.
- Review the connection timing, port, and ActionType to confirm it is truly inbound to the management server and not a benign outbound or proxy-related event.
- Look for follow-on management logins, policy changes, or other admin actions from the same RemoteIP shortly after the connection.
- If the RemoteIP is unknown and the server is internet-reachable, treat the event as potentially malicious and escalate.

**Evidence to collect:**
- Timestamp, DeviceName, RemoteIP, RemotePort, LocalPort, ActionType, InitiatingProcessFileName.
- Any additional DeviceNetworkEvents for the same DeviceName and RemoteIP before and after the alert.
- Check Point management or audit logs showing whether the connection was followed by authentication or configuration activity.
- Network perimeter logs showing whether the RemoteIP reached the management server from outside approved networks.
- Asset inventory or CMDB data confirming the management server hostname, exposed ports, and expected admin source ranges.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceName to identify repeated inbound attempts or other unusual ports from the same RemoteIP.
- CommonSecurityLog for Check Point management logins and policy changes from the same RemoteIP or around the same time.
- Firewall, VPN, or proxy logs to determine whether the RemoteIP is a corporate egress address or external source.
- Endpoint or network sensor telemetry for the management server if available, to validate whether the connection was accepted and by which process.

**Benign explanations:**
- A new SmartConsole workstation or newly assigned VPN IP connecting for the first time.
- A management server port exposure that is expected in your environment but has not been seen in the 14-day baseline.
- A proxy or NAT change causing a legitimate administrator to appear as a new RemoteIP.

**Escalation criteria:**
- The RemoteIP is external or unrecognized and the management server is reachable from that source.
- The connection is followed by a SmartConsole login, policy modification, or other privileged management action.
- Multiple novel RemoteIPs target the management server in a short period, suggesting active probing or exploitation.
- The management server shows other suspicious activity, such as repeated inbound attempts or unexpected process/network behavior.

**Containment actions:**
- Block the RemoteIP or source network if it is confirmed malicious and not part of an approved admin path.
- Restrict management-server exposure to approved admin networks if the service is currently reachable from broader networks.
- Coordinate with the Check Point team to temporarily limit SmartConsole access if exploitation is suspected.
- Increase monitoring on the management server for additional inbound attempts and follow-on authentication events.

**Closure criteria:**
- The RemoteIP is confirmed to be an approved admin source or expected corporate egress address.
- No follow-on login, policy change, or other suspicious activity is observed from the same source.
- The connection is explained by a documented change, test, or maintenance activity.
- The management server exposure and port usage are validated as expected for the environment.

<br/>
---
<br/>

## Detection 3: AutoIT Process Injection - AutoIT3.exe Accessing Remote Process Memory on Windows

### Detection Opportunity

AutoIT3.exe performing remote process injection by spawning unusual child processes or accessing memory of unrelated processes.

### Intelligence Context

- SANS ISC: AutoIT Payload Injector , (Tue, Jul 28th) — [https://isc.sans.edu/diary/rss/33192](https://isc.sans.edu/diary/rss/33192)
  - Context: SANS ISC documented AutoIT being used as a payload injector to perform all required actions to inject a payload into a remote process on Windows. Threat actors favor AutoIT for its ease of scripting and capability to interact with Windows APIs for process injection.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1055, T1059, T1059.004
- Products: Not specified
- Platforms: Windows
- Malware: Not specified
- Tools: AutoIT
- Search tags: T1055, Windows, AutoIT, T1059, T1059.004

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: medium
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.004 Visual Basic (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let lookbackWindow = 7d;
let suspiciousChildProcesses = dynamic(["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "schtasks.exe", "wmic.exe"]);
let suspiciousPaths = dynamic(["\\AppData\\Local\\Temp\\", "\\Users\\Public\\", "\\ProgramData\\", "\\Windows\\Temp\\"]);
DeviceProcessEvents
| where Timestamp > ago(lookbackWindow)
| where isnotempty(InitiatingProcessFileName)
| where InitiatingProcessFileName =~ "AutoIt3.exe" or InitiatingProcessFileName =~ "AutoIt3_x64.exe"
| where FileName in~ (suspiciousChildProcesses)
    or FolderPath has_any (suspiciousPaths)
    or ProcessCommandLine matches regex @"(?i)(\-encodedcommand|\-enc\s|/e\s|frombase64|iex|invoke-expression|hidden)"
| project
    Timestamp,
    DeviceName,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    FileName,
    ProcessCommandLine,
    FolderPath,
    SHA256
| sort by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Enterprise software that bundles AutoIT as a scripting engine and legitimately spawns cmd.exe or powershell.exe for installation or configuration tasks.
- IT automation tools using AutoIT scripts that execute from ProgramData or AppData paths as part of normal deployment workflows.
- Security tools or RMM agents that use AutoIT internally.

**Tuning notes:**
- Add known legitimate AutoIT deployment FolderPath prefixes as exclusion filters using a where not (FolderPath has_any (...)) clause after confirming safe paths in your environment.
- Cross-reference SHA256 values from alerts against threat intelligence to prioritize confirmed malicious binaries.
- Consider adding InitiatingProcessFolderPath has_any (suspiciousPaths) as an additional high-confidence signal to separate malicious from legitimate AutoIT child process spawning.
- If AutoIT is not used in your environment at all, the absence of any AutoIT3.exe entries in DeviceProcessEvents is itself a useful validation signal.

**Risks / caveats:**
- DeviceProcessEvents requires Microsoft Defender for Endpoint onboarding on Windows endpoints with process creation telemetry enabled. If MDE is not deployed or process telemetry is disabled, the query returns no results.
- Adversaries may rename AutoIT3.exe to evade the filename-based filter; SHA256-based detection should be layered once known malicious AutoIT binary hashes are identified.
- The suspiciousChildProcesses list is not exhaustive; novel injection chains using unlisted binaries will not be detected.
- FolderPath matching on has_any with path substrings may miss injection activity where the child process runs from a non-suspicious path even when spawned by malicious AutoIT.

### Triage Runbook

**First 15 minutes:**
- Identify the host, user, and parent process that launched AutoIT3.exe and determine whether the execution path is expected.
- Review the child process name, command line, and folder path for signs of script execution, encoded commands, or suspicious living-off-the-land binaries.
- Check whether the AutoIT binary is running from a user-writable or temporary location and whether that location is normal for this endpoint.
- Look for concurrent alerts on the same host involving credential theft, script execution, or suspicious network activity.
- If the process tree shows injection into another process or suspicious child process spawning, escalate to incident response.

**Evidence to collect:**
- Timestamp, DeviceName, AccountName, AccountDomain, InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, ProcessCommandLine, FolderPath, SHA256.
- Full process tree for the AutoIT3.exe instance, including parent and child processes.
- Any related DeviceNetworkEvents from the same host around the same time.
- File reputation or hash intelligence for the SHA256 values observed.
- Endpoint telemetry showing whether the AutoIT binary or script was created, downloaded, or executed from a user-writable path.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName, AccountName, or SHA256 to find repeated AutoIT execution or related child processes.
- DeviceNetworkEvents for the same DeviceName to identify outbound connections after AutoIT execution.
- DeviceFileEvents for the same host to see whether the AutoIT binary or script was dropped recently.
- Threat intelligence or hash reputation sources for the observed SHA256.

**Benign explanations:**
- Legitimate enterprise software or IT automation that uses AutoIT for installation or configuration tasks.
- A managed deployment or RMM tool that launches AutoIT from ProgramData or AppData as part of normal operations.
- A developer or tester running AutoIT scripts on a lab or build workstation.

**Escalation criteria:**
- AutoIT3.exe spawns cmd.exe, powershell.exe, wscript.exe, mshta.exe, rundll32.exe, or another suspicious child process.
- The binary runs from a user-writable or temporary path and the command line includes encoded or obfuscated content.
- The same host shows evidence of injection, credential access, persistence, or suspicious outbound connections.
- The SHA256 is known malicious or the process tree matches a confirmed intrusion pattern.

**Containment actions:**
- Isolate the host if the process tree or surrounding telemetry indicates active malicious execution or injection.
- Terminate the suspicious AutoIT process and any clearly related child processes if containment is required and approved.
- Block or quarantine the file hash if it is confirmed malicious and present across multiple endpoints.
- Disable the user account if the activity appears tied to compromised credentials or unauthorized execution.

**Closure criteria:**
- The AutoIT activity is confirmed to be part of a legitimate software deployment, automation, or testing workflow.
- The process tree, hash, and command line are consistent with approved enterprise use and no malicious follow-on activity is found.
- Any suspicious child processes are explained by a known installer or admin script and validated by the owning team.
- No additional alerts or indicators appear on the host after review.

<br/>
---
<br/>

## Detection 4: AutoIT Script Execution from Suspicious User-Writable Paths on Windows

### Detection Opportunity

AutoIT3.exe executing scripts from user-writable or temporary directories, consistent with malicious delivery and execution.

### Intelligence Context

- SANS ISC: AutoIT Payload Injector , (Tue, Jul 28th) — [https://isc.sans.edu/diary/rss/33192](https://isc.sans.edu/diary/rss/33192)
  - Context: SANS ISC reported that threat actors use AutoIT scripts as a malicious delivery mechanism on Windows due to ease of authoring and powerful Windows API access. Execution from temp or user-writable paths is a common indicator of malicious AutoIT deployment.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1055, T1059, T1059.004
- Products: Not specified
- Platforms: Windows
- Malware: Not specified
- Tools: AutoIT
- Search tags: T1055, Windows, AutoIT, T1059, T1059.004

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.004 Visual Basic (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let lookbackWindow = 7d;
let suspiciousPaths = dynamic(["\\AppData\\Local\\Temp\\", "\\AppData\\Roaming\\", "\\Users\\Public\\", "\\ProgramData\\", "\\Windows\\Temp\\", "\\Downloads\\"]);
DeviceProcessEvents
| where Timestamp > ago(lookbackWindow)
| where isnotempty(FileName)
| where FileName =~ "AutoIt3.exe" or FileName =~ "AutoIt3_x64.exe"
| where FolderPath has_any (suspiciousPaths)
    or ProcessCommandLine has_any (suspiciousPaths)
| project
    Timestamp,
    DeviceName,
    AccountName,
    AccountDomain,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    SHA256
| sort by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Enterprise software installers that extract and run AutoIT scripts from AppData or ProgramData as part of legitimate installation workflows.
- IT automation or RMM tools that stage AutoIT scripts in ProgramData or temp directories during managed deployments.
- Developer workstations where AutoIT scripts are authored and tested from Downloads or AppData paths.

**Tuning notes:**
- After initial hunting run, identify legitimate AutoIT FolderPath values in your environment and add them as exclusions using where not (FolderPath startswith '<safe_path>').
- Combine this hunting query with the scheduled rule detection for AutoIT child process spawning to build a higher-confidence correlation.
- Consider pivoting on SHA256 values from results to identify whether the same AutoIT binary is executing across multiple endpoints, which is a stronger malicious signal.
- Restrict lookbackWindow to 1d during active incident response to reduce result volume.

**Risks / caveats:**
- DeviceProcessEvents requires Microsoft Defender for Endpoint onboarding on Windows endpoints with process creation telemetry enabled. If MDE is not deployed or process telemetry is disabled, the query returns no results.
- Path-based detection is easily evaded by adversaries who stage AutoIT binaries in non-suspicious directories.
- Legitimate enterprise AutoIT deployments from ProgramData or AppData paths will generate false positives until exclusions are baselined.
- The query does not distinguish between compiled AutoIT executables (.exe) and interpreted script execution, which may affect coverage depending on how the malicious AutoIT payload is delivered.

### Triage Runbook

**First 15 minutes:**
- Confirm the exact FolderPath and ProcessCommandLine to see whether AutoIT is executing from Temp, Downloads, AppData, ProgramData, or another user-writable location.
- Identify the user and parent process responsible for launching AutoIT3.exe and determine whether that source is expected.
- Check the SHA256 and file origin to see whether the binary was recently downloaded, dropped, or copied from an unusual location.
- Look for immediate follow-on behavior such as child process spawning, persistence creation, or outbound network connections.
- If the path is unusual and the execution is not tied to a known software install or admin workflow, escalate for deeper investigation.

**Evidence to collect:**
- Timestamp, DeviceName, AccountName, AccountDomain, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, SHA256.
- Process tree showing the parent process and any child processes spawned by AutoIT3.exe.
- File creation or download telemetry for the AutoIT binary or script on the endpoint.
- Network activity from the host around the execution time, especially outbound connections to unfamiliar destinations.
- Any user or helpdesk ticket that explains why AutoIT was executed from the observed path.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName, AccountName, or SHA256 to find repeated executions or related child processes.
- DeviceFileEvents to identify the source of the AutoIT binary or script and whether it was recently written to disk.
- DeviceNetworkEvents to determine whether the host communicated externally after execution.
- DeviceLogonEvents or identity logs to validate whether the account was actively logged in and expected to run the software.

**Benign explanations:**
- A legitimate installer or IT automation package staging AutoIT in ProgramData or AppData.
- A developer or tester running AutoIT scripts from Downloads or a working directory.
- A packaged enterprise application that extracts AutoIT components to a temporary folder during installation.

**Escalation criteria:**
- AutoIT executes from a suspicious path and is followed by child processes, persistence, or outbound connections.
- The file hash is unknown or malicious and the parent process is a browser, script host, or archive utility.
- The same path or hash appears on multiple hosts, suggesting a broader campaign.
- The execution is not explainable by a known software deployment, admin task, or user activity.

**Containment actions:**
- Isolate the host if the execution is accompanied by suspicious child processes, persistence, or network activity.
- Quarantine the AutoIT binary or script if it is confirmed malicious and still present on disk.
- Block the hash or related file path across the environment if the artifact is confirmed malicious.
- Disable or reset the user account if the execution appears to be tied to compromised credentials or unauthorized activity.

**Closure criteria:**
- The execution is validated as part of a known installation, automation, or testing workflow.
- The file path, parent process, and hash match approved enterprise behavior and no suspicious follow-on activity is found.
- The owning team confirms the AutoIT use case and the endpoint shows no additional indicators of compromise.
- Any suspicious artifacts are removed and the endpoint remains quiet after review.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- CVE-2026-16232 - Check Point SmartConsole Admin Login Followed by Policy Modification: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.
- CVE-2026-16232 - Unexpected Inbound Connection to Check Point Management Server Port: Environment-specific telemetry or field mapping must be resolved for Both: DeviceNetworkEvents before scheduling.

**Schema / correlation keys:**
- AutoIT Script Execution from Suspicious User-Writable Paths on Windows: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- DeviceProcessEvents: shared by AutoIT Process Injection - AutoIT3.exe Accessing Remote Process Memory on Windows; AutoIT Script Execution from Suspicious User-Writable Paths on Windows

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: AutoIT Process Injection - AutoIT3.exe Accessing Remote Process Memory on Windows.
2. Resolve environment-mapping detections next: CVE-2026-16232 - Check Point SmartConsole Admin Login Followed by Policy Modification; CVE-2026-16232 - Unexpected Inbound Connection to Check Point Management Server Port.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: AutoIT Script Execution from Suspicious User-Writable Paths on Windows.

### Hunting Agenda and Promotion Criteria

- AutoIT Script Execution from Suspicious User-Writable Paths on Windows: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- CVE-2026-16232 - Check Point SmartConsole Admin Login Followed by Policy Modification: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- CVE-2026-16232 - Unexpected Inbound Connection to Check Point Management Server Port: Environment-specific telemetry or field mapping must be resolved for Both: DeviceNetworkEvents before scheduling..

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
