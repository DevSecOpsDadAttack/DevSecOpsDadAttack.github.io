---
layout: post
title: "Detection Engineering Brief - Friday, October 2, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-10-02
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-76504
  - T1190
  - Cisco Catalyst SD-WAN Manager
  - ScreenConnect
  - T1059
  - T1059.001
  - T1059.003
  - T1071
  - T1071.001
---

## Detection Engineering Summary

This brief produced 3 detection candidates.

1 production candidate, 1 hunting-only, 1 require environment mapping, and 0 rejected.

3 detections include KQL. 3 include ATT&CK mappings. 3 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-76504, T1190, Cisco Catalyst SD-WAN Manager, ScreenConnect, T1059, T1059.001, T1059.003, T1071, T1071.001.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Cisco SD-WAN Manager API Auth Bypass - Unauthenticated Admin API Access (CVE-2026-76504); ScreenConnect Process Spawning Shell or Establishing Outbound Connection to Non-Corporate Relay.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Cisco SD-WAN Manager API Auth Bypass - Unauthenticated Admin API Access (CVE-2026-76504)

### Detection Opportunity

Unauthenticated crafted HTTP requests to SD-WAN Manager API endpoint returning success, followed by admin-level API activity from the same source IP with no prior authenticated session

### Intelligence Context

- Rapid7: Critical Cisco Catalyst SD-WAN Manager API authentication bypass exploited in the wild (CVE-2026-76504) — [https://www.rapid7.com/blog/post/etr-critical-cisco-catalyst-sd-wan-manager-api-authentication-bypass-exploited-in-the-wild-cve-2026-76504](https://www.rapid7.com/blog/post/etr-critical-cisco-catalyst-sd-wan-manager-api-authentication-bypass-exploited-in-the-wild-cve-2026-76504)
  - Context: An unauthenticated remote attacker sends a crafted HTTP request that bypasses an authentication rule for a specific API endpoint, gaining admin-level API access. Cisco confirmed active exploitation in the wild.

### Search Metadata

- CVEs: CVE-2026-76504
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Cisco Catalyst SD-WAN Manager
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-76504, T1190, Cisco Catalyst SD-WAN Manager

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
let lookback = 1h;
let adminWindow = 30m;
let sdwanVendor = "Cisco";
let sdwanProduct = "SD-WAN";
let apiPath = "/dataservice/";
let unauthRequests =
    CommonSecurityLog
    | where TimeGenerated >= ago(lookback)
    | where DeviceVendor has sdwanVendor and DeviceProduct has sdwanProduct
    | where RequestURL has apiPath
    | where tostring(ResponseCode) == "200"
    | where isempty(UserName) or UserName == "-"
    | where isnotempty(SourceIP)
    | summarize
        FirstUnauthRequest = min(TimeGenerated),
        RequestCount = count(),
        SampleRequestURL = any(RequestURL),
        DeviceProduct = any(DeviceProduct)
        by SourceIP;
let adminActivity =
    CommonSecurityLog
    | where TimeGenerated >= ago(lookback + adminWindow)
    | where DeviceVendor has sdwanVendor and DeviceProduct has sdwanProduct
    | where Activity has_any ("admin", "configuration", "write", "delete", "create")
    | where isnotempty(SourceIP)
    | summarize
        FirstAdminActivity = min(TimeGenerated),
        AdminActions = count(),
        Activity = any(Activity),
        UserName = any(UserName)
        by SourceIP;
unauthRequests
| join kind=inner adminActivity on SourceIP
| where FirstAdminActivity >= FirstUnauthRequest
| where FirstAdminActivity <= FirstUnauthRequest + adminWindow
| project
    SourceIP,
    FirstUnauthRequest,
    FirstAdminActivity,
    RequestCount,
    AdminActions,
    UserName,
    Activity,
    SampleRequestURL,
    DeviceProduct
| extend AlertDetail = strcat("Unauthenticated API request followed by admin activity from ", SourceIP)
| sort by FirstUnauthRequest desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Monitoring or health-check agents that poll /dataservice/ endpoints without authentication tokens and are followed by legitimate admin API calls from the same management host.
- Automated configuration management tools that use service accounts whose UserName field is not populated in syslog output.
- Environments where the SD-WAN Manager API gateway strips authentication headers before logging, causing all API calls to appear unauthenticated in CommonSecurityLog.

**Tuning notes:**
- Validate ResponseCode field type in your workspace with: CommonSecurityLog → where DeviceVendor has 'Cisco' → project ResponseCode, gettype(ResponseCode) → take 5
- Confirm Activity field values present in your SD-WAN Manager logs with: CommonSecurityLog → where DeviceVendor has 'Cisco' and DeviceProduct has 'SD-WAN' → summarize count() by Activity → sort by count_ desc
- Narrow apiPath to the specific vulnerable endpoint once Cisco publishes endpoint details in a follow-up advisory.
- Add an isnotempty(RequestURL) filter to the unauthRequests subquery if many log entries have null RequestURL values that inflate RequestCount.

**Risks / caveats:**
- CommonSecurityLog ingestion from Cisco SD-WAN Manager requires a syslog connector and CEF/syslog forwarding configuration on the appliance. If this connector is not deployed, the query returns no results.
- The Activity field in CommonSecurityLog is not guaranteed to be populated by Cisco SD-WAN Manager syslog output. If the appliance does not emit structured activity labels, the admin-activity subquery will return no results.
- ResponseCode in CommonSecurityLog is a string field in some Sentinel workspace configurations and an integer in others. The filter ResponseCode == 200 may need to be written as ResponseCode == '200' depending on the workspace schema version.
- The UserName field may not be populated for unauthenticated requests depending on how the SD-WAN Manager formats its syslog output, making the unauthenticated filter unreliable without validation.

### Triage Runbook

**First 15 minutes:**
- Confirm the alert is tied to the expected Cisco SD-WAN Manager host and not a misparsed syslog source or test environment.
- Review the SourceIP, FirstUnauthRequest, FirstAdminActivity, RequestCount, AdminActions, and SampleRequestURL to determine whether the sequence is consistent with exploitation.
- Check whether the same SourceIP has other recent requests to /dataservice/ or other management endpoints, especially repeated 200 responses without a valid UserName.
- Validate whether the admin activity occurred from a known management host, automation system, or maintenance window; if not, treat as likely malicious.
- Determine whether the activity is ongoing and whether additional suspicious admin actions followed the initial unauthenticated request.

**Evidence to collect:**
- Raw CommonSecurityLog entries for the SourceIP covering at least 1 hour before and after FirstUnauthRequest.
- All RequestURL values, ResponseCode values, UserName values, and Activity values associated with the SourceIP.
- Any Cisco SD-WAN Manager authentication, admin, or configuration logs that show whether a legitimate session existed.
- DeviceProduct and DeviceVendor values to confirm the log source is truly Cisco SD-WAN Manager.
- Change records or maintenance tickets for the management window to validate whether the activity was authorized.

**Pivot points:**
- CommonSecurityLog filtered to the same SourceIP and DeviceProduct for a wider time range.
- CommonSecurityLog entries for other SourceIP values hitting the same RequestURL or /dataservice/ path.
- Any available Cisco SD-WAN Manager audit, authentication, or configuration logs outside Sentinel.
- Incident timeline pivots on SourceIP and UserName to identify related activity across the environment.

**Benign explanations:**
- A legitimate monitoring or health-check system may poll /dataservice/ endpoints without a populated UserName and then trigger normal admin activity from the same host.
- An automation or configuration management tool may use a service account that is not populated in the syslog UserName field.
- Some environments log proxied or stripped authentication headers, making authenticated requests appear unauthenticated in CommonSecurityLog.

**Escalation criteria:**
- Escalate immediately if the SourceIP is external, unknown, or not associated with approved management infrastructure.
- Escalate if admin-level actions include configuration changes, account creation, deletion, or other write operations not tied to a change ticket.
- Escalate if there are multiple unauthenticated requests followed by repeated admin actions or evidence of lateral movement from the management plane.
- Escalate if the appliance shows signs of tampering, unexpected reboots, or loss of administrative visibility.

**Containment actions:**
- If exploitation appears likely, block the SourceIP at the perimeter or management access layer.
- Restrict access to the Cisco SD-WAN Manager interface to approved admin networks only until the incident is resolved.
- Preserve logs and configuration state before making changes that could overwrite evidence.
- If compromise is confirmed, rotate administrative credentials and review all recent configuration changes.

**Closure criteria:**
- The SourceIP is confirmed to be an approved internal management or monitoring system and the activity matches a documented change or maintenance task.
- No unauthorized admin actions are present, and the RequestURL/Activity sequence is explained by known appliance behavior or logging quirks.
- The alert is attributable to a validated false positive caused by syslog parsing, proxy behavior, or missing UserName population.
- Supporting logs show no additional suspicious activity from the SourceIP or the Cisco SD-WAN Manager host.

<br/>
---
<br/>

## Detection 2: Unauthorized ScreenConnect Client Installation on Endpoint

### Detection Opportunity

ScreenConnect client installer executed or dropped on an endpoint outside of authorized IT software deployment processes

### Intelligence Context

- SANS ISC: ScreenConnect Client (Ab)used by Attackers, (Thu, Oct 1st) — [https://isc.sans.edu/diary/rss/33388](https://isc.sans.edu/diary/rss/33388)
  - Context: Threat actors abused the legitimate ScreenConnect remote access application by installing unauthorized ScreenConnect clients on endpoints to establish remote sessions, without using complex malware.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.001, T1059.003, T1071, T1071.001
- Products: ScreenConnect
- Platforms: Not specified
- Malware: Not specified
- Tools: ScreenConnect
- Search tags: ScreenConnect, T1059, T1059.001, T1059.003, T1071, T1071.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: medium
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.001 PowerShell (high); Execution: T1059 Command and Scripting Interpreter/ T1059.003 Windows Command Shell (high); Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let screenconnectNames = dynamic(["ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe", "ScreenConnect.WindowsBackstageShell.exe", "ConnectWiseControl.ClientService.exe"]);
let suspiciousPaths = dynamic(["\\AppData\\", "\\Temp\\", "\\Downloads\\", "\\Users\\Public\\"]);
let fileDrops =
    DeviceFileEvents
    | where TimeGenerated >= ago(24h)
    | where ActionType in ("FileCreated", "FileRenamed")
    | where isnotempty(FolderPath)
    | where FileName has_any (screenconnectNames)
        or (FileName has "screenconnect" and FileName endswith ".exe")
        or (FileName has "connectwisecontrol" and FileName endswith ".exe")
    | where FolderPath has_any (suspiciousPaths)
    | project
        DeviceName,
        FileName,
        FolderPath,
        InitiatingProcessFileName,
        InitiatingProcessCommandLine,
        AccountName,
        FileDropTime = TimeGenerated,
        SHA256,
        FileReportId = ReportId;
let processExec =
    DeviceProcessEvents
    | where TimeGenerated >= ago(24h)
    | where isnotempty(FolderPath)
    | where FileName has_any (screenconnectNames)
        or ProcessCommandLine has_any (screenconnectNames)
        or (FileName has "screenconnect" and FileName endswith ".exe")
    | where FolderPath has_any (suspiciousPaths)
    | project
        DeviceName,
        FileName,
        ProcessCommandLine,
        InitiatingProcessFileName,
        AccountName,
        ExecTime = TimeGenerated,
        ProcReportId = ReportId;
fileDrops
| join kind=leftouter processExec on DeviceName, FileName
| where isnotempty(FileDropTime)
| project
    DeviceName,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ProcessCommandLine,
    AccountName,
    FileDropTime,
    ExecTime,
    SHA256,
    FileReportId,
    ProcReportId
| sort by FileDropTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- IT helpdesk staff who manually download and run ScreenConnect from their own user profile directories for ad-hoc support sessions.
- Endpoints enrolled in a ConnectWise-managed MSP program where the client is deployed via user-context installers rather than system-context MSI.
- Security testing or red team exercises using ScreenConnect as a C2 simulation tool in authorized engagements.

**Tuning notes:**
- After initial deployment, collect SHA256 values from authorized ScreenConnect installers and add an exclusion: → where SHA256 !in (knownGoodHashes)
- Add an InitiatingProcessFileName exclusion for authorized deployment tools such as msiexec.exe or your endpoint management agent if they appear in FP results.
- Extend screenconnectNames with any rebranded binary names discovered via: DeviceProcessEvents → where FileName has 'ScreenConnect' or FileName has 'ConnectWise' → summarize count() by FileName

**Risks / caveats:**
- The regex pattern in FileName matches regex requires the re2 engine available in Defender XDR Advanced Hunting. Confirm the regex syntax is accepted; if not, replace with FileName has 'screenconnect' and FileName endswith '.exe'.
- DeviceFileEvents ActionType must include 'FileCreated' or 'FileRenamed' events for the file drop to be visible. If MDE sensor policy filters these action types, file drops may not appear.
- Authorized IT deployments that use user-context installers landing in AppData will generate alerts until an allowlist of known-good SHA256 hashes or initiating process names is applied.
- The 24-hour lookback window may miss staged installers that were dropped earlier and executed later; consider extending to 48h for hunting runs.

### Triage Runbook

**First 15 minutes:**
- Identify the affected DeviceName and confirm whether the file drop and execution occurred in a user-writable path such as AppData, Temp, Downloads, or Public.
- Review FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName, and SHA256 to understand how the installer arrived.
- Check whether the same SHA256 or FileName is associated with approved IT support tooling or a known managed deployment process.
- Determine whether the process was executed after the drop and whether the initiating process was a browser, archive utility, script host, or other suspicious parent.
- Look for additional ScreenConnect-related files or processes on the same host to see whether this is a one-off install or part of a broader remote access foothold.

**Evidence to collect:**
- DeviceFileEvents and DeviceProcessEvents for the affected DeviceName covering at least 24 hours before and after the alert.
- The full file path, SHA256, and initiating process details for the ScreenConnect binary.
- Any related process command lines showing installation parameters, silent install flags, or user-context execution.
- User logon context for AccountName to determine whether the action was performed by a local user, helpdesk technician, or service account.
- Any endpoint management or IT support records showing an approved ScreenConnect deployment.

**Pivot points:**
- DeviceFileEvents for the same SHA256 across the environment to identify other hosts with the same installer.
- DeviceProcessEvents for the same FileName or ProcessCommandLine to find execution on other devices.
- DeviceNetworkEvents for the affected host to identify outbound connections associated with ScreenConnect activity.
- Endpoint management or software deployment logs to validate whether the installation was authorized.

**Benign explanations:**
- Helpdesk staff may manually install ScreenConnect from a user profile directory during an approved support session.
- Managed service provider deployments may place the client in user-writable paths as part of a legitimate support workflow.
- Security testing or red team exercises may intentionally deploy ScreenConnect in an authorized engagement.

**Escalation criteria:**
- Escalate if the installer is present in a user-writable directory and there is no approved deployment record.
- Escalate if the initiating process is a browser, script host, archive utility, or other suspicious parent not associated with IT tooling.
- Escalate if the same host shows additional remote access tools, suspicious persistence, or follow-on execution.
- Escalate if the SHA256 is unknown and the installation was performed by a non-IT user account.

**Containment actions:**
- If unauthorized installation is likely, isolate the endpoint from the network to prevent remote access.
- Remove or disable the unauthorized ScreenConnect client after preserving evidence.
- Block the installer hash and related file names in endpoint controls if confirmed malicious.
- Notify IT operations before removal if there is any chance the client is being used for legitimate support.

**Closure criteria:**
- The installation is matched to an approved IT deployment, helpdesk ticket, or managed service process.
- The SHA256 is confirmed as a known-good authorized installer and the parent process is expected.
- No execution, persistence, or suspicious network activity is observed beyond the approved install.
- The alert is attributable to a documented false positive pattern in the environment.

<br/>
---
<br/>

## Detection 3: ScreenConnect Process Spawning Shell or Establishing Outbound Connection to Non-Corporate Relay

### Detection Opportunity

ScreenConnect client process spawning cmd.exe or PowerShell as a child process, or initiating outbound network connections to relay infrastructure not associated with corporate IT

### Intelligence Context

- SANS ISC: ScreenConnect Client (Ab)used by Attackers, (Thu, Oct 1st) — [https://isc.sans.edu/diary/rss/33388](https://isc.sans.edu/diary/rss/33388)
  - Context: Attackers abused ScreenConnect to create unexpected remote sessions and used the tool to execute commands on victim endpoints, leveraging the legitimate application to avoid detection.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.001, T1059.003, T1071, T1071.001
- Products: ScreenConnect
- Platforms: Not specified
- Malware: Not specified
- Tools: ScreenConnect
- Search tags: ScreenConnect, T1059, T1059.001, T1059.003, T1071, T1071.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.001 PowerShell (high); Execution: T1059 Command and Scripting Interpreter/ T1059.003 Windows Command Shell (high); Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let scProcessNames = dynamic(["ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe", "ConnectWiseControl.ClientService.exe", "ScreenConnect.WindowsBackstageShell.exe"]);
let shellChildren = dynamic(["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"]);
let timeWindow = 15;
let shellSpawns =
    DeviceProcessEvents
    | where TimeGenerated >= ago(7d)
    | where InitiatingProcessFileName has_any (scProcessNames)
    | where FileName has_any (shellChildren)
    | project
        DeviceName,
        AccountName,
        ShellSpawnTime = TimeGenerated,
        ChildProcess = FileName,
        CommandLine = ProcessCommandLine,
        ParentProcess = InitiatingProcessFileName,
        ShellReportId = ReportId;
let outboundConns =
    DeviceNetworkEvents
    | where TimeGenerated >= ago(7d)
    | where InitiatingProcessFileName has_any (scProcessNames)
    | where RemotePort in (443, 8040, 8041)
    | where isnotempty(RemoteIP)
    | project
        DeviceName,
        ConnTime = TimeGenerated,
        RemoteIP,
        RemotePort,
        RemoteUrl,
        InitiatingProcess = InitiatingProcessFileName,
        NetReportId = ReportId;
shellSpawns
| join kind=leftouter outboundConns on DeviceName
| extend HasNetworkActivity = isnotempty(ConnTime)
| where not(HasNetworkActivity) or abs(datetime_diff('minute', ShellSpawnTime, ConnTime)) <= timeWindow
| project
    DeviceName,
    AccountName,
    ShellSpawnTime,
    ChildProcess,
    CommandLine,
    ParentProcess,
    ConnTime,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    HasNetworkActivity,
    ShellReportId,
    NetReportId
| sort by ShellSpawnTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate IT remote support sessions where the technician opens a command prompt on the endpoint via ScreenConnect, which will appear as cmd.exe spawned by ScreenConnect.
- Authorized ScreenConnect relay connections on port 443 to corporate relay servers will appear in the network subquery for every active session.
- Automated ScreenConnect maintenance tasks that invoke PowerShell for update or health-check scripts.

**Tuning notes:**
- To promote the shell spawn subquery to a scheduled rule, run it independently and baseline against known-good IT support sessions before scheduling.
- Add a RemoteIP exclusion for corporate relay servers once their IPs are inventoried: → where RemoteIP !in (corporateRelayIPs)
- Consider adding AccountName exclusions for known IT helpdesk accounts that routinely open shells via ScreenConnect.
- Reduce timeWindow from 15 to 5 minutes if the join produces too many unrelated network-to-shell pairings in high-activity environments.

**Risks / caveats:**
- DeviceNetworkEvents InitiatingProcessFileName may not be populated for all network events depending on MDE sensor version and OS. Validate field population before relying on it for the outbound connection subquery.
- The abs(datetime_diff('minute', ...)) pattern in the original join condition references ConnTime which may be null for devices with no network events in the window, causing the where clause to drop valid shell-spawn-only rows. The improved query handles this with a conditional filter.
- Without a corporate relay IP exclusion list applied to the outboundConns subquery, the network signal will match every legitimate ScreenConnect session on port 443, making the correlated results noisy.
- The shell spawn signal alone (rows where HasNetworkActivity is false) is high-fidelity and may warrant promotion to a standalone scheduled rule after FP baselining.

### Triage Runbook

**First 15 minutes:**
- Check whether the alert contains a shell spawn, a network connection, or both; prioritize rows where ScreenConnect spawned cmd.exe or PowerShell.
- Review DeviceName, AccountName, ShellSpawnTime, ChildProcess, CommandLine, ParentProcess, RemoteIP, RemotePort, and HasNetworkActivity for signs of interactive abuse.
- Validate whether the RemoteIP or RemoteUrl belongs to an approved corporate relay or known IT support infrastructure.
- Look for repeated shell launches, encoded commands, script execution, or suspicious child processes such as wscript.exe, cscript.exe, or mshta.exe.
- Determine whether the activity aligns with a known support session or whether the user account and timing are unexpected.

**Evidence to collect:**
- DeviceProcessEvents showing the full parent-child process chain for the ScreenConnect process.
- DeviceNetworkEvents for the same DeviceName to identify all remote destinations and ports used by ScreenConnect.
- Any ScreenConnect session logs or admin console records showing the remote operator identity and session timing.
- User logon and interactive session data for AccountName to determine whether the activity was user-initiated or remote-controlled.
- Any command lines, scripts, or downloaded files executed during the session.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and ParentProcess to find additional child processes spawned by ScreenConnect.
- DeviceNetworkEvents for the same DeviceName and time window to identify other outbound connections from the host.
- ScreenConnect server or relay logs, if available, to correlate session IDs and operator accounts.
- DeviceFileEvents for the same host to look for files dropped during the session.

**Benign explanations:**
- Legitimate IT support sessions often use ScreenConnect to open cmd.exe or PowerShell for troubleshooting.
- Authorized ScreenConnect relay traffic to corporate infrastructure will appear as normal outbound web traffic.
- Automated maintenance or update tasks may invoke PowerShell during a managed support session.

**Escalation criteria:**
- Escalate if the shell spawn occurs on a host not expected to receive remote support.
- Escalate if the RemoteIP or RemoteUrl is not in the approved relay list or is externally hosted and unknown.
- Escalate if commands indicate credential access, persistence, defense evasion, or data collection.
- Escalate if the session is associated with an unknown operator, unapproved account, or off-hours activity without a ticket.

**Containment actions:**
- If unauthorized remote access is suspected, terminate the ScreenConnect session and isolate the endpoint.
- Block the remote relay destination if it is confirmed to be non-corporate and malicious.
- Disable or reset the affected local account if command execution or credential abuse is confirmed.
- Preserve process and network evidence before remediation to support incident investigation.

**Closure criteria:**
- The shell activity is tied to a documented and approved support session with a known operator.
- The outbound connection is to an approved corporate relay or managed ScreenConnect infrastructure.
- No suspicious child processes, commands, or follow-on activity are present.
- The alert is explained by a validated maintenance workflow or known benign ScreenConnect behavior.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- Cisco SD-WAN Manager API Auth Bypass - Unauthenticated Admin API Access (CVE-2026-76504): Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Schema / correlation keys:**
- ScreenConnect Process Spawning Shell or Establishing Outbound Connection to Non-Corporate Relay: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- DeviceProcessEvents: shared by Unauthorized ScreenConnect Client Installation on Endpoint; ScreenConnect Process Spawning Shell or Establishing Outbound Connection to Non-Corporate Relay

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Unauthorized ScreenConnect Client Installation on Endpoint.
2. Resolve environment-mapping detections next: Cisco SD-WAN Manager API Auth Bypass - Unauthenticated Admin API Access (CVE-2026-76504).
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: ScreenConnect Process Spawning Shell or Establishing Outbound Connection to Non-Corporate Relay.

### Hunting Agenda and Promotion Criteria

- ScreenConnect Process Spawning Shell or Establishing Outbound Connection to Non-Corporate Relay: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Cisco SD-WAN Manager API Auth Bypass - Unauthenticated Admin API Access (CVE-2026-76504): Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
