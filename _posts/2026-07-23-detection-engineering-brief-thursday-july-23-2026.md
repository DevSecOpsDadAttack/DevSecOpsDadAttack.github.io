---
layout: post
title: "Detection Engineering Brief - Thursday, July 23, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-23
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - BitLocker
  - Windows
  - RMM tools
  - web shells
  - Project CAV3RN
  - Outlook
  - Microsoft Graph
  - Microsoft 365
  - DNS
  - T1190
  - WebDAV
  - T1505
  - T1505.003
  - T1071
  - T1071.004
  - T1059
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

3 production candidates, 2 hunting-only, 0 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: BitLocker, Windows, RMM tools, web shells, Project CAV3RN, Outlook, Microsoft Graph, Microsoft 365, DNS, T1190, WebDAV, T1505, T1505.003, T1071, T1071.004, T1059.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Project CAV3RN: Anomalous App Registration Making Repeated Outlook Calendar API Calls; Project CAV3RN: DNS AAAA Queries from Non-Browser Processes on IPv4-Only Endpoints.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: BitLocker Abused for Extortion via manage-bde.exe Outside IT Admin Context

### Detection Opportunity

Unauthorized BitLocker encryption initiated via manage-bde.exe as part of extortion intrusion

### Intelligence Context

- Securelist: A new extortion cocktail: office printers, small ransoms, and BitLocker — [https://securelist.com/new-extortion-scheme-printers-bitlocker/120718/](https://securelist.com/new-extortion-scheme-printers-bitlocker/120718/)
  - Context: Attackers abused BitLocker to encrypt victim systems for extortion, gaining access via RDP and deploying web shells and RMM tools before triggering encryption with manage-bde.exe.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1505, T1505.003
- Products: BitLocker
- Platforms: Windows
- Malware: Not specified
- Tools: RMM tools, web shells
- Search tags: BitLocker, Windows, RMM tools, web shells, T1505, T1505.003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1505 Server Software Component/ T1505.003 Web Shell (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceLogonEvents

### KQL

```kql
let lookback = 1h;
let rdp_logons = DeviceLogonEvents
| where Timestamp > ago(lookback)
| where LogonType == "RemoteInteractive"
| where isnotempty(RemoteIP)
| where not(ipv4_is_private(RemoteIP))
| project DeviceName, AccountName, RdpTime = Timestamp, RemoteIP;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName =~ "manage-bde.exe"
| where ProcessCommandLine has_any ("-on", "-protectors", "-encrypt")
| join kind=inner rdp_logons on DeviceName
| where InitiatingProcessAccountName =~ AccountName
| extend TimeDeltaMinutes = datetime_diff('minute', Timestamp, RdpTime)
| where TimeDeltaMinutes >= 0 and TimeDeltaMinutes <= 60
| project
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteIP,
    RdpTime,
    TimeDeltaMinutes
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- IT administrators who RDP from external IPs (e.g., via VPN split-tunnel where the RemoteIP appears external) and legitimately manage BitLocker.
- Automated BitLocker provisioning scripts run under accounts that also have external RDP sessions open on the same device.
- Jump server scenarios where an admin RDPs from an external IP to a management host and then manages BitLocker on that same host.

**Tuning notes:**
- Add a known IT admin account exclusion: → where InitiatingProcessAccountName !in~ ("bitlocker-svc", "it-admin") using your environment's actual service account names.
- Extend lookback to 4h or 24h if threat intelligence indicates longer dwell time between initial access and encryption in similar intrusions.
- Consider adding a threshold: if manage-bde.exe fires on more than 3 devices within the lookback window from the same RemoteIP, escalate severity.

**Risks / caveats:**
- ipv4_is_private() is a built-in KQL function available in Defender XDR and Sentinel; confirm it is supported in the target workspace version if query is ported.
- DeviceLogonEvents.RemoteIP may be empty for some RDP sessions depending on MDE sensor version and network configuration; validate field population in the target tenant before relying on external IP filtering.
- The 1-hour lookback window may miss intrusions with longer dwell time between initial RDP access and BitLocker activation; extend to 4h or 24h if attacker dwell time in the environment is known to be longer.
- Accounts used exclusively for BitLocker management that also have legitimate external RDP access should be added to an exclusion list to suppress recurring false positives.

### Triage Runbook

**First 15 minutes:**
- Confirm the account, host, and RDP source IP in the alert; verify whether the account is a known BitLocker admin or service account.
- Check whether the manage-bde.exe command line includes -on, -encrypt, or -protectors and whether the action is occurring on multiple hosts from the same source IP.
- Review the initiating process and parent process chain to see whether manage-bde.exe was launched from an interactive admin session, script, RMM tool, or suspicious shell.
- Look for concurrent signs of intrusion on the same host: new remote logons, web shell activity, RMM tool execution, privilege escalation, or unusual lateral movement.

**Evidence to collect:**
- DeviceProcessEvents for manage-bde.exe, parent process, command line, and account context.
- DeviceLogonEvents for the correlated RemoteInteractive logon, RemoteIP, and logon timing.
- Any recent process or file activity on the host indicating staging, script execution, or RMM usage.
- BitLocker status and recovery key handling for the affected device, including whether encryption was intentionally enabled.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and AccountName to find other suspicious processes launched near the alert time.
- DeviceLogonEvents for the same RemoteIP and AccountName to identify other devices accessed by the same source.
- DeviceFileEvents and DeviceNetworkEvents on the host to look for web shells, RMM tools, or staging activity preceding encryption.
- Entra ID sign-in logs or Defender XDR identity data to validate whether the account and source IP are expected.

**Benign explanations:**
- A legitimate IT administrator remotely enabling BitLocker during device provisioning or remediation.
- An automated provisioning or compliance script that uses manage-bde.exe under a managed admin account.
- A jump-host or VPN scenario where the RemoteIP appears external even though the session is legitimate.

**Escalation criteria:**
- The account is not a known admin or the source IP is not associated with approved IT access.
- manage-bde.exe is executed on multiple devices from the same source within a short period.
- There are additional intrusion indicators such as web shells, RMM tools, suspicious remote logons, or destructive activity.
- BitLocker is being enabled without a change ticket, maintenance window, or documented business justification.

**Containment actions:**
- Disable or reset the suspected account if unauthorized use is confirmed or strongly suspected.
- Isolate the affected endpoint if encryption is in progress or if there are signs of active compromise.
- Block the source IP or remote access path if it is clearly malicious and not shared with legitimate admins.
- Preserve recovery key and system state evidence before rebooting or making changes that could affect encryption status.

**Closure criteria:**
- The activity is confirmed as authorized IT administration with supporting change records and expected source IPs.
- No additional suspicious activity is found on the host or related devices.
- The account, source, and command line are consistent with normal BitLocker management patterns in the environment.
- Any false-positive source is documented and added to tuning or exclusion review.

<br/>
---
<br/>

## Detection 2: Web Shell Written to Web Root by Web Server Process

### Detection Opportunity

Web shell file created in web-accessible directory by a web server worker process as a persistence mechanism

### Intelligence Context

- Securelist: A new extortion cocktail: office printers, small ransoms, and BitLocker — [https://securelist.com/new-extortion-scheme-printers-bitlocker/120718/](https://securelist.com/new-extortion-scheme-printers-bitlocker/120718/)
  - Context: Attackers deployed web shells as a persistence mechanism during BitLocker extortion intrusions, using web server processes to write script files to web-accessible directories.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1505, T1505.003
- Products: web shells
- Platforms: Windows
- Malware: Not specified
- Tools: web shells
- Search tags: web shells, Windows, T1505, T1505.003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1505 Server Software Component/ T1505.003 Web Shell (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType in ("FileCreated", "FileModified")
| where InitiatingProcessFileName in~ (
    "w3wp.exe",
    "httpd.exe",
    "nginx.exe",
    "php-cgi.exe",
    "php.exe",
    "tomcat.exe",
    "java.exe",
    "python.exe",
    "perl.exe"
)
| where FileName has_any (
    ".asp",
    ".aspx",
    ".php",
    ".jsp",
    ".jspx",
    ".cfm",
    ".shtml"
)
| where FolderPath has_any (
    "\\inetpub\\",
    "\\wwwroot\\",
    "/var/www/",
    "/htdocs/",
    "/webapps/"
)
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    FileName,
    FolderPath,
    ActionType,
    SHA256
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate web application deployments where the web server process writes script files during application updates or plugin installations.
- Content management systems that use the web server process to write user-uploaded files including script-extension files.
- Java-based application servers (java.exe) writing JSP files as part of normal application compilation or hot-deploy workflows.

**Tuning notes:**
- Add environment-specific web root paths to the FolderPath filter after reviewing the actual web server configurations in the monitored environment.
- If java.exe generates excessive false positives, scope it further by adding InitiatingProcessCommandLine has 'catalina' or similar Tomcat-specific arguments.
- Consider adding a SHA256 lookup against threat intelligence after the projection to auto-enrich results with known web shell hashes.

**Risks / caveats:**
- DeviceFileEvents ActionType values 'FileCreated' and 'FileModified' are standard in MDE; confirm these exact strings are present in the tenant's schema as ActionType enumeration can vary by sensor version.
- java.exe as a web server initiating process is broad; Tomcat on Windows runs under java.exe but so do many other Java applications. This may require environment-specific scoping.
- Custom web root paths not matching the five standard paths in the FolderPath filter will produce no results for those deployments; add environment-specific web root paths after deployment.
- java.exe covers all Java processes, not only Tomcat; environments with non-web Java applications writing JSP or script files to web directories may see false positives.

### Triage Runbook

**First 15 minutes:**
- Inspect the file path, extension, and hash to confirm whether the file is in a true web root and whether it resembles a script or web shell.
- Review the initiating process name and command line to determine whether the write came from a normal deployment, plugin install, or an unusual worker process.
- Check whether the file was newly created or modified alongside other suspicious web root changes, especially multiple script files or unexpected timestamps.
- Look for evidence of web exploitation on the same host, including suspicious requests, new child processes from the web server, or recent authentication anomalies.

**Evidence to collect:**
- DeviceFileEvents for the created or modified file, including SHA256, folder path, and initiating process details.
- Any related DeviceProcessEvents showing the web server spawning shells, interpreters, or command execution.
- Web server logs or application logs showing the request that preceded the file write, if available.
- Threat intelligence or internal reputation results for the file hash and any related filenames.

**Pivot points:**
- DeviceFileEvents for the same DeviceName and FolderPath to find other files written by the same web server process.
- DeviceProcessEvents for child processes of the web server worker to identify command execution or script interpreter use.
- DeviceNetworkEvents for the host to look for inbound web traffic patterns or outbound callbacks after the file write.
- If available, web server or reverse proxy logs to identify the source IP and request path that triggered the write.

**Benign explanations:**
- A legitimate application deployment, hotfix, or plugin installation performed by the web server process.
- A content management system or framework that writes user-uploaded or generated script files as part of normal operation.
- A Java-based application server performing normal compilation or deployment of JSP content.

**Escalation criteria:**
- The file is a script or executable-like artifact in a web root and is not associated with a known deployment.
- The hash is unknown or malicious, or the file content matches common web shell patterns.
- The web server process also spawned suspicious child processes or there are signs of interactive attacker activity.
- Multiple web root files were created or modified in a short period without a change record.

**Containment actions:**
- Quarantine or remove the suspicious web shell only after preserving the file and hash for evidence.
- Disable or restrict the affected web application or virtual directory if active exploitation is suspected.
- Block suspicious inbound source IPs or temporarily place the server behind a maintenance page if operationally feasible.
- Rotate any credentials or secrets exposed to the web application if compromise is confirmed.

**Closure criteria:**
- The file is verified as a legitimate deployment artifact or application-generated file.
- No suspicious child processes, inbound exploit activity, or additional web root changes are found.
- The hash and path are documented for future allowlisting if appropriate.
- The host is otherwise clean and the event aligns with a known maintenance or deployment window.

<br/>
---
<br/>

## Detection 3: Project CAV3RN: Anomalous App Registration Making Repeated Outlook Calendar API Calls

### Detection Opportunity

Non-standard application or service principal making repeated Outlook calendar event create or read calls via Microsoft Graph API for C2 communication

### Intelligence Context

- Securelist: New Project CAV3RN module abuses Outlook calendar events for C2 and DNS AAAA records for configuration recovery — [https://securelist.com/project-cav3rn-cyberespionage-framework-using-outlook-and-dns/120757/](https://securelist.com/project-cav3rn-cyberespionage-framework-using-outlook-and-dns/120757/)
  - Context: Project CAV3RN malware uses Outlook calendar events via Microsoft Graph API as a C2 channel, with a backup configuration recovery mechanism using DNS AAAA record responses.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1071.004
- Products: Outlook, Microsoft Graph
- Platforms: Microsoft 365
- Malware: Project CAV3RN
- Tools: Not specified
- Search tags: Project CAV3RN, Outlook, Microsoft Graph, Microsoft 365, T1071, T1071.004

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.004 DNS (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- OperationName values in AuditLogs for Graph API calendar operations are not standardized as 'Create', 'Update', 'Get' in all tenants; the actual values depend on the audit log category and may appear as 'Add', 'Set', or resource-specific strings. Validate exact OperationName values in the target tenant before relying on this filter.

**Required telemetry:**
- AuditLogs

### KQL

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where ResultStatus == "Success"
| extend AppId = tostring(InitiatedBy.app.appId)
| extend UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
| extend ServicePrincipalId = tostring(InitiatedBy.app.servicePrincipalId)
| where isnotempty(AppId) and isempty(UserPrincipalName)
| mv-expand Resource = TargetResources
| extend ResourceType = tostring(Resource.type)
| extend ResourceDisplayName = tostring(Resource.displayName)
| where ResourceDisplayName has_any ("calendar", "event", "CalendarEvent") or ResourceType has_any ("calendar", "event")
| where OperationName has_any ("Create", "Update", "Get", "Add", "Set", "Delete")
| summarize
    CallCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    UniqueOperationTypes = dcount(OperationName),
    Operations = make_set(OperationName, 10)
    by AppId, ServicePrincipalId
| extend ActivitySpreadHours = datetime_diff('hour', LastSeen, FirstSeen)
| where CallCount > 20
| order by CallCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate calendar automation apps such as scheduling assistants, room booking systems, or meeting management tools that make high-frequency Graph API calendar calls.
- Microsoft first-party service principals that interact with calendar data on behalf of users.
- Third-party productivity integrations registered in the tenant that poll calendar events for synchronization.

**Tuning notes:**
- Run the query without the CallCount filter first to enumerate all service principals making any calendar API calls, then set the threshold based on observed distribution.
- Cross-reference AppId values in results against Entra ID app registrations using the Azure portal or Get-AzureADApplication to identify unknown or recently registered apps.
- Add known-legitimate calendar automation AppIds to an exclusion list once identified: → where AppId !in ("known-app-id-1", "known-app-id-2").
- Consider correlating high-frequency AppIds with sign-in logs to identify whether the service principal is authenticating from unexpected IP ranges or countries.

**Risks / caveats:**
- AuditLogs in Microsoft Sentinel requires the Microsoft 365 Unified Audit Log connector (via Diagnostic Settings or the Microsoft 365 connector) to be configured and ingesting data; if this connector is absent, the query returns no results.
- OperationName values in AuditLogs for Graph API calendar operations are not standardized as 'Create', 'Update', 'Get' in all tenants; the actual values depend on the audit log category and may appear as 'Add', 'Set', or resource-specific strings. Validate exact OperationName values in the target tenant before relying on this filter.
- InitiatedBy is a dynamic JSON object; tostring(InitiatedBy.app.appId) and tostring(InitiatedBy.user.userPrincipalName) require the JSON structure to match exactly. If the schema differs, these extractions return empty strings silently.
- OperationName values for Graph API calendar operations must be validated in the target tenant's AuditLogs before the filter is reliable; incorrect values will cause the query to return no results or miss the target behavior.

### Triage Runbook

**First 15 minutes:**
- Identify the AppId and service principal name, then verify whether it is a known enterprise app, vendor integration, or newly registered application.
- Review the call pattern: repeated calendar-related operations, sustained activity over time, and whether the app is acting without a user principal.
- Check the app registration details, permissions, consent grants, and owner to see whether the app has excessive Graph permissions.
- Look for related sign-in activity, unusual tenant-wide consent, or recent changes to the app registration around the first seen time.

**Evidence to collect:**
- AuditLogs entries for the AppId, operation names, and target resources involved in the calendar activity.
- Entra ID application registration details, including owners, permissions, and consent history.
- Sign-in logs or service principal sign-in records for the same AppId to identify source IPs, locations, and authentication patterns.
- Any related alerts or incidents involving the same app, tenant, or user accounts.

**Pivot points:**
- AuditLogs filtered to the same AppId or ServicePrincipalId to enumerate all operations and target resources.
- Entra ID app registration and enterprise application views to validate legitimacy and permission scope.
- Sign-in logs for the service principal to identify anomalous geographies, IPs, or authentication failures.
- Defender XDR incidents or alerts for the same host, user, or app to determine whether this is part of a broader intrusion.

**Benign explanations:**
- A legitimate scheduling, room booking, or meeting automation application.
- A third-party productivity integration that synchronizes calendar events at high frequency.
- A Microsoft first-party or approved enterprise service principal performing expected calendar operations.

**Escalation criteria:**
- The AppId is unknown, recently created, or lacks a clear business owner.
- The app has high-privilege Graph permissions that are not justified by its function.
- The activity pattern is sustained, repetitive, and not consistent with normal calendar automation.
- The app is associated with suspicious sign-in locations, consent abuse, or other intrusion indicators.

**Containment actions:**
- Disable the service principal or revoke its credentials if the app is confirmed malicious or unauthorized.
- Remove suspicious consent grants or reduce permissions if the app is over-privileged and under investigation.
- Block or restrict the app pending validation by the application owner and identity team.
- Preserve audit and sign-in evidence before making changes to the app registration.

**Closure criteria:**
- The app is validated as a known business application with a documented owner and purpose.
- The call pattern matches expected automation behavior and no other suspicious identity activity is present.
- Permissions and consent are appropriate for the app's function.
- Any recurring legitimate app is documented for tuning or allowlisting.

<br/>
---
<br/>

## Detection 4: Project CAV3RN: DNS AAAA Queries from Non-Browser Processes on IPv4-Only Endpoints

### Detection Opportunity

Non-browser process issuing DNS AAAA record queries as a backup C2 configuration recovery channel

### Intelligence Context

- Securelist: New Project CAV3RN module abuses Outlook calendar events for C2 and DNS AAAA records for configuration recovery — [https://securelist.com/project-cav3rn-cyberespionage-framework-using-outlook-and-dns/120757/](https://securelist.com/project-cav3rn-cyberespionage-framework-using-outlook-and-dns/120757/)
  - Context: Project CAV3RN uses DNS AAAA record responses as a backup channel for C2 configuration recovery, with non-browser processes issuing AAAA queries to attacker-controlled domains.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1071.004
- Products: Outlook, Microsoft Graph
- Platforms: Microsoft 365, DNS
- Malware: Project CAV3RN
- Tools: Not specified
- Search tags: Project CAV3RN, Outlook, Microsoft Graph, Microsoft 365, DNS, T1071, T1071.004

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.004 DNS (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
let browser_processes = dynamic(["chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe"]);
let system_processes = dynamic(["svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "MsMpEng.exe", "SenseIR.exe"]);
let graph_callers = DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has "graph.microsoft.com"
| where not(InitiatingProcessFileName in~ (browser_processes))
| where not(InitiatingProcessFileName in~ (system_processes))
| where isnotempty(InitiatingProcessFileName)
| distinct DeviceName, SuspectProcess = InitiatingProcessFileName;
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType == "ConnectionSuccess"
| where not(InitiatingProcessFileName in~ (browser_processes))
| where not(InitiatingProcessFileName in~ (system_processes))
| where isnotempty(InitiatingProcessFileName)
| where not(RemoteUrl has_any (
    "graph.microsoft.com",
    "login.microsoftonline.com",
    "microsoft.com",
    "windows.com",
    "windowsupdate.com"
))
| join kind=inner graph_callers on DeviceName
| where InitiatingProcessFileName =~ SuspectProcess
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    RemoteUrl,
    RemoteIP,
    ActionType
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate non-browser applications that use Microsoft Graph API such as desktop sync clients, Teams background processes, or enterprise management agents.
- Security tools and EDR agents that make Graph API calls for telemetry or policy retrieval.
- Custom enterprise applications built on Graph SDK that run as background services.

**Tuning notes:**
- After initial hunting runs, identify recurring legitimate non-browser Graph API callers and add their process names to the system_processes exclusion list.
- Narrow scope to high-value device groups such as executive endpoints or servers using → where DeviceName in (device_list) to reduce volume during initial investigation.
- Correlate DeviceName hits from this query with the CAV3RN calendar API hunting query to identify devices showing both signals simultaneously, which significantly increases confidence.

**Risks / caveats:**
- DeviceNetworkEvents does not expose DNS query record type (A vs AAAA) as a distinct field in the standard MDE schema; it is not possible to filter specifically for AAAA queries using this table alone. The detection approximates the behavior by correlating non-browser Graph API connections with other DNS-like network activity.
- ActionType 'DnsQueryResponse' is not a documented standard ActionType value in DeviceNetworkEvents; the documented values are 'ConnectionSuccess', 'ConnectionFailed', 'ConnectionFound', 'InboundConnectionAccepted', 'ListeningConnectionCreated'. Using an undocumented ActionType will cause the filter to match zero rows.
- AAAA-specific DNS query type cannot be distinguished from A queries using DeviceNetworkEvents alone; this query detects the dual-channel behavioral pattern (Graph API + other external connections from the same non-browser process) rather than AAAA queries specifically.
- Legitimate non-browser Graph API clients such as OneDrive sync, Teams service processes, or enterprise apps will appear in results and require analyst review to dismiss.

### Triage Runbook

**First 15 minutes:**
- Identify the process name, command line, and account context to determine whether it is a known enterprise application or an unusual binary.
- Check whether the same process also connects to graph.microsoft.com or other external destinations from the same device.
- Review whether the endpoint is expected to be IPv4-only and whether the process is a normal background service, sync client, or management agent.
- Look for related alerts, suspicious persistence, or recent execution from user-writable paths on the same host.

**Evidence to collect:**
- DeviceNetworkEvents for the process, including RemoteUrl, RemoteIP, and timing of connections.
- DeviceProcessEvents for the same process to capture parent process, command line, and execution path.
- Any available DNS telemetry from the environment if a separate DNS logging source exists.
- Host inventory data to confirm whether the endpoint should be IPv4-only and whether the process is approved.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceName and InitiatingProcessFileName to find other external destinations.
- DeviceProcessEvents for the same process name and command line to identify launch source and persistence.
- Defender XDR incidents and alerts for the host to see whether this is part of a broader intrusion chain.
- If available, DNS server logs or secure DNS logs to validate AAAA query behavior outside Defender telemetry.

**Benign explanations:**
- A legitimate non-browser application such as a sync client, collaboration tool, or enterprise agent using Microsoft Graph.
- A security or management agent that communicates with Microsoft services and external infrastructure as part of normal operation.
- A custom internal application that uses background network calls and is not browser-based.

**Escalation criteria:**
- The process is unknown, unsigned, or running from an unusual path such as a user profile or temp directory.
- The same process also shows suspicious external communications or persistence behavior.
- The host is not expected to run the application, or the account context is inconsistent with normal use.
- Multiple devices show the same unusual process pattern, suggesting coordinated activity.

**Containment actions:**
- Isolate the host if the process is unknown and there are additional signs of compromise.
- Terminate the suspicious process only after preserving process and network evidence if active malicious behavior is confirmed.
- Block the associated executable or hash if it is verified malicious.
- Escalate to identity and endpoint teams if the process appears tied to a broader campaign or lateral movement.

**Closure criteria:**
- The process is identified as a legitimate application or approved agent.
- No suspicious companion activity is found on the host or across related devices.
- The network pattern is explainable by normal application behavior and not a covert channel.
- Any recurring legitimate process is documented for tuning.

<br/>
---
<br/>

## Detection 5: WebDAV Remote Path Used to Initiate Process Execution on Windows Endpoint

### Detection Opportunity

Process execution initiated from a WebDAV-mounted remote path, consistent with malware delivery via exposed WebDAV infrastructure

### Intelligence Context

- Rapid7: From a Single Alert to 1,000 Files: Inside an Exposed WebDAV Malware Delivery Lab — [https://www.rapid7.com/blog/post/tr-exposed-webdav-malware-delivery-lab-analysis](https://www.rapid7.com/blog/post/tr-exposed-webdav-malware-delivery-lab-analysis)
  - Context: An exposed WebDAV server was used as a fully operational malware delivery lab where attackers systematically tested WebDAV execution methods to deliver payloads to Windows endpoints.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: WebDAV
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: T1190, WebDAV, Windows, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (low); Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let lookback = 1h;
let webdav_connections = DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has_any ("DavWWWRoot", "webdav", "@SSL")
    or (RemoteUrl matches regex @"^https?://[^/]+/" and ActionType == "ConnectionSuccess")
| project DeviceName, WebDavRemoteUrl = RemoteUrl, RemoteIP, WebDavTime = Timestamp;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where (
    ProcessCommandLine has_any ("DavWWWRoot", "\\\\webdav", "davclnt", "@SSL")
    or FolderPath has_any ("DavWWWRoot", "\\\\webdav")
)
| where FileName in~ (
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "msiexec.exe",
    "certutil.exe",
    "bitsadmin.exe"
)
| join kind=leftouter webdav_connections on DeviceName
| project
    Timestamp,
    DeviceName,
    FileName,
    ProcessCommandLine,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    SHA256,
    WebDavRemoteUrl,
    RemoteIP,
    WebDavTime
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- SharePoint or OneDrive mapped drives accessed via WebDAV where users or scripts execute files from the mapped drive path.
- Enterprise content management systems that mount WebDAV shares and execute scripts from them as part of normal workflow.
- IT automation tools that use WebDAV-mounted paths for script distribution and execution.

**Tuning notes:**
- After initial deployment, identify legitimate WebDAV hostnames in the environment (e.g., internal SharePoint URLs) and add them to a RemoteUrl exclusion filter in the network join subquery.
- If the rule generates volume from a specific initiating process (e.g., a deployment tool), add it to an InitiatingProcessFileName exclusion rather than removing the entire detection.
- Consider adding a SHA256 lookup against Microsoft Threat Intelligence or a custom watchlist of known-bad hashes to auto-escalate confirmed malicious payloads.

**Risks / caveats:**
- davclnt.dll is a DLL, not an executable; it will not appear as InitiatingProcessFileName in DeviceNetworkEvents since that field captures the process name, not loaded DLLs. The original query's use of davclnt.dll as an InitiatingProcessFileName filter in the network join was incorrect and has been removed.
- FolderPath in DeviceProcessEvents may not always be populated for processes executed from network paths depending on MDE sensor version; validate that DavWWWRoot paths appear in FolderPath in the target environment.
- FolderPath population for processes executed from network paths depends on MDE sensor behavior; if FolderPath is not populated for WebDAV-sourced processes, the FolderPath filter will not match and detection relies solely on ProcessCommandLine.
- Legitimate SharePoint or OneDrive WebDAV mapped drives will produce false positives if users execute scripts from those paths; known-good SharePoint hostnames should be excluded from RemoteUrl in the network join after baselining.

### Triage Runbook

**First 15 minutes:**
- Inspect the process name, command line, and folder path to confirm the executable or script was launched from a WebDAV path such as DavWWWRoot or a mapped remote share.
- Check the initiating process and account to see whether the execution came from a user action, automation, or a suspicious parent process like a script host or LOLBin.
- Review the correlated network event for the remote URL or IP to identify the WebDAV server and whether it is internal, approved, or external and unknown.
- Look for additional suspicious activity on the host, including downloads, script execution, or child processes spawned from the same remote path.

**Evidence to collect:**
- DeviceProcessEvents for the launched process, parent process, command line, folder path, and hash.
- DeviceNetworkEvents for the same device to identify the WebDAV server URL, IP, and connection timing.
- Any related file events showing payload staging or additional files executed from the same remote path.
- User and device context to determine whether the endpoint normally accesses WebDAV shares.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and FolderPath to find other executions from the WebDAV location.
- DeviceNetworkEvents for the same RemoteUrl or RemoteIP to identify other affected devices or repeated connections.
- DeviceFileEvents to look for files written to or copied from the same remote path.
- Defender XDR incidents and alerts for the host to determine whether this is part of a broader malware delivery chain.

**Benign explanations:**
- A legitimate SharePoint, OneDrive, or enterprise content share mounted via WebDAV and used for normal file execution.
- An IT automation or deployment workflow that stages scripts or installers from a WebDAV share.
- A user opening a file from a sanctioned remote document repository that happens to be WebDAV-backed.

**Escalation criteria:**
- The WebDAV server is external, unknown, or not associated with a sanctioned business service.
- The launched process is a script interpreter or LOLBin and the parent chain is suspicious.
- The same remote path is used to launch multiple suspicious processes or payloads.
- There are signs of malware delivery, persistence, or lateral movement on the endpoint.

**Containment actions:**
- Disconnect or isolate the endpoint if the WebDAV source is malicious or if execution is ongoing.
- Block access to the suspicious WebDAV server or remote path at the network layer if feasible.
- Quarantine the launched file or associated payload after preserving evidence.
- Reset credentials if the execution appears to have been triggered through compromised user access.

**Closure criteria:**
- The WebDAV source is confirmed as an approved internal service or business workflow.
- The executed process and parent chain are consistent with normal operations.
- No additional suspicious files, processes, or network activity are found.
- The remote URL or path is documented for future allowlisting if appropriate.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- Project CAV3RN: Anomalous App Registration Making Repeated Outlook Calendar API Calls: Do not schedule yet; validate as an analyst-led hunt first.
- Project CAV3RN: Anomalous App Registration Making Repeated Outlook Calendar API Calls: OperationName values in AuditLogs for Graph API calendar operations are not standardized as 'Create', 'Update', 'Get' in all tenants; the actual values depend on the audit log category and may appear as 'Add', 'Set', or resource-specific strings. Validate exact OperationName values in the target tenant before relying on this filter.
- Project CAV3RN: DNS AAAA Queries from Non-Browser Processes on IPv4-Only Endpoints: Do not schedule yet; validate as an analyst-led hunt first.

**Other deployment dependency:**
- WebDAV Remote Path Used to Initiate Process Execution on Windows Endpoint: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Shared-table notes:**
- DeviceProcessEvents: shared by BitLocker Abused for Extortion via manage-bde.exe Outside IT Admin Context; WebDAV Remote Path Used to Initiate Process Execution on Windows Endpoint
- DeviceNetworkEvents: shared by Project CAV3RN: DNS AAAA Queries from Non-Browser Processes on IPv4-Only Endpoints; WebDAV Remote Path Used to Initiate Process Execution on Windows Endpoint

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: BitLocker Abused for Extortion via manage-bde.exe Outside IT Admin Context; Web Shell Written to Web Root by Web Server Process; WebDAV Remote Path Used to Initiate Process Execution on Windows Endpoint.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Project CAV3RN: Anomalous App Registration Making Repeated Outlook Calendar API Calls; Project CAV3RN: DNS AAAA Queries from Non-Browser Processes on IPv4-Only Endpoints.

### Hunting Agenda and Promotion Criteria

- Project CAV3RN: Anomalous App Registration Making Repeated Outlook Calendar API Calls: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Project CAV3RN: DNS AAAA Queries from Non-Browser Processes on IPv4-Only Endpoints: Do not schedule yet; validate as an analyst-led hunt first..

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
