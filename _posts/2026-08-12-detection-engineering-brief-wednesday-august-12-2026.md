---
layout: post
title: "Detection Engineering Brief - Wednesday, August 12, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-08-12
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-63520
  - CVE-2026-55040
  - T1190
  - Microsoft SharePoint
  - Microsoft Project Server
  - Microsoft Office Web Apps Server
  - Windows
  - Microsoft DNS Server
  - T1059
  - T1068
  - T1087
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 4 hunting-only, 0 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-63520, CVE-2026-55040, T1190, Microsoft SharePoint, Microsoft Project Server, Microsoft Office Web Apps Server, Windows, Microsoft DNS Server, T1059, T1068, T1087.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: SharePoint RCE - Anomalous Child Process Spawned by w3wp.exe; SharePoint Auth Bypass - Privileged Operations from Unauthenticated or Anomalous Session Context; SharePoint RCE Chain - w3wp.exe Spawning Shells or Recon Tools; DNS Server RCE - Anomalous Child Process Spawned by dns.exe.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: SharePoint RCE - Anomalous Child Process Spawned by w3wp.exe

### Detection Opportunity

Unauthenticated remote code execution against vulnerable SharePoint servers producing unexpected child processes under the IIS worker process.

### Intelligence Context

- Rapid7: CVE-2026-63520: Microsoft SharePoint Remote Code Execution (FIXED) — [https://www.rapid7.com/blog/post/etr-cve-2026-63520-microsoft-sharepoint-remote-code-execution-fixed](https://www.rapid7.com/blog/post/etr-cve-2026-63520-microsoft-sharepoint-remote-code-execution-fixed)
  - Context: Rapid7 reported that CVE-2026-63520 and CVE-2026-55040 can be chained to achieve unauthenticated RCE against vulnerable SharePoint servers. Successful exploitation results in code execution under the SharePoint IIS worker process (w3wp.exe), making anomalous child process spawning the primary host-based detection signal.

### Search Metadata

- CVEs: CVE-2026-63520, CVE-2026-55040
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Microsoft SharePoint, Microsoft Project Server, Microsoft Office Web Apps Server
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-63520, CVE-2026-55040, T1190, Microsoft SharePoint, Microsoft Project Server, Microsoft Office Web Apps Server, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (medium); Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let suspicious_children = dynamic([
    "cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe",
    "mshta.exe", "certutil.exe", "bitsadmin.exe", "net.exe", "net1.exe",
    "whoami.exe", "nltest.exe", "rundll32.exe", "regsvr32.exe"
]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ (suspicious_children)
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    FileName,
    ProcessCommandLine
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate SharePoint administrative scripts executed via IIS application pools may spawn cmd.exe or powershell.exe during maintenance windows.
- Monitoring or backup agents running under IIS application pool identity may spawn certutil.exe or net.exe.
- Other IIS-hosted applications on the same host will trigger this rule if DeviceName is not scoped.

**Tuning notes:**
- Add a let-bound list of SharePoint server hostnames (e.g., let sharepoint_servers = dynamic(["sp-app01", "sp-app02"]);) and filter with → where DeviceName in~ (sharepoint_servers) to scope to SharePoint infrastructure.
- Alternatively, use a Defender device group tag and filter with → where DeviceName in (toscalar(DeviceInfo → where DeviceManualTags has "SharePoint" → summarize make_set(DeviceName))) for dynamic scoping.
- Extend the suspicious_children list with additional LOLBins relevant to your threat model (e.g., msiexec.exe, wmic.exe, curl.exe).

**Risks / caveats:**
- DeviceProcessEvents is only populated for devices onboarded to Microsoft Defender for Endpoint. SharePoint servers not onboarded will produce no results.
- Without scoping DeviceName to SharePoint server hosts, this query will match any IIS worker process across the entire Defender for Endpoint estate.
- Legitimate SharePoint farm maintenance tasks (timer jobs, health analyzer) may spawn powershell.exe or cmd.exe under w3wp.exe and require allowlisting after baseline review.
- The 7-day lookback may miss exploitation that occurred before Defender for Endpoint was onboarded on a given host.

### Triage Runbook

**First 15 minutes:**
- Confirm the alert is on a known SharePoint server and not another IIS-hosted application server.
- Review the child process name, command line, parent command line, and full process tree for the alerting event.
- Check whether the child process is a known maintenance or farm-management action versus a shell, scripting, or LOLBin execution.
- Look for additional suspicious activity on the same host in the same time window, especially network connections, file creation, scheduled task creation, or service changes.

**Evidence to collect:**
- DeviceProcessEvents for the alert window, including InitiatingProcessCommandLine, InitiatingProcessParentFileName, and any sibling processes from w3wp.exe.
- DeviceNetworkEvents for the same host and time range to identify inbound connections and outbound follow-on activity.
- Recent IIS/SharePoint logs or web access logs to identify the request path, source IP, and any suspicious POST/GET patterns.
- Any file writes, archive creation, or script drops in web directories or temp locations on the SharePoint server.

**Pivot points:**
- DeviceProcessEvents filtered to the host and a 24-hour window around the alert to find other w3wp.exe children.
- DeviceNetworkEvents for the host to identify remote IPs interacting with SharePoint ports 80/443.
- DeviceFileEvents for suspicious writes to web root, temp, or application pool directories.
- If available, IIS logs or SharePoint ULS logs to correlate the request that preceded the process spawn.

**Benign explanations:**
- Planned SharePoint maintenance or administrative automation may spawn cmd.exe or powershell.exe under w3wp.exe.
- Backup, monitoring, or certificate-management agents running under the application pool identity may launch certutil.exe or net.exe.
- The alert may fire on non-SharePoint IIS servers if the host scoping is not yet tuned.

**Escalation criteria:**
- The child process is a shell, scripting interpreter, or recon tool with no approved maintenance explanation.
- You find evidence of webshell behavior, suspicious file writes, or repeated child process spawning from w3wp.exe.
- Outbound connections, credential access, or lateral movement activity appear after the initial process spawn.
- The host is a production SharePoint server exposed to the internet and the event aligns with a recent exploit window.

**Containment actions:**
- Isolate the SharePoint server from the network if there is evidence of active exploitation or follow-on activity.
- Preserve volatile evidence before rebooting or patching, including process tree, network connections, and relevant logs.
- Disable or restrict external access to the affected SharePoint service until the host is validated and patched.
- Block the source IPs only if they are clearly malicious and you have confidence they are tied to the attack.

**Closure criteria:**
- The process is confirmed as a documented maintenance or monitoring action and no other suspicious activity is present.
- The host is not a SharePoint server and the alert is attributable to expected IIS activity on another application.
- No webshell, malicious file write, outbound beaconing, or additional suspicious child processes are found after review.
- The server is patched, scoped correctly, and baseline allowlists are updated for any approved child processes.

<br/>
---
<br/>

## Detection 2: SharePoint Auth Bypass - Privileged Operations from Unauthenticated or Anomalous Session Context

### Detection Opportunity

Remote unauthenticated attacker bypasses SharePoint JWT token authentication and performs operations as a SharePoint site user or administrator.

### Intelligence Context

- Rapid7: Rapid7 Analysis: Microsoft SharePoint JWT Token Authentication Bypass (CVE-2026-55040) — [https://www.rapid7.com/blog/post/ra-microsoft-sharepoint-jwt-token-authentication-bypass-cve-2026-55040](https://www.rapid7.com/blog/post/ra-microsoft-sharepoint-jwt-token-authentication-bypass-cve-2026-55040)
  - Context: Rapid7 published analysis and a proof-of-concept showing that CVE-2026-55040 allows a remote unauthenticated attacker to bypass SharePoint authentication via JWT token validation flaws, then perform privileged operations as a site user or administrator. The compound signal of privileged SharePoint operations from accounts with no prior successful authentication is the primary detection opportunity.

### Search Metadata

- CVEs: CVE-2026-55040
- Threat actors: Not specified
- ATT&CK tags: T1190, T1068
- Products: Microsoft SharePoint
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-55040, T1190, Microsoft SharePoint, T1068

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Privilege Escalation: T1068 Exploitation for Privilege Escalation (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- The Microsoft 365 audit log connector must be enabled in Sentinel for OfficeActivity to be populated.
- The Entra ID diagnostic settings connector must be enabled in Sentinel for SigninLogs to be populated.

**Required telemetry:**
- OfficeActivity, SigninLogs

### KQL

```kql
let privileged_ops = dynamic([
    "SiteCollectionAdminAdded", "PermissionLevelAdded", "PermissionLevelModified",
    "AddedToGroup", "FileDeleted", "SiteAdminChangeRequest", "ListItemsViewed"
]);
let lookback = 30m;
let query_window = 7d;
let sp_events = OfficeActivity
| where TimeGenerated > ago(query_window)
| where OfficeWorkload == "SharePoint"
| where Operation in (privileged_ops)
| project EventTime = TimeGenerated, Actor = UserId, SourceIP = ClientIP, Operation, ResultStatus;
let signin_events = SigninLogs
| where TimeGenerated > ago(query_window)
| where ResultType == "0"
| project SigninTime = TimeGenerated, UserPrincipalName, SigninIP = IPAddress;
sp_events
| join kind=leftouter (
    signin_events
) on $left.Actor == $right.UserPrincipalName and $left.SourceIP == $right.SigninIP
| where isnull(SigninTime) or (EventTime < SigninTime) or (EventTime > SigninTime + lookback)
| project
    TimeGenerated = EventTime,
    Actor,
    SourceIP,
    Operation,
    ResultStatus,
    MatchedSigninTime = SigninTime,
    MatchedSigninIP = SigninIP
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Service principals and managed identities performing SharePoint operations will not have matching SigninLogs entries and will appear as false positives.
- Users authenticating via legacy authentication protocols or pass-through authentication may not generate SigninLogs entries matching the ClientIP used in OfficeActivity.
- Legitimate newly promoted SharePoint administrators performing their first admin operation may trigger this rule.

**Tuning notes:**
- Add → where ResultStatus == "Succeeded" to the OfficeActivity filter to reduce noise from failed privileged operation attempts.
- Exclude known service account UPNs with → where Actor !in (dynamic(["svc-sharepoint@contoso.com"])) after confirming the list in your environment.
- Adjust the lookback variable from 30m to match observed authentication-to-action latency in your tenant.
- Consider adding AppDisplayName filtering in SigninLogs (e.g., where AppDisplayName has "SharePoint") to restrict sign-in matching to SharePoint-specific authentication events.

**Risks / caveats:**
- OfficeActivity covers SharePoint Online only. On-premises SharePoint audit events are not forwarded to this table by default and require a separate connector or log forwarding configuration.
- SigninLogs covers Entra ID (Azure AD) authentication only. On-premises SharePoint authentication against Active Directory Federation Services or local Windows authentication does not appear in SigninLogs.
- The Microsoft 365 audit log connector must be enabled in Sentinel for OfficeActivity to be populated.
- The Entra ID diagnostic settings connector must be enabled in Sentinel for SigninLogs to be populated.

### Triage Runbook

**First 15 minutes:**
- Validate the affected operation, actor, source IP, and whether the event is on SharePoint Online or an on-premises-connected telemetry source.
- Check whether the actor has a matching successful sign-in from the same IP and within the expected time window.
- Review the operation type to see if it is truly privileged, such as admin assignment, permission changes, or deletion actions.
- Look for a burst of related SharePoint operations from the same actor or IP that would indicate active abuse of the session.

**Evidence to collect:**
- OfficeActivity records for the actor across the alert window and surrounding 24 hours.
- SigninLogs for the same user, IP, and time range, including success/failure, app name, and authentication method.
- Any available SharePoint audit or ULS logs to confirm the operation source and session context.
- Change records or admin approvals that explain why the operation should have occurred.

**Pivot points:**
- OfficeActivity filtered by UserId, ClientIP, and privileged operations over the last 24 hours.
- SigninLogs for the same UserPrincipalName and IPAddress to verify whether the session was authenticated as expected.
- Entra ID audit logs for role or permission changes involving the same account.
- If available, SharePoint admin center or tenant audit logs for corroborating administrative actions.

**Benign explanations:**
- Service accounts, managed identities, or OAuth-based automation may perform SharePoint actions without a matching interactive sign-in.
- Federated or SSO environments may place the authentication evidence in another identity provider log rather than SigninLogs.
- A legitimate admin may be performing a first-time or rare administrative action that has no recent sign-in correlation.

**Escalation criteria:**
- The operation is privileged and there is no credible matching sign-in or approved automation explanation.
- Multiple admin-level actions occur from the same actor or IP in a short period.
- The actor performs permission changes, site admin changes, or deletion actions that are not expected.
- You observe additional suspicious identity activity, such as role changes, token abuse, or repeated failed sign-in attempts.

**Containment actions:**
- Disable or reset the affected account if unauthorized activity is confirmed or strongly suspected.
- Revoke active sessions and refresh tokens for the account to stop continued access.
- Restrict SharePoint administrative actions temporarily if the environment shows ongoing abuse.
- Preserve audit evidence before making account changes when possible.

**Closure criteria:**
- A valid sign-in and approved change record explain the operation.
- The activity is attributable to a known service account, automation, or federated identity flow.
- No additional suspicious SharePoint or identity activity is present after correlation.
- The account and source IP are documented and added to tuning/allowlist logic if appropriate.

<br/>
---
<br/>

## Detection 3: SharePoint - Privileged Admin Operations from Accounts with No Baseline Admin Activity

### Detection Opportunity

Attacker acting as a SharePoint site administrator performs privileged operations after authentication bypass, with no prior history of admin-level SharePoint activity for that account.

### Intelligence Context

- Rapid7: Rapid7 Analysis: Microsoft SharePoint JWT Token Authentication Bypass (CVE-2026-55040) — [https://www.rapid7.com/blog/post/ra-microsoft-sharepoint-jwt-token-authentication-bypass-cve-2026-55040](https://www.rapid7.com/blog/post/ra-microsoft-sharepoint-jwt-token-authentication-bypass-cve-2026-55040)
  - Context: Rapid7 confirmed that CVE-2026-55040 allows an attacker to impersonate any SharePoint site user or administrator. Accounts performing privileged SharePoint admin operations with no historical baseline of such activity represent a high-fidelity signal for impersonation via the auth bypass.

### Search Metadata

- CVEs: CVE-2026-55040
- Threat actors: Not specified
- ATT&CK tags: T1190, T1068
- Products: Microsoft SharePoint
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-55040, T1190, Microsoft SharePoint, T1068

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Privilege Escalation: T1068 Exploitation for Privilege Escalation (medium)

### Deployment Gates

- The Microsoft 365 audit log connector must be enabled in Sentinel for OfficeActivity to be populated.

**Required telemetry:**
- OfficeActivity

### KQL

```kql
let admin_ops = dynamic([
    "SiteCollectionAdminAdded", "PermissionLevelAdded", "PermissionLevelModified",
    "AddedToGroup", "SiteAdminChangeRequest"
]);
let baseline_window = 30d;
let detection_window = 1d;
let known_admins = OfficeActivity
    | where TimeGenerated between (ago(baseline_window) .. ago(detection_window))
    | where OfficeWorkload == "SharePoint"
    | where Operation in (admin_ops)
    | where ResultStatus == "Succeeded"
    | summarize by UserId;
OfficeActivity
| where TimeGenerated > ago(detection_window)
| where OfficeWorkload == "SharePoint"
| where Operation in (admin_ops)
| where ResultStatus == "Succeeded"
| where UserId !in (known_admins)
| project
    TimeGenerated,
    UserId,
    ClientIP,
    Operation,
    ResultStatus
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Newly onboarded or promoted SharePoint administrators with no prior admin history in the 30-day baseline window.
- Accounts that performed admin operations infrequently and whose last admin action falls outside the 30-day baseline window.
- Automated provisioning or migration service accounts performing one-time admin operations.

**Tuning notes:**
- Extend baseline_window to 60d or 90d if SharePoint admin activity is infrequent in your tenant to reduce false positives from legitimate admins who act rarely.
- Add → where UserId !endswith "#ext#" to exclude guest accounts if guest admin operations are expected and not of interest.
- Cross-reference flagged UserId values against Entra ID group membership for SharePoint admin roles to quickly triage legitimate promotions.

**Risks / caveats:**
- OfficeActivity covers SharePoint Online only. On-premises SharePoint audit events are not forwarded to this table by default and require a separate connector or log forwarding configuration.
- The Microsoft 365 audit log connector must be enabled in Sentinel for OfficeActivity to be populated.
- If the Sentinel workspace has less than 30 days of OfficeActivity retention, the baseline query will be incomplete and known_admins will be underpopulated, increasing false positives.
- The 30-day baseline window may be insufficient in environments with low admin activity frequency; extending to 60 or 90 days reduces false positives from infrequent legitimate admins.

### Triage Runbook

**First 15 minutes:**
- Confirm the account identity and whether it is supposed to have SharePoint admin privileges.
- Check HR, IAM, or change-management records for a recent role assignment or promotion.
- Review the exact privileged operations and whether they match a legitimate onboarding, migration, or maintenance task.
- Look for other activity from the same account or IP that suggests broader compromise, such as multiple admin actions or unusual sign-in patterns.

**Evidence to collect:**
- OfficeActivity for the account over the baseline and detection windows to see the full admin history.
- Entra ID role assignment or group membership changes for the account.
- SigninLogs for the account to identify source IPs, device patterns, and authentication methods.
- Change-management tickets or provisioning records that justify the new admin behavior.

**Pivot points:**
- OfficeActivity summarized by UserId and Operation over 30-90 days to establish whether the account has any prior admin history.
- Entra ID audit logs for role assignment, group membership, or privileged access changes involving the account.
- SigninLogs for the account to identify unusual geolocation, device, or IP changes.
- If available, mailbox or ticketing records for approval of the admin action.

**Benign explanations:**
- The account was newly promoted to SharePoint admin and is legitimately performing first-time admin tasks.
- The account is a migration or provisioning service account used for one-time administrative work.
- The baseline window is too short and missed older legitimate admin activity.

**Escalation criteria:**
- The account is not approved for SharePoint administration and no change record exists.
- The account shows additional suspicious sign-ins, impossible travel, or unfamiliar source IPs.
- The admin actions include permission changes, site collection admin changes, or deletions that are not business-justified.
- Multiple accounts begin showing first-time admin behavior around the same time, suggesting coordinated abuse.

**Containment actions:**
- Disable the account or revoke sessions if the activity is unauthorized or cannot be quickly explained.
- Remove unexpected SharePoint admin role assignments if confirmed malicious.
- Escalate to identity and platform owners to review whether other accounts were similarly affected.
- Preserve audit logs and role-change evidence before making changes when feasible.

**Closure criteria:**
- A documented role change or approved task explains the first-time admin activity.
- The account is a known service or migration identity with validated purpose.
- No other suspicious identity or SharePoint actions are found during the investigation window.
- The account is added to tuning exceptions only after validation by the platform owner.

<br/>
---
<br/>

## Detection 4: SharePoint RCE Chain - w3wp.exe Spawning Shells or Recon Tools

### Detection Opportunity

SharePoint critical RCE chain exploitation producing anomalous process execution under the IIS worker process on SharePoint server hosts.

### Intelligence Context

- Rapid7: Patch Tuesday - August 2026 — [https://www.rapid7.com/blog/post/em-patch-tuesday-august-2026](https://www.rapid7.com/blog/post/em-patch-tuesday-august-2026)
  - Context: Rapid7's August 2026 Patch Tuesday coverage highlighted a critical SharePoint RCE chain discovered by Rapid7 researchers. Successful exploitation of the chain results in code execution on the SharePoint server host, detectable via anomalous child processes under w3wp.exe correlated with inbound network connections to SharePoint ports.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1087, T1190
- Products: Microsoft SharePoint
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Microsoft SharePoint, Windows, T1059, T1087, T1190

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (high); Discovery: T1087 Account Discovery (medium); Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let suspicious_children = dynamic([
    "cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe",
    "mshta.exe", "certutil.exe", "whoami.exe", "net.exe", "net1.exe",
    "nltest.exe", "bitsadmin.exe", "rundll32.exe", "regsvr32.exe"
]);
let rce_procs = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName =~ "w3wp.exe"
    | where FileName in~ (suspicious_children)
    | project
        ProcTime = Timestamp,
        DeviceName,
        AccountName,
        InitiatingProcessFileName,
        InitiatingProcessCommandLine,
        InitiatingProcessParentFileName,
        FileName,
        ProcessCommandLine;
let inbound_http = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where ActionType == "InboundConnectionAccepted"
    | where LocalPort in (80, 443)
    | project NetTime = Timestamp, DeviceName, RemoteIP;
rce_procs
| join kind=inner inbound_http on DeviceName
| where ProcTime between (NetTime .. NetTime + 5m)
| project
    ProcTime,
    NetTime,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    FileName,
    ProcessCommandLine,
    RemoteIP
| order by ProcTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Scheduled IIS health checks or monitoring agents that trigger inbound connections followed by legitimate w3wp.exe child process spawning during maintenance windows.
- Load balancer health probes on port 80/443 coinciding with legitimate administrative powershell.exe or cmd.exe spawning under w3wp.exe.
- Other IIS-hosted applications on the same host if DeviceName is not scoped to SharePoint servers.

**Tuning notes:**
- Add a let-bound list of SharePoint server hostnames and filter both subqueries with → where DeviceName in~ (sharepoint_servers) to scope to SharePoint infrastructure.
- Adjust the 5m correlation window based on observed exploitation timing or reduce it to 2m to increase precision.
- Consider adding LocalIP to the DeviceNetworkEvents projection and filtering on known SharePoint server IP addresses as an additional scoping mechanism.

**Risks / caveats:**
- DeviceProcessEvents and DeviceNetworkEvents are only populated for devices onboarded to Microsoft Defender for Endpoint. SharePoint servers not onboarded will produce no results.
- InboundConnectionAccepted ActionType availability in DeviceNetworkEvents depends on the Defender for Endpoint sensor configuration and Windows Firewall audit settings on the host; this ActionType may not be present on all onboarded devices.
- Without scoping DeviceName to SharePoint server hosts, this query will match any IIS server in the Defender for Endpoint estate.
- The 5-minute correlation window between inbound connection and process spawn is a starting point; exploitation timing may vary and the window may need adjustment.

### Triage Runbook

**First 15 minutes:**
- Verify the host is a SharePoint server and identify the exact child process and command line.
- Check whether the process is a shell, scripting interpreter, or recon utility such as whoami.exe or nltest.exe.
- Correlate the process spawn with inbound HTTP/HTTPS activity to the server around the same time.
- Look for follow-on actions such as additional process creation, file writes, or outbound connections from the same host.

**Evidence to collect:**
- DeviceProcessEvents for the host, including the full ancestry of the suspicious child process.
- DeviceNetworkEvents for inbound connections on ports 80/443 and any outbound connections after the alert.
- DeviceFileEvents for dropped scripts, webshells, or temporary files on the SharePoint server.
- IIS or SharePoint logs showing the request that preceded the process spawn.

**Pivot points:**
- DeviceProcessEvents for all w3wp.exe children on the host during the last 24 hours.
- DeviceNetworkEvents filtered to the host and local ports 80/443 to identify the source IP of the inbound request.
- DeviceFileEvents for recent writes to web directories, temp folders, or application pool paths.
- If available, Windows Event Logs or IIS logs to correlate request timing with process creation.

**Benign explanations:**
- Legitimate SharePoint maintenance or health-check activity may spawn administrative shells during approved windows.
- Monitoring, backup, or certificate tasks may use cmd.exe, powershell.exe, or certutil.exe under the application pool identity.
- The host may be another IIS server if the environment is not yet scoped to SharePoint infrastructure.

**Escalation criteria:**
- The child process is a shell, scripting tool, or recon utility with no approved maintenance explanation.
- You find evidence of webshells, suspicious file writes, or repeated process spawning from w3wp.exe.
- Inbound traffic from an external source aligns with the process spawn and is followed by additional suspicious activity.
- The host shows signs of lateral movement, credential access, or persistence after the initial execution.

**Containment actions:**
- Isolate the SharePoint server if there is evidence of active exploitation or post-exploitation activity.
- Preserve process, network, and web log evidence before remediation.
- Temporarily restrict external access to the SharePoint service until the host is validated and patched.
- Block clearly malicious source IPs if they are confirmed to be part of the attack.

**Closure criteria:**
- The process is confirmed as approved maintenance or monitoring activity.
- No webshell, malicious file write, or outbound follow-on activity is found.
- The host is patched and scoped correctly, and any approved child processes are documented.
- The alert is attributable to a non-SharePoint IIS server or benign administrative action.

<br/>
---
<br/>

## Detection 5: DNS Server RCE - Anomalous Child Process Spawned by dns.exe

### Detection Opportunity

Critical Windows DNS Server RCE vulnerability exploitation producing unexpected child processes under the DNS server process.

### Intelligence Context

- SANS ISC: Microsoft Patch Tuesday August 2026, (Tue, Aug 11th) — [https://isc.sans.edu/diary/rss/33236](https://isc.sans.edu/diary/rss/33236)
  - Context: SANS ISC reported that the August 2026 Patch Tuesday included critical RCE vulnerabilities in the Windows DNS Server. Successful exploitation of a DNS Server RCE would result in code execution under the dns.exe process, making anomalous child process spawning the primary host-based detection signal on Windows DNS server infrastructure.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1190
- Products: Microsoft DNS Server
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Microsoft DNS Server, Windows, T1059, T1190

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (high); Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let suspicious_children = dynamic([
    "cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe",
    "mshta.exe", "certutil.exe", "whoami.exe", "net.exe", "net1.exe",
    "nltest.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe"
]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "dns.exe"
| where FileName in~ (suspicious_children)
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    FileName,
    ProcessCommandLine
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate DNS server management scripts executed in the context of the DNS Server service during maintenance may spawn cmd.exe or powershell.exe; these should be rare and warrant investigation regardless.
- Monitoring or backup agents that inject into or spawn from dns.exe on DNS server hosts.

**Tuning notes:**
- Add a let-bound list of DNS server hostnames (e.g., let dns_servers = dynamic(["dc01", "dns-srv01"]);) and filter with → where DeviceName in~ (dns_servers) to scope to DNS server infrastructure.
- Alternatively, use DeviceInfo to dynamically identify DNS servers: join with DeviceInfo → where OSPlatform == "Windows" and DeviceType == "Server" to pre-filter, though this does not confirm the DNS Server role is installed.
- Given the extremely low false-positive rate expected for dns.exe spawning shells, this detection is a strong candidate for promotion to a scheduled alert rule once DeviceName scoping is applied.

**Risks / caveats:**
- DeviceProcessEvents is only populated for devices onboarded to Microsoft Defender for Endpoint. Windows DNS servers not onboarded will produce no results.
- dns.exe as a server process runs only on Windows Server with the DNS Server role installed; however, the query does not filter on OS type or device role, so scoping is required to avoid matching unrelated processes named dns.exe on non-DNS hosts.
- Without scoping DeviceName to Windows DNS server hosts, the query may match non-DNS Windows servers if any process named dns.exe exists outside the DNS Server role.
- The 7-day lookback may miss exploitation that occurred before Defender for Endpoint was onboarded on a given DNS server host.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a Windows DNS server and not another server with an unrelated dns.exe process.
- Review the child process name, command line, and parent process ancestry for the alerting event.
- Check whether the child process is a shell, scripting interpreter, or recon tool and whether it is expected on a DNS server.
- Look for additional suspicious activity on the host, including outbound connections, service changes, or new persistence mechanisms.

**Evidence to collect:**
- DeviceProcessEvents for the DNS server around the alert time, including full process ancestry.
- DeviceNetworkEvents for the same host to identify outbound connections after the process spawn.
- Windows Event Logs or DNS server logs for service errors, restarts, or suspicious query patterns.
- Any file creation or modification events in system or temp locations on the DNS server.

**Pivot points:**
- DeviceProcessEvents filtered to the host and dns.exe children over the last 24 hours.
- DeviceNetworkEvents for the host to identify unusual outbound traffic after the alert.
- DeviceFileEvents for recent writes to system directories, temp folders, or DNS-related paths.
- If available, DNS server operational logs and Windows security logs for service or account anomalies.

**Benign explanations:**
- Rare DNS server maintenance or troubleshooting activity may spawn cmd.exe or powershell.exe under the service context.
- Monitoring or backup agents may inject into or spawn from dns.exe on managed servers.
- The alert may be caused by a non-DNS host if the environment has not been scoped to DNS server infrastructure.

**Escalation criteria:**
- The child process is a shell, scripting interpreter, or recon tool with no approved maintenance explanation.
- You observe outbound connections, file drops, or persistence activity after the dns.exe child spawn.
- The DNS service crashes, restarts, or behaves abnormally around the same time as the alert.
- Multiple suspicious child processes or repeated execution attempts occur on the same host.

**Containment actions:**
- Isolate the DNS server if exploitation or post-exploitation activity is confirmed or strongly suspected.
- Preserve volatile evidence and DNS logs before rebooting or remediating the host.
- Restrict external access to the DNS service if the server is internet-facing or exposed through forwarding.
- Coordinate with infrastructure owners before service disruption, but do not delay containment if active compromise is evident.

**Closure criteria:**
- The process is confirmed as a documented maintenance or monitoring action and no other suspicious activity is present.
- The host is not a DNS server and the alert is attributable to unrelated process naming or mis-scoping.
- No follow-on network, file, or persistence activity is found after investigation.
- The server is patched, scoped correctly, and any approved exceptions are documented.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- SharePoint RCE - Anomalous Child Process Spawned by w3wp.exe: Do not schedule yet; validate as an analyst-led hunt first.
- SharePoint Auth Bypass - Privileged Operations from Unauthenticated or Anomalous Session Context: Do not schedule yet; validate as an analyst-led hunt first.
- SharePoint RCE Chain - w3wp.exe Spawning Shells or Recon Tools: Do not schedule yet; validate as an analyst-led hunt first.
- DNS Server RCE - Anomalous Child Process Spawned by dns.exe: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- SharePoint Auth Bypass - Privileged Operations from Unauthenticated or Anomalous Session Context: The Microsoft 365 audit log connector must be enabled in Sentinel for OfficeActivity to be populated.
- SharePoint Auth Bypass - Privileged Operations from Unauthenticated or Anomalous Session Context: The Entra ID diagnostic settings connector must be enabled in Sentinel for SigninLogs to be populated.
- SharePoint - Privileged Admin Operations from Accounts with No Baseline Admin Activity: The Microsoft 365 audit log connector must be enabled in Sentinel for OfficeActivity to be populated.

**Shared-table notes:**
- DeviceProcessEvents: shared by SharePoint RCE - Anomalous Child Process Spawned by w3wp.exe; SharePoint RCE Chain - w3wp.exe Spawning Shells or Recon Tools; DNS Server RCE - Anomalous Child Process Spawned by dns.exe
- OfficeActivity: shared by SharePoint Auth Bypass - Privileged Operations from Unauthenticated or Anomalous Session Context; SharePoint - Privileged Admin Operations from Accounts with No Baseline Admin Activity

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: SharePoint - Privileged Admin Operations from Accounts with No Baseline Admin Activity.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: SharePoint RCE - Anomalous Child Process Spawned by w3wp.exe; SharePoint Auth Bypass - Privileged Operations from Unauthenticated or Anomalous Session Context; SharePoint RCE Chain - w3wp.exe Spawning Shells or Recon Tools; DNS Server RCE - Anomalous Child Process Spawned by dns.exe.

### Hunting Agenda and Promotion Criteria

- SharePoint RCE - Anomalous Child Process Spawned by w3wp.exe: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- SharePoint Auth Bypass - Privileged Operations from Unauthenticated or Anomalous Session Context: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- SharePoint RCE Chain - w3wp.exe Spawning Shells or Recon Tools: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- DNS Server RCE - Anomalous Child Process Spawned by dns.exe: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
