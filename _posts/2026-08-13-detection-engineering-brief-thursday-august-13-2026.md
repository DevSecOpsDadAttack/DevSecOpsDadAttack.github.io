---
layout: post
title: "Detection Engineering Brief - Thursday, August 13, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-08-13
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
  - SharePoint Server Subscription Edition
  - Windows
  - DNS Server
  - T1071
  - T1041
  - T1098.003
  - T1098
  - T1059
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

3 production candidates, 2 hunting-only, 0 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-63520, CVE-2026-55040, T1190, Microsoft SharePoint, Microsoft Project Server, Microsoft Office Web Apps Server, SharePoint Server Subscription Edition, Windows, DNS Server, T1071, T1041, T1098.003, T1098, T1059.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: SharePoint Privileged Operations from Account with No Prior Authentication Event - CVE-2026-55040; SharePoint Admin Operations from Account with No Prior Activity - CVE-2026-55040 Post-Bypass.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: SharePoint Worker Process Spawning Unexpected Child Process - CVE-2026-63520

### Detection Opportunity

SharePoint IIS worker process (w3wp.exe) spawning unexpected child processes, indicative of unauthenticated RCE via chained CVE-2026-63520 and CVE-2026-55040 exploitation.

### Intelligence Context

- Rapid7: CVE-2026-63520: Microsoft SharePoint Remote Code Execution (FIXED) — [https://www.rapid7.com/blog/post/etr-cve-2026-63520-microsoft-sharepoint-remote-code-execution-fixed](https://www.rapid7.com/blog/post/etr-cve-2026-63520-microsoft-sharepoint-remote-code-execution-fixed)
  - Context: Rapid7 reported that CVE-2026-63520 and CVE-2026-55040 can be chained to achieve unauthenticated remote code execution against vulnerable SharePoint servers. Exploitation results in code execution under the SharePoint IIS worker process context, making w3wp.exe spawning unexpected child processes a key post-exploitation signal.

### Search Metadata

- CVEs: CVE-2026-63520, CVE-2026-55040
- Threat actors: Not specified
- ATT&CK tags: T1190, T1071, T1041
- Products: Microsoft SharePoint, Microsoft Project Server, Microsoft Office Web Apps Server
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-63520, CVE-2026-55040, T1190, Microsoft SharePoint, Microsoft Project Server, Microsoft Office Web Apps Server, T1071, T1041

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol (low); Exfiltration: T1041 Exfiltration Over C2 Channel (low); Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let SuspiciousChildProcs = dynamic(["cmd.exe", "powershell.exe", "csc.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe"]);
let PostExploitPatterns = dynamic(["FromBase64", "EncodedCommand", "-enc ", "IEX", "Invoke-Expression", "DownloadString", "DownloadFile", "WebClient", "certutil -decode", "bitsadmin /transfer", "Start-Process", "Net.WebClient"]);
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ (SuspiciousChildProcs)
| extend SuspiciousCommandLine = iff(
    ProcessCommandLine has_any (PostExploitPatterns),
    true,
    false
  )
| project
    Timestamp,
    DeviceName,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    SHA256,
    SuspiciousCommandLine
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate SharePoint farm administration scripts run under the IIS application pool identity may spawn cmd.exe or powershell.exe during patching or configuration management operations.
- Third-party SharePoint add-ins or monitoring agents that invoke scripting engines under the w3wp.exe context.
- Non-SharePoint IIS applications on the same host running w3wp.exe that spawn scripting processes for legitimate reasons.

**Tuning notes:**
- After baselining, add FolderPath exclusions for verified legitimate automation tooling that runs under w3wp.exe.
- Consider creating a Defender XDR device group or watchlist of SharePoint server hostnames and filtering DeviceName against it to reduce FP volume from non-SharePoint IIS hosts.
- Extend PostExploitPatterns list based on observed attacker tradecraft in the environment.

**Risks / caveats:**
- Query covers all w3wp.exe instances on enrolled devices, not only SharePoint servers. Analysts should confirm DeviceName is a SharePoint, Project Server, or Office Web Apps Server host before escalating.
- Lookback window of 24h may miss delayed exploitation if detection latency exceeds the window; adjust based on ingestion pipeline latency.
- Encoded or obfuscated command lines that do not match the PostExploitPatterns list will not set SuspiciousCommandLine=true but will still appear in results.

### Triage Runbook

**First 15 minutes:**
- Confirm the device is actually a SharePoint, Project Server, or Office Web Apps Server host and not another IIS application server.
- Review the child process name, command line, parent command line, and account context to see whether the spawn is consistent with patching, deployment, or monitoring activity.
- Check whether the child process is a common attacker utility or scripting engine such as cmd.exe, powershell.exe, mshta.exe, certutil.exe, or rundll32.exe with encoded or download-style arguments.
- Look for nearby process activity from the same host around the same timestamp, especially follow-on process chains, archive creation, credential access, or additional scripting activity.
- If the command line is clearly malicious or the host is internet-facing and unapproved for such activity, treat as likely compromise and escalate immediately.

**Evidence to collect:**
- DeviceName, Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, FileName, FolderPath, ProcessCommandLine, SHA256, and SuspiciousCommandLine.
- Any preceding or subsequent w3wp.exe child processes on the same host within the last 24 hours.
- SharePoint/IIS logs or web access logs showing suspicious requests, unusual URLs, or repeated requests before the process spawn.
- Recent patching, deployment, backup, or SharePoint farm maintenance records for the host and application pool identity.
- Any outbound network connections from the same host and process tree that occurred shortly after the spawn.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and InitiatingProcessAccountName to reconstruct the full process tree.
- DeviceNetworkEvents for the same DeviceName and SHA256 or initiating process context to identify callback or staging traffic.
- DeviceFileEvents to look for dropped payloads, scripts, or web shells in SharePoint-related directories.
- DeviceLogonEvents and IdentityLogonEvents to determine whether the account context is service-based or interactive.
- IIS/SharePoint web logs to correlate the process spawn with suspicious HTTP requests or exploit patterns.

**Benign explanations:**
- Legitimate SharePoint farm administration or patching can spawn cmd.exe or powershell.exe under the IIS application pool identity.
- Third-party SharePoint add-ins, monitoring agents, or deployment tooling may invoke scripting engines from w3wp.exe.
- The host may be running a non-SharePoint IIS application that also uses w3wp.exe for normal automation.

**Escalation criteria:**
- The child process is a scripting or LOLBin utility with encoded, download, or execution-staging arguments.
- The host is confirmed to be a SharePoint-family server and the activity is not tied to a known maintenance window or approved automation.
- There is evidence of follow-on outbound connections, file drops, or additional suspicious child processes from the same worker process.
- The same host shows multiple suspicious w3wp.exe spawns or repeated exploit-like web requests.

**Containment actions:**
- Isolate the host if the child process command line or follow-on activity strongly indicates active exploitation.
- Disable or rotate the affected application pool/service credentials if they are suspected to be abused.
- Block known malicious outbound destinations if callback traffic is observed from the compromised host.
- Preserve volatile evidence before rebooting or patching the server.

**Closure criteria:**
- The process spawn is matched to a documented maintenance, deployment, or monitoring action.
- The host is not a SharePoint-family server or the child process is a known approved automation component.
- No suspicious follow-on activity, outbound connections, or file drops are found after review.
- A valid allowlist entry or baseline explains the exact parent-child process relationship.

<br/>
---
<br/>

## Detection 2: SharePoint Privileged Operations from Account with No Prior Authentication Event - CVE-2026-55040

### Detection Opportunity

Privileged SharePoint operations performed by an account or source IP with no corresponding prior authentication event, consistent with JWT authentication bypass exploitation of CVE-2026-55040.

### Intelligence Context

- Rapid7: Rapid7 Analysis: Microsoft SharePoint JWT Token Authentication Bypass (CVE-2026-55040) — [https://www.rapid7.com/blog/post/ra-microsoft-sharepoint-jwt-token-authentication-bypass-cve-2026-55040](https://www.rapid7.com/blog/post/ra-microsoft-sharepoint-jwt-token-authentication-bypass-cve-2026-55040)
  - Context: Rapid7 reported that CVE-2026-55040 allows a remote unauthenticated attacker to bypass SharePoint authentication via flaws in the JWT token validation pipeline, enabling the attacker to perform operations as a SharePoint site user or administrator. Detection opportunity exists by correlating privileged SharePoint audit operations against the absence of a valid prior authentication event for the same user or IP within a short time window.

### Search Metadata

- CVEs: CVE-2026-55040
- Threat actors: Not specified
- ATT&CK tags: T1190, T1098.003, T1098
- Products: Microsoft SharePoint, SharePoint Server Subscription Edition
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-55040, T1190, Microsoft SharePoint, SharePoint Server Subscription Edition, T1098.003, T1098

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Persistence: T1098 Account Manipulation/ T1098.003 Additional Cloud Roles (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- OfficeActivity for SharePoint Online requires the Microsoft 365 connector to be enabled in Microsoft Sentinel. On-premises SharePoint Server audit logs are not ingested into OfficeActivity by default.

**Required telemetry:**
- OfficeActivity, SigninLogs

### KQL

```kql
let HighPrivilegeOps = dynamic(["SiteCollectionAdminAdded", "PermissionLevelAdded", "AddedToGroup", "SiteCollectionCreated", "FileDeleted"]);
let PrivilegedOps = OfficeActivity
| where TimeGenerated > ago(1h)
| where Workload == "SharePoint"
| where Operation in (HighPrivilegeOps)
| project OpTime = TimeGenerated, UserId, ClientIP, Operation, SiteUrl, ItemType;
let RecentSignins = SigninLogs
| where TimeGenerated > ago(4h)
| where ResultType == 0
| project SigninTime = TimeGenerated, UserPrincipalName, IPAddress;
PrivilegedOps
| join kind=leftanti (
    RecentSignins
    | project IPAddress, UserPrincipalName
) on $left.ClientIP == $right.IPAddress, $left.UserId == $right.UserPrincipalName
| project OpTime, UserId, ClientIP, Operation, SiteUrl, ItemType
| order by OpTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Service principals and managed identities performing SharePoint operations do not generate SigninLogs entries and will appear as authentication-bypass events.
- Users behind shared corporate NAT or proxy IPs where the IP-based join fails to match their individual sign-in event.
- Accounts authenticated via on-premises ADFS or non-Entra identity providers that do not surface in SigninLogs.
- Newly provisioned accounts performing first-time SharePoint operations before their sign-in event is ingested.

**Tuning notes:**
- Extend SigninLogs lookback beyond 4h if the environment has long-lived authenticated sessions or high ingestion latency.
- Add a UserId exclusion list for known service accounts and managed identities that legitimately perform SharePoint admin operations without interactive sign-in.
- Consider normalizing UserId and UserPrincipalName to lowercase before joining to avoid case-sensitivity mismatches.
- Restrict Operation list to the three or four most sensitive actions in the environment to reduce alert volume.

**Risks / caveats:**
- SigninLogs requires the Microsoft Entra ID (Azure AD) connector to be enabled in Microsoft Sentinel. If the connector is absent or the tenant uses on-premises-only authentication without Entra federation, SigninLogs will be empty and the leftanti join will surface every OfficeActivity row as a false positive.
- OfficeActivity for SharePoint Online requires the Microsoft 365 connector to be enabled in Microsoft Sentinel. On-premises SharePoint Server audit logs are not ingested into OfficeActivity by default.
- The composite join on ClientIP and UserId will still miss cases where UserId in OfficeActivity does not exactly match UserPrincipalName in SigninLogs due to UPN format differences (e.g., alias vs. full UPN).
- Ingestion delay between OfficeActivity and SigninLogs may cause legitimate sign-ins to fall outside the 4h lookback window, producing false positives during high-latency periods.

### Triage Runbook

**First 15 minutes:**
- Validate the account, source IP, and operation type in the alert and confirm whether the activity is truly privileged.
- Check whether the account is a service principal, managed identity, or other non-interactive identity that may not produce a normal SigninLogs record.
- Review whether the source IP is corporate NAT, proxy egress, or a known admin jump host that could hide the original user.
- Look for a burst of sensitive operations such as permission changes, site collection admin changes, group additions, or deletions.
- If the activity is from an external or unrecognized IP and there is no legitimate sign-in context, escalate as probable bypass exploitation.

**Evidence to collect:**
- UserId, ClientIP, Operation, SiteUrl, ItemType, and OpTime for each matched event.
- Any corresponding SigninLogs entries for the same UserPrincipalName or IPAddress within the surrounding time window.
- OfficeActivity history for the same account to determine whether the operation pattern is new or unusual.
- Tenant or SharePoint audit records showing whether the account has administrative privileges or service-account status.
- UserAgent and any available session metadata to distinguish browser-based activity from automation.

**Pivot points:**
- SigninLogs to verify whether a successful authentication exists for the same user or source IP.
- OfficeActivity to enumerate all SharePoint operations by the same UserId before and after the alert.
- AuditLogs or identity governance records to determine whether the account was recently granted elevated access.
- Device or network telemetry for the source IP if it maps to an internal host or jump box.
- SharePoint admin and site audit logs to identify the exact objects modified.

**Benign explanations:**
- Service accounts or managed identities may perform SharePoint actions without a corresponding interactive sign-in.
- Shared corporate NAT or proxy IPs can break IP-based correlation and make legitimate activity appear unauthenticated.
- On-premises or non-Entra authentication paths may not surface in SigninLogs.
- Recent account provisioning or delayed ingestion can make a legitimate sign-in appear absent.

**Escalation criteria:**
- The account is a human admin account and there is no valid sign-in or approved automation context.
- The operations include permission changes, site collection admin changes, or other high-impact actions from an unrecognized IP.
- Multiple privileged operations occur in a short burst from the same account or source IP.
- The activity aligns with other signs of compromise such as unusual user agents, impossible travel, or concurrent suspicious process activity on a SharePoint server.

**Containment actions:**
- Disable or reset the affected account if it is confirmed or strongly suspected to be abused.
- Revoke active sessions and refresh tokens for the account where applicable.
- Block the source IP if it is external and clearly malicious.
- Preserve SharePoint audit data and identity logs before making major changes.

**Closure criteria:**
- A valid sign-in or approved service identity explains the operations.
- The account is a known automation identity with documented behavior matching the alert.
- The source IP is a known corporate egress or admin path and the operations are expected.
- No additional suspicious SharePoint or identity activity is found after investigation.

<br/>
---
<br/>

## Detection 3: SharePoint Admin Operations from Account with No Prior Activity - CVE-2026-55040 Post-Bypass

### Detection Opportunity

Admin-level SharePoint operations performed by accounts with no prior OfficeActivity history, consistent with post-authentication-bypass adversary action following CVE-2026-55040 exploitation.

### Intelligence Context

- Rapid7: Rapid7 Analysis: Microsoft SharePoint JWT Token Authentication Bypass (CVE-2026-55040) — [https://www.rapid7.com/blog/post/ra-microsoft-sharepoint-jwt-token-authentication-bypass-cve-2026-55040](https://www.rapid7.com/blog/post/ra-microsoft-sharepoint-jwt-token-authentication-bypass-cve-2026-55040)
  - Context: Rapid7 reported that after bypassing authentication via CVE-2026-55040, an attacker can perform operations as a SharePoint site user or administrator. Detecting admin-level SharePoint operations from accounts with no prior activity baseline provides a post-exploitation signal for this bypass.

### Search Metadata

- CVEs: CVE-2026-55040
- Threat actors: Not specified
- ATT&CK tags: T1190, T1098.003, T1098
- Products: Microsoft SharePoint, SharePoint Server Subscription Edition
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-55040, T1190, Microsoft SharePoint, SharePoint Server Subscription Edition, T1098.003, T1098

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Persistence: T1098 Account Manipulation/ T1098.003 Additional Cloud Roles (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- OfficeActivity for SharePoint Online requires the Microsoft 365 connector to be enabled in Microsoft Sentinel. On-premises SharePoint Server audit logs are not ingested into OfficeActivity by default.

**Required telemetry:**
- OfficeActivity

### KQL

```kql
let HighPrivilegeOps = dynamic(["SiteCollectionAdminAdded", "PermissionLevelAdded", "AddedToGroup", "SiteCollectionCreated", "FileDeleted"]);
let RecentAdminOps = OfficeActivity
| where TimeGenerated > ago(24h)
| where Workload == "SharePoint"
| where Operation in (HighPrivilegeOps)
| summarize
    FirstSeen = min(TimeGenerated),
    OpCount = count(),
    Operations = make_set(Operation),
    Sites = make_set(SiteUrl),
    ClientIPs = make_set(ClientIP)
  by UserId;
let HistoricalUsers = OfficeActivity
| where TimeGenerated between (ago(30d) .. ago(24h))
| where Workload == "SharePoint"
| summarize HistoricalCount = count() by UserId;
RecentAdminOps
| join kind=leftanti HistoricalUsers on UserId
| where OpCount >= 1
| project FirstSeen, UserId, ClientIPs, OpCount, Operations, Sites
| order by FirstSeen desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Newly provisioned legitimate SharePoint administrators performing their first administrative actions will have no 30-day history.
- Service principals and automation accounts that perform SharePoint operations infrequently or for the first time.
- Accounts that were inactive for more than 30 days and have returned to perform legitimate administrative tasks.
- Accounts whose historical OfficeActivity was not ingested due to connector gaps or retention policy changes.

**Tuning notes:**
- Extend the historical baseline window beyond 30 days for environments with infrequent admin activity patterns.
- Add a UserId exclusion list for known service accounts and managed identities after initial hunting runs.
- Consider adding a ClientIPs filter to prioritize results where all source IPs are external to the corporate network.
- Raise the OpCount threshold above 1 if single-operation anomalies generate excessive noise.

**Risks / caveats:**
- OfficeActivity for SharePoint Online requires the Microsoft 365 connector to be enabled in Microsoft Sentinel. On-premises SharePoint Server audit logs are not ingested into OfficeActivity by default.
- A 30-day OfficeActivity lookback requires sufficient data retention configuration. If the workspace retention is set below 30 days, the historical baseline will be incomplete and the leftanti join will produce false positives for all users.
- The 30-day baseline window requires at least 30 days of OfficeActivity retention in the workspace. Shorter retention will cause all users to appear as having no history.
- Ingestion gaps in OfficeActivity during the 30-day baseline window may cause legitimate users to appear as having no prior history.

### Triage Runbook

**First 15 minutes:**
- Review the account history to confirm whether it is truly new to SharePoint administration or simply inactive for a long period.
- Inspect the operations, sites, and source IPs to see whether the activity is limited to one action or part of a broader admin sequence.
- Check whether the account is a service principal, managed identity, or recently provisioned admin account.
- Compare the activity against recent onboarding, migration, or maintenance work that could explain first-time admin actions.
- Escalate quickly if the account is unknown, the source IP is external, or the operations include permission or role changes.

**Evidence to collect:**
- FirstSeen, UserId, ClientIPs, OpCount, Operations, and Sites from the alert.
- 30-day OfficeActivity history for the same UserId to confirm whether there is truly no prior activity.
- Account creation, role assignment, and lifecycle records for the user or service identity.
- Any associated SigninLogs or identity events that show how the account authenticated.
- SharePoint audit details for the exact objects and permissions affected.

**Pivot points:**
- OfficeActivity to build a longer history for the same UserId and related accounts.
- SigninLogs to determine whether the account had recent successful authentication.
- AuditLogs or identity management records to check for recent account creation or privilege assignment.
- Threat hunting across other Microsoft 365 workloads for the same UserId or source IP.
- DeviceNetworkEvents if the source IP maps to an internal host that may be compromised.

**Benign explanations:**
- A newly provisioned legitimate administrator will have no prior SharePoint activity history.
- A dormant admin account returning after a long absence can look like first-time activity.
- Service principals and automation accounts may legitimately have sparse or no historical OfficeActivity.
- Historical data gaps or retention issues can make normal accounts appear new.

**Escalation criteria:**
- The account is not a known service identity and has no documented business reason for first-time admin activity.
- The operations include site collection admin changes, permission changes, group additions, or deletions.
- The source IP is external, unusual, or associated with other suspicious activity.
- There is evidence of multiple accounts or multiple sites being touched in a short time window.

**Containment actions:**
- Disable or suspend the account if it is not immediately explainable and the activity is high impact.
- Revoke sessions and tokens for the account if compromise is suspected.
- Block the source IP if it is external and malicious.
- Preserve audit logs and account lifecycle records before remediation.

**Closure criteria:**
- The account is verified as newly provisioned or a documented service identity with expected first-use behavior.
- The operations are confirmed as approved administrative work tied to a change record.
- No additional suspicious activity is found for the account, source IP, or related sites.
- Historical gaps or retention limitations are confirmed to explain the lack of prior activity.

<br/>
---
<br/>

## Detection 4: Outbound Network Connection from SharePoint Worker Process - CVE-2026-63520 RCE Indicator

### Detection Opportunity

w3wp.exe on a SharePoint server initiating outbound network connections to external IPs on non-standard ports, consistent with post-exploitation callback or lateral movement following unauthenticated RCE via CVE-2026-63520.

### Intelligence Context

- Rapid7: CVE-2026-63520: Microsoft SharePoint Remote Code Execution (FIXED) — [https://www.rapid7.com/blog/post/etr-cve-2026-63520-microsoft-sharepoint-remote-code-execution-fixed](https://www.rapid7.com/blog/post/etr-cve-2026-63520-microsoft-sharepoint-remote-code-execution-fixed)
  - Context: Rapid7 reported that chaining CVE-2026-63520 and CVE-2026-55040 achieves unauthenticated remote code execution on SharePoint servers. Post-exploitation activity commonly includes outbound callback connections initiated by the compromised worker process, making outbound network events from w3wp.exe a high-value detection signal.

### Search Metadata

- CVEs: CVE-2026-63520, CVE-2026-55040
- Threat actors: Not specified
- ATT&CK tags: T1190, T1071, T1041
- Products: Microsoft SharePoint, Microsoft Project Server, Microsoft Office Web Apps Server
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-63520, CVE-2026-55040, T1190, Microsoft SharePoint, Microsoft Project Server, Microsoft Office Web Apps Server, T1071, T1041

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol (low); Exfiltration: T1041 Exfiltration Over C2 Channel (low); Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where ActionType == "ConnectionSuccess"
| where RemotePort !in (80, 443, 1433, 25, 587)
| where not(ipv4_is_private(RemoteIP))
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    Protocol,
    LocalPort,
    ActionType
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- SharePoint integrations with external services (e.g., third-party APIs, CDN endpoints, telemetry services) that use non-standard ports.
- Non-SharePoint IIS applications on the same host running w3wp.exe that make legitimate outbound connections.
- SharePoint hybrid configuration connections to Microsoft 365 endpoints on non-standard ports.

**Tuning notes:**
- After baselining, add RemotePort exclusions for known legitimate SharePoint integration endpoints that use non-standard ports.
- Consider creating a Defender XDR device group of SharePoint server hostnames and filtering DeviceName against it to reduce FP volume.
- Add RemoteIP threat intelligence enrichment via the ThreatIntelligenceIndicator table join to prioritize known-bad destinations.

**Risks / caveats:**
- Query covers all w3wp.exe instances on enrolled devices, not only SharePoint servers. Analysts must confirm DeviceName is a SharePoint, Project Server, or Office Web Apps Server host before treating as a true positive.
- Attackers using ports 80 or 443 for C2 callbacks will evade this detection; consider a complementary detection on unusual RemoteUrl patterns for w3wp.exe connections on standard ports.
- Lookback window of 24h may miss delayed exploitation if detection latency exceeds the window.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a SharePoint, Project Server, or Office Web Apps Server system and not another IIS server.
- Review the remote IP, port, URL, and initiating process command line to determine whether the connection is expected integration traffic or suspicious callback behavior.
- Check whether the destination is external, newly seen, or on a non-standard port for the environment.
- Look for nearby process creation, file writes, or additional network connections from the same worker process.
- If the connection is to an unknown external host and the command line or timing suggests exploitation, escalate immediately.

**Evidence to collect:**
- Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, Protocol, LocalPort, and ActionType.
- Any other DeviceNetworkEvents from the same host and process tree around the alert time.
- DeviceProcessEvents to identify whether the outbound connection followed suspicious child process execution.
- Firewall, proxy, or DNS logs to resolve the destination and determine whether it is known or malicious.
- SharePoint/IIS logs to correlate the outbound connection with suspicious inbound requests.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceName, RemoteIP, or RemoteUrl to find repeated callbacks.
- DeviceProcessEvents for the same DeviceName and InitiatingProcessAccountName to reconstruct the process chain.
- DeviceFileEvents to look for dropped scripts, web shells, or staging artifacts.
- DNS logs or network telemetry to identify the resolved hostname behind RemoteIP.
- Threat intelligence or reputation sources for the destination IP or domain.

**Benign explanations:**
- SharePoint integrations with third-party services may use non-standard ports and external destinations.
- Hybrid SharePoint configurations can generate legitimate outbound traffic to Microsoft 365 or related services.
- Non-SharePoint IIS applications on the same host may use w3wp.exe for normal outbound communication.
- Some monitoring or telemetry agents may initiate outbound connections from the worker process context.

**Escalation criteria:**
- The destination is external, unrecognized, or known malicious.
- The connection occurs alongside suspicious child process creation or other exploit indicators on the same host.
- The remote port or URL is inconsistent with approved SharePoint integrations.
- There are repeated outbound connections from w3wp.exe to the same destination in a short period.

**Containment actions:**
- Isolate the host if the outbound connection is part of a confirmed or strongly suspected compromise.
- Block the remote IP or domain at the network edge if it is malicious.
- Disable or rotate credentials associated with the affected application pool if abuse is suspected.
- Preserve endpoint and network evidence before rebooting or patching.

**Closure criteria:**
- The destination is a documented and approved SharePoint integration endpoint.
- The traffic pattern matches known baseline behavior for the host and application pool.
- No supporting evidence of exploit activity, suspicious child processes, or malicious destinations is found.
- The alert is attributable to a known maintenance or monitoring workflow.

<br/>
---
<br/>

## Detection 5: DNS Server Process Spawning Unexpected Child Process - August 2026 Patch Tuesday Critical RCE

### Detection Opportunity

Windows DNS Server process (dns.exe) spawning unexpected child processes or initiating outbound connections to non-DNS ports, consistent with exploitation of the critical DNS Server RCE patched in August 2026 Patch Tuesday.

### Intelligence Context

- SANS ISC: Microsoft Patch Tuesday August 2026, (Tue, Aug 11th) — [https://isc.sans.edu/diary/rss/33236](https://isc.sans.edu/diary/rss/33236)
  - Context: SANS ISC reported that August 2026 Patch Tuesday included a critical remote code execution vulnerability in Windows DNS Server. Exploitation of DNS Server RCE vulnerabilities typically results in dns.exe spawning unexpected child processes or making anomalous outbound network connections, which are detectable with endpoint telemetry.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1071, T1190
- Products: Windows, DNS Server
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Windows, DNS Server, T1059, T1071, T1190

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (medium); Command and Control: T1071 Application Layer Protocol (low); Initial Access: T1190 Exploit Public-Facing Application (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let SuspiciousChildProcs = dynamic(["cmd.exe", "powershell.exe", "csc.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe", "rundll32.exe", "net.exe", "net1.exe"]);
let DnsChildProcs = DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName =~ "dns.exe"
| where FileName in~ (SuspiciousChildProcs)
| project
    Timestamp,
    DeviceName,
    EventType = "ChildProcess",
    InitiatingProcessFileName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    SHA256,
    RemoteIP = "",
    RemotePort = int(null),
    RemoteUrl = "",
    Protocol = "";
let DnsOutbound = DeviceNetworkEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName =~ "dns.exe"
| where ActionType == "ConnectionSuccess"
| where RemotePort != 53
| where not(ipv4_is_private(RemoteIP))
| project
    Timestamp,
    DeviceName,
    EventType = "OutboundConnection",
    InitiatingProcessFileName,
    FileName = "",
    FolderPath = "",
    ProcessCommandLine = "",
    SHA256 = "",
    RemoteIP,
    RemotePort,
    RemoteUrl,
    Protocol;
union DnsChildProcs, DnsOutbound
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- DNS servers that use RPC-based zone transfers may initiate outbound connections on high-numbered ports that are not port 53.
- DNS server management tools or monitoring agents that spawn child processes under dns.exe context.
- Windows DNS Server debug logging or diagnostic tools that invoke scripting engines during troubleshooting.

**Tuning notes:**
- Add RemotePort exclusions for RPC ephemeral port ranges (49152-65535) if the DNS server performs RPC-based zone transfers to reduce false positives in the DnsOutbound branch.
- Consider creating a Defender XDR device group of Windows DNS Server hostnames and filtering DeviceName against it.
- Extend the lookback window to 7d or 30d for proactive hunting exercises on systems that may not have received the August 2026 patches.
- Add SHA256-based allowlisting for known-good child process hashes after baselining DNS server management tooling.

**Risks / caveats:**
- No specific CVE ID is associated with this detection; the behavioral scope covers any dns.exe exploitation pattern, which may include benign administrative activity.
- Query covers all dns.exe instances on enrolled devices. Analysts must confirm DeviceName is a Windows DNS Server host before treating as a true positive.
- DNS servers performing RPC-based zone transfers will generate outbound connections on high-numbered ports that are not port 53, producing false positives in the DnsOutbound branch.
- Lookback window of 24h may miss delayed exploitation; extend for hunting exercises targeting unpatched systems.

### Triage Runbook

**First 15 minutes:**
- Confirm the device is a Windows DNS Server and not a workstation or non-server host running a DNS-related service.
- Review whether the alert is a child-process event, an outbound connection event, or both, and inspect the exact process names and command lines.
- Check whether the child process is a common attacker utility such as cmd.exe, powershell.exe, mshta.exe, certutil.exe, or rundll32.exe.
- Validate whether the outbound connection is to a non-DNS port and whether it is expected for zone transfers, management, or monitoring.
- Escalate immediately if dns.exe spawned a scripting or command interpreter without a clear administrative explanation.

**Evidence to collect:**
- Timestamp, DeviceName, EventType, InitiatingProcessFileName, FileName, FolderPath, ProcessCommandLine, SHA256, RemoteIP, RemotePort, RemoteUrl, and Protocol.
- Any additional DeviceProcessEvents from dns.exe on the same host within the last 24 hours.
- Any DeviceNetworkEvents from dns.exe showing repeated or unusual external connections.
- Windows event logs and DNS server logs for service errors, crashes, or suspicious query patterns.
- Administrative change records, troubleshooting sessions, or monitoring tool activity on the DNS server.

**Pivot points:**
- DeviceProcessEvents to reconstruct the dns.exe child process tree.
- DeviceNetworkEvents to identify repeated outbound connections or unusual destinations.
- Windows event logs for service restarts, crashes, or script execution around the alert time.
- DNS server logs to correlate suspicious activity with inbound queries or zone transfer behavior.
- Threat intelligence lookups for any external RemoteIP or RemoteUrl.

**Benign explanations:**
- DNS management or troubleshooting tools can spawn child processes under dns.exe during maintenance.
- RPC-based zone transfers may create outbound connections on high-numbered ports.
- Diagnostic or debug workflows may invoke scripting engines on DNS servers.
- Some monitoring agents may interact with dns.exe in ways that resemble anomalous activity.

**Escalation criteria:**
- dns.exe spawns a scripting or command interpreter with no approved maintenance context.
- The outbound destination is external, unknown, or clearly malicious.
- The server shows repeated suspicious child processes or multiple anomalous outbound connections.
- There are signs of service instability, crashes, or concurrent suspicious activity on the same host.

**Containment actions:**
- Isolate the DNS server if the activity strongly indicates active exploitation.
- Block malicious outbound destinations if callback traffic is observed.
- Suspend or restrict remote administrative access to the server until validated.
- Preserve logs and memory evidence before rebooting or applying remediation.

**Closure criteria:**
- The child process or outbound connection is explained by documented DNS administration or troubleshooting.
- The host is confirmed to be a legitimate DNS server and the activity matches baseline behavior.
- No additional suspicious child processes, external connections, or service anomalies are found.
- A known-good hash, tool, or maintenance record explains the event.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- SharePoint Privileged Operations from Account with No Prior Authentication Event - CVE-2026-55040: Do not schedule yet; validate as an analyst-led hunt first.
- SharePoint Admin Operations from Account with No Prior Activity - CVE-2026-55040 Post-Bypass: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- SharePoint Privileged Operations from Account with No Prior Authentication Event - CVE-2026-55040: OfficeActivity for SharePoint Online requires the Microsoft 365 connector to be enabled in Microsoft Sentinel. On-premises SharePoint Server audit logs are not ingested into OfficeActivity by default.
- SharePoint Admin Operations from Account with No Prior Activity - CVE-2026-55040 Post-Bypass: OfficeActivity for SharePoint Online requires the Microsoft 365 connector to be enabled in Microsoft Sentinel. On-premises SharePoint Server audit logs are not ingested into OfficeActivity by default.

**Shared-table notes:**
- DeviceProcessEvents: shared by SharePoint Worker Process Spawning Unexpected Child Process - CVE-2026-63520; DNS Server Process Spawning Unexpected Child Process - August 2026 Patch Tuesday Critical RCE
- OfficeActivity: shared by SharePoint Privileged Operations from Account with No Prior Authentication Event - CVE-2026-55040; SharePoint Admin Operations from Account with No Prior Activity - CVE-2026-55040 Post-Bypass
- DeviceNetworkEvents: shared by Outbound Network Connection from SharePoint Worker Process - CVE-2026-63520 RCE Indicator; DNS Server Process Spawning Unexpected Child Process - August 2026 Patch Tuesday Critical RCE

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: SharePoint Worker Process Spawning Unexpected Child Process - CVE-2026-63520; Outbound Network Connection from SharePoint Worker Process - CVE-2026-63520 RCE Indicator; DNS Server Process Spawning Unexpected Child Process - August 2026 Patch Tuesday Critical RCE.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: SharePoint Privileged Operations from Account with No Prior Authentication Event - CVE-2026-55040; SharePoint Admin Operations from Account with No Prior Activity - CVE-2026-55040 Post-Bypass.

### Hunting Agenda and Promotion Criteria

- SharePoint Privileged Operations from Account with No Prior Authentication Event - CVE-2026-55040: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- SharePoint Admin Operations from Account with No Prior Activity - CVE-2026-55040 Post-Bypass: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
