---
layout: post
title: "Detection Engineering Brief - Friday, November 6, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-11-06
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - GitHub
  - OAuth applications
  - Microsoft cloud tenants
  - ARTEX
  - Storm-2603
  - SharePoint
  - ToolShell
  - CVE-2023-20198
  - Cisco IOS
  - T1528
  - T1098
  - T1098.003
  - T1098.001
  - T1213
  - T1190
---

## Detection Engineering Summary

This brief produced 4 detection candidates.

3 production candidates, 0 hunting-only, 1 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: GitHub, OAuth applications, Microsoft cloud tenants, ARTEX, Storm-2603, SharePoint, ToolShell, CVE-2023-20198, Cisco IOS, T1528, T1098, T1098.003, T1098.001, T1213, T1190.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: CVE-2023-20198 Exploitation Attempt Patterns in Cisco IOS Logs.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: OAuth App Authenticated Actions Following Credential Exposure

### Detection Opportunity

Compromised OAuth application performing authenticated operations within Microsoft cloud tenant after secrets were exposed on GitHub and harvested via ARTEX.

### Intelligence Context

- Microsoft Security Blog: Threat actors use agentic AI tooling to find and abuse exposed secrets — [https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/](https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/)
  - Context: Threat actors used the ARTEX agentic offensive framework to search GitHub for exposed OAuth application secrets, then used those compromised applications to perform authenticated actions within victim Microsoft cloud tenants.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1528, T1098, T1098.003, T1098.001
- Products: GitHub, OAuth applications
- Platforms: Microsoft cloud tenants
- Malware: Not specified
- Tools: ARTEX
- Search tags: GitHub, OAuth applications, Microsoft cloud tenants, ARTEX, T1528, T1098, T1098.003, T1098.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1528 Steal Application Access Token (medium); Persistence: T1098 Account Manipulation/ T1098.003 Additional Cloud Roles (medium); Defense Evasion: T1098 Account Manipulation/ T1098.001 Additional Cloud Credentials (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- SigninLogs, AuditLogs

### KQL

```kql
let lookback = 30d;
let recentWindow = 7d;
let sensitiveOps = dynamic(["Add member to role", "Update application", "Add application", "Consent to application", "Add service principal", "Update service principal", "Remove member from role", "Delete application", "Delete service principal"]);
let firstSeenApps =
    SigninLogs
    | where TimeGenerated >= ago(lookback)
    | where AppId != "" and ResultType == 0
    | summarize
        FirstSeen = min(TimeGenerated),
        SigninCount = count(),
        SeenIPAddresses = make_set(IPAddress, 10),
        SeenUserAgents = make_set(UserAgent, 5)
        by AppId, AppDisplayName
    | where FirstSeen >= ago(recentWindow) and SigninCount <= 3;
AuditLogs
| where TimeGenerated >= ago(recentWindow)
| where OperationName in (sensitiveOps)
| extend
    InitiatingAppId = tostring(InitiatedBy.app.appId),
    InitiatingAppDisplayName = tostring(InitiatedBy.app.displayName),
    InitiatingUserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
| where InitiatingAppId != ""
| join kind=inner firstSeenApps on $left.InitiatingAppId == $right.AppId
| extend TargetResourcesSummary = tostring(TargetResources)
| project
    TimeGenerated,
    OperationName,
    Result,
    InitiatingAppId,
    InitiatingAppDisplayName,
    InitiatingUserPrincipalName,
    FirstSeen,
    SigninCount,
    SeenIPAddresses,
    SeenUserAgents,
    TargetResourcesSummary
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Newly provisioned internal OAuth applications that were legitimately registered and used for the first time within the 7-day window.
- Automated deployment pipelines that register and immediately use OAuth applications as part of CI/CD workflows.
- Applications migrated from another tenant that appear new in SigninLogs but are operationally established.

**Tuning notes:**
- Increase SigninCount threshold from 3 to a higher value if newly onboarded apps legitimately authenticate multiple times during provisioning.
- Add a known-safe AppId exclusion list using a let statement or watchlist join to suppress internal automation.
- Consider splitting into two scheduled rules: one for role assignment operations (higher severity) and one for application modifications (medium severity).

**Risks / caveats:**
- AuditLogs.InitiatedBy.app.appId is only populated for service-principal-initiated operations; user-delegated OAuth flows may populate InitiatedBy.user instead, causing those events to be excluded from the join.
- SigninLogs requires the Entra ID diagnostic settings connector to be configured and streaming to the Sentinel workspace; absence of this connector produces zero results.
- The 7-day firstSeenApps window and SigninCount <= 3 threshold should be baselined against the environment's application onboarding cadence before scheduling as a high-fidelity alert.
- Environments with frequent automated application provisioning may require a higher SigninCount threshold or an allowlist of known CI/CD service principal AppIds.

### Triage Runbook

**First 15 minutes:**
- Confirm the AppId/AppDisplayName is not a known internal automation app or approved CI/CD service principal.
- Review the alert timeframe for the exact sensitive OperationName values and whether Result indicates success.
- Check whether the initiating app has a recent first-seen sign-in pattern, low historical sign-in count, or unusual IP/User-Agent.
- Identify any role assignment, consent, application update, or service principal changes performed by the app and note affected resources.

**Evidence to collect:**
- SigninLogs for the AppId: first-seen time, IPAddress, UserAgent, ResultType, and any non-interactive sign-ins.
- AuditLogs for the same AppId: OperationName, Result, InitiatedBy details, and TargetResources.
- Any Entra ID app registration or enterprise application changes around the same time, including credential additions, consent grants, or role assignments.
- GitHub evidence of secret exposure if available: repository, commit, issue, or artifact where the secret was published.

**Pivot points:**
- SigninLogs filtered on AppId and a 7-30 day window to establish baseline sign-in behavior.
- AuditLogs filtered on InitiatedBy.app.appId and the sensitive operations list to enumerate all actions by the app.
- AADServicePrincipalSignInLogs if available to capture non-interactive OAuth flows not present in SigninLogs.
- Entra ID application and service principal audit history for credential, consent, and role changes.

**Benign explanations:**
- A newly deployed internal application legitimately used for the first time within the last 7 days.
- A migration or redeployment that caused a previously established app to appear new in the sign-in history.
- Automated provisioning or CI/CD workflows that register and immediately use an OAuth application.
- A test or lab tenant where app registration and role changes are expected.

**Escalation criteria:**
- Any successful role assignment, consent grant, credential addition, or service principal modification not tied to an approved change.
- Evidence that the app was used from an unexpected IP, impossible travel pattern, or unfamiliar User-Agent.
- Multiple sensitive operations performed in a short period, especially if the app was first seen recently.
- Any indication the exposed secret is still active and the app continues to authenticate after the alert.

**Containment actions:**
- Disable or delete the compromised application secret or rotate all credentials for the app.
- Temporarily disable the service principal or block the app registration if business impact is acceptable.
- Revoke active sessions/tokens associated with the app and review tenant-wide consent grants.
- Remove unauthorized role assignments or service principal changes made by the app.

**Closure criteria:**
- The app is confirmed to be an approved internal automation identity and the activity matches expected change records.
- All exposed credentials have been rotated or revoked and no further suspicious app activity is observed.
- Unauthorized role, consent, or service principal changes have been removed and validated.
- A documented root cause exists for the GitHub exposure and compensating controls are in place.

<br/>
---
<br/>

## Detection 2: SharePoint Worker Process Spawning Anomalous Child Processes

### Detection Opportunity

Runtime subversion following ToolShell exploitation on SharePoint server, observed as IIS worker processes spawning unexpected child processes indicative of in-memory code execution.

### Intelligence Context

- Securelist: The SOC Files 5: Ghost in the pipeline, or a fileless SharePoint breach by Storm-2603 — [https://securelist.com/storm-2603-fileless-toolshell-attack/121467/](https://securelist.com/storm-2603-fileless-toolshell-attack/121467/)
  - Context: Storm-2603 conducted a fileless attack against SharePoint using ToolShell exploitation followed by runtime subversion. The fileless nature means artifacts appear in process telemetry rather than file events, with IIS worker processes being the likely execution host.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-2603
- ATT&CK tags: T1213, T1190
- Products: SharePoint
- Platforms: Not specified
- Malware: Not specified
- Tools: ToolShell
- Search tags: Storm-2603, SharePoint, ToolShell, T1213, T1190

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Collection: T1213 Data from Information Repositories (medium); Initial Access: T1190 Exploit Public-Facing Application (low)

### Deployment Gates

- Defender for Endpoint must be onboarded on SharePoint server hosts; if servers are not onboarded, DeviceProcessEvents will contain no records for those hosts and the query produces no results.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let suspiciousChildren = dynamic([
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "net.exe", "net1.exe", "whoami.exe", "nltest.exe", "ipconfig.exe",
    "msiexec.exe", "wmic.exe", "forfiles.exe", "pcalua.exe", "conhost.exe",
    "at.exe", "schtasks.exe", "reg.exe", "curl.exe", "wget.exe"
]);
DeviceProcessEvents
| where TimeGenerated >= ago(14d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ (suspiciousChildren)
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    AccountDomain,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    InitiatingProcessId,
    FileName,
    ProcessCommandLine,
    FolderPath,
    SHA256
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- IIS sites unrelated to SharePoint running on the same host may trigger this detection if they spawn scripting hosts for legitimate purposes.
- SharePoint health monitoring or diagnostic scripts that invoke cmd.exe or powershell.exe from application pool context.
- Antivirus or EDR agents that inject into w3wp.exe and spawn child processes during scanning.

**Tuning notes:**
- Scope DeviceName to a watchlist or dynamic list of known SharePoint server hostnames to reduce noise from non-SharePoint IIS hosts.
- Add an exclusion for known SharePoint health check or monitoring processes by filtering on InitiatingProcessCommandLine patterns associated with those tools.
- Consider correlating results with DeviceNetworkEvents on the same DeviceName and timeframe to identify outbound C2 connections following process spawning.

**Risks / caveats:**
- Defender for Endpoint must be onboarded on SharePoint server hosts; if servers are not onboarded, DeviceProcessEvents will contain no records for those hosts and the query produces no results.
- Without scoping DeviceName to known SharePoint server hostnames, this query will fire on any IIS-hosted application that spawns the listed child processes, increasing false positive volume in environments with many IIS servers.
- The 14-day lookback window may miss historical activity if the compromise occurred before the window; consider extending for initial threat hunting runs.
- Fileless execution via .NET reflection or COM objects may not produce child process events visible in DeviceProcessEvents, limiting detection coverage for the most sophisticated ToolShell variants.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a SharePoint server and not another IIS application server.
- Review the child process name, command line, and parent w3wp.exe instance for signs of script execution, LOLBins, or post-exploitation activity.
- Check whether the same host shows suspicious network connections, new services, scheduled tasks, or additional process trees around the same time.
- Identify the account context and whether the process lineage aligns with expected SharePoint maintenance or health-check activity.

**Evidence to collect:**
- DeviceProcessEvents for the host: full process tree, command lines, parent/child relationships, SHA256, and initiating process IDs.
- DeviceNetworkEvents for the same host and timeframe to identify outbound connections after the suspicious spawn.
- DeviceFileEvents and DeviceRegistryEvents for persistence artifacts, dropped files, or configuration changes.
- SharePoint/IIS logs if available to correlate the process event with web requests or unusual endpoints.

**Pivot points:**
- DeviceProcessEvents filtered on DeviceName and w3wp.exe lineage to find adjacent suspicious processes.
- DeviceNetworkEvents on the same DeviceName and timeframe for outbound C2 or lateral movement indicators.
- DeviceFileEvents and DeviceRegistryEvents on the host for dropped web shells, scripts, or persistence.
- If available, IIS or SharePoint logs to correlate the process spawn with a specific request path or source IP.

**Benign explanations:**
- Legitimate SharePoint health monitoring or diagnostic tooling that launches cmd.exe or powershell.exe.
- An antivirus or EDR product injecting into w3wp.exe and causing child process creation.
- A non-SharePoint IIS site on the same host performing administrative scripting.
- Authorized maintenance or patching activity by administrators.

**Escalation criteria:**
- Any suspicious child process with encoded commands, download cradle behavior, or credential access activity.
- Evidence of persistence, lateral movement, or outbound connections to untrusted infrastructure.
- Multiple anomalous child processes from w3wp.exe or repeated spawns across several SharePoint servers.
- Confirmation that the host is internet-facing and the activity aligns with known ToolShell exploitation patterns.

**Containment actions:**
- Isolate the SharePoint server from the network if active exploitation is suspected and business impact is acceptable.
- Terminate malicious child processes and preserve memory and process artifacts before rebooting.
- Block suspicious outbound destinations and disable any newly created local accounts or services.
- Apply vendor guidance or emergency mitigation for the SharePoint vulnerability if not already remediated.

**Closure criteria:**
- The child process is confirmed to be benign maintenance, monitoring, or security tooling.
- No additional suspicious process, network, or persistence activity is found on the host.
- The server is patched or mitigated and a clean process baseline is re-established.
- Any malicious artifacts have been removed and the host has been validated by endpoint and server teams.

<br/>
---
<br/>

## Detection 3: Anomalous SharePoint Operations from Unexpected Source IPs Following ToolShell Activity

### Detection Opportunity

Fileless exploitation of SharePoint via ToolShell resulting in anomalous file access or administrative operations logged in OfficeActivity from unexpected client IPs.

### Intelligence Context

- Securelist: The SOC Files 5: Ghost in the pipeline, or a fileless SharePoint breach by Storm-2603 — [https://securelist.com/storm-2603-fileless-toolshell-attack/121467/](https://securelist.com/storm-2603-fileless-toolshell-attack/121467/)
  - Context: Storm-2603 conducted a fileless breach of SharePoint using ToolShell. OfficeActivity logs capture SharePoint-level operations including file access and administrative actions that may reflect post-exploitation activity even when no files are written to disk.

### Search Metadata

- CVEs: Not specified
- Threat actors: Storm-2603
- ATT&CK tags: T1213, T1190
- Products: SharePoint
- Platforms: Not specified
- Malware: Not specified
- Tools: ToolShell
- Search tags: Storm-2603, SharePoint, ToolShell, T1213, T1190

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Collection: T1213 Data from Information Repositories (medium); Initial Access: T1190 Exploit Public-Facing Application (low)

### Deployment Gates

- OfficeActivity requires the Microsoft 365 (Office 365) data connector to be enabled in Sentinel; without this connector the table is absent and the query produces no results.

**Required telemetry:**
- OfficeActivity

### KQL

```kql
let lookback = 30d;
let recentWindow = 3d;
let sensitiveOps = dynamic([
    "FileDownloaded", "FileSyncDownloadedFull", "SiteCollectionAdminAdded",
    "SitePermissionsModified", "ListItemsViewed", "SearchQueryPerformed",
    "FileAccessed", "FilePreviewed", "SharingInvitationCreated", "AddedToSecureLink"
]);
let historicIPs =
    OfficeActivity
    | where TimeGenerated between (ago(lookback) .. ago(recentWindow))
    | where Workload == "SharePoint"
    | where ClientIP != "" and ClientIP != "null"
    | summarize KnownIPs = make_set(ClientIP, 500) by UserId;
OfficeActivity
| where TimeGenerated >= ago(recentWindow)
| where Workload == "SharePoint"
| where Operation in (sensitiveOps)
| where ClientIP != "" and ClientIP != "null"
| join kind=leftouter historicIPs on UserId
| extend
    IsNewUser = isnull(KnownIPs),
    IsNewIP = isnull(KnownIPs) or not(set_has_element(KnownIPs, ClientIP))
| where IsNewIP == true
| summarize
    DistinctOperations = dcount(Operation),
    Operations = make_set(Operation, 20),
    SiteUrls = make_set(SiteUrl, 10),
    FileNames = make_set(SourceFileName, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by UserId, ClientIP, IsNewUser
| project
    FirstSeen,
    LastSeen,
    UserId,
    ClientIP,
    IsNewUser,
    DistinctOperations,
    Operations,
    SiteUrls,
    FileNames
| order by DistinctOperations desc, FirstSeen asc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Users accessing SharePoint from a new location such as travel, home office, or VPN exit node not previously used.
- SharePoint crawl accounts or indexing service accounts that operate from variable infrastructure IPs.
- Users whose ClientIP changes due to corporate proxy rotation or NAT pool changes.
- Newly onboarded users with no 30-day IP baseline who perform any sensitive SharePoint operation.

**Tuning notes:**
- Add a UserId exclusion list for known SharePoint service accounts, crawl accounts, and indexing identities to reduce persistent false positives.
- Consider adding a geo-enrichment step using the geo_info_from_ip_address() function to flag IPs from unexpected countries as a secondary signal.
- Reduce DistinctOperations threshold or add a minimum event count filter to surface only accounts performing multiple sensitive operations from the new IP, not single accidental accesses.
- Correlate results with SigninLogs on the same UserId and ClientIP within the same timeframe to confirm whether Entra ID also recorded a sign-in from the new IP, which would indicate interactive access rather than server-side exploitation.

**Risks / caveats:**
- OfficeActivity requires the Microsoft 365 (Office 365) data connector to be enabled in Sentinel; without this connector the table is absent and the query produces no results.
- ClientIP is frequently null or set to an internal proxy address for server-side SharePoint operations initiated by service accounts or crawl processes; this causes those events to be excluded from the new-IP detection logic.
- The 3-day recent window and 30-day baseline window should be validated against the environment's user behavior patterns before scheduling; environments with high user mobility may require a shorter baseline or additional geo-based filtering.
- Service accounts and SharePoint crawl accounts with variable IPs will generate persistent false positives until excluded by UserId allowlist.

### Triage Runbook

**First 15 minutes:**
- Check whether the UserId is a service account, crawl account, or known automation identity.
- Review the ClientIP, SiteUrl, Operation list, and DistinctOperations count to see if the activity is broad or targeted.
- Compare the source IP against the user's recent sign-in history and known corporate egress ranges.
- Determine whether the operations include sensitive actions such as permissions changes, downloads, or sharing events.

**Evidence to collect:**
- OfficeActivity records for the UserId: full operation history, SiteUrl, SourceFileName, OfficeObjectId, and timestamps.
- SigninLogs for the same UserId and ClientIP to confirm whether Entra ID also observed an interactive sign-in.
- Any SharePoint audit or admin logs showing permission changes, sharing invitations, or file access from the same timeframe.
- Geo/IP reputation context for the ClientIP, including whether it belongs to a VPN, proxy, or cloud provider.

**Pivot points:**
- OfficeActivity filtered on UserId and ClientIP to expand the activity set and identify related operations.
- SigninLogs for the same UserId and ClientIP to validate whether the IP is associated with a real sign-in.
- SharePoint admin/audit logs for permission changes, site collection admin changes, and sharing events.
- If available, DeviceProcessEvents on SharePoint servers to correlate with server-side exploitation activity.

**Benign explanations:**
- A user traveling, working from home, or using a new VPN exit node.
- A newly onboarded user with no meaningful 30-day IP baseline.
- SharePoint crawl, indexing, or service accounts that operate from variable infrastructure IPs.
- Corporate proxy or NAT rotation causing the ClientIP to differ from prior history.

**Escalation criteria:**
- The IP is external, untrusted, or associated with known malicious infrastructure.
- The user performed multiple sensitive operations from the new IP, especially permission or sharing changes.
- There is no matching legitimate sign-in and the activity aligns with post-exploitation collection or admin abuse.
- The same timeframe shows server-side SharePoint exploitation indicators on the host.

**Containment actions:**
- Disable or reset the affected account if compromise is likely and business impact is acceptable.
- Revoke active sessions and tokens for the user or service account.
- Block the source IP if it is clearly malicious and not a corporate VPN/proxy.
- Review and remove unauthorized SharePoint permissions, sharing links, or site collection admin assignments.

**Closure criteria:**
- The source IP is validated as an approved corporate, VPN, or service account address.
- The activity is explained by a documented business event, and no additional suspicious actions are present.
- No corroborating evidence of exploitation, persistence, or unauthorized access is found.
- Any unauthorized permissions or sharing changes have been reverted and verified.

<br/>
---
<br/>

## Detection 4: CVE-2023-20198 Exploitation Attempt Patterns in Cisco IOS Logs

### Detection Opportunity

Active exploitation attempts targeting Cisco IOS devices consistent with CVE-2023-20198, observed as HTTP-based privilege escalation patterns in network device logs.

### Intelligence Context

- SANS ISC: Vulnerability Scans for Older Cisco IOS Vulnerability / Opt-Out Headers, (Thu, Nov 5th) — [https://isc.sans.edu/diary/rss/33492](https://isc.sans.edu/diary/rss/33492)
  - Context: SANS ISC observed active exploitation attempts against Cisco IOS devices suspected to target CVE-2023-20198, a privilege escalation vulnerability in the IOS XE web UI. Scanning and exploitation activity was observed in the wild.

### Search Metadata

- CVEs: CVE-2023-20198
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Cisco IOS
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2023-20198, Cisco IOS, T1190

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- The keyword strings in the Message filter must be validated against actual Cisco IOS XE syslog output in the target environment before this query can be trusted to produce meaningful results; the exact syslog message format for CVE-2023-20198 exploitation events is not standardized across Cisco firmware versions.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where TimeGenerated >= ago(7d)
| where DeviceVendor has "Cisco"
| where DeviceProduct has_any ("IOS", "IOS XE", "ASA")
| where
    Message has "CVE-2023-20198"
    or Message has_all ("webui", "privilege")
    or Message has_all ("HTTP", "level 15")
    or Message has_all ("unauthorized", "webui")
    or Activity has "CVE-2023-20198"
| summarize
    AttemptCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    DestinationIPs = make_set(DestinationIP, 50),
    TargetDeviceCount = dcount(DestinationIP),
    SampleMessages = make_set(Message, 5),
    Activities = make_set(Activity, 10)
    by SourceIP, DeviceVendor, DeviceProduct
| where AttemptCount >= 3
| extend DurationMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| project
    FirstSeen,
    LastSeen,
    DurationMinutes,
    SourceIP,
    DeviceVendor,
    DeviceProduct,
    AttemptCount,
    TargetDeviceCount,
    DestinationIPs,
    Activities,
    SampleMessages
| order by AttemptCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Internal vulnerability scanners or network management systems that probe Cisco device web UIs as part of authorized assessments.
- Cisco device health monitoring tools that generate repeated HTTP authentication events against management interfaces.
- Unrelated Cisco log messages containing the word 'privilege' or 'webui' in a non-exploitation context.

**Tuning notes:**
- Run the query without the Message keyword filters first to enumerate all Cisco log messages in CommonSecurityLog, then identify the exact message strings produced by your Cisco IOS XE devices for web UI authentication events before refining the filter.
- Add SourceIP exclusions for known internal scanners and network management platforms using a let statement.
- If Cisco devices forward logs via a syslog aggregator rather than directly, confirm that the CEF header DeviceVendor and DeviceProduct fields are correctly populated by the aggregator's CEF mapping configuration.
- Consider correlating SourceIP values against threat intelligence watchlists or Microsoft Sentinel TI tables to prioritize external scanning sources.

**Risks / caveats:**
- CommonSecurityLog requires a CEF-compatible syslog forwarder and the Common Event Format connector in Sentinel; if Cisco devices are not configured to forward logs to this connector, the table will contain no Cisco records.
- The Message field content for Cisco IOS XE web UI events is syslog-format and vendor-specific; the keyword strings used in the query (e.g., 'HTTP Auth bypass', 'level 15', 'unauthorized user') may not match the exact syslog message text produced by Cisco IOS XE, causing the query to return zero results even when exploitation is occurring.
- DeviceProduct values for Cisco IOS XE in CommonSecurityLog depend on the CEF header set by the forwarding agent and may differ from 'IOS', 'IOS XE', or 'ASA' used in the filter; the actual DeviceProduct string must be confirmed against ingested records in the target environment.
- The keyword strings in the Message filter must be validated against actual Cisco IOS XE syslog output in the target environment before this query can be trusted to produce meaningful results; the exact syslog message format for CVE-2023-20198 exploitation events is not standardized across Cisco firmware versions.

### Triage Runbook

**First 15 minutes:**
- Confirm the affected device is a Cisco IOS/IOS XE system and that the log source is expected.
- Review the SourceIP, AttemptCount, and SampleMessages to determine whether this is scanning, probing, or a likely exploit attempt.
- Check whether the destination device is internet-facing and whether the activity is concentrated on one device or many.
- Look for any concurrent device alerts, configuration changes, or management-plane logins around the same time.

**Evidence to collect:**
- CommonSecurityLog entries for the SourceIP and DestinationIP pair, including full Message and Activity text.
- Device logs from the Cisco platform if available, especially web UI, authentication, and configuration events.
- Any management-plane access logs or AAA logs showing successful logins from the same SourceIP.
- Threat intelligence or firewall logs to determine whether the SourceIP is known malicious or part of a scan campaign.

**Pivot points:**
- CommonSecurityLog filtered on SourceIP and DestinationIP to expand the event set and identify other targeted devices.
- Cisco device syslog/AAA logs to confirm whether any authentication succeeded after the attempts.
- Firewall or proxy logs for the same SourceIP to identify broader scanning behavior.
- Threat intelligence tables or watchlists for the SourceIP reputation.

**Benign explanations:**
- Authorized vulnerability scanning or penetration testing from an internal scanner.
- Network management tools that legitimately probe the web UI or authentication endpoints.
- Misconfigured monitoring systems repeatedly checking device availability or login pages.
- Unrelated Cisco syslog messages that match the keyword pattern but are not exploit attempts.

**Escalation criteria:**
- The SourceIP is external, repeated, and targets multiple Cisco devices or multiple attempts on the same device.
- There is evidence of successful authentication, configuration change, or privilege escalation after the attempts.
- The device is internet-facing and not protected by compensating controls such as ACLs or management-plane restrictions.
- The activity is accompanied by other suspicious network or device telemetry indicating compromise.

**Containment actions:**
- Block the SourceIP at the perimeter if it is clearly malicious and not an approved scanner.
- Restrict management-plane access to trusted IP ranges and disable internet exposure if possible.
- Increase monitoring on the affected device and preserve logs for incident response.
- If compromise is suspected, follow network device incident response procedures to validate configuration integrity and credentials.

**Closure criteria:**
- The SourceIP is confirmed as an authorized scanner or benign monitoring source.
- No successful login, configuration change, or other compromise evidence is found on the device.
- The device logs are consistent with noise or false-positive keyword matches rather than exploitation.
- Compensating controls or filtering are documented to prevent repeat alerts from known benign sources.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Environment scope / baselines:**
- SharePoint Worker Process Spawning Anomalous Child Processes: Defender for Endpoint must be onboarded on SharePoint server hosts; if servers are not onboarded, DeviceProcessEvents will contain no records for those hosts and the query produces no results.

**Telemetry availability:**
- Anomalous SharePoint Operations from Unexpected Source IPs Following ToolShell Activity: OfficeActivity requires the Microsoft 365 (Office 365) data connector to be enabled in Sentinel; without this connector the table is absent and the query produces no results.

**Schema / correlation keys:**
- CVE-2023-20198 Exploitation Attempt Patterns in Cisco IOS Logs: The keyword strings in the Message filter must be validated against actual Cisco IOS XE syslog output in the target environment before this query can be trusted to produce meaningful results; the exact syslog message format for CVE-2023-20198 exploitation events is not standardized across Cisco firmware versions.

**Shared-table notes:**
- No major shared table dependency identified across this run.

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: OAuth App Authenticated Actions Following Credential Exposure; SharePoint Worker Process Spawning Anomalous Child Processes; Anomalous SharePoint Operations from Unexpected Source IPs Following ToolShell Activity.
2. Resolve environment-mapping detections next: CVE-2023-20198 Exploitation Attempt Patterns in Cisco IOS Logs.

### Hunting Agenda and Promotion Criteria

- CVE-2023-20198 Exploitation Attempt Patterns in Cisco IOS Logs: The keyword strings in the Message filter must be validated against actual Cisco IOS XE syslog output in the target environment before this query can be trusted to produce meaningful results; the exact syslog message format for CVE-2023-20198 exploitation events is not standardized across Cisco firmware versions.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
