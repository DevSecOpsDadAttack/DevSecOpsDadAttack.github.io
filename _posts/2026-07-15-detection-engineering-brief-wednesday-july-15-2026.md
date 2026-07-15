---
layout: post
title: "Detection Engineering Brief - Wednesday, July 15, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-15
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-55040
  - T1190
  - Microsoft SharePoint
  - ShinyHunters
  - Windows
  - OkoBot
  - Rilide
  - TookPS
  - Linux
  - TuxBot v3
  - T1098
  - T1098.003
  - T1176
  - T1059
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

2 production candidates, 3 hunting-only, 0 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-55040, T1190, Microsoft SharePoint, ShinyHunters, Windows, OkoBot, Rilide, TookPS, Linux, TuxBot v3, T1098, T1098.003, T1176, T1059.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Anomalous SharePoint Access Without Prior Authentication Event - CVE-2026-55040 Auth Bypass; Suspicious Process Writing Files to Chromium Extension Storage Directories - OkoBot Dropper Behavior; ELF Binary Executed from World-Writable Directory on Linux Host - TuxBot Deployment Pattern.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: SharePoint Worker Process Spawning Suspicious Child Process - CVE-2026-55040 RCE

### Detection Opportunity

SharePoint IIS worker process w3wp.exe spawning command interpreter or scripting engine as a child process, consistent with unauthenticated RCE via chained JWT authentication bypass.

### Intelligence Context

- Rapid7: CVE-2026-55040: Microsoft SharePoint JWT Token Authentication Bypass (FIXED) — [https://www.rapid7.com/blog/post/ve-cve-2026-55040-microsoft-sharepoint-jwt-token-authentication-bypass-fixed](https://www.rapid7.com/blog/post/ve-cve-2026-55040-microsoft-sharepoint-jwt-token-authentication-bypass-fixed)
  - Context: Rapid7 reported that CVE-2026-55040 can be chained with a second vulnerability to achieve unauthenticated RCE against SharePoint servers. The RCE path runs through the IIS worker process, making w3wp.exe spawning shells a high-fidelity indicator.

### Search Metadata

- CVEs: CVE-2026-55040
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Microsoft SharePoint
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-55040, T1190, Microsoft SharePoint

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ (
    "cmd.exe",
    "powershell.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "msiexec.exe",
    "rundll32.exe"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    AccountDomain,
    LogonId,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    FileName,
    ProcessCommandLine,
    SHA256
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Other IIS-hosted applications on the same host that legitimately invoke cmd.exe or powershell.exe during normal operation (e.g., custom web applications with shell-out logic).
- Automated deployment or health-check scripts running under the IIS application pool identity.
- certutil.exe invocations from legitimate certificate management workflows hosted in IIS.

**Tuning notes:**
- Scope DeviceName to known SharePoint server hostnames using a watchlist or a static list to reduce noise from other IIS workloads.
- Consider adding InitiatingProcessCommandLine contains '-ap' or contains 'sharepoint' as an additional signal to increase confidence that w3wp.exe is the SharePoint application pool.
- Extend lookback to 7 days for retrospective hunting across the CVE-2026-55040 patch gap period.
- Allowlist known-good child process invocations by combining FileName and ProcessCommandLine patterns specific to your environment.

**Risks / caveats:**
- Without scoping DeviceName to known SharePoint server hostnames, the rule will fire on any IIS-hosted application that spawns these child processes. Maintaining a SharePoint server hostname list (via watchlist or dynamic group) is recommended.
- The 24-hour lookback window may miss exploitation that occurred before onboarding or during a log ingestion gap. Extend to 7 days for retrospective hunting during the patch gap period.
- certutil.exe and bitsadmin.exe generate false positives in environments with active certificate lifecycle management or BITS-based software distribution. Baseline these before enabling alerting.
- msiexec.exe spawned from w3wp.exe may occur in environments with web-based installer workflows; validate against known deployment patterns before treating as high-confidence.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a SharePoint server and not another IIS workload; check DeviceName against your SharePoint server inventory.
- Review the parent and child process command lines for obvious attacker tradecraft such as cmd.exe /c, powershell -enc, mshta, certutil, bitsadmin, or rundll32 loading a remote or unusual path.
- Check whether the child process hash is known-good in your environment and whether the account context is the SharePoint application pool or an unexpected identity.
- Look for nearby process activity from the same host within the last hour, especially archive tools, downloaders, credential access tools, or additional script interpreters.
- If the command line or hash is suspicious, treat this as likely web exploitation and move immediately to host scoping and containment.

**Evidence to collect:**
- w3wp.exe parent command line, including application pool name and site context.
- Full child process command line, SHA256, and any subsequent child processes spawned by that process.
- Device timeline around the alert time, including network connections, file writes, and service creation.
- SharePoint/IIS logs for the same timestamp window, including the request path, source IP, and HTTP status codes.
- Any related sign-in, authentication, or admin activity on the server account or adjacent management accounts.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and LogonId to find additional child processes from w3wp.exe.
- DeviceNetworkEvents on the same host to identify outbound connections after the suspicious spawn.
- DeviceFileEvents on the same host for new files written in web directories, temp paths, or system locations.
- IIS/SharePoint logs to correlate the request that preceded the process spawn.
- Threat intelligence or internal hash reputation lookups for the child process SHA256.

**Benign explanations:**
- A legitimate SharePoint custom application or plugin may shell out to a script or installer during maintenance.
- Automated deployment, health-check, or certificate management tasks may run under the IIS application pool identity.
- Some web applications hosted on IIS legitimately invoke certutil, msiexec, or scripting engines for admin workflows.

**Escalation criteria:**
- The child process is cmd.exe, powershell.exe, mshta.exe, wscript.exe, cscript.exe, certutil.exe, bitsadmin.exe, msiexec.exe, or rundll32.exe with suspicious arguments.
- The host shows additional post-exploitation behavior such as new services, scheduled tasks, credential dumping, or outbound C2 traffic.
- The SharePoint server is internet-facing and the process spawn aligns with a suspicious external request or unexplained authentication bypass.
- The child process hash is unknown or malicious, or the command line references remote content, encoded payloads, or dropped files.

**Containment actions:**
- Isolate the SharePoint server from the network if exploitation appears active or if you observe follow-on payload execution.
- Preserve volatile evidence before rebooting, including running processes, network connections, and memory if your process allows it.
- Disable or restrict external access to the affected SharePoint service until patching and scoping are complete.
- Block any confirmed malicious hashes, domains, or IPs identified during triage across endpoint and network controls.

**Closure criteria:**
- The process spawn is confirmed as a documented SharePoint maintenance or application workflow and no other suspicious activity is present.
- The child process hash and command line match an approved administrative or deployment pattern on that server.
- No corroborating evidence exists in IIS logs, network telemetry, or subsequent endpoint activity after review.
- The host is patched or otherwise protected and the event is attributed to a known-good SharePoint workload.

<br/>
---
<br/>

## Detection 2: Anomalous SharePoint Access Without Prior Authentication Event - CVE-2026-55040 Auth Bypass

### Detection Opportunity

Successful SharePoint operations recorded in OfficeActivity from external IPs where no corresponding successful Entra ID sign-in event exists within a short preceding window, consistent with JWT token authentication bypass.

### Intelligence Context

- Rapid7: CVE-2026-55040: Microsoft SharePoint JWT Token Authentication Bypass (FIXED) — [https://www.rapid7.com/blog/post/ve-cve-2026-55040-microsoft-sharepoint-jwt-token-authentication-bypass-fixed](https://www.rapid7.com/blog/post/ve-cve-2026-55040-microsoft-sharepoint-jwt-token-authentication-bypass-fixed)
  - Context: CVE-2026-55040 bypasses JWT token authentication in SharePoint, meaning an attacker may produce successful SharePoint access log entries without a legitimate Entra ID authentication event preceding them. Correlating OfficeActivity against SigninLogs surfaces this gap.

### Search Metadata

- CVEs: CVE-2026-55040
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Microsoft SharePoint
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-55040, T1190, Microsoft SharePoint

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- OfficeActivity, SigninLogs

### KQL

```kql
let sharepoint_access = OfficeActivity
| where TimeGenerated > ago(1d)
| where OfficeWorkload == "SharePoint"
| where ResultStatus =~ "Succeeded"
| extend CompositeKey = strcat(tolower(UserId), "|", ClientIP)
| project SPTime = TimeGenerated, UserId, ClientIP, Operation, SiteUrl, CompositeKey;
let interactive_signins = SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0
| extend CompositeKey = strcat(tolower(UserPrincipalName), "|", IPAddress)
| project CompositeKey, AppDisplayName, ConditionalAccessStatus, AuthenticationRequirement;
let noninteractive_signins = AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0
| extend CompositeKey = strcat(tolower(UserPrincipalName), "|", IPAddress)
| project CompositeKey;
let all_signins = interactive_signins
| union (noninteractive_signins | extend AppDisplayName = "", ConditionalAccessStatus = "", AuthenticationRequirement = "")
| summarize
    AppDisplayName = take_any(AppDisplayName),
    ConditionalAccessStatus = take_any(ConditionalAccessStatus),
    AuthenticationRequirement = take_any(AuthenticationRequirement)
    by CompositeKey;
sharepoint_access
| join kind=leftanti all_signins on CompositeKey
| project SPTime, UserId, ClientIP, Operation, SiteUrl
| order by SPTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Service accounts and managed identities accessing SharePoint via application permissions that do not generate user sign-in log entries.
- Users accessing SharePoint via cached or refreshed tokens where the original sign-in occurred outside the 1-day lookback window.
- SharePoint mobile app or sync client sessions that authenticate via device-bound tokens not reflected in SigninLogs.
- IP address mismatches caused by NAT, proxy, or CDN infrastructure between the SharePoint access log and the sign-in log.

**Tuning notes:**
- Add a filter excluding known service account and automation UPN patterns from UserId before promoting to scheduled alert.
- Consider extending the sign-in lookback window to 2 days while keeping the SharePoint access window at 1 day to account for long-lived token sessions.
- Validate that AADNonInteractiveUserSignInLogs is available in the workspace before relying on it to suppress false positives.
- If IP normalization mismatches are observed, apply tostring(parse_ipv4(ClientIP)) normalization to both sides of the join key.

**Risks / caveats:**
- The leftanti join on two simultaneous key columns ($left.UserId == $right.UserPrincipalName, $left.ClientIP == $right.IPAddress) is not valid KQL syntax for leftanti joins. The corrected approach uses a composite key via strcat or a sequential join pattern.
- SigninLogs ResultType == 0 covers only interactive sign-ins. Non-interactive sign-ins are in AADNonInteractiveUserSignInLogs, which is a separate table. Absence of a record in SigninLogs alone does not confirm authentication bypass.
- OfficeActivity ingestion from SharePoint Online requires the Office 365 connector to be enabled in Microsoft Sentinel. If the connector is not configured, this query returns no results.
- AADNonInteractiveUserSignInLogs may not be enabled in all Sentinel deployments. If absent, the query falls back to interactive SigninLogs only, increasing false-positive volume.

### Triage Runbook

**First 15 minutes:**
- Validate the user, IP, and site URL in OfficeActivity and confirm whether the activity is expected for that account.
- Check SigninLogs and AADNonInteractiveUserSignInLogs for the same user and source IP across a wider time window than the alert used.
- Review whether the account is a guest, service account, sync client, mobile client, or automation identity that may not produce a matching interactive sign-in.
- Inspect ConditionalAccessStatus and AuthenticationRequirement to see whether the access path was interactive, non-interactive, or exempted.
- If the access is from an external IP and the user has no plausible sign-in history, escalate for exploitation review.

**Evidence to collect:**
- OfficeActivity record details: operation, site URL, user ID, client IP, and timestamp.
- Matching or near-matching entries from SigninLogs and AADNonInteractiveUserSignInLogs for the same identity and IP.
- Conditional Access and authentication requirement details for the user session.
- Tenant context for the account type, including whether it is guest, service, or managed identity related.
- Any related audit events showing consent, mailbox access, file downloads, or permission changes around the same time.

**Pivot points:**
- OfficeActivity for the same UserId over the last 24-72 hours to identify broader SharePoint usage patterns.
- SigninLogs and AADNonInteractiveUserSignInLogs for the same UserPrincipalName and IPAddress over an extended window.
- AuditLogs for changes to the user, guest account, or application permissions.
- Entra ID risk and conditional access records for the account if available.
- Proxy, VPN, or NAT logs to determine whether the source IP is shared or translated.

**Benign explanations:**
- The user may have a valid non-interactive or token-refresh session that does not appear in SigninLogs.
- The activity may come from a mobile app, sync client, or cached session with a sign-in outside the alert window.
- IP mismatches can occur because of NAT, proxy, CDN, or logging latency between data sources.
- Service principals or workload identities can generate SharePoint activity without a corresponding user sign-in.

**Escalation criteria:**
- The same user performs sensitive SharePoint actions from an external IP with no matching interactive or non-interactive sign-in.
- Multiple users or sites show the same pattern from the same source IP, suggesting active exploitation.
- The account is a guest or external identity and the activity is not consistent with normal collaboration behavior.
- You find corroborating evidence of exploitation, such as suspicious process execution on a SharePoint server or unusual admin activity.

**Containment actions:**
- If exploitation is credible, disable or block the affected account and revoke active sessions.
- Restrict access to the affected SharePoint site or external exposure until the investigation is complete.
- Coordinate with identity administrators to review conditional access, guest access, and token revocation as needed.
- Preserve relevant audit and sign-in logs before they age out.

**Closure criteria:**
- A valid interactive or non-interactive sign-in is found that explains the SharePoint activity.
- The event is attributable to a known service, sync, or mobile workflow with supporting tenant evidence.
- IP normalization, NAT, or ingestion latency explains the mismatch and no other suspicious activity is present.
- No additional anomalous SharePoint or identity activity is found after extended review.

<br/>
---
<br/>

## Detection 3: OAuth Consent Grant to Unrecognized Application by Guest Account - ShinyHunters SaaS Abuse

### Detection Opportunity

Guest or external user accounts granting OAuth consent to newly registered or unrecognized applications in Entra ID, consistent with ShinyHunters abusing misconfigured guest access and OAuth to gain persistent SaaS access.

### Intelligence Context

- Microsoft Security Blog: Defending SaaS-based applications against ShinyHunters OAuth abuse — [https://www.microsoft.com/en-us/security/blog/2026/07/13/defending-saas-based-applications-against-shinyhunters-oauth-abuse/](https://www.microsoft.com/en-us/security/blog/2026/07/13/defending-saas-based-applications-against-shinyhunters-oauth-abuse/)
  - Context: Microsoft attributed OAuth abuse and exploitation of misconfigured guest access in SaaS environments to ShinyHunters. The actor grants OAuth consent to attacker-controlled applications to establish persistent access, often leveraging guest accounts that lack conditional access enforcement.

### Search Metadata

- CVEs: Not specified
- Threat actors: ShinyHunters
- ATT&CK tags: T1098, T1098.003
- Products: Not specified
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: ShinyHunters, T1098, T1098.003

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1098 Account Manipulation/ T1098.003 Additional Cloud Roles (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- AuditLogs, SigninLogs

### KQL

```kql
let known_apps = AuditLogs
| where TimeGenerated between (ago(30d) .. ago(1d))
| where OperationName =~ "Consent to application"
| where Category =~ "ApplicationManagement"
| extend AppId = tostring(TargetResources[0].id)
| where isnotempty(AppId)
| summarize by AppId;
AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName =~ "Consent to application"
| where Category =~ "ApplicationManagement"
| extend InitiatorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatorIP = tostring(InitiatedBy.user.ipAddress)
| extend AppId = tostring(TargetResources[0].id)
| extend AppName = tostring(TargetResources[0].displayName)
| extend ResultDescription = tostring(ResultDescription)
| where isnotempty(InitiatorUPN)
| where InitiatorUPN has "#EXT#" or tolower(InitiatorUPN) has "guest"
| join kind=leftanti known_apps on AppId
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(1d)
    | where UserType =~ "Guest"
    | where ResultType == 0
    | project UserPrincipalName, ConditionalAccessStatus, IPAddress
    | summarize
        ConditionalAccessStatus = take_any(ConditionalAccessStatus)
        by UserPrincipalName, IPAddress
) on $left.InitiatorUPN == $right.UserPrincipalName
| project
    TimeGenerated,
    InitiatorUPN,
    InitiatorIP,
    AppId,
    AppName,
    ConditionalAccessStatus,
    ResultDescription,
    CorrelationId
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate partner or vendor guest accounts consenting to newly onboarded SaaS applications that have not yet appeared in the 30-day baseline.
- Guest accounts from organizations that recently joined a federated tenant where their application consents have no prior history in this tenant.
- Newly registered internal applications that were created within the last 30 days and are being consented to by guest accounts for legitimate collaboration purposes.

**Tuning notes:**
- Extend the known_apps baseline window to 90 days in tenants with large volumes of legitimate new application registrations to reduce false positives.
- Add a filter excluding known sanctioned application IDs using a watchlist or static list of approved AppId values.
- Add InitiatorIP against known corporate egress IP ranges to prioritize external consent grants from unexpected locations.
- Consider adding a filter on ResultDescription to exclude failed consent attempts and focus on successful grants only.

**Risks / caveats:**
- TargetResources is a dynamic array in AuditLogs. The fields TargetResources[0].id and TargetResources[0].displayName are standard for consent grant operations but may be null if the audit event schema differs for delegated versus admin consent operations. Validate that AppId and AppName are populated for the specific consent operation types in your tenant.
- The 30-day baseline window will not capture applications that were consented to more than 30 days ago but have not been consented to recently. Applications with infrequent but legitimate consent cycles may appear as new.
- The #EXT# filter relies on Entra ID's standard guest UPN convention. Tenants with custom guest UPN formats or B2B direct connect configurations may not match this filter.
- The SigninLogs leftouter join matches on UPN only (not time-bounded to the consent event) due to the complexity of time-range joins in this pattern. A guest account with any successful sign-in in the last day will have ConditionalAccessStatus populated, which may not reflect the session at consent time.

### Triage Runbook

**First 15 minutes:**
- Identify the guest account, application ID, application name, and consent outcome from the alert.
- Check whether the application is sanctioned, recently registered, or has a suspicious publisher, name, or permission set.
- Review the guest account's recent sign-ins, location, and conditional access status to determine whether the consent came from an unexpected context.
- Look for evidence of mailbox, file, or SaaS access by the application immediately after consent.
- If the app is unrecognized or requests high-risk permissions, treat this as a likely persistence event and escalate.

**Evidence to collect:**
- AuditLogs consent event details, including InitiatedBy, TargetResources, ResultDescription, and CorrelationId.
- Application permissions granted, especially offline_access, Mail.Read, Files.Read, Sites.Read.All, or directory-related scopes.
- Guest account sign-in history, IP address, and Conditional Access status around the consent time.
- App registration metadata such as publisher, creation time, and whether it is multi-tenant or newly created.
- Any subsequent activity by the app or guest account in Exchange, SharePoint, Teams, or other SaaS logs.

**Pivot points:**
- AuditLogs for other consent grants, app role assignments, or application management events involving the same app or user.
- SigninLogs for the guest account and any related app sign-ins after consent.
- Service principal and enterprise application inventory to determine whether the app is known and approved.
- Mailbox, SharePoint, and other SaaS audit logs for activity tied to the app or guest account.
- Entra ID application consent and permission review records if available.

**Benign explanations:**
- A legitimate partner or vendor guest may be onboarding a new approved SaaS application.
- A newly created internal application may not yet exist in the 30-day baseline.
- Some collaboration workflows legitimately require guest consent in tenants that permit it.
- The app may be approved but not yet added to the allowlist or baseline.

**Escalation criteria:**
- The app requests broad or high-risk permissions, especially offline access or directory-wide access.
- The guest account is unexpected, recently created, or signs in from a suspicious location.
- The app is newly registered, unverified, or impersonates a common business service.
- You observe post-consent access to mail, files, or SaaS resources that is not consistent with normal collaboration.

**Containment actions:**
- Revoke the OAuth consent and disable or remove the enterprise application if it is unauthorized.
- Disable the guest account or revoke its sessions if the account is compromised or abused.
- Block the application ID or publisher if your tenant supports application blocking controls.
- Review and tighten guest consent and user consent settings if abuse is confirmed.

**Closure criteria:**
- The application is confirmed as sanctioned and the consent is tied to a legitimate business workflow.
- The guest account and app activity are consistent with approved collaboration and no risky permissions were granted.
- No suspicious post-consent activity is observed in SaaS audit logs or sign-in logs.
- The event is documented and the app is added to the approved baseline or allowlist as appropriate.

<br/>
---
<br/>

## Detection 4: Suspicious Process Writing Files to Chromium Extension Storage Directories - OkoBot Dropper Behavior

### Detection Opportunity

Non-browser processes writing executable or script files into Chromium browser extension directories under AppData, consistent with OkoBot installing the Rilide stealer as a malicious browser extension.

### Intelligence Context

- Securelist: OkoBot: new sophisticated malware framework targets cryptocurrency users — [https://securelist.com/okobot-framework-targets-cryptocurrency-wallets/120660/](https://securelist.com/okobot-framework-targets-cryptocurrency-wallets/120660/)
  - Context: Securelist reported that OkoBot installs additional malware strains including the Rilide browser stealer. Rilide operates as a Chromium extension to monitor browser activity and exfiltrate cryptocurrency wallet data. The dropper writes extension components into Chromium AppData paths.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1176, T1059
- Products: Not specified
- Platforms: Windows
- Malware: OkoBot, Rilide
- Tools: TookPS
- Search tags: Windows, OkoBot, Rilide, TookPS, T1176, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Persistence: T1176 Browser Session Hijacking (medium); Execution: T1059 Command and Scripting Interpreter (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let extension_writes = DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_all ("AppData", "Extensions")
| where FolderPath has_any ("Google\\Chrome", "Microsoft\\Edge", "BraveSoftware", "Chromium")
| where ActionType in ("FileCreated", "FileModified")
| where FileName has_any (".js", ".json", ".html", ".crx", ".dll", ".exe")
| where InitiatingProcessFileName !in~ (
    "chrome.exe",
    "msedge.exe",
    "brave.exe",
    "chromium.exe",
    "setup.exe",
    "installer.exe"
)
| project
    WriteTime = Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    FolderPath,
    WrittenFileSHA256 = SHA256;
let exec_events = DeviceProcessEvents
| where Timestamp > ago(7d)
| project
    ExecTime = Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    ExecSHA256 = SHA256;
extension_writes
| join kind=leftouter (
    exec_events
) on DeviceName, AccountName, FileName
| where isempty(ExecTime) or ExecTime between (WriteTime .. (WriteTime + 10m))
| project
    WriteTime,
    ExecTime,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    FolderPath,
    WrittenFileSHA256,
    ProcessCommandLine,
    ExecSHA256
| order by WriteTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Enterprise software deployment tools (SCCM, Intune, custom installers) writing browser extension policy files to managed extension directories.
- Browser update processes using intermediate installer executables not covered by the exclusion list.
- Developer workstations where extension development tools write to local extension directories during testing.
- Antivirus or EDR products scanning and touching files in extension directories.

**Tuning notes:**
- Add enterprise deployment tool process names to the InitiatingProcessFileName exclusion list for managed environments.
- Replace has_any extension string matching with a series of endswith_cs conditions for stricter file type filtering.
- Narrow the join time window from 10 minutes if the environment shows high noise from legitimate extension update cycles.
- Consider adding a DeviceName scoping filter to exclude known developer workstations or test machines.

**Risks / caveats:**
- FolderPath in DeviceProcessEvents represents the directory containing the process image file, not a working directory or launch path. Filtering DeviceProcessEvents on extension directory paths will only match if the process binary itself resides in the extension directory, which is uncommon for standard executables. The improved query removes this filter from DeviceProcessEvents and instead joins on the specific written FileName to track execution of the dropped file.
- The FileName join between DeviceFileEvents and DeviceProcessEvents will match any process with the same filename executed on the same device and account within the time window, not necessarily the specific file instance written to the extension directory. This can produce false correlations if a common filename (e.g., update.exe) is both written to an extension directory and executed from a different path.
- The file type filter using has_any with extension strings may match filenames that contain the extension string in the middle of the name rather than as a suffix. Consider using endswith_cs for stricter matching if noise is observed.
- The 7-day lookback window may generate large result sets in environments with active browser extension management. Consider narrowing to 24-48 hours for scheduled hunting runs.

### Triage Runbook

**First 15 minutes:**
- Identify the initiating process and confirm it is not a known browser, installer, or enterprise deployment tool.
- Review the written file names, extensions, and hashes to see whether they resemble extension payloads such as .js, .json, .html, .crx, .dll, or .exe.
- Check whether the same device later executed the written file or whether a browser process loaded the extension directory.
- Look for related browser credential theft, wallet activity, or suspicious network connections from the same host.
- If the initiating process is unknown or the file content is clearly malicious, escalate for endpoint containment.

**Evidence to collect:**
- Full file write details: path, filename, hash, timestamp, and initiating process command line.
- Any matching process execution events for the same file name and device.
- Browser extension inventory and recent extension install or update events on the host.
- Network connections from the host after the file write, especially to unfamiliar domains or IPs.
- User context and recent software installation activity on the device.

**Pivot points:**
- DeviceFileEvents for additional writes to Chromium extension directories on the same host and account.
- DeviceProcessEvents for execution of the same file name or related child processes.
- DeviceNetworkEvents for outbound traffic from the host after the write event.
- Browser-related logs or extension management data if available in your environment.
- Threat intelligence lookups for the written file hashes and any associated filenames.

**Benign explanations:**
- Enterprise software deployment or browser management tools may write extension policy or package files.
- Developer workstations may legitimately create extension files during testing.
- Browser update or installer processes not covered by the exclusion list may write to extension paths.
- Security tools may touch files in extension directories during scanning.

**Escalation criteria:**
- The writer is an unknown process or a script host with suspicious command-line arguments.
- The written files are later executed or loaded by a browser and are not part of a known extension workflow.
- The host shows credential theft, wallet theft, or suspicious outbound connections after the write.
- The same pattern appears on multiple endpoints, suggesting a broader campaign.

**Containment actions:**
- Isolate the endpoint if the written files are confirmed malicious or if browser credential theft is suspected.
- Remove the malicious extension or files only after preserving evidence and confirming the scope.
- Reset affected browser and SaaS credentials if the host likely exposed session data or tokens.
- Block the initiating process hash and any confirmed malicious network indicators.

**Closure criteria:**
- The file writes are attributable to a known browser management, installer, or development workflow.
- The written files are benign extension components and no suspicious execution or network activity follows.
- The host has no evidence of browser credential theft, malicious extension loading, or related malware behavior.
- The event is documented and the process/file pattern is added to an allowlist if appropriate.

<br/>
---
<br/>

## Detection 5: ELF Binary Executed from World-Writable Directory on Linux Host - TuxBot Deployment Pattern

### Detection Opportunity

Execution of ELF binaries written to temporary or world-writable directories on Linux hosts, consistent with TuxBot v3 deploying cross-compiled botnet binaries for C2 enrollment.

### Intelligence Context

- Unit 42: TuxBot v3: Inside an IoT Botnet Framework With LLM-Assisted Development — [https://unit42.paloaltonetworks.com/tuxbot-v3-evolution-iot-botnet/](https://unit42.paloaltonetworks.com/tuxbot-v3-evolution-iot-botnet/)
  - Context: Unit 42 reported that TuxBot v3 uses cross-compiled ELF binaries deployed to Linux and IoT targets. The binaries are written to writable directories and executed to enroll the host in the botnet C2 infrastructure. Detection relies on observing file writes to temp paths followed by execution.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059
- Products: Not specified
- Platforms: Linux
- Malware: TuxBot v3
- Tools: Not specified
- Search tags: Linux, TuxBot v3, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let writable_drops = DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/run/")
| where ActionType == "FileCreated"
| where not (
    FileName endswith ".log"
    or FileName endswith ".pid"
    or FileName endswith ".lock"
    or FileName endswith ".tmp"
    or FileName endswith ".swp"
)
| project
    DropTime = Timestamp,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    DroppedFileSHA256 = SHA256;
let exec_events = DeviceProcessEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/run/")
| project
    ExecTime = Timestamp,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    ExecSHA256 = SHA256;
writable_drops
| join kind=inner exec_events on DeviceName, AccountName, FileName, FolderPath
| where ExecTime between (DropTime .. (DropTime + 5m))
| project
    DropTime,
    ExecTime,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    FolderPath,
    DroppedFileSHA256,
    ProcessCommandLine,
    ExecSHA256
| order by DropTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Package managers (apt, yum, dnf, rpm) writing and executing binaries in temporary directories during installation or upgrade workflows.
- CI/CD pipeline agents (Jenkins, GitLab Runner, GitHub Actions) writing and executing build artifacts in /tmp or /var/tmp.
- Container runtime processes writing and executing binaries in world-writable paths during container initialization.
- Legitimate system administration scripts that download and execute tools in /tmp for one-time maintenance tasks.

**Tuning notes:**
- Add known package manager process names (apt, apt-get, yum, dnf, rpm, dpkg) to an exclusion filter on InitiatingProcessFileName to suppress installation noise.
- Add known CI/CD agent process names to the InitiatingProcessFileName exclusion list for environments with automated build pipelines.
- Extend the join time window from 5 minutes to 15 minutes if staged deployment patterns are observed in threat intelligence for TuxBot v3.
- Validate that DeviceFileEvents is populated for Linux hosts in the environment by running a count query scoped to known Linux DeviceName values before relying on this detection.

**Risks / caveats:**
- DeviceFileEvents and DeviceProcessEvents coverage for Linux hosts depends on the Microsoft Defender for Endpoint Linux agent being deployed and the fanotify-based file monitoring being active. Hosts running unsupported Linux kernel versions or distributions may not generate file creation events in these tables, causing the query to silently miss activity on those hosts.
- MDE Linux agent telemetry coverage must be validated for each Linux distribution and kernel version in the environment before relying on this query. Hosts without active fanotify-based monitoring will not generate DeviceFileEvents entries.
- IoT devices and unmanaged Linux hosts are not covered by this query. TuxBot v3 targets on these devices will not be detected.
- The 5-minute join window may miss TuxBot deployments that use a staged execution pattern with a longer delay between drop and execution.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a managed Linux server and identify the user and process that created and executed the binary.
- Review the file path, filename, hash, and command line to determine whether the binary was staged in /tmp, /var/tmp, /dev/shm, /run/shm, or /run.
- Check for immediate follow-on activity such as outbound connections, persistence changes, or additional binaries dropped in the same directory.
- Look for package manager, CI/CD, or admin maintenance activity that could explain the drop-and-execute sequence.
- If the binary is unknown or the host shows network beaconing, treat this as likely compromise and escalate.

**Evidence to collect:**
- Dropped file path, SHA256, and the initiating process command line.
- Execution command line, parent process, and any child processes spawned by the ELF binary.
- Network connections from the host after execution, including destination IPs and ports.
- System logs for user logins, cron changes, service creation, or shell history around the event.
- Any additional file writes in the same writable directory that may indicate staging or persistence.

**Pivot points:**
- DeviceFileEvents for other files created in the same writable directory on the same host.
- DeviceProcessEvents for the same SHA256, filename, or parent process across Linux hosts.
- DeviceNetworkEvents for outbound traffic from the host after execution.
- Linux auth, syslog, cron, and service management logs if available.
- Threat intelligence or sandbox results for the ELF hash.

**Benign explanations:**
- Package managers may stage and execute binaries in temporary directories during installation or upgrades.
- CI/CD agents may execute build artifacts from /tmp or /var/tmp.
- Administrators may temporarily download and run maintenance tools from writable paths.
- Container initialization or runtime workflows can create short-lived binaries in world-writable locations.

**Escalation criteria:**
- The binary hash is unknown or malicious, or the command line indicates downloader, bot, or persistence behavior.
- The host makes suspicious outbound connections or begins scanning, beaconing, or lateral movement.
- The same pattern appears on multiple Linux hosts, suggesting a coordinated deployment.
- There is no credible operational explanation from package management, CI/CD, or admin activity.

**Containment actions:**
- Isolate the Linux host if the binary is malicious or if active beaconing is observed.
- Preserve the dropped binary and relevant logs before remediation.
- Terminate the malicious process and remove persistence only after evidence capture.
- Block confirmed malicious hashes and network indicators across the environment.

**Closure criteria:**
- The execution is explained by a known package manager, CI/CD pipeline, or approved admin workflow.
- The binary hash and command line match a sanctioned tool or maintenance action.
- No suspicious network, persistence, or lateral movement activity is found after review.
- The host is monitored for recurrence and no additional related events occur.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- Anomalous SharePoint Access Without Prior Authentication Event - CVE-2026-55040 Auth Bypass: Do not schedule yet; validate as an analyst-led hunt first.
- Suspicious Process Writing Files to Chromium Extension Storage Directories - OkoBot Dropper Behavior: Do not schedule yet; validate as an analyst-led hunt first.
- ELF Binary Executed from World-Writable Directory on Linux Host - TuxBot Deployment Pattern: Do not schedule yet; validate as an analyst-led hunt first.

**Other deployment dependency:**
- ELF Binary Executed from World-Writable Directory on Linux Host - TuxBot Deployment Pattern: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Shared-table notes:**
- DeviceProcessEvents: shared by SharePoint Worker Process Spawning Suspicious Child Process - CVE-2026-55040 RCE; Suspicious Process Writing Files to Chromium Extension Storage Directories - OkoBot Dropper Behavior; ELF Binary Executed from World-Writable Directory on Linux Host - TuxBot Deployment Pattern
- SigninLogs: shared by Anomalous SharePoint Access Without Prior Authentication Event - CVE-2026-55040 Auth Bypass; OAuth Consent Grant to Unrecognized Application by Guest Account - ShinyHunters SaaS Abuse
- DeviceFileEvents: shared by Suspicious Process Writing Files to Chromium Extension Storage Directories - OkoBot Dropper Behavior; ELF Binary Executed from World-Writable Directory on Linux Host - TuxBot Deployment Pattern

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: SharePoint Worker Process Spawning Suspicious Child Process - CVE-2026-55040 RCE; OAuth Consent Grant to Unrecognized Application by Guest Account - ShinyHunters SaaS Abuse.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Anomalous SharePoint Access Without Prior Authentication Event - CVE-2026-55040 Auth Bypass; Suspicious Process Writing Files to Chromium Extension Storage Directories - OkoBot Dropper Behavior; ELF Binary Executed from World-Writable Directory on Linux Host - TuxBot Deployment Pattern.

### Hunting Agenda and Promotion Criteria

- Anomalous SharePoint Access Without Prior Authentication Event - CVE-2026-55040 Auth Bypass: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Suspicious Process Writing Files to Chromium Extension Storage Directories - OkoBot Dropper Behavior: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- ELF Binary Executed from World-Writable Directory on Linux Host - TuxBot Deployment Pattern: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
