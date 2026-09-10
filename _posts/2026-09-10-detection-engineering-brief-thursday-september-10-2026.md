---
layout: post
title: "Detection Engineering Brief - Thursday, September 10, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-10
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Microsoft Entra ID
  - SharePoint
  - OneDrive
  - Exchange Online
  - Microsoft Graph
  - Windows
  - T1098
  - T1098.001
  - T1087
  - T1087.004
  - T1059
  - T1036
  - T1059.001
  - T1068
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

3 production candidates, 2 hunting-only, 0 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Microsoft Entra ID, SharePoint, OneDrive, Exchange Online, Microsoft Graph, Windows, T1098, T1098.001, T1087, T1087.004, T1059, T1036, T1059.001, T1068.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Browser Process Spawning Scripting Engine or Dropping Executable to Temp Path; Low-Privilege Process Spawning High-Integrity Child Process Indicative of ALPC EoP Exploitation.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: MFA Method Registration Following Risky or Atypical Sign-In

### Detection Opportunity

Threat actors register new MFA authentication methods shortly after compromising an identity, establishing persistence in Entra ID.

### Intelligence Context

- Microsoft Security Blog: Passkey-themed social engineering leads to identity and cloud compromise — [https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/](https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/)
  - Context: Following passkey-themed social engineering to harvest credentials, threat actors registered new MFA authentication methods to establish durable persistence in compromised Entra ID accounts.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1098, T1098.001, T1087, T1087.004
- Products: Microsoft Entra ID
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: Microsoft Entra ID, T1098, T1098.001, T1087, T1087.004

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1098 Account Manipulation/ T1098.001 Additional Cloud Credentials (medium); Discovery: T1087 Account Discovery/ T1087.004 Cloud Account (medium)

### Deployment Gates

- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.
- AuditLogs must be streamed to the Sentinel workspace via Entra ID diagnostic settings. If this connector is absent, the table will be empty.

**Required telemetry:**
- SigninLogs, AuditLogs

### KQL

```kql
let LookbackWindow = 2d;
let RegistrationWindow = 60m;
let KnownGoodResultTypes = dynamic(['0', '50125', '50140', '70011', '70043', '70044']);
let MFAOperations = dynamic([
    'User registered security info',
    'User registered all required security info',
    'Admin registered security info for user',
    'User changed default security info',
    'User deleted security info'
]);
let RiskySignIns = SigninLogs
| where TimeGenerated > ago(LookbackWindow)
| where RiskLevelDuringSignIn in ('high', 'medium')
    or ResultType !in (KnownGoodResultTypes)
| summarize
    SignInTime = max(TimeGenerated),
    RiskLevel = max(RiskLevelDuringSignIn),
    ResultType = max(ResultType),
    SignInIP = max(IPAddress)
    by UserPrincipalName;
AuditLogs
| where TimeGenerated > ago(LookbackWindow)
| where Category in ('UserManagement', 'Authentication')
| where OperationName in (MFAOperations)
| extend UPN = tolower(tostring(TargetResources[0].userPrincipalName))
| extend RegistrationIP = tostring(InitiatedBy.user.ipAddress)
| extend InitiatedByUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatedByType = iff(isnotempty(tostring(InitiatedBy.app.appId)), 'Application', 'User')
| extend TargetResourceDisplayName = tostring(TargetResources[0].displayName)
| where isnotempty(UPN)
| join kind=inner (
    RiskySignIns
    | extend UPN = tolower(UserPrincipalName)
) on UPN
| where TimeGenerated between (SignInTime .. (SignInTime + RegistrationWindow))
| project
    RegistrationTime = TimeGenerated,
    UPN,
    OperationName,
    RegistrationIP,
    SignInIP,
    RiskLevel,
    ResultType,
    SignInTime,
    InitiatedByUPN,
    InitiatedByType,
    TargetResourceDisplayName
| sort by RegistrationTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate users resetting or adding MFA methods after a failed sign-in attempt due to a lost device.
- IT administrators registering security info on behalf of users (OperationName: 'Admin registered security info for user') following a support ticket.
- Conditional Access policies that force MFA re-registration after a risky sign-in as a remediation step.

**Tuning notes:**
- Set RiskLevelDuringSignIn filter to 'high' only to reduce volume if medium-risk events are common for legitimate users.
- Add a tolower() normalization on UPN join keys if mixed-case UPNs exist in the environment.
- Consider adding an allowlist of known IT admin UPNs who routinely register MFA on behalf of users to suppress expected admin activity.
- Adjust RegistrationWindow from 60m to a shorter window (e.g., 30m) if attacker behavior in the environment is faster-moving.

**Risks / caveats:**
- RiskLevelDuringSignIn is only populated when Entra ID Identity Protection (P2 licensing) is active. Without it, the risk-level branch of the OR filter produces no results and the query falls back entirely to ResultType-based matching.
- AuditLogs must be streamed to the Sentinel workspace via Entra ID diagnostic settings. If this connector is absent, the table will be empty.
- The 60-minute correlation window between risky sign-in and MFA registration may miss attackers who delay registration; baseline attacker dwell time in the environment before adjusting.
- ResultType-based matching (non-zero codes) will generate noise from users with legitimate authentication failures such as expired passwords or MFA prompts; review ResultType distribution before scheduling.

### Triage Runbook

**First 15 minutes:**
- Confirm the sign-in risk details for the UPN: time, IP, location, device, result type, and whether the sign-in was successful or only a failed attempt.
- Review the AuditLogs event to identify the exact MFA operation, who initiated it, and whether it was user-driven or admin-driven.
- Check whether the registration IP matches the risky sign-in IP or a known corporate/VPN range; mismatched geographies or impossible travel increase suspicion.
- Validate whether the account is privileged, a break-glass account, or an IT/admin account that may legitimately register security info.
- Look for immediate follow-on activity such as mailbox access, app consent, Graph API use, or additional authentication method changes.

**Evidence to collect:**
- SigninLogs entries for the UPN covering at least 24 hours before and after the alert, including RiskLevelDuringSignIn, ResultType, IPAddress, Conditional Access outcome, and device details.
- AuditLogs entries for security info registration, deletion, or default method changes, including OperationName, InitiatedBy, TargetResources, and InitiatedByType.
- User account metadata: role assignments, recent password resets, MFA method inventory, and whether the account is in any allowlist.
- Network and location context for the registration IP and sign-in IP, including VPN, proxy, or known corporate egress.
- Any helpdesk ticket, change request, or user communication that explains the MFA change.

**Pivot points:**
- SigninLogs filtered on the same UPN for the prior 7 days to identify earlier risky sign-ins or repeated failures.
- AuditLogs for the same UPN and nearby time window to find other identity changes such as password reset, consent grants, or role changes.
- IdentityProtectionRiskEvents or equivalent Entra ID risk data if available to confirm whether the account was flagged for compromise.
- Entra ID user and authentication method inventory to verify what methods existed before and after the event.
- Mailbox or cloud activity logs for the same UPN to see whether the account was used after MFA registration.

**Benign explanations:**
- User legitimately added or re-registered MFA after losing a phone or replacing a device.
- Helpdesk or IT admin performed a supported MFA reset or security info registration on behalf of the user.
- Conditional Access or security policy forced re-registration after a legitimate risky sign-in or password reset.
- User was onboarding a new device or passkey as part of an approved enrollment workflow.

**Escalation criteria:**
- The MFA registration was initiated from an unfamiliar IP, foreign location, or non-corporate device shortly after a risky sign-in.
- The account is privileged, highly sensitive, or used for finance, HR, or executive access.
- There is evidence of additional suspicious activity after registration, such as mailbox access, consent grants, or Graph API enumeration.
- The user denies the activity or the registration cannot be tied to a valid support ticket or change request.

**Containment actions:**
- Disable the account or force sign-out if the registration appears unauthorized and the account is still active.
- Revoke active sessions and refresh tokens for the account.
- Reset the password and remove any newly added MFA methods that were not approved.
- Block the source IP or isolate the device only if there is corroborating evidence of compromise.

**Closure criteria:**
- A valid support ticket or change record explains the MFA registration and the initiating actor is confirmed as legitimate.
- The sign-in risk is attributable to a known benign event such as device replacement, and no other suspicious activity is present.
- New MFA methods are accounted for and match the user’s expected enrollment workflow.
- No additional identity abuse, mailbox access, or cloud reconnaissance is observed in the surrounding time window.

<br/>
---
<br/>

## Detection 2: Bulk SharePoint and OneDrive Access Following Risky Sign-In

### Detection Opportunity

After compromising an identity, threat actors perform bulk access to SharePoint, OneDrive, and Exchange Online data as an exfiltration precursor.

### Intelligence Context

- Microsoft Security Blog: Passkey-themed social engineering leads to identity and cloud compromise — [https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/](https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/)
  - Context: Post-compromise, threat actors accessed SharePoint, OneDrive, and Exchange Online data at volume, consistent with data staging or exfiltration following identity compromise via passkey-themed social engineering.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1098, T1098.001, T1087, T1087.004
- Products: Microsoft Entra ID, SharePoint, OneDrive, Exchange Online
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: Microsoft Entra ID, SharePoint, OneDrive, Exchange Online, T1098, T1098.001, T1087, T1087.004

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1098 Account Manipulation/ T1098.001 Additional Cloud Credentials (medium); Discovery: T1087 Account Discovery/ T1087.004 Cloud Account (medium)

### Deployment Gates

- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Required telemetry:**
- OfficeActivity, SigninLogs

### KQL

```kql
let LookbackWindow = 2d;
let PostCompromiseWindow = 2h;
let BulkAccessThreshold = 50;
let BulkWindowBin = 30m;
let TargetOperations = dynamic([
    'FileDownloaded',
    'FileAccessed',
    'FileSyncDownloadedFull',
    'MailItemsAccessed',
    'FileAccessedExtended'
]);
let TargetWorkloads = dynamic(['SharePoint', 'OneDrive', 'Exchange']);
let RiskySignIns = SigninLogs
| where TimeGenerated > ago(LookbackWindow)
| where RiskLevelDuringSignIn in ('high', 'medium')
| summarize
    SignInTime = max(TimeGenerated),
    SignInIP = max(IPAddress),
    RiskLevelDuringSignIn = max(RiskLevelDuringSignIn)
    by UserPrincipalName
| extend JoinKey = tolower(UserPrincipalName);
let BulkAccess = OfficeActivity
| where TimeGenerated > ago(LookbackWindow)
| where OfficeWorkload in (TargetWorkloads)
| where Operation in (TargetOperations)
| where ResultStatus =~ 'Succeeded'
| extend JoinKey = tolower(UserId)
| summarize
    AccessCount = count(),
    EarliestAccessTime = min(TimeGenerated),
    WorkloadsAccessed = make_set(OfficeWorkload),
    ClientIPs = make_set(ClientIP),
    UniqueClientIPCount = dcount(ClientIP)
    by JoinKey, UserId, bin(TimeGenerated, BulkWindowBin)
| where AccessCount >= BulkAccessThreshold;
BulkAccess
| join kind=inner RiskySignIns on JoinKey
| where EarliestAccessTime between (SignInTime .. (SignInTime + PostCompromiseWindow))
| project
    EarliestAccessTime,
    UserId,
    AccessCount,
    UniqueClientIPCount,
    WorkloadsAccessed,
    ClientIPs,
    SignInIP,
    SignInTime,
    RiskLevelDuringSignIn
| sort by EarliestAccessTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate bulk file operations by SharePoint migration tools or backup services running under a user identity.
- Power users or developers who routinely access large numbers of files via automated scripts or sync clients.
- IT administrators performing bulk mailbox access for compliance or eDiscovery purposes.

**Tuning notes:**
- Raise BulkAccessThreshold to 100 or higher if power users or sync clients routinely exceed 50 operations per 30 minutes.
- Remove Exchange from TargetWorkloads if MailItemsAccessed generates excessive noise from legitimate mail clients.
- Add a filter excluding known service account UserId values that perform legitimate bulk access.
- Consider adding UniqueClientIPCount > 1 as an additional filter to focus on sessions where access originates from multiple IPs, which is a stronger exfiltration signal.

**Risks / caveats:**
- OfficeActivity requires the Microsoft 365 connector to be configured in Sentinel. If absent, the table will be empty.
- RiskLevelDuringSignIn requires Entra ID Identity Protection (P2 licensing). Without it, the risky sign-in filter returns no results.
- UserId in OfficeActivity may not always match UserPrincipalName format in SigninLogs exactly; case sensitivity and domain suffix differences can cause join misses.
- MailItemsAccessed operation in OfficeActivity requires Exchange Online Plan 2 or Microsoft 365 E3/E5 with audit logging enabled at the mailbox level.

### Triage Runbook

**First 15 minutes:**
- Confirm the risky sign-in details for the same user: IP, location, device, risk level, and whether the sign-in succeeded.
- Review the OfficeActivity events to identify which workloads were accessed, what operations occurred, and whether access volume is unusual for the user.
- Check whether the access came from a single client IP, multiple IPs, or a sync client that could explain high-volume activity.
- Determine whether the account is a service account, migration account, or power user with expected bulk access behavior.
- Look for signs of follow-on exfiltration such as mass downloads, mailbox item access, sharing changes, or file deletions.

**Evidence to collect:**
- OfficeActivity records for the user covering at least 24 hours before and after the alert, including Operation, OfficeWorkload, ClientIP, ResultStatus, and timestamps.
- SigninLogs for the same user and time window, including RiskLevelDuringSignIn, IPAddress, ResultType, and Conditional Access status.
- A list of the top accessed files, folders, mailboxes, or sites if available from audit logs or eDiscovery tools.
- User role, department, and any known automation or migration tooling associated with the account.
- Any DLP, eDiscovery, or data access alerts that correlate with the same user or IP.

**Pivot points:**
- OfficeActivity filtered to the same UserId for FileDownloaded, FileAccessed, MailItemsAccessed, and sharing-related operations over the prior 7 days.
- SharePoint and OneDrive audit logs for file download, sync, and sharing events tied to the same account or IP.
- Exchange Online audit logs for MailItemsAccessed or unusual mailbox enumeration if Exchange activity is present.
- SigninLogs for the same IP to identify other accounts that may have been compromised from the same source.
- Defender for Cloud Apps or DLP telemetry for mass download, unusual data transfer, or impossible travel context.

**Benign explanations:**
- The user is a migration, backup, or sync account that legitimately performs bulk access.
- A power user, developer, or analyst routinely accesses many files or mail items in a short period.
- The activity is part of a legitimate compliance, eDiscovery, or mailbox export workflow.
- A sync client or offline cache refresh caused a burst of file access events.

**Escalation criteria:**
- Bulk access occurred immediately after a risky sign-in from an unfamiliar IP or location.
- The user accessed sensitive sites, mailboxes, or files outside their normal business function.
- There are multiple client IPs, unusual download patterns, or evidence of staging for exfiltration.
- The user denies the activity or the access pattern is inconsistent with any approved automation or support process.

**Containment actions:**
- Revoke sessions and force password reset if the access appears unauthorized.
- Disable the account temporarily if the user is confirmed compromised or if sensitive data exposure is ongoing.
- Block the source IP or isolate the endpoint if the access originated from a managed device under investigation.
- Coordinate with data protection teams to preserve evidence and assess whether sensitive content was exposed.

**Closure criteria:**
- The activity is explained by a documented migration, backup, or compliance workflow.
- Access volume and workloads match the user’s established baseline and no suspicious follow-on activity exists.
- The risky sign-in is determined to be benign or unrelated, and the account shows no signs of compromise.
- No evidence of mass download, sharing abuse, or data staging is found after review.

<br/>
---
<br/>

## Detection 3: Microsoft Graph API Access by Newly Registered Application Following Account Compromise

### Detection Opportunity

Post-compromise, threat actors abuse Microsoft Graph API for reconnaissance, often via newly registered applications or service principals created shortly after account takeover.

### Intelligence Context

- Microsoft Security Blog: Passkey-themed social engineering leads to identity and cloud compromise — [https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/](https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/)
  - Context: Following identity compromise, threat actors abused Microsoft Graph API for reconnaissance. The reporting indicates Graph API abuse is a consistent post-compromise behavior in this campaign.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1098, T1098.001, T1087, T1087.004
- Products: Microsoft Entra ID, Microsoft Graph
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: Microsoft Entra ID, Microsoft Graph, T1098, T1098.001, T1087, T1087.004

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1098 Account Manipulation/ T1098.001 Additional Cloud Credentials (medium); Discovery: T1087 Account Discovery/ T1087.004 Cloud Account (medium)

### Deployment Gates

- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Required telemetry:**
- SigninLogs, AuditLogs

### KQL

```kql
let LookbackWindow = 2d;
let AppUsageWindow = 24h;
let NewApps = AuditLogs
| where TimeGenerated > ago(LookbackWindow)
| where OperationName in ('Add application', 'Add service principal')
| extend AppName = tolower(tostring(TargetResources[0].displayName))
| extend AppId = tostring(TargetResources[0].id)
| extend CreatedBy = tostring(InitiatedBy.user.userPrincipalName)
| where isnotempty(AppName)
| project AppCreatedTime = TimeGenerated, AppName, AppId, CreatedBy;
let RiskySignIns = SigninLogs
| where TimeGenerated > ago(LookbackWindow)
| where RiskLevelDuringSignIn in ('high', 'medium')
| summarize
    SignInTime = max(TimeGenerated),
    RiskLevelDuringSignIn = max(RiskLevelDuringSignIn)
    by UserPrincipalName;
let GraphSignIns = SigninLogs
| where TimeGenerated > ago(LookbackWindow)
| where ResourceDisplayName =~ 'Microsoft Graph'
| where ResultType == '0'
| extend AppNameNorm = tolower(AppDisplayName)
| project
    GraphSignInTime = TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    AppNameNorm,
    GraphSignInIP = IPAddress;
GraphSignIns
| join kind=inner NewApps on $left.AppNameNorm == $right.AppName
| where GraphSignInTime between (AppCreatedTime .. (AppCreatedTime + AppUsageWindow))
| join kind=inner RiskySignIns on UserPrincipalName
| where GraphSignInTime > SignInTime
| project
    GraphSignInTime,
    UserPrincipalName,
    AppDisplayName,
    AppId,
    GraphSignInIP,
    AppCreatedTime,
    CreatedBy,
    SignInTime,
    RiskLevelDuringSignIn
| sort by GraphSignInTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate developers registering new applications and immediately testing Graph API connectivity.
- Automated DevOps pipelines that register applications and use them for Graph API calls within the same session.
- IT administrators registering service principals for new integrations.

**Tuning notes:**
- Extend AppUsageWindow beyond 24 hours if attackers are observed pre-staging applications before account compromise.
- Add ConditionalAccessStatus != 'success' as an additional filter to focus on sign-ins that bypassed Conditional Access policies.
- Consider adding a filter on CreatedBy to exclude known application registration service accounts.
- Restrict RiskLevelDuringSignIn to 'high' only if medium-risk events generate excessive false positives.

**Risks / caveats:**
- RiskLevelDuringSignIn requires Entra ID Identity Protection (P2 licensing). Without it, the risky sign-in filter returns no results.
- AuditLogs must be streamed to the Sentinel workspace via Entra ID diagnostic settings. If absent, the table will be empty.
- AppDisplayName in SigninLogs may not reliably match TargetResources[0].displayName in AuditLogs for all application types, particularly service principals with display name overrides.
- The assumption that Graph API reconnaissance occurs under the same compromised UPN as the risky sign-in may miss cases where attackers use a separate service principal identity for Graph access after initial compromise.

### Triage Runbook

**First 15 minutes:**
- Confirm the application registration event and identify who created it, when it was created, and whether the creator is the same user that had the risky sign-in.
- Review the Graph sign-in event to see which account or service principal used the app, from what IP, and whether the access was successful.
- Check whether the app has unusual permissions, consent grants, or directory roles that would enable broad enumeration or persistence.
- Determine whether the app is part of a known deployment pipeline, integration, or developer workflow.
- Look for immediate post-registration activity such as directory enumeration, mailbox access, consent changes, or additional app registrations.

**Evidence to collect:**
- AuditLogs for Add application and Add service principal events, including AppId, AppName, CreatedBy, and timestamps.
- SigninLogs for Microsoft Graph access by the same user or app, including ResourceDisplayName, AppDisplayName, IPAddress, ResultType, and RiskLevelDuringSignIn.
- App registration details: permissions, consent status, owners, secrets/certificates, and any recent changes.
- User and service principal role assignments to determine whether the app can access sensitive data or directory objects.
- Any related admin actions such as consent grants, role assignments, or credential additions around the same time.

**Pivot points:**
- AuditLogs for the same AppId to find subsequent changes, consent grants, or credential additions.
- SigninLogs for Microsoft Graph and other Microsoft 365 resources accessed by the same user or app in the surrounding time window.
- Entra ID application inventory to determine whether the app is new, owned by the user, or part of a known integration.
- Directory audit logs for account discovery or role enumeration activity tied to the same identity.
- Defender for Cloud Apps or CASB logs for unusual app behavior, token use, or data access patterns.

**Benign explanations:**
- A developer or administrator legitimately registered a new app and immediately tested Graph connectivity.
- An approved DevOps or automation pipeline created the app and used it for integration testing.
- An IT integration or SaaS onboarding process created the service principal as part of normal business operations.
- The app was created by a legitimate admin for a sanctioned internal tool.

**Escalation criteria:**
- The app was created shortly after a risky sign-in and is not tied to a known business process.
- The app has broad Graph permissions, newly added secrets, or consent that was not expected.
- The same user or app performs directory enumeration, mailbox access, or other suspicious post-registration activity.
- The creator denies the action or the app is unknown to the application owners.

**Containment actions:**
- Disable or delete the suspicious application or service principal if it is confirmed unauthorized.
- Revoke app secrets, certificates, and OAuth consents associated with the app.
- Revoke sessions and reset credentials for the user who created or used the app if compromise is suspected.
- Review and remove excessive permissions or directory roles granted to the app.

**Closure criteria:**
- The app is confirmed to be part of a documented integration, deployment pipeline, or approved test activity.
- Permissions and usage are consistent with the app’s intended purpose and no suspicious Graph reconnaissance is observed.
- The risky sign-in is explained by a benign event and there is no evidence of unauthorized app creation or use.
- No additional identity abuse or directory enumeration is found in the surrounding time window.

<br/>
---
<br/>

## Detection 4: Browser Process Spawning Scripting Engine or Dropping Executable to Temp Path

### Detection Opportunity

Multi-payload malware delivered via SEO poisoning or gaming lures causes browser or download manager processes to spawn scripting engines or write executables to temporary directories on enterprise endpoints.

### Intelligence Context

- Unit 42: Untracked Nightmares: The Threats Hiding Behind Commodity Infrastructure — [https://unit42.paloaltonetworks.com/ppi-network-malware-campaign-analysis/](https://unit42.paloaltonetworks.com/ppi-network-malware-campaign-analysis/)
  - Context: Cybercriminals used YouTube gaming lures and SEO poisoning to deliver multi-payload malware to enterprise endpoints. The delivery chain results in browser or download manager processes spawning scripting engines or dropping executables, a detectable behavioral pattern even without specific malware family IOCs.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1036, T1059.001
- Products: Not specified
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: T1059, T1036, T1059.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (high); Defense Evasion: T1036 Masquerading (low); Command and Scripting Interpreter: T1059 Command and Scripting Interpreter/ T1059.001 PowerShell (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- SHA256 is not available in DeviceProcessEvents so hash-based triage is only available for file drop events.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let LookbackWindow = 1d;
let BrowserProcesses = dynamic(['chrome.exe', 'msedge.exe', 'firefox.exe', 'iexplore.exe', 'brave.exe', 'opera.exe']);
let DownloadManagers = dynamic(['wget.exe', 'curl.exe', 'bitsadmin.exe']);
let ScriptingEngines = dynamic(['powershell.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'cmd.exe', 'wmic.exe']);
let TempPaths = dynamic(['\\AppData\\Local\\Temp\\', '\\AppData\\Roaming\\', '\\Users\\Public\\', '\\Windows\\Temp\\']);
let DroppableExtensions = dynamic(['.exe', '.dll', '.ps1', '.vbs', '.js', '.hta', '.bat', '.cmd']);
let ScriptSpawn = DeviceProcessEvents
| where TimeGenerated > ago(LookbackWindow)
| where InitiatingProcessFileName in~ (BrowserProcesses)
    or InitiatingProcessFileName in~ (DownloadManagers)
| where FileName in~ (ScriptingEngines)
| project
    EventTime = TimeGenerated,
    DeviceName,
    AccountName,
    EventType = 'ScriptEngineSpawn',
    ParentProcess = InitiatingProcessFileName,
    RelatedFile = FileName,
    FolderPath = '',
    CommandLine = ProcessCommandLine,
    SHA256 = '',
    SHA1 = '';
let ExeDrop = DeviceFileEvents
| where TimeGenerated > ago(LookbackWindow)
| where InitiatingProcessFileName in~ (BrowserProcesses)
    or InitiatingProcessFileName in~ (DownloadManagers)
| where FolderPath has_any (TempPaths)
| where FileName has_any (DroppableExtensions)
| where ActionType in ('FileCreated', 'FileRenamed')
| project
    EventTime = TimeGenerated,
    DeviceName,
    AccountName,
    EventType = 'ExecutableDrop',
    ParentProcess = InitiatingProcessFileName,
    RelatedFile = FileName,
    FolderPath,
    CommandLine = InitiatingProcessCommandLine,
    SHA256,
    SHA1;
ScriptSpawn
| union ExeDrop
| summarize
    EventCount = count(),
    EventTypes = make_set(EventType),
    RelatedFiles = make_set(RelatedFile),
    FolderPaths = make_set(FolderPath),
    Commands = make_set(CommandLine),
    Hashes = make_set(SHA256)
    by DeviceName, AccountName, ParentProcess, bin(EventTime, 1h)
| where EventCount >= 2
| sort by EventCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate browser-initiated software downloads that invoke PowerShell or cmd.exe as part of an installer chain.
- Browser extension update mechanisms that write DLLs to AppData paths.
- Developer tools that use browsers to download and execute scripts in temp directories.
- Enterprise software deployment that uses curl.exe or bitsadmin.exe to stage installers.

**Tuning notes:**
- Extend BrowserProcesses list to include any additional browsers deployed in the environment.
- Raise EventCount threshold to 3 or higher if legitimate software deployment generates frequent browser-spawned scripting engine events.
- Add SHA256 allowlisting for known-good installer hashes to suppress legitimate software deployment noise.
- Consider splitting into two separate hunting queries (ScriptEngineSpawn only and ExecutableDrop only) for more targeted investigation.

**Risks / caveats:**
- DeviceProcessEvents and DeviceFileEvents require Defender for Endpoint (MDE) agents deployed on endpoints. Without MDE onboarding, these tables will be empty for affected devices.
- The EventCount >= 2 threshold per hour is still low and will produce noise from legitimate browser-initiated installer chains; baseline against normal software deployment activity before scheduling.
- The has_any operator on TempPaths performs substring matching which may match unexpected paths; validate against DeviceFileEvents FolderPath distribution in the environment.
- SHA256 is not available in DeviceProcessEvents so hash-based triage is only available for file drop events.

### Triage Runbook

**First 15 minutes:**
- Identify the parent browser or download manager, the child process or dropped file, and the exact command line or folder path involved.
- Check whether the activity occurred on a user workstation, developer machine, or software deployment host where browser-driven installers are expected.
- Review the file name, extension, and hash if present to see whether it resembles a known installer, script, or suspicious payload.
- Determine whether the event is isolated or repeated across the same device or user in a short time window.
- Look for immediate follow-on behavior such as PowerShell execution, persistence creation, network beacons, or additional file drops.

**Evidence to collect:**
- DeviceProcessEvents for the same device and user around the alert time, including parent/child process trees and command lines.
- DeviceFileEvents for the same device to capture dropped files, folder paths, hashes, and file creation or rename actions.
- File hashes and any available reputation results for the dropped executable or script.
- User context and recent browser activity, including whether the download came from a known software portal or an unfamiliar site.
- Any Defender for Endpoint alerts, SmartScreen events, or network connections associated with the same process tree.

**Pivot points:**
- DeviceProcessEvents filtered to the same DeviceName and AccountName for 24 hours before and after the alert to reconstruct the process tree.
- DeviceFileEvents for the same device to find additional dropped files, renamed payloads, or temp-path staging.
- DeviceNetworkEvents to identify outbound connections from the browser, scripting engine, or dropped executable.
- Defender for Endpoint alert history for the device to see whether this is part of a broader intrusion chain.
- Browser download history or endpoint telemetry if available to identify the source URL or download origin.

**Benign explanations:**
- A legitimate software installer or updater launched from the browser and used PowerShell, cmd.exe, or a temp directory during setup.
- A developer downloaded and executed a script or tool from a trusted internal portal.
- Enterprise software deployment or remote support tooling staged files in temp paths as part of normal operation.
- Browser extension or application update mechanisms created temporary executables or scripts.

**Escalation criteria:**
- The child process is PowerShell, WScript, mshta, cmd, or another scripting engine with suspicious arguments.
- The dropped file is unsigned, unknown, or has a suspicious hash and was written to a temp or public path.
- There are repeated events, multiple payloads, or follow-on persistence/network activity on the same device.
- The user did not initiate the download or the source site is untrusted or unrelated to business activity.

**Containment actions:**
- Isolate the endpoint if the script or dropped executable appears malicious or if follow-on execution is observed.
- Quarantine or remove the suspicious file and block the hash if confirmed malicious.
- Terminate the suspicious process tree and prevent further execution if the device is actively executing payloads.
- Reset credentials for the user if the activity appears tied to credential theft or session hijacking.

**Closure criteria:**
- The event is tied to a known-good installer, updater, or approved internal tool and the file hash is benign.
- No suspicious follow-on execution, persistence, or network activity is observed.
- The browser/download source is trusted and the process tree matches expected software installation behavior.
- The event is isolated and consistent with normal administrative or developer activity.

<br/>
---
<br/>

## Detection 5: Low-Privilege Process Spawning High-Integrity Child Process Indicative of ALPC EoP Exploitation

### Detection Opportunity

Exploitation of a Windows ALPC zero-day for local elevation of privilege, resulting in a low-integrity or standard-user process spawning a child process running at SYSTEM or high integrity without expected parent context.

### Intelligence Context

- Rapid7: Patch Tuesday - September 2026 — [https://www.rapid7.com/blog/post/em-patch-tuesday-september-2026](https://www.rapid7.com/blog/post/em-patch-tuesday-september-2026)
  - Context: Rapid7 reported active in-the-wild exploitation of a Windows ALPC zero-day elevation-of-privilege vulnerability as part of the September 2026 Patch Tuesday disclosure. The exploitation results in privilege escalation from a standard user context to SYSTEM.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1068
- Products: Windows
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Windows, T1068

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Privilege Escalation: T1068 Exploitation for Privilege Escalation (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let LookbackWindow = 1d;
let LegitimateSystemParents = dynamic([
    'services.exe',
    'wininit.exe',
    'smss.exe',
    'csrss.exe',
    'lsass.exe',
    'svchost.exe',
    'msiexec.exe',
    'TrustedInstaller.exe',
    'taskhost.exe',
    'taskhostw.exe',
    'spoolsv.exe',
    'dllhost.exe',
    'wmiprvse.exe',
    'searchindexer.exe',
    'winlogon.exe',
    'userinit.exe'
]);
DeviceProcessEvents
| where TimeGenerated > ago(LookbackWindow)
| where AccountName =~ 'SYSTEM'
| where not(AccountName endswith '$')
| where isnotempty(InitiatingProcessAccountName)
| where InitiatingProcessAccountName !in~ ('SYSTEM', 'NT AUTHORITY\\SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE')
| where not(InitiatingProcessAccountName endswith '$')
| where InitiatingProcessFileName !in~ (LegitimateSystemParents)
| project
    EscalationTime = TimeGenerated,
    DeviceName,
    ParentProcess = InitiatingProcessFileName,
    ParentAccount = InitiatingProcessAccountName,
    ChildProcess = FileName,
    ChildAccount = AccountName,
    CommandLine = ProcessCommandLine,
    FolderPath,
    SHA256,
    SHA1
| summarize
    EscalationCount = count(),
    ChildProcesses = make_set(ChildProcess),
    Commands = make_set(CommandLine),
    Hashes = make_set(SHA256)
    by DeviceName, ParentProcess, ParentAccount, bin(EscalationTime, 1h)
| where EscalationCount >= 1
| sort by EscalationTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate Windows service management operations where a user-space process triggers a service that runs as SYSTEM.
- Software installation processes that use user-initiated installers to spawn SYSTEM-context setup components.
- Remote management tools such as SCCM, Intune management extension, or similar agents that spawn SYSTEM processes on behalf of user sessions.
- Antivirus or EDR agents that spawn SYSTEM-context processes in response to user-initiated scans.

**Tuning notes:**
- Baseline the query over 7 days to identify recurring legitimate parent-child SYSTEM escalation patterns before converting to a scheduled rule.
- Add a DeviceName filter using a list of unpatched hosts from vulnerability management data to focus on highest-risk endpoints.
- Extend LegitimateSystemParents with any additional management tools in the environment that legitimately spawn SYSTEM processes.
- Consider raising EscalationCount threshold to 2 or more if single-event noise is high after initial baselining.

**Risks / caveats:**
- DeviceProcessEvents requires Defender for Endpoint (MDE) agents deployed on Windows endpoints. Without MDE onboarding, this table will be empty for affected devices.
- AccountName and InitiatingProcessAccountName reflect the token account at process creation time as recorded by MDE. If MDE sensor coverage is incomplete, escalation events on uncovered hosts will not appear.
- The LegitimateSystemParents exclusion list is not exhaustive; environment-specific management tools, antivirus agents, and software deployment clients may spawn SYSTEM-context children and will generate false positives until added to the exclusion list.
- The EscalationCount >= 1 threshold means every matching event fires; baselining over 7 days is strongly recommended before scheduling as a production rule.

### Triage Runbook

**First 15 minutes:**
- Confirm the parent and child processes, the initiating account, and whether the child truly ran as SYSTEM or another elevated context.
- Check whether the parent process is a known Windows component, installer, or management agent that legitimately spawns SYSTEM children.
- Identify the device patch status and whether it is among hosts exposed to the reported ALPC vulnerability.
- Review the command line and folder path for the child process to see whether it is a normal service action or suspicious execution.
- Look for concurrent signs of exploitation such as crash events, unusual service creation, token manipulation, or post-exploitation activity.

**Evidence to collect:**
- DeviceProcessEvents for the device covering at least 24 hours before and after the alert, including full process tree context and command lines.
- Device vulnerability or patch management data showing whether the host is missing the relevant Windows security update.
- Hashes for the parent and child processes, plus any reputation or threat intelligence results.
- Any related Windows event logs or Defender for Endpoint alerts indicating service creation, privilege changes, or exploit behavior.
- User logon context and whether the initiating account is a local admin, standard user, or service account.

**Pivot points:**
- DeviceProcessEvents on the same DeviceName to identify repeated SYSTEM-spawning behavior or additional suspicious children.
- DeviceNetworkEvents and DeviceRegistryEvents for signs of post-exploitation activity such as beaconing or persistence.
- Vulnerability management or patch compliance tables to confirm whether the host is unpatched.
- Windows security logs or MDE alerts for service installation, scheduled task creation, or privilege assignment around the same time.
- Other endpoints with the same parent process or hash to determine whether the behavior is isolated or widespread.

**Benign explanations:**
- A legitimate installer or software update spawned a SYSTEM child process as part of setup.
- A remote management or endpoint protection agent executed a SYSTEM-context action on behalf of the user.
- A Windows service or scheduled maintenance task caused the process tree and the parent was not captured cleanly.
- An administrative tool or support workflow triggered a SYSTEM child process on a managed endpoint.

**Escalation criteria:**
- The host is unpatched or known vulnerable and the process tree does not match a legitimate Windows or management component.
- The child process is unexpected, unsigned, or launches suspicious commands, scripts, or network connections.
- There are additional indicators of exploitation such as crashes, token theft, persistence, or lateral movement.
- The initiating user is a standard user and cannot explain the activity, or the device is a high-value asset.

**Containment actions:**
- Isolate the endpoint if exploitation is suspected or if suspicious post-escalation activity is observed.
- Suspend or disable the user session if the account appears to be involved in the exploit chain.
- Apply the relevant Windows security update or remove the host from production until patched if the device is vulnerable.
- Collect volatile evidence and preserve process, memory, and event data before remediation if possible.

**Closure criteria:**
- The process tree is explained by a known Windows service, installer, or approved management tool.
- The host is patched and no additional suspicious activity is present.
- The child process and command line match expected administrative behavior and hashes are benign.
- No corroborating evidence of privilege escalation, persistence, or post-exploitation activity is found.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Licensing / identity risk fields:**
- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Telemetry availability:**
- MFA Method Registration Following Risky or Atypical Sign-In: AuditLogs must be streamed to the Sentinel workspace via Entra ID diagnostic settings. If this connector is absent, the table will be empty.

**Schema / correlation keys:**
- Browser Process Spawning Scripting Engine or Dropping Executable to Temp Path: Do not schedule yet; validate as an analyst-led hunt first.
- Low-Privilege Process Spawning High-Integrity Child Process Indicative of ALPC EoP Exploitation: Do not schedule yet; validate as an analyst-led hunt first.

**Environment scope / baselines:**
- Browser Process Spawning Scripting Engine or Dropping Executable to Temp Path: SHA256 is not available in DeviceProcessEvents so hash-based triage is only available for file drop events.

**Shared-table notes:**
- SigninLogs: shared by MFA Method Registration Following Risky or Atypical Sign-In; Bulk SharePoint and OneDrive Access Following Risky Sign-In; Microsoft Graph API Access by Newly Registered Application Following Account Compromise
- AuditLogs: shared by MFA Method Registration Following Risky or Atypical Sign-In; Microsoft Graph API Access by Newly Registered Application Following Account Compromise
- DeviceProcessEvents: shared by Browser Process Spawning Scripting Engine or Dropping Executable to Temp Path; Low-Privilege Process Spawning High-Integrity Child Process Indicative of ALPC EoP Exploitation

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: MFA Method Registration Following Risky or Atypical Sign-In; Bulk SharePoint and OneDrive Access Following Risky Sign-In; Microsoft Graph API Access by Newly Registered Application Following Account Compromise.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Browser Process Spawning Scripting Engine or Dropping Executable to Temp Path; Low-Privilege Process Spawning High-Integrity Child Process Indicative of ALPC EoP Exploitation.

### Hunting Agenda and Promotion Criteria

- Browser Process Spawning Scripting Engine or Dropping Executable to Temp Path: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Low-Privilege Process Spawning High-Integrity Child Process Indicative of ALPC EoP Exploitation: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

This run exposes an identity-risk licensing blind spot: detections using RiskLevelDuringSignIn lose fidelity in tenants without Entra ID P2 risk enrichment.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
