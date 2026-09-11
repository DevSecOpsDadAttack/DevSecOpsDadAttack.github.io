---
layout: post
title: "Detection Engineering Brief - Friday, September 11, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-11
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Microsoft Graph
  - SharePoint
  - OneDrive
  - SPIFFE
  - SPIRE
  - Kubernetes
  - T1213
  - T1213.002
  - T1566
  - T1566.003
  - T1585
  - T1552
  - T1552.001
  - T1083
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

2 production candidates, 1 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Microsoft Graph, SharePoint, OneDrive, SPIFFE, SPIRE, Kubernetes, T1213, T1213.002, T1566, T1566.003, T1585, T1552, T1552.001, T1083.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Microsoft Graph Enumeration Operations from Recently MFA-Registered Account; Executive Display Name Spoofing Email to Finance Recipients; Root-Level Process Access to SPIRE Agent Socket on Kubernetes Node.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: MFA Method Registration Following Suspicious Sign-In

### Detection Opportunity

MFA persistence established by registering a new authentication method shortly after a successful sign-in from an unfamiliar location or device, following identity compromise via passkey-themed social engineering.

### Intelligence Context

- Microsoft Security Blog: Passkey-themed social engineering leads to identity and cloud compromise — [https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/](https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/)
  - Context: After compromising identities via passkey-themed social engineering, threat actors registered new MFA methods to establish persistence, enabling continued access even after password resets.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1213, T1213.002
- Products: Microsoft Graph, SharePoint, OneDrive
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: Microsoft Graph, SharePoint, OneDrive, T1213, T1213.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Collection: T1213 Data from Information Repositories/ T1213.002 SharePoint (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- SigninLogs, AuditLogs

### KQL

```kql
let lookback = 1d;
let correlationWindow = 30min;
let suspiciousSignins = SigninLogs
| where TimeGenerated >= ago(lookback)
| where ResultType == 0
| extend NormalizedUPN = tolower(UserPrincipalName)
| where isnotempty(NormalizedUPN)
| project SigninTime = TimeGenerated, NormalizedUPN, UserPrincipalName, SigninIP = IPAddress, AppDisplayName;
let mfaRegistrations = AuditLogs
| where TimeGenerated >= ago(lookback)
| where OperationName has_any (
    "Update user",
    "Register security info",
    "User registered security info",
    "User registered all required security info"
  )
| extend UPN_Target = tolower(tostring(TargetResources[0].userPrincipalName))
| extend UPN_Initiator = tolower(tostring(InitiatedBy.user.userPrincipalName))
| extend UPN = iff(isnotempty(UPN_Target), UPN_Target, UPN_Initiator)
| where isnotempty(UPN)
| project RegTime = TimeGenerated, UPN, OperationName;
suspiciousSignins
| join kind=inner mfaRegistrations on $left.NormalizedUPN == $right.UPN
| where RegTime between (SigninTime .. (SigninTime + correlationWindow))
| extend MinutesBetween = datetime_diff('minute', RegTime, SigninTime)
| project UserPrincipalName, SigninTime, SigninIP, AppDisplayName, RegTime, OperationName, MinutesBetween
| order by SigninTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Users who legitimately sign in and immediately self-enroll MFA for the first time during onboarding.
- IT helpdesk-assisted MFA resets performed immediately after a user authenticates.
- Automated provisioning workflows that trigger MFA enrollment shortly after a service account sign-in.

**Tuning notes:**
- Reduce correlationWindow to 10 minutes to lower false positive volume from users who enroll MFA during the same session.
- Add a SigninIP exclusion for known corporate egress IP ranges to suppress helpdesk-assisted enrollments.
- Consider adding a RiskLevelDuringSignIn filter on SigninLogs (e.g., riskLevelDuringSignIn != 'none') to focus on risky sign-ins if Entra ID Identity Protection is licensed.

**Risks / caveats:**
- AuditLogs.TargetResources[0].userPrincipalName may be null for some MFA registration events where the UPN is stored in InitiatedBy.user.userPrincipalName instead; if UPN extraction yields empty strings the join will produce no results for those events.
- SigninLogs and AuditLogs require the Entra ID (Azure AD) diagnostic settings connector to be enabled and streaming both log categories to the Sentinel workspace.
- The 30-minute correlation window may still capture legitimate self-service MFA enrollment; baselining against a 7-day historical period before scheduling is recommended.
- OperationName values for MFA registration vary across Entra ID tenants and may include additional values not covered by the current filter; review AuditLogs for tenant-specific operation names before deployment.

### Triage Runbook

**First 15 minutes:**
- Confirm the sign-in was successful and assess whether the IP, device, browser, and geolocation are unfamiliar for the user.
- Check the MFA registration event time relative to the sign-in; treat rapid enrollment after a suspicious sign-in as likely compromise until proven otherwise.
- Review Entra ID sign-in risk, user risk, and any conditional access prompts or failures around the event window.
- Identify whether the new MFA method was added by the user, helpdesk, or an attacker-controlled session; look for password reset, token issuance, or session refresh activity after enrollment.

**Evidence to collect:**
- SigninLogs details: user, IP, device, app, result type, risk indicators, and authentication details.
- AuditLogs MFA registration operation, target resources, initiator, and exact method type added.
- User’s recent sign-in history, including prior known-good IPs/devices and any impossible travel or unfamiliar sign-in patterns.
- Any helpdesk tickets, identity protection alerts, or password reset records for the account.

**Pivot points:**
- SigninLogs for the same user over the last 7 days to establish normal IPs, devices, and locations.
- AuditLogs for additional security info changes, password resets, consent grants, or role changes by the same account.
- IdentityProtectionRiskEvents or related risk tables if available in the tenant.
- Entra ID sign-in logs for other accounts from the same IP, device, or browser fingerprint.

**Benign explanations:**
- First-time MFA enrollment during onboarding or after a planned security campaign.
- Helpdesk-assisted MFA reset or re-registration performed immediately after user verification.
- Automated provisioning or account setup workflows that trigger enrollment shortly after first sign-in.

**Escalation criteria:**
- The sign-in originated from a new country, anonymizer, impossible travel path, or unmanaged device.
- The MFA method added is a passkey, authenticator, or phone method the user does not recognize.
- There are additional signs of compromise such as password reset, consent grant, mailbox access, or suspicious file activity after enrollment.
- The user denies the sign-in or MFA registration, or the event occurred outside normal onboarding/helpdesk processes.

**Containment actions:**
- Disable the account or force sign-out if the user denies the activity or if multiple compromise indicators are present.
- Revoke active sessions and refresh tokens, then require password reset and MFA re-registration through a trusted channel.
- Block the source IP or device only if it is clearly malicious and not shared corporate infrastructure.
- Preserve audit evidence before making changes to the account.

**Closure criteria:**
- The MFA registration is confirmed as legitimate through user or helpdesk verification.
- No additional suspicious sign-ins, token activity, or post-enrollment abuse is found in the surrounding time window.
- The account’s MFA methods and recovery settings match approved change records.
- Any suspicious session has been revoked and the user has reauthenticated through approved controls.

<br/>
---
<br/>

## Detection 2: Microsoft Graph Enumeration Operations from Recently MFA-Registered Account

### Detection Opportunity

Microsoft Graph API used for reconnaissance operations such as listing users or groups, performed by an account that recently registered a new MFA method, indicating post-compromise identity abuse.

### Intelligence Context

- Microsoft Security Blog: Passkey-themed social engineering leads to identity and cloud compromise — [https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/](https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/)
  - Context: Following identity compromise and MFA persistence establishment, threat actors abused Microsoft Graph API to perform reconnaissance including enumeration of users, groups, and directory objects.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1213, T1213.002
- Products: Microsoft Graph, SharePoint, OneDrive
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: Microsoft Graph, SharePoint, OneDrive, T1213, T1213.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Collection: T1213 Data from Information Repositories/ T1213.002 SharePoint (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- AuditLogs

### KQL

```kql
let lookback = 2d;
let enrollmentWindow = 24h;
let reconThreshold = 5;
let recentMFAEnrollments = AuditLogs
| where TimeGenerated >= ago(lookback)
| where OperationName has_any (
    "Register security info",
    "User registered security info",
    "User registered all required security info"
  )
| extend UPN_Target = tolower(tostring(TargetResources[0].userPrincipalName))
| extend UPN_Initiator = tolower(tostring(InitiatedBy.user.userPrincipalName))
| extend UPN = iff(isnotempty(UPN_Target), UPN_Target, UPN_Initiator)
| where isnotempty(UPN)
| summarize EnrollmentTime = max(TimeGenerated) by UPN;
let graphRecon = AuditLogs
| where TimeGenerated >= ago(lookback)
| where OperationName has_any (
    "Get member objects",
    "List users",
    "List groups",
    "List members",
    "List directoryObjects",
    "Get user",
    "List servicePrincipals"
  )
| extend UPN = tolower(tostring(InitiatedBy.user.userPrincipalName))
| where isnotempty(UPN)
| summarize
    ReconCount = count(),
    FirstReconTime = min(TimeGenerated),
    LastReconTime = max(TimeGenerated),
    OperationNames = make_set(OperationName, 20)
    by UPN;
graphRecon
| where ReconCount >= reconThreshold
| join kind=inner recentMFAEnrollments on UPN
| where FirstReconTime > EnrollmentTime
| where FirstReconTime <= (EnrollmentTime + enrollmentWindow)
| project UPN, EnrollmentTime, FirstReconTime, LastReconTime, ReconCount, OperationNames
| order by ReconCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Administrators who register MFA and then perform routine directory lookups as part of their job function.
- Automated scripts or service accounts that perform directory enumeration and also trigger MFA registration events.
- Security tools that enumerate directory objects as part of posture assessment.

**Tuning notes:**
- Increase reconThreshold based on a percentile baseline of normal daily directory operation counts per user.
- Expand OperationName list after reviewing tenant-specific AuditLogs to include any additional enumeration operation names observed.
- Consider adding a time-of-day filter to focus on off-hours enumeration if the environment has predictable business hours.

**Risks / caveats:**
- AuditLogs does not consistently record Graph API directory enumeration operations (List users, List groups, etc.) for all tenants; these operations may not appear in AuditLogs at all depending on the audit policy and the calling application.
- AppDisplayName == 'Microsoft Graph' is not a reliable filter for user-driven Graph calls; the value reflects the registered application name, which varies by client.
- InitiatedBy.user.userPrincipalName is null for service principal-driven Graph calls, which may represent a significant portion of enumeration activity.
- Graph API enumeration operations may not appear in AuditLogs in all tenants; validate by querying AuditLogs for the specific OperationName values before relying on this detection.

### Triage Runbook

**First 15 minutes:**
- Verify the account recently registered MFA and confirm the enumeration began after that enrollment.
- Review the specific Graph-related operations and determine whether they are bulk or unusual for the user’s role.
- Check whether the activity came from a user principal or service principal and whether the source IP/device is unfamiliar.
- Look for follow-on actions such as mailbox access, SharePoint/OneDrive access, consent grants, or role changes.

**Evidence to collect:**
- AuditLogs entries for the enumeration operations, including OperationName, InitiatedBy, TargetResources, and timestamps.
- The MFA enrollment event and any preceding suspicious sign-in details for the same account.
- Source IP, user agent, and device context associated with the Graph activity if available in tenant logs.
- Any related directory changes, app consent events, or privilege assignments around the same time.

**Pivot points:**
- AuditLogs for the same UPN over 24 hours before and after enrollment to identify additional reconnaissance or admin actions.
- SigninLogs for the account to correlate source IPs, devices, and risk indicators.
- AuditLogs for other accounts using the same IP or initiating similar enumeration patterns.
- Microsoft 365 or Defender XDR logs for subsequent SharePoint, OneDrive, or mailbox access by the same user.

**Benign explanations:**
- An administrator or IT staff member performing routine directory lookups after a legitimate MFA re-registration.
- A security or inventory tool enumerating users and groups as part of normal operations.
- A service account or automation workflow that legitimately queries directory objects after a maintenance event.

**Escalation criteria:**
- Enumeration volume is high, repetitive, or includes multiple object types not aligned to the user’s role.
- The account is non-administrative and the activity occurs from an unfamiliar IP, device, or off-hours session.
- There is evidence of privilege escalation, consent abuse, or subsequent data access after the enumeration.
- The user denies the activity or the account was not expected to perform directory reconnaissance.

**Containment actions:**
- Disable the account or revoke sessions if the activity is clearly unauthorized or paired with other compromise indicators.
- Reset credentials and require MFA re-registration if the account appears compromised.
- Block or investigate the source IP and any associated application only after confirming it is not a legitimate corporate service.
- Preserve logs and notify identity administrators if the account has elevated privileges.

**Closure criteria:**
- The enumeration is explained by approved administrative or automation activity.
- No additional suspicious Graph, directory, or data access is found after the MFA enrollment.
- The account’s source IPs, devices, and operations align with its normal baseline.
- Any unauthorized session has been terminated and the account is remediated.

<br/>
---
<br/>

## Detection 3: Bulk SharePoint and OneDrive Access from Account with Recent MFA Registration

### Detection Opportunity

Bulk file access or download activity across SharePoint and OneDrive performed by an account that recently registered a new MFA method, consistent with post-compromise data collection following passkey-themed social engineering.

### Intelligence Context

- Microsoft Security Blog: Passkey-themed social engineering leads to identity and cloud compromise — [https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/](https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/)
  - Context: After establishing MFA persistence, threat actors accessed SharePoint, OneDrive, and email data as part of post-compromise data collection activity.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1213, T1213.002
- Products: Microsoft Graph, SharePoint, OneDrive
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: Microsoft Graph, SharePoint, OneDrive, T1213, T1213.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Collection: T1213 Data from Information Repositories/ T1213.002 SharePoint (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- AuditLogs, OfficeActivity

### KQL

```kql
let lookback = 2d;
let enrollmentWindow = 48h;
let bulkThreshold = 50;
let recentMFAEnrollments = AuditLogs
| where TimeGenerated >= ago(lookback)
| where OperationName has_any (
    "Register security info",
    "User registered security info",
    "User registered all required security info"
  )
| extend UPN_Target = tolower(tostring(TargetResources[0].userPrincipalName))
| extend UPN_Initiator = tolower(tostring(InitiatedBy.user.userPrincipalName))
| extend UPN = iff(isnotempty(UPN_Target), UPN_Target, UPN_Initiator)
| where isnotempty(UPN)
| summarize EnrollmentTime = max(TimeGenerated) by UPN;
let fileAccess = OfficeActivity
| where TimeGenerated >= ago(lookback)
| where OfficeWorkload in ("SharePoint", "OneDrive")
| where Operation in (
    "FileDownloaded",
    "FileAccessed",
    "FileSyncDownloadedFull",
    "FileAccessedExtended"
  )
| extend NormalizedUser = tolower(UserId)
| where isnotempty(NormalizedUser)
| summarize
    AccessCount = count(),
    UniqueFiles = dcount(SiteUrl),
    SiteCount = dcount(SiteUrl),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated),
    SiteUrls = make_set(SiteUrl, 20),
    ClientIP = take_any(ClientIP)
    by NormalizedUser;
| where AccessCount >= bulkThreshold;
fileAccess
| join kind=inner recentMFAEnrollments on $left.NormalizedUser == $right.UPN
| where FirstAccess > EnrollmentTime
| where FirstAccess <= (EnrollmentTime + enrollmentWindow)
| extend MinutesBetweenEnrollmentAndAccess = datetime_diff('minute', FirstAccess, EnrollmentTime)
| project
    UPN,
    EnrollmentTime,
    FirstAccess,
    LastAccess,
    AccessCount,
    UniqueFiles,
    SiteCount,
    ClientIP,
    SiteUrls,
    MinutesBetweenEnrollmentAndAccess
| order by AccessCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Users who legitimately enroll MFA and then perform large file migrations or sync operations.
- Onboarding workflows that trigger MFA enrollment followed by automated file provisioning.
- Power users or developers who access many files as part of normal job function.

**Tuning notes:**
- Adjust bulkThreshold based on a percentile baseline of normal daily file access counts per user.
- Narrow enrollmentWindow from 48 hours to 12 hours to focus on immediate post-enrollment access if false positive volume is high.
- Add a NormalizedUser exclusion for known service accounts or sync agents that perform high-volume file access as part of normal operations.

**Risks / caveats:**
- AuditLogs and OfficeActivity require separate connectors: Entra ID diagnostic settings for AuditLogs and the Office 365 data connector for OfficeActivity; if either is not enabled the query returns no results.
- OfficeActivity.UserId format may not always be a UPN; in some tenants it may be an email alias or object ID, which would cause the tolower join to fail silently.
- bulkThreshold of 50 is a starting point; it should be baselined against the 90th percentile of daily file access counts per user in the environment before scheduling.
- OfficeActivity ingestion delay can be up to several hours, which may cause some correlated pairs to appear outside the enrollment window when queried in near-real-time.

### Triage Runbook

**First 15 minutes:**
- Confirm the file access began after the MFA registration and assess whether the volume and breadth are unusual for the user.
- Review the accessed sites, file types, and client IP to determine whether this looks like bulk download, sync, or manual browsing.
- Check whether the account also showed suspicious sign-ins, Graph enumeration, or mailbox access in the same period.
- Identify whether the activity is concentrated on sensitive sites, finance/legal folders, or a large number of distinct files.

**Evidence to collect:**
- OfficeActivity records showing operation type, site URL, client IP, and access timestamps.
- The MFA enrollment event and any suspicious sign-in details for the same UPN.
- Counts of unique files, sites, and operations to distinguish bulk collection from normal collaboration.
- Any download, sync, sharing, or deletion actions associated with the same account.

**Pivot points:**
- OfficeActivity for the same user over the last 7 days to establish normal file access patterns.
- AuditLogs and SigninLogs for the same account to correlate enrollment, sign-in source, and any identity changes.
- SharePoint/OneDrive activity for other accounts from the same IP or device to identify broader compromise.
- Defender XDR or M365 logs for file sharing, link creation, or mass download indicators.

**Benign explanations:**
- Legitimate large file migration, sync, or archive activity by the user.
- Onboarding or project work that requires accessing many documents in a short period.
- Automated sync clients or approved service accounts performing expected bulk access.

**Escalation criteria:**
- Access volume, site breadth, or file diversity is far above the user’s baseline and not explained by job function.
- The account accessed sensitive repositories, downloaded many files, or used an unfamiliar IP/device after MFA enrollment.
- There are concurrent signs of compromise such as suspicious sign-ins, enumeration, or sharing activity.
- The user denies the activity or the account is not expected to perform bulk file access.

**Containment actions:**
- Revoke sessions and disable the account if the activity is unauthorized or clearly malicious.
- Reset credentials and require MFA re-registration through a trusted channel.
- Suspend external sharing or block suspicious download activity if the platform supports immediate control and the incident is active.
- Preserve file access logs and notify data owners if sensitive repositories were accessed.

**Closure criteria:**
- The bulk access is validated as legitimate business activity or approved automation.
- No additional suspicious access, sharing, or exfiltration indicators are present.
- The account’s access pattern matches its normal role or a documented project.
- Any unauthorized session has been terminated and the account is remediated.

<br/>
---
<br/>

## Detection 4: Executive Display Name Spoofing Email to Finance Recipients

### Detection Opportunity

Inbound emails where the sender display name matches known executive names but the sending domain does not match the organizational domain, delivered to finance team recipients, consistent with AI-assisted BEC executive impersonation campaigns targeting invoice and payment fraud.

### Intelligence Context

- Microsoft Security Blog: Protecting organizations from AI-assisted executive impersonation and invoice fraud — [https://www.microsoft.com/en-us/security/blog/2026/09/10/protecting-organizations-ai-assisted-executive-impersonation-invoice-fraud/](https://www.microsoft.com/en-us/security/blog/2026/09/10/protecting-organizations-ai-assisted-executive-impersonation-invoice-fraud/)
  - Context: Threat actors used AI-assisted techniques to impersonate executives via display name spoofing in emails targeting finance teams, delivering fake invoices to facilitate ACH payment fraud.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1566, T1566.003, T1585
- Products: Not specified
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: T1566, T1566.003, T1585

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1566 Phishing/ T1566.003 Spearphishing via Service (medium); Resource Development: T1585 Establish Accounts (low)

### Deployment Gates

- OfficeActivity does not expose a SenderDisplayName field separate from SenderAddress, making display name spoofing detection impossible in that table; EmailEvents from Microsoft Defender XDR is required and must be available in the Sentinel workspace via the Defender XDR connector or Advanced Hunting.

**Required telemetry:**
- EmailEvents

### KQL

```kql
let invoiceKeywords = dynamic(["invoice", "payment", "wire transfer", "ACH", "remittance", "bank details", "urgent payment"]);
let executiveTitleKeywords = dynamic(["CEO", "CFO", "COO", "President", "Chief Executive", "Chief Financial", "Managing Director"]);
let orgDomains = dynamic(["REPLACE_WITH_ORG_DOMAIN_1", "REPLACE_WITH_ORG_DOMAIN_2"]);
let financeKeywords = dynamic(["finance", "accounts", "payable", "treasury", "payments"]);
EmailEvents
| where TimeGenerated >= ago(7d)
| where DeliveryAction == "Delivered"
| where SenderDisplayName has_any (executiveTitleKeywords)
| where not(SenderFromDomain has_any (orgDomains))
| where Subject has_any (invoiceKeywords)
| where RecipientEmailAddress has_any (financeKeywords)
| project TimeGenerated, SenderDisplayName, SenderFromAddress, SenderFromDomain, RecipientEmailAddress, Subject, DeliveryAction, NetworkMessageId
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate external vendors whose display names coincidentally contain executive title keywords.
- Newsletters or automated systems with display names containing CEO, CFO, or similar titles.
- Finance team members receiving legitimate invoice emails from external parties.

**Tuning notes:**
- Replace orgDomains list with the organization's actual email domain(s) before deployment.
- Replace financeKeywords with an explicit Sentinel watchlist of finance team UPN addresses.
- Add known executive full names to executiveTitleKeywords or create a separate executive name watchlist for higher-fidelity matching.
- Add a SenderFromDomain exclusion list of known trusted external invoice vendors to suppress recurring legitimate invoice traffic.

**Risks / caveats:**
- OfficeActivity does not expose a SenderDisplayName field separate from SenderAddress, making display name spoofing detection impossible in that table; EmailEvents from Microsoft Defender XDR is required and must be available in the Sentinel workspace via the Defender XDR connector or Advanced Hunting.
- The organizational email domain and executive display name list are required inputs that must be supplied before the query can run meaningfully; the query as written uses placeholder dynamic lists that must be replaced with real values.
- orgDomains list contains placeholder values that must be replaced with the organization's actual email domains before the query produces meaningful results.
- financeKeywords matching on RecipientEmailAddress is a weak proxy; replacing with an explicit watchlist of finance team UPNs will significantly improve precision.

### Triage Runbook

**First 15 minutes:**
- Inspect the sender display name, from address, and domain to confirm whether the message is external and impersonates a known executive.
- Review the subject and body for invoice, payment, wire transfer, or urgency language and check whether the recipient is in finance.
- Check whether the message was delivered to multiple recipients or followed by replies, forwarding, or attachment/link interaction.
- Search for similar messages sent to other finance users or from the same sender domain.

**Evidence to collect:**
- EmailEvents details including SenderDisplayName, SenderFromAddress, SenderFromDomain, RecipientEmailAddress, Subject, DeliveryAction, and NetworkMessageId.
- Message body, attachments, and URLs if available through mail security tooling.
- Recipient list and whether the message was delivered, quarantined, or reported by users.
- Any related messages from the same sender domain or with the same display name pattern.

**Pivot points:**
- EmailEvents for the same sender address, domain, or NetworkMessageId across the last 7 days.
- EmailEvents for other finance recipients to determine campaign scope.
- Defender XDR or mail security logs for URL clicks, attachment detonations, or user reports.
- Tenant allowlists/blocklists and historical mail flow for the sender domain.

**Benign explanations:**
- A legitimate external vendor whose display name resembles an executive title.
- A real executive using an external mailbox during travel or merger activity.
- A routine invoice email from a trusted supplier that happens to target finance recipients.

**Escalation criteria:**
- The sender domain is newly registered, lookalike, or otherwise suspicious.
- The message requests urgent payment, bank detail changes, gift cards, or secrecy.
- Multiple finance recipients received similar messages or users interacted with the content.
- The impersonated executive confirms they did not send the email.

**Containment actions:**
- Quarantine or purge the message from mailboxes if it is confirmed malicious and the platform supports it.
- Block the sender domain or address if it is clearly abusive and not a legitimate vendor.
- Warn finance recipients and instruct them not to respond or process payment requests.
- Escalate to fraud and legal teams if payment instructions or invoice changes were requested.

**Closure criteria:**
- The message is confirmed as legitimate or blocked and removed from circulation.
- No additional impersonation messages or user interactions are found.
- Finance recipients have been notified if needed and no payment action occurred.
- The sender is added to appropriate allow/block controls based on validation.

<br/>
---
<br/>

## Detection 5: Root-Level Process Access to SPIRE Agent Socket on Kubernetes Node

### Detection Opportunity

Root-level process execution on a Kubernetes node accessing SPIRE agent Unix domain socket paths or SVID-related files, indicating potential post-exploitation identity harvesting from co-located workloads.

### Intelligence Context

- Unit 42: The Machine With Many Faces: Post-Exploitation Identity Misuse in SPIFFE/SPIRE — [https://unit42.paloaltonetworks.com/kubernetes-spiffe-spire-identity-spoofing/](https://unit42.paloaltonetworks.com/kubernetes-spiffe-spire-identity-spoofing/)
  - Context: Attackers with root access on a compromised Kubernetes node accessed SPIFFE/SPIRE metadata and agent socket paths to harvest co-located workload identities (SVIDs) for lateral movement and impersonation.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1552, T1552.001, T1083
- Products: SPIFFE, SPIRE
- Platforms: Kubernetes
- Malware: Not specified
- Tools: Not specified
- Search tags: SPIFFE, SPIRE, Kubernetes, T1552, T1552.001, T1083

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1552 Unsecured Credentials/ T1552.001 Credentials In Files (low); Discovery: T1083 File and Directory Discovery (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.

**Required telemetry:**
- Syslog

### KQL

```kql
let spirePathKeywords = dynamic([
    "spire-agent",
    "/run/spire",
    "/tmp/spire",
    "workload.sock",
    "agent.sock",
    "spiffe",
    "svid"
]);
let legitimateSpireProcesses = dynamic(["spire-agent", "spire-server"]);
Syslog
| where TimeGenerated >= ago(7d)
| where Facility in ("kern", "daemon", "auth", "authpriv", "user")
| where SyslogMessage has_any (spirePathKeywords)
| where SyslogMessage has_any ("uid=0", "euid=0")
| where not(ProcessName in (legitimateSpireProcesses))
| summarize
    EventCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SampleMessages = make_set(SyslogMessage, 5)
    by HostName, ProcessName, Facility
| order by EventCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate SPIRE agent startup, health-check, or rotation operations that generate syslog messages referencing socket paths.
- Container runtime processes running as root that interact with SPIRE sockets as part of workload identity provisioning.
- Security scanning tools running as root that enumerate socket files on the node.

**Tuning notes:**
- Deploy auditd on Kubernetes nodes with a rule such as '-a always,exit -F arch=b64 -S openat -F path=/run/spire/sockets/agent.sock -F auid>=0 -k spire_socket_access' to generate reliable socket access audit events.
- Scope HostName to known Kubernetes node hostnames using a Sentinel watchlist to avoid matching non-Kubernetes Linux hosts.
- Add any custom SPIRE socket paths used in the deployment to the spirePathKeywords list.
- Add additional legitimate process names that are expected to access SPIRE sockets in the environment to the legitimateSpireProcesses exclusion list.

**Risks / caveats:**
- Syslog ingestion from Kubernetes nodes requires Azure Monitor Agent or the legacy Syslog connector to be deployed and configured on each node; if not deployed, the Syslog table will contain no node-level events.
- Standard syslog facilities (kern, daemon, auth) do not reliably capture Unix domain socket access events; auditd with a rule targeting the SPIRE socket path is required to generate the relevant log messages.
- SPIRE agent socket paths are deployment-specific and may differ from /run/spire and /tmp/spire used in the query; custom paths will not be detected without modification.
- Without auditd configured with OPENAT/OPEN syscall rules targeting SPIRE socket paths, standard syslog will not capture socket access events and the query will return no results.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a Kubernetes node and identify whether the process is expected on that node.
- Review the process name, command line, and parent process to determine whether the access came from a legitimate agent, container runtime, or an unknown binary.
- Check whether the access targeted SPIRE socket paths, SVID files, or other identity-related locations and whether it occurred as root.
- Look for concurrent signs of node compromise such as new processes, suspicious containers, privilege escalation, or outbound connections.

**Evidence to collect:**
- Syslog messages showing the exact path accessed, process name, facility, and timestamps.
- Host inventory details for the node, including whether SPIRE is deployed and which workloads should access it.
- Process lineage or auditd records if available to confirm the command, parent, and user context.
- Any container, kubelet, or node security alerts around the same time.

**Pivot points:**
- Syslog and auditd-related logs on the same host for additional file, socket, or privilege events.
- Kubernetes audit logs for pod creation, exec, or node access around the same time.
- Endpoint or EDR telemetry for the host to identify the process hash, command line, and network activity.
- Logs from other nodes to see whether the same process or pattern appears elsewhere.

**Benign explanations:**
- Legitimate SPIRE agent or server maintenance activity.
- Container runtime or node bootstrap processes that interact with SPIRE as part of workload identity provisioning.
- Security scanning or administrative troubleshooting performed by authorized staff.

**Escalation criteria:**
- The process is unknown, unsigned, or not expected on the node.
- There is evidence of root-level access combined with identity file or socket probing.
- The node shows additional compromise indicators such as suspicious containers, persistence, or outbound beaconing.
- SPIRE identities or SVIDs appear to have been exposed or used from an unexpected workload.

**Containment actions:**
- Isolate the Kubernetes node from the network if compromise is likely and operationally feasible.
- Stop or quarantine the suspicious process/container and preserve volatile evidence.
- Rotate affected SPIRE identities or credentials if exposure is confirmed.
- Notify platform and container security teams to assess cluster-wide impact.

**Closure criteria:**
- The process is identified as legitimate node or SPIRE activity.
- No additional suspicious root-level access or identity harvesting indicators are found.
- The node is clean after review or has been remediated and reimaged if needed.
- Any affected SPIRE identities have been rotated or validated as uncompromised.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- Microsoft Graph Enumeration Operations from Recently MFA-Registered Account: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- Executive Display Name Spoofing Email to Finance Recipients: OfficeActivity does not expose a SenderDisplayName field separate from SenderAddress, making display name spoofing detection impossible in that table; EmailEvents from Microsoft Defender XDR is required and must be available in the Sentinel workspace via the Defender XDR connector or Advanced Hunting.
- Root-Level Process Access to SPIRE Agent Socket on Kubernetes Node: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.

**Shared-table notes:**
- AuditLogs: shared by MFA Method Registration Following Suspicious Sign-In; Microsoft Graph Enumeration Operations from Recently MFA-Registered Account; Bulk SharePoint and OneDrive Access from Account with Recent MFA Registration

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: MFA Method Registration Following Suspicious Sign-In; Bulk SharePoint and OneDrive Access from Account with Recent MFA Registration.
2. Resolve environment-mapping detections next: Executive Display Name Spoofing Email to Finance Recipients; Root-Level Process Access to SPIRE Agent Socket on Kubernetes Node.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Microsoft Graph Enumeration Operations from Recently MFA-Registered Account.

### Hunting Agenda and Promotion Criteria

- Microsoft Graph Enumeration Operations from Recently MFA-Registered Account: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Executive Display Name Spoofing Email to Finance Recipients: OfficeActivity does not expose a SenderDisplayName field separate from SenderAddress, making display name spoofing detection impossible in that table; EmailEvents from Microsoft Defender XDR is required and must be available in the Sentinel workspace via the Defender XDR connector or Advanced Hunting..
- Root-Level Process Access to SPIRE Agent Socket on Kubernetes Node: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling..

### Unique Blind Spot Callout

This run exposes an identity-risk licensing blind spot: detections using RiskLevelDuringSignIn lose fidelity in tenants without Entra ID P2 risk enrichment.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
