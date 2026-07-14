---
layout: post
title: "Detection Engineering Brief - Tuesday, July 14, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-14
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - ShinyHunters
  - Microsoft Entra ID
  - CVE-2026-41264
  - Flowise
  - Flowise CSV_Agents
  - macOS
  - Metasploit
  - T1078.004
  - T1098.003
  - T1078
  - T1098
  - T1190
---

## Detection Engineering Summary

This brief produced 4 detection candidates.

1 production candidate, 1 hunting-only, 2 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: ShinyHunters, Microsoft Entra ID, CVE-2026-41264, Flowise, Flowise CSV_Agents, macOS, Metasploit, T1078.004, T1098.003, T1078, T1098, T1190.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: ShinyHunters - Guest Account Accessing Sensitive SaaS Resources After Misconfigured Provisioning; CVE-2026-41264 - Python Process Spawned as Child of Flowise Node.js Service; CVE-2026-41264 - Unauthenticated POST to Flowise CSV_Agents API Endpoint.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: ShinyHunters - OAuth Consent Grant to Unfamiliar Application

### Detection Opportunity

Adversary abuses OAuth consent flow to grant permissions to an unfamiliar or newly registered application in Entra ID, enabling persistent access to SaaS resources.

### Intelligence Context

- Microsoft Security Blog: Defending SaaS-based applications against ShinyHunters OAuth abuse — [https://www.microsoft.com/en-us/security/blog/2026/07/13/defending-saas-based-applications-against-shinyhunters-oauth-abuse/](https://www.microsoft.com/en-us/security/blog/2026/07/13/defending-saas-based-applications-against-shinyhunters-oauth-abuse/)
  - Context: ShinyHunters was reported abusing OAuth consent flows in SaaS environments to gain persistent access. The campaign involved granting OAuth permissions to attacker-controlled or unfamiliar applications, enabling access beyond the initial compromised account.

### Search Metadata

- CVEs: Not specified
- Threat actors: ShinyHunters
- ATT&CK tags: T1078.004, T1098.003, T1078, T1098
- Products: Microsoft Entra ID
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: ShinyHunters, Microsoft Entra ID, T1078.004, T1098.003, T1078, T1098

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1078 Valid Accounts/ T1078.004 Cloud Accounts (high); Persistence: T1098 Account Manipulation/ T1098.003 Additional Cloud Roles (medium)

### Deployment Gates

- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Required telemetry:**
- AuditLogs, SigninLogs

### KQL

```kql
let ConsentOps = AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName in ("Consent to application", "Add OAuth2PermissionGrant")
| where Result == "success"
| extend ConsentType = tostring(AdditionalDetails[0].value)
| extend AppName = tostring(TargetResources[0].displayName)
| extend InitiatingUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatingIP = tostring(InitiatedBy.user.ipAddress)
| where isnotempty(AppName)
| where isnotempty(InitiatingUPN);
let RiskySignins = SigninLogs
| where TimeGenerated > ago(1d)
| where RiskLevelDuringSignIn in ("medium", "high")
| project UserPrincipalName, RiskLevelDuringSignIn, SigninTime = TimeGenerated, SigninIP = IPAddress;
ConsentOps
| join kind=leftouter (
    RiskySignins
) on $left.InitiatingUPN == $right.UserPrincipalName
| extend TimeDiffMinutes = iff(isnotempty(SigninTime), abs(datetime_diff('minute', TimeGenerated, SigninTime)), int(null))
| extend CorrelatedRiskySignin = isnotempty(SigninTime) and TimeDiffMinutes <= 30
| where CorrelatedRiskySignin == true or ConsentType == "AllPrincipals"
| project TimeGenerated, OperationName, AppName, ConsentType, InitiatingUPN, InitiatingIP, RiskLevelDuringSignIn, SigninTime, SigninIP, CorrelatedRiskySignin
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate IT-sanctioned admin consent grants to new enterprise applications will fire on the AllPrincipals branch; allowlisting known approved applications by AppName is the primary mitigation.
- Users with elevated Entra ID risk scores due to travel or VPN usage who legitimately consent to a new application will generate alerts on the risky sign-in correlation branch.

**Tuning notes:**
- Populate a where AppName !in ('app1', 'app2') exclusion list from your approved OAuth application inventory to suppress known-good enterprise applications.
- To restrict to newly registered applications, join TargetResources[0].id against AADServicePrincipalSignInLogs or an application inventory watchlist filtered to CreatedDateTime within the last 30 days.
- If Entra ID P2 is not licensed, remove the RiskySignins join entirely and rely solely on the ConsentType == 'AllPrincipals' branch, then reclassify severity accordingly.

**Risks / caveats:**
- RiskLevelDuringSignIn in SigninLogs requires Entra ID P2 licensing; without it the field is absent and the risky sign-in correlation arm produces no results, leaving only the AllPrincipals branch active.
- ConsentType extracted from AdditionalDetails[0].value is not a guaranteed schema position; the key name and array index may differ across tenant configurations and Entra ID audit log schema versions.
- Without an approved-application allowlist applied via a where AppName !in (...) clause, admin consent grants to any new application will alert; allowlist tuning is required to reduce volume in environments with frequent legitimate OAuth app onboarding.
- The 30-minute correlation window between consent and risky sign-in is a heuristic; environments with long authentication session reuse may miss correlated events or produce stale correlations.

### Triage Runbook

**First 15 minutes:**
- Identify the consenting account, the application name, consent type, and whether the alert came from the AllPrincipals branch or a risky sign-in correlation.
- Check whether the app is in your approved enterprise application inventory or allowlist; if not, treat it as suspicious until proven otherwise.
- Review the initiating IP, sign-in risk, and recent sign-in history for the consenting user to determine whether the consent followed a suspicious login or impossible travel event.
- Confirm whether the consent granted high-impact permissions such as offline_access, Mail.Read, Files.Read.All, Directory.Read.All, or admin-consent scope equivalents.
- Look for follow-on activity from the app service principal or user account, such as mailbox access, file downloads, or additional consent grants.

**Evidence to collect:**
- AuditLogs event details for the consent operation, including OperationName, Result, AdditionalDetails, TargetResources, and InitiatedBy.
- SigninLogs for the consenting user around the alert time, including RiskLevelDuringSignIn, IPAddress, and sign-in timestamps.
- Application registration and service principal details for the AppName, including publisher, app ID, tenant ID, and permission scopes.
- Any recent admin-consent or app-role assignment events for the same user or tenant.
- Subsequent access logs showing use of the newly consented application against Exchange, SharePoint, OneDrive, or other SaaS resources.

**Pivot points:**
- AuditLogs for other consent grants, app role assignments, and service principal changes by the same InitiatingUPN.
- SigninLogs for the InitiatingUPN and any sign-ins from the same InitiatingIP or unusual geolocation in the prior 24 hours.
- Service principal and enterprise application inventory to validate whether AppName is known and approved.
- Mailbox, SharePoint, and OneDrive audit logs to identify post-consent access by the application or user.
- Entra ID risk and identity protection events for the consenting account.

**Benign explanations:**
- An IT or security administrator may have intentionally granted admin consent to a newly onboarded business application.
- A legitimate SaaS integration or automation tool may appear unfamiliar if it was recently deployed by another team.
- A user may have consented to a low-risk app during normal productivity onboarding, especially in tenants with permissive user-consent settings.

**Escalation criteria:**
- The app is not in the approved application inventory and has broad or sensitive permissions.
- The consent was granted by a user with elevated privileges or followed a medium/high-risk sign-in.
- There is evidence of post-consent access to sensitive data, additional consent grants, or suspicious mailbox/file activity.
- The app publisher is unverified, newly registered, or the app is multi-tenant with no business justification.

**Containment actions:**
- Revoke the OAuth consent and disable or remove the service principal if the app is unauthorized.
- Reset the consenting account credentials and revoke active sessions if the account shows signs of compromise.
- Block the application or publisher in Entra ID if it is confirmed malicious or unauthorized.
- Review and tighten user-consent settings and admin-consent workflow to prevent recurrence.

**Closure criteria:**
- The application is confirmed approved and the consent is documented as a legitimate change.
- No suspicious sign-in, privilege escalation, or post-consent data access is found.
- The app permissions are validated as appropriate for the business use case.
- Any necessary allowlist or policy updates have been completed and documented.

<br/>
---
<br/>

## Detection 2: ShinyHunters - Guest Account Accessing Sensitive SaaS Resources After Misconfigured Provisioning

### Detection Opportunity

Guest accounts in Entra ID access sensitive SaaS application resources, consistent with ShinyHunters targeting of misconfigured guest access in SaaS environments.

### Intelligence Context

- Microsoft Security Blog: Defending SaaS-based applications against ShinyHunters OAuth abuse — [https://www.microsoft.com/en-us/security/blog/2026/07/13/defending-saas-based-applications-against-shinyhunters-oauth-abuse/](https://www.microsoft.com/en-us/security/blog/2026/07/13/defending-saas-based-applications-against-shinyhunters-oauth-abuse/)
  - Context: ShinyHunters was reported targeting misconfigured guest access in SaaS environments. Guest accounts with overly permissive access represent an exploitation path for lateral movement and data access within victim tenants.

### Search Metadata

- CVEs: Not specified
- Threat actors: ShinyHunters
- ATT&CK tags: T1078.004, T1098.003, T1078, T1098
- Products: Microsoft Entra ID
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: ShinyHunters, Microsoft Entra ID, T1078.004, T1098.003, T1078, T1098

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1078 Valid Accounts/ T1078.004 Cloud Accounts (high); Persistence: T1098 Account Manipulation/ T1098.003 Additional Cloud Roles (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- SigninLogs, AuditLogs

### KQL

```kql
let GuestSignins = SigninLogs
| where TimeGenerated > ago(7d)
| where UserType == "Guest"
| where ResultType == 0
| where GuestUPN has "#EXT#"
| where ConditionalAccessStatus != "success" or isempty(ConditionalAccessStatus)
| project GuestUPN = UserPrincipalName, AppDisplayName, IPAddress, ConditionalAccessStatus, SigninTime = TimeGenerated;
let RecentGuestProvisioning = AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in ("Add user", "Invite external user", "Update user")
| extend ProvisionedUPN = tostring(TargetResources[0].userPrincipalName)
| where ProvisionedUPN has "#EXT#"
| project ProvisionedUPN, OperationName, ProvisionTime = TimeGenerated;
GuestSignins
| join kind=inner (
    RecentGuestProvisioning
) on $left.GuestUPN == $right.ProvisionedUPN
| where SigninTime > ProvisionTime
| extend DaysSinceProvisioning = datetime_diff('day', SigninTime, ProvisionTime)
| project SigninTime, GuestUPN, AppDisplayName, IPAddress, ConditionalAccessStatus, OperationName, ProvisionTime, DaysSinceProvisioning
| order by SigninTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate external collaborators invited for projects who sign in to Teams, SharePoint, or other collaboration apps will generate high volumes of matches; application exclusion is required.
- Guest accounts in tenants that do not enforce Conditional Access for guests will match on every sign-in due to empty ConditionalAccessStatus.
- Bulk guest provisioning events such as B2B collaboration onboarding campaigns will produce large result sets during the 30-day window.

**Tuning notes:**
- Add a where AppDisplayName !in ('Microsoft Teams', 'SharePoint Online', 'Office 365 SharePoint Online', 'My Apps') exclusion to reduce noise from legitimate guest collaboration.
- Narrow the provisioning lookback from 30 days to 7 days to focus on newly invited guests with immediate access activity.
- Consider scheduling only after baselining the volume of matching guest sign-ins in your tenant over a 7-day period to set appropriate alert thresholds.

**Risks / caveats:**
- TargetResources[0].userPrincipalName may not be populated for all guest provisioning audit events; 'Add user' and 'Update user' operations may store the UPN under a different TargetResources property depending on the Entra ID audit log schema version, causing the join to produce no results for those operation types.
- Without an AppDisplayName exclusion list for known collaboration applications such as Microsoft Teams and SharePoint Online, this query will produce high volumes of results in any tenant with active guest collaboration.
- The 30-day provisioning lookback window means long-standing guest accounts that were provisioned more than 30 days ago will not be correlated even if their access is anomalous.
- TargetResources[0].userPrincipalName may be null for some AuditLogs operation types; the '#EXT#' filter mitigates false joins but may also drop valid provisioning events where UPN is stored at a different array index.

### Triage Runbook

**First 15 minutes:**
- Identify the guest UPN, target application, source IP, and provisioning event that created or updated the guest account.
- Confirm whether the guest account and application are expected for an active business collaboration or partner relationship.
- Check whether the guest sign-in occurred soon after provisioning and whether Conditional Access was bypassed, absent, or failing.
- Review the guest’s recent activity for access to sensitive sites, files, chats, or application data beyond the stated collaboration need.
- Determine whether the guest account has access to more resources than intended, especially if the app is not a standard collaboration platform.

**Evidence to collect:**
- SigninLogs for the guest account, including AppDisplayName, IPAddress, ConditionalAccessStatus, and sign-in timestamps.
- AuditLogs for the guest provisioning event, including OperationName, ProvisionTime, and the provisioning source.
- Guest account attributes, group memberships, and role assignments in Entra ID.
- Application and resource access logs showing what the guest accessed after provisioning.
- Any related invitation, sponsorship, or approval records that justify the guest account.

**Pivot points:**
- SigninLogs for the same GuestUPN across the last 7 to 30 days to identify repeated access patterns.
- AuditLogs for other guest invites, updates, or role assignments tied to the same sponsor or administrator.
- SharePoint, Teams, and other SaaS audit logs for file access, downloads, or sharing activity by the guest.
- Entra ID group and role membership data to see whether the guest has excessive privileges.
- Conditional Access and Identity Protection events for the guest and sponsoring account.

**Benign explanations:**
- A legitimate external collaborator may be accessing Teams, SharePoint, or another shared workspace as part of an approved project.
- A newly invited guest may sign in immediately after provisioning as part of normal onboarding.
- Tenants with weak or absent guest Conditional Access controls may generate alerts for ordinary guest collaboration activity.

**Escalation criteria:**
- The guest account is not tied to a known business sponsor or approved collaboration project.
- The guest accessed sensitive resources outside the expected application set or downloaded unusual volumes of data.
- The guest has elevated group membership, role assignments, or access to restricted sites.
- Multiple guest accounts from the same sponsor or domain show similar suspicious access patterns.

**Containment actions:**
- Disable or remove the guest account if it is unauthorized or no longer needed.
- Revoke the guest’s access to sensitive groups, sites, and applications.
- Remove excessive guest role assignments or group memberships.
- If abuse is confirmed, review sponsor controls and guest invitation policies to prevent recurrence.

**Closure criteria:**
- The guest account is validated against a business sponsor and approved collaboration need.
- Access is limited to expected applications and resources.
- No evidence of data exfiltration, privilege abuse, or repeated suspicious access is found.
- Any excessive permissions discovered have been removed and documented.

<br/>
---
<br/>

## Detection 3: CVE-2026-41264 - Python Process Spawned as Child of Flowise Node.js Service

### Detection Opportunity

Arbitrary Python code execution through insufficient sandboxing in Flowise CSV_Agents, where a Python interpreter is spawned as a child of the Flowise Node.js process following a CSV upload.

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Exploits for FlowiseAI CSV Agent and MacOS Package Kit — [https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-exploits-for-flowiseai-csv-agent-and-macos-package-kit](https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-exploits-for-flowiseai-csv-agent-and-macos-package-kit)
  - Context: CVE-2026-41264 allows unauthenticated attackers to upload a CSV file containing arbitrary Python code to the Flowise CSV_Agents endpoint and execute it due to insufficient sandboxing. A Metasploit module was released for this vulnerability. The exploit results in Python being spawned as a child of the Flowise Node.js process.

### Search Metadata

- CVEs: CVE-2026-41264
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Flowise, Flowise CSV_Agents
- Platforms: macOS
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-41264, Flowise, Flowise CSV_Agents, macOS, Metasploit, T1190

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let FlowisePythonExec = DeviceProcessEvents
| where TimeGenerated > ago(1d)
| where FileName in~ ("python", "python3", "python.exe")
| where InitiatingProcessFileName in~ ("node", "node.exe")
| where InitiatingProcessCommandLine has_any ("flowise", "Flowise")
| project DeviceName, AccountName, PythonLaunchTime = TimeGenerated, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName;
let FlowiseCSVWrite = DeviceFileEvents
| where TimeGenerated > ago(1d)
| where ActionType == "FileCreated"
| where FileName endswith ".csv"
| where FolderPath has_any ("flowise", "Flowise")
| project DeviceName, CSVWriteTime = TimeGenerated, CSVFileName = FileName, FolderPath;
FlowisePythonExec
| join kind=inner (
    FlowiseCSVWrite
) on DeviceName
| where PythonLaunchTime > CSVWriteTime
| where datetime_diff('minute', PythonLaunchTime, CSVWriteTime) <= 5
| project PythonLaunchTime, CSVWriteTime, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessParentFileName, CSVFileName, FolderPath
| order by PythonLaunchTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate Flowise CSV_Agents usage that processes CSV files and invokes Python as part of normal operation will match this detection; distinguishing malicious from benign requires inspection of ProcessCommandLine content.
- Development or testing environments where developers upload CSV files and trigger Python execution as part of Flowise workflow testing will generate alerts.

**Tuning notes:**
- Before deploying, query DeviceProcessEvents for the exact InitiatingProcessCommandLine value used by the Flowise Node.js process in your environment and update the has_any filter to match.
- Query DeviceFileEvents for the actual FolderPath of CSV files written by Flowise in your environment and update the FolderPath filter accordingly.
- If Python is invoked with a version-suffixed binary name such as python3.11, extend the FileName filter to FileName startswith 'python'.

**Risks / caveats:**
- Microsoft Defender for Endpoint must be deployed and actively collecting process and file telemetry on the host running Flowise; without MDE coverage on that specific host the query returns no results.
- On macOS, Defender for Endpoint process telemetry collection for non-Microsoft processes depends on Full Disk Access being granted to the MDE sensor; without this permission child process creation events for Node.js may not be captured.
- The InitiatingProcessCommandLine has_any ('flowise', 'Flowise') filter must match the actual command line used to start the Flowise service in the target environment; if the process is launched via a path or wrapper that does not contain this string the query will not fire.
- The FolderPath has_any ('flowise', 'Flowise') filter must match the actual Flowise installation directory; custom installation paths will require this value to be updated.

### Triage Runbook

**First 15 minutes:**
- Identify the host, user account, Python command line, and the parent Node.js command line involved in the process chain.
- Check whether the Python launch occurred shortly after a CSV file was created in a Flowise-associated directory.
- Review the Python process command line for suspicious arguments, inline code, downloaded payloads, or script paths outside the Flowise workflow.
- Determine whether the Flowise instance is internet-facing and whether the timing aligns with a recent CSV upload or API interaction.
- Look for immediate follow-on activity such as network connections, file creation, shell spawning, or additional child processes.

**Evidence to collect:**
- DeviceProcessEvents for the Python process, parent Node.js process, and any child processes spawned afterward.
- DeviceFileEvents showing the CSV file creation time, file name, and folder path associated with the Flowise workflow.
- Process command lines for Node.js and Python, including any script names, arguments, or encoded content.
- Network telemetry from the host around the execution time, including outbound connections and destination IPs or domains.
- Host inventory details confirming whether the device runs Flowise in production, development, or test mode.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName to identify additional suspicious processes, shells, or scripting engines.
- DeviceFileEvents for recent CSV, script, or archive creation on the host.
- DeviceNetworkEvents or equivalent network telemetry for outbound connections from the Flowise host after the Python launch.
- Defender XDR alerts on the same host for exploit, malware, or persistence activity.
- Application logs from Flowise, if available, to correlate the CSV upload or job execution.

**Benign explanations:**
- A legitimate Flowise CSV_Agents workflow may intentionally invoke Python as part of normal automation.
- A developer or tester may be exercising the CSV_Agents feature in a lab or staging environment.
- Some deployments may use wrapper scripts or service managers that make the process chain look unusual even when benign.

**Escalation criteria:**
- The Python command line contains suspicious inline code, external downloads, or unexpected script execution.
- The host is internet-facing and the process chain aligns with a recent unauthenticated or untrusted CSV upload.
- There is evidence of post-exploitation behavior such as shell spawning, credential access, or outbound beaconing.
- The Flowise instance is production and the activity is not tied to a documented change or test.

**Containment actions:**
- Isolate the Flowise host if malicious execution is confirmed or strongly suspected.
- Stop the Flowise service and preserve volatile evidence if active exploitation is ongoing.
- Block inbound access to the vulnerable Flowise endpoint until patched or mitigated.
- Remove or quarantine any malicious files created during the execution chain.

**Closure criteria:**
- The process chain is confirmed as expected Flowise behavior in a known-good environment.
- No suspicious command-line content, network activity, or follow-on execution is found.
- The CSV upload and Python invocation are tied to a documented workflow or test case.
- Any environment-specific path or command-line tuning issues have been validated for future monitoring.

<br/>
---
<br/>

## Detection 4: CVE-2026-41264 - Unauthenticated POST to Flowise CSV_Agents API Endpoint

### Detection Opportunity

Unauthenticated HTTP POST request to the Flowise CSV_Agents run endpoint, consistent with exploitation of CVE-2026-41264 to achieve remote code execution.

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Exploits for FlowiseAI CSV Agent and MacOS Package Kit — [https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-exploits-for-flowiseai-csv-agent-and-macos-package-kit](https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-exploits-for-flowiseai-csv-agent-and-macos-package-kit)
  - Context: CVE-2026-41264 is exploited via an unauthenticated POST request to the CSV_Agents run method in Flowise. A Metasploit module exists for this vulnerability. The request uploads a malicious CSV file that is then executed server-side due to insufficient sandboxing.

### Search Metadata

- CVEs: CVE-2026-41264
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Flowise, Flowise CSV_Agents
- Platforms: macOS
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-41264, Flowise, Flowise CSV_Agents, macOS, Metasploit, T1190

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
let FlowiseAPIHits = CommonSecurityLog
| where TimeGenerated > ago(1d)
| where RequestMethod == "POST"
| where RequestURL has_any ("/api/v1/prediction", "csv_agent", "csvagent", "CSV_Agent")
| where toint(StatusCode) == 200
| extend DeviceName = tolower(Computer)
| project SourceIP, RequestURL, StatusCode, DestinationPort, HitTime = TimeGenerated, DeviceName;
let PythonSyslog = Syslog
| where TimeGenerated > ago(1d)
| where SyslogMessage has_any ("python", "python3")
| where Facility in ("daemon", "user")
| extend DeviceName = tolower(Computer)
| project DeviceName, SyslogMessage, ExecTime = TimeGenerated;
FlowiseAPIHits
| join kind=inner (
    PythonSyslog
) on DeviceName
| where ExecTime > HitTime
| where datetime_diff('minute', ExecTime, HitTime) <= 5
| project HitTime, ExecTime, SourceIP, RequestURL, StatusCode, DestinationPort, SyslogMessage, DeviceName
| order by HitTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate Flowise users uploading CSV files through the CSV_Agents interface will generate matching CommonSecurityLog entries; distinguishing malicious from benign requires inspection of SourceIP and subsequent Python syslog activity.
- Automated integration tests or CI/CD pipelines that POST to the Flowise API will match if they target the CSV_Agents endpoint.

**Tuning notes:**
- Confirm that CommonSecurityLog entries from the Flowise host contain populated RequestURL and RequestMethod fields by running a baseline query against CommonSecurityLog filtered to Computer matching the Flowise hostname.
- Confirm that Syslog entries from the Flowise host appear in the Syslog table by querying Syslog where Computer matches the Flowise hostname before deploying.
- Refine the RequestURL has_any filter to the exact API path used by the Flowise version in your environment after confirming the path from the Flowise access logs.
- Consider replacing the Syslog correlation arm with the DeviceProcessEvents-based detection (CVE-2026-41264 - Python Process Spawned as Child of Flowise Node.js Service) if MDE is deployed on the Flowise host, as that provides higher-fidelity process telemetry.

**Risks / caveats:**
- CommonSecurityLog.RequestURL and CommonSecurityLog.RequestMethod are only populated when the log source device type forwards HTTP access log fields in CEF format; a generic syslog forwarder without CEF mapping will not populate these fields, causing the query to return no results.
- CommonSecurityLog.StatusCode is not a native CEF field name; the actual field may be mapped as cs-status, sc-status, or a custom extension depending on the forwarder configuration, and may be absent or null.
- Syslog on macOS does not use traditional syslog facilities in the same way as Linux; Python process execution may not appear in Syslog at all on macOS without explicit audit daemon configuration, making the correlation arm non-functional on the stated platform.
- CommonSecurityLog.Computer may not match Syslog.Computer if the Flowise host reports different hostnames to different log pipelines, causing the join to produce no results.

### Triage Runbook

**First 15 minutes:**
- Identify the source IP, request URL, destination port, and response status for the POST request.
- Confirm whether the request was authenticated or came from an untrusted external source.
- Check for a matching Python execution or other suspicious process activity on the Flowise host within minutes of the request.
- Review the request path and timing for signs of automated exploitation, scanning, or Metasploit-style activity.
- Determine whether the Flowise instance should be exposed to the source network at all.

**Evidence to collect:**
- CommonSecurityLog entries for the request, including RequestMethod, RequestURL, StatusCode, SourceIP, and DestinationPort.
- Syslog or host process telemetry showing any Python execution or other post-request activity on the Flowise host.
- Flowise application or access logs, if available, to confirm the endpoint hit and any uploaded content.
- Firewall, reverse proxy, or load balancer logs to validate the request path and client identity.
- Host inventory and exposure details showing whether the service is internet-facing or restricted.

**Pivot points:**
- CommonSecurityLog for additional requests from the same SourceIP or to the same RequestURL.
- Syslog or DeviceProcessEvents for Python, Node.js, shell, or downloader activity on the same host.
- Firewall or proxy logs for repeated POSTs, scanning behavior, or other exploit attempts from the same source.
- Defender XDR or endpoint alerts on the Flowise host for suspicious child processes or file writes.
- Flowise application logs to correlate the request with job execution or CSV upload handling.

**Benign explanations:**
- A legitimate user or integration may be uploading a CSV through the Flowise interface.
- Automated testing or CI/CD validation may generate POSTs to the endpoint in a controlled environment.
- A reverse proxy or logging normalization issue may make an authenticated request appear unauthenticated in the collected logs.

**Escalation criteria:**
- The source IP is external, untrusted, or associated with repeated exploit attempts.
- The POST is followed by Python execution, shell spawning, or other suspicious host activity.
- The endpoint is internet-facing and there is no approved business reason for the request.
- Multiple requests or multiple hosts show the same exploit pattern.

**Containment actions:**
- Block the source IP or upstream network path if the request is confirmed malicious.
- Disable or restrict access to the vulnerable Flowise endpoint until patched.
- Isolate the Flowise host if there is evidence of successful exploitation.
- Preserve logs and host evidence before making disruptive changes when possible.

**Closure criteria:**
- The request is confirmed to be a legitimate, authorized application action.
- No correlated host execution or suspicious follow-on activity is found.
- The endpoint exposure is understood and documented, including any compensating controls.
- Any required patching, access restriction, or monitoring improvements have been completed.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Licensing / identity risk fields:**
- Entra ID P2 is required for RiskLevelDuringSignIn-based identity-risk detections.

**Schema / correlation keys:**
- ShinyHunters - Guest Account Accessing Sensitive SaaS Resources After Misconfigured Provisioning: Do not schedule yet; validate as an analyst-led hunt first.

**Other deployment dependency:**
- CVE-2026-41264 - Python Process Spawned as Child of Flowise Node.js Service: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Telemetry availability:**
- CVE-2026-41264 - Unauthenticated POST to Flowise CSV_Agents API Endpoint: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.

**Shared-table notes:**
- AuditLogs: shared by ShinyHunters - OAuth Consent Grant to Unfamiliar Application; ShinyHunters - Guest Account Accessing Sensitive SaaS Resources After Misconfigured Provisioning
- SigninLogs: shared by ShinyHunters - OAuth Consent Grant to Unfamiliar Application; ShinyHunters - Guest Account Accessing Sensitive SaaS Resources After Misconfigured Provisioning

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: ShinyHunters - OAuth Consent Grant to Unfamiliar Application.
2. Resolve environment-mapping detections next: CVE-2026-41264 - Python Process Spawned as Child of Flowise Node.js Service; CVE-2026-41264 - Unauthenticated POST to Flowise CSV_Agents API Endpoint.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: ShinyHunters - Guest Account Accessing Sensitive SaaS Resources After Misconfigured Provisioning.

### Hunting Agenda and Promotion Criteria

- ShinyHunters - Guest Account Accessing Sensitive SaaS Resources After Misconfigured Provisioning: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- CVE-2026-41264 - Python Process Spawned as Child of Flowise Node.js Service: Defender for Endpoint file-event coverage must be confirmed on the target host population..
- CVE-2026-41264 - Unauthenticated POST to Flowise CSV_Agents API Endpoint: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

This run exposes an identity-risk licensing blind spot: detections using RiskLevelDuringSignIn lose fidelity in tenants without Entra ID P2 risk enrichment.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
