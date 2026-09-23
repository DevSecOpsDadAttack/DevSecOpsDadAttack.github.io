---
layout: post
title: "Detection Engineering Brief - Wednesday, September 23, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-23
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Active Directory
  - Group Policy Objects
  - PAYLOAD
  - CVE-2026-94127
  - T1190
  - F5 BIG-IP APM
  - Microsoft identity
  - EvilTokens
  - T1059
  - T1059.001
  - T1047
  - T1528
  - T1566
  - T1566.002
---

## Detection Engineering Summary

This brief produced 4 detection candidates.

1 production candidate, 1 hunting-only, 2 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: Active Directory, Group Policy Objects, PAYLOAD, CVE-2026-94127, T1190, F5 BIG-IP APM, Microsoft identity, EvilTokens, T1059, T1059.001, T1047, T1528, T1566, T1566.002.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: PAYLOAD Ransomware - Suspicious GPO Modification by Non-Privileged Account; PAYLOAD Ransomware - PowerShell or WMI Activity Targeting GPO Paths Without File Creation; CVE-2026-94127 - Anomalous Unauthenticated Requests to F5 BIG-IP APM OAuth Endpoints.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: PAYLOAD Ransomware - Suspicious GPO Modification by Non-Privileged Account

### Detection Opportunity

Active Directory Group Policy Objects modified by accounts not typically associated with GPO administration, consistent with PAYLOAD ransomware abusing AD mechanisms for encryptionless, binary-less propagation.

### Intelligence Context

- Securelist: Group Policy hijacked: PAYLOAD ransomware weaponizes Active Directory GPO — [https://securelist.com/tr/payload-ransomware-via-group-policy/121335/](https://securelist.com/tr/payload-ransomware-via-group-policy/121335/)
  - Context: PAYLOAD ransomware was reported to weaponize Active Directory Group Policy Objects in an encryptionless, binary-less operation. No files are dropped; instead, AD mechanisms are abused directly, making GPO modification events the primary detectable artifact.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.001, T1047
- Products: Active Directory, Group Policy Objects
- Platforms: Not specified
- Malware: PAYLOAD
- Tools: Not specified
- Search tags: Active Directory, Group Policy Objects, PAYLOAD, T1059, T1059.001, T1047

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.001 PowerShell (high); Execution: T1047 Windows Management Instrumentation (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.

**Required telemetry:**
- SecurityEvent

### KQL

```kql
SecurityEvent
| where EventID in (5136, 5137)
| where SubjectUserName !endswith "$"
| where ObjectName has "groupPolicyContainer"
    or ObjectName matches regex @"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}"
| where OperationType has_any ("%%14674", "%%14675", "%%14676", "Value Added", "Value Deleted", "Object Created")
| summarize
    ModificationCount = count(),
    DistinctGPOs = dcount(ObjectName),
    Operations = make_set(OperationType, 10),
    SampleObjectNames = make_set(ObjectName, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SubjectUserName, SubjectDomainName, Computer
| extend TimespanMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| where TimespanMinutes <= 60
| where ModificationCount >= 3 or DistinctGPOs >= 2
| project
    FirstSeen,
    LastSeen,
    SubjectUserName,
    SubjectDomainName,
    Computer,
    ModificationCount,
    DistinctGPOs,
    Operations,
    SampleObjectNames,
    TimespanMinutes
| sort by ModificationCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate GPO administrators performing batch policy updates during change windows will trigger this rule if they exceed the modification thresholds.
- Automated configuration management tools or scripts that modify GPOs on a schedule may generate recurring alerts.
- Group Policy migration or import operations performed by authorized accounts will match the pattern.

**Tuning notes:**
- Run the validation query 'SecurityEvent → where EventID in (5136,5137) → take 10' first to confirm audit events are present and to inspect the actual format of ObjectName and OperationType fields before scheduling.
- Consider adding a watchlist of known GPO admin accounts and excluding them with '| where SubjectUserName !in (GPOAdminWatchlist)' to reduce false positives.
- The TimespanMinutes window can be narrowed to 30 minutes in environments with frequent legitimate GPO changes to improve signal quality.
- SampleObjectNames in the projection provides raw GPO distinguished names for analyst triage without requiring a separate lookup.

**Risks / caveats:**
- EventID 5136 and 5137 require the 'Audit Directory Service Changes' subcategory to be enabled in Windows Advanced Audit Policy on domain controllers. These events are absent by default and will produce no results if auditing is not configured.
- The OperationType field in SecurityEvent for AD object modification events may contain raw Windows message format codes (%%14674 etc.) or their resolved string equivalents depending on the MMA/AMA connector version and locale. The query must be validated against actual ingested event data to confirm which format is present.
- The ObjectName field for groupPolicyContainer objects in SecurityEvent contains the LDAP distinguished name of the object, not a simple GUID string. The filter logic must match the actual field content observed in the environment.
- The ModificationCount threshold of 3 and DistinctGPOs threshold of 2 must be baselined against the environment's normal GPO change rate before scheduling to avoid alert fatigue.

### Triage Runbook

**First 15 minutes:**
- Confirm the alerting account is not a known GPO administrator, service account, or approved automation identity.
- Review the sample GPO distinguished names and modification operations to see whether changes are concentrated on multiple GPOs in a short window.
- Check whether the source computer is a domain controller or an admin workstation used for legitimate policy management.
- Look for concurrent signs of account compromise such as unusual logon source, impossible travel, or recent password reset activity for the modifying account.

**Evidence to collect:**
- SubjectUserName, SubjectDomainName, Computer, ModificationCount, DistinctGPOs, Operations, FirstSeen, LastSeen, TimespanMinutes, SampleObjectNames.
- Related SecurityEvent 5136/5137 records for the same account and time window to confirm the exact GPO objects and change types.
- Recent logon events for the account and host to determine whether the activity was interactive, remote, or service-driven.
- Any change-management ticket or approved maintenance window covering the observed GPO edits.

**Pivot points:**
- SecurityEvent for EventID 5136 and 5137 around the alert window, filtered on SubjectUserName and ObjectName.
- SecurityEvent for logon events tied to SubjectUserName and Computer to identify the session origin.
- Active Directory or GPO management records to validate whether the modified GPOs are production policies or test objects.
- If available, endpoint telemetry from the modifying host to identify the process or script used to make the changes.

**Benign explanations:**
- A legitimate GPO administrator performed a batch policy update or migration during a change window.
- An approved configuration management tool or script modified multiple GPOs on behalf of an admin account.
- A policy import, backup restore, or migration operation caused multiple GPO change events in a short period.

**Escalation criteria:**
- The account is not a known GPO admin and no approved change exists.
- Multiple GPOs were modified rapidly, especially if the changes affect logon scripts, startup scripts, or security settings.
- The activity originated from an unusual host or from a user session inconsistent with normal administration.
- There are additional indicators of compromise on the same account, host, or domain controller.

**Containment actions:**
- Disable or reset the suspected account if unauthorized GPO modification is confirmed or strongly suspected.
- Revoke active sessions and Kerberos tickets for the account if available in your environment.
- Pause or revert the affected GPO changes through change-control procedures to stop further propagation.
- Isolate the source admin workstation or domain controller only if there is corroborating evidence of active compromise.

**Closure criteria:**
- The account is verified as an authorized GPO admin or approved automation identity.
- The changes are matched to a documented change ticket and expected maintenance activity.
- No additional suspicious AD activity, logon anomalies, or downstream policy abuse is found.
- Affected GPOs are reviewed and confirmed to contain only intended changes.

<br/>
---
<br/>

## Detection 2: PAYLOAD Ransomware - PowerShell or WMI Activity Targeting GPO Paths Without File Creation

### Detection Opportunity

PowerShell or WMI processes observed accessing Group Policy filesystem paths in an encryptionless, binary-less operation consistent with PAYLOAD ransomware abusing AD mechanisms without dropping executables.

### Intelligence Context

- Securelist: Group Policy hijacked: PAYLOAD ransomware weaponizes Active Directory GPO — [https://securelist.com/tr/payload-ransomware-via-group-policy/121335/](https://securelist.com/tr/payload-ransomware-via-group-policy/121335/)
  - Context: PAYLOAD ransomware operates without dropping binaries, relying on AD and GPO mechanisms. The fallback detection strategy from the feasibility mapping targets PowerShell or WMI activity modifying GPO paths as the primary behavioral indicator when no file artifacts are present.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1059.001, T1047
- Products: Active Directory, Group Policy Objects
- Platforms: Not specified
- Malware: PAYLOAD
- Tools: Not specified
- Search tags: Active Directory, Group Policy Objects, PAYLOAD, T1059, T1059.001, T1047

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter/ T1059.001 PowerShell (high); Execution: T1047 Windows Management Instrumentation (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe", "wmiprvse.exe", "wmic.exe")
| where ProcessCommandLine has_any (
    "SYSVOL",
    "GroupPolicy",
    "gpt.ini",
    "\\Policies\\",
    "Set-GPO",
    "New-GPO",
    "Import-GPO",
    "Get-GPO",
    "Copy-GPO"
)
| where AccountName !endswith "$"
| summarize
    CommandLines = make_set(ProcessCommandLine, 10),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    EventCount = count()
    by
    AccountName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    FileName,
    DeviceName
| project
    FirstSeen,
    LastSeen,
    AccountName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    FileName,
    DeviceName,
    EventCount,
    CommandLines
| sort by FirstSeen desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- GPO administrators using PowerShell cmdlets such as Set-GPO, New-GPO, or Import-GPO as part of routine policy management will match this query.
- Automated configuration management platforms (SCCM, Ansible, etc.) that invoke PowerShell against SYSVOL paths will generate results.
- Scheduled tasks on domain controllers that reference GroupPolicy paths for compliance or reporting purposes will appear in results.
- Security tooling that audits GPO configurations via PowerShell will match the command line patterns.

**Tuning notes:**
- Filter DeviceName to domain controller naming patterns in the environment to reduce noise from workstations where GPO cmdlets may be used by admins remotely.
- Add AccountName exclusions for known GPO admin service accounts and scheduled task identities after reviewing initial results.
- Extend the has_any list with environment-specific GPO management script names or paths if custom tooling is in use.
- Consider correlating results with DeviceLogonEvents to identify whether the account had an interactive or remote logon session on the DC at the time of the process event.

**Risks / caveats:**
- Defender for Endpoint must be deployed on domain controllers or systems with SYSVOL access for this query to capture relevant GPO-related process activity. Domain controllers are frequently excluded from EDR deployment in some organizations.
- ProcessCommandLine population requires 'Enable process creation events with command line' to be active in the Defender for Endpoint advanced settings or via Windows audit policy. If command line logging is disabled, the has_any filter will produce no matches.
- The command line string list is broad and will match legitimate GPO administration activity. Analyst review of CommandLines output is required for every result set.
- No file write correlation is included in this query because joining DeviceProcessEvents with DeviceFileEvents on process tree within a hunting query significantly increases complexity and query cost; analysts should pivot to DeviceFileEvents manually for process trees of interest.

### Triage Runbook

**First 15 minutes:**
- Inspect the command lines to confirm whether the activity is a known GPO management command or an unusual script touching SYSVOL or GroupPolicy paths.
- Identify the parent process and initiating account to determine whether the activity came from an admin tool, remote session, or suspicious launcher.
- Check whether the device is a domain controller or admin workstation where GPO management is expected.
- Look for repeated PowerShell or WMI executions from the same account or host within the alert window.

**Evidence to collect:**
- AccountName, InitiatingProcessAccountName, InitiatingProcessFileName, FileName, DeviceName, EventCount, and the full CommandLines set.
- Process tree details including ProcessId and InitiatingProcessId if available from endpoint telemetry.
- Any related file, script, or scheduled task activity on the same host around the same time.
- Recent sign-in or remote access activity for the account to validate whether the session was expected.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and AccountName to reconstruct the process tree.
- DeviceFileEvents or related endpoint file telemetry to check for writes to SYSVOL, Policies, or gpt.ini paths.
- DeviceLogonEvents to determine whether the account had an interactive or remote session on the host.
- If the host is a domain controller, review directory service and administrative activity around the same time.

**Benign explanations:**
- A legitimate administrator used PowerShell cmdlets such as Set-GPO, New-GPO, Import-GPO, or Copy-GPO.
- A configuration management platform or compliance script queried or updated GPO paths.
- A security or inventory tool used WMI or PowerShell to audit Group Policy settings.

**Escalation criteria:**
- The command line is not associated with a known admin workflow or approved tool.
- The activity is occurring on a domain controller or privileged admin host outside a change window.
- The same account is also involved in suspicious GPO modification events or other AD abuse.
- There is evidence of lateral movement, credential misuse, or follow-on malicious activity from the same host.

**Containment actions:**
- Disable the suspected account if the activity is not authorized and appears malicious.
- Isolate the host if it is a compromised admin workstation or domain controller with corroborating evidence.
- Terminate suspicious PowerShell or WMI sessions only if your response process supports safe interruption.
- Preserve process, script, and command-line evidence before remediation.

**Closure criteria:**
- The command lines are confirmed to be from approved GPO administration or automation.
- The initiating account and host are validated against a change ticket or maintenance activity.
- No suspicious file writes, persistence, or additional AD abuse is found.
- The activity is consistent with normal administrative baselines for the environment.

<br/>
---
<br/>

## Detection 3: CVE-2026-94127 - Anomalous Unauthenticated Requests to F5 BIG-IP APM OAuth Endpoints

### Detection Opportunity

Unauthenticated external traffic targeting F5 BIG-IP APM OAuth endpoints with anomalous response codes, consistent with exploitation attempts for CVE-2026-94127 remote code execution.

### Intelligence Context

- Rapid7: CVE-2026-94127: Critical Unauthenticated RCE in F5 BIG-IP APM — [https://www.rapid7.com/blog/post/etr-cve-2026-94127-critical-unauthenticated-rce-in-f5-big-ip-apm](https://www.rapid7.com/blog/post/etr-cve-2026-94127-critical-unauthenticated-rce-in-f5-big-ip-apm)
  - Context: An unauthenticated attacker with network access to a BIG-IP virtual server configured with an APM access policy and OAuth profile can send crafted traffic to achieve remote code execution. Detection relies on F5 syslog forwarded to Sentinel via CommonSecurityLog, targeting OAuth endpoint access patterns from external IPs with unusual HTTP response codes.

### Search Metadata

- CVEs: CVE-2026-94127
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: F5 BIG-IP APM
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-94127, T1190, F5 BIG-IP APM

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
CommonSecurityLog
| where DeviceVendor =~ "F5"
| where DeviceProduct has_any ("BIG-IP", "APM")
| where RequestURL has_any (
    "/oauth",
    "/oauth2",
    "/oauthclients",
    "/.well-known/openid",
    "/authorize",
    "/token"
)
| where (
    AdditionalExtensions has_any ("=500", "=502", "=503", "=400", "=403")
    or Activity has_any ("error", "fail", "denied")
)
| where isnotempty(SourceIP)
| where ipv4_is_private(SourceIP) == false
| summarize
    RequestCount = count(),
    DistinctURLs = dcount(RequestURL),
    SampleURLs = make_set(RequestURL, 5),
    ResponseCodes = make_set(AdditionalExtensions, 10),
    Activities = make_set(Activity, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP, DeviceProduct, DestinationPort
| where RequestCount >= 5
| extend TimespanMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| project
    FirstSeen,
    LastSeen,
    SourceIP,
    DeviceProduct,
    DestinationPort,
    RequestCount,
    DistinctURLs,
    SampleURLs,
    ResponseCodes,
    Activities,
    TimespanMinutes
| sort by RequestCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate OAuth clients that experience repeated authentication failures due to misconfiguration will generate error responses matching the pattern.
- Security scanners and vulnerability assessment tools targeting the APM OAuth endpoints from external IPs will match.
- Load balancer health checks or monitoring probes that hit OAuth endpoints and receive non-200 responses may appear in results.

**Tuning notes:**
- Run 'CommonSecurityLog → where DeviceVendor =~ "F5" → take 20 → project AdditionalExtensions, Activity, RequestURL' to inspect actual field content before scheduling.
- Adjust the AdditionalExtensions filter to use the exact key name emitted by the F5 APM CEF profile for HTTP response codes once the format is confirmed.
- Consider adding a GeoIP enrichment step using geo_info_from_ip_address() on SourceIP to prioritize results from unexpected geographic origins.
- The RequestCount threshold of 5 may need to be raised significantly in environments with high OAuth traffic volume from external partners or mobile clients.

**Risks / caveats:**
- CommonSecurityLog ingestion from F5 BIG-IP APM requires the F5 CEF syslog connector to be configured and active. Without this connector, the table will contain no F5 data and the query will return no results.
- The RequestURL field in CommonSecurityLog is only populated if the F5 APM logging profile is configured to emit HTTP request details at the CEF layer. Default F5 syslog configurations may not include request URL in the CEF message.
- Response codes in AdditionalExtensions are embedded as freeform key-value pairs in F5 CEF output. The has_any filter on raw strings '500', '502', etc. may produce false matches on other numeric values in the field. The exact key name used by F5 for HTTP response codes in CEF AdditionalExtensions must be validated against actual ingested data.
- CVE-2026-94127 is not present in public CVE databases as of the knowledge cutoff date. The OAuth endpoint paths used in the detection are inferred from the source article description and may not precisely match the actual exploitation path for this vulnerability.

### Triage Runbook

**First 15 minutes:**
- Confirm the source IP is external and not a known monitoring, partner, or vulnerability scanning address.
- Review the requested URLs and response patterns to see whether the traffic is concentrated on OAuth-related endpoints or broad probing.
- Check whether the affected BIG-IP device is internet-facing and whether the APM OAuth profile is enabled.
- Look for spikes in request volume, repeated failures, or unusual activity from the same source IP across multiple URLs.

**Evidence to collect:**
- SourceIP, DeviceProduct, DestinationPort, RequestCount, DistinctURLs, SampleURLs, ResponseCodes, Activities, FirstSeen, LastSeen, TimespanMinutes.
- Raw F5 syslog or CEF messages from the same time window to validate the response code and URL parsing.
- Device configuration details showing whether APM and OAuth are enabled on the targeted virtual server.
- Any concurrent device alerts, crashes, configuration changes, or unexpected admin logins on the F5 appliance.

**Pivot points:**
- CommonSecurityLog for the same SourceIP, DeviceProduct, and time range to identify additional endpoints or repeated failures.
- CommonSecurityLog for other external IPs hitting the same OAuth paths to determine whether this is broader scanning.
- F5 management or audit logs to check for configuration changes or administrative access around the alert time.
- Network telemetry or firewall logs to confirm whether the source IP is part of a known scanner or threat feed.

**Benign explanations:**
- A legitimate client or partner application is misconfigured and repeatedly failing OAuth authentication.
- A vulnerability scanner or external assessment tool is testing the exposed F5 service.
- A health check or monitoring probe is hitting OAuth endpoints and receiving non-200 responses.

**Escalation criteria:**
- The traffic is from an unknown external IP and is concentrated on OAuth endpoints with repeated errors.
- There are signs of exploitation beyond probing, such as unusual response behavior, crashes, or admin anomalies on the F5 device.
- Multiple external sources are targeting the same endpoints in a short period.
- The device is internet-facing and the organization has not yet validated patching or exposure to the referenced CVE.

**Containment actions:**
- Block or rate-limit the offending external IPs at the firewall or edge if the traffic is clearly malicious.
- Restrict exposure of the affected virtual server if business impact allows and exploitation risk is high.
- Engage the F5 platform owner to validate patch status and review device health immediately.
- Preserve logs and configuration state before making changes to the appliance.

**Closure criteria:**
- The source is confirmed as an approved scanner, monitoring system, or legitimate client behavior.
- The F5 device shows no signs of compromise, instability, or unauthorized configuration changes.
- The traffic pattern is explained by expected application behavior or a documented test.
- The device owner confirms exposure is understood and remediation or patching is tracked.

<br/>
---
<br/>

## Detection 4: EvilTokens - Device Code Phishing Token Reuse from Different IP After Authentication

### Detection Opportunity

OAuth device code authentication flow completed from one IP address followed by token use originating from a different IP address, consistent with EvilTokens device code phishing token theft and replay.

### Intelligence Context

- Microsoft Security Blog: Unmasking EvilTokens: Getting to the root of device code phishing — [https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)
  - Context: EvilTokens used device code phishing with AI-assisted lures to steal OAuth tokens from Microsoft identity users. The key detectable artifact is a device code authentication event followed by subsequent token use from a different IP address than the one that completed the device code flow, indicating the token was stolen and replayed by the attacker.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1528, T1566, T1566.002
- Products: Microsoft identity
- Platforms: Not specified
- Malware: EvilTokens
- Tools: Not specified
- Search tags: Microsoft identity, EvilTokens, T1528, T1566, T1566.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1528 Steal Application Access Token (medium); Initial Access: T1566 Phishing/ T1566.002 Spearphishing Link (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- SigninLogs

### KQL

```kql
let LookbackWindow = 2d;
let DeviceCodeAuths = SigninLogs
| where TimeGenerated > ago(LookbackWindow)
| where AuthenticationProtocol =~ "deviceCode"
| where ResultType == 0
| where isnotempty(IPAddress)
| where ipv4_is_private(IPAddress) == false
| project
    DeviceCodeTime = TimeGenerated,
    UserPrincipalName,
    DeviceCodeIP = IPAddress,
    CorrelationId,
    ClientAppUsed,
    ConditionalAccessStatus;
let FollowOnSessions = SigninLogs
| where TimeGenerated > ago(LookbackWindow)
| where ResultType == 0
| where AuthenticationProtocol !~ "deviceCode"
| where isnotempty(IPAddress)
| where ipv4_is_private(IPAddress) == false
| project
    FollowOnTime = TimeGenerated,
    UserPrincipalName,
    FollowOnIP = IPAddress,
    FollowOnApp = AppDisplayName;
DeviceCodeAuths
| join kind=inner FollowOnSessions on UserPrincipalName
| where FollowOnTime > DeviceCodeTime
| where FollowOnTime <= DeviceCodeTime + 2h
| where DeviceCodeIP != FollowOnIP
| summarize
    DeviceCodeIP = take_any(DeviceCodeIP),
    FollowOnIPs = make_set(FollowOnIP, 5),
    FollowOnApps = make_set(FollowOnApp, 5),
    FirstFollowOn = min(FollowOnTime),
    EventCount = count()
    by
    UserPrincipalName,
    DeviceCodeTime,
    CorrelationId,
    ClientAppUsed,
    ConditionalAccessStatus
| project
    DeviceCodeTime,
    FirstFollowOn,
    UserPrincipalName,
    DeviceCodeIP,
    FollowOnIPs,
    FollowOnApps,
    ClientAppUsed,
    ConditionalAccessStatus,
    CorrelationId,
    EventCount
| sort by DeviceCodeTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Users who complete device code authentication on a mobile network and then access resources from a corporate VPN egress IP will generate IP mismatches.
- Users who authenticate via device code on a home network and then connect through a corporate proxy will appear as IP mismatches.
- Shared device scenarios where one user completes device code auth and another user on the same device accesses resources from a different network location.
- Users who travel or switch networks between device code completion and subsequent resource access within the 2-hour window.

**Tuning notes:**
- Add a known VPN egress IP exclusion using '| where FollowOnIP !in ("<egress_ip_1>", "<egress_ip_2>")' after the IP mismatch filter, populated from the organization's VPN egress IP inventory.
- Consider extending the query to also join against NonInteractiveUserSignInLogs for the FollowOnSessions subquery to capture token refresh events that may not appear in SigninLogs.
- Narrow the follow-on window from 2h to 30min after reviewing baseline results to reduce false positives from legitimate network switching.
- Review ConditionalAccessStatus values in results; events where ConditionalAccessStatus is 'success' despite IP mismatch are higher fidelity indicators of token theft than those where CA was not applied.

**Risks / caveats:**
- SigninLogs requires the Azure Active Directory (Entra ID) diagnostic settings to be configured to stream sign-in logs to the Log Analytics workspace. Without this connector, the table will be absent.
- The AuthenticationProtocol field is populated in SigninLogs for interactive and non-interactive sign-ins but may not be consistently populated for all token refresh events depending on the Entra ID log schema version in use.
- The 2-hour follow-on window will generate false positives for users who switch networks legitimately between device code completion and resource access. A 30-minute window reduces this but may miss delayed token replay.
- No allowlist for known corporate VPN egress IPs is included. Adding an exclusion for known VPN egress ranges will significantly reduce false positive volume in environments with split-tunnel VPN.

### Triage Runbook

**First 15 minutes:**
- Verify the user and confirm whether the device code authentication was expected or initiated by the user.
- Compare the device code IP and follow-on IPs to determine whether the second IP is a known VPN, proxy, or corporate egress address.
- Check the follow-on applications to see whether the token was used against high-value cloud services or unusual client apps.
- Review Conditional Access status and any recent sign-in anomalies for the same user.

**Evidence to collect:**
- UserPrincipalName, DeviceCodeTime, FirstFollowOn, DeviceCodeIP, FollowOnIPs, FollowOnApps, ClientAppUsed, ConditionalAccessStatus, EventCount, CorrelationId.
- The full sign-in history for the user around the alert window, including interactive and non-interactive events if available.
- Any user-reported phishing emails, device code prompts, or suspicious login notifications.
- Recent mailbox, file, or cloud app activity that may indicate post-authentication abuse.

**Pivot points:**
- SigninLogs for the same UserPrincipalName to review the complete authentication sequence and IP history.
- NonInteractiveUserSignInLogs if available to capture token refresh or background token use.
- Audit logs for mailbox, SharePoint, OneDrive, or other cloud app actions by the same user after the suspicious sign-in.
- Identity protection or risk events to determine whether the account was flagged by Entra ID.

**Benign explanations:**
- The user authenticated from a mobile network and later accessed resources through a corporate VPN or proxy.
- The user changed networks between device code completion and subsequent access.
- A shared device or remote access scenario caused the apparent IP mismatch.

**Escalation criteria:**
- The follow-on IP is not a known corporate egress, VPN, or proxy address.
- The follow-on apps or client types are unusual for the user or indicate high-value cloud access.
- There are additional signs of phishing, consent abuse, or suspicious mailbox activity.
- The user denies initiating the device code authentication or subsequent access.

**Containment actions:**
- Disable the account or force sign-out if token theft is strongly suspected and the user cannot validate the activity.
- Revoke refresh tokens and sessions for the affected account through identity response procedures.
- Reset the user password and require MFA re-registration if compromise is confirmed.
- Notify the user and identity team to review recent consent grants and mailbox rules if applicable.

**Closure criteria:**
- The IP mismatch is explained by a known VPN, proxy, or legitimate network transition.
- The user confirms the device code flow and follow-on access were expected.
- No suspicious cloud activity, consent grants, or mailbox abuse is found.
- Identity logs show no additional anomalous sign-ins or token use after the event.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- PAYLOAD Ransomware - Suspicious GPO Modification by Non-Privileged Account: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.
- CVE-2026-94127 - Anomalous Unauthenticated Requests to F5 BIG-IP APM OAuth Endpoints: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Schema / correlation keys:**
- PAYLOAD Ransomware - PowerShell or WMI Activity Targeting GPO Paths Without File Creation: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- No major shared table dependency identified across this run.

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: EvilTokens - Device Code Phishing Token Reuse from Different IP After Authentication.
2. Resolve environment-mapping detections next: PAYLOAD Ransomware - Suspicious GPO Modification by Non-Privileged Account; CVE-2026-94127 - Anomalous Unauthenticated Requests to F5 BIG-IP APM OAuth Endpoints.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: PAYLOAD Ransomware - PowerShell or WMI Activity Targeting GPO Paths Without File Creation.

### Hunting Agenda and Promotion Criteria

- PAYLOAD Ransomware - PowerShell or WMI Activity Targeting GPO Paths Without File Creation: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- PAYLOAD Ransomware - Suspicious GPO Modification by Non-Privileged Account: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- CVE-2026-94127 - Anomalous Unauthenticated Requests to F5 BIG-IP APM OAuth Endpoints: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
