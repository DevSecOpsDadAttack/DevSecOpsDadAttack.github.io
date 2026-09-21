---
layout: post
title: "Detection Engineering Brief - Monday, September 21, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-21
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - PAYLOAD
  - Active Directory
  - Group Policy Objects
  - Windows
  - TerminalFix
  - AWS IAM
  - CloudTrail
  - GitHub secret scanning
  - AWS
  - T1484
  - T1484.001
  - T1090
  - T1090.001
  - T1071
  - T1071.001
  - T1098
  - T1098.003
  - T1552
  - T1552.001
---

## Detection Engineering Summary

This brief produced 4 detection candidates.

1 production candidate, 1 hunting-only, 2 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: PAYLOAD, Active Directory, Group Policy Objects, Windows, TerminalFix, AWS IAM, CloudTrail, GitHub secret scanning, AWS, T1484, T1484.001, T1090, T1090.001, T1071, T1071.001, T1098, T1098.003, T1552, T1552.001.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: TerminalFix - Reverse Tunnel Outbound Connection from Unusual Process; Exposed AWS IAM Credential Abuse - Anomalous IAM API Activity After Credential Exposure; Exposed AWS IAM Credential Abuse - IAM Policy Change Following Credential Exposure Correlation.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: PAYLOAD Ransomware - Suspicious Group Policy Object Modification in Active Directory

### Detection Opportunity

Active Directory Group Policy Objects modified in a short timeframe, consistent with PAYLOAD ransomware weaponizing GPO for ransomware-related changes without deploying binaries.

### Intelligence Context

- Securelist: Group Policy hijacked: PAYLOAD ransomware weaponizes Active Directory GPO — [https://securelist.com/tr/payload-ransomware-via-group-policy/121335/](https://securelist.com/tr/payload-ransomware-via-group-policy/121335/)
  - Context: PAYLOAD ransomware abuses Active Directory Group Policy Objects to deploy ransomware-related configuration changes without dropping binaries, using an encryptionless, binary-less operation that relies entirely on GPO mechanisms.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1484, T1484.001
- Products: Active Directory, Group Policy Objects
- Platforms: Windows
- Malware: PAYLOAD
- Tools: Not specified
- Search tags: PAYLOAD, Active Directory, Group Policy Objects, Windows, T1484, T1484.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1484 Domain Policy Modification/ T1484.001 Group Policy Modification (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- SecurityEvent

### KQL

```kql
SecurityEvent
| where EventID == 5136
| where ObjectName has "CN=Policies,CN=System"
| where OperationType in ("%%14675", "%%14674")
| where SubjectUserName != "SYSTEM"
| where not(SubjectUserName endswith "$")
| summarize
    GPOModCount = count(),
    DistinctGPOs = dcount(ObjectName),
    SampleObjectNames = make_set(ObjectName, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SubjectUserName, SubjectDomainName, bin(TimeGenerated, 15m)
| where GPOModCount >= 3
| where DistinctGPOs >= 2
| extend DurationSeconds = datetime_diff('second', LastSeen, FirstSeen)
| project
    FirstSeen,
    LastSeen,
    DurationSeconds,
    SubjectUserName,
    SubjectDomainName,
    GPOModCount,
    DistinctGPOs,
    SampleObjectNames
| order by GPOModCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate Group Policy administrators performing bulk GPO updates during change windows.
- Automated GPO management tools or scripts that modify multiple GPOs in rapid succession.
- Domain controller promotion or demotion processes that touch multiple GPO objects.

**Tuning notes:**
- Baseline GPO modification frequency per account over 30 days before setting the final GPOModCount threshold.
- Consider adding a time-of-day filter to suppress alerts during known maintenance windows.
- If the environment uses a non-standard AD structure, the CN=Policies,CN=System path filter may need adjustment to match the actual GPO container distinguished name.

**Risks / caveats:**
- EventID 5136 requires the Windows Advanced Audit Policy subcategory 'Audit Directory Service Changes' to be enabled on domain controllers and those events forwarded to the Log Analytics workspace. If this audit subcategory is not enabled, the query will return no results.
- OperationType values '%%14675' and '%%14674' are Windows audit log hex codes for 'Value Added' and 'Value Deleted'. These codes are standard for EventID 5136 but should be confirmed present in the ingested SecurityEvent data, as some connector configurations decode them differently.
- The 15-minute bin window and GPOModCount >= 3 threshold are starting points; environments with active GPO management teams may require a higher threshold or time-of-day suppression for business hours.
- Ingestion latency from domain controllers to the Log Analytics workspace may cause events to span bin boundaries, potentially splitting a burst across two bins and suppressing an alert.

### Triage Runbook

**First 15 minutes:**
- Identify the modifying account and confirm whether it is a known domain admin, delegated GPO admin, or service account used for change automation.
- Check the time window against approved change tickets, maintenance windows, and any recent GPO deployment activity.
- Review the sample GPO object names to see whether the changes target security settings, startup scripts, scheduled tasks, software deployment, or logon/logoff scripts.
- Look for concurrent signs of domain-wide abuse such as new startup scripts, disabled security controls, or rapid edits to multiple GPOs by the same account.
- If the account is unexpected or the changes are outside a change window, treat as likely compromise and begin incident escalation.

**Evidence to collect:**
- SubjectUserName, SubjectDomainName, and SubjectLogonId for the modifying session.
- FirstSeen, LastSeen, GPOModCount, DistinctGPOs, and SampleObjectNames from the alert.
- Recent 5136 events for the same account to determine whether the activity is part of a broader burst.
- Any change-management ticket, CAB approval, or admin notification covering the same time period.
- Domain controller and AD admin logs showing whether the same account made other privileged changes.

**Pivot points:**
- SecurityEvent for EventID 5136 on the same SubjectUserName and SubjectLogonId.
- SecurityEvent for other privileged AD changes by the same account in the prior 24 hours.
- Change-management or ticketing system records for the alert time window.
- Domain controller logs or AD audit trails for related GPO edits, link changes, or script changes.

**Benign explanations:**
- Planned bulk GPO maintenance by a legitimate AD administrator.
- Automated GPO management or compliance tooling making multiple edits in a short period.
- Domain controller promotion or demotion activity that touches multiple GPO objects.

**Escalation criteria:**
- The modifying account is not a known GPO administrator or service account.
- The activity occurred outside an approved maintenance window or without a matching change ticket.
- The GPO changes include security hardening removal, startup script changes, or other ransomware-enabling modifications.
- Multiple GPOs were modified rapidly and the account shows no prior history of similar activity.

**Containment actions:**
- Disable or reset the suspected account if the activity is unauthorized and still in progress.
- Revoke active admin sessions and force logoff for the suspected account where feasible.
- Review and revert malicious GPO changes from a known-good backup or prior version.
- Increase monitoring on domain controllers and GPO-related changes until scope is understood.

**Closure criteria:**
- A valid change record and known administrator account explain the activity.
- The modified GPOs are confirmed to be expected and no malicious settings were introduced.
- No additional suspicious AD changes or ransomware indicators are found during follow-up review.
- Any unauthorized changes have been reverted and the incident has been documented.

<br/>
---
<br/>

## Detection 2: TerminalFix - Reverse Tunnel Outbound Connection from Unusual Process

### Detection Opportunity

Non-browser, non-system process establishes outbound network connections consistent with reverse tunnel deployment observed in the TerminalFix multistage intrusion campaign.

### Intelligence Context

- SANS ISC: TerminalFix: PNG Steganography, (Mon, Sep 21st) — [https://isc.sans.edu/diary/rss/33318](https://isc.sans.edu/diary/rss/33318)
  - Context: The TerminalFix campaign deploys a reverse tunnel as part of a multistage intrusion. Reverse tunnels produce observable outbound network connections from processes that would not normally initiate external connectivity.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1090, T1090.001, T1071, T1071.001
- Products: Not specified
- Platforms: Windows
- Malware: TerminalFix
- Tools: Not specified
- Search tags: TerminalFix, Windows, T1090, T1090.001, T1071, T1071.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Command and Control: T1090 Proxy/ T1090.001 Internal Proxy (medium); Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
let KnownBrowsers = dynamic(["chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "opera.exe", "brave.exe", "safari.exe"]);
let SystemProcesses = dynamic(["svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "csrss.exe", "smss.exe", "MsMpEng.exe", "msiexec.exe", "WmiPrvSE.exe", "spoolsv.exe", "SearchIndexer.exe", "OneDrive.exe", "Teams.exe", "Slack.exe", "zoom.exe"]);
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where RemotePort !in (80, 443, 53)
| where isnotempty(RemoteIP)
| where not(RemoteIP startswith "10.")
| where not(RemoteIP startswith "192.168.")
| where not(RemoteIP startswith "172.16.")
| where not(RemoteIP startswith "172.17.")
| where not(RemoteIP startswith "172.18.")
| where not(RemoteIP startswith "172.19.")
| where not(RemoteIP startswith "172.20.")
| where not(RemoteIP startswith "172.21.")
| where not(RemoteIP startswith "172.22.")
| where not(RemoteIP startswith "172.23.")
| where not(RemoteIP startswith "172.24.")
| where not(RemoteIP startswith "172.25.")
| where not(RemoteIP startswith "172.26.")
| where not(RemoteIP startswith "172.27.")
| where not(RemoteIP startswith "172.28.")
| where not(RemoteIP startswith "172.29.")
| where not(RemoteIP startswith "172.30.")
| where not(RemoteIP startswith "172.31.")
| where not(RemoteIP startswith "127.")
| where not(RemoteIP startswith "169.254.")
| where not(InitiatingProcessFileName in~ (KnownBrowsers))
| where not(InitiatingProcessFileName in~ (SystemProcesses))
| where isnotempty(InitiatingProcessFileName)
| summarize
    ConnectionCount = count(),
    SampledRemotePorts = make_set(RemotePort, 10),
    DistinctPorts = dcount(RemotePort),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    SampleCommandLine = any(InitiatingProcessCommandLine),
    InitiatingProcessFolderPath = any(InitiatingProcessFolderPath)
    by DeviceId, DeviceName, InitiatingProcessFileName, RemoteIP, bin(Timestamp, 10m)
| where ConnectionCount >= 5
| extend DurationSeconds = datetime_diff('second', LastSeen, FirstSeen)
| project
    FirstSeen,
    LastSeen,
    DurationSeconds,
    DeviceName,
    DeviceId,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    RemoteIP,
    ConnectionCount,
    DistinctPorts,
    SampledRemotePorts,
    SampleCommandLine
| order by ConnectionCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate remote access tools such as AnyDesk, TeamViewer, ngrok, or SSH clients not included in the exclusion list.
- Backup agents, monitoring agents, and telemetry collectors making repeated outbound connections on non-standard ports.
- Custom in-house applications that maintain persistent outbound connections to external services.
- Software update mechanisms using non-standard ports.

**Tuning notes:**
- Extend the SystemProcesses and KnownBrowsers exclusion lists with legitimate remote management tools deployed in the environment before using this query for recurring hunts.
- Consider adding an InitiatingProcessFolderPath filter to exclude connections from known software installation directories if noise remains high.
- Adjust ConnectionCount threshold based on observed baseline outbound connection frequency per process in the environment.
- For environments where port 443 tunneling is a concern, a separate query targeting unusual processes connecting to port 443 with high connection frequency would complement this detection.

**Risks / caveats:**
- DeviceNetworkEvents is only populated for devices onboarded to Microsoft Defender for Endpoint. Devices without MDE onboarding will produce no results.
- ActionType value 'ConnectionSuccess' must be confirmed present in the environment's DeviceNetworkEvents data; some MDE configurations or network sensor gaps may result in sparse ConnectionSuccess events for certain process types.
- The RFC1918 exclusion uses prefix-based string matching rather than ipv4_is_private(); this is intentional for compatibility but means unusual private ranges outside standard RFC1918 blocks will not be excluded.
- The process exclusion list is static and will not automatically cover newly deployed legitimate remote access or monitoring tools in the environment.

### Triage Runbook

**First 15 minutes:**
- Identify the initiating process, its full command line, and parent process to determine whether it is expected on the host.
- Check whether the destination IP is a known corporate service, remote management endpoint, or sanctioned SaaS platform.
- Review the process folder path and signer reputation to see if the binary is in a standard application or system location.
- Look for repeated connections from the same process to the same remote IP and whether the port usage is unusual for that application.
- If the process is unknown, unsigned, or launched from a user-writable path, escalate for deeper host investigation.

**Evidence to collect:**
- DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, and InitiatingProcessFolderPath.
- RemoteIP, sampled remote ports, connection count, and the first/last seen timestamps.
- Parent process name and any related process creation events around the same time.
- File hash, signer information, and file creation time for the initiating binary if available.
- User context and recent logon activity on the affected device.

**Pivot points:**
- DeviceNetworkEvents for additional connections from the same process, device, or remote IP.
- DeviceProcessEvents for process ancestry, command-line history, and related child processes.
- DeviceFileEvents for file creation, rename, or drop activity tied to the initiating binary.
- DeviceLogonEvents or identity telemetry to determine which user was active on the device.

**Benign explanations:**
- Legitimate remote support or remote administration software not included in the exclusion list.
- Backup, monitoring, or telemetry agents that maintain persistent outbound connections.
- Custom internal applications that use non-standard ports for normal business functions.
- Software update mechanisms or installers using temporary outbound connections.

**Escalation criteria:**
- The process is unsigned, newly created, or running from a suspicious user-writable directory.
- The command line indicates tunneling, proxying, port forwarding, or remote shell behavior.
- The destination IP is unrecognized and the process repeatedly connects on unusual ports.
- The host also shows other compromise indicators such as suspicious child processes, credential access, or lateral movement.

**Containment actions:**
- Isolate the device from the network if the process is confirmed or strongly suspected to be malicious.
- Terminate the suspicious process and any related child processes if operationally safe.
- Block the remote IP or domain at the network edge if it is confirmed malicious.
- Preserve the binary and memory artifacts before remediation if possible.

**Closure criteria:**
- The process is identified as a sanctioned tool or expected application behavior.
- The remote destination is confirmed legitimate and the connection pattern matches baseline activity.
- No additional suspicious process, file, or network activity is found on the host.
- Any false positive is documented with the approved application, owner, and expected behavior.

<br/>
---
<br/>

## Detection 3: Exposed AWS IAM Credential Abuse - Anomalous IAM API Activity After Credential Exposure

### Detection Opportunity

AWS IAM credentials used from a new or anomalous IP address shortly after credential exposure, consistent with attacker abuse of leaked IAM keys detected via CloudTrail monitoring.

### Intelligence Context

- Unit 42: From Exposure to Lockdown: How AWS Neutralizes Compromised IAM Credentials through Managed Policies — [https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/](https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/)
  - Context: Unit 42 reporting describes how exposed AWS IAM credentials are detected via CloudTrail monitoring and GitHub secret scanning. Attackers who obtain leaked IAM keys will use them from external infrastructure, producing IAM API calls from IP addresses not previously associated with the credential.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1098, T1098.003, T1552, T1552.001
- Products: AWS IAM, CloudTrail, GitHub secret scanning
- Platforms: AWS
- Malware: Not specified
- Tools: Not specified
- Search tags: AWS IAM, CloudTrail, GitHub secret scanning, AWS, T1098, T1098.003, T1552, T1552.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1098 Account Manipulation/ T1098.003 Additional Cloud Roles (medium); Privilege Escalation: T1098 Account Manipulation/ T1098.003 Additional Cloud Roles (medium); Credential Access: T1552 Unsecured Credentials/ T1552.001 Credentials In Files (medium)

### Deployment Gates

- If the environment uses a custom CloudTrail ingestion pipeline rather than the standard Sentinel AWS S3 connector, the table name and field names may differ from AWSCloudTrail, EventName, SourceIpAddress, and UserIdentityArn. The query must be validated against the actual ingested schema.

**Required telemetry:**
- AWSCloudTrail

### KQL

```kql
let SensitiveIAMOps = dynamic(["CreateAccessKey", "AttachUserPolicy", "PutUserPolicy", "CreateLoginProfile", "UpdateLoginProfile", "AddUserToGroup"]);
let LookbackDays = 14d;
let RecentWindow = 1d;
let HistoricalCallers = AWSCloudTrail
| where TimeGenerated between (ago(LookbackDays) .. ago(RecentWindow))
| where EventName in (SensitiveIAMOps)
| where isnull(ErrorCode) or ErrorCode == ""
| summarize HistoricalIPs = make_set(SourceIpAddress) by UserIdentityArn;
AWSCloudTrail
| where TimeGenerated >= ago(RecentWindow)
| where EventName in (SensitiveIAMOps)
| where isnull(ErrorCode) or ErrorCode == ""
| join kind=leftouter HistoricalCallers on UserIdentityArn
| where not(SourceIpAddress in (HistoricalCallers))
| project
    EventTime = TimeGenerated,
    EventName,
    SourceIpAddress,
    UserAgent,
    UserIdentityArn,
    UserIdentityUserName,
    RecipientAccountId,
    HistoricalIPs
| order by EventTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrators accessing AWS from a new IP address such as a new office, VPN endpoint, or cloud shell session.
- Automated pipelines or CI/CD systems that rotate source IPs and perform IAM operations.
- New employees or contractors performing IAM operations from previously unseen infrastructure.

**Tuning notes:**
- Confirm the exact table name used by the CloudTrail ingestion pipeline in the environment before deploying.
- Confirm that SourceIpAddress, EventName, UserIdentityArn, UserIdentityUserName, RecipientAccountId, and ErrorCode are populated in the ingested CloudTrail data.
- Adjust LookbackDays to extend the historical baseline if IAM administrators access AWS infrequently.
- Expand SensitiveIAMOps to include additional high-risk operations such as DeleteAccessKey, DetachUserPolicy, or CreateRole if those are relevant to the threat model.

**Risks / caveats:**
- The original query uses AuditLogs with CallerIpAddress and OperationName, which are Azure AD audit log fields. The standard Sentinel AWS S3 connector ingests CloudTrail into AWSCloudTrail with fields EventName and SourceIpAddress. The query will return no results if run against AuditLogs in an environment using the standard connector.
- The field ResourceId in AuditLogs does not map to an AWS IAM identity. In AWSCloudTrail, the identity is represented by UserIdentityArn or UserIdentityUserName. The historical baseline join key must be confirmed against the actual ingested schema.
- ActivityStatus is an Azure AD AuditLogs field. In AWSCloudTrail, successful events are identified by the absence of ErrorCode or ErrorCode == ''. This field mapping must be corrected before the query can run.
- If the environment uses a custom CloudTrail ingestion pipeline rather than the standard Sentinel AWS S3 connector, the table name and field names may differ from AWSCloudTrail, EventName, SourceIpAddress, and UserIdentityArn. The query must be validated against the actual ingested schema.

### Triage Runbook

**First 15 minutes:**
- Identify the IAM identity, source IP, user agent, and account involved in the flagged API call.
- Confirm whether the source IP is new for that identity and whether it belongs to a known VPN, office, cloud shell, or automation environment.
- Check whether the identity is a human user, service account, or automation role and whether the action matches expected behavior.
- Review the exposure context to determine when and where the credential was leaked and whether the key is still active.
- If the activity is unauthorized or the source is clearly anomalous, begin credential revocation and incident escalation immediately.

**Evidence to collect:**
- EventTime, EventName, SourceIpAddress, UserAgent, UserIdentityArn, UserIdentityUserName, and RecipientAccountId.
- HistoricalIPs for the identity and any prior IAM activity from the same account.
- The original credential exposure alert details, including alert source and exposure time.
- CloudTrail records for related IAM actions before and after the alert window.
- Any evidence of access key creation, policy attachment, login profile changes, or group membership changes.

**Pivot points:**
- AWSCloudTrail for all events by the same UserIdentityArn or UserIdentityUserName.
- AWSCloudTrail for the same SourceIpAddress across other identities to identify broader abuse.
- SecurityAlert for the original exposure alert and any related credential findings.
- AWS IAM console or account inventory to verify whether the access key is still active.

**Benign explanations:**
- A legitimate administrator using a new VPN endpoint, office network, or cloud shell session.
- A CI/CD or automation system that rotates source IPs while performing IAM operations.
- A new contractor or employee performing approved IAM administration from a previously unseen location.

**Escalation criteria:**
- The source IP is not recognized and does not match any approved admin or automation network.
- The IAM action is high risk, such as creating access keys, attaching policies, or adding users to privileged groups.
- The identity has a recent credential exposure alert and the activity occurred shortly afterward.
- There is evidence of additional suspicious CloudTrail activity from the same identity or source IP.

**Containment actions:**
- Deactivate or rotate the exposed access key immediately if compromise is suspected.
- Revoke active sessions and disable the affected IAM user or role if operationally appropriate.
- Remove unauthorized policy attachments, access keys, or group memberships.
- Notify cloud operations to review for broader account abuse and preserve CloudTrail evidence.

**Closure criteria:**
- The activity is confirmed as authorized and matches a known admin or automation pattern.
- The source IP is validated as an approved network or service endpoint.
- No additional suspicious IAM actions are observed after the alert window.
- Any exposed credential has been rotated or invalidated and the exposure is documented.

<br/>
---
<br/>

## Detection 4: Exposed AWS IAM Credential Abuse - IAM Policy Change Following Credential Exposure Correlation

### Detection Opportunity

IAM policy modification or privilege escalation API calls observed within a short window after a credential exposure event, correlating exposure timing with follow-on cloud abuse activity.

### Intelligence Context

- Unit 42: From Exposure to Lockdown: How AWS Neutralizes Compromised IAM Credentials through Managed Policies — [https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/](https://unit42.paloaltonetworks.com/detecting-exposed-aws-iam-credentials/)
  - Context: Unit 42 describes correlating GitHub secret scanning exposure alerts with subsequent CloudTrail IAM API activity. Attackers who obtain leaked credentials rapidly attempt privilege escalation or persistence actions. Detecting IAM policy changes shortly after an exposure event confirms active abuse rather than passive credential leakage.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1098, T1098.003, T1552, T1552.001
- Products: AWS IAM, CloudTrail, GitHub secret scanning
- Platforms: AWS
- Malware: Not specified
- Tools: Not specified
- Search tags: AWS IAM, CloudTrail, GitHub secret scanning, AWS, T1098, T1098.003, T1552, T1552.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1098 Account Manipulation/ T1098.003 Additional Cloud Roles (medium); Privilege Escalation: T1098 Account Manipulation/ T1098.003 Additional Cloud Roles (medium); Credential Access: T1552 Unsecured Credentials/ T1552.001 Credentials In Files (medium)

### Deployment Gates

- SecurityAlert.CompromisedEntity must contain a value that matches UserIdentityArn or UserIdentityUserName from AWSCloudTrail. This mapping is not guaranteed by any standard connector and must be confirmed in the specific environment before the join will produce results.

**Required telemetry:**
- AWSCloudTrail, SecurityAlert

### KQL

```kql
let SensitiveIAMOps = dynamic(["AttachUserPolicy", "PutUserPolicy", "CreateAccessKey", "AddUserToGroup", "CreateLoginProfile", "UpdateLoginProfile"]);
let ExposureAlerts = SecurityAlert
| where TimeGenerated >= ago(7d)
| where AlertName has_any ("secret", "credential", "exposed", "leaked", "IAM")
| project ExposureTime = TimeGenerated, AlertName, CompromisedEntity, SystemAlertId;
AWSCloudTrail
| where TimeGenerated >= ago(7d)
| where EventName in (SensitiveIAMOps)
| where isnull(ErrorCode) or ErrorCode == ""
| join kind=inner ExposureAlerts on $left.UserIdentityArn == $right.CompromisedEntity
| where TimeGenerated between (ExposureTime .. (ExposureTime + 1h))
| extend MinutesAfterExposure = datetime_diff('minute', TimeGenerated, ExposureTime)
| project
    ExposureTime,
    AlertName,
    SystemAlertId,
    IAMEventTime = TimeGenerated,
    MinutesAfterExposure,
    EventName,
    SourceIpAddress,
    UserIdentityArn,
    UserIdentityUserName,
    RecipientAccountId,
    CompromisedEntity
| order by ExposureTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate security response actions by administrators who rotate or audit IAM credentials immediately after receiving an exposure alert.
- Automated remediation pipelines that perform IAM policy changes in response to exposure alerts, which would appear as IAM activity within the correlation window.

**Tuning notes:**
- Validate the join key by running: SecurityAlert → where AlertName has_any ('secret','credential','exposed','leaked','IAM') → project CompromisedEntity → take 20 and compare the format against AWSCloudTrail → project UserIdentityArn, UserIdentityUserName → take 20.
- If CompromisedEntity contains access key IDs rather than ARNs or usernames, add a join on the AccessKeyId field from AWSCloudTrail if that field is populated by the ingestion pipeline.
- Adjust the post-exposure correlation window from 1 hour to a shorter window such as 15 minutes if the threat model focuses on immediate exploitation.
- Add known automated remediation service account ARNs to an exclusion list to suppress false positives from security response automation.

**Risks / caveats:**
- The original query uses AuditLogs with OperationName and ActivityStatus, which are Azure AD audit log fields. CloudTrail events in Sentinel are in AWSCloudTrail with EventName and ErrorCode. The query will return no results if run against AuditLogs.
- SecurityAlert.CompromisedEntity must contain a value that matches UserIdentityArn or UserIdentityUserName from AWSCloudTrail. This mapping is not guaranteed by any standard connector and must be confirmed in the specific environment before the join will produce results.
- If GitHub Advanced Security secret scanning alerts are not forwarded to the Sentinel SecurityAlert table, the ExposureAlerts subquery will return no rows and the correlation will never fire.
- The join on UserIdentityArn == CompromisedEntity will only produce results if the credential exposure alert populates CompromisedEntity with the exact ARN format used in CloudTrail. If CompromisedEntity contains a username, access key ID, or partial ARN, the join will return no results. A secondary join variant on UserIdentityUserName == CompromisedEntity may be needed.

### Triage Runbook

**First 15 minutes:**
- Confirm the exposure alert details and identify the exact IAM identity or access key implicated.
- Review the correlated IAM event to see whether it is a policy attachment, policy update, login profile change, or group membership change.
- Check the source IP and user agent for the IAM event against known admin, automation, or AWS-managed sources.
- Determine whether the change occurred within the expected post-exposure window and whether it was performed by an approved responder.
- If the change is unauthorized, treat the identity as compromised and escalate immediately.

**Evidence to collect:**
- ExposureTime, AlertName, SystemAlertId, IAMEventTime, and MinutesAfterExposure.
- EventName, SourceIpAddress, UserIdentityArn, UserIdentityUserName, RecipientAccountId, and CompromisedEntity.
- The original SecurityAlert record and any linked GitHub secret scanning or cloud security alert metadata.
- CloudTrail history for the same identity before and after the correlated event.
- Any remediation actions already taken by cloud security or identity teams.

**Pivot points:**
- SecurityAlert for the original exposure alert and related credential findings.
- AWSCloudTrail for all IAM actions by the same identity in the surrounding time window.
- AWSCloudTrail for access key creation, policy changes, and group membership changes across the account.
- Identity and access management records to verify whether the identity is a human user, role, or automation principal.

**Benign explanations:**
- A security administrator responding to the exposure by rotating credentials or tightening permissions.
- An automated remediation workflow that attaches managed policies or disables access after an exposure alert.
- A planned IAM change that happened to occur shortly after the exposure alert but was independently approved.

**Escalation criteria:**
- The IAM change was not performed by a known responder or automation account.
- The source IP is unfamiliar and not associated with approved cloud administration.
- The change increases privilege, persistence, or access to sensitive resources.
- Additional suspicious CloudTrail activity appears before or after the correlated event.

**Containment actions:**
- Disable or rotate the exposed credential and revoke active sessions immediately if compromise is suspected.
- Remove unauthorized IAM policy changes, access keys, or group memberships.
- Apply emergency least-privilege controls or managed policies to the affected identity if supported by your response process.
- Preserve CloudTrail and alert evidence before making destructive changes where possible.

**Closure criteria:**
- The correlated IAM change is confirmed as an approved remediation action.
- The exposure alert has been addressed and the credential is no longer usable.
- No additional unauthorized IAM activity is observed in the follow-up window.
- The join key and alert linkage are validated for future detections and the case is documented.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- TerminalFix - Reverse Tunnel Outbound Connection from Unusual Process: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- Exposed AWS IAM Credential Abuse - Anomalous IAM API Activity After Credential Exposure: If the environment uses a custom CloudTrail ingestion pipeline rather than the standard Sentinel AWS S3 connector, the table name and field names may differ from AWSCloudTrail, EventName, SourceIpAddress, and UserIdentityArn. The query must be validated against the actual ingested schema.
- Exposed AWS IAM Credential Abuse - IAM Policy Change Following Credential Exposure Correlation: SecurityAlert.CompromisedEntity must contain a value that matches UserIdentityArn or UserIdentityUserName from AWSCloudTrail. This mapping is not guaranteed by any standard connector and must be confirmed in the specific environment before the join will produce results.

**Shared-table notes:**
- AWSCloudTrail: shared by Exposed AWS IAM Credential Abuse - Anomalous IAM API Activity After Credential Exposure; Exposed AWS IAM Credential Abuse - IAM Policy Change Following Credential Exposure Correlation

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: PAYLOAD Ransomware - Suspicious Group Policy Object Modification in Active Directory.
2. Resolve environment-mapping detections next: Exposed AWS IAM Credential Abuse - Anomalous IAM API Activity After Credential Exposure; Exposed AWS IAM Credential Abuse - IAM Policy Change Following Credential Exposure Correlation.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: TerminalFix - Reverse Tunnel Outbound Connection from Unusual Process.

### Hunting Agenda and Promotion Criteria

- TerminalFix - Reverse Tunnel Outbound Connection from Unusual Process: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Exposed AWS IAM Credential Abuse - Anomalous IAM API Activity After Credential Exposure: If the environment uses a custom CloudTrail ingestion pipeline rather than the standard Sentinel AWS S3 connector, the table name and field names may differ from AWSCloudTrail, EventName, SourceIpAddress, and UserIdentityArn. The query must be validated against the actual ingested schema.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Exposed AWS IAM Credential Abuse - IAM Policy Change Following Credential Exposure Correlation: SecurityAlert.CompromisedEntity must contain a value that matches UserIdentityArn or UserIdentityUserName from AWSCloudTrail. This mapping is not guaranteed by any standard connector and must be confirmed in the specific environment before the join will produce results.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
