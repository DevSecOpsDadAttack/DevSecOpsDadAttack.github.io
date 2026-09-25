---
layout: post
title: "Detection Engineering Brief - Friday, September 25, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-25
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - Zimbra
  - Zimbra Collaboration Suite
  - macOS
  - MacSync
  - T1098
  - T1098.001
  - T1114
  - T1114.001
  - T1204
  - T1071
---

## Detection Engineering Summary

This brief produced 4 detection candidates.

1 production candidate, 2 hunting-only, 1 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: Zimbra, Zimbra Collaboration Suite, macOS, MacSync, T1098, T1098.001, T1114, T1114.001, T1204, T1071.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: BEC - Mailbox Silent Monitoring Followed by Inbox Rule Manipulation; BEC - Sender Impersonation Without Credential Match in Mail Audit Logs; MacSync Backdoor - Outbound Network Connection from Newly Created Binary in User-Writable Directory on macOS.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: BEC - Mailbox Silent Monitoring Followed by Inbox Rule Manipulation

### Detection Opportunity

Threat actor breaches a mailbox, silently monitors operations, then creates inbox rules to alter visibility or redirect mail as part of a BEC campaign.

### Intelligence Context

- Rapid7: When Business Email Compromise Starts Rewriting Reality — [https://www.rapid7.com/blog/post/ve-business-email-compromise-rewriting-reality-zimbra-cve](https://www.rapid7.com/blog/post/ve-business-email-compromise-rewriting-reality-zimbra-cve)
  - Context: Rapid7 reported that threat actors breach a mailbox and silently monitor operations before manipulating inbox rules, shared documents, and calendars to support fraud or exfiltration. The compound behavior of passive read access followed by active rule creation is the core BEC tradecraft described.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1098, T1098.001, T1114, T1114.001
- Products: Zimbra, Zimbra Collaboration Suite
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: Zimbra, Zimbra Collaboration Suite, T1098, T1098.001, T1114, T1114.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1098 Account Manipulation/ T1098.001 Additional Cloud Credentials (low); Collection: T1114 Email Collection/ T1114.001 Local Email Collection (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- OfficeActivity

### KQL

```kql
let LookbackWindow = 4h;
let ReadOps = OfficeActivity
    | where TimeGenerated >= ago(LookbackWindow)
    | where Operation in ("MailboxLogin", "MessageRead", "FolderBind")
    | where ResultStatus == "Succeeded"
    | where isnotempty(UserId)
    | summarize
        ReadCount = count(),
        ReadIPs = make_set(ClientIP, 50),
        FirstRead = min(TimeGenerated),
        LastRead = max(TimeGenerated)
        by UserId, MailboxOwnerUPN;
let RuleOps = OfficeActivity
    | where TimeGenerated >= ago(LookbackWindow)
    | where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
    | where ResultStatus == "Succeeded"
    | where isnotempty(UserId)
    | summarize
        RuleCount = count(),
        RuleIPs = make_set(ClientIP, 50),
        FirstRule = min(TimeGenerated),
        RuleParameters = make_set(Parameters, 20)
        by UserId, MailboxOwnerUPN;
ReadOps
| join kind=inner RuleOps on UserId
| where FirstRule > FirstRead
| where ReadCount >= 5
| extend SharedIPs = set_intersect(ReadIPs, RuleIPs)
| project
    UserId,
    MailboxOwnerUPN = coalesce(MailboxOwnerUPN, MailboxOwnerUPN1),
    ReadCount,
    ReadIPs,
    FirstRead,
    LastRead,
    RuleCount,
    RuleIPs,
    FirstRule,
    RuleParameters,
    SharedIPs
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Administrators or helpdesk staff who access multiple mailboxes and then configure inbox rules on behalf of users.
- Users who perform bulk mailbox reads via mobile sync or IMAP clients and then create legitimate inbox rules.
- Automated service accounts that perform scheduled mailbox reads followed by rule management.

**Tuning notes:**
- Increase ReadCount threshold to 20 or higher in environments with active mobile clients to reduce noise.
- Filter SharedIPs to require array_length(SharedIPs) > 0 to enforce IP-level session correlation if noise is high.
- Add a UserId exclusion list for known service accounts and helpdesk identities.

**Risks / caveats:**
- OfficeActivity only captures Exchange Online audit events via the Office 365 connector; Zimbra Collaboration Suite does not natively emit to OfficeActivity. If the environment runs on-premises Zimbra without a custom connector that maps Zimbra audit fields to OfficeActivity-compatible Operations, this query will produce no results.
- MailboxOwnerUPN is not guaranteed to be populated for all Exchange Online audit record types; FolderBind events in particular may omit it depending on mailbox audit configuration.
- ReadCount threshold of 5 is arbitrary; environments with high-volume IMAP or mobile sync clients will generate significant noise until the threshold is baselined.
- LookbackWindow of 4 hours may miss attackers with longer dwell times between initial access and rule creation.

### Triage Runbook

**First 15 minutes:**
- Confirm the UserId and MailboxOwnerUPN are expected to be the same person or a known delegate.
- Review the sequence and timing of ReadCount, FirstRead, LastRead, FirstRule, and RuleCount to verify the read-then-rule pattern.
- Inspect RuleParameters for forwarding, delete, move, mark-as-read, or keyword-based suppression actions.
- Check ReadIPs, RuleIPs, and SharedIPs for a new or unusual source IP, VPN, proxy, or impossible travel pattern.

**Evidence to collect:**
- OfficeActivity events for the user covering at least 24 hours before and after FirstRule.
- Full inbox rule details from Parameters, including any forwarding address, delete action, or folder target.
- Authentication and sign-in logs for the same UserId and IPs to validate session legitimacy.
- Mailbox audit history showing whether the rule was created, modified, or deleted repeatedly.

**Pivot points:**
- OfficeActivity filtered to the same UserId and MailboxOwnerUPN for MessageRead, FolderBind, New-InboxRule, Set-InboxRule, and UpdateInboxRules.
- Sign-in or authentication logs for the UserId and ReadIPs/RuleIPs.
- Mailbox audit or admin activity logs for rule changes and delegate access.
- Email security or message trace data for suspicious forwarding or external recipients.

**Benign explanations:**
- Helpdesk or messaging administrators may have accessed the mailbox and configured rules on behalf of the user.
- A user may have legitimately created rules after bulk reading mail from mobile sync or IMAP clients.
- Automated mailbox management or archiving tools may generate read activity followed by rule changes.

**Escalation criteria:**
- RuleParameters show forwarding to an external address, deletion of security alerts, or hiding finance-related mail.
- ReadIPs or RuleIPs are from an unfamiliar country, TOR/VPN, or a source not used by the account before.
- The mailbox owner denies the activity or there is no approved delegate relationship.
- Additional BEC indicators appear, such as suspicious payment requests, reply-chain manipulation, or new external recipients.

**Containment actions:**
- Disable or remove the suspicious inbox rule if it is confirmed unauthorized.
- Reset the account password and revoke active sessions/tokens if mailbox compromise is likely.
- Block or restrict the suspicious source IP or session only if it is clearly malicious and not a shared corporate egress.
- Notify the mailbox owner and finance/helpdesk stakeholders if the mailbox is used for payment or vendor communications.

**Closure criteria:**
- The rule is confirmed as legitimate and matches an approved business process or delegate relationship.
- No suspicious forwarding, deletion, or suppression behavior is present in RuleParameters.
- Authentication logs show the activity came from a known corporate IP or expected user session.
- No additional suspicious mailbox activity is observed after review of the surrounding time window.

<br/>
---
<br/>

## Detection 2: BEC - Sender Impersonation Without Credential Match in Mail Audit Logs

### Detection Opportunity

Threat actor sends email impersonating a legitimate user without using that user's credentials, resulting in a mismatch between the authenticated sender identity and the envelope or display sender.

### Intelligence Context

- Rapid7: When Business Email Compromise Starts Rewriting Reality — [https://www.rapid7.com/blog/post/ve-business-email-compromise-rewriting-reality-zimbra-cve](https://www.rapid7.com/blog/post/ve-business-email-compromise-rewriting-reality-zimbra-cve)
  - Context: Rapid7 described threat actors impersonating senders without using their credentials, a technique that produces a detectable mismatch between the authenticated user identity and the sender identity recorded in mail flow audit logs.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1098, T1098.001, T1114, T1114.001
- Products: Zimbra, Zimbra Collaboration Suite
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: Zimbra, Zimbra Collaboration Suite, T1098, T1098.001, T1114, T1114.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1098 Account Manipulation/ T1098.001 Additional Cloud Credentials (low); Collection: T1114 Email Collection/ T1114.001 Local Email Collection (low)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: OfficeActivity before scheduling.

**Required telemetry:**
- OfficeActivity

### KQL

```kql
OfficeActivity
| where TimeGenerated >= ago(1d)
| where Operation in ("SendAs", "SendOnBehalf")
| where ResultStatus == "Succeeded"
| where isnotempty(MailboxOwnerUPN)
| where isnotempty(UserId)
| where tolower(UserId) != tolower(MailboxOwnerUPN)
| extend ImpersonatedSender = MailboxOwnerUPN
| where tolower(UserId) != tolower(ImpersonatedSender)
| project
    TimeGenerated,
    UserId,
    ImpersonatedSender,
    MailboxOwnerUPN,
    ClientIP,
    Operation,
    ResultStatus
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- All legitimate SendAs and SendOnBehalf delegation relationships, including shared mailboxes, executive assistants, and resource mailboxes.
- Automated systems that send on behalf of functional mailboxes using service account credentials.
- Legal, finance, and HR shared mailboxes where multiple users send as a single identity.

**Tuning notes:**
- Build a watchlist of known legitimate (UserId, MailboxOwnerUPN) delegation pairs and add an anti-join or exclusion filter before deploying as a scheduled rule.
- Restrict to SendAs only if SendOnBehalf generates excessive noise from calendar and resource mailbox delegation.
- Confirm whether SendOnBehalfOfUserSmtp is populated in the tenant's OfficeActivity schema; if present, use it to refine ImpersonatedSender for SendOnBehalf events.

**Risks / caveats:**
- SendOnBehalfOfUserSmtp is not a confirmed standard field in the OfficeActivity table for Exchange Online workload events in Microsoft Sentinel. If absent, the ImpersonatedSender coalesce logic falls back to MailboxOwnerUPN only, which changes the detection semantics.
- The 'Send' operation is not a standard Exchange Online audit operation in OfficeActivity. Valid send-related operations are 'SendAs' and 'SendOnBehalf'. Including 'Send' may cause the filter to match zero events or match unintended record types.
- OfficeActivity only captures Exchange Online audit events via the Office 365 connector; Zimbra Collaboration Suite does not natively emit to OfficeActivity without a custom connector.
- Without a confirmed exclusion list of legitimate delegated sender pairs, this detection will produce high false-positive volume in any environment with shared mailboxes or executive delegation.

### Triage Runbook

**First 15 minutes:**
- Verify whether the UserId and ImpersonatedSender pair is an approved delegation relationship.
- Check whether the operation was SendAs or SendOnBehalf and whether the sender pair is on a known shared mailbox or executive assistant list.
- Review the message content, recipients, and subject for payment, invoice, gift card, or urgent request language.
- Correlate the ClientIP with sign-in logs to confirm whether the sending session matches the expected user or service account.

**Evidence to collect:**
- OfficeActivity send events for the same UserId and ImpersonatedSender over the last 24 hours.
- Message trace or mail flow logs showing recipients, subject, and delivery status.
- Authentication logs for the sending account and source IP.
- Any approved delegation or shared mailbox records for the sender pair.

**Pivot points:**
- OfficeActivity filtered to SendAs and SendOnBehalf for the UserId and MailboxOwnerUPN.
- Message trace or mail flow logs for the same timestamp and recipients.
- Sign-in logs for the UserId and ClientIP.
- Directory or mailbox delegation records for approved send-as permissions.

**Benign explanations:**
- Shared mailboxes, executive assistants, and resource mailboxes commonly generate legitimate SendAs or SendOnBehalf activity.
- Automated systems may send mail using service accounts or functional mailboxes.
- Finance, legal, and HR teams often have approved delegated sending relationships.

**Escalation criteria:**
- The sender pair is not on an approved delegation list and the user denies sending the message.
- The email contains payment instructions, vendor banking changes, or other BEC indicators.
- The source IP, device, or sign-in context is unfamiliar or inconsistent with the account.
- Multiple impersonation attempts occur in a short period or target high-value recipients.

**Containment actions:**
- Disable the suspicious delegated send relationship or shared mailbox access if unauthorized.
- Reset credentials and revoke sessions for the acting account if compromise is suspected.
- Quarantine or recall the message if mail controls allow and the message is still in transit or recently delivered.
- Alert finance or business stakeholders if the message targets payment or vendor workflows.

**Closure criteria:**
- The activity is matched to a documented and approved delegation relationship.
- Message content and recipients are consistent with normal business operations.
- Authentication and device context are expected for the account or service.
- No additional unauthorized impersonation activity is found in the review window.

<br/>
---
<br/>

## Detection 3: BEC - Inbox Rule Creation Outside Business Hours from Anomalous Client IP

### Detection Opportunity

Threat actor alters inbox visibility by creating or modifying inbox rules, consistent with BEC tradecraft to redirect or suppress mail during an active compromise.

### Intelligence Context

- Rapid7: When Business Email Compromise Starts Rewriting Reality — [https://www.rapid7.com/blog/post/ve-business-email-compromise-rewriting-reality-zimbra-cve](https://www.rapid7.com/blog/post/ve-business-email-compromise-rewriting-reality-zimbra-cve)
  - Context: Rapid7 reported that threat actors alter inbox visibility, shared documents, and calendars as part of BEC operations. Inbox rule creation is a primary mechanism for suppressing fraud-detection emails and redirecting financial communications.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1098, T1098.001, T1114, T1114.001
- Products: Zimbra, Zimbra Collaboration Suite
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: Zimbra, Zimbra Collaboration Suite, T1098, T1098.001, T1114, T1114.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1098 Account Manipulation/ T1098.001 Additional Cloud Credentials (low); Collection: T1114 Email Collection/ T1114.001 Local Email Collection (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- OfficeActivity

### KQL

```kql
let KnownIPs = OfficeActivity
    | where TimeGenerated between (ago(30d) .. ago(1d))
    | where Operation in ("MailboxLogin", "MessageRead", "FolderBind")
    | where isnotempty(ClientIP)
    | where isnotempty(UserId)
    | summarize HistoricIPs = make_set(ClientIP, 200) by UserId;
OfficeActivity
| where TimeGenerated >= ago(1d)
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| where ResultStatus == "Succeeded"
| where isnotempty(UserId)
| where isnotempty(ClientIP)
| extend HourUTC = datetime_part("Hour", TimeGenerated)
| join kind=leftouter KnownIPs on UserId
| extend IsOffHours = (HourUTC < 7 or HourUTC > 20)
| extend IsNewIP = iif(array_length(HistoricIPs) > 0, not(set_has_element(HistoricIPs, ClientIP)), true)
| where IsOffHours or IsNewIP
| project
    TimeGenerated,
    UserId,
    ClientIP,
    RuleOperation = Operation,
    IsOffHours,
    HourUTC,
    IsNewIP,
    Parameters
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Users who travel internationally and create inbox rules from new geographic IPs during off-hours relative to UTC.
- IT administrators who configure inbox rules for users outside business hours during maintenance windows.
- Users who access email from a new device or VPN endpoint for the first time and create a legitimate inbox rule.

**Tuning notes:**
- Require both IsOffHours and IsNewIP to be true simultaneously by changing the where clause to 'where IsOffHours and IsNewIP' if standalone off-hours rule creation generates excessive noise.
- Adjust HourUTC boundaries to match the organization's primary time zone offset from UTC.
- Parse the Parameters field using parse_json() or extract() to surface specific rule conditions such as ForwardTo, DeleteMessage, or MoveToFolder for higher-fidelity triage.
- Add a UserId exclusion list for known IT administrator accounts that routinely configure inbox rules outside business hours.

**Risks / caveats:**
- OfficeActivity only captures Exchange Online audit events via the Office 365 connector; Zimbra Collaboration Suite does not natively emit to OfficeActivity without a custom connector mapping Zimbra audit events to Exchange-compatible operation names.
- The 30-day baseline query requires at least 30 days of OfficeActivity retention. Workspaces with shorter retention or recently onboarded tenants will have an incomplete baseline, causing IsNewIP to fire broadly on all IPs.
- Off-hours window of 07:00-20:00 UTC is a fixed approximation; organizations spanning multiple time zones will see elevated false positives from users in time zones where 07:00-20:00 UTC does not align with their local business hours.
- The 30-day IP baseline uses only MailboxLogin, MessageRead, and FolderBind operations; users who primarily access mail via protocols not captured by these operations may have sparse baselines, causing IsNewIP to fire more broadly.

### Triage Runbook

**First 15 minutes:**
- Review whether IsOffHours, IsNewIP, or both are true and whether the timing matches the user's normal work pattern.
- Inspect Parameters to identify forwarding, deletion, move-to-folder, or mark-as-read actions.
- Compare the ClientIP to the user's historical access patterns and known VPN or office egress ranges.
- Check whether the rule was created shortly after a successful login from the same IP or device.

**Evidence to collect:**
- OfficeActivity events for the same UserId around the rule creation time, including prior logins and message reads.
- The full Parameters field for the rule to identify the exact action and target.
- Authentication logs for the ClientIP and any associated device or session identifiers.
- Historical IP baseline for the user to confirm whether the source is truly new.

**Pivot points:**
- OfficeActivity for the same UserId over the last 30 days to compare normal access patterns.
- Sign-in logs or VPN logs for the ClientIP.
- Mailbox audit logs for rule creation, modification, and deletion events.
- Message trace or mail flow logs if forwarding or redirection is suspected.

**Benign explanations:**
- Travel, remote work, or first-time VPN use can produce a new IP and off-hours activity.
- IT staff may create or adjust inbox rules during maintenance windows.
- Users may legitimately create rules from a new device or mobile client outside local business hours.

**Escalation criteria:**
- Parameters show external forwarding, deletion of security alerts, or suppression of finance-related mail.
- The IP is associated with a known bad ASN, anonymizer, or foreign location inconsistent with the user.
- The user denies the activity or there is no legitimate reason for off-hours mailbox administration.
- Additional suspicious mailbox actions occur before or after the rule creation.

**Containment actions:**
- Remove the suspicious rule if it is unauthorized.
- Reset the account password and revoke active sessions if the login appears compromised.
- Block the suspicious IP or session if it is confirmed malicious and not a shared corporate endpoint.
- Notify the mailbox owner and relevant business contacts if mail redirection may have occurred.

**Closure criteria:**
- The rule is verified as legitimate and matches a known business or admin activity.
- The source IP is explained by a valid VPN, travel, or corporate remote access pattern.
- No forwarding, deletion, or suppression behavior is present in the rule parameters.
- No other suspicious mailbox activity is found in the surrounding time window.

<br/>
---
<br/>

## Detection 4: MacSync Backdoor - Outbound Network Connection from Newly Created Binary in User-Writable Directory on macOS

### Detection Opportunity

MacSync backdoor module establishes outbound network connections from a newly written binary located in a user-writable directory on macOS, consistent with post-delivery payload execution.

### Intelligence Context

- Securelist: MacSync under the microscope: new delivery methods and a new payload — [https://securelist.com/macsync-new-version/121383/](https://securelist.com/macsync-new-version/121383/)
  - Context: Securelist reported that MacSync now includes a new payload with a backdoor module. Backdoor modules characteristically establish persistent outbound connections. The combination of a newly created file in a user-writable path followed by outbound network activity from that process is the primary detectable pattern given the absence of specific IOCs.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1204, T1071
- Products: Not specified
- Platforms: macOS
- Malware: MacSync
- Tools: Not specified
- Search tags: macOS, MacSync, T1204, T1071

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1204 User Execution (low); Command and Control: T1071 Application Layer Protocol (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceFileEvents, DeviceNetworkEvents

### KQL

```kql
let LookbackDays = 7d;
let NewFiles = DeviceFileEvents
    | where Timestamp >= ago(LookbackDays)
    | where ActionType == "FileCreated"
    | where FolderPath matches regex @"(?i)^/Users/|^/tmp/|^/var/folders/"
    | where FileName !endswith ".log"
        and FileName !endswith ".plist"
        and FileName !endswith ".txt"
        and FileName !endswith ".json"
        and FileName !endswith ".xml"
    | project DeviceId, FileName, FolderPath, SHA256, FileCreatedTime = Timestamp;
DeviceNetworkEvents
| where Timestamp >= ago(LookbackDays)
| where ActionType == "ConnectionSuccess"
| where isnotempty(RemoteIP)
| where not(ipv4_is_private(RemoteIP))
| join kind=inner NewFiles on DeviceId
| where InitiatingProcessFileName == FileName
| where Timestamp > FileCreatedTime
| project
    Timestamp,
    DeviceId,
    DeviceName,
    FileName,
    FolderPath,
    SHA256,
    InitiatingProcessSHA256,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    FileCreatedTime
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate software installers that drop binaries into /Users/ or /tmp/ and immediately make outbound connections for license validation or update checks.
- Developer tools, package managers (Homebrew), and build systems that create and execute binaries in user-writable paths.
- Security agents and endpoint management tools that write and execute components in temporary directories.

**Tuning notes:**
- Add known-good software installer paths such as /Users/*/Library/Application Support/ to the FolderPath exclusion list to suppress legitimate application updates.
- Reduce LookbackDays to 2 or 3 days for interactive hunting to avoid query timeouts on large tenants.
- Submit SHA256 and InitiatingProcessSHA256 values from results to threat intelligence platforms to prioritize follow-up on unknown hashes.
- Consider adding a filter on RemotePort to focus on common C2 ports such as 443, 80, 8080, and 8443 if noise from legitimate software update connections is high.

**Risks / caveats:**
- DeviceFileEvents and DeviceNetworkEvents require Microsoft Defender for Endpoint to be deployed on macOS endpoints with sufficient sensor coverage. If macOS endpoints are not enrolled in MDE or the sensor does not collect file creation events for user-writable paths, the query will return no results.
- InitiatingProcessFileName in DeviceNetworkEvents contains only the process binary name without path, making it impossible to confirm the initiating process is the exact file created in the monitored directory rather than a different binary with the same name. This is a structural limitation of the join approach.
- The join on DeviceId and FileName without full path matching means a legitimate process with the same binary name as a newly created file in a monitored path will produce a false match. InitiatingProcessFolderPath is not reliably populated in all MDE schema versions and was not added to the join condition to avoid breaking the query on tenants where it is absent.
- The regex path filter covers /Users/, /tmp/, and /var/folders/ but does not cover all user-writable macOS paths such as /private/tmp/ or application-specific cache directories.

### Triage Runbook

**First 15 minutes:**
- Confirm the file path, SHA256, and creation time for the binary and whether it is expected software.
- Review the remote IP, port, and URL to determine whether the connection is to a known service or suspicious external host.
- Check whether the initiating process path and hash match the newly created file or a legitimate installer/updater.
- Look for additional process, file, or network activity on the same host around the same timestamp.

**Evidence to collect:**
- DeviceFileEvents for the file creation event, including FolderPath, FileName, SHA256, and FileCreatedTime.
- DeviceNetworkEvents for the same DeviceId, including RemoteIP, RemotePort, RemoteUrl, and InitiatingProcessSHA256.
- Process creation or command-line telemetry for the initiating process if available.
- Any threat intelligence hits for the SHA256, RemoteIP, or RemoteUrl.

**Pivot points:**
- DeviceFileEvents for the same DeviceId and SHA256 to find related file drops or renames.
- DeviceNetworkEvents for the same DeviceId to identify additional outbound connections.
- DeviceProcessEvents or equivalent process telemetry for command line and parent process context.
- Threat intelligence or reputation lookups for the file hash and remote endpoint.

**Benign explanations:**
- Legitimate installers, updaters, and package managers often drop binaries in user-writable directories and then connect out.
- Developer tools and build systems can create and execute binaries in /Users/, /tmp/, or /var/folders/.
- Security or endpoint management tools may stage components in temporary directories before connecting to management services.

**Escalation criteria:**
- The binary hash is unknown or matches malware intelligence, and the remote destination is suspicious.
- The file is unsigned, newly created, and not associated with a known installer or enterprise software.
- The host shows additional suspicious behavior such as persistence, credential access, or lateral movement.
- The user cannot explain the file or the process is running from an unexpected user-writable path.

**Containment actions:**
- Isolate the macOS host from the network if the binary appears malicious or the remote connection is clearly suspicious.
- Quarantine or remove the file only after preserving evidence and confirming it is not legitimate software.
- Terminate the suspicious process if containment is required and the process is actively communicating externally.
- Collect a forensic package or live response artifacts before rebooting or wiping the system.

**Closure criteria:**
- The file is identified as a legitimate installer, updater, or approved tool.
- The remote destination is a known corporate or vendor service and the hash is trusted.
- No additional suspicious processes, persistence, or outbound connections are found on the host.
- Threat intelligence and endpoint review do not indicate malicious behavior.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- BEC - Mailbox Silent Monitoring Followed by Inbox Rule Manipulation: Do not schedule yet; validate as an analyst-led hunt first.
- MacSync Backdoor - Outbound Network Connection from Newly Created Binary in User-Writable Directory on macOS: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- BEC - Sender Impersonation Without Credential Match in Mail Audit Logs: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: OfficeActivity before scheduling.

**Shared-table notes:**
- OfficeActivity: shared by BEC - Mailbox Silent Monitoring Followed by Inbox Rule Manipulation; BEC - Sender Impersonation Without Credential Match in Mail Audit Logs; BEC - Inbox Rule Creation Outside Business Hours from Anomalous Client IP

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: BEC - Inbox Rule Creation Outside Business Hours from Anomalous Client IP.
2. Resolve environment-mapping detections next: BEC - Sender Impersonation Without Credential Match in Mail Audit Logs.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: BEC - Mailbox Silent Monitoring Followed by Inbox Rule Manipulation; MacSync Backdoor - Outbound Network Connection from Newly Created Binary in User-Writable Directory on macOS.

### Hunting Agenda and Promotion Criteria

- BEC - Mailbox Silent Monitoring Followed by Inbox Rule Manipulation: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- MacSync Backdoor - Outbound Network Connection from Newly Created Binary in User-Writable Directory on macOS: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- BEC - Sender Impersonation Without Credential Match in Mail Audit Logs: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: OfficeActivity before scheduling.; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
