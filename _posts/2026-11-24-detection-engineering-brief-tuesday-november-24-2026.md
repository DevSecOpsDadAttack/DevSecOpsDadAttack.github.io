---
layout: post
title: "Detection Engineering Brief - Tuesday, November 24, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-11-24
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-123890
  - ARMORY CASTLE
  - VMware vCenter
  - VMware Directory Service
  - CVE-2026-73571
  - Zimbra
  - Metasploit
  - cloud services
  - T1190
  - T1078
  - T1580
  - T1566.004
  - T1556
  - T1537
  - T1566
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 0 hunting-only, 4 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-123890, ARMORY CASTLE, VMware vCenter, VMware Directory Service, CVE-2026-73571, Zimbra, Metasploit, cloud services, T1190, T1078, T1580, T1566.004, T1556, T1537, T1566.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: CVE-2026-123890 - VMware vCenter Administrator Logon from Previously Unseen Source IP; CVE-2026-123890 - Unauthenticated Network Connection to vCenter Management Port Followed by Admin Session; CVE-2026-73571 - Zimbra Authenticated User Sending Mail as a Different Identity; CVE-2026-73571 - Zimbra SaveDraftRequest Authorization Bypass Attempt.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: CVE-2026-123890 - VMware vCenter Administrator Logon from Previously Unseen Source IP

### Detection Opportunity

Unauthorized access as the Administrator user following authentication bypass exploit of CVE-2026-123890 in VMware vCenter.

### Intelligence Context

- Rapid7: CVE-2026-123890: Critical Authentication Bypass in VMware vCenter — [https://www.rapid7.com/blog/post/etr-cve-2026-123890-critical-authentication-bypass-vmware-vcenter](https://www.rapid7.com/blog/post/etr-cve-2026-123890-critical-authentication-bypass-vmware-vcenter)
  - Context: Mandiant/Google Threat Intelligence confirmed in-the-wild exploitation of CVE-2026-123890. Successful exploitation grants unauthorized access as the Administrator user without credentials. Admin logon from a source IP with no prior successful authentication history is a high-fidelity post-exploit signal.

### Search Metadata

- CVEs: CVE-2026-123890
- Threat actors: ARMORY CASTLE
- ATT&CK tags: T1190, T1078
- Products: VMware vCenter, VMware Directory Service
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-123890, ARMORY CASTLE, VMware vCenter, VMware Directory Service, T1190, T1078

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Persistence: T1078 Valid Accounts (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent, Syslog before scheduling.

**Required telemetry:**
- SecurityEvent, Syslog

### KQL

```kql
let lookback = 30d;
let alertWindow = 1h;
// SecurityEvent branch: baseline of known Administrator source IPs
let knownAdminSourcesSE =
    SecurityEvent
    | where TimeGenerated between (ago(lookback) .. ago(alertWindow))
    | where AccountName =~ "Administrator"
    | where EventID in (4624, 4648)
    | where IpAddress != "-" and isnotempty(IpAddress)
    | distinct IpAddress;
// SecurityEvent branch: new Administrator logons in alert window
let newAdminLogonsSE =
    SecurityEvent
    | where TimeGenerated >= ago(alertWindow)
    | where AccountName =~ "Administrator"
    | where EventID in (4624, 4648)
    | where IpAddress != "-" and isnotempty(IpAddress)
    | project TimeGenerated, AccountName, IpAddress, LogonType, Computer, EventID;
// Syslog branch: baseline of known Administrator source IPs per host
let knownAdminSourcesSL =
    Syslog
    | where TimeGenerated between (ago(lookback) .. ago(alertWindow))
    | where SyslogMessage has "Administrator" and SyslogMessage has "authenticated"
    | extend SourceIP = extract(@"from\s+([\d\.]+)", 1, SyslogMessage)
    | where isnotempty(SourceIP)
    | distinct SourceIP, HostName;
// Syslog branch: new Administrator logons in alert window
let newAdminLogonsSL =
    Syslog
    | where TimeGenerated >= ago(alertWindow)
    | where SyslogMessage has_any ("Administrator", "vpxd", "vCenter")
    | where SyslogMessage has "authenticated"
    | extend SourceIP = extract(@"from\s+([\d\.]+)", 1, SyslogMessage)
    | where isnotempty(SourceIP)
    | project TimeGenerated, SourceIP, HostName, SyslogMessage;
// SecurityEvent: surface logons from IPs not in baseline
newAdminLogonsSE
| join kind=leftanti knownAdminSourcesSE on IpAddress
| extend SourceIP = IpAddress, HostName = Computer, SyslogMessage = ""
| project TimeGenerated, AccountName, SourceIP, LogonType, HostName, EventID, SyslogMessage
| union (
    // Syslog: surface logons from IPs not in baseline for the same host
    newAdminLogonsSL
    | join kind=leftanti knownAdminSourcesSL on SourceIP, HostName
    | extend AccountName = "Administrator", LogonType = int(null), EventID = int(null)
    | project TimeGenerated, AccountName, SourceIP, LogonType, HostName, EventID, SyslogMessage
)
| extend AlertDetail = "Administrator logon from previously unseen source IP - possible CVE-2026-123890 exploitation by ARMORY CASTLE"
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrator logons from new jump hosts, VPN egress IPs, or newly provisioned management workstations not seen in the 30-day baseline.
- First-run of the rule after deployment will have no baseline and may fire on all current admin source IPs until the lookback window is populated.
- Syslog regex may not match all vCenter log formats across versions, potentially missing events or extracting incorrect IPs.

**Tuning notes:**
- Extend lookback from 30d to 60d if the environment has infrequent but legitimate admin logons from rotating IPs.
- Add a HostName filter to scope SecurityEvent and Syslog queries to known vCenter hostnames to reduce noise from non-vCenter Windows hosts.
- Consider adding a watchlist of known management jump-host IPs to exclude from alerting.

**Risks / caveats:**
- SecurityEvent table will only contain vCenter logon events if the vCenter appliance is AD-joined and the Windows Security event log is forwarded to Sentinel via the Log Analytics agent or AMA; this is non-default for vCenter VCSA appliances.
- Syslog table will only contain vCenter authentication events if syslog forwarding from the vCenter appliance to the Sentinel syslog collector is explicitly configured.
- The original KQL uses 'join kind=leftanti on $left.IpAddress == $right.KnownIPs' where KnownIPs is a dynamic set column; this join predicate is invalid in KQL and will produce incorrect results. The hardened query corrects this using 'join kind=leftanti' after mv-expanding the set.
- The 30-day baseline will not suppress new source IPs that appeared only after the lookback window; manual allowlisting of known management IPs is recommended at deployment.

### Triage Runbook

**First 15 minutes:**
- Confirm the source IP, hostname, and exact timestamp of the Administrator logon and compare it to the 30-day baseline of known admin IPs.
- Check whether the source IP belongs to a known jump host, VPN egress, management workstation, or a recently approved admin change.
- Review adjacent vCenter and directory authentication events for the same account to see whether the login was preceded by unusual failures, bypass indicators, or other suspicious activity.
- Determine whether the vCenter appliance is AD-joined and whether the event came from SecurityEvent or Syslog, since that affects how much context is available.
- If the source IP is external or unknown, treat the event as a likely exploitation indicator and move to incident handling.

**Evidence to collect:**
- Exact source IP, host, account, logon type, event ID, and time window around the alert.
- vCenter authentication logs, syslog entries, and any nearby administrative actions performed by the Administrator account.
- Recent changes to jump hosts, VPN ranges, or admin access paths that could explain a new source IP.
- Any evidence of concurrent vCenter configuration changes, new sessions, or privilege changes after the login.

**Pivot points:**
- SecurityEvent for EventID 4624 and 4648 involving AccountName=Administrator and related IpAddress values.
- Syslog for vCenter authentication messages containing Administrator, authenticated, and the extracted SourceIP.
- vCenter management logs and VMware Directory Service logs for the same time window.
- Network/security telemetry for the source IP to identify whether it is a known admin endpoint or an external address.

**Benign explanations:**
- A legitimate administrator used a new workstation, jump host, or VPN egress IP not yet present in the 30-day baseline.
- The rule fired during initial deployment before the baseline was populated.
- A newly provisioned management host or rotated VPN IP was used for routine maintenance.

**Escalation criteria:**
- The source IP is external, unrecognized, or not associated with approved administration paths.
- The Administrator login is followed by suspicious vCenter actions such as new account creation, permission changes, or configuration export.
- There are signs of exploitation such as unusual authentication patterns, multiple failed attempts, or other alerts tied to the same host or IP.
- The event occurs on a vCenter instance exposed to the internet or otherwise reachable from untrusted networks.

**Containment actions:**
- If the login is not immediately explainable, disable or reset the Administrator account and revoke active sessions through the vCenter management interface.
- Block or restrict the source IP at network controls if it is not a known admin endpoint.
- Preserve vCenter and directory logs before making disruptive changes.
- Coordinate with virtualization and identity teams before rebooting or patching the appliance.

**Closure criteria:**
- The source IP is confirmed as an approved admin endpoint and the activity matches a documented change or maintenance window.
- No suspicious follow-on actions are found in vCenter or directory logs.
- The account owner or virtualization team confirms the login and provides a valid business reason.
- Any required allowlist or baseline update has been completed to prevent repeat noise.

<br/>
---
<br/>

## Detection 2: CVE-2026-123890 - Unauthenticated Network Connection to vCenter Management Port Followed by Admin Session

### Detection Opportunity

Authentication bypass against VMware vCenter without credentials, followed by an Administrator session, consistent with CVE-2026-123890 exploitation by ARMORY CASTLE.

### Intelligence Context

- Rapid7: CVE-2026-123890: Critical Authentication Bypass in VMware vCenter — [https://www.rapid7.com/blog/post/etr-cve-2026-123890-critical-authentication-bypass-vmware-vcenter](https://www.rapid7.com/blog/post/etr-cve-2026-123890-critical-authentication-bypass-vmware-vcenter)
  - Context: CVE-2026-123890 allows a network-adjacent actor to bypass authentication entirely and gain Administrator access. The compound signal of an external IP connecting to vCenter management ports followed within a short window by an Administrator logon from the same IP is a high-fidelity exploitation indicator.

### Search Metadata

- CVEs: CVE-2026-123890
- Threat actors: ARMORY CASTLE
- ATT&CK tags: T1190, T1078
- Products: VMware vCenter, VMware Directory Service
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-123890, ARMORY CASTLE, VMware vCenter, VMware Directory Service, T1190, T1078

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Persistence: T1078 Valid Accounts (medium)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceNetworkEvents, SecurityEvent

### KQL

```kql
let correlationWindow = 15m;
let lookbackWindow = 1h;
let vcenterPorts = dynamic([443, 5480, 9443]);
// Set to true to exclude RFC-1918 source IPs from network hits
let excludeInternalIPs = false;
let networkHits =
    DeviceNetworkEvents
    | where TimeGenerated >= ago(lookbackWindow)
    | where LocalPort in (vcenterPorts)
    | where ActionType in ("InboundConnectionAccepted", "ConnectionFound")
    | where not(excludeInternalIPs and (
        RemoteIP startswith "10."
        or RemoteIP startswith "192.168."
        or RemoteIP matches regex @"^172\.(1[6-9]|2[0-9]|3[01])\."
    ))
    | where isnotempty(RemoteIP)
    | project NetworkTime = TimeGenerated, RemoteIP, LocalPort, DeviceName;
let adminLogons =
    SecurityEvent
    | where TimeGenerated >= ago(lookbackWindow)
    | where EventID in (4624, 4648)
    | where AccountName =~ "Administrator"
    | where IpAddress != "-" and isnotempty(IpAddress)
    | project LogonTime = TimeGenerated, IpAddress, AccountName, Computer, LogonType, EventID;
networkHits
| join kind=inner adminLogons on $left.RemoteIP == $right.IpAddress
| where LogonTime between (NetworkTime .. (NetworkTime + correlationWindow))
| project NetworkTime, LogonTime, RemoteIP, LocalPort, AccountName, Computer, DeviceName, LogonType, EventID
| extend AlertDetail = "External IP connected to vCenter management port then authenticated as Administrator within 15 minutes - possible CVE-2026-123890 exploitation by ARMORY CASTLE"
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrators connecting to vCenter management interfaces from new workstations or VPN IPs will trigger this rule.
- Automated monitoring tools or health-check agents that connect to vCenter ports and are followed by scheduled admin logons.
- Internal RFC-1918 source IPs if the excludeInternalIPs flag is not enabled and internal admin access is routine.

**Tuning notes:**
- If vCenter is not AD-joined, replace the SecurityEvent admin logon branch with a Syslog-based branch using the same regex pattern from the companion detection.
- Add a DeviceName filter to scope DeviceNetworkEvents to the specific vCenter hostname or network device fronting vCenter.
- Consider reducing correlationWindow to 5 minutes if exploitation tooling is known to operate quickly.

**Risks / caveats:**
- DeviceNetworkEvents is populated by MDE-onboarded devices only; vCenter VCSA appliances are Linux-based and are not natively onboarded to MDE, so inbound connection records for vCenter will not appear unless a network sensor or proxy fronting vCenter is onboarded.
- SecurityEvent will only contain vCenter Administrator logon events if vCenter is AD-joined and Windows Security event forwarding is configured.
- ActionType value 'ConnectionSuccess' is not a standard MDE DeviceNetworkEvents ActionType; valid inbound values are 'InboundConnectionAccepted' and 'ConnectionFound'. Using an unsupported ActionType will silently drop matching rows.
- If DeviceNetworkEvents does not contain vCenter host entries, this query will produce no results regardless of exploitation activity; validate data presence before scheduling.

### Triage Runbook

**First 15 minutes:**
- Confirm the remote IP, destination port, device name, and timing between the network connection and the Administrator logon.
- Check whether the remote IP is external or otherwise not part of approved admin infrastructure.
- Review whether the same IP has any prior history of legitimate vCenter access or whether this is a first-seen source.
- Look for additional connections from the same IP to vCenter ports 443, 5480, or 9443 and any repeated authentication activity.
- If the connection and login are tightly correlated and the IP is untrusted, treat this as a probable exploit attempt with successful access.

**Evidence to collect:**
- Network event details including RemoteIP, LocalPort, ActionType, DeviceName, and NetworkTime.
- SecurityEvent logon details including IpAddress, AccountName, LogonType, EventID, and LogonTime.
- Any vCenter or VMware Directory Service logs showing the same source IP or account activity.
- Firewall, proxy, or NDR records that confirm whether the source IP is external or internal.

**Pivot points:**
- DeviceNetworkEvents for inbound connections to vCenter management ports from the same RemoteIP.
- SecurityEvent for Administrator logons from the matching IpAddress within the correlation window.
- Syslog and vCenter logs for the same source IP and time range.
- Network security telemetry to determine whether the source IP is a known scanner, admin host, or internet address.

**Benign explanations:**
- A legitimate administrator connected from a new workstation or VPN IP and then authenticated normally.
- A monitoring or health-check system connected to the management port and was followed by a routine admin login.
- The source IP is internal and belongs to a known management network, but the allowlist is incomplete.

**Escalation criteria:**
- The source IP is external, unknown, or not associated with approved administration.
- The login occurs within minutes of the connection and there is no valid change record.
- There are signs of broader compromise such as new accounts, privilege changes, or suspicious vCenter configuration changes.
- Multiple vCenter hosts or repeated source IPs are involved, suggesting active exploitation.

**Containment actions:**
- Block the source IP at the perimeter or management network if it is not a trusted admin endpoint.
- Disable or reset the Administrator account if unauthorized access is suspected.
- Preserve relevant logs and session data before making changes.
- Engage virtualization and network teams to verify whether the appliance is exposed and whether emergency patching is required.

**Closure criteria:**
- The source IP is confirmed as a legitimate admin or monitoring endpoint.
- The login is tied to an approved maintenance activity and no other suspicious actions are found.
- No additional malicious activity is observed from the same IP or account.
- The environment has been validated so the rule only alerts on truly suspicious combinations.

<br/>
---
<br/>

## Detection 3: CVE-2026-73571 - Zimbra Authenticated User Sending Mail as a Different Identity

### Detection Opportunity

Authenticated Zimbra user sends outbound mail where the sender address differs from the authenticated session identity, exploiting the SaveDraftRequest authorization bypass in CVE-2026-73571.

### Intelligence Context

- Rapid7: Metasploit Wrap Up: Breaking Zimbra's Identity Boundaries — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-breaking-zimbra-s-identity-boundaries](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-breaking-zimbra-s-identity-boundaries)
  - Context: CVE-2026-73571 is an authorization bypass in Zimbra's SaveDraftRequest handling that allows an ordinary authenticated user to send mail as another identity. A Metasploit module has been developed for this vulnerability. The mismatch between authenticated session user and the envelope sender address is a specific, high-fidelity signal for this abuse pattern.

### Search Metadata

- CVEs: CVE-2026-73571
- Threat actors: Not specified
- ATT&CK tags: T1190, T1580
- Products: Zimbra
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-73571, Zimbra, Metasploit, T1190, T1580

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Discovery: T1580 Cloud Infrastructure Discovery (low)

### Deployment Gates

- CommonSecurityLog DeviceVendor field value for Zimbra is connector-dependent; the exact string must match what the deployed Zimbra CEF connector emits. A mismatch will silently exclude all Zimbra events.
- CommonSecurityLog DeviceVendor value must match the exact string emitted by the Zimbra CEF connector in the environment.

**Required telemetry:**
- CommonSecurityLog, Syslog

### KQL

```kql
let zimbraIdentityMismatch =
    CommonSecurityLog
    | where TimeGenerated >= ago(1h)
    | where DeviceVendor has_any ("Zimbra", "zimbra")
    | where RequestURL has "SaveDraftRequest" or Activity has "SaveDraftRequest"
    | where isnotempty(SourceUserName) and isnotempty(DestinationUserName)
    | where tolower(SourceUserName) != tolower(DestinationUserName)
    | project TimeGenerated, SourceUserName, DestinationUserName, SourceIP, RequestURL, DeviceVendor, HostName = DeviceName;
let syslogMismatch =
    Syslog
    | where TimeGenerated >= ago(1h)
    | where SyslogMessage has "SaveDraftRequest"
    | extend AuthUser = extract(@"authUser=([^\s;,]+)", 1, SyslogMessage)
    | extend SenderAddr = extract(@"from=<([^>]+)>", 1, SyslogMessage)
    | where isnotempty(AuthUser) and isnotempty(SenderAddr)
    | where tolower(AuthUser) != tolower(SenderAddr)
    | project TimeGenerated, SourceUserName = AuthUser, DestinationUserName = SenderAddr, SourceIP = "", RequestURL = "", DeviceVendor = "Zimbra-Syslog", HostName;
zimbraIdentityMismatch
| union syslogMismatch
| extend AlertDetail = "Zimbra authenticated user identity does not match envelope sender - possible CVE-2026-73571 exploitation"
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate mail delegation configurations where one user is authorized to send on behalf of another.
- Shared mailbox or distribution list scenarios where the authenticated user and sender address are intentionally different.
- Service accounts that send mail on behalf of other identities as part of automated workflows.

**Tuning notes:**
- Build an exclusion list of known legitimate delegation accounts and add a 'where SourceUserName !in (exclusionList)' filter before scheduling.
- Validate the DeviceVendor string by running 'CommonSecurityLog → where DeviceVendor has "zimbra" → distinct DeviceVendor' against the environment before enabling.
- If Zimbra logs are forwarded via a custom syslog format, update the regex patterns to match the actual field delimiters used.

**Risks / caveats:**
- CommonSecurityLog DeviceVendor field value for Zimbra is connector-dependent; the exact string must match what the deployed Zimbra CEF connector emits. A mismatch will silently exclude all Zimbra events.
- Syslog regex patterns 'authUser=([^\s;,]+)' and 'from=<([^>]+)>' are format-dependent; Zimbra log verbosity must be set to include these fields and the format must match the deployed version.
- If Zimbra does not forward logs to Sentinel via either a CEF connector or syslog forwarder, both branches will produce no results.
- Syslog regex patterns must be validated against actual Zimbra log output for the deployed version before scheduling.

### Triage Runbook

**First 15 minutes:**
- Confirm the authenticated user, sender address, source IP, host, and exact SaveDraftRequest details from the alert.
- Check whether the sender identity is a known delegated mailbox, shared mailbox, or service account exception.
- Review recent Zimbra activity from the same source IP for repeated sender changes, unusual draft activity, or other suspicious requests.
- Validate whether the event came from CommonSecurityLog or Syslog and whether the extracted fields look reliable.
- If the sender mismatch is not expected, treat the event as likely exploitation and move to incident response.

**Evidence to collect:**
- The full Zimbra request context including RequestURL, SourceUserName or AuthUser, DestinationUserName or SenderAddr, SourceIP, and HostName.
- Nearby Zimbra logs showing prior and subsequent SaveDraftRequest activity from the same account or IP.
- Mail flow records showing whether messages were actually sent as the impersonated identity.
- Any delegation, shared mailbox, or service account documentation that could explain the mismatch.

**Pivot points:**
- CommonSecurityLog for Zimbra events with SaveDraftRequest and mismatched SourceUserName/DestinationUserName.
- Syslog for SaveDraftRequest entries with authUser and from fields from the same source IP.
- Mail gateway or message trace logs for messages sent under the impersonated identity.
- Zimbra audit and application logs for the same account and host around the alert time.

**Benign explanations:**
- Legitimate mail delegation or shared mailbox use where the authenticated user is allowed to send as another identity.
- A service account or automation workflow that sends mail on behalf of another user.
- Connector parsing issues causing the sender or authenticated user field to be extracted incorrectly.

**Escalation criteria:**
- The sender identity is not an approved delegation or shared mailbox case.
- The same source IP shows repeated mismatches or multiple targeted identities.
- There is evidence of actual message sending as another user or other post-exploitation activity.
- The activity aligns with a known exploitation pattern or occurs on an internet-facing Zimbra instance.

**Containment actions:**
- Suspend the affected account or revoke active sessions if unauthorized sending is confirmed.
- Temporarily block the source IP if it is not a trusted mail relay or admin endpoint.
- Preserve Zimbra logs and mail traces before altering the system.
- Coordinate with messaging administrators to disable the vulnerable endpoint or apply vendor guidance if exploitation is suspected.

**Closure criteria:**
- The mismatch is confirmed as legitimate delegation, shared mailbox use, or an approved service account workflow.
- No unauthorized mail sending or other suspicious Zimbra activity is found.
- The parsing result is validated and the event is determined to be a connector artifact.
- An exclusion or tuning rule has been documented for the approved case.

<br/>
---
<br/>

## Detection 4: Vishing Account Compromise - MFA Change Followed by Cloud Data Bulk Export

### Detection Opportunity

Following vishing-enabled account compromise, an attacker performs bulk cloud data download or sharing operations shortly after an MFA method change, consistent with Com affiliate cloud data theft campaigns.

### Intelligence Context

- Unit 42: Dialing for Data: Inside the Com's High-Profile Heists — [https://unit42.paloaltonetworks.com/com-affiliate-vishing-attacks/](https://unit42.paloaltonetworks.com/com-affiliate-vishing-attacks/)
  - Context: Com affiliate vishing attacks target healthcare and finance organizations, using social engineering to compromise accounts and then exfiltrate cloud data. The compound signal of an MFA method change followed by bulk data download or sharing from the same account within a short window is a detectable post-compromise exfiltration pattern.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1566.004, T1556, T1537, T1566
- Products: Not specified
- Platforms: cloud services
- Malware: Not specified
- Tools: Not specified
- Search tags: cloud services, T1566.004, T1556, T1537, T1566

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1566 Phishing/ T1566.004 Vishing (high); Defense Evasion: T1556 Modify Authentication Process (medium); Exfiltration: T1537 Transfer Data to Cloud Account (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- AuditLogs, OfficeActivity, AzureActivity

### KQL

```kql
let correlationWindow = 4h;
let mfaChanges =
    AuditLogs
    | where TimeGenerated >= ago(24h)
    | where OperationName has_any ("Update user", "User registered security info", "User deleted security info", "Admin registered security info")
    | where TargetResources has_any ("StrongAuthenticationMethod", "MFA", "AuthenticationMethod")
    | mv-expand TargetResource = TargetResources
    | extend UPN = tostring(TargetResource.userPrincipalName)
    | where isnotempty(UPN)
    | summarize MFAChangeTime = min(TimeGenerated), OperationName = take_any(OperationName) by UPN;
let bulkDataOps =
    OfficeActivity
    | where TimeGenerated >= ago(24h)
    | where Operation in ("FileDownloaded", "FileSyncDownloadedFull", "AnonymousLinkCreated", "SharingSet", "FileAccessed")
    | summarize OpCount = count(), FirstOp = min(TimeGenerated), ClientIP = take_any(ClientIP) by UserId
    | where OpCount >= 50
    | project FirstOp, UserId, ClientIP, OpCount;
let azureBulk =
    AzureActivity
    | where TimeGenerated >= ago(24h)
    | where OperationName has_any ("List Keys", "Get Blob", "List Blobs", "Get Storage Account")
    | where ActivityStatus == "Succeeded"
    | summarize AzureOpCount = count(), AzureFirstOp = min(TimeGenerated), CallerIpAddress = take_any(CallerIpAddress) by Caller
    | where AzureOpCount >= 30
    | project AzureFirstOp, Caller, CallerIpAddress, AzureOpCount;
let officeCorrelated =
    mfaChanges
    | join kind=inner bulkDataOps on $left.UPN == $right.UserId
    | where FirstOp between (MFAChangeTime .. (MFAChangeTime + correlationWindow))
    | project MFAChangeTime, DataOpTime = FirstOp, UPN, SourceIP = ClientIP, OpCount, AzureOpCount = int(null), OperationName, DataSource = "OfficeActivity";
let azureCorrelated =
    mfaChanges
    | join kind=inner azureBulk on $left.UPN == $right.Caller
    | where AzureFirstOp between (MFAChangeTime .. (MFAChangeTime + correlationWindow))
    | project MFAChangeTime, DataOpTime = AzureFirstOp, UPN, SourceIP = CallerIpAddress, OpCount = int(null), AzureOpCount, OperationName, DataSource = "AzureActivity";
officeCorrelated
| union azureCorrelated
| extend AlertDetail = "MFA method change followed by bulk cloud data access within 4 hours - consistent with vishing-enabled account compromise and exfiltration (Com affiliate campaign)"
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate users who change their MFA method during onboarding or device replacement and then perform bulk file operations.
- IT administrators who reset MFA for users and then perform bulk data migrations.
- Automated pipelines that trigger bulk Azure storage operations shortly after a scheduled credential rotation.
- Users in organizations with high baseline file download volumes may exceed the OpCount threshold during normal work.

**Tuning notes:**
- Run 'OfficeActivity → where Operation in ("FileDownloaded", "FileSyncDownloadedFull") → summarize count() by UserId → order by count_ desc' over 7 days to calibrate the OpCount threshold for the environment.
- Add a known-safe UPN exclusion list for IT admin accounts that routinely perform bulk operations after MFA resets.
- Narrow correlationWindow to 2 hours if the environment has tight change-management controls that make shorter windows more precise.

**Risks / caveats:**
- AuditLogs TargetResources is a dynamic array; the expression TargetResources[0].userPrincipalName may return empty if the UPN is not in the first element. The hardened query uses mv-expand to handle multi-element TargetResources arrays.
- AzureActivity Caller field contains UPN for user-initiated actions but may contain a service principal object ID for automated actions; the join to UPN will miss service principal activity.
- OfficeActivity UserId field contains UPN in most cases but may contain a display name or SID in some connector configurations; validate field content before relying on the join.
- AzureActivity Caller field contains service principal object IDs for non-user-initiated operations; bulk Azure storage access by service principals running under a compromised account context will not be correlated.

### Triage Runbook

**First 15 minutes:**
- Identify the user, MFA change time, source IPs, and the specific cloud operations that triggered the alert.
- Contact the account owner or service desk through an out-of-band method to verify whether the MFA change was legitimate.
- Check whether the account recently reported a vishing call, help desk interaction, or password reset request.
- Review whether the bulk activity is unusual for the user based on role, department, and historical behavior.
- If the MFA change is unapproved or the bulk activity is clearly abnormal, treat the account as compromised.

**Evidence to collect:**
- AuditLogs entries for the MFA method change, including UPN, operation name, and target resources.
- OfficeActivity records showing file downloads, sharing actions, or other bulk operations with counts and source IPs.
- AzureActivity records if cloud storage or Azure resource access was involved, including Caller and CallerIpAddress.
- User communication records or help desk tickets that may explain the MFA change.

**Pivot points:**
- AuditLogs for security info changes, MFA registration, and authentication method updates for the same UPN.
- OfficeActivity for high-volume file download, sync, or sharing operations by the same user.
- AzureActivity for bulk storage access or other high-volume cloud operations by the same caller.
- Sign-in logs and identity telemetry to identify unusual geolocation, device, or IP patterns.

**Benign explanations:**
- The user legitimately changed MFA during onboarding, device replacement, or recovery and then performed normal work.
- IT or identity administrators changed MFA on behalf of the user as part of support.
- A scheduled migration, backup, or automation job caused the bulk cloud activity.
- The user has a role that routinely performs high-volume file operations.

**Escalation criteria:**
- The MFA change was not requested or approved by the user or identity team.
- Bulk downloads or sharing are outside the user’s normal behavior and occur shortly after the MFA change.
- There are signs of suspicious sign-ins, impossible travel, or repeated access from unfamiliar IPs.
- Multiple users or accounts show the same pattern, suggesting an active campaign.

**Containment actions:**
- Reset the account password and revoke active sessions if compromise is likely.
- Remove recently added MFA methods or authentication factors that were not approved.
- Temporarily disable the account if the user cannot be verified or if exfiltration is ongoing.
- Coordinate with cloud and identity teams to preserve logs and stop further data access.

**Closure criteria:**
- The MFA change is verified as legitimate and the bulk activity matches the user’s normal role or an approved task.
- No evidence of unauthorized access, exfiltration, or suspicious sign-in behavior is found.
- The account owner confirms the activity and the help desk record supports it.
- Any necessary tuning or allowlisting has been documented for recurring legitimate workflows.

<br/>
---
<br/>

## Detection 5: CVE-2026-73571 - Zimbra SaveDraftRequest Authorization Bypass Attempt

### Detection Opportunity

Authorization bypass attempt via Zimbra SaveDraftRequest endpoint, where an authenticated user submits a SaveDraftRequest with a sender identity differing from their session, exploiting CVE-2026-73571.

### Intelligence Context

- Rapid7: Metasploit Wrap Up: Breaking Zimbra's Identity Boundaries — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-breaking-zimbra-s-identity-boundaries](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-breaking-zimbra-s-identity-boundaries)
  - Context: A Metasploit module was developed for CVE-2026-73571, increasing exploitation likelihood. The vulnerability is triggered via the SaveDraftRequest SOAP endpoint. Repeated SaveDraftRequest calls from a single source IP targeting multiple different sender identities within a short window is a pattern consistent with automated exploitation or reconnaissance of the vulnerability.

### Search Metadata

- CVEs: CVE-2026-73571
- Threat actors: Not specified
- ATT&CK tags: T1190, T1580
- Products: Zimbra
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-73571, Zimbra, Metasploit, T1190, T1580

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Discovery: T1580 Cloud Infrastructure Discovery (low)

### Deployment Gates

- CommonSecurityLog DeviceVendor value must be validated against the exact string emitted by the Zimbra CEF connector.

**Required telemetry:**
- CommonSecurityLog, Syslog

### KQL

```kql
let huntWindow = 24h;
let burstWindow = 10m;
let minDistinctSenders = 2;
let allHits =
    union
    (
        CommonSecurityLog
        | where TimeGenerated >= ago(huntWindow)
        | where DeviceVendor has_any ("Zimbra", "zimbra")
        | where RequestURL has "SaveDraftRequest" or Activity has "SaveDraftRequest"
        | where isnotempty(SourceIP) and isnotempty(SourceUserName)
        | project TimeGenerated, SourceIP, SourceUserName, HostName = DeviceName
    ),
    (
        Syslog
        | where TimeGenerated >= ago(huntWindow)
        | where SyslogMessage has "SaveDraftRequest"
        | extend SourceIP = extract(@"client=\[?([\d\.]+)\]?", 1, SyslogMessage)
        | extend SourceUserName = extract(@"authUser=([^\s;,]+)", 1, SyslogMessage)
        | where isnotempty(SourceIP) and isnotempty(SourceUserName)
        | project TimeGenerated, SourceIP, SourceUserName, HostName
    );
allHits
| join kind=inner (
    allHits
    | project JoinTime = TimeGenerated, JoinSourceIP = SourceIP, JoinSourceUserName = SourceUserName
) on $left.SourceIP == $right.JoinSourceIP
| where JoinTime between (TimeGenerated .. (TimeGenerated + burstWindow))
| summarize
    RequestCount = count(),
    DistinctSenders = dcount(JoinSourceUserName),
    SenderList = make_set(JoinSourceUserName),
    WindowStart = min(TimeGenerated),
    WindowEnd = max(JoinTime),
    HostName = take_any(HostName)
    by SourceIP
| where DistinctSenders >= minDistinctSenders
| extend AlertDetail = "Single source IP submitted SaveDraftRequests for multiple distinct sender identities within 10 minutes - possible CVE-2026-73571 exploitation via Metasploit module"
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Mail relay servers or shared infrastructure where multiple users authenticate from the same source IP and submit SaveDraftRequests.
- Legitimate mail delegation configurations where a single IP submits drafts on behalf of multiple users.
- Automated mail processing systems that generate SaveDraftRequests for multiple identities as part of normal workflow.

**Tuning notes:**
- Run over a 7-day historical window before scheduling to establish baseline SaveDraftRequest volume and confirm minDistinctSenders threshold does not fire on known-good delegation activity.
- Add a SourceIP exclusion list for known mail relay servers and shared infrastructure IPs.
- If the self-join produces performance issues, replace with a summarize-based approach using make_set(SourceUserName) per SourceIP per hour and filter on array_length(SenderSet) >= minDistinctSenders.

**Risks / caveats:**
- CommonSecurityLog DeviceVendor field value for Zimbra is connector-dependent; a mismatch will silently exclude all Zimbra events.
- Syslog regex patterns for SourceIP ('client=\[?([\d\.]+)\]?') and SourceUserName ('authUser=([^\s;,]+)') are format-dependent and must match the deployed Zimbra version's log output.
- If Zimbra does not forward logs to Sentinel via CEF or syslog, both branches will produce no results.
- bin(TimeGenerated, burstWindow) in the original query creates fixed time buckets that will miss bursts spanning a bucket boundary; corrected in hardened query.

### Triage Runbook

**First 15 minutes:**
- Review the source IP, host, request count, and list of targeted sender identities from the alert.
- Check whether the source IP is a known mail relay, shared gateway, or automation host.
- Look for repeated SaveDraftRequest calls in a short window and whether they span multiple identities or only one user.
- Validate the Zimbra log format and confirm the extracted source IP and user fields are accurate.
- If the activity is concentrated, repetitive, and not tied to a known relay or delegation workflow, treat it as suspicious exploitation activity.

**Evidence to collect:**
- The full burst context including WindowStart, WindowEnd, SourceIP, RequestCount, DistinctSenders, and SenderList.
- Raw Zimbra logs for the same source IP and time range to confirm the request pattern.
- Any mail relay, delegation, or automation documentation for the source IP.
- Subsequent mail delivery or draft submission records tied to the same source IP.

**Pivot points:**
- CommonSecurityLog for SaveDraftRequest events from the same SourceIP and multiple SourceUserName values.
- Syslog for SaveDraftRequest entries with authUser and client fields from the same source IP.
- Mail gateway logs to determine whether the source IP is a relay or application server.
- Zimbra audit logs for follow-on actions from the same account or host.

**Benign explanations:**
- A mail relay or shared infrastructure host legitimately handles multiple users.
- A delegated mailbox or service account generates multiple SaveDraftRequest events as part of normal workflow.
- The source IP is a shared NAT address used by many users.
- The alert is caused by a parsing issue or a noisy connector format.

**Escalation criteria:**
- The source IP is not a known relay, shared gateway, or approved automation host.
- The burst includes multiple sender identities with no legitimate business explanation.
- The activity is accompanied by other suspicious Zimbra behavior or successful unauthorized mail actions.
- The pattern repeats across multiple time windows or multiple Zimbra hosts.

**Containment actions:**
- Block the source IP if it is external and not a trusted relay or admin endpoint.
- Suspend the associated account or session if exploitation is confirmed.
- Preserve Zimbra logs and mail traces before making changes.
- Coordinate with messaging administrators to investigate whether the vulnerable endpoint needs immediate mitigation.

**Closure criteria:**
- The source IP is confirmed as a legitimate relay, shared gateway, or approved automation host.
- The burst is explained by normal delegated or service-account behavior.
- No unauthorized sender impersonation or mail abuse is found.
- An exclusion or tuning update has been documented for the approved source.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- CVE-2026-123890 - VMware vCenter Administrator Logon from Previously Unseen Source IP: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent, Syslog before scheduling.
- CVE-2026-73571 - Zimbra Authenticated User Sending Mail as a Different Identity: CommonSecurityLog DeviceVendor field value for Zimbra is connector-dependent; the exact string must match what the deployed Zimbra CEF connector emits. A mismatch will silently exclude all Zimbra events.
- CVE-2026-73571 - Zimbra SaveDraftRequest Authorization Bypass Attempt: CommonSecurityLog DeviceVendor value must be validated against the exact string emitted by the Zimbra CEF connector.

**Other deployment dependency:**
- CVE-2026-123890 - Unauthenticated Network Connection to vCenter Management Port Followed by Admin Session: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Shared-table notes:**
- SecurityEvent: shared by CVE-2026-123890 - VMware vCenter Administrator Logon from Previously Unseen Source IP; CVE-2026-123890 - Unauthenticated Network Connection to vCenter Management Port Followed by Admin Session
- Syslog: shared by CVE-2026-123890 - VMware vCenter Administrator Logon from Previously Unseen Source IP; CVE-2026-73571 - Zimbra Authenticated User Sending Mail as a Different Identity; CVE-2026-73571 - Zimbra SaveDraftRequest Authorization Bypass Attempt
- CommonSecurityLog: shared by CVE-2026-73571 - Zimbra Authenticated User Sending Mail as a Different Identity; CVE-2026-73571 - Zimbra SaveDraftRequest Authorization Bypass Attempt

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Vishing Account Compromise - MFA Change Followed by Cloud Data Bulk Export.
2. Resolve environment-mapping detections next: CVE-2026-123890 - VMware vCenter Administrator Logon from Previously Unseen Source IP; CVE-2026-123890 - Unauthenticated Network Connection to vCenter Management Port Followed by Admin Session; CVE-2026-73571 - Zimbra Authenticated User Sending Mail as a Different Identity; CVE-2026-73571 - Zimbra SaveDraftRequest Authorization Bypass Attempt.

### Hunting Agenda and Promotion Criteria

- CVE-2026-123890 - VMware vCenter Administrator Logon from Previously Unseen Source IP: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent, Syslog before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- CVE-2026-123890 - Unauthenticated Network Connection to vCenter Management Port Followed by Admin Session: Defender for Endpoint file-event coverage must be confirmed on the target host population.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- CVE-2026-73571 - Zimbra Authenticated User Sending Mail as a Different Identity: CommonSecurityLog DeviceVendor field value for Zimbra is connector-dependent; the exact string must match what the deployed Zimbra CEF connector emits. A mismatch will silently exclude all Zimbra events.; baseline expected benign activity and define an alert-volume threshold.
- CVE-2026-73571 - Zimbra SaveDraftRequest Authorization Bypass Attempt: CommonSecurityLog DeviceVendor value must be validated against the exact string emitted by the Zimbra CEF connector.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
