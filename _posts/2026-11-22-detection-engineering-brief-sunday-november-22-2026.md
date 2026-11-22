---
layout: post
title: "Detection Engineering Brief - Sunday, November 22, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-11-22
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - cloud services
  - Webworm
  - SoftEther VPN
  - CVE-2026-123890
  - ARMORY CASTLE
  - T1190
  - VMware vCenter
  - VMware Directory Service
  - CVE-2026-73571
  - Zimbra
  - Metasploit
  - T1213
  - T1537
  - T1547.001
  - T1090.001
  - T1547
  - T1090
  - T1098
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

2 production candidates, 1 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: cloud services, Webworm, SoftEther VPN, CVE-2026-123890, ARMORY CASTLE, T1190, VMware vCenter, VMware Directory Service, CVE-2026-73571, Zimbra, Metasploit, T1213, T1537, T1547.001, T1090.001, T1547, T1090, T1098.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: ARMORY CASTLE - Unauthenticated Network Access to vCenter Followed by Admin-Level Syslog Activity; Zimbra CVE-2026-73571 - Authenticated User Sending Mail as a Different Identity; Webworm - Persistence via Registry Combined with Recurring Outbound Encrypted Tunnel Connections.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Cloud Audit - Bulk Data Access Following Anomalous Authentication

### Detection Opportunity

Bulk cloud data read or export operations performed by recently authenticated accounts originating from anomalous IP addresses, consistent with post-vishing cloud data theft.

### Intelligence Context

- Unit 42: Dialing for Data: Inside the Com's High-Profile Heists — [https://unit42.paloaltonetworks.com/com-affiliate-vishing-attacks/](https://unit42.paloaltonetworks.com/com-affiliate-vishing-attacks/)
  - Context: Threat actors used vishing to compromise cloud accounts and subsequently performed bulk data theft and extortion against healthcare and finance organizations. The detectable downstream signal is high-volume data access or export operations following authentication from previously unseen IP addresses.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1213, T1537
- Products: Not specified
- Platforms: cloud services
- Malware: Not specified
- Tools: Not specified
- Search tags: cloud services, T1213, T1537

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Collection: T1213 Data from Information Repositories (high); Exfiltration: T1537 Transfer Data to Cloud Account (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- SigninLogs, AuditLogs

### KQL

```kql
let lookbackDays = 30d;
let detectionWindow = 1d;
let correlationWindow = 2h;
let bulkOpThreshold = 5;
let knownIPs =
    SigninLogs
    | where TimeGenerated between (ago(lookbackDays) .. ago(detectionWindow))
    | where ResultType == 0
    | where isnotempty(IPAddress)
    | summarize KnownIPs = make_set(tostring(IPAddress)) by UserPrincipalName;
let recentLogins =
    SigninLogs
    | where TimeGenerated > ago(detectionWindow)
    | where ResultType == 0
    | where isnotempty(IPAddress)
    | join kind=leftouter knownIPs on UserPrincipalName
    | where not(tostring(IPAddress) in (KnownIPs))
    | summarize LoginTime = min(TimeGenerated) by UserPrincipalName, AnomalousIP = tostring(IPAddress);
let bulkAuditOps =
    AuditLogs
    | where TimeGenerated > ago(detectionWindow)
    | where OperationName in~ ("Export", "Download", "Get", "List", "Read")
    | extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
    | where isnotempty(ActorUPN)
    | project ActorUPN, OpTime = TimeGenerated, OperationName, TargetResources = tostring(TargetResources), ResultDescription;
recentLogins
| join kind=inner bulkAuditOps on $left.UserPrincipalName == $right.ActorUPN
| where OpTime between (LoginTime .. (LoginTime + correlationWindow))
| summarize
    BulkOpCount = count(),
    Operations = make_set(OperationName),
    Targets = make_set(TargetResources),
    FirstOpTime = min(OpTime),
    LastOpTime = max(OpTime)
    by UserPrincipalName, AnomalousIP, LoginTime
| where BulkOpCount >= bulkOpThreshold
| project
    UserPrincipalName,
    AnomalousIP,
    LoginTime,
    FirstOpTime,
    LastOpTime,
    BulkOpCount,
    Operations,
    Targets
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Administrators performing legitimate bulk exports after logging in from a new corporate IP or VPN endpoint.
- Automated service accounts that authenticate interactively from rotating IPs and perform scheduled data exports.
- Users returning from travel or remote work who authenticate from a new IP and then access large volumes of data normally.

**Tuning notes:**
- Raise bulkOpThreshold above 5 in environments where administrators routinely perform large-scale data operations.
- Narrow OperationName to Export and Download only if Get, List, and Read generate excessive noise from normal application activity.
- Add a UserPrincipalName exclusion list for known service accounts or admin accounts with documented bulk-export workflows.

**Risks / caveats:**
- AuditLogs.InitiatedBy.user.userPrincipalName is a dynamic nested field; if the audit event was initiated by a service principal rather than a user, this field will be empty and those events will be silently dropped. Service-principal-initiated bulk exports will not be detected.
- AuditLogs OperationName values are tenant-specific and depend on which Microsoft 365 or Azure services are in scope. The filter list (Export, Download, Get, List, Read) may match zero events if the environment logs different operation name strings.
- The 30-day IP baseline requires 30 days of SigninLogs retention. If workspace retention is shorter, the baseline will be incomplete and false-positive rates will increase.
- OperationName values in AuditLogs vary by service. The in~ filter list should be validated against actual OperationName values in the tenant before scheduling.

### Triage Runbook

**First 15 minutes:**
- Confirm the sign-in was successful and inspect the anomalous IP, geolocation, ASN, device, and user agent for travel, VPN, or impossible-travel indicators.
- Review the bulk operations list and target resources to understand what data was accessed, exported, or downloaded and whether the volume is unusual for this user.
- Check whether the account is privileged, a service account, or tied to a known admin workflow that could explain the activity.
- Look for immediate follow-on actions such as mailbox rule changes, MFA resets, new OAuth consent, password changes, or additional sign-ins from the same IP.

**Evidence to collect:**
- SigninLogs for the user covering at least 24 hours before and after the alert, including IPAddress, ResultType, location, device, and authentication method.
- AuditLogs entries for the same user and time window, including OperationName, TargetResources, ResultDescription, and any export/download/read activity.
- User identity context: role, department, recent travel, known VPN endpoints, and whether the account is a service or admin account.
- Any correlated identity events such as MFA changes, password resets, consent grants, or suspicious mailbox/SharePoint/OneDrive activity.

**Pivot points:**
- SigninLogs filtered on UserPrincipalName and AnomalousIP to identify other sessions from the same source.
- AuditLogs filtered on the same UserPrincipalName and LoginTime window to enumerate all operations and targets.
- Identity-related logs for MFA registration, password reset, conditional access failures, and consent events.
- If available, cloud app access logs for file download, sharing, or mass export activity tied to the same account.

**Benign explanations:**
- The user legitimately connected from a new corporate VPN, home network, or travel location and performed a planned bulk export.
- An administrator or support engineer used a new workstation or IP to perform a sanctioned data retrieval task.
- An automated service account or integration performed scheduled exports from a rotating IP range.
- The user recently returned from travel or remote work and accessed a large repository as part of normal duties.

**Escalation criteria:**
- The anomalous IP is foreign, hosting/VPN infrastructure, or otherwise inconsistent with the user’s normal access pattern.
- Bulk access includes sensitive repositories, large exports, or data types not normally handled by the user.
- There are additional suspicious identity events such as MFA changes, password resets, new tokens, or repeated sign-ins from the same IP.
- The account is privileged and the activity cannot be clearly tied to an approved administrative change or ticket.

**Containment actions:**
- If compromise is likely, disable the account or force sign-out and revoke active sessions/tokens.
- Reset the password and require MFA re-registration if there is evidence of credential theft or session hijacking.
- Block the anomalous source IP or associated VPN/proxy path if it is clearly malicious and not shared infrastructure.
- Preserve audit and sign-in evidence before making changes.

**Closure criteria:**
- The activity is confirmed as an approved admin or user workflow and matches documented business need.
- The anomalous IP is explained by a known VPN, travel, or corporate egress change and no other suspicious identity activity is present.
- No additional suspicious operations, token abuse, or follow-on access are found in the surrounding time window.
- Any required allowlist or threshold tuning has been documented for future alerts.

<br/>
---
<br/>

## Detection 2: Webworm - SoftEther VPN Process and Network Activity on Endpoint

### Detection Opportunity

Deployment and execution of SoftEther VPN binaries on endpoints, combined with outbound network connections on SoftEther default ports, consistent with Webworm establishing covert tunnels in government networks.

### Intelligence Context

- Rapid7: Spying on Governments with Zero Lines of Malware: A Custom SoftEther Bridge in Webworm's Toolkit — [https://www.rapid7.com/blog/post/tr-spying-on-governments-no-malware-custom-webworms-toolkit-softether-bridge](https://www.rapid7.com/blog/post/tr-spying-on-governments-no-malware-custom-webworms-toolkit-softether-bridge)
  - Context: Webworm deployed SoftEther VPN into compromised government networks using a custom variant with evasion capabilities. The actor used SoftEther to maintain long-term covert remote access. Process execution of SoftEther binaries combined with outbound connections on SoftEther default ports (443, 992, 1194, 5555) are the primary detectable signals.

### Search Metadata

- CVEs: Not specified
- Threat actors: Webworm
- ATT&CK tags: T1547.001, T1090.001, T1547, T1090
- Products: SoftEther VPN
- Platforms: Not specified
- Malware: Not specified
- Tools: SoftEther VPN
- Search tags: Webworm, SoftEther VPN, T1547.001, T1090.001, T1547, T1090

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1547 Boot or Logon Autostart Execution/ T1547.001 Registry Run Keys / Startup Folder (high); Command and Control: T1090 Proxy/ T1090.001 Internal Proxy (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let softEtherPorts = dynamic([443, 992, 1194, 5555]);
let softEtherNames = dynamic(["vpnclient.exe", "vpnserver.exe", "vpncmd.exe", "vpnbridge.exe", "se_bridge.exe"]);
let correlationWindow = 1h;
let lookback = 7d;
let procEvents =
    DeviceProcessEvents
    | where TimeGenerated > ago(lookback)
    | where FileName in~ (softEtherNames)
        or ProcessCommandLine has_any ("SoftEther", "vpnclient", "vpnserver", "vpncmd", "vpnbridge")
    | summarize
        ProcTime = min(TimeGenerated),
        FileName = take_any(FileName),
        ProcessCommandLine = take_any(ProcessCommandLine),
        FolderPath = take_any(FolderPath),
        InitiatingProcessFileName = take_any(InitiatingProcessFileName),
        AccountName = take_any(AccountName),
        DeviceName = take_any(DeviceName)
        by DeviceId;
let netEvents =
    DeviceNetworkEvents
    | where TimeGenerated > ago(lookback)
    | where RemotePort in (softEtherPorts)
    | where (RemoteIPType == "Public") or (isempty(RemoteIPType) and not(ipv4_is_private(RemoteIP)))
    | project DeviceId, NetTime = TimeGenerated, RemoteIP, RemotePort, NetInitiatingProcess = InitiatingProcessFileName;
procEvents
| join kind=inner netEvents on DeviceId
| where NetTime between (ProcTime .. (ProcTime + correlationWindow))
| summarize
    FirstSeen = min(ProcTime),
    NetConnections = count(),
    RemoteIPs = make_set(RemoteIP),
    RemotePorts = make_set(RemotePort)
    by DeviceId, DeviceName, AccountName, FileName, ProcessCommandLine, FolderPath, InitiatingProcessFileName
| project
    DeviceId,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    FolderPath,
    InitiatingProcessFileName,
    FirstSeen,
    NetConnections,
    RemoteIPs,
    RemotePorts
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate SoftEther VPN deployments in environments that use it for authorized remote access.
- Security research or red team exercises using SoftEther tooling.
- Port 443 outbound connections from SoftEther processes may overlap with legitimate HTTPS traffic if the process name matches but the binary is unrelated.

**Tuning notes:**
- Remove port 443 from softEtherPorts if HTTPS traffic volume causes false positives; ports 992, 1194, and 5555 are higher-fidelity SoftEther indicators.
- Reduce correlationWindow from 1h to 30m if high process churn inflates correlation matches.
- Add a FolderPath exclusion for known legitimate SoftEther installation paths if authorized deployments exist in the environment.

**Risks / caveats:**
- RemoteIPType is not guaranteed to be populated in all Defender XDR tenants or for all network event types. If absent, the public IP filter will silently drop all network events. The improved KQL includes an ipv4_is_private() fallback to handle this.
- Port 443 in softEtherPorts will match any outbound HTTPS connection from a process with a SoftEther-like name. If legitimate software shares a binary name, false positives will occur on port 443 specifically.
- Webworm's custom SoftEther variant may use entirely different binary names not covered by the FileName or ProcessCommandLine filters.
- The 7-day lookback may miss persistent implants installed before the window. Extending to 14 or 30 days increases coverage but also query cost.

### Triage Runbook

**First 15 minutes:**
- Validate the process name, command line, folder path, and parent process to determine whether the binary is a legitimate installation or a renamed tool.
- Check whether the device has an approved SoftEther deployment or any sanctioned remote-access software that could explain the activity.
- Review the remote IPs and ports for public exposure, rarity, and whether the connections are persistent or repeated.
- Look for adjacent signs of compromise such as new services, scheduled tasks, registry persistence, or suspicious logon activity on the same host.

**Evidence to collect:**
- DeviceProcessEvents for the host, including FileName, ProcessCommandLine, FolderPath, InitiatingProcessFileName, AccountName, and first-seen time.
- DeviceNetworkEvents for the same host, including RemoteIP, RemotePort, RemoteIPType, and initiating process details.
- File reputation and hash information for the SoftEther-related binary if available from endpoint telemetry or EDR file inventory.
- Host context showing whether the device is a server, admin workstation, or user endpoint and whether remote-access software is expected.

**Pivot points:**
- DeviceProcessEvents for the same DeviceId to find other SoftEther-related executions or parent/child process chains.
- DeviceNetworkEvents for the same DeviceId and RemoteIPs to identify additional tunnel endpoints or repeated connections.
- DeviceFileEvents or file inventory to determine when the binary appeared and whether it was dropped recently.
- DeviceLogonEvents or identity logs to check for suspicious interactive logons around the same time.

**Benign explanations:**
- SoftEther is legitimately installed for authorized remote access or lab use.
- A security team or administrator is running a sanctioned test, proof-of-concept, or remote support session.
- The process name matches a legitimate binary used by approved software, and the network traffic is expected management traffic.
- The host is a jump box or remote-access server where SoftEther-like activity is normal and documented.

**Escalation criteria:**
- The binary is running from an unusual path such as user profile, temp, downloads, or another non-standard location.
- The remote IPs are rare, external, and not associated with approved infrastructure.
- The process is unsigned, recently dropped, or launched by an unexpected parent process.
- There are additional signs of persistence, credential theft, or lateral movement on the same host.

**Containment actions:**
- If unauthorized, isolate the endpoint from the network to stop tunnel traffic and preserve evidence.
- Terminate the suspicious process and quarantine the binary if EDR supports safe containment.
- Block the remote IPs or ports only after confirming they are not shared legitimate infrastructure.
- Preserve process, network, and file artifacts before remediation.

**Closure criteria:**
- The SoftEther activity is confirmed as authorized and matches a documented deployment or test.
- The binary path, parent process, and remote endpoints are consistent with approved software behavior.
- No additional suspicious persistence or remote-access indicators are found on the host.
- Any approved exception or allowlist entry has been recorded.

<br/>
---
<br/>

## Detection 3: ARMORY CASTLE - Unauthenticated Network Access to vCenter Followed by Admin-Level Syslog Activity

### Detection Opportunity

Network connections to vCenter management ports from unexpected sources correlated with subsequent administrator-level session creation events in syslog, consistent with CVE-2026-123890 authentication bypass exploitation by ARMORY CASTLE.

### Intelligence Context

- Rapid7: CVE-2026-123890: Critical Authentication Bypass in VMware vCenter — [https://www.rapid7.com/blog/post/etr-cve-2026-123890-critical-authentication-bypass-vmware-vcenter](https://www.rapid7.com/blog/post/etr-cve-2026-123890-critical-authentication-bypass-vmware-vcenter)
  - Context: ARMORY CASTLE exploited CVE-2026-123890 to bypass vCenter authentication without credentials and gain unauthorized Administrator access. The attack originates from network-accessible sources against vCenter management ports and results in admin-level session creation detectable in vCenter syslog output.

### Search Metadata

- CVEs: CVE-2026-123890
- Threat actors: ARMORY CASTLE
- ATT&CK tags: T1190
- Products: VMware vCenter, VMware Directory Service
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-123890, ARMORY CASTLE, T1190, VMware vCenter, VMware Directory Service

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.

**Required telemetry:**
- CommonSecurityLog, Syslog

### KQL

```kql
let vcenterPorts = dynamic([443, 9443]);
let lookback = 30d;
let detectionWindow = 1d;
let correlationWindow = 30m;
// Operators must populate vCenterHosts with the IP addresses of vCenter servers in this environment.
let vCenterHosts = dynamic([]);
let knownSources =
    CommonSecurityLog
    | where TimeGenerated between (ago(lookback) .. ago(detectionWindow))
    | where DestinationPort in (vcenterPorts)
    | where DestinationIP in (vCenterHosts)
    | summarize KnownSources = make_set(SourceIP) by DestinationIP;
let newAccess =
    CommonSecurityLog
    | where TimeGenerated > ago(detectionWindow)
    | where DestinationPort in (vcenterPorts)
    | where DestinationIP in (vCenterHosts)
    | join kind=leftouter knownSources on DestinationIP
    | where not(SourceIP in (KnownSources))
    | project SourceIP, DestinationIP, AccessTime = TimeGenerated, DestinationPort, DeviceAction;
let adminSyslog =
    Syslog
    | where TimeGenerated > ago(detectionWindow)
    | where ProcessName has_any ("vpxd", "vmdir", "vmafd")
    | where SyslogMessage has_any ("Administrator", "admin", "session created", "login succeeded", "authenticated")
    | project SyslogTime = TimeGenerated, Computer, SyslogMessage, ProcessName;
newAccess
| join kind=inner adminSyslog on $left.DestinationIP == $right.Computer
| where SyslogTime between (AccessTime .. (AccessTime + correlationWindow))
| project
    SourceIP,
    DestinationIP,
    AccessTime,
    DestinationPort,
    DeviceAction,
    SyslogTime,
    Computer,
    ProcessName,
    SyslogMessage
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrators accessing vCenter from a new workstation or IP after a network change.
- Automated monitoring or backup tools that connect to vCenter management ports from IPs not previously seen.
- vCenter upgrades or migrations that introduce new source IPs for management traffic.

**Tuning notes:**
- If Syslog.Computer contains hostnames, add a DNS lookup table or use a let statement mapping vCenter hostnames to IPs and join on that instead of DestinationIP.
- Extend the lookback window beyond 30 days if vCenter management access is infrequent and the baseline is too sparse.
- Restrict SyslogMessage keywords further to specific vCenter audit event strings observed in the environment to reduce matches from unrelated processes.

**Risks / caveats:**
- CommonSecurityLog.DestinationIP and Syslog.Computer represent the same vCenter host in different formats (IP vs. hostname). The join will produce zero results unless the environment resolves this mismatch via a hostname-to-IP lookup table, a DNS log join, or by configuring syslog forwarding to populate Computer with the IP address.
- CommonSecurityLog is populated only if a firewall or network device is configured to forward traffic logs to Sentinel via the CEF connector. If no such device logs traffic to vCenter management ports, CommonSecurityLog will have no relevant rows.
- Syslog ingestion of vCenter output requires explicit syslog forwarding configuration from vCenter to the Sentinel Log Analytics workspace or a syslog forwarder. If not configured, the Syslog table will contain no vCenter events.
- The vCenterHosts dynamic list must be populated with actual vCenter IP addresses before this query will return any results. It is the primary environment-specific dependency.

### Triage Runbook

**First 15 minutes:**
- Confirm the source IP, destination vCenter host, and destination port to determine whether the access came from an unexpected or external source.
- Review the correlated syslog message for evidence of administrator session creation, login success, or other privileged actions.
- Check whether the source IP is a known management workstation, backup system, monitoring tool, or approved admin network.
- Assess whether the timing and sequence indicate unauthenticated access followed by privileged activity rather than normal administrative use.

**Evidence to collect:**
- CommonSecurityLog entries for the source IP, destination IP, destination port, and device action around the alert time.
- Syslog entries from the vCenter host, including the full message, process name, and timestamps.
- vCenter audit or authentication logs if available, including admin session creation, user creation, role changes, and login events.
- Asset inventory or CMDB data showing the expected management sources for the vCenter environment.

**Pivot points:**
- CommonSecurityLog filtered on the destination vCenter IP and source IP to identify other access attempts or repeated connections.
- Syslog filtered on the vCenter host and process names such as vpxd, vmdir, and vmafd for surrounding admin activity.
- Any available vCenter audit logs for role changes, account creation, or privilege escalation.
- Firewall or proxy logs to determine whether the source IP is external, internal, or part of a known management segment.

**Benign explanations:**
- A legitimate administrator accessed vCenter from a new workstation or after a network change.
- Monitoring, backup, or automation tooling connected from a previously unseen source IP.
- A vCenter migration, upgrade, or infrastructure change introduced new management sources.
- The syslog event reflects normal administrative activity rather than exploitation.

**Escalation criteria:**
- The source IP is external, unrecognized, or not part of approved management infrastructure.
- The syslog shows administrator session creation or privileged actions that cannot be tied to a known admin.
- There are signs of account creation, role changes, or other post-exploitation activity in vCenter.
- Multiple access attempts or repeated privileged events occur from the same unexpected source.

**Containment actions:**
- If exploitation is likely, restrict network access to vCenter management ports from the suspicious source or segment.
- Disable or rotate credentials for any accounts suspected of being used in the attack.
- Preserve vCenter and firewall logs before making changes.
- Coordinate with virtualization administrators before restarting or modifying vCenter services.

**Closure criteria:**
- The source is confirmed as an approved management system or administrator.
- The syslog activity is validated as normal administrative behavior with no unauthorized changes.
- No additional suspicious vCenter logins, role changes, or account modifications are found.
- The environment-specific mapping for vCenter host identification is documented and working as intended.

<br/>
---
<br/>

## Detection 4: Zimbra CVE-2026-73571 - Authenticated User Sending Mail as a Different Identity

### Detection Opportunity

Mail messages delivered where the envelope sender address differs from the authenticated session user with no delegation configured, consistent with exploitation of the Zimbra SaveDraftRequest authorization bypass.

### Intelligence Context

- Rapid7: Metasploit Wrap Up: Breaking Zimbra's Identity Boundaries — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-breaking-zimbra-s-identity-boundaries](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-breaking-zimbra-s-identity-boundaries)
  - Context: CVE-2026-73571 allows an ordinary authenticated Zimbra user to send mail as another user by abusing an authorization bypass in SaveDraftRequest SOAP handling. The high-fidelity signal is a mismatch between the authenticated session identity and the envelope sender in mail delivery logs, absent any configured send-as delegation.

### Search Metadata

- CVEs: CVE-2026-73571
- Threat actors: Not specified
- ATT&CK tags: T1190, T1098
- Products: Zimbra
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-73571, Zimbra, Metasploit, T1190, T1098

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium); Persistence: T1098 Account Manipulation (low)

### Deployment Gates

- Zimbra MTA syslog must be explicitly forwarded to the Sentinel Log Analytics workspace. There is no built-in Zimbra connector. If syslog forwarding is not configured, the Syslog table will contain no Zimbra MTA events and the query will return zero results.

**Required telemetry:**
- Syslog

### KQL

```kql
let lookback = 7d;
Syslog
| where TimeGenerated > ago(lookback)
| where ProcessName has_any ("postfix", "zimbra", "zmmtactl", "zmlogger")
| where SyslogMessage has "sasl_username" and SyslogMessage has "from="
| extend
    EnvelopeFrom = extract(@"from=<([^>]+)>", 1, SyslogMessage),
    AuthUser = extract(@"sasl_username=([^,\s]+)", 1, SyslogMessage),
    ClientIP = extract(@"client=[^\[]*\[([^\]]+)\]", 1, SyslogMessage)
| where isnotempty(EnvelopeFrom) and isnotempty(AuthUser)
| where tolower(EnvelopeFrom) != tolower(AuthUser)
| summarize
    MismatchCount = count(),
    EnvelopeSenders = make_set(EnvelopeFrom),
    SourceIPs = make_set(ClientIP),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by AuthUser, HostName
| where MismatchCount >= 1
| project
    AuthUser,
    HostName,
    MismatchCount,
    EnvelopeSenders,
    SourceIPs,
    FirstSeen,
    LastSeen
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Configured send-as delegation accounts where one user is authorized to send as another. These will appear as mismatches and must be suppressed via an allowlist during triage.
- Shared mailbox configurations where multiple users authenticate and send from a common address.
- Mail relay or forwarding configurations where the envelope sender is rewritten by the MTA.

**Tuning notes:**
- Create a Sentinel watchlist of known send-as delegation pairs and add a where AuthUser !in (watchlist) filter to suppress legitimate matches before scheduling.
- Raise MismatchCount above 1 if delivery retries cause duplicate log entries for the same send event.
- Add a filter where EnvelopeDomain != AuthDomain to focus on cross-domain impersonation, which is higher fidelity for CVE-2026-73571 abuse.

**Risks / caveats:**
- Zimbra MTA syslog must be explicitly forwarded to the Sentinel Log Analytics workspace. There is no built-in Zimbra connector. If syslog forwarding is not configured, the Syslog table will contain no Zimbra MTA events and the query will return zero results.
- The sasl_username field in SyslogMessage is present only when Postfix is configured with SASL authentication logging enabled. If Zimbra's MTA is configured differently, this field may be absent and the extract will return empty strings, causing all rows to be dropped by the isnotempty filter.
- The from= field in SyslogMessage reflects the Postfix envelope sender log format. Zimbra versions or configurations that use a different MTA or log format may not produce this field.
- Without an inline delegation allowlist, all configured send-as delegation accounts will appear as matches. Analysts must manually suppress known-legitimate delegations during triage until a watchlist is created.

### Triage Runbook

**First 15 minutes:**
- Verify the authenticated user, envelope sender, and host to confirm the mismatch and identify the affected mailbox or domain.
- Check whether the user has approved send-as or delegation rights that would explain the sender mismatch.
- Review the message content, recipients, and timing to determine whether the mail was part of a phishing, fraud, or impersonation campaign.
- Look for repeated mismatches from the same account or host, which increases confidence in abuse.

**Evidence to collect:**
- Zimbra/Postfix syslog entries showing sasl_username, from=, client IP, and the full delivery context.
- Mailbox or delegation configuration for the authenticated user and the sender identity involved.
- Message metadata such as recipients, subject, and whether the message was internal or external.
- Any related authentication logs showing the client IP, session timing, and repeated use of the same account.

**Pivot points:**
- Syslog filtered on the same AuthUser and HostName to find additional sender mismatches or repeated delivery attempts.
- Mailbox administration or directory data to confirm whether send-as delegation exists for the involved identities.
- Mail flow logs to identify recipients and whether the same sender identity was used elsewhere.
- Authentication logs for the same client IP to determine whether the session is normal or suspicious.

**Benign explanations:**
- The user has a legitimate send-as delegation, shared mailbox, or alias configuration.
- Mail relay or forwarding behavior rewrote the envelope sender in a way that appears mismatched.
- A service or shared account is used by multiple authorized users.
- The mismatch is caused by a known Zimbra or Postfix logging format quirk rather than abuse.

**Escalation criteria:**
- No approved delegation or alias exists for the sender mismatch.
- The message was sent to external recipients or contains phishing, fraud, or impersonation content.
- The same account shows repeated mismatches or unusual client IPs.
- There is evidence of broader mailbox abuse, suspicious login activity, or unauthorized configuration changes.

**Containment actions:**
- If abuse is likely, suspend the account or block outbound mail temporarily while investigating.
- Reset credentials and revoke active sessions if the account appears compromised.
- Coordinate with messaging administrators to stop further impersonation from the affected mailbox.
- Preserve mail logs and message samples before remediation.

**Closure criteria:**
- A legitimate delegation, alias, or shared-mailbox workflow explains the mismatch.
- The message flow is consistent with approved mail routing or relay behavior.
- No repeated unauthorized sender mismatches or suspicious authentication activity are present.
- Any required allowlist for known send-as pairs has been documented.

<br/>
---
<br/>

## Detection 5: Webworm - Persistence via Registry Combined with Recurring Outbound Encrypted Tunnel Connections

### Detection Opportunity

Registry-based persistence entries created by an unusual process combined with recurring outbound network connections to rare external IPs, consistent with Webworm maintaining long-term covert remote access via a custom SoftEther-based tool.

### Intelligence Context

- Rapid7: Spying on Governments with Zero Lines of Malware: A Custom SoftEther Bridge in Webworm's Toolkit — [https://www.rapid7.com/blog/post/tr-spying-on-governments-no-malware-custom-webworms-toolkit-softether-bridge](https://www.rapid7.com/blog/post/tr-spying-on-governments-no-malware-custom-webworms-toolkit-softether-bridge)
  - Context: Webworm used a custom SoftEther-based tool with evasion capabilities to maintain long-term covert access in government networks. Persistence mechanisms and recurring encrypted outbound connections to rare external IPs are the detectable artifacts of this sustained access pattern.

### Search Metadata

- CVEs: Not specified
- Threat actors: Webworm
- ATT&CK tags: T1547.001, T1090.001, T1547, T1090
- Products: SoftEther VPN
- Platforms: Not specified
- Malware: Not specified
- Tools: SoftEther VPN
- Search tags: Webworm, SoftEther VPN, T1547.001, T1090.001, T1547, T1090

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1547 Boot or Logon Autostart Execution/ T1547.001 Registry Run Keys / Startup Folder (high); Command and Control: T1090 Proxy/ T1090.001 Internal Proxy (high)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceRegistryEvents, DeviceNetworkEvents

### KQL

```kql
let tunnelPorts = dynamic([992, 1194, 5555]);
let persistenceKeys = dynamic([
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services"
]);
let suspiciousProcs = dynamic(["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"]);
let lookback = 14d;
let minConnections = 3;
let persistenceEvents =
    DeviceRegistryEvents
    | where TimeGenerated > ago(lookback)
    | where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
    | where RegistryKey has_any (persistenceKeys)
    | where InitiatingProcessFileName in~ (suspiciousProcs)
    | project
        DeviceId,
        DeviceName,
        AccountName,
        PersistTime = TimeGenerated,
        RegistryKey,
        RegistryValueName,
        InitiatingProcessFileName;
let recurringConnections =
    DeviceNetworkEvents
    | where TimeGenerated > ago(lookback)
    | where RemotePort in (tunnelPorts)
    | where (RemoteIPType == "Public") or (isempty(RemoteIPType) and not(ipv4_is_private(RemoteIP)))
    | summarize
        ConnectionCount = count(),
        FirstConn = min(TimeGenerated),
        LastConn = max(TimeGenerated)
        by DeviceId, RemoteIP, RemotePort
    | where ConnectionCount >= minConnections;
persistenceEvents
| join kind=inner recurringConnections on DeviceId
| where FirstConn >= PersistTime
| project
    DeviceId,
    DeviceName,
    AccountName,
    PersistTime,
    RegistryKey,
    RegistryValueName,
    InitiatingProcessFileName,
    RemoteIP,
    RemotePort,
    ConnectionCount,
    FirstConn,
    LastConn
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate software installers that use cmd.exe or powershell.exe to write Run key entries during installation.
- IT management tools that use mshta.exe or rundll32.exe to configure startup entries.
- Authorized VPN clients that make recurring connections on ports 992 or 1194.
- Software update mechanisms that write RunOnce keys and subsequently connect to update servers.

**Tuning notes:**
- Increase minConnections above 3 if legitimate VPN or update traffic on ports 992, 1194, or 5555 generates excessive matches.
- Expand suspiciousProcs to include additional living-off-the-land binaries observed in the environment, or narrow it to only the most anomalous initiating processes.
- Add a RegistryValueName or RegistryValueData filter to focus on persistence entries that reference unusual binary paths or names consistent with SoftEther tooling.
- Consider adding a companion detection for scheduled task creation by the same initiating processes to broaden persistence coverage.

**Risks / caveats:**
- RemoteIPType is not guaranteed to be populated in all Defender XDR tenants. The improved KQL includes an ipv4_is_private() fallback.
- DeviceRegistryEvents ActionType values RegistryValueSet and RegistryKeyCreated must be confirmed as valid in the tenant. Some Defender XDR schema versions use different ActionType strings for registry operations.
- The suspiciousProcs list is broad. cmd.exe and powershell.exe write Run keys during many legitimate administrative and software installation operations. This detection will require significant analyst triage to distinguish malicious from benign matches.
- ConnectionCount threshold of 3 over a 14-day window is a low bar. Legitimate VPN clients or update services may exceed this threshold on the monitored ports.

### Triage Runbook

**First 15 minutes:**
- Inspect the registry key, value name, and initiating process to determine whether the persistence entry is expected or suspicious.
- Review the remote IP, port, and connection frequency to assess whether the traffic resembles a persistent tunnel or normal VPN/update behavior.
- Check whether the host is a server, admin workstation, or endpoint where VPN clients or startup entries are authorized.
- Look for additional compromise indicators such as suspicious logons, new services, scheduled tasks, or unusual parent-child process chains.

**Evidence to collect:**
- DeviceRegistryEvents showing the exact registry path, value name, initiating process, and any available value data.
- DeviceNetworkEvents showing remote IPs, ports, first and last connection times, and connection counts.
- Process lineage and command line for the initiating process that wrote the persistence entry.
- Host context and software inventory to determine whether VPN or remote-access tooling is approved on the device.

**Pivot points:**
- DeviceRegistryEvents for the same DeviceId to find other persistence writes or repeated registry modifications.
- DeviceNetworkEvents for the same DeviceId and RemoteIP to identify additional tunnel endpoints or longer-lived sessions.
- DeviceProcessEvents to inspect the parent process and any related binaries dropped around the same time.
- DeviceLogonEvents or identity logs to check for suspicious interactive logons or remote sessions on the host.

**Benign explanations:**
- A legitimate installer or updater wrote Run or RunOnce entries and then connected to update infrastructure.
- An authorized VPN client or remote-access tool is installed on the host and uses the monitored ports.
- IT administration tools used a scripting host to configure startup behavior during a sanctioned change.
- The host is a managed system where recurring outbound connections are expected and documented.

**Escalation criteria:**
- The registry entry points to an unusual path, user profile, temp directory, or unknown binary.
- The remote IPs are rare, external, and not associated with approved infrastructure.
- The initiating process is a living-off-the-land binary used in an unexpected context.
- There are signs of persistence plus active remote access on a system that should not host such tooling.

**Containment actions:**
- If unauthorized, isolate the host to stop the tunnel and preserve evidence.
- Remove or disable the suspicious persistence entry only after evidence capture.
- Terminate the associated process and quarantine related binaries if supported by EDR.
- Block the remote IPs or ports if they are confirmed malicious and not shared infrastructure.

**Closure criteria:**
- The registry change and network traffic are confirmed as part of an approved installation or remote-access workflow.
- The persistence path, initiating process, and remote endpoints match documented software behavior.
- No additional suspicious persistence mechanisms or lateral movement indicators are found.
- Any approved exception or tuning adjustment has been recorded for future alerts.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- ARMORY CASTLE - Unauthenticated Network Access to vCenter Followed by Admin-Level Syslog Activity: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.
- Zimbra CVE-2026-73571 - Authenticated User Sending Mail as a Different Identity: Zimbra MTA syslog must be explicitly forwarded to the Sentinel Log Analytics workspace. There is no built-in Zimbra connector. If syslog forwarding is not configured, the Syslog table will contain no Zimbra MTA events and the query will return zero results.

**Schema / correlation keys:**
- Webworm - Persistence via Registry Combined with Recurring Outbound Encrypted Tunnel Connections: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- DeviceNetworkEvents: shared by Webworm - SoftEther VPN Process and Network Activity on Endpoint; Webworm - Persistence via Registry Combined with Recurring Outbound Encrypted Tunnel Connections
- Syslog: shared by ARMORY CASTLE - Unauthenticated Network Access to vCenter Followed by Admin-Level Syslog Activity; Zimbra CVE-2026-73571 - Authenticated User Sending Mail as a Different Identity

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Cloud Audit - Bulk Data Access Following Anomalous Authentication; Webworm - SoftEther VPN Process and Network Activity on Endpoint.
2. Resolve environment-mapping detections next: ARMORY CASTLE - Unauthenticated Network Access to vCenter Followed by Admin-Level Syslog Activity; Zimbra CVE-2026-73571 - Authenticated User Sending Mail as a Different Identity.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Webworm - Persistence via Registry Combined with Recurring Outbound Encrypted Tunnel Connections.

### Hunting Agenda and Promotion Criteria

- Webworm - Persistence via Registry Combined with Recurring Outbound Encrypted Tunnel Connections: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- ARMORY CASTLE - Unauthenticated Network Access to vCenter Followed by Admin-Level Syslog Activity: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Zimbra CVE-2026-73571 - Authenticated User Sending Mail as a Different Identity: Zimbra MTA syslog must be explicitly forwarded to the Sentinel Log Analytics workspace. There is no built-in Zimbra connector. If syslog forwarding is not configured, the Syslog table will contain no Zimbra MTA events and the query will return zero results.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
