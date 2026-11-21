---
layout: post
title: "Detection Engineering Brief - Saturday, November 21, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-11-21
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-123890
  - ARMORY CASTLE
  - T1190
  - VMware vCenter
  - VMware Directory Service
  - Webworm
  - SoftEther VPN
  - CVE-2026-73571
  - Zimbra
  - Metasploit
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

0 production candidates, 2 hunting-only, 3 require environment mapping, and 0 rejected.

5 detections include KQL. 3 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-123890, ARMORY CASTLE, T1190, VMware vCenter, VMware Directory Service, Webworm, SoftEther VPN, CVE-2026-73571, Zimbra, Metasploit.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: CVE-2026-123890 - vCenter Auth Bypass Followed by Administrator Session from Novel IP; Webworm - SoftEther VPN Deployment on Endpoints Without Authorized VPN Software; Webworm - Persistent Low-Frequency Outbound Connections on Non-Standard VPN Ports; CVE-2026-73571 - Zimbra SaveDraftRequest Sender Impersonation via Authorization Bypass; CVE-2026-73571 - Metasploit Exploitation Pattern Against Zimbra SOAP Endpoint.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: CVE-2026-123890 - vCenter Auth Bypass Followed by Administrator Session from Novel IP

### Detection Opportunity

Unauthenticated bypass of vCenter authentication followed by Administrator-level session from a source IP with no prior authenticated history.

### Intelligence Context

- Rapid7: CVE-2026-123890: Critical Authentication Bypass in VMware vCenter — [https://www.rapid7.com/blog/post/etr-cve-2026-123890-critical-authentication-bypass-vmware-vcenter](https://www.rapid7.com/blog/post/etr-cve-2026-123890-critical-authentication-bypass-vmware-vcenter)
  - Context: Rapid7 and Mandiant confirmed in-the-wild exploitation where a network-accessible attacker bypasses vCenter authentication without credentials and gains Administrator-level access. The compound behavior of auth failures followed by a successful Administrator session from the same novel IP is the core detection signal.

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

- CommonSecurityLog DeviceProduct values for vCenter syslog forwarding are not standardized; 'vCenter' and 'VMware' are assumed values that must be confirmed in the environment before the query returns results.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
let lookbackDays = 30d;
let correlationWindow = 1h;
let knownAdminIPs =
    CommonSecurityLog
    | where TimeGenerated > ago(lookbackDays)
    | where DeviceProduct has_any ("vCenter", "VMware")
    | where Activity has_any ("login", "authentication", "session")
    | where EventOutcome =~ "success"
    | where DestinationUserName =~ "Administrator"
    | where isnotempty(SourceIP)
    | summarize by SourceIP;
let authFailures =
    CommonSecurityLog
    | where TimeGenerated > ago(1d)
    | where DeviceProduct has_any ("vCenter", "VMware")
    | where Activity has_any ("login", "authentication")
    | where EventOutcome =~ "failure"
    | where isnotempty(SourceIP)
    | summarize
        FailureCount = count(),
        FirstFailure = min(TimeGenerated)
        by SourceIP;
let adminSuccess =
    CommonSecurityLog
    | where TimeGenerated > ago(1d)
    | where DeviceProduct has_any ("vCenter", "VMware")
    | where Activity has_any ("login", "authentication", "session")
    | where EventOutcome =~ "success"
    | where DestinationUserName =~ "Administrator"
    | where isnotempty(SourceIP)
    | project SuccessTime = TimeGenerated, SourceIP, DestinationUserName, DeviceName;
authFailures
| join kind=inner adminSuccess on SourceIP
| where SuccessTime between (FirstFailure .. (FirstFailure + correlationWindow))
| where SourceIP !in (knownAdminIPs)
| project
    SourceIP,
    DestinationUserName,
    DeviceName,
    FailureCount,
    FirstFailure,
    SuccessTime,
    AlertDetail = strcat("Auth bypass pattern: ", FailureCount, " failures then Administrator success from ", SourceIP)
| order by SuccessTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate Administrator logins from new corporate egress IPs or VPN endpoints that have not previously authenticated within the 30-day lookback window.
- Scheduled automation or monitoring accounts that authenticate as Administrator from rotating infrastructure IPs.
- First-time logins following a network infrastructure change that introduces new source IPs for existing administrators.

**Tuning notes:**
- Confirm DeviceProduct values in CommonSecurityLog for vCenter events before deployment: CommonSecurityLog → where DeviceProduct has_any ('vCenter','VMware') → summarize count() by DeviceProduct → take 20.
- Confirm EventOutcome values used in vCenter log events: CommonSecurityLog → where DeviceProduct has_any ('vCenter','VMware') → summarize count() by EventOutcome → take 20.
- Update DestinationUserName filter from 'Administrator' to the actual privileged account name used in the vCenter deployment.
- Adjust correlationWindow from 1h to 4h if exploitation attempts in the environment span longer reconnaissance periods.

**Risks / caveats:**
- CommonSecurityLog DeviceProduct values for vCenter syslog forwarding are not standardized; 'vCenter' and 'VMware' are assumed values that must be confirmed in the environment before the query returns results.
- EventOutcome field population depends on the syslog connector and CEF mapping configuration for vCenter; if EventOutcome is empty or uses non-standard values, both the failure and success branches will return no results.
- DestinationUserName field may not be populated for vCenter authentication events depending on the CEF field mapping used by the syslog forwarder.
- The 30-day knownAdminIPs lookback will produce an empty exclusion set if vCenter log forwarding was recently configured, causing elevated alert volume during the initial baselining period.

### Triage Runbook

**First 15 minutes:**
- Validate the source IP against VPN, jump host, and known admin egress records; treat any truly novel IP as suspicious.
- Check whether the Administrator session was followed by privilege changes, VM inventory access, account creation, snapshot/export actions, or other vCenter admin activity.
- Review the first failure and success timestamps to confirm the sequence is consistent with bypass behavior rather than a normal login retry pattern.
- Identify whether the affected vCenter instance is internet-facing or reachable from untrusted networks and whether other failed logins occurred from the same IP.

**Evidence to collect:**
- Source IP, first failure time, success time, and count of failures preceding success.
- vCenter authentication and session logs around the alert window, including any admin actions performed after login.
- Account context for the Administrator session, including source host, user agent if available, and any concurrent sessions.
- Network telemetry showing whether the source IP connected directly to vCenter or through a proxy/VPN.

**Pivot points:**
- CommonSecurityLog for the same SourceIP over the prior 24 hours and 30 days to identify other vCenter activity.
- CommonSecurityLog for the same DestinationUserName to find additional source IPs or repeated admin sessions.
- vCenter audit or syslog sources for actions performed by the Administrator account after the success time.
- Firewall/proxy logs for inbound connections to the vCenter management interface from the source IP.

**Benign explanations:**
- A legitimate administrator used a new VPN or corporate egress IP that has not previously authenticated within the lookback window.
- A scheduled automation or monitoring account is using the Administrator account from rotating infrastructure.
- A recent network change introduced a new NAT or proxy path for a known administrator.
- The alert is caused by incomplete or inconsistent CEF mapping of vCenter authentication events.

**Escalation criteria:**
- The source IP is not associated with any approved admin, VPN, or automation path.
- The Administrator session is followed by sensitive vCenter actions such as privilege changes, snapshot/export operations, or creation of new accounts.
- There are multiple failed attempts followed by success from the same IP across more than one vCenter host or management endpoint.
- Evidence suggests the vCenter instance is exposed to the internet or was accessed from an external address.

**Containment actions:**
- Disable or reset the affected Administrator account if unauthorized use is confirmed or strongly suspected.
- Block the source IP at perimeter controls and any upstream proxy or VPN termination points.
- Terminate active vCenter sessions associated with the suspicious source IP if the platform supports session revocation.
- Increase monitoring on vCenter and adjacent identity systems for additional admin logins or configuration changes.

**Closure criteria:**
- The source IP is confirmed as an approved admin/VPN/automation endpoint and the session is explained by a documented change or maintenance activity.
- No suspicious post-login administrative actions are found in the alert window.
- The event is attributable to logging or field-mapping issues rather than a real auth bypass pattern.
- Any required compensating controls or allowlist updates have been documented and approved.

<br/>
---
<br/>

## Detection 2: Webworm - SoftEther VPN Deployment on Endpoints Without Authorized VPN Software

### Detection Opportunity

SoftEther VPN process execution and outbound network connections to known SoftEther default ports on endpoints where SoftEther is not an authorized tool, consistent with Webworm covert tunnel deployment.

### Intelligence Context

- Rapid7: Spying on Governments with Zero Lines of Malware: A Custom SoftEther Bridge in Webworm's Toolkit — [https://www.rapid7.com/blog/post/tr-spying-on-governments-no-malware-custom-webworms-toolkit-softether-bridge](https://www.rapid7.com/blog/post/tr-spying-on-governments-no-malware-custom-webworms-toolkit-softether-bridge)
  - Context: Rapid7 reported that Webworm deploys SoftEther VPN into compromised government networks using a custom variant that hides from security tools. The actor uses SoftEther to maintain long-term covert access. Detection targets process execution of SoftEther binaries correlated with outbound connections on SoftEther default ports.

### Search Metadata

- CVEs: Not specified
- Threat actors: Webworm
- ATT&CK tags: Not specified
- Products: SoftEther VPN
- Platforms: Not specified
- Malware: Not specified
- Tools: SoftEther VPN
- Search tags: Webworm, SoftEther VPN

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Not mapped

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let softEtherPorts = dynamic([443, 992, 1194, 5555]);
let softEtherNames = dynamic(["vpnserver", "vpnclient", "vpncmd", "vpnbridge", "softether"]);
let standardPaths = dynamic(["program files", "programdata"]);
let suspiciousProcesses =
    DeviceProcessEvents
    | where TimeGenerated > ago(7d)
    | where FileName has_any (softEtherNames)
        or ProcessCommandLine has_any (softEtherNames)
    | project
        DeviceId,
        DeviceName,
        ProcessTime = TimeGenerated,
        FileName,
        ProcessCommandLine,
        FolderPath,
        InitiatingProcessFileName,
        AccountName,
        AccountDomain;
let networkConnections =
    DeviceNetworkEvents
    | where TimeGenerated > ago(7d)
    | where RemotePort in (softEtherPorts)
    | where ActionType == "ConnectionSuccess"
    | project
        DeviceId,
        NetTime = TimeGenerated,
        RemoteIP,
        RemotePort,
        NetInitiatingProcessFileName = InitiatingProcessFileName;
suspiciousProcesses
| join kind=inner networkConnections on DeviceId
| where NetTime between (ProcessTime .. (ProcessTime + 10m))
| where isempty(FolderPath)
    or not (tolower(FolderPath) has_any (standardPaths))
| project
    DeviceName,
    AccountName,
    AccountDomain,
    FileName,
    ProcessCommandLine,
    FolderPath,
    InitiatingProcessFileName,
    RemoteIP,
    RemotePort,
    ProcessTime,
    NetTime
| order by ProcessTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate SoftEther VPN deployments installed in non-standard directories by IT administrators.
- Security research or penetration testing activity using SoftEther tooling on authorized endpoints.
- Other VPN or tunneling software that shares port usage on 443, 992, 1194, or 5555.

**Tuning notes:**
- Validate ActionType value for successful outbound connections in the environment: DeviceNetworkEvents → summarize count() by ActionType → order by count_ desc → take 20.
- Add a device allowlist exclusion by DeviceId or DeviceName for any endpoints with authorized SoftEther deployments.
- Consider removing port 443 from softEtherPorts if HTTPS false-positive volume is high and SoftEther tunnel activity is expected on non-443 ports in the environment.
- Extend the join time window from 10m to 30m if process-to-network correlation misses delayed connection events.

**Risks / caveats:**
- ActionType value 'ConnectionSuccess' must be confirmed as a valid value in DeviceNetworkEvents in the target tenant; alternate values such as 'ConnectSuccess' or 'NetworkConnectionEvents' schema variants may apply depending on MDE sensor version.
- Port 443 inclusion will generate significant volume from HTTPS traffic; analysts should filter or deprioritize RemotePort 443 results unless correlated with a SoftEther process name match.
- The 10-minute correlation window may miss delayed network connections from SoftEther processes that initialize slowly; extend to 30 minutes if correlation gaps are observed.
- A device allowlist for endpoints with authorized SoftEther deployments should be maintained and applied as an exclusion to suppress known-good infrastructure.

### Triage Runbook

**First 15 minutes:**
- Identify the endpoint owner, business function, and whether SoftEther is approved on that device or in that business unit.
- Inspect the process command line and parent process to determine how SoftEther was launched and whether it was staged from a user-writable location.
- Check whether the outbound connection is to an approved corporate VPN gateway or an unknown external IP on SoftEther-related ports.
- Look for concurrent signs of compromise on the host, including new services, scheduled tasks, autoruns, or suspicious child processes.

**Evidence to collect:**
- Device name, account name, process path, command line, parent process, and initiating process folder path.
- Remote IP, remote port, connection time, and whether the connection is repeated or long-lived.
- File hashes and file location for the SoftEther binary or related components if present on disk.
- Recent process and network activity on the same host to identify staging, persistence, or lateral movement.

**Pivot points:**
- DeviceProcessEvents for the same DeviceId to find SoftEther-related executions and any dropped or renamed binaries.
- DeviceNetworkEvents for the same DeviceId and RemoteIP to determine connection frequency and duration.
- DeviceFileEvents and DeviceRegistryEvents for persistence artifacts, if available in the tenant.
- Asset inventory or endpoint management records to confirm whether SoftEther is authorized on the device.

**Benign explanations:**
- An IT administrator or security tester installed SoftEther for an approved remote-access or lab use case.
- The endpoint is a sanctioned research or engineering system where SoftEther is expected.
- A legitimate VPN or tunneling product was renamed or packaged in a way that resembles SoftEther.
- The alert is triggered by a non-SoftEther tool using the same ports, especially if the process name is misleading.

**Escalation criteria:**
- SoftEther is not approved for the device or user and the process is running from a non-standard or user-writable path.
- The connection is to an unknown external IP and is persistent or recurring across multiple days.
- Additional host artifacts indicate persistence, credential theft, or remote execution.
- Multiple endpoints show the same pattern, suggesting broader compromise or a campaign.

**Containment actions:**
- Isolate the endpoint from the network if unauthorized SoftEther execution is confirmed or strongly suspected.
- Terminate the SoftEther process and remove the binary only after preserving evidence and coordinating with incident response.
- Block the remote IP and associated ports at perimeter and endpoint controls where feasible.
- Reset credentials used on the host if there is evidence the tunnel was used for interactive access.

**Closure criteria:**
- SoftEther is confirmed as authorized and the device is on an approved allowlist with documented business justification.
- The process and network activity are explained by legitimate administration or testing and no other compromise indicators are present.
- No persistence, suspicious parent process, or unauthorized remote access is found.
- Any required allowlist or detection tuning updates have been completed.

<br/>
---
<br/>

## Detection 3: Webworm - Persistent Low-Frequency Outbound Connections on Non-Standard VPN Ports

### Detection Opportunity

Long-term persistent outbound connections to non-standard VPN ports from endpoints lacking authorized VPN software, consistent with Webworm's covert SoftEther-based tunnel for sustained access.

### Intelligence Context

- Rapid7: Spying on Governments with Zero Lines of Malware: A Custom SoftEther Bridge in Webworm's Toolkit — [https://www.rapid7.com/blog/post/tr-spying-on-governments-no-malware-custom-webworms-toolkit-softether-bridge](https://www.rapid7.com/blog/post/tr-spying-on-governments-no-malware-custom-webworms-toolkit-softether-bridge)
  - Context: Rapid7 reported Webworm maintains low-profile, long-term covert access using a custom SoftEther bridge. The persistence behavior produces recurring outbound connections over extended periods, distinguishable from one-time VPN usage by their regularity and duration across multiple days.

### Search Metadata

- CVEs: Not specified
- Threat actors: Webworm
- ATT&CK tags: Not specified
- Products: SoftEther VPN
- Platforms: Not specified
- Malware: Not specified
- Tools: SoftEther VPN
- Search tags: Webworm, SoftEther VPN

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Not mapped

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
let softEtherPorts = dynamic([992, 1194, 5555]);
let authorizedVPNProcesses = dynamic(["vpnui.exe", "vpnagent.exe", "ciscovpn.exe", "openvpn.exe", "anyconnect.exe", "globalprotect.exe"]);
DeviceNetworkEvents
| where TimeGenerated > ago(14d)
| where RemotePort in (softEtherPorts)
| where ActionType == "ConnectionSuccess"
| where not (InitiatingProcessFileName has_any (authorizedVPNProcesses))
| summarize
    ConnectionDays = dcount(bin(TimeGenerated, 1d)),
    TotalConnections = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    InitiatingProcessFileNames = make_set(InitiatingProcessFileName, 20)
    by DeviceId, DeviceName, RemoteIP, RemotePort
| where ConnectionDays >= 5
| project
    DeviceName,
    DeviceId,
    RemoteIP,
    RemotePort,
    InitiatingProcessFileNames,
    ConnectionDays,
    TotalConnections,
    FirstSeen,
    LastSeen
| order by ConnectionDays desc, RemotePort asc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate VPN clients not included in the authorizedVPNProcesses list that connect on ports 992, 1194, or 5555.
- Security monitoring or network management tools that maintain persistent outbound connections on these ports.
- Endpoints in environments where OpenVPN or other VPN software uses port 1194 legitimately but the process name differs from the exclusion list.

**Tuning notes:**
- Run without the ConnectionDays >= 5 filter first to assess baseline connection volume on ports 992, 1194, and 5555 before applying the persistence threshold.
- Add RemoteIP exclusions for known corporate VPN gateway IPs: → where RemoteIP !in (dynamic(["<gateway_ip_1>", "<gateway_ip_2>"])).
- Update authorizedVPNProcesses to include all VPN client executables deployed in the environment.
- Validate ActionType value for successful outbound connections: DeviceNetworkEvents → summarize count() by ActionType → order by count_ desc → take 20.

**Risks / caveats:**
- ActionType value 'ConnectionSuccess' must be confirmed as a valid value in DeviceNetworkEvents in the target tenant; alternate values may apply depending on MDE sensor version.
- The authorizedVPNProcesses list must be updated to reflect all VPN client process names in use in the environment; unrecognized legitimate VPN processes will appear as false positives.
- The ConnectionDays >= 5 threshold may be too low in environments with legitimate periodic connections on these ports; increase to 7 or higher after reviewing baseline volume.
- RemoteIP exclusions for known corporate VPN gateway IPs should be added to suppress authorized infrastructure from results.

### Triage Runbook

**First 15 minutes:**
- Check whether the device has approved VPN software or a documented business need to connect on the flagged ports.
- Review the initiating process names and paths to see whether the traffic comes from a known VPN client or an unexpected executable.
- Assess whether the connections are to a corporate gateway, a known service provider, or an unknown external IP.
- Compare the connection pattern to normal user or device behavior to see if it is periodic, long-lived, and low-volume.

**Evidence to collect:**
- Device name, DeviceId, remote IP, remote port, initiating process names, first seen, last seen, and total connection count.
- Process path and account context for the initiating process if available.
- Historical network activity for the same device to determine whether the pattern is new or longstanding.
- Any endpoint management or VPN deployment records that explain the traffic.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceId and RemoteIP over 14 to 30 days to confirm persistence.
- DeviceProcessEvents for the same initiating process names to identify installation source and parent process.
- Asset inventory or software inventory to verify whether the process is an approved VPN client.
- Proxy, firewall, or DNS logs to determine whether the remote endpoint is a known corporate service.

**Benign explanations:**
- The device uses an approved VPN client not included in the current exclusion list.
- A legitimate monitoring, remote support, or network management tool maintains persistent outbound connectivity.
- The remote IP belongs to a sanctioned corporate gateway or service provider.
- The device is in a lab or engineering environment where non-standard VPN ports are expected.

**Escalation criteria:**
- The process is not an approved VPN client and the remote IP is not a sanctioned gateway.
- The pattern is persistent across multiple days and appears on multiple endpoints.
- The device shows additional suspicious activity such as new services, scheduled tasks, or unusual logons.
- The traffic is associated with a user or host that should not be running tunneling software.

**Containment actions:**
- If unauthorized tunneling is confirmed, isolate the endpoint and block the remote IP and ports.
- Remove or disable the unauthorized VPN/tunnel software after evidence preservation.
- Reset credentials used on the device if interactive access is suspected.
- Expand monitoring to other endpoints for the same remote IP, ports, or process names.

**Closure criteria:**
- The connections are attributed to approved software, a sanctioned gateway, or a documented business process.
- No additional compromise indicators are found on the host or in adjacent telemetry.
- The device is added to an approved allowlist if the behavior is expected.
- The alert is explained by baseline tuning or environment-specific VPN usage patterns.

<br/>
---
<br/>

## Detection 4: CVE-2026-73571 - Zimbra SaveDraftRequest Sender Impersonation via Authorization Bypass

### Detection Opportunity

Authenticated Zimbra user sends mail as a different user by exploiting the SaveDraftRequest authorization bypass, resulting in a mismatch between the authenticated session identity and the message envelope sender.

### Intelligence Context

- Rapid7: Metasploit Wrap Up: Breaking Zimbra's Identity Boundaries — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-breaking-zimbra-s-identity-boundaries](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-breaking-zimbra-s-identity-boundaries)
  - Context: Rapid7 disclosed CVE-2026-73571, an authorization bypass in Zimbra's SaveDraftRequest SOAP handler that allows an authenticated user to send mail as another user. A Metasploit module was released targeting this behavior. The detection targets the sender identity mismatch in Zimbra audit logs as the primary signal.

### Search Metadata

- CVEs: CVE-2026-73571
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Zimbra, Metasploit
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-73571, T1190, Zimbra, Metasploit

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
let zimbraMailSendActivities = dynamic(["SaveDraftRequest", "SendMsgRequest", "send", "mail send"]);
let cslBranch =
    CommonSecurityLog
    | where TimeGenerated > ago(1d)
    | where DeviceProduct has_any ("Zimbra", "zimbra")
    | where Activity has_any (zimbraMailSendActivities)
        or RequestURL has "SaveDraftRequest"
    | where EventOutcome =~ "success"
    | where isnotempty(SourceUserName) and isnotempty(DestinationUserName)
    | where SourceUserName != DestinationUserName
    | project
        TimeGenerated,
        SourceIP,
        AuthenticatedUser = SourceUserName,
        SenderUser = DestinationUserName,
        Activity,
        RequestURL,
        LogSource = "CommonSecurityLog";
let syslogBranch =
    Syslog
    | where TimeGenerated > ago(1d)
    | where ProcessName has_any ("zimbra", "zmmailboxd")
    | where SyslogMessage has "SaveDraftRequest"
    | where SyslogMessage has "acct="
    | extend
        AuthenticatedUser = extract(@"acct=([^;\s]+)", 1, SyslogMessage),
        SenderUser = extract(@"from=([^;\s]+)", 1, SyslogMessage),
        SourceIP = extract(@"ip=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", 1, SyslogMessage)
    | where isnotempty(AuthenticatedUser) and isnotempty(SenderUser)
    | where AuthenticatedUser != SenderUser
    | project
        TimeGenerated,
        SourceIP,
        AuthenticatedUser,
        SenderUser,
        Activity = "SaveDraftRequest",
        RequestURL = "",
        LogSource = "Syslog";
union cslBranch, syslogBranch
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate mail delegation configurations where one user is authorized to send on behalf of another, producing an intentional SourceUserName/DestinationUserName mismatch.
- Service accounts or shared mailbox configurations that send mail under a different display identity than the authenticated session account.
- Zimbra distribution list or alias expansion that causes the envelope sender to differ from the authenticated user.

**Tuning notes:**
- Confirm Zimbra events in CommonSecurityLog: CommonSecurityLog → where DeviceProduct has_any ('Zimbra','zimbra') → summarize count() by DeviceProduct, SourceUserName, DestinationUserName → take 20.
- Confirm SaveDraftRequest in Syslog: Syslog → where ProcessName has_any ('zimbra','zmmailboxd') → where SyslogMessage has 'SaveDraftRequest' → take 10.
- Validate 'acct=' and 'from=' field presence in Syslog messages: Syslog → where ProcessName has_any ('zimbra','zmmailboxd') → where SyslogMessage has 'acct=' → take 5.
- Add AuthenticatedUser exclusions for service accounts or delegation-configured accounts that legitimately send on behalf of other users.

**Risks / caveats:**
- CommonSecurityLog SourceUserName and DestinationUserName field population for Zimbra events depends on the CEF connector mapping; these fields may be empty if the Zimbra syslog forwarder does not map sender and authenticated user to CEF source/destination user fields.
- Syslog branch regex patterns extract 'acct=' and 'from=' from SyslogMessage; if the Zimbra audit log format uses different field names or delimiters, both extract() calls will return empty strings and the branch will produce no results.
- DeviceProduct values 'Zimbra' and 'zimbra' in CommonSecurityLog are assumed; the actual DeviceProduct value depends on the CEF header configured in the Zimbra syslog forwarder.
- The Syslog branch regex for SourceIP extraction assumes a standard 'ip=' field in Zimbra audit log messages; if the field name differs, SourceIP will be empty for Syslog-sourced alerts.

### Triage Runbook

**First 15 minutes:**
- Identify the authenticated user, the impersonated sender, and the source IP for the message activity.
- Check whether the sender mismatch is expected due to delegation, shared mailboxes, or service account behavior.
- Review the message content, recipients, and timing to determine whether the email was used for fraud, phishing, or internal abuse.
- Look for additional send events from the same account or source IP around the alert time.

**Evidence to collect:**
- Authenticated user, sender user, source IP, request URL or activity name, and event outcome.
- Message metadata including recipients, subject, and any attachment or link indicators if available.
- Zimbra audit or syslog records showing the exact SaveDraftRequest or send operation sequence.
- Any prior or subsequent logins from the same source IP or account.

**Pivot points:**
- CommonSecurityLog for the same SourceIP, SourceUserName, or DestinationUserName over the prior 24 hours.
- Syslog for Zimbra SaveDraftRequest, SendMsgRequest, or related mail-sending events from the same account.
- Mail gateway or message tracking logs to identify recipients and delivery outcomes.
- Identity logs to determine whether the authenticated user had a legitimate delegation relationship.

**Benign explanations:**
- The user has an approved send-on-behalf or delegation configuration.
- A shared mailbox or service account legitimately sends mail under a different sender identity.
- Alias expansion or distribution list behavior causes the envelope sender to differ from the authenticated user.
- The alert is caused by incomplete field mapping in the Zimbra connector.

**Escalation criteria:**
- The sender mismatch is not explained by delegation, shared mailbox, or service account configuration.
- The message content is suspicious, external-facing, or part of a phishing or fraud campaign.
- The same account or source IP generates multiple impersonation events.
- There is evidence of unauthorized access to a privileged or high-value mailbox.

**Containment actions:**
- Disable the affected account or revoke active sessions if unauthorized impersonation is confirmed.
- Block the source IP if it is external or otherwise untrusted.
- Quarantine or recall suspicious messages where mail controls support it.
- Reset credentials and review mailbox delegation settings for abuse.

**Closure criteria:**
- A legitimate delegation, shared mailbox, or service account explains the sender mismatch.
- No suspicious message content, recipients, or follow-on activity is found.
- The event is attributable to logging or connector mapping issues rather than abuse.
- Any required mailbox policy or detection tuning changes have been documented.

<br/>
---
<br/>

## Detection 5: CVE-2026-73571 - Metasploit Exploitation Pattern Against Zimbra SOAP Endpoint

### Detection Opportunity

Repeated requests to the Zimbra SOAP endpoint matching SaveDraftRequest patterns from source IPs with no prior authenticated session history, consistent with Metasploit module exploitation of CVE-2026-73571.

### Intelligence Context

- Rapid7: Metasploit Wrap Up: Breaking Zimbra's Identity Boundaries — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-breaking-zimbra-s-identity-boundaries](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-breaking-zimbra-s-identity-boundaries)
  - Context: Rapid7 released a Metasploit module targeting CVE-2026-73571 in Zimbra's SaveDraftRequest SOAP handler. The module generates HTTP requests to the Zimbra SOAP endpoint. Detection targets repeated SOAP endpoint access from IPs with no prior authenticated history as an exploitation probe pattern.

### Search Metadata

- CVEs: CVE-2026-73571
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Zimbra, Metasploit
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-73571, T1190, Zimbra, Metasploit

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
let lookbackDays = 7d;
let minRequests = 3;
let knownAuthIPs =
    CommonSecurityLog
    | where TimeGenerated > ago(lookbackDays)
    | where DeviceProduct has_any ("Zimbra", "zimbra")
    | where EventOutcome =~ "success"
    | where isnotempty(SourceIP)
    | summarize by SourceIP;
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DeviceProduct has_any ("Zimbra", "zimbra")
| where RequestURL has "SaveDraftRequest"
    or Activity has "SaveDraftRequest"
| where isnotempty(SourceIP)
| where SourceIP !in (knownAuthIPs)
| summarize
    RequestCount = count(),
    FirstRequest = min(TimeGenerated),
    LastRequest = max(TimeGenerated),
    ResultCodes = make_set(EventOutcome, 10),
    Activities = make_set(Activity, 10)
    by SourceIP, bin(TimeGenerated, 1h)
| where RequestCount >= minRequests
| project
    SourceIP,
    RequestCount,
    FirstRequest,
    LastRequest,
    ResultCodes,
    Activities
| order by RequestCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Automated mail clients or integration services that send multiple SaveDraftRequest calls from IPs not previously seen in the 7-day authentication baseline.
- New employee or contractor endpoints accessing Zimbra for the first time from IPs with no prior authentication history.
- Security scanners or vulnerability assessment tools probing the Zimbra SOAP endpoint.

**Tuning notes:**
- Confirm RequestURL is populated for Zimbra events: CommonSecurityLog → where DeviceProduct has_any ('Zimbra','zimbra') → where isnotempty(RequestURL) → summarize count() by RequestURL → take 20.
- Run without the SourceIP !in (knownAuthIPs) filter to assess total SaveDraftRequest volume before applying the novel-IP filter.
- Extend lookbackDays for knownAuthIPs from 7d to 30d to build a more stable baseline of authorized source IPs before production deployment.
- Increase minRequests from 3 to 10 if the Zimbra environment generates high legitimate SaveDraftRequest traffic from shared or automated accounts.

**Risks / caveats:**
- RequestURL field population in CommonSecurityLog for Zimbra SOAP requests depends on the CEF connector mapping HTTP request paths to the RequestURL field; if this mapping is absent, the primary filter will return no results.
- EventOutcome field must be populated with 'success' values in Zimbra log events for the knownAuthIPs baseline to function; an empty EventOutcome will result in an empty exclusion set and elevated false-positive volume.
- DeviceProduct values 'Zimbra' and 'zimbra' in CommonSecurityLog are assumed based on the CEF header configured in the Zimbra syslog forwarder and must be confirmed.
- The 7-day knownAuthIPs lookback will produce an empty exclusion set if Zimbra log forwarding was recently configured, causing elevated alert volume during the initial baselining period; extend to 30 days after sufficient log history is available.

### Triage Runbook

**First 15 minutes:**
- Validate whether the source IP belongs to an approved scanner, tester, or internal monitoring system.
- Review the request rate, repetition, and timing to confirm the pattern is consistent with exploitation probing rather than normal client use.
- Check whether the same source IP has any successful authenticated sessions or only repeated SOAP requests.
- Assess whether the Zimbra server shows signs of follow-on abuse such as mailbox access, sender impersonation, or unusual errors.

**Evidence to collect:**
- Source IP, request count, first request time, last request time, and observed activities.
- Request URL, HTTP method if available, and any response codes or error patterns.
- Zimbra authentication history for the source IP and any associated account activity.
- Server-side logs showing whether the requests triggered errors, exceptions, or abnormal processing.

**Pivot points:**
- CommonSecurityLog for the same SourceIP across a wider time range to identify other Zimbra endpoints or related activity.
- CommonSecurityLog or Syslog for the same RequestURL or SaveDraftRequest pattern from other source IPs.
- Web server or reverse proxy logs for request headers, user agents, and response codes.
- Identity and mail logs for any successful logins or message actions following the probe pattern.

**Benign explanations:**
- An approved vulnerability scanner or penetration test is probing the Zimbra SOAP endpoint.
- A new client or integration service is making repeated SOAP calls during normal operation.
- A user or automation is retrying failed requests due to transient application errors.
- The alert is caused by a first-time source IP that has not yet established an authentication history.

**Escalation criteria:**
- The source IP is not approved and the request pattern is consistent with exploitation tooling.
- There is evidence of successful authentication, mailbox access, or sender impersonation after the probe pattern.
- Multiple Zimbra hosts or multiple source IPs show the same request pattern.
- The server exhibits errors or behavior consistent with active exploitation attempts.

**Containment actions:**
- Block the source IP if it is unapproved and the activity is clearly malicious.
- Rate-limit or temporarily restrict access to the Zimbra SOAP endpoint if exploitation is ongoing.
- Increase monitoring on the Zimbra host for additional requests, authentication attempts, and mailbox abuse.
- Coordinate with the application owner before making service-impacting changes.

**Closure criteria:**
- The source IP is confirmed as an approved scanner, tester, or legitimate integration.
- No successful exploitation, mailbox abuse, or suspicious follow-on activity is found.
- The request pattern is explained by normal application behavior or a documented maintenance activity.
- Any required allowlist or threshold tuning has been completed.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Other deployment dependency:**
- CVE-2026-123890 - vCenter Auth Bypass Followed by Administrator Session from Novel IP: CommonSecurityLog DeviceProduct values for vCenter syslog forwarding are not standardized; 'vCenter' and 'VMware' are assumed values that must be confirmed in the environment before the query returns results.

**Schema / correlation keys:**
- Webworm - SoftEther VPN Deployment on Endpoints Without Authorized VPN Software: Do not schedule yet; validate as an analyst-led hunt first.
- Webworm - Persistent Low-Frequency Outbound Connections on Non-Standard VPN Ports: Do not schedule yet; validate as an analyst-led hunt first.

**Telemetry availability:**
- CVE-2026-73571 - Zimbra SaveDraftRequest Sender Impersonation via Authorization Bypass: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.
- CVE-2026-73571 - Metasploit Exploitation Pattern Against Zimbra SOAP Endpoint: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.

**Shared-table notes:**
- CommonSecurityLog: shared by CVE-2026-123890 - vCenter Auth Bypass Followed by Administrator Session from Novel IP; CVE-2026-73571 - Zimbra SaveDraftRequest Sender Impersonation via Authorization Bypass; CVE-2026-73571 - Metasploit Exploitation Pattern Against Zimbra SOAP Endpoint
- DeviceNetworkEvents: shared by Webworm - SoftEther VPN Deployment on Endpoints Without Authorized VPN Software; Webworm - Persistent Low-Frequency Outbound Connections on Non-Standard VPN Ports

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: CVE-2026-123890 - vCenter Auth Bypass Followed by Administrator Session from Novel IP; CVE-2026-73571 - Zimbra SaveDraftRequest Sender Impersonation via Authorization Bypass; CVE-2026-73571 - Metasploit Exploitation Pattern Against Zimbra SOAP Endpoint.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Webworm - SoftEther VPN Deployment on Endpoints Without Authorized VPN Software; Webworm - Persistent Low-Frequency Outbound Connections on Non-Standard VPN Ports.

### Hunting Agenda and Promotion Criteria

- Webworm - SoftEther VPN Deployment on Endpoints Without Authorized VPN Software: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- Webworm - Persistent Low-Frequency Outbound Connections on Non-Standard VPN Ports: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- CVE-2026-123890 - vCenter Auth Bypass Followed by Administrator Session from Novel IP: CommonSecurityLog DeviceProduct values for vCenter syslog forwarding are not standardized; 'vCenter' and 'VMware' are assumed values that must be confirmed in the environment before the query returns results..
- CVE-2026-73571 - Zimbra SaveDraftRequest Sender Impersonation via Authorization Bypass: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- CVE-2026-73571 - Metasploit Exploitation Pattern Against Zimbra SOAP Endpoint: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog before scheduling.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
