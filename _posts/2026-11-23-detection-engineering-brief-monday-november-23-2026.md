---
layout: post
title: "Detection Engineering Brief - Monday, November 23, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-11-23
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
  - government networks
  - network
  - CVE-2026-73571
  - Zimbra
  - Metasploit
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

0 production candidates, 1 hunting-only, 4 require environment mapping, and 0 rejected.

5 detections include KQL. 4 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-123890, ARMORY CASTLE, T1190, VMware vCenter, VMware Directory Service, Webworm, SoftEther VPN, government networks, network, CVE-2026-73571, Zimbra, Metasploit.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: CVE-2026-123890 - Unauthenticated Access to VMware vCenter Management Endpoint; CVE-2026-123890 - Unexpected Administrator Logon to VMware vCenter Host; Webworm - SoftEther VPN Process Execution from Non-Standard Path or with Suspicious Network Connections; CVE-2026-73571 - Zimbra Authenticated User Sending Mail as a Different Account; CVE-2026-73571 - HTTP POST to Zimbra SaveDraftRequest Endpoint with Cross-Account Activity.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: CVE-2026-123890 - Unauthenticated Access to VMware vCenter Management Endpoint

### Detection Opportunity

Exploitation of vCenter authentication bypass allowing unauthenticated HTTP access to management endpoints, returning successful responses without credentials.

### Intelligence Context

- Rapid7: CVE-2026-123890: Critical Authentication Bypass in VMware vCenter — [https://www.rapid7.com/blog/post/etr-cve-2026-123890-critical-authentication-bypass-vmware-vcenter](https://www.rapid7.com/blog/post/etr-cve-2026-123890-critical-authentication-bypass-vmware-vcenter)
  - Context: ARMORY CASTLE confirmed in-the-wild exploitation of CVE-2026-123890, bypassing vCenter authentication without credentials and gaining Administrator access. The bypass produces successful HTTP responses to management endpoints from unauthenticated external sources.

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
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, SecurityEvent before scheduling.

**Required telemetry:**
- CommonSecurityLog, SecurityEvent

### KQL

```kql
let vCenterManagementPaths = dynamic(["/ui/", "/sdk", "/mob", "/vpxd"]);
let lookback = 1h;
let joinWindowMinutes = 30;
let suspiciousRequests =
    CommonSecurityLog
    | where TimeGenerated >= ago(lookback)
    | where DeviceProduct has_any ("vCenter", "VMware")
    | where RequestURL has_any (vCenterManagementPaths)
    | where tostring(ResponseCode) == "200"
    | where isnotempty(SourceIP)
    | project RequestTime = TimeGenerated, SourceIP, RequestURL, ResponseCode, DeviceVendor, DeviceProduct;
let adminLogons =
    SecurityEvent
    | where TimeGenerated >= ago(lookback + totimespan(joinWindowMinutes * 1m))
    | where EventID == 4624
    | where AccountName =~ "Administrator"
    | where LogonType in (3, 10)
    | where isnotempty(IpAddress)
    | project LogonTime = TimeGenerated, AccountName, IpAddress, WorkstationName, LogonType;
suspiciousRequests
| join kind=inner adminLogons on $left.SourceIP == $right.IpAddress
| where LogonTime >= RequestTime and LogonTime <= RequestTime + totimespan(joinWindowMinutes * 1m)
| project
    RequestTime,
    LogonTime,
    SourceIP,
    RequestURL,
    ResponseCode,
    AccountName,
    WorkstationName,
    LogonType,
    DeviceVendor,
    DeviceProduct
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Internal vulnerability scanners or monitoring tools that probe vCenter management paths and return HTTP 200 will match the first leg.
- Legitimate Administrator logons from new jump hosts or VPN egress IPs will match the second leg.
- Shared NAT or proxy IPs may cause false correlation between unrelated HTTP requests and logon events.

**Tuning notes:**
- Restrict SourceIP to known external CIDR ranges using an ipv4_is_private() exclusion to reduce internal scanner noise.
- Populate a watchlist of known-legitimate vCenter management IPs and exclude them from SourceIP matches.
- Extend lookback beyond 1h if exploitation-to-logon timing in the environment exceeds 30 minutes.

**Risks / caveats:**
- CommonSecurityLog DeviceProduct field population depends on the vCenter syslog connector configuration; if vCenter logs are not forwarded or DeviceProduct is not set to 'vCenter' or 'VMware', the suspiciousRequests subquery returns zero rows.
- vCenter Server Appliance is Linux-based; Windows Security Event logs (SecurityEvent table, EventID 4624) are not natively generated by the appliance. This join leg will produce no results unless a Windows-based vCenter deployment or a separate Windows host is in scope.
- SecurityEvent IpAddress field is frequently empty for LogonType 3 network logons depending on the authentication protocol; the inner join on SourceIP == IpAddress may silently drop valid matches.
- The 30-minute join window is a starting assumption; adjust based on observed exploitation timing in the environment.

### Triage Runbook

**First 15 minutes:**
- Confirm the source IP is external and not a known scanner, proxy, or internal management host.
- Validate the request URL, response code, and timestamp against vCenter logs to confirm the endpoint was actually accessed successfully.
- Check for any Administrator logons from the same source IP or nearby time window and identify the target host and logon type.
- Look for immediate follow-on activity on the vCenter appliance or adjacent infrastructure such as new sessions, configuration changes, or service restarts.
- Open an incident if the source IP is unknown, the request was successful, and any administrative access or configuration change follows.

**Evidence to collect:**
- RequestTime, SourceIP, RequestURL, ResponseCode, DeviceVendor, and DeviceProduct from the alert.
- Matching vCenter access logs showing the same source IP, requested path, and any session identifiers.
- SecurityEvent 4624 records for Administrator logons, including LogonType, WorkstationName, and IpAddress.
- Any vCenter audit or admin activity around the same time, including user creation, privilege changes, or task execution.
- Network telemetry showing whether the source IP made repeated requests or probed other management paths.

**Pivot points:**
- CommonSecurityLog for the same SourceIP over the last 24 hours.
- SecurityEvent for Administrator logons from the same IpAddress or WorkstationName.
- vCenter appliance audit/authentication logs for the same RequestTime window.
- Any proxy, firewall, or load balancer logs that can confirm the original client IP.
- Change-management records for planned admin access or maintenance during the alert window.

**Benign explanations:**
- A vulnerability scanner or monitoring tool may probe vCenter management paths and receive HTTP 200 responses.
- A legitimate administrator may have logged in from a new VPN or jump host IP.
- Shared NAT or proxy egress can make a benign internal user appear as a new source IP.
- Planned maintenance or patch validation may generate unusual but authorized management access.

**Escalation criteria:**
- The source IP is external and not associated with approved administration or scanning.
- An Administrator logon from the same IP occurs within the join window and is not explained by maintenance.
- There are signs of privilege changes, new sessions, or configuration changes on vCenter after the request.
- Multiple management endpoints are accessed successfully from the same source IP in a short period.

**Containment actions:**
- Block the source IP at the perimeter if it is confirmed malicious or unauthorized.
- Disable or reset the affected Administrator credentials if compromise is suspected.
- Isolate the vCenter appliance from nonessential management access if active exploitation is ongoing.
- Preserve logs and snapshots before making disruptive changes.

**Closure criteria:**
- The source IP is confirmed as an approved scanner, admin host, or maintenance system.
- No corresponding suspicious logon, privilege change, or post-exploitation activity is found.
- vCenter logs show the request was benign or part of an authorized workflow.
- The alert is attributable to known test activity and documented in the case notes.

<br/>
---
<br/>

## Detection 2: CVE-2026-123890 - Unexpected Administrator Logon to VMware vCenter Host

### Detection Opportunity

Unauthorized Administrator account logon to vCenter host from an IP with no prior access history, consistent with post-exploitation access following authentication bypass.

### Intelligence Context

- Rapid7: CVE-2026-123890: Critical Authentication Bypass in VMware vCenter — [https://www.rapid7.com/blog/post/etr-cve-2026-123890-critical-authentication-bypass-vmware-vcenter](https://www.rapid7.com/blog/post/etr-cve-2026-123890-critical-authentication-bypass-vmware-vcenter)
  - Context: Exploitation of CVE-2026-123890 results in the attacker gaining access as the Administrator user on the vCenter system. Administrator logons from previously unseen source IPs represent a high-fidelity post-exploitation signal.

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
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.

**Required telemetry:**
- SecurityEvent

### KQL

```kql
let lookback = 30d;
let alertWindow = 1d;
let vCenterHosts = dynamic(["vcenter01", "vcenter02"]);
let historicAdminLogons =
    SecurityEvent
    | where TimeGenerated between (ago(lookback) .. ago(alertWindow))
    | where EventID == 4624
    | where AccountName =~ "Administrator"
    | where WorkstationName has_any (vCenterHosts)
    | where LogonType in (3, 10)
    | where isnotempty(IpAddress)
    | summarize KnownIPs = make_set(IpAddress) by WorkstationName;
SecurityEvent
| where TimeGenerated >= ago(alertWindow)
| where EventID == 4624
| where AccountName =~ "Administrator"
| where WorkstationName has_any (vCenterHosts)
| where LogonType in (3, 10)
| where isnotempty(IpAddress)
| join kind=leftouter historicAdminLogons on WorkstationName
| extend KnownIPs = coalesce(KnownIPs, dynamic([]))
| where not(IpAddress in (KnownIPs))
| project
    TimeGenerated,
    AccountName,
    SubjectUserName,
    IpAddress,
    WorkstationName,
    LogonType,
    LogonProcessName
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- New jump hosts, VPN concentrators, or PAM solution egress IPs that were not active in the 30-day baseline will trigger alerts.
- Scheduled maintenance windows using new management IPs will generate alerts.
- IP address changes on existing management workstations will appear as new sources.

**Tuning notes:**
- Replace 'vcenter01' and 'vcenter02' in the vCenterHosts list with the actual WorkstationName values observed in SecurityEvent for the vCenter hosts.
- Consider maintaining vCenterHosts as a Sentinel watchlist to allow updates without rule edits.
- Extend the baseline lookback beyond 30 days if Administrator logon patterns are infrequent in the environment.

**Risks / caveats:**
- The vCenterHosts list contains example values ('vcenter01', 'vcenter02') that are not real hostnames; the query will return no results until replaced with actual environment hostnames.
- SecurityEvent IpAddress is frequently empty for LogonType 3 events depending on authentication protocol; rows with empty IpAddress will pass the not(IpAddress in (KnownIPs)) filter and generate false positives.
- vCenter Server Appliance is Linux-based and does not natively emit Windows Security Events; SecurityEvent availability depends on a Windows Event Forwarding or Azure Monitor Agent deployment targeting the vCenter host.
- The vCenterHosts list must be updated whenever vCenter hostnames change or new appliances are deployed.

### Triage Runbook

**First 15 minutes:**
- Verify the source IP against known admin, VPN, PAM, and jump host ranges.
- Check whether the WorkstationName is the actual vCenter host and whether the logon type is consistent with expected administration.
- Review prior 30-day Administrator logons to see whether this IP or host has ever been used before.
- Correlate the logon time with any recent vCenter management endpoint access, especially successful unauthenticated requests.
- Escalate immediately if the IP is new, external, or paired with other suspicious vCenter activity.

**Evidence to collect:**
- TimeGenerated, AccountName, IpAddress, WorkstationName, LogonType, LogonProcessName, and SubjectUserName from the alert.
- Historical Administrator logons for the same WorkstationName and any prior known IPs.
- Any vCenter audit logs showing actions performed after the logon.
- VPN, PAM, or jump host logs that could explain the source IP.
- Asset inventory details confirming the host identity and whether the appliance is expected to generate SecurityEvent logs.

**Pivot points:**
- SecurityEvent for all 4624 logons to the same WorkstationName over 30 to 90 days.
- CommonSecurityLog for the same source IP and nearby timestamps.
- vCenter audit and appliance logs for actions by Administrator after the logon.
- VPN, PAM, and bastion host logs for the source IP and user identity.
- Firewall or proxy logs to determine whether the IP is internal, NATed, or external.

**Benign explanations:**
- A new jump host or VPN egress IP may be used by an authorized administrator.
- Maintenance or emergency access may come from a previously unseen management source.
- IP changes on an existing admin workstation can appear as a new source.
- A PAM solution may rotate egress IPs and trigger the baseline exclusion.

**Escalation criteria:**
- The source IP is not in any approved admin, VPN, or PAM range.
- The logon is followed by suspicious vCenter actions such as privilege changes, new accounts, or service manipulation.
- The same source IP also appears in successful management endpoint access around the same time.
- There is no business justification for the Administrator logon and no matching change ticket.

**Containment actions:**
- Disable or reset the Administrator account if unauthorized access is likely.
- Revoke active sessions and tokens associated with the suspicious logon.
- Restrict management access to vCenter from untrusted networks until the source is understood.
- Preserve authentication and audit logs before remediation.

**Closure criteria:**
- The source IP is validated as an approved management source.
- The logon is tied to a documented change, maintenance window, or approved admin action.
- No suspicious follow-on activity is found on the vCenter host.
- The event is explained by baseline drift or a known infrastructure change and documented accordingly.

<br/>
---
<br/>

## Detection 3: Webworm - SoftEther VPN Process Execution from Non-Standard Path or with Suspicious Network Connections

### Detection Opportunity

Deployment of SoftEther VPN binaries (vpnbridge, vpnclient) executing from non-standard filesystem paths or establishing outbound connections on SoftEther default ports, consistent with Webworm's low-profile persistent access technique.

### Intelligence Context

- Rapid7: Spying on Governments with Zero Lines of Malware: A Custom SoftEther Bridge in Webworm's Toolkit — [https://www.rapid7.com/blog/post/tr-spying-on-governments-no-malware-custom-webworms-toolkit-softether-bridge](https://www.rapid7.com/blog/post/tr-spying-on-governments-no-malware-custom-webworms-toolkit-softether-bridge)
  - Context: Webworm deployed a custom SoftEther VPN-based tool to maintain long-term low-profile access to government networks. The tool implements evasion tricks and may execute from non-standard paths with renamed binaries. Detection focuses on SoftEther process names and default port usage as compound signals.

### Search Metadata

- CVEs: Not specified
- Threat actors: Webworm
- ATT&CK tags: Not specified
- Products: SoftEther VPN
- Platforms: government networks, network
- Malware: Not specified
- Tools: SoftEther VPN
- Search tags: Webworm, SoftEther VPN, government networks, network

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
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let softEtherProcessNames = dynamic(["vpnbridge.exe", "vpnclient.exe", "vpnserver.exe", "vpncmd.exe"]);
let softEtherPortsNoHTTPS = dynamic([992, 1194, 5555]);
let standardPaths = dynamic(["c:\\program files\\softether", "c:\\softethervpn"]);
let lookback = 24h;
let softEtherProcs =
    DeviceProcessEvents
    | where TimeGenerated >= ago(lookback)
    | where FileName in~ (softEtherProcessNames)
    | extend IsNonStandardPath = not(FolderPath has_any (standardPaths))
    | project
        ProcTime = TimeGenerated,
        DeviceId,
        DeviceName,
        FileName,
        FolderPath,
        ProcessCommandLine,
        InitiatingProcessFileName,
        IsNonStandardPath;
let softEtherNet =
    DeviceNetworkEvents
    | where TimeGenerated >= ago(lookback)
    | where RemotePort in (softEtherPortsNoHTTPS)
    | where ActionType == "ConnectionSuccess"
    | where not(ipv4_is_private(RemoteIP))
    | project
        NetTime = TimeGenerated,
        DeviceId,
        RemoteIP,
        RemotePort;
let correlated =
    softEtherProcs
    | join kind=inner softEtherNet on DeviceId
    | where NetTime >= ProcTime and NetTime <= ProcTime + 10m
    | project
        ProcTime,
        NetTime,
        DeviceName,
        FileName,
        FolderPath,
        ProcessCommandLine,
        InitiatingProcessFileName,
        IsNonStandardPath,
        RemoteIP,
        RemotePort;
let nonStandardOnly =
    softEtherProcs
    | where IsNonStandardPath == true
    | project
        ProcTime,
        NetTime = datetime(null),
        DeviceName,
        FileName,
        FolderPath,
        ProcessCommandLine,
        InitiatingProcessFileName,
        IsNonStandardPath,
        RemoteIP = "",
        RemotePort = int(null);
correlated
| union nonStandardOnly
| summarize arg_min(ProcTime, *) by DeviceName, FileName, FolderPath, ProcessCommandLine
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate SoftEther VPN deployments in non-default installation paths will match the non-standard path branch.
- Security research or penetration testing tools using SoftEther binaries will match.
- Ports 992 and 1194 overlap with OpenVPN and other VPN solutions; network-only matches on these ports without a process match are noisy.

**Tuning notes:**
- Add known-legitimate SoftEther installation paths to the standardPaths list to reduce non-standard path false positives.
- If port 443 is required for SoftEther C2 detection, create a separate query that joins SoftEther process events with port-443 connections and applies additional filters such as unusual certificate subjects or connection frequency.
- Consider adding a SHA256 allowlist for verified legitimate SoftEther binaries to suppress known-good executions.

**Risks / caveats:**
- ActionType value 'ConnectionSuccess' must be verified against the DeviceNetworkEvents ActionType enumeration in the target tenant; the correct value may be 'ConnectionSuccess' or differ by MDE version.
- Webworm may rename SoftEther binaries, bypassing the FileName-based filter entirely; hash-based detection would require known SHA256 values.
- Port 443 was removed from the network join to reduce noise; if Webworm exclusively uses port 443 for C2, the network correlation branch will miss it.
- The 10-minute join window between process start and network connection may miss delayed connection establishment.

### Triage Runbook

**First 15 minutes:**
- Identify the host, parent process, and command line for the SoftEther binary execution.
- Check whether the binary path is a known approved installation path or an unusual user-writable or temporary directory.
- Review the remote IP and port to determine whether the connection is external and whether it matches expected VPN infrastructure.
- Look for additional SoftEther-related processes or repeated connections from the same host.
- If the host is sensitive or the path is clearly abnormal, escalate for deeper investigation.

**Evidence to collect:**
- ProcTime, DeviceName, FileName, FolderPath, ProcessCommandLine, and InitiatingProcessFileName from the alert.
- NetTime, RemoteIP, and RemotePort for any correlated network activity.
- File hash information if available from endpoint telemetry or file inventory.
- User context and parent process lineage for the execution.
- Any installed software inventory or change records showing approved SoftEther use.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and FileName over the last 24 hours.
- DeviceNetworkEvents for the same DeviceId, RemoteIP, or RemotePort.
- DeviceFileEvents or file inventory to confirm the binary location and hash.
- DeviceLogonEvents or related endpoint telemetry to identify the user context.
- Asset and software inventory to confirm whether SoftEther is sanctioned on the host.

**Benign explanations:**
- A legitimate SoftEther VPN installation may run from a non-default path in a managed environment.
- Security testing or red-team activity may intentionally use SoftEther binaries.
- A lab, research, or remote support tool may reuse SoftEther components.
- Network-only matches on common VPN ports can reflect normal encrypted traffic rather than malicious activity.

**Escalation criteria:**
- The binary is running from a user-writable, temp, or otherwise unauthorized path.
- The remote IP is external and not associated with approved VPN infrastructure.
- The process is launched by an unusual parent process or under a suspicious user context.
- Multiple hosts show the same SoftEther pattern, suggesting broader deployment.

**Containment actions:**
- Isolate the host if the execution path, parent process, or network destination is clearly unauthorized.
- Terminate the suspicious process if it is confirmed to be malicious and business impact is acceptable.
- Block the external destination if it is confirmed to be a malicious C2 or unauthorized VPN endpoint.
- Collect the binary and preserve memory or disk evidence before cleanup.

**Closure criteria:**
- The SoftEther installation is verified as approved and the path is expected.
- The network destination is a sanctioned VPN endpoint or test infrastructure.
- No additional suspicious persistence, lateral movement, or unauthorized access is found.
- The alert is attributable to known administrative or security testing activity.

<br/>
---
<br/>

## Detection 4: CVE-2026-73571 - Zimbra Authenticated User Sending Mail as a Different Account

### Detection Opportunity

An authenticated Zimbra session user sends email where the envelope sender or From address differs from the authenticated account identity, indicating exploitation of the SaveDraftRequest authorization bypass.

### Intelligence Context

- Rapid7: Metasploit Wrap Up: Breaking Zimbra's Identity Boundaries — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-breaking-zimbra-s-identity-boundaries](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-breaking-zimbra-s-identity-boundaries)
  - Context: CVE-2026-73571 is an authorization bypass in Zimbra's SaveDraftRequest handling that allows an ordinary authenticated user to send mail as another user. The mismatch between the authenticated session identity and the envelope sender address is the primary detectable artifact.

### Search Metadata

- CVEs: CVE-2026-73571
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Zimbra
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-73571, Zimbra, Metasploit, T1190

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- The Syslog regex patterns (account=([^;]+) and from=<([^>]+)>) are derived from assumed Zimbra log format; if the deployed Zimbra version uses a different log format, both extract() calls return empty strings and the query produces no results.
- The CommonSecurityLog branch requires SourceUserName and DestinationUserName to be populated by the Zimbra connector; these fields are not populated by default Syslog forwarding and require a custom connector or CEF mapping.

**Required telemetry:**
- Syslog, CommonSecurityLog

### KQL

```kql
let lookback = 24h;
let syslogBranch =
    Syslog
    | where TimeGenerated >= ago(lookback)
    | where ProcessName has_any ("zimbra", "zmmailboxd")
    | where SyslogMessage has_any ("SendMsg", "saveDraft", "SendMsgRequest")
    | extend AuthUser = trim(@"\s", extract(@"account=([^;]+)", 1, SyslogMessage))
    | extend EnvelopeFrom = trim(@"\s", extract(@"from=<([^>]+)>", 1, SyslogMessage))
    | where isnotempty(AuthUser) and isnotempty(EnvelopeFrom)
    | where tolower(AuthUser) != tolower(EnvelopeFrom)
    | project
        TimeGenerated,
        Computer,
        ProcessName,
        AuthUser,
        EnvelopeFrom,
        SourceIP = "",
        SourceUserName = "",
        DestinationUserName = "",
        RequestURL = "",
        DeviceVendor = "",
        DeviceProduct = "",
        SyslogMessage;
let cslBranch =
    CommonSecurityLog
    | where TimeGenerated >= ago(lookback)
    | where DeviceProduct has "Zimbra"
    | where RequestURL has_any ("SaveDraftRequest", "SendMsgRequest")
    | where isnotempty(SourceUserName) and isnotempty(DestinationUserName)
    | where tolower(SourceUserName) != tolower(DestinationUserName)
    | project
        TimeGenerated,
        Computer = "",
        ProcessName = "",
        AuthUser = SourceUserName,
        EnvelopeFrom = DestinationUserName,
        SourceIP,
        SourceUserName,
        DestinationUserName,
        RequestURL,
        DeviceVendor,
        DeviceProduct,
        SyslogMessage = "";
syslogBranch
| union cslBranch
| project
    TimeGenerated,
    Computer,
    ProcessName,
    AuthUser,
    EnvelopeFrom,
    SourceIP,
    RequestURL,
    DeviceVendor,
    DeviceProduct,
    SyslogMessage
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate delegate-send configurations where one user is authorized to send on behalf of another will match the AuthUser != EnvelopeFrom condition.
- Shared mailbox or distribution list send-as configurations will generate matches.
- Mail relay or forwarding rules that rewrite the From address may produce mismatches.

**Tuning notes:**
- Validate the extract() regex patterns against raw SyslogMessage samples from the deployed Zimbra version before relying on AuthUser and EnvelopeFrom extractions.
- Build an exclusion list of known delegate-send account pairs and apply a where not(AuthUser in (knownDelegates)) filter.
- If the CommonSecurityLog connector does not populate DestinationUserName, consider parsing the target account from RequestURL or a custom field using extract().

**Risks / caveats:**
- The Syslog regex patterns (account=([^;]+) and from=<([^>]+)>) are derived from assumed Zimbra log format; if the deployed Zimbra version uses a different log format, both extract() calls return empty strings and the query produces no results.
- The CommonSecurityLog branch requires SourceUserName and DestinationUserName to be populated by the Zimbra connector; these fields are not populated by default Syslog forwarding and require a custom connector or CEF mapping.
- Zimbra Server Appliance does not have a native Microsoft Sentinel data connector; log ingestion depends on a custom syslog forwarder or CEF agent configuration.
- The Syslog regex patterns must be validated against the exact Zimbra log format version deployed; format differences between Zimbra 8.x and 9.x may require pattern adjustments.

### Triage Runbook

**First 15 minutes:**
- Confirm the authenticated account and the envelope sender or From address are truly different.
- Check whether the account has approved delegate, shared mailbox, or send-as permissions.
- Review the source IP, host, and timestamp for other suspicious Zimbra activity from the same session.
- Look for evidence of phishing, internal impersonation, or mailbox abuse using the mismatched identity.
- Escalate if the sender mismatch is not explained by an approved delegation relationship.

**Evidence to collect:**
- TimeGenerated, Computer, ProcessName, AuthUser, EnvelopeFrom, SourceIP, RequestURL, DeviceVendor, and DeviceProduct from the alert.
- Raw SyslogMessage or CommonSecurityLog entries showing the exact account and from fields.
- Mailbox permission records showing delegate or send-as relationships for the involved accounts.
- Message headers or mail logs for the affected email to confirm sender, recipient, and delivery path.
- Authentication logs for the same source IP and session around the alert time.

**Pivot points:**
- Syslog for the same Computer and source IP over the last 24 hours.
- CommonSecurityLog for Zimbra requests from the same SourceIP and RequestURL.
- Mailbox permission or directory records for send-as and delegate rights.
- Mail delivery logs and message trace for the suspicious message.
- Authentication logs for the same user and session to identify additional mailbox actions.

**Benign explanations:**
- A legitimate delegate-send or shared mailbox configuration can produce a sender mismatch.
- Mail relay, forwarding, or aliasing may rewrite the visible From address.
- Administrative or service accounts may send on behalf of multiple users.
- A custom connector or parsing issue could mis-extract the account fields and create a false mismatch.

**Escalation criteria:**
- The accounts have no documented send-as or delegate relationship.
- The same source IP shows additional suspicious mailbox actions or multiple mismatched sends.
- The message content, recipients, or timing suggest phishing, fraud, or impersonation.
- There is evidence of exploitation or unauthorized mailbox access beyond a single mismatched message.

**Containment actions:**
- Disable the affected session or revoke active authentication tokens if abuse is ongoing.
- Reset credentials for the implicated account if unauthorized access is confirmed.
- Temporarily restrict send-as or delegate permissions if they are being abused.
- Preserve message headers and logs before mailbox changes are made.

**Closure criteria:**
- A valid delegate, shared mailbox, or approved send-as relationship is confirmed.
- The mismatch is explained by a known relay, alias, or connector parsing issue.
- No additional suspicious messages or unauthorized mailbox actions are found.
- The event is documented as benign with supporting permission evidence.

<br/>
---
<br/>

## Detection 5: CVE-2026-73571 - HTTP POST to Zimbra SaveDraftRequest Endpoint with Cross-Account Activity

### Detection Opportunity

POST requests to the Zimbra SaveDraftRequest API endpoint from authenticated sessions where the request context indicates action on behalf of a different user account, consistent with the authorization bypass described in CVE-2026-73571.

### Intelligence Context

- Rapid7: Metasploit Wrap Up: Breaking Zimbra's Identity Boundaries — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-breaking-zimbra-s-identity-boundaries](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-breaking-zimbra-s-identity-boundaries)
  - Context: Metasploit modules were developed to exploit CVE-2026-73571, an authorization bypass in Zimbra's SaveDraftRequest handling. The exploit allows an authenticated user to craft requests that act on another user's mailbox. Detecting anomalous POST volume or cross-account targeting via this endpoint provides a network-visible signal.

### Search Metadata

- CVEs: CVE-2026-73571
- Threat actors: Not specified
- ATT&CK tags: T1190
- Products: Zimbra
- Platforms: Not specified
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-73571, Zimbra, Metasploit, T1190

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (medium)

### Deployment Gates

- If DestinationUserName is not populated by the Zimbra connector, the isnotempty filter will suppress all rows and the query will return no results without any error indication.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
let lookback = 24h;
let threshold = 3;
CommonSecurityLog
| where TimeGenerated >= ago(lookback)
| where (DeviceProduct has "Zimbra" or RequestURL has "SaveDraftRequest")
| where RequestMethod == "POST"
| where RequestURL has "SaveDraftRequest"
| where tostring(ResponseCode) == "200"
| where isnotempty(DestinationUserName)
| summarize
    RequestCount = count(),
    DistinctTargetUsers = dcount(DestinationUserName),
    TargetUsers = make_set(DestinationUserName),
    SourceUsers = make_set(SourceUserName),
    UserAgents = make_set(UserAgent)
    by SourceIP, bin(TimeGenerated, 1h)
| where DistinctTargetUsers >= threshold
| project
    TimeGenerated,
    SourceIP,
    RequestCount,
    DistinctTargetUsers,
    TargetUsers,
    SourceUsers,
    UserAgents
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Batch mail processing systems or mail migration tools that POST to SaveDraftRequest for multiple accounts will exceed the threshold.
- Shared infrastructure such as mail gateways or archiving appliances may generate multi-account POST patterns.
- Automated testing or monitoring tools that probe the SaveDraftRequest endpoint will match.

**Tuning notes:**
- Verify DestinationUserName is populated in CommonSecurityLog Zimbra entries before relying on this detection.
- Adjust the DistinctTargetUsers threshold above 3 if batch mail systems legitimately POST to SaveDraftRequest for multiple accounts within an hour.
- If Metasploit user-agent strings become known, add a where UserAgent has_any (knownMetasploitAgents) branch as a high-confidence supplementary signal.

**Risks / caveats:**
- DestinationUserName must be populated by the Zimbra connector for the dcount(DestinationUserName) aggregation to produce meaningful cross-account signals; if this field is empty, all requests appear to target zero distinct users and the threshold filter suppresses all results.
- ResponseCode in CommonSecurityLog may be stored as a string or integer depending on the connector; the comparison ResponseCode == 200 may fail silently if the field type is string.
- If DestinationUserName is not populated by the Zimbra connector, the isnotempty filter will suppress all rows and the query will return no results without any error indication.
- The threshold of 3 distinct target users per hour is a starting assumption; legitimate batch systems may require a higher threshold.

### Triage Runbook

**First 15 minutes:**
- Confirm the source IP and user agent are not associated with approved mail migration, testing, or automation.
- Review the number of distinct target users and whether the same source IP is touching multiple accounts in a short period.
- Check whether the requests are successful and whether the affected accounts show unusual draft or send activity.
- Correlate with authentication logs to identify the authenticated user driving the requests.
- Escalate immediately if the activity spans multiple accounts without a business explanation.

**Evidence to collect:**
- TimeGenerated, SourceIP, RequestCount, DistinctTargetUsers, TargetUsers, SourceUsers, and UserAgents from the alert.
- Raw CommonSecurityLog entries for the SaveDraftRequest POSTs, including RequestURL, RequestMethod, and ResponseCode.
- Authentication logs for the same SourceIP and any associated user sessions.
- Mailbox audit or message trace data for the target accounts.
- Any change tickets or migration records that could explain bulk SaveDraftRequest activity.

**Pivot points:**
- CommonSecurityLog for the same SourceIP and RequestURL over the last 24 hours.
- Authentication or SSO logs for the same source IP and time window.
- Mailbox audit logs for the listed target users.
- Message trace or delivery logs to see whether drafts were later sent.
- Proxy or firewall logs to identify whether the source is a migration tool, gateway, or user workstation.

**Benign explanations:**
- Mail migration, archiving, or synchronization tools may legitimately touch multiple accounts.
- A shared mail gateway or automation platform may generate repeated SaveDraftRequest traffic.
- Testing or QA activity may produce multi-account POST patterns.
- Connector parsing may overcount target users if the field mapping is imperfect.

**Escalation criteria:**
- The source IP is not tied to an approved automation, migration, or admin function.
- Multiple distinct target users are affected and no business process explains the activity.
- The same source IP also shows suspicious authentication or mailbox manipulation.
- There is evidence of unauthorized draft creation, message sending, or account impersonation.

**Containment actions:**
- Block the source IP if it is confirmed malicious and not part of an approved service.
- Revoke or reset the authenticated account if abuse is tied to a user session.
- Suspend or review affected mailbox permissions if cross-account access is confirmed.
- Preserve logs and message evidence before making mailbox changes.

**Closure criteria:**
- The source IP is identified as an approved migration, gateway, or automation system.
- The activity is explained by a documented maintenance or testing workflow.
- No unauthorized mailbox actions or suspicious follow-on activity are found.
- The alert is attributable to connector behavior or expected bulk processing and is documented.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- CVE-2026-123890 - Unauthenticated Access to VMware vCenter Management Endpoint: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, SecurityEvent before scheduling.
- CVE-2026-123890 - Unexpected Administrator Logon to VMware vCenter Host: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.
- CVE-2026-73571 - Zimbra Authenticated User Sending Mail as a Different Account: The CommonSecurityLog branch requires SourceUserName and DestinationUserName to be populated by the Zimbra connector; these fields are not populated by default Syslog forwarding and require a custom connector or CEF mapping.
- CVE-2026-73571 - HTTP POST to Zimbra SaveDraftRequest Endpoint with Cross-Account Activity: If DestinationUserName is not populated by the Zimbra connector, the isnotempty filter will suppress all rows and the query will return no results without any error indication.

**Schema / correlation keys:**
- Webworm - SoftEther VPN Process Execution from Non-Standard Path or with Suspicious Network Connections: Do not schedule yet; validate as an analyst-led hunt first.

**Other deployment dependency:**
- CVE-2026-73571 - Zimbra Authenticated User Sending Mail as a Different Account: The Syslog regex patterns (account=([^;]+) and from=<([^>]+)>) are derived from assumed Zimbra log format; if the deployed Zimbra version uses a different log format, both extract() calls return empty strings and the query produces no results.

**Shared-table notes:**
- CommonSecurityLog: shared by CVE-2026-123890 - Unauthenticated Access to VMware vCenter Management Endpoint; CVE-2026-73571 - Zimbra Authenticated User Sending Mail as a Different Account; CVE-2026-73571 - HTTP POST to Zimbra SaveDraftRequest Endpoint with Cross-Account Activity
- SecurityEvent: shared by CVE-2026-123890 - Unauthenticated Access to VMware vCenter Management Endpoint; CVE-2026-123890 - Unexpected Administrator Logon to VMware vCenter Host

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: CVE-2026-123890 - Unauthenticated Access to VMware vCenter Management Endpoint; CVE-2026-123890 - Unexpected Administrator Logon to VMware vCenter Host; CVE-2026-73571 - Zimbra Authenticated User Sending Mail as a Different Account; CVE-2026-73571 - HTTP POST to Zimbra SaveDraftRequest Endpoint with Cross-Account Activity.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Webworm - SoftEther VPN Process Execution from Non-Standard Path or with Suspicious Network Connections.

### Hunting Agenda and Promotion Criteria

- Webworm - SoftEther VPN Process Execution from Non-Standard Path or with Suspicious Network Connections: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- CVE-2026-123890 - Unauthenticated Access to VMware vCenter Management Endpoint: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, SecurityEvent before scheduling.; prove correlation keys join correctly on real tenant telemetry.
- CVE-2026-123890 - Unexpected Administrator Logon to VMware vCenter Host: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- CVE-2026-73571 - Zimbra Authenticated User Sending Mail as a Different Account: The Syslog regex patterns (account=([^;]+) and from=<([^>]+)>) are derived from assumed Zimbra log format; if the deployed Zimbra version uses a different log format, both extract() calls return empty strings and the query produces no results.; baseline expected benign activity and define an alert-volume threshold.
- CVE-2026-73571 - HTTP POST to Zimbra SaveDraftRequest Endpoint with Cross-Account Activity: If DestinationUserName is not populated by the Zimbra connector, the isnotempty filter will suppress all rows and the query will return no results without any error indication.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
