---
layout: post
title: "Detection Engineering Brief - Thursday, September 3, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-03
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-83548
  - CVE-2026-83549
  - T1190
  - T1059
  - SonicWall SMA1000
  - SMA1000 Appliance Work Place
  - Appliance Management Console
  - T1566
  - T1219
  - Microsoft Teams
  - Microsoft Defender XDR
  - Node.js
  - T1189
  - T1204
  - Windows
  - T1021
  - T1204.002
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

2 production candidates, 1 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-83548, CVE-2026-83549, T1190, T1059, SonicWall SMA1000, SMA1000 Appliance Work Place, Appliance Management Console, T1566, T1219, Microsoft Teams, Microsoft Defender XDR, Node.js, T1189, T1204, Windows, T1021, T1204.002.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: SonicWall SMA1000 Chained RCE - Perimeter Hit Correlated with Downstream Lateral Movement; IT Support Impersonation via Teams External Collaboration Followed by Node.js Implant Execution; Lateral Movement via Legitimate Tools Following Remote Session Established After Teams IT Impersonation.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: SonicWall SMA1000 Chained RCE - Perimeter Hit Correlated with Downstream Lateral Movement

### Detection Opportunity

Unauthenticated RCE via chained CVE-2026-83548 SSRF and CVE-2026-83549 command injection on SonicWall SMA1000, followed by downstream lateral movement from the same external source IP.

### Intelligence Context

- Rapid7: Critical SonicWall SMA1000 Vulnerabilities CVE-2026-83548, CVE-2026-83549 Exploited in the Wild — [https://www.rapid7.com/blog/post/etr-critical-sonicwall-sma1000-vulnerabilities-cve-2026-83548-cve-2026-83549-exploited-in-the-wild](https://www.rapid7.com/blog/post/etr-critical-sonicwall-sma1000-vulnerabilities-cve-2026-83548-cve-2026-83549-exploited-in-the-wild)
  - Context: Rapid7 confirmed active exploitation of CVE-2026-83548 (pre-auth SSRF on Work Place interface) chained with CVE-2026-83549 (OS command injection on AMC) to achieve unauthenticated RCE. Post-exploitation lateral movement from the same external IP is the compound signal targeted here.

### Search Metadata

- CVEs: CVE-2026-83548, CVE-2026-83549
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059, T1021
- Products: SonicWall SMA1000, SMA1000 Appliance Work Place, Appliance Management Console
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-83548, CVE-2026-83549, T1190, T1059, SonicWall SMA1000, SMA1000 Appliance Work Place, Appliance Management Console, T1021

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Both
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter (high); Lateral Movement: T1021 Remote Services (medium)

### Deployment Gates

- CommonSecurityLog requires a SonicWall SMA1000 CEF/syslog connector to be configured and actively forwarding logs; if absent the sonicwallHits subquery returns no rows and the entire detection produces no results.

**Required telemetry:**
- CommonSecurityLog, DeviceNetworkEvents

### KQL

```kql
let lookback = 24h;
let correlationWindow = 60min;
let sonicwallHits =
    CommonSecurityLog
    | where TimeGenerated >= ago(lookback)
    | where DeviceVendor =~ "SonicWall" and DeviceProduct has "SMA1000"
    | where isnotempty(SourceIP)
    | where not(ipv4_is_private(SourceIP))
    | summarize FirstHit = min(TimeGenerated), LastHit = max(TimeGenerated),
        Activities = make_set(Activity, 20),
        Messages = make_set(Message, 10)
        by SourceIP;
let lateralMovement =
    DeviceNetworkEvents
    | where TimeGenerated >= ago(lookback)
    | where ActionType in ("ConnectionSuccess", "InboundConnectionAccepted")
    | where isnotempty(RemoteIP)
    | where not(ipv4_is_private(RemoteIP))
    | project TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessCommandLine, ActionType;
sonicwallHits
| join kind=inner (
    lateralMovement
) on $left.SourceIP == $right.RemoteIP
| where TimeGenerated between (FirstHit .. (FirstHit + correlationWindow))
| summarize
    LateralMoveFirstSeen = min(TimeGenerated),
    LateralMoveLastSeen = max(TimeGenerated),
    AffectedDevices = make_set(DeviceName, 20),
    ObservedPorts = make_set(RemotePort, 20),
    ObservedProcesses = make_set(InitiatingProcessCommandLine, 10),
    ObservedActions = make_set(ActionType, 10)
    by SourceIP, FirstHit, LastHit, Activities, Messages
| project
    SonicWallFirstHit = FirstHit,
    SonicWallLastHit = LastHit,
    AttackerIP = SourceIP,
    LateralMoveFirstSeen,
    LateralMoveLastSeen,
    AffectedDevices,
    ObservedPorts,
    ObservedProcesses,
    ObservedActions,
    SonicWallActivities = Activities,
    SonicWallMessages = Messages
| order by SonicWallFirstHit asc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Shared egress IPs such as large ISP NAT pools or cloud provider egress ranges may appear in both the SonicWall hit set and DeviceNetworkEvents RemoteIP, producing false correlations.
- Legitimate external vendors or partners whose IPs appear in SonicWall logs and also initiate connections to internal hosts via VPN or direct peering.
- Security scanners or threat intelligence platforms that probe the SMA1000 and also connect to internal honeypots or monitoring infrastructure.

**Tuning notes:**
- Adjust correlationWindow based on observed attacker dwell time in your environment; increase to 4h or 8h for slower campaigns.
- Add a DestinationIP filter in the CommonSecurityLog subquery scoped to the specific SMA1000 appliance IP(s) to reduce noise from other SonicWall devices forwarding to the same workspace.
- Consider adding an allowlist of known external scanner IPs or partner IPs to exclude from AttackerIP before the join.

**Risks / caveats:**
- CommonSecurityLog requires a SonicWall SMA1000 CEF/syslog connector to be configured and actively forwarding logs; if absent the sonicwallHits subquery returns no rows and the entire detection produces no results.
- DeviceVendor and DeviceProduct field values are connector-dependent and may differ from 'SonicWall' and 'SMA1000' depending on the CEF mapping used by the appliance firmware version.
- DeviceNetworkEvents ActionType values 'ConnectionSuccess' and 'InboundConnectionAccepted' are Defender for Endpoint schema values; if MDE is not deployed on internal hosts this table will be empty for those devices.
- The 60-minute correlation window may miss slow-and-low attackers who delay lateral movement beyond one hour after the initial perimeter hit.

### Triage Runbook

**First 15 minutes:**
- Confirm the SonicWall event is on the SMA1000 appliance and not another SonicWall device or a management/test system.
- Review the first and last hit times, attacker IP, activities, and messages to see whether the appliance logged SSRF, command injection, or RCE-like behavior.
- Check the correlated internal hosts and ports to determine whether the same source IP immediately followed the perimeter hit with SMB, RDP, WinRM, SSH, or other remote-service activity.
- Validate whether the source IP is a true external address or a shared egress/NAT/proxy address that could create a false correlation.
- Identify the affected internal device owners and determine whether any admin or vendor activity was expected during the alert window.

**Evidence to collect:**
- CommonSecurityLog entries for the attacker IP, including Activity, Message, SourceIP, destination appliance, and exact timestamps.
- DeviceNetworkEvents for the correlated internal hosts, including RemoteIP, RemotePort, ActionType, InitiatingProcessCommandLine, and DeviceName.
- Any additional logs from the SMA1000 appliance showing authentication failures, session creation, or unusual management actions around the same time.
- Host telemetry from the affected internal devices to identify the initiating process and whether the connection was user-driven, service-driven, or suspicious.
- A list of all internal hosts contacted by the same source IP within the correlation window.

**Pivot points:**
- CommonSecurityLog filtered on SourceIP, DeviceVendor, and DeviceProduct containing SMA1000.
- DeviceNetworkEvents filtered on RemoteIP equal to the attacker IP and ActionType in ConnectionSuccess or InboundConnectionAccepted.
- DeviceProcessEvents on the affected hosts to identify the process that initiated the downstream connections.
- If available, DeviceLogonEvents or identity logs for any logons from the affected hosts during the same window.
- Firewall or proxy logs to confirm whether the same external IP touched other internal services.

**Benign explanations:**
- A legitimate external vendor or partner IP that also appears in internal connectivity logs due to VPN, peering, or remote support.
- A security scanner or threat-intelligence platform probing the SMA1000 and later connecting to internal lab or honeypot systems.
- A shared cloud or ISP NAT address causing unrelated perimeter and internal events to correlate by IP only.
- Planned maintenance or admin activity on the SMA1000 appliance that generated unusual logs but no real exploitation.

**Escalation criteria:**
- The same external IP is confirmed to have triggered suspicious SMA1000 activity and then connected to multiple internal hosts within the window.
- Internal hosts show suspicious processes, new services, or unusual logons associated with the correlated connections.
- The appliance logs indicate command injection, SSRF chaining, or other exploit indicators rather than routine access.
- The source IP is not attributable to a known scanner, vendor, or internal NAT/proxy source.

**Containment actions:**
- Block the attacker IP at the perimeter if it is confirmed external and not a shared or business-critical address.
- Isolate affected internal hosts if they show signs of compromise or if the same source IP is actively reaching multiple systems.
- Disable or restrict SMA1000 exposure temporarily if exploitation is ongoing and the appliance cannot be quickly patched or validated.
- Preserve appliance and endpoint logs before rebooting or making configuration changes.

**Closure criteria:**
- The source IP is validated as benign, such as a known scanner, vendor, or shared NAT address, and no suspicious internal activity is found.
- The SMA1000 logs do not show exploit behavior and the downstream connections are explained by normal administration or maintenance.
- No suspicious processes, logons, or persistence are found on the correlated internal hosts.
- The alert is documented with the confirmed benign source and the detection is tuned if needed.

<br/>
---
<br/>

## Detection 2: IT Support Impersonation via Teams External Collaboration Followed by Node.js Implant Execution

### Detection Opportunity

External Teams user impersonating IT support contacts an internal user, remote access is granted, and a Node.js-based implant is subsequently executed on the victim host.

### Intelligence Context

- Microsoft Security Blog: Impersonating IT support: how threat actors turn a remote session into enterprise-wide access — [https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/](https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/)
  - Context: Microsoft documented a campaign where attackers abused Teams external collaboration to impersonate IT support, convinced users to grant remote access, then deployed a Node.js-based implant. The compound signal is a Teams external message with IT-themed display names correlated with node.exe execution on the same user's device within a short window.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1566, T1219, T1059, T1021
- Products: Microsoft Teams, Microsoft Defender XDR
- Platforms: Node.js
- Malware: Not specified
- Tools: Not specified
- Search tags: T1566, T1219, T1059, Microsoft Teams, Microsoft Defender XDR, Node.js, T1021

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Both
- Analytic type: correlation
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1566 Phishing (medium); Remote Services: T1219 Remote Access Software (high); Lateral Movement: T1021 Remote Services (medium)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Both: OfficeActivity, DeviceProcessEvents, DeviceNetworkEvents before scheduling.

**Required telemetry:**
- OfficeActivity, DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let lookback = 48h;
let implantWindow = 2h;
let networkWindow = 30min;
let itKeywords = dynamic(["it support", "helpdesk", "help desk", "it helpdesk", "tech support", "it admin", "sysadmin"]);
let suspiciousNodeParents = dynamic(["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "explorer.exe"]);
let teamsExternalIT =
    OfficeActivity
    | where TimeGenerated >= ago(lookback)
    | where RecordType =~ "MicrosoftTeams"
    | where Operation in ("MessageCreatedHasLink", "MessageCreated", "ChatCreated")
    | where ExternalAccess == true
    | extend SenderRaw = tostring(parse_json(AdditionalProperties)["MessageSender"])
    | extend SenderDisplay = tostring(parse_json(SenderRaw)["DisplayName"])
    | where isnotempty(SenderDisplay)
    | where SenderDisplay has_any (itKeywords)
    | extend UPNPrefix = tolower(split(UserId, "@")[0])
    | project TeamsEventTime = TimeGenerated, RecipientUPN = UserId, UPNPrefix, SenderDisplay;
let nodeImplant =
    DeviceProcessEvents
    | where TimeGenerated >= ago(lookback)
    | where FileName =~ "node.exe"
    | where InitiatingProcessFileName has_any (suspiciousNodeParents)
    | extend AccountLower = tolower(AccountName)
    | project NodeTime = TimeGenerated, DeviceName, AccountName, AccountLower, ProcessCommandLine, InitiatingProcessFileName, FolderPath, SHA256;
let nodeNetwork =
    DeviceNetworkEvents
    | where TimeGenerated >= ago(lookback)
    | where InitiatingProcessFileName =~ "node.exe"
    | where isnotempty(RemoteIP)
    | where not(ipv4_is_private(RemoteIP))
    | project NetTime = TimeGenerated, DeviceName, RemoteIP, RemoteUrl;
let implantWithNetwork =
    nodeImplant
    | join kind=leftouter (
        nodeNetwork
    ) on DeviceName
    | where NetTime between (NodeTime .. (NodeTime + networkWindow))
    | summarize
        OutboundConnections = count(),
        RemoteIPs = make_set(RemoteIP, 10),
        RemoteUrls = make_set(RemoteUrl, 10)
        by NodeTime, DeviceName, AccountName, AccountLower, ProcessCommandLine, InitiatingProcessFileName, FolderPath, SHA256;
teamsExternalIT
| join kind=inner (
    implantWithNetwork
) on $left.UPNPrefix == $left.UPNPrefix
| join kind=inner (
    implantWithNetwork
) on $left.UPNPrefix == $right.AccountLower
| where NodeTime between (TeamsEventTime .. (TeamsEventTime + implantWindow))
| project
    TeamsContactTime = TeamsEventTime,
    RecipientUPN,
    SenderDisplay,
    NodeExecutionTime = NodeTime,
    DeviceName,
    NodeCommandLine = ProcessCommandLine,
    NodeParent = InitiatingProcessFileName,
    NodePath = FolderPath,
    NodeSHA256 = SHA256,
    OutboundConnections,
    RemoteIPs,
    RemoteUrls
| order by TeamsContactTime asc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Developers who receive external Teams messages from vendors and also run node.exe for legitimate development work within the same 2-hour window.
- IT administrators who use Teams external collaboration legitimately and run Node.js-based automation tools.
- Shared AccountName values where multiple users share a SAM account prefix across different UPNs in multi-domain environments.

**Tuning notes:**
- Validate the AdditionalProperties JSON path for SenderDisplay by running: OfficeActivity → where RecordType =~ 'MicrosoftTeams' and ExternalAccess == true → extend raw = tostring(parse_json(AdditionalProperties)) → take 10
- If SAM account names in your tenant do not match UPN prefixes, replace the UPNPrefix join with a lookup against an identity table or IdentityInfo table available in Defender XDR.
- Expand itKeywords based on observed attacker display name patterns discovered during incident review.
- Consider adding an allowlist of known external vendor UPN domains to exclude from the ExternalAccess filter.

**Risks / caveats:**
- OfficeActivity ExternalAccess field is only populated when the Microsoft 365 unified audit log Teams connector is enabled and the tenant has external access or guest access configured; if absent all rows will have ExternalAccess == false and the teamsExternalIT subquery returns no rows.
- The nested JSON path parse_json(AdditionalProperties).MessageSender.DisplayName is not a documented stable field in the OfficeActivity Teams schema and may be absent or differently structured depending on the Teams audit log version.
- OfficeActivity RecordType for Teams messages uses the integer value 25 in some tenants rather than the string 'MicrosoftTeams'; the string comparison may fail silently depending on the connector version.
- DeviceNetworkEvents nodeNetwork join uses bin(TimeGenerated, 5m) as a join key alongside DeviceName, which does not guarantee temporal alignment with the node implant execution time and may produce incorrect or missing network enrichment.

### Triage Runbook

**First 15 minutes:**
- Identify the recipient user, sender display name, and exact Teams message timing to confirm the external collaboration event.
- Contact the user or their manager through an out-of-band channel to verify whether they interacted with the sender or granted remote access.
- Review the node.exe process details, including command line, parent process, folder path, and SHA256, to determine whether it is a legitimate developer or automation tool.
- Check whether the node.exe execution occurred shortly after the Teams contact and whether the parent process is one of the suspicious remote-access or shell parents.
- Look for immediate outbound connections from the same host to unknown external IPs or URLs.

**Evidence to collect:**
- OfficeActivity records for the Teams message, including ExternalAccess, UserId, SenderDisplay, and TeamsContactTime.
- DeviceProcessEvents for node.exe, including NodeExecutionTime, NodeCommandLine, NodeParent, NodePath, and NodeSHA256.
- DeviceNetworkEvents for outbound connections from node.exe, including RemoteIP, RemoteUrl, and connection timing.
- Any remote support tool logs or screen-sharing records if the user reports granting access.
- Identity or mailbox activity around the same time to see whether the account was used for other suspicious actions.

**Pivot points:**
- OfficeActivity filtered on the recipient UPN and sender display name.
- DeviceProcessEvents filtered on node.exe, parent process, and suspicious folder paths such as AppData or Temp.
- DeviceNetworkEvents filtered on node.exe and non-private RemoteIP values.
- IdentityInfo or equivalent identity table to map UPN to SAM account names if needed.
- Microsoft Defender XDR incident timeline for related alerts on the same host or user.

**Benign explanations:**
- A legitimate external vendor or consultant using Teams external collaboration and the user also running node.exe for development work.
- An IT administrator legitimately using remote support and Node.js-based automation on the same endpoint.
- A developer workstation where node.exe is expected and the parent process is a normal shell or IDE.
- A false correlation caused by account-name normalization issues or shared SAM prefixes.

**Escalation criteria:**
- The user confirms they granted remote access to an external Teams contact posing as IT support.
- node.exe is launched from an unusual path or by a suspicious parent process and makes outbound connections to unknown infrastructure.
- The host shows additional suspicious activity such as credential prompts, new persistence, or other post-execution behavior.
- Multiple users or hosts show the same sender display name or related remote-access pattern.

**Containment actions:**
- Disable or suspend the affected user account if compromise is likely and the account is not required for immediate business operations.
- Isolate the endpoint if node.exe behavior or outbound connections indicate active malicious activity.
- Revoke active Teams sessions and reset credentials if the user granted remote access or entered credentials into a suspicious session.
- Block suspicious outbound destinations observed from the host if they are confirmed malicious.

**Closure criteria:**
- The Teams contact is verified as a legitimate vendor or internal support interaction and node.exe is confirmed as expected software.
- No suspicious outbound connections, parent processes, or file paths are found for node.exe.
- The user did not grant remote access and no additional suspicious activity is present on the host.
- The alert is documented with the validated benign explanation and any necessary tuning feedback.

<br/>
---
<br/>

## Detection 3: Node.js Implant Spawned by Remote Access Tool with Outbound C2 Connection

### Detection Opportunity

After remote access is obtained via IT support impersonation, a Node.js-based implant is executed from an unusual parent process and establishes outbound network connections consistent with C2 activity.

### Intelligence Context

- Microsoft Security Blog: Impersonating IT support: how threat actors turn a remote session into enterprise-wide access — [https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/](https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/)
  - Context: Microsoft reported that after remote access was granted to the impersonating attacker, a Node.js-based implant was deployed. The implant execution from a remote session tool parent process combined with immediate outbound connections is the high-confidence signal described in the reporting.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1566, T1219, T1059, T1021
- Products: Microsoft Teams, Microsoft Defender XDR
- Platforms: Node.js
- Malware: Not specified
- Tools: Not specified
- Search tags: T1566, T1219, T1059, Microsoft Teams, Microsoft Defender XDR, Node.js, T1021

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1566 Phishing (medium); Remote Services: T1219 Remote Access Software (high); Lateral Movement: T1021 Remote Services (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let lookback = 24h;
let networkWindow = 5min;
let remoteAccessParents = dynamic(["quickassist.exe", "msra.exe", "anydesk.exe", "teamviewer.exe", "screenconnect.exe", "rustdesk.exe", "atera_agent.exe", "splashtop.exe"]);
let nodeProcs =
    DeviceProcessEvents
    | where TimeGenerated >= ago(lookback)
    | where FileName =~ "node.exe"
    | where InitiatingProcessFileName has_any (remoteAccessParents)
    | project NodeStartTime = TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, FolderPath, SHA256, ProcessId;
let nodeConns =
    DeviceNetworkEvents
    | where TimeGenerated >= ago(lookback)
    | where InitiatingProcessFileName =~ "node.exe"
    | where ActionType == "ConnectionSuccess"
    | where not(ipv4_is_private(RemoteIP))
    | where isnotempty(RemoteIP)
    | project ConnTime = TimeGenerated, DeviceName, RemoteIP, RemoteUrl, RemotePort;
nodeProcs
| join kind=inner (
    nodeConns
) on DeviceName
| where ConnTime between (NodeStartTime .. (NodeStartTime + networkWindow))
| summarize
    FirstC2ConnTime = min(ConnTime),
    C2ConnectionCount = count(),
    RemoteIPs = make_set(RemoteIP, 20),
    RemoteUrls = make_set(RemoteUrl, 20),
    RemotePorts = make_set(RemotePort, 20)
    by NodeStartTime, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, FolderPath, SHA256
| project
    NodeStartTime,
    DeviceName,
    AccountName,
    NodeCommandLine = ProcessCommandLine,
    NodeParent = InitiatingProcessFileName,
    NodePath = FolderPath,
    NodeSHA256 = SHA256,
    FirstC2ConnTime,
    C2ConnectionCount,
    RemoteIPs,
    RemoteUrls,
    RemotePorts
| order by NodeStartTime asc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate remote IT administration sessions where an administrator uses a remote access tool and then runs a Node.js-based automation or monitoring script.
- Software deployment pipelines that use remote access tools to push Node.js applications and the application immediately phones home to a legitimate update server.
- Security tools that use node.exe and are launched via remote management frameworks.

**Tuning notes:**
- Extend remoteAccessParents with additional remote support utilities observed in your environment's software inventory.
- If node.exe renaming is suspected, add a SHA256 allowlist of known-good node.exe hashes and alert on node.exe executions whose SHA256 is not in the allowlist.
- Consider adding FolderPath filters to flag node.exe running from unusual paths such as AppData or Temp directories.

**Risks / caveats:**
- InitiatingProcessId in DeviceNetworkEvents is typed as string in some MDE schema versions; the tolong() cast in the original query may silently produce nulls if the field is already long or if the cast fails on non-numeric values. Removed the cast in the improved query and joined on DeviceName plus time window instead of ProcessId to avoid this risk.
- ActionType value 'ConnectionSuccess' must be present in the tenant's DeviceNetworkEvents; verify with: DeviceNetworkEvents → where ActionType == 'ConnectionSuccess' → take 1
- The remoteAccessParents list covers tools documented in the campaign report; attackers may use unlisted remote access tools, reducing recall.
- If node.exe is renamed by the attacker, the FileName and InitiatingProcessFileName filters will not match.

### Triage Runbook

**First 15 minutes:**
- Identify the remote access tool parent process and confirm whether it is approved in the environment.
- Review the node.exe command line, folder path, account name, and SHA256 to determine whether the binary is expected.
- Check the outbound RemoteIP, RemoteUrl, and RemotePort values to see whether the host contacted unknown or suspicious infrastructure.
- Determine whether the connection occurred within minutes of node.exe start and whether multiple outbound destinations were contacted.
- Verify whether the endpoint was being remotely administered by IT at the time of the alert.

**Evidence to collect:**
- DeviceProcessEvents for the node.exe process, including NodeStartTime, NodeCommandLine, NodeParent, NodePath, and NodeSHA256.
- DeviceNetworkEvents for node.exe outbound connections, including FirstC2ConnTime, RemoteIPs, RemoteUrls, and RemotePorts.
- Remote access tool logs or session records showing who initiated the session and from where.
- Endpoint telemetry for any follow-on processes, persistence, or credential access activity.
- User and asset context to determine whether the host is a developer machine, admin workstation, or standard user endpoint.

**Pivot points:**
- DeviceProcessEvents filtered on node.exe and remote-access parent processes such as quickassist.exe, anydesk.exe, teamviewer.exe, or screenconnect.exe.
- DeviceNetworkEvents filtered on node.exe with ConnectionSuccess and non-private RemoteIP values.
- DeviceFileEvents for the node.exe binary or related dropped files in AppData, Temp, or user profile paths.
- Microsoft Defender XDR incident timeline for related alerts on the same device or account.
- Remote support platform audit logs if available.

**Benign explanations:**
- A legitimate IT support session where an administrator used a remote tool and then launched Node.js automation.
- A software deployment or update workflow that uses node.exe and immediately reaches a vendor update server.
- A developer or automation workstation where node.exe is commonly launched from a remote session.
- A known remote support tool that is approved and routinely used on the endpoint.

**Escalation criteria:**
- The remote access parent is not approved or cannot be explained by the user or IT staff.
- node.exe is running from an unusual path, has a suspicious hash, or is followed by outbound connections to unknown external infrastructure.
- The host shows additional suspicious processes, persistence, or credential-related activity.
- The same remote access pattern appears on multiple endpoints or accounts.

**Containment actions:**
- Isolate the endpoint if the node.exe process or outbound connections are confirmed suspicious.
- Terminate the remote session and disable the remote access tool if it is unauthorized.
- Block the suspicious RemoteIP or RemoteUrl if confirmed malicious.
- Preserve process, network, and remote-session evidence before remediation.

**Closure criteria:**
- The remote access session is confirmed authorized and node.exe activity matches normal administrative or development use.
- Outbound connections are to known vendor or internal update infrastructure and no other suspicious behavior is present.
- The node.exe hash, path, and parent process are consistent with approved software.
- The alert is documented as benign with supporting evidence.

<br/>
---
<br/>

## Detection 4: Lateral Movement via Legitimate Tools Following Remote Session Established After Teams IT Impersonation

### Detection Opportunity

After a remote session is established following Teams-based IT support impersonation, legitimate living-off-the-land tools are used to authenticate to additional internal hosts within a short time window.

### Intelligence Context

- Microsoft Security Blog: Impersonating IT support: how threat actors turn a remote session into enterprise-wide access — [https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/](https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/)
  - Context: Microsoft described attackers moving from social engineering through remote session tools to lateral movement using legitimate tools, turning a single compromised endpoint into enterprise-wide access. This detection chains remote tool execution with subsequent network logons to new hosts.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1566, T1219, T1059, T1021
- Products: Microsoft Teams, Microsoft Defender XDR
- Platforms: Node.js
- Malware: Not specified
- Tools: Not specified
- Search tags: T1566, T1219, T1059, Microsoft Teams, Microsoft Defender XDR, Node.js, T1021

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1566 Phishing (medium); Remote Services: T1219 Remote Access Software (high); Lateral Movement: T1021 Remote Services (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents, DeviceLogonEvents

### KQL

```kql
let lookback = 24h;
let lateralWindow = 30min;
let logonWindow = 10min;
let remoteAccessTools = dynamic(["quickassist.exe", "msra.exe", "anydesk.exe", "teamviewer.exe", "screenconnect.exe", "rustdesk.exe"]);
let lateralPorts = dynamic(["445", "135", "139"]);
let remoteSessionDevices =
    DeviceProcessEvents
    | where TimeGenerated >= ago(lookback)
    | where FileName has_any (remoteAccessTools)
    | summarize SessionStart = min(TimeGenerated) by DeviceName, AccountName;
let outboundLateral =
    DeviceNetworkEvents
    | where TimeGenerated >= ago(lookback)
    | where ActionType == "ConnectionSuccess"
    | where tostring(RemotePort) in (lateralPorts)
    | where ipv4_is_private(RemoteIP)
    | project ConnTime = TimeGenerated, SourceDevice = DeviceName, RemoteIP, RemotePort = tostring(RemotePort);
let networkLogons =
    DeviceLogonEvents
    | where TimeGenerated >= ago(lookback)
    | where LogonType == "Network"
    | where ActionType == "LogonSuccess"
    | where isnotempty(RemoteDeviceName)
    | project LogonTime = TimeGenerated, LogonDevice = DeviceName, LogonAccount = AccountName, RemoteDeviceName;
remoteSessionDevices
| join kind=inner (
    outboundLateral
) on $left.DeviceName == $right.SourceDevice
| where ConnTime between (SessionStart .. (SessionStart + lateralWindow))
| join kind=inner (
    networkLogons
) on $left.SourceDevice == $right.RemoteDeviceName
| where LogonTime between (ConnTime .. (ConnTime + logonWindow))
| project
    RemoteSessionStart = SessionStart,
    OriginDevice = DeviceName,
    AccountName,
    LateralConnTime = ConnTime,
    TargetIP = RemoteIP,
    TargetPort = RemotePort,
    LogonTime,
    LogonTargetDevice = LogonDevice,
    LogonAccount
| order by RemoteSessionStart asc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate IT administrators who use remote access tools and then perform authorized lateral movement to manage other hosts.
- Automated patch management or monitoring agents that run under remote session contexts and authenticate to multiple hosts.
- Domain controllers and jump servers that routinely accept network logons from many sources.

**Tuning notes:**
- Extend remoteAccessTools to include additional remote support utilities observed in your environment.
- Add an AccountName exclusion list for known IT administrator accounts to reduce false positives from authorized lateral movement.
- If RemoteDeviceName is sparsely populated in your tenant, consider enriching with the DeviceInfo table to map RemoteIP to DeviceName via IPAddresses field as an alternative correlation path.
- Narrow TargetPort list if only SMB-based lateral movement is of interest.

**Risks / caveats:**
- The join between DeviceNetworkEvents RemoteIP and DeviceLogonEvents DeviceName is semantically incorrect: DeviceLogonEvents DeviceName is the hostname of the device where the logon event was recorded, not its IP address. This join will produce no results unless RemoteIP happens to equal the device hostname string, which does not occur in standard MDE telemetry.
- DeviceLogonEvents RemoteDeviceName field may be empty for network logons initiated from non-domain-joined devices, reducing recall.
- The outboundLateral filter contains a logic error in the original query: the where clause simultaneously excludes and includes private ranges, which is contradictory. The improved query corrects this to only include connections to internal RFC-1918 ranges on lateral movement ports, since SMB/RPC lateral movement targets internal hosts.
- The RemoteDeviceName field in DeviceLogonEvents is populated only when the source device is domain-joined and the logon is authenticated via Kerberos or NTLM with a resolvable source name; workgroup or non-domain-joined source devices will not populate this field, causing missed detections.

### Triage Runbook

**First 15 minutes:**
- Confirm the remote access tool used on the origin device and whether the session was authorized.
- Review the lateral connection target IPs and ports to determine whether they match SMB, RPC, or other internal management traffic.
- Check the subsequent logon events to see which target hosts accepted network logons from the origin device.
- Validate whether the origin device and account belong to IT administration or a jump-host workflow.
- Determine whether the lateral movement occurred shortly after the Teams contact and remote session start.

**Evidence to collect:**
- DeviceProcessEvents for the remote access tool execution on the origin device.
- DeviceNetworkEvents showing the internal target IPs, ports, and timestamps for the lateral connections.
- DeviceLogonEvents for successful network logons to the target hosts, including LogonAccount and LogonTargetDevice.
- OfficeActivity records for the original Teams impersonation event if available.
- Asset and identity context for the origin device, target hosts, and account.

**Pivot points:**
- DeviceProcessEvents filtered on remote access tools such as quickassist.exe, msra.exe, anydesk.exe, teamviewer.exe, screenconnect.exe, or rustdesk.exe.
- DeviceNetworkEvents filtered on internal RFC-1918 destinations and ports 445, 135, and 139.
- DeviceLogonEvents filtered on LogonType Network and LogonSuccess for the same origin device or account.
- IdentityInfo or equivalent mapping table if hostname or account normalization is needed.
- Microsoft Defender XDR incident timeline for related host and account activity.

**Benign explanations:**
- Authorized IT administration using remote support tools to manage multiple internal hosts.
- Automated patching, monitoring, or deployment activity that uses network logons after a remote session.
- A jump server or admin workstation that routinely connects to many internal systems.
- A false correlation caused by hostname mismatches or incomplete RemoteDeviceName population.

**Escalation criteria:**
- The origin device is not an approved admin system and the account is not an IT account.
- Multiple internal hosts receive network logons or SMB/RPC connections from the same origin device in a short window.
- The user denies initiating the remote session or the session was not authorized.
- Additional suspicious activity appears on the target hosts, such as new services, remote execution, or credential access.

**Containment actions:**
- Isolate the origin device if lateral movement is confirmed or strongly suspected.
- Disable the account used during the remote session if it is not an approved admin account.
- Block or restrict the remote access tool if it was unauthorized.
- Coordinate with endpoint and identity teams to preserve evidence on both origin and target hosts.

**Closure criteria:**
- The remote session and subsequent logons are confirmed as authorized administrative activity.
- The target hosts and ports match normal management workflows and no suspicious follow-on activity is found.
- The account and origin device are validated as approved for the observed actions.
- The alert is documented as benign and tuning is considered for approved admin systems.

<br/>
---
<br/>

## Detection 5: Counterfeit Installer Archive Executing Unexpected Child Process or Outbound Connection Post-Drop

### Detection Opportunity

A regenerated installer archive dropped in a user download path executes and spawns unexpected child processes or makes outbound network connections, consistent with malware delivery via counterfeit software installers.

### Intelligence Context

- Microsoft Security Blog: Counterfeit installers to system compromise: Tracking a deceptive software download campaign — [https://www.microsoft.com/en-us/security/blog/2026/09/01/counterfeit-installers-system-compromise-tracking-deceptive-software-download-campaign/](https://www.microsoft.com/en-us/security/blog/2026/09/01/counterfeit-installers-system-compromise-tracking-deceptive-software-download-campaign/)
  - Context: Microsoft documented a campaign delivering malware through regenerated installer archives hosted on look-alike software vendor pages. The post-execution behavior of spawning unexpected child processes or making outbound connections from installer executables dropped in user download directories is the actionable signal.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1189, T1204, T1204.002, T1059
- Products: Microsoft Defender XDR
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: T1189, T1204, Windows, Microsoft Defender XDR, T1204.002, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1189 Drive-by Compromise (low); User Execution: T1204 User Execution/ T1204.002 Malicious File (medium); Execution: T1059 Command and Scripting Interpreter (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let lookback = 24h;
let execWindow = 5min;
let downloadPaths = dynamic(["\\Downloads\\", "\\AppData\\Local\\Temp\\", "\\Users\\Public\\"]);
let installerPatterns = dynamic(["setup", "install", "update", "patch"]);
let installerParents = dynamic(["setup", "install", "update", "patch", "msiexec"]);
let suspiciousChildren = dynamic(["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe"]);
let installerDrops =
    DeviceFileEvents
    | where TimeGenerated >= ago(lookback)
    | where ActionType == "FileCreated"
    | where FolderPath has_any (downloadPaths)
    | where FileName has_any (installerPatterns) or FileName endswith ".msi" or FileName endswith ".msp"
    | project DropTime = TimeGenerated, DeviceName, DropFileName = FileName, FolderPath, SHA256, AccountName;
let childProcs =
    DeviceProcessEvents
    | where TimeGenerated >= ago(lookback)
    | where FileName has_any (suspiciousChildren)
    | where InitiatingProcessFileName has_any (installerParents) or InitiatingProcessFileName endswith ".msi"
    | project ProcTime = TimeGenerated, DeviceName, ChildProcess = FileName, ParentProcess = InitiatingProcessFileName, ProcessCommandLine;
let installerNetConns =
    DeviceNetworkEvents
    | where TimeGenerated >= ago(lookback)
    | where ActionType == "ConnectionSuccess"
    | where InitiatingProcessFileName has_any (installerParents)
    | where not(ipv4_is_private(RemoteIP))
    | where isnotempty(RemoteIP)
    | project ConnTime = TimeGenerated, DeviceName, RemoteIP, RemoteUrl, RemotePort = tostring(RemotePort), InstallerProcess = InitiatingProcessFileName;
let childProcAlerts =
    installerDrops
    | join kind=inner (
        childProcs
    ) on DeviceName
    | where ProcTime between (DropTime .. (DropTime + execWindow))
    | project
        DropTime,
        DeviceName,
        AccountName,
        DropFileName,
        FolderPath,
        SHA256,
        ChildProcess,
        ParentProcess,
        ProcessCommandLine,
        RemoteIP = "",
        RemoteUrl = "",
        RemotePort = "",
        SignalType = "SuspiciousChildProcess";
let netConnAlerts =
    installerDrops
    | join kind=inner (
        installerNetConns
    ) on DeviceName
    | where ConnTime between (DropTime .. (DropTime + execWindow))
    | project
        DropTime,
        DeviceName,
        AccountName,
        DropFileName,
        FolderPath,
        SHA256,
        ChildProcess = "",
        ParentProcess = InstallerProcess,
        ProcessCommandLine = "",
        RemoteIP,
        RemoteUrl,
        RemotePort,
        SignalType = "OutboundConnection";
childProcAlerts
| union netConnAlerts
| summarize
    SignalTypes = make_set(SignalType, 5),
    ChildProcesses = make_set(ChildProcess, 10),
    ParentProcesses = make_set(ParentProcess, 5),
    CommandLines = make_set(ProcessCommandLine, 10),
    RemoteIPs = make_set(RemoteIP, 10),
    RemoteUrls = make_set(RemoteUrl, 10),
    RemotePorts = make_set(RemotePort, 10)
    by DropTime, DeviceName, AccountName, DropFileName, FolderPath, SHA256
| project
    DropTime,
    DeviceName,
    AccountName,
    DropFileName,
    FolderPath,
    SHA256,
    SignalTypes,
    ChildProcesses,
    ParentProcesses,
    CommandLines,
    RemoteIPs,
    RemoteUrls,
    RemotePorts
| order by DropTime asc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate software installers that spawn cmd.exe or powershell.exe as part of their installation process, such as some enterprise application installers.
- Software update mechanisms that download and execute installers from user temp directories and then connect to vendor update servers.
- IT-deployed software packages staged in Downloads or Public directories that use scripting engines during installation.

**Tuning notes:**
- Add known-good installer SHA256 hashes to an exclusion list to reduce false positives from legitimate software deployments.
- Extend downloadPaths with enterprise-specific software staging directories if software is deployed to non-standard paths.
- Extend suspiciousChildren with additional LOLBins observed in your environment's incident history.
- Consider adding a FolderPath filter on ChildProcess to flag children running from AppData or Temp paths, which increases precision for malware payloads dropped alongside the installer.

**Risks / caveats:**
- DeviceFileEvents ActionType 'FileCreated' must be present in the tenant's MDE telemetry; verify with: DeviceFileEvents → where ActionType == 'FileCreated' → take 1
- The InitiatingProcessFileName filter in installerNetConns uses has_any(installerPatterns) which matches on substring; if the installer process name does not contain 'setup', 'install', 'update', or 'patch', outbound connections from that installer will not be captured by the network subquery. This is a recall limitation, not a schema risk.
- MSI execution is handled by msiexec.exe as the actual process; InitiatingProcessFileName for MSI-spawned children will be 'msiexec.exe', not the .msi filename. The childProcs subquery filters on InitiatingProcessFileName has_any(installerPatterns) or endswith '.msi', which will not match 'msiexec.exe'. The improved query adds 'msiexec.exe' to the parent filter.
- Highly randomized installer filenames that do not contain 'setup', 'install', 'update', or 'patch' will not be captured by the DropFileName filter, reducing recall for campaigns using randomized naming.

### Triage Runbook

**First 15 minutes:**
- Identify the dropped file name, folder path, account, and SHA256 to determine whether it resembles a legitimate installer or a suspicious look-alike.
- Check whether the file was created in a user download, temp, or public path and whether the user recently downloaded software from the web.
- Review the child process or outbound connection signal to see whether the installer spawned cmd.exe, powershell.exe, mshta.exe, or similar tools.
- Validate whether the outbound RemoteIP or RemoteUrl is a known vendor update server or an unknown external destination.
- Ask the user whether they intentionally installed the software and whether the installer came from an approved source.

**Evidence to collect:**
- DeviceFileEvents for the file creation event, including DropTime, FolderPath, DropFileName, and SHA256.
- DeviceProcessEvents for child processes spawned by the installer, including ChildProcess, ParentProcess, and ProcessCommandLine.
- DeviceNetworkEvents for outbound connections from the installer process, including RemoteIP, RemoteUrl, and RemotePort.
- Browser download history or email/web proxy evidence showing how the installer was obtained.
- Any reputation or threat-intelligence results for the SHA256 and destination URLs.

**Pivot points:**
- DeviceFileEvents filtered on FileCreated in Downloads, Temp, or Public paths.
- DeviceProcessEvents filtered on suspicious child processes such as cmd.exe, powershell.exe, wscript.exe, mshta.exe, or regsvr32.exe.
- DeviceNetworkEvents filtered on the installer process and non-private RemoteIP values.
- Browser, proxy, or email gateway logs to trace the download source.
- Microsoft Defender XDR file reputation or threat intelligence lookups for the SHA256.

**Benign explanations:**
- A legitimate software installer that uses scripting or helper processes during installation.
- An IT-deployed package staged in a user-accessible directory for convenience.
- A vendor updater that connects to a legitimate update server immediately after launch.
- A user downloading and running a normal installer that happens to match the filename patterns.

**Escalation criteria:**
- The installer spawns scripting, command, or LOLBin processes that are not expected for the software.
- The installer makes outbound connections to unknown or suspicious external infrastructure.
- The file hash is unknown or malicious and the user did not intentionally install the software.
- Additional payload behavior appears, such as persistence, credential prompts, or secondary downloads.

**Containment actions:**
- Isolate the endpoint if the installer behavior is suspicious or if a payload is executing.
- Quarantine or remove the dropped file if it is confirmed malicious and not needed for business use.
- Block the suspicious RemoteIP or RemoteUrl if the connection is malicious.
- Preserve the installer, child-process, and network evidence before cleanup.

**Closure criteria:**
- The installer is confirmed legitimate and the child process or network activity matches expected vendor behavior.
- The file hash is known-good or approved by software inventory, and no other suspicious behavior is present.
- The user confirms the installation was intentional and from a trusted source.
- The alert is documented as benign and any allowlist or tuning updates are recorded.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- SonicWall SMA1000 Chained RCE - Perimeter Hit Correlated with Downstream Lateral Movement: CommonSecurityLog requires a SonicWall SMA1000 CEF/syslog connector to be configured and actively forwarding logs; if absent the sonicwallHits subquery returns no rows and the entire detection produces no results.
- IT Support Impersonation via Teams External Collaboration Followed by Node.js Implant Execution: Environment-specific telemetry or field mapping must be resolved for Both: OfficeActivity, DeviceProcessEvents, DeviceNetworkEvents before scheduling.

**Schema / correlation keys:**
- Lateral Movement via Legitimate Tools Following Remote Session Established After Teams IT Impersonation: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- DeviceNetworkEvents: shared by SonicWall SMA1000 Chained RCE - Perimeter Hit Correlated with Downstream Lateral Movement; IT Support Impersonation via Teams External Collaboration Followed by Node.js Implant Execution; Node.js Implant Spawned by Remote Access Tool with Outbound C2 Connection; Lateral Movement via Legitimate Tools Following Remote Session Established After Teams IT Impersonation; Counterfeit Installer Archive Executing Unexpected Child Process or Outbound Connection Post-Drop
- DeviceProcessEvents: shared by IT Support Impersonation via Teams External Collaboration Followed by Node.js Implant Execution; Node.js Implant Spawned by Remote Access Tool with Outbound C2 Connection; Lateral Movement via Legitimate Tools Following Remote Session Established After Teams IT Impersonation; Counterfeit Installer Archive Executing Unexpected Child Process or Outbound Connection Post-Drop

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Node.js Implant Spawned by Remote Access Tool with Outbound C2 Connection; Counterfeit Installer Archive Executing Unexpected Child Process or Outbound Connection Post-Drop.
2. Resolve environment-mapping detections next: SonicWall SMA1000 Chained RCE - Perimeter Hit Correlated with Downstream Lateral Movement; IT Support Impersonation via Teams External Collaboration Followed by Node.js Implant Execution.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Lateral Movement via Legitimate Tools Following Remote Session Established After Teams IT Impersonation.

### Hunting Agenda and Promotion Criteria

- Lateral Movement via Legitimate Tools Following Remote Session Established After Teams IT Impersonation: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- SonicWall SMA1000 Chained RCE - Perimeter Hit Correlated with Downstream Lateral Movement: CommonSecurityLog requires a SonicWall SMA1000 CEF/syslog connector to be configured and actively forwarding logs; if absent the sonicwallHits subquery returns no rows and the entire detection produces no results.; prove correlation keys join correctly on real tenant telemetry.
- IT Support Impersonation via Teams External Collaboration Followed by Node.js Implant Execution: Environment-specific telemetry or field mapping must be resolved for Both: OfficeActivity, DeviceProcessEvents, DeviceNetworkEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
