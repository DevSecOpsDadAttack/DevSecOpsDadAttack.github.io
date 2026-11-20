---
layout: post
title: "Detection Engineering Brief - Friday, November 20, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-11-20
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-123890
  - ARMORY CASTLE
  - T1190
  - VMware vCenter
  - VMware Directory Service
  - AuditTeam
  - OpsAgent
  - Windows
  - CVE-2026-73571
  - Zimbra
  - Metasploit
  - Webworm
  - SoftEther VPN
  - T1204
  - T1486
  - T1090
  - T1090.001
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

0 production candidates, 2 hunting-only, 3 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-123890, ARMORY CASTLE, T1190, VMware vCenter, VMware Directory Service, AuditTeam, OpsAgent, Windows, CVE-2026-73571, Zimbra, Metasploit, Webworm, SoftEther VPN, T1204, T1486, T1090, T1090.001.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: CVE-2026-123890 vCenter Auth Bypass - Unauthenticated Access to Management Endpoints; CVE-2026-123890 vCenter - Administrator Logon from Unexpected Source Post-Exploitation; OpsAgent Ransomware Implant - Unsigned Binary Execution with Mass File Modification on Windows; CVE-2026-73571 Zimbra SaveDraftRequest Authorization Bypass - Unauthenticated SOAP Exploitation; Webworm SoftEther VPN Deployment - Process Execution with Outbound VPN Tunnel Traffic.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: CVE-2026-123890 vCenter Auth Bypass - Unauthenticated Access to Management Endpoints

### Detection Opportunity

Unauthenticated HTTP requests exploiting CVE-2026-123890 to bypass VMware vCenter authentication and gain Administrator access.

### Intelligence Context

- Rapid7: CVE-2026-123890: Critical Authentication Bypass in VMware vCenter — [https://www.rapid7.com/blog/post/etr-cve-2026-123890-critical-authentication-bypass-vmware-vcenter](https://www.rapid7.com/blog/post/etr-cve-2026-123890-critical-authentication-bypass-vmware-vcenter)
  - Context: ARMORY CASTLE exploited CVE-2026-123890 in the wild to bypass vCenter authentication without credentials, gaining Administrator-level access. The exploit targets vCenter management and directory service endpoints via unauthenticated network requests.

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

- CommonSecurityLog must be populated by a CEF or syslog connector forwarding vCenter HTTP access logs; this connector is not present by default and must be explicitly configured.
- SecurityEvent collection from vCenter hosts requires MMA or AMA agent deployment on the vCenter appliance, which is not standard and may not be supported on all vCenter versions.

**Required telemetry:**
- CommonSecurityLog, SecurityEvent

### KQL

```kql
let lookback = 1h;
let joinWindow = 15m;
let vCenterAuthBypass = CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where RequestURL has_any ("/vsphere-client", "/vmdir", "/lookupservice", "/sts", "/sdk")
| where RequestMethod == "POST"
| where ResponseCode == 200
| where isnotempty(SourceIP)
| extend NormalizedSourceIP = tolower(SourceIP)
| project TimeGenerated, NormalizedSourceIP, SourceIP, RequestURL, ResponseCode, DeviceVendor, DeviceProduct;
let vCenterAdminLogon = SecurityEvent
| where TimeGenerated > ago(lookback + joinWindow)
| where EventID in (4624, 4648)
| where tolower(coalesce(TargetUserName, AccountName)) =~ "administrator"
| where LogonType in (3, 10)
| where isnotempty(IpAddress) and IpAddress != "127.0.0.1" and IpAddress != "-"
| extend NormalizedSourceIP = tolower(IpAddress)
| project LogonTime = TimeGenerated, Computer, TargetUserName = coalesce(TargetUserName, AccountName), LogonType, NormalizedSourceIP, IpAddress;
vCenterAuthBypass
| join kind=inner (vCenterAdminLogon) on NormalizedSourceIP
| where LogonTime between (TimeGenerated .. (TimeGenerated + joinWindow))
| project
    TimeGenerated,
    SourceIP,
    RequestURL,
    ResponseCode,
    DeviceVendor,
    DeviceProduct,
    Computer,
    TargetUserName,
    LogonType,
    LogonTime
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrative tooling that POSTs to vCenter SDK or STS endpoints and is followed by an Administrator logon from the same management host.
- Shared NAT or jump host IPs where multiple administrators operate, causing unrelated HTTP and logon events to correlate.
- Automated monitoring or health-check agents that authenticate to vCenter management endpoints.

**Tuning notes:**
- Restrict SourceIP to known external CIDR ranges using ipv4_is_private() to reduce noise from internal administrative activity.
- Add a DeviceProduct filter on CommonSecurityLog matching your vCenter CEF connector's DeviceProduct value to scope results to vCenter logs only.
- Populate a watchlist of known administrative source IPs and exclude them from the bypass subquery.

**Risks / caveats:**
- CommonSecurityLog must be populated by a CEF or syslog connector forwarding vCenter HTTP access logs; this connector is not present by default and must be explicitly configured.
- SecurityEvent IpAddress field for EventID 4624/4648 is frequently empty or '-' for non-network logon types; the join on SourceIP == IpAddress will produce no results if IpAddress is unpopulated.
- SecurityEvent collection from vCenter hosts requires MMA or AMA agent deployment on the vCenter appliance, which is not standard and may not be supported on all vCenter versions.
- The 15-minute join window between HTTP exploit and Administrator logon is a heuristic; adjust based on observed exploitation-to-logon latency in your environment.

### Triage Runbook

**First 15 minutes:**
- Validate the source IP, request URL, response code, and timestamp against vCenter access logs to confirm the request was truly unauthenticated and targeted a management endpoint.
- Check whether the same source IP generated an Administrator logon on the vCenter host within the expected time window and whether the logon type was network or remote interactive.
- Identify whether the source IP is a known admin jump host, monitoring system, or NAT egress used by multiple administrators.
- Review recent vCenter administrative actions, new sessions, privilege changes, and any changes to directory service or authentication settings around the alert time.

**Evidence to collect:**
- HTTP request details: source IP, request URL, request method, response code, user agent, and exact timestamp.
- vCenter host logon evidence: account name, logon type, source IP, and logon time from SecurityEvent or equivalent host logs.
- Recent vCenter audit/admin activity, including user creation, role changes, SSO changes, and configuration modifications.
- Any correlated authentication failures, unusual session creation, or follow-on activity from the same source IP.

**Pivot points:**
- CommonSecurityLog for the same source IP over the prior 24 hours to identify reconnaissance or repeated POSTs to vCenter endpoints.
- SecurityEvent for the vCenter host to review all logons by the affected account and source IP.
- vCenter audit or appliance logs for administrative actions, SSO events, and endpoint access around the alert time.
- Network/security telemetry for the source IP to determine whether it is a known management host or external address.

**Benign explanations:**
- Legitimate administrative tooling or automation posting to vCenter SDK or STS endpoints and then logging in as Administrator.
- Shared jump host or NAT egress causing unrelated HTTP and logon events to correlate.
- Health-check or monitoring systems that authenticate to vCenter management endpoints.
- Incomplete or mis-mapped telemetry causing a normal admin session to appear as an exploit sequence.

**Escalation criteria:**
- The source IP is external or unknown and the Administrator logon is confirmed from the same IP within the alert window.
- You find evidence of unauthorized vCenter configuration changes, new admin sessions, or directory/authentication tampering.
- The alert repeats from the same source IP or across multiple vCenter endpoints.
- There is any sign of lateral movement, new account creation, or suspicious use of vCenter administrative privileges.

**Containment actions:**
- If compromise is plausible, isolate the vCenter management interface from untrusted networks or restrict access to approved admin sources only.
- Disable or rotate credentials for any account used in the suspicious logon path, especially Administrator or equivalent privileged accounts.
- Block the source IP at network controls if it is external and not an approved management host.
- Preserve vCenter and host logs before making disruptive changes.

**Closure criteria:**
- The source IP is confirmed as an approved admin or monitoring source and the correlated logon is explained by normal operations.
- No unauthorized administrative actions, privilege changes, or suspicious follow-on activity are found.
- Telemetry confirms the request was a benign management action rather than exploit behavior.
- Document the approved source and add it to the environment-specific allowlist or tuning baseline if appropriate.

<br/>
---
<br/>

## Detection 2: CVE-2026-123890 vCenter - Administrator Logon from Unexpected Source Post-Exploitation

### Detection Opportunity

Administrator account logon on vCenter host following unauthenticated exploitation of CVE-2026-123890, indicating successful privilege acquisition by ARMORY CASTLE.

### Intelligence Context

- Rapid7: CVE-2026-123890: Critical Authentication Bypass in VMware vCenter — [https://www.rapid7.com/blog/post/etr-cve-2026-123890-critical-authentication-bypass-vmware-vcenter](https://www.rapid7.com/blog/post/etr-cve-2026-123890-critical-authentication-bypass-vmware-vcenter)
  - Context: Post-exploitation of CVE-2026-123890 results in the attacker gaining access as the Administrator user on the vCenter system. Detecting Administrator logon events on vCenter hosts from unexpected sources provides a high-fidelity post-exploitation signal.

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
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID in (4624, 4648)
| extend EffectiveUser = coalesce(TargetUserName, AccountName)
| where tolower(EffectiveUser) =~ "administrator"
| where LogonType in (3, 10)
| where Computer has_any ("vcenter", "vc", "vsphere")
| where isnotempty(IpAddress)
| where IpAddress != "127.0.0.1"
| where IpAddress != "-"
| where not(IpAddress startswith "::")
| where not(ipv4_is_private(IpAddress))
| summarize
    LogonCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Computer, EffectiveUser, IpAddress, LogonType
| project FirstSeen, LastSeen, Computer, EffectiveUser, IpAddress, LogonType, LogonCount
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrators logging into vCenter from approved jump hosts or bastion servers not yet added to the exclusion baseline.
- Automated backup, monitoring, or orchestration tools authenticating as Administrator from internal IPs not covered by the RFC1918 exclusion.
- Hostname substring matching may catch non-vCenter hosts with similar naming patterns.

**Tuning notes:**
- Replace the Computer has_any substring filter with an explicit list of vCenter hostnames or a watchlist reference once hostnames are confirmed.
- Add approved jump host and bastion IPs to an explicit exclusion list layered on top of the ipv4_is_private() filter.
- Consider lowering the lookback to 1h and scheduling the rule hourly for faster detection latency.

**Risks / caveats:**
- SecurityEvent collection from vCenter hosts requires MMA or AMA agent deployment on the vCenter appliance; this is not a default configuration and may not be supported on all vCenter versions.
- The Computer field substring filter ('vcenter', 'vc', 'vsphere') is a naming convention dependency; environments with different hostname patterns will produce no results.
- The Computer has_any filter must be updated to match your organization's vCenter hostname naming convention; the current substrings are illustrative defaults.
- ipv4_is_private() suppresses all RFC1918 source IPs; if your vCenter is administered from internal IPs that are not RFC1918 (e.g., CGNAT ranges), add explicit exclusions.

### Triage Runbook

**First 15 minutes:**
- Confirm the vCenter hostname and verify the logon event is on the appliance or host you expect to monitor.
- Check whether the source IP is a known jump host, bastion, backup system, or other approved administrative source.
- Review the logon type, account name, and time of the event to determine whether it is a network or remote interactive session.
- Look for nearby signs of exploitation or admin abuse, including unusual HTTP requests, new sessions, or configuration changes on the same host.

**Evidence to collect:**
- SecurityEvent details for the logon: EventID, account name, logon type, source IP, computer name, and timestamp.
- Any vCenter audit logs showing actions performed immediately after the logon.
- Historical logon baseline for the same account and host to determine whether the source IP is unusual.
- Correlated network or web access logs from the same source IP around the same time.

**Pivot points:**
- SecurityEvent for all Administrator logons on the vCenter host over the last 7 days.
- CommonSecurityLog or vCenter access logs for the same source IP and time window.
- vCenter audit logs for privilege changes, session creation, and administrative actions after the logon.
- Asset or CMDB data to determine whether the source IP belongs to an approved admin workstation or jump server.

**Benign explanations:**
- A legitimate administrator used a new or recently changed jump host.
- Backup, monitoring, or orchestration tooling authenticated as Administrator from an internal management system.
- Hostname filtering or telemetry mapping caused a normal logon to appear unexpected.
- The source IP is a shared NAT or bastion address used by multiple administrators.

**Escalation criteria:**
- The source IP is not an approved management source and the logon is confirmed as successful Administrator access.
- You find evidence of unauthorized changes to vCenter roles, SSO, users, or inventory.
- The same source IP appears in exploit-like web requests or repeated suspicious logons.
- There are signs of broader compromise, such as additional privileged logons or lateral movement from the vCenter host.

**Containment actions:**
- If the logon is unauthorized, disable the affected account or force credential reset for the privileged account used.
- Restrict vCenter access to approved management sources and block the suspicious source IP if external.
- Preserve logs and session evidence before restarting services or making major changes.
- Escalate to infrastructure owners to assess whether the vCenter appliance requires isolation or rebuild.

**Closure criteria:**
- The source IP is validated as an approved admin source and the logon is explained by normal operations.
- No unauthorized actions occurred after the logon and no additional suspicious sessions are present.
- The account and host are confirmed clean after review of audit logs and recent activity.
- Any required tuning or allowlist updates are documented for future alerts.

<br/>
---
<br/>

## Detection 3: OpsAgent Ransomware Implant - Unsigned Binary Execution with Mass File Modification on Windows

### Detection Opportunity

OpsAgent implant deployed on Windows systems executing as an unsigned binary and performing ransomware-typical file modification activity.

### Intelligence Context

- Securelist: The forced audit: how AuditTeam's OpsAgent framework masks ransomware as consulting — [https://securelist.com/auditteam-opsagent-forced-audit/122031/](https://securelist.com/auditteam-opsagent-forced-audit/122031/)
  - Context: AuditTeam deploys the OpsAgent implant, rewritten in Rust, on Windows systems as part of a ransomware operation. The implant executes from non-standard paths and performs mass file modifications consistent with encryption. No hashes are available, requiring behavioral detection anchored to unsigned binary execution and file modification volume.

### Search Metadata

- CVEs: Not specified
- Threat actors: AuditTeam
- ATT&CK tags: T1204, T1486
- Products: Not specified
- Platforms: Windows
- Malware: OpsAgent
- Tools: Not specified
- Search tags: AuditTeam, OpsAgent, Windows, T1204, T1486

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1204 User Execution (low); Impact: T1486 Data Encrypted for Impact (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let suspiciousPaths = dynamic(["\\AppData\\", "\\Temp\\", "\\ProgramData\\", "\\Users\\Public\\"]);
let fileModWindow = 5m;
let fileModThreshold = 50;
let suspiciousProcs = DeviceProcessEvents
| where TimeGenerated > ago(1d)
| where FolderPath has_any (suspiciousPaths)
| where isempty(InitiatingProcessFileName)
    or InitiatingProcessFileName !in~ ("msiexec.exe", "setup.exe", "install.exe", "MpSigStub.exe", "MpCmdRun.exe")
| project DeviceId, DeviceName, ProcessStartTime = TimeGenerated, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, SHA256;
let massFileChanges = DeviceFileEvents
| where TimeGenerated > ago(1d)
| where ActionType in ("FileModified", "FileCreated", "FileRenamed")
| where FolderPath !has "\\Windows\\"
| where FolderPath has_any (suspiciousPaths)
| summarize
    FileChangeCount = count(),
    FirstChange = min(TimeGenerated),
    LastChange = max(TimeGenerated)
    by DeviceId, FileWindowStart = bin(TimeGenerated, fileModWindow)
| where FileChangeCount >= fileModThreshold;
suspiciousProcs
| join kind=inner (massFileChanges) on DeviceId
| where FirstChange >= ProcessStartTime and FirstChange <= (ProcessStartTime + 10m)
| project
    ProcessStartTime,
    DeviceName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    SHA256,
    FileChangeCount,
    FirstChange,
    LastChange
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Software deployment agents (SCCM, Intune, patch management) executing from ProgramData or Temp with high file write volumes.
- Backup or archiving agents writing large numbers of files from AppData or ProgramData paths.
- Development environments with build tools executing from user AppData directories generating high file output.
- Antivirus or EDR update processes writing to ProgramData.

**Tuning notes:**
- Increase fileModThreshold above 50 if legitimate software deployment in your environment generates high file modification counts from temp paths.
- Add known legitimate installer and agent parent process names to the InitiatingProcessFileName exclusion list.
- Run against a 7-day window initially to establish false positive baseline before considering scheduling.
- Consider adding a FolderPath extension filter for common ransomware encrypted file extensions as an additional signal layer.

**Risks / caveats:**
- DeviceFileEvents ActionType values 'FileModified', 'FileCreated', and 'FileRenamed' must be confirmed present in the tenant's telemetry; ActionType availability depends on MDE sensor version and onboarding configuration.
- ProcessIntegrityLevel is not reliably populated for all process types in DeviceProcessEvents; Rust-compiled binaries may have empty values, making integrity-level filtering unreliable as a primary signal.
- The fileModThreshold of 50 modifications in 5 minutes is a heuristic; baseline against your environment's legitimate software deployment activity before using this as a scheduling threshold.
- The 10-minute process-to-file-modification window is a heuristic; OpsAgent may delay encryption activity beyond this window.

### Triage Runbook

**First 15 minutes:**
- Identify the host, process name, command line, parent process, and file path to determine whether the binary executed from a user-writable or temporary location.
- Confirm whether file modification activity is ongoing and whether the affected files are user data, shared drives, or backup locations.
- Check for signs of ransomware behavior such as rapid file renames, extension changes, ransom notes, or disabled security tools.
- Determine whether the process is associated with a known software deployment, backup, or maintenance activity before taking action.

**Evidence to collect:**
- Process details: file name, folder path, command line, initiating process, SHA256, and start time.
- File activity details: count of modified/created/renamed files, first and last change times, and affected directories.
- Host context: device name, logged-on user, recent software installs, and any security alerts on the same endpoint.
- Any ransom note files, unusual extensions, or evidence of encryption across local or network shares.

**Pivot points:**
- DeviceProcessEvents for the same device and time window to identify parent/child process chains and repeated executions.
- DeviceFileEvents for the host to identify the scope of file changes and affected paths.
- DeviceNetworkEvents for outbound connections from the host that may indicate command-and-control or exfiltration.
- DeviceLogonEvents or equivalent identity telemetry to determine which user was active when the process started.

**Benign explanations:**
- Software deployment, patching, or installer activity generating many file writes from a temporary or user-writable path.
- Backup, sync, or archiving software modifying large numbers of files.
- Developer build tools or packaging workflows producing high file churn in AppData or ProgramData.
- Security tooling updates or remediation actions that rewrite many files.

**Escalation criteria:**
- File encryption indicators, ransom notes, or widespread file renaming are present.
- The process is unsigned, runs from a suspicious path, and is not tied to a known business application or deployment.
- Multiple endpoints show the same behavior or the host begins contacting suspicious external infrastructure.
- User data or shared storage is actively impacted and business operations are at risk.

**Containment actions:**
- Isolate the endpoint from the network immediately if encryption or active mass modification is confirmed.
- Terminate the suspicious process only after preserving evidence if the host is still actively impacting files.
- Disable the affected user account and reset credentials if the process appears tied to a compromised session.
- Coordinate with IT to protect backups and prevent spread to mapped drives or adjacent systems.

**Closure criteria:**
- The activity is confirmed as legitimate software, backup, or maintenance behavior.
- No encryption, ransom note, or malicious follow-on activity is found after full review.
- The process is identified and documented as benign, with supporting change or deployment evidence.
- If malicious, containment is complete and the incident is handed off for full ransomware response.

<br/>
---
<br/>

## Detection 4: CVE-2026-73571 Zimbra SaveDraftRequest Authorization Bypass - Unauthenticated SOAP Exploitation

### Detection Opportunity

Unauthenticated or anomalous POST requests to Zimbra's SaveDraftRequest SOAP endpoint exploiting CVE-2026-73571 authorization bypass.

### Intelligence Context

- Rapid7: Metasploit Wrap Up: Breaking Zimbra's Identity Boundaries — [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-breaking-zimbra-s-identity-boundaries](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-breaking-zimbra-s-identity-boundaries)
  - Context: CVE-2026-73571 is an authorization bypass in Zimbra's SaveDraftRequest SOAP handler. A Metasploit module exists for exploitation. Attackers send POST requests to the SaveDraftRequest endpoint, potentially without valid authentication, to abuse Zimbra's identity resolution and SOAP authentication mechanisms.

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
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- CommonSecurityLog must be populated by a CEF or syslog connector forwarding Zimbra HTTP access logs; this connector is not present by default and must be explicitly configured for the Zimbra deployment.

**Required telemetry:**
- CommonSecurityLog

### KQL

```kql
let lookback = 1h;
let metasploitAgents = dynamic(["ruby", "libwww-perl", "python-requests", "go-http-client", "masscan"]);
let zimbraSoapRequests = CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where RequestURL has "SaveDraftRequest"
| where RequestMethod == "POST"
| where ResponseCode == 200
| where isnotempty(SourceIP)
| project TimeGenerated, SourceIP, RequestURL, ResponseCode, UserAgent, DeviceVendor, DeviceProduct;
let priorAuthSessions = CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where RequestURL has_any ("/service/soap", "/zimbra")
| where ResponseCode == 200
| where RequestURL !has "SaveDraftRequest"
| where isnotempty(SourceIP)
| summarize PriorRequests = count() by SourceIP;
zimbraSoapRequests
| join kind=leftouter (priorAuthSessions) on SourceIP
| extend PriorRequests = coalesce(PriorRequests, 0)
| extend MetasploitUA = tolower(UserAgent) has_any (metasploitAgents)
| extend NoSessionHistory = PriorRequests == 0
| where NoSessionHistory or MetasploitUA
| extend DetectionBranch = case(
    MetasploitUA and NoSessionHistory, "MetasploitUA+NoSession",
    MetasploitUA, "MetasploitUA",
    "NoSessionHistory"
  )
| project
    TimeGenerated,
    SourceIP,
    RequestURL,
    ResponseCode,
    UserAgent,
    PriorRequests,
    DetectionBranch,
    DeviceVendor,
    DeviceProduct
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Zimbra mobile clients or third-party mail clients that POST to SaveDraftRequest without prior SOAP session activity in the lookback window.
- New Zimbra users or clients connecting for the first time within the lookback window will have no prior session history.
- Source IPs behind NAT or shared egress will have their prior session history aggregated, potentially masking new connections.
- Legitimate HTTP client libraries (python-requests, Go-http-client) used by internal automation may match the Metasploit user-agent list.

**Tuning notes:**
- Extend the lookback window to 4h or 8h to improve prior session baseline accuracy for environments with infrequent Zimbra access patterns.
- Add organization-specific trusted source IP ranges to an exclusion list to suppress alerts from known internal mail clients.
- Review the metasploitAgents list against your environment's legitimate HTTP client user-agents and remove strings that match internal tooling.
- Consider splitting into two separate rules: one for Metasploit UA (higher confidence) and one for no-prior-session (lower confidence, hunting-grade).

**Risks / caveats:**
- CommonSecurityLog must be populated by a CEF or syslog connector forwarding Zimbra HTTP access logs; this connector is not present by default and must be explicitly configured for the Zimbra deployment.
- UserAgent field population in CommonSecurityLog depends on the Zimbra log format and connector mapping; if UserAgent is not forwarded, the Metasploit agent filter will never match.
- The absence-of-prior-session heuristic requires complete Zimbra log forwarding; partial forwarding will cause legitimate sessions to appear as having no prior activity, generating false positives.
- The 1-hour lookback for prior session history is a short window; attackers who perform reconnaissance more than 1 hour before exploitation will appear to have no prior session, increasing true positive rate but also false positive rate for new legitimate clients.

### Triage Runbook

**First 15 minutes:**
- Validate the request URL, method, response code, source IP, and user agent against Zimbra access logs.
- Check whether the source IP has any prior authenticated Zimbra activity in the lookback window or whether this is a first-seen source.
- Determine whether the user agent matches common exploit tooling or automation strings and whether the request pattern is unusual for your environment.
- Review whether the request was followed by mailbox access, draft creation, or other suspicious SOAP activity from the same source.

**Evidence to collect:**
- HTTP request details: source IP, request URL, request method, response code, user agent, and timestamp.
- Prior session history for the source IP, including any earlier SOAP or authenticated Zimbra requests.
- Any mailbox or account activity tied to the same source IP after the request.
- Zimbra server logs showing authentication, session creation, or errors around the same time.

**Pivot points:**
- CommonSecurityLog for the source IP over the last 24 hours to identify prior Zimbra activity and repeated requests.
- Zimbra access and audit logs for SaveDraftRequest, SOAP endpoints, and authentication events.
- Identity or mail logs for the affected account to identify unusual logins, message access, or draft creation.
- Network telemetry for the source IP to determine whether it is a known mail client, proxy, or external scanner.

**Benign explanations:**
- A legitimate mail client or mobile client making a first request within the lookback window.
- A new user or newly observed source IP with no prior session history.
- Internal automation or integration using a generic HTTP client user agent.
- Partial log forwarding causing the source to appear sessionless when it is not.

**Escalation criteria:**
- The source IP is external or unknown and the request pattern matches exploit behavior or known tooling.
- There is evidence of unauthorized mailbox access, draft manipulation, or additional suspicious SOAP requests.
- The same source IP targets multiple Zimbra endpoints or multiple accounts.
- The request is followed by account compromise indicators or abnormal authentication activity.

**Containment actions:**
- If exploitation is plausible, block the source IP at the web or perimeter layer.
- Force password reset or session invalidation for any account that may have been impacted.
- Increase monitoring on the Zimbra server and preserve logs before making service changes.
- If multiple suspicious requests are seen, consider temporarily restricting external access to the affected endpoint while investigating.

**Closure criteria:**
- The source is confirmed as a legitimate client or approved automation and the request is consistent with normal use.
- No unauthorized mailbox activity or suspicious follow-on SOAP behavior is found.
- The user agent and source IP are explained by known business processes or testing.
- Any tuning changes or allowlist updates are documented for future triage.

<br/>
---
<br/>

## Detection 5: Webworm SoftEther VPN Deployment - Process Execution with Outbound VPN Tunnel Traffic

### Detection Opportunity

SoftEther VPN binaries executed on endpoints with concurrent outbound connections on SoftEther-associated ports, consistent with Webworm covert access infrastructure deployment.

### Intelligence Context

- Rapid7: Spying on Governments with Zero Lines of Malware: A Custom SoftEther Bridge in Webworm's Toolkit — [https://www.rapid7.com/blog/post/tr-spying-on-governments-no-malware-custom-webworms-toolkit-softether-bridge](https://www.rapid7.com/blog/post/tr-spying-on-governments-no-malware-custom-webworms-toolkit-softether-bridge)
  - Context: Webworm deploys SoftEther VPN into compromised governmental networks for covert long-term access. A custom SoftEther-based tool with stealth features is also used. Detection focuses on SoftEther process execution correlated with outbound connections on ports associated with SoftEther VPN tunneling protocols.

### Search Metadata

- CVEs: Not specified
- Threat actors: Webworm
- ATT&CK tags: T1090, T1090.001
- Products: SoftEther VPN
- Platforms: Not specified
- Malware: Not specified
- Tools: SoftEther VPN
- Search tags: Webworm, SoftEther VPN, T1090, T1090.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1090 Proxy/ T1090.001 Internal Proxy (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let softEtherProcessNames = dynamic(["vpnserver.exe", "vpnclient.exe", "vpncmd.exe", "vpnbridge.exe", "se_vpn"]);
let softEtherPortsHighFidelity = dynamic([992, 1194, 5555, 8888]);
let procEvents = DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FileName has_any (softEtherProcessNames)
    or ProcessCommandLine has_any (softEtherProcessNames)
| project DeviceId, DeviceName, ProcessStartTime = TimeGenerated, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName;
let netEventsHighFidelity = DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where RemotePort in (softEtherPortsHighFidelity)
| where ActionType == "ConnectionSuccess"
| where isnotempty(RemoteIP)
| where not(ipv4_is_private(RemoteIP))
| project DeviceId, NetTime = TimeGenerated, RemoteIP, RemotePort, HighFidelityPort = true;
let netEvents443 = DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where RemotePort == 443
| where ActionType == "ConnectionSuccess"
| where isnotempty(RemoteIP)
| where not(ipv4_is_private(RemoteIP))
| where InitiatingProcessFileName has_any (softEtherProcessNames)
| project DeviceId, NetTime = TimeGenerated, RemoteIP, RemotePort, HighFidelityPort = false;
let allNetEvents = union netEventsHighFidelity, netEvents443;
procEvents
| join kind=inner (allNetEvents) on DeviceId
| where NetTime >= ProcessStartTime and NetTime <= (ProcessStartTime + 5m)
| project
    ProcessStartTime,
    DeviceName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    RemoteIP,
    RemotePort,
    NetTime,
    HighFidelityPort
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate SoftEther VPN deployments authorized by the organization for remote access.
- Port 443 correlation will match any process in the SoftEther name list that makes HTTPS connections, including legitimate VPN clients.
- Environments where SoftEther is used for authorized site-to-site connectivity.
- Custom-named Webworm SoftEther variant will not match the process name list and will be missed entirely.

**Tuning notes:**
- Remove port 443 from the query entirely if false positive volume remains high after applying the InitiatingProcessFileName filter.
- Extend the time window beyond 5 minutes if SoftEther process startup to first connection latency in your environment exceeds this threshold.
- Add known-good device IDs or organizational SoftEther deployment paths to an exclusion list after reviewing initial results.
- Consider adding FolderPath filters to restrict process execution to non-standard paths if legitimate SoftEther is deployed from a known directory.

**Risks / caveats:**
- ActionType 'ConnectionSuccess' must be confirmed available in DeviceNetworkEvents for the tenant's MDE sensor version; some environments may only have 'ConnectionFound' or 'InboundConnectionAccepted'.
- Webworm's custom SoftEther variant may use a different binary name and will not be detected by the process name filter; behavioral signals alone (port + path) are insufficient without a process name anchor.
- The 5-minute process-to-connection window may be too short if SoftEther takes longer to establish its first tunnel connection after process start.
- Port 443 branch relies on InitiatingProcessFileName in DeviceNetworkEvents, which may not be populated in all MDE sensor configurations.

### Triage Runbook

**First 15 minutes:**
- Confirm the process name, command line, folder path, and parent process to determine whether SoftEther was launched from a suspicious location.
- Validate the remote IP and port to see whether the connection is to an external host and whether it uses a SoftEther-associated port.
- Check whether the endpoint is expected to run SoftEther for legitimate remote access or site-to-site connectivity.
- Look for additional signs of proxying or remote access, including repeated connections, service creation, or other tunneling tools on the host.

**Evidence to collect:**
- Process details: file name, command line, folder path, initiating process, and start time.
- Network details: remote IP, remote port, connection time, and whether the destination is external.
- Host context: device name, logged-on user, recent software installs, and any related service or scheduled task creation.
- Any evidence of additional tunneling, remote administration, or persistence mechanisms on the same host.

**Pivot points:**
- DeviceProcessEvents for the same host to identify SoftEther binaries, service creation, or related tooling.
- DeviceNetworkEvents for repeated outbound connections to the same remote IP or port.
- DeviceRegistryEvents and DeviceServiceEvents for persistence artifacts associated with VPN deployment.
- Asset inventory or change records to confirm whether SoftEther is approved on the endpoint.

**Benign explanations:**
- Authorized SoftEther VPN installation for remote access or site-to-site connectivity.
- A legitimate VPN client or admin tool using a similar binary name or command line.
- Port 443 traffic from a normal application that happens to correlate with a process name match.
- Testing or lab activity on a non-production endpoint.

**Escalation criteria:**
- SoftEther is not approved on the endpoint and the remote connection is external or suspicious.
- The process runs from an unusual path or is accompanied by persistence, service creation, or repeated tunnel connections.
- The endpoint shows signs of unauthorized remote access, lateral movement, or additional proxy tools.
- Multiple hosts exhibit the same behavior, suggesting broader covert access infrastructure.

**Containment actions:**
- If unauthorized, isolate the endpoint from the network to stop tunneling and remote access.
- Terminate the suspicious process and remove any related service or scheduled task after preserving evidence.
- Block the remote IP or destination port if it is not an approved VPN endpoint.
- Reset credentials used on the host if the activity suggests compromise of an administrative account.

**Closure criteria:**
- SoftEther use is confirmed as approved and matches a documented business need.
- The remote destination and process lineage are explained by legitimate VPN deployment or testing.
- No persistence, unauthorized access, or additional suspicious network activity is found.
- The alert is documented and tuned if the environment legitimately uses SoftEther.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- CVE-2026-123890 vCenter Auth Bypass - Unauthenticated Access to Management Endpoints: CommonSecurityLog must be populated by a CEF or syslog connector forwarding vCenter HTTP access logs; this connector is not present by default and must be explicitly configured.
- CVE-2026-123890 vCenter - Administrator Logon from Unexpected Source Post-Exploitation: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.
- CVE-2026-73571 Zimbra SaveDraftRequest Authorization Bypass - Unauthenticated SOAP Exploitation: CommonSecurityLog must be populated by a CEF or syslog connector forwarding Zimbra HTTP access logs; this connector is not present by default and must be explicitly configured for the Zimbra deployment.

**Other deployment dependency:**
- CVE-2026-123890 vCenter Auth Bypass - Unauthenticated Access to Management Endpoints: SecurityEvent collection from vCenter hosts requires MMA or AMA agent deployment on the vCenter appliance, which is not standard and may not be supported on all vCenter versions.

**Schema / correlation keys:**
- OpsAgent Ransomware Implant - Unsigned Binary Execution with Mass File Modification on Windows: Do not schedule yet; validate as an analyst-led hunt first.
- Webworm SoftEther VPN Deployment - Process Execution with Outbound VPN Tunnel Traffic: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- CommonSecurityLog: shared by CVE-2026-123890 vCenter Auth Bypass - Unauthenticated Access to Management Endpoints; CVE-2026-73571 Zimbra SaveDraftRequest Authorization Bypass - Unauthenticated SOAP Exploitation
- SecurityEvent: shared by CVE-2026-123890 vCenter Auth Bypass - Unauthenticated Access to Management Endpoints; CVE-2026-123890 vCenter - Administrator Logon from Unexpected Source Post-Exploitation
- DeviceProcessEvents: shared by OpsAgent Ransomware Implant - Unsigned Binary Execution with Mass File Modification on Windows; Webworm SoftEther VPN Deployment - Process Execution with Outbound VPN Tunnel Traffic

### Sequenced Deployment Plan

1. Resolve environment-mapping detections next: CVE-2026-123890 vCenter Auth Bypass - Unauthenticated Access to Management Endpoints; CVE-2026-123890 vCenter - Administrator Logon from Unexpected Source Post-Exploitation; CVE-2026-73571 Zimbra SaveDraftRequest Authorization Bypass - Unauthenticated SOAP Exploitation.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: OpsAgent Ransomware Implant - Unsigned Binary Execution with Mass File Modification on Windows; Webworm SoftEther VPN Deployment - Process Execution with Outbound VPN Tunnel Traffic.

### Hunting Agenda and Promotion Criteria

- OpsAgent Ransomware Implant - Unsigned Binary Execution with Mass File Modification on Windows: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- Webworm SoftEther VPN Deployment - Process Execution with Outbound VPN Tunnel Traffic: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- CVE-2026-123890 vCenter Auth Bypass - Unauthenticated Access to Management Endpoints: CommonSecurityLog must be populated by a CEF or syslog connector forwarding vCenter HTTP access logs; this connector is not present by default and must be explicitly configured.; prove correlation keys join correctly on real tenant telemetry.
- CVE-2026-123890 vCenter - Administrator Logon from Unexpected Source Post-Exploitation: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling..
- CVE-2026-73571 Zimbra SaveDraftRequest Authorization Bypass - Unauthenticated SOAP Exploitation: CommonSecurityLog must be populated by a CEF or syslog connector forwarding Zimbra HTTP access logs; this connector is not present by default and must be explicitly configured for the Zimbra deployment.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
