---
layout: post
title: "Detection Engineering Brief - Thursday, May 28, 2026"
subtitle: "Machine-speed threat intelligence translated into detection engineering action."
date: 2026-05-28
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - MITRE ATT&CK
  - Akira
  - Windows
  - ScreenConnect
  - .NET
  - T1021
  - T1021.001
  - T1021.002
  - T1078
  - T1071
  - T1071.001
  - T1496
---

## Executive Signal

This brief produced 5 detection candidates.

3 production candidates, 2 hunting-only, 0 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: Akira, Windows, ScreenConnect, .NET, T1021, T1021.001, T1021.002, T1078, T1071, T1071.001, T1496.

Deployment blockers or scheduling gates were identified for: Akira Intrusion - SMB or RDP Lateral Movement Spike Followed by Privileged Logon on Multiple Targets; Combined Miner and RAT C2 Behavior - High-Frequency Outbound Connections with CPU-Intensive Child Process.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: Akira Intrusion - Domain Admin Group Membership Change Following Privileged Logon

### Detection Opportunity

Account added to Domain Admins group during ransomware intrusion pre-encryption phase, correlated with prior privileged logon activity on domain controllers

### Intelligence Context

- SANS ISC: Reconstructing an Akira Ransomware Kill Chain from Perimeter and Endpoint Logs, (Wed, May 27th) — [https://isc.sans.edu/diary/rss/33024](https://isc.sans.edu/diary/rss/33024)
  - Context: The SANS ISC article reconstructs an Akira ransomware intrusion and specifically investigates when and how the attacker acquired domain admin privileges as a pre-encryption step. Windows Security Event logs (4672, 4728, 4732) are identified as the primary telemetry source for this activity.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1021, T1021.001, T1021.002, T1078
- Products: Not specified
- Platforms: Windows
- Malware: Akira
- Tools: Not specified
- Search tags: Akira, Windows, T1021, T1021.001, T1021.002, T1078

### Metadata

- Readiness: production candidate
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1021 Remote Services/ T1021.001 Remote Desktop Protocol (high); Lateral Movement: T1021 Remote Services/ T1021.002 SMB/Windows Admin Shares (high); Privilege Escalation: T1078 Valid Accounts (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- SecurityEvent

### KQL

```kql
let lookback = 60m;
let excluded_accounts = dynamic(["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"]);
let privileged_logons = SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4672
| where SubjectUserName !in~ (excluded_accounts)
| where isnotempty(SubjectUserName)
| summarize PrivLogonTime = min(TimeGenerated) by SubjectUserName, SubjectDomainName, Computer;
let group_additions = SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID in (4728, 4732)
| where GroupName has_any ("Domain Admins", "Administrators")
| where SubjectUserName !in~ (excluded_accounts)
| where isnotempty(SubjectUserName)
| project AddTime = TimeGenerated, SubjectUserName, SubjectDomainName, TargetUserName, TargetDomainName = column_ifexists("TargetDomainName", ""), GroupName, Computer;
group_additions
| join kind=inner privileged_logons on SubjectUserName, SubjectDomainName
| where AddTime between (PrivLogonTime .. (PrivLogonTime + lookback))
| summarize
    FirstSeen = min(AddTime),
    PrivLogonTime = min(PrivLogonTime),
    Count = count()
    by SubjectUserName, SubjectDomainName, TargetUserName, TargetDomainName, GroupName, Computer
| extend AlertDetail = strcat(SubjectUserName, "@", SubjectDomainName, " added ", TargetUserName, " to ", GroupName, " on ", Computer, " within 60m of privileged logon")
| project FirstSeen, PrivLogonTime, SubjectUserName, SubjectDomainName, TargetUserName, TargetDomainName, GroupName, Computer, Count, AlertDetail
| sort by FirstSeen desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate IT administrators adding accounts to privileged groups shortly after their own privileged logon during planned maintenance windows.
- Automated provisioning systems that log on with privileged tokens and then modify group membership as part of onboarding workflows.
- Password reset or break-glass account activation procedures that involve both a privileged logon and a group membership change.

Tuning notes:
- Extend lookback from 60m to 4h or 8h if threat intelligence indicates longer dwell times between initial access and privilege escalation in your environment.
- Add Enterprise Admins and Schema Admins to the GroupName filter if your AD topology uses these groups for equivalent privilege.
- Consider adding a watchlist of known privileged admin accounts to suppress alerts for expected administrative activity.
- Scope the Computer field to known domain controller hostnames using a watchlist or naming convention filter to exclude workstation-local Administrators group changes that may appear if non-DC machines forward these EventIDs.

Risks / caveats:
- EventID 4728 and 4732 are only generated when Advanced Audit Policy for Account Management is enabled on domain controllers. If this audit category is not configured, the SecurityEvent table will contain no records for these EventIDs and the detection will produce no results.
- EventID 4672 requires 'Audit Special Logon' to be enabled. Without it, privileged_logons will be empty and the join will return nothing.
- The 60-minute lookback window may miss slow-and-low intrusions where the attacker waits longer between privileged logon and group modification.
- If domain controllers forward logs with ingestion delay exceeding the lookback window, the join may miss correlated events.

### Triage Runbook

First 15 minutes:
- Confirm the actor account (SubjectUserName/SubjectDomainName) and the target account (TargetUserName/TargetDomainName) from the alert.
- Check whether the group change occurred on a domain controller and whether the same actor had a 4672 privileged logon shortly before the change.
- Validate with change-management records, ticketing, or the on-call AD team whether this membership change was expected.
- Look for additional suspicious activity from the actor account and target account around the same time, including other group changes, logons, or remote service use.

Evidence to collect:
- SecurityEvent 4672, 4728, and 4732 records for the actor and target within at least 4 hours of the alert.
- Domain controller hostname, timestamp, and any repeated group-add events for the same target account.
- Recent logon history for the actor account, including source host and logon type if available.
- Any related admin activity on the same domain controller, such as other privileged group modifications or account creations.

Pivot points:
- SecurityEvent for EventID 4672, 4728, 4732 filtered on SubjectUserName, TargetUserName, and Computer.
- SecurityEvent for other account management events involving the same SubjectUserName or TargetUserName.
- If available, correlate with sign-in or endpoint telemetry for the actor account source host to identify the initiating workstation.
- Review domain controller logs for adjacent administrative actions in the same time window.

Benign explanations:
- Planned administrative maintenance where a legitimate admin temporarily adds an account to a privileged group.
- Break-glass or emergency access procedures that require rapid privilege elevation.
- Automated provisioning or onboarding workflows that use privileged tokens to modify group membership.
- Password reset or account recovery workflows performed by authorized IT staff.

Escalation criteria:
- Escalate immediately if the change is not tied to a documented change request or approved maintenance window.
- Escalate if the actor account is unusual, newly created, or not normally used for domain administration.
- Escalate if there are multiple privileged group changes, especially across several accounts or groups, within a short period.
- Escalate if the target account is a service account, dormant account, or account not normally used for admin work.

Containment actions:
- Disable or reset the actor account if the change is unauthorized or if compromise is strongly suspected.
- Remove unauthorized privileged group membership immediately after preserving evidence.
- Isolate the source workstation or jump host used for the privileged logon if it can be identified and is not a domain controller.
- Increase monitoring on domain controllers and privileged accounts for additional group changes and logons.

Closure criteria:
- Change is confirmed as authorized by the AD owner or change ticket.
- No additional suspicious privileged activity is found for the actor or target account.
- Any unauthorized membership change has been reverted and documented.
- Related logs were reviewed and no evidence of broader intrusion was identified.

---

## Detection 2: Akira Intrusion - SMB or RDP Lateral Movement Spike Followed by Privileged Logon on Multiple Targets

### Detection Opportunity

Pre-encryption lateral movement pattern where a single host initiates SMB or RDP connections to multiple internal targets, followed by privileged logons on those targets, consistent with Akira staging behavior

### Intelligence Context

- SANS ISC: Reconstructing an Akira Ransomware Kill Chain from Perimeter and Endpoint Logs, (Wed, May 27th) — [https://isc.sans.edu/diary/rss/33024](https://isc.sans.edu/diary/rss/33024)
  - Context: The SANS ISC article investigates pre-encryption lateral movement and staging activity as part of the Akira kill chain reconstruction, correlating endpoint process and network telemetry with firewall perimeter logs to identify attacker movement before ransomware deployment.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1021, T1021.001, T1021.002, T1078
- Products: Not specified
- Platforms: Windows
- Malware: Akira
- Tools: Not specified
- Search tags: Akira, Windows, T1021, T1021.001, T1021.002, T1078

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1021 Remote Services/ T1021.001 Remote Desktop Protocol (high); Lateral Movement: T1021 Remote Services/ T1021.002 SMB/Windows Admin Shares (high); Privilege Escalation: T1078 Valid Accounts (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.
- RemoteDeviceName in DeviceLogonEvents is frequently null or empty for network logon events in many Defender XDR environments. If this field is not populated, the join between lateral_sources and DeviceLogonEvents will return no results.

Required telemetry:
- DeviceNetworkEvents, DeviceLogonEvents

### KQL

```kql
let smb_rdp_window = 30m;
let logon_window = 60m;
let lateral_sources = DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort in (445, 3389)
| where ActionType in ("ConnectionSuccess", "ConnectionAttempt")
| where RemoteIP !startswith "255."
    and RemoteIP !startswith "224."
    and RemoteIP != "127.0.0.1"
| summarize
    TargetCount = dcount(RemoteIP),
    TargetIPs = make_set(RemoteIP, 20),
    FirstConn = min(Timestamp)
    by DeviceName, bin(Timestamp, smb_rdp_window)
| where TargetCount >= 5
| project DeviceName, FirstConn, TargetIPs, TargetCount;
lateral_sources
| join kind=inner (
    DeviceLogonEvents
    | where Timestamp > ago(1d)
    | where LogonType in (3, 10)
    | where isnotempty(RemoteDeviceName)
    | project
        LogonTime = Timestamp,
        LogonDevice = DeviceName,
        RemoteDeviceName,
        AccountName,
        AccountDomain,
        LogonType
) on $left.DeviceName == $right.RemoteDeviceName
| where LogonTime between (FirstConn .. (FirstConn + logon_window))
| summarize
    LogonCount = dcount(LogonDevice),
    Accounts = make_set(AccountName, 10),
    LogonTypes = make_set(LogonType),
    FirstLogon = min(LogonTime)
    by DeviceName, FirstConn, TargetCount, tostring(TargetIPs)
| extend AlertDetail = strcat(DeviceName, " contacted ", TargetCount, " hosts over SMB/RDP then had privileged logons on ", LogonCount, " targets")
| project DeviceName, FirstConn, FirstLogon, TargetCount, TargetIPs, LogonCount, Accounts, LogonTypes, AlertDetail
| sort by FirstConn desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Vulnerability scanners, patch management systems, and backup agents that connect to many hosts over SMB within short windows.
- IT administrators using RDP jump hosts that legitimately connect to many systems in sequence.
- Domain controllers performing replication or SYSVOL access across many member servers.
- Monitoring agents that establish SMB connections for log collection or inventory.

Tuning notes:
- Run the lateral_sources subquery over 7 days and review DeviceName values that consistently exceed the threshold to build an exclusion list of known scanners and management systems.
- If RemoteDeviceName is sparsely populated, consider an alternative correlation using TargetIPs from the network events joined against DeviceLogonEvents on the logon device's IP address via DeviceInfo.
- Raise TargetCount to 10 or 15 in environments with active patch management or vulnerability scanning infrastructure.
- Restrict to LogonType 3 only if RDP-based remote administration generates excessive false positives.

Risks / caveats:
- RemoteDeviceName in DeviceLogonEvents is frequently null or empty for network logon events in many Defender XDR environments. If this field is not populated, the join between lateral_sources and DeviceLogonEvents will return no results.
- ActionType value 'ConnectionSuccess' may not be present in all Defender for Endpoint sensor configurations. Some environments only record 'ConnectionAttempt'. Verify ActionType values in DeviceNetworkEvents before relying on this filter.
- RemoteDeviceName sparsity is the primary reliability risk. Analysts should run DeviceLogonEvents | where isnotempty(RemoteDeviceName) | summarize count() to assess field population before using this query operationally.
- The 5-IP threshold requires environment-specific baselining. Environments with active vulnerability scanners or backup agents will need a higher threshold or process-based exclusions.

### Triage Runbook

First 15 minutes:
- Identify the source device, the set of target IPs, and the accounts used in the correlated logons.
- Check whether the source device is a known admin jump host, scanner, backup server, or management system.
- Review whether the logons are network or remote interactive logons and whether they occurred within the expected admin workflow.
- Look for signs of compromise on the source device, such as unusual parent processes, remote tools, or recent credential access activity.

Evidence to collect:
- DeviceNetworkEvents showing the source device contacting multiple internal targets over ports 445 and 3389.
- DeviceLogonEvents for the same time window, including AccountName, AccountDomain, LogonType, and RemoteDeviceName.
- Process ancestry on the source device for any remote administration tools, scripts, or suspicious binaries.
- A list of target hosts and whether they are servers, workstations, or domain controllers.

Pivot points:
- DeviceNetworkEvents filtered on DeviceName, RemotePort 445/3389, and the alert time window.
- DeviceLogonEvents filtered on the same DeviceName or RemoteDeviceName values and the same time window.
- DeviceProcessEvents on the source device for remote admin tools, scripting engines, or credential-dumping indicators.
- If available, DeviceInfo to confirm whether the source is a managed admin host or server.

Benign explanations:
- Legitimate remote administration from a jump host or help desk workstation.
- Vulnerability scanning, patch management, or inventory tooling that touches many hosts.
- Backup, monitoring, or software deployment systems that use SMB or RDP as part of normal operations.
- Domain controller or server maintenance activity performed by IT staff.

Escalation criteria:
- Escalate if the source device is not a known admin system and the activity spans multiple targets in a short period.
- Escalate if the same account is used across several hosts and the logons are not tied to a change window.
- Escalate if any target is a domain controller, file server, or other high-value asset.
- Escalate if the source device also shows suspicious process execution, credential access, or remote tool installation.

Containment actions:
- Isolate the source device if it is not a trusted management host and compromise is suspected.
- Disable or reset the account used for the logons if it is unauthorized or appears abused.
- Block or restrict the suspicious source-to-target paths temporarily if lateral movement is ongoing.
- Preserve volatile evidence from the source device before remediation if possible.

Closure criteria:
- The source device is confirmed as a legitimate admin, scanner, or management system.
- The accounts and target hosts match approved operational activity.
- No additional suspicious lateral movement or privileged logons are observed.
- Any unauthorized activity has been contained and documented.

---

## Detection 3: ScreenConnect Spawned by Browser or User Download Path - Cryptojacking Campaign Delivery

### Detection Opportunity

ScreenConnect remote access tool installed and executed with a browser or user download directory as the initiating process, consistent with SEO-poisoned download lure used in the GPU mining cryptojacking campaign

### Intelligence Context

- Microsoft Security Blog: From poisoned search results to GPU mining: A cryptojacking campaign abusing ScreenConnect and Microsoft .NET utilities — [https://www.microsoft.com/en-us/security/blog/2026/05/26/poisoned-search-results-gpu-mining-cryptojacking-campaign-abusing-screenconnect-microsoft-net-utilities/](https://www.microsoft.com/en-us/security/blog/2026/05/26/poisoned-search-results-gpu-mining-cryptojacking-campaign-abusing-screenconnect-microsoft-net-utilities/)
  - Context: Microsoft describes a cryptojacking campaign where victims are lured via SEO-poisoned search results to download ScreenConnect, which is then abused for remote access to deploy GPU mining payloads. The delivery chain involves a browser-initiated download followed by ScreenConnect execution.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1071.001, T1496
- Products: ScreenConnect
- Platforms: Windows, .NET
- Malware: Not specified
- Tools: ScreenConnect
- Search tags: ScreenConnect, Windows, .NET, T1071, T1071.001, T1496

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (low); Impact: T1496 Resource Hijacking (high)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
let browser_procs = dynamic(["chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe", "vivaldi.exe"]);
let suspicious_paths = dynamic(["\\Downloads\\", "\\Temp\\", "\\AppData\\Local\\Temp\\", "\\AppData\\Roaming\\", "\\AppData\\Local\\"]);
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe", "ScreenConnect.WindowsBackstageShell.exe")
| where
    InitiatingProcessFileName in~ (browser_procs)
    or FolderPath has_any (suspicious_paths)
    or FolderPath startswith "\\\\"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    SHA256,
    ProcessId,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    ReportId
| extend AlertDetail = strcat("ScreenConnect '", FileName, "' launched by '", InitiatingProcessFileName, "' from path: ", FolderPath)
| sort by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- IT administrators who download ScreenConnect installers via browser for legitimate deployment and execute them from the Downloads folder.
- Help desk staff who use browser-based ScreenConnect invitation links that trigger client installation from a browser parent process.
- Automated deployment scripts that stage ScreenConnect in Temp directories as part of a managed rollout.

Tuning notes:
- Run a 30-day baseline query for ScreenConnect process names to identify all FolderPath values used by legitimate IT deployments and add them as exclusions.
- If the organization uses a custom-branded ScreenConnect client, add the custom executable name to the FileName filter.
- Consider adding a SHA256 allowlist for known-good ScreenConnect installer hashes to reduce false positives from legitimate IT downloads.
- Add AccountName exclusions for IT service accounts or help desk accounts that legitimately deploy ScreenConnect via browser.

Risks / caveats:
- Custom-branded ScreenConnect deployments use non-default executable names. If the organization's ScreenConnect instance uses a renamed binary, the FileName filter will not match and the detection will produce no results for that variant.
- Legitimate IT-managed ScreenConnect deployments that install to AppData or are initiated by browser-based invitation links will generate false positives until an allowlist of known-good FolderPath values or AccountName values is applied.
- Custom-branded ScreenConnect builds with non-default executable names will not be caught by the FileName filter. The SHA256 field in results can be used to identify renamed variants after initial detection.
- The FolderPath has_any check is case-sensitive on some Defender XDR versions; the in~ operator handles case for FileName but has_any does not use case-insensitive matching by default. Paths with unexpected casing may be missed.

### Triage Runbook

First 15 minutes:
- Confirm the initiating process and path: browser parent, Downloads, Temp, AppData, or UNC path.
- Identify the user account and device involved and determine whether ScreenConnect is expected on that endpoint.
- Check whether the execution was part of a sanctioned IT deployment or a user-initiated download from the web.
- Look for immediate follow-on activity such as additional payload downloads, script execution, or new persistence mechanisms.

Evidence to collect:
- DeviceProcessEvents for the ScreenConnect executable, its parent process, command line, SHA256, and process IDs.
- Any related browser download activity or file creation events leading up to execution.
- The user account, device name, and exact folder path where ScreenConnect was launched from.
- Any subsequent child processes or network connections spawned by ScreenConnect after launch.

Pivot points:
- DeviceProcessEvents for ScreenConnect file names and their parent processes on the same device.
- DeviceFileEvents or related file telemetry, if available, to confirm download and staging behavior.
- DeviceNetworkEvents for outbound connections from the same device after ScreenConnect execution.
- Search for the SHA256 across the environment to determine whether the binary is unique or broadly deployed.

Benign explanations:
- Legitimate help desk or IT-managed ScreenConnect installation.
- A user following a valid support link that installs ScreenConnect from a browser.
- A managed rollout that stages the client in Temp or AppData during deployment.
- Testing or remote support activity on a lab system.

Escalation criteria:
- Escalate if the device is not managed by IT or ScreenConnect is not approved on that endpoint.
- Escalate if the binary was launched from a user download directory or browser parent and there is no ticket or deployment record.
- Escalate if the device shows follow-on mining, persistence, or additional remote access activity.
- Escalate if the SHA256 is unknown and the process tree includes suspicious scripting or archive extraction.

Containment actions:
- Terminate the ScreenConnect process if it is unauthorized or clearly part of malicious activity.
- Isolate the endpoint if there is evidence of follow-on payload execution or remote control.
- Block the observed SHA256 or related download source if confirmed malicious.
- Disable the user account temporarily if the download/execution appears to be user-driven compromise.

Closure criteria:
- ScreenConnect installation is confirmed as authorized and matches a known deployment or support workflow.
- No suspicious follow-on activity is observed after the execution.
- The file hash and path are matched to a known-good package or approved IT process.
- Any unauthorized remote access component has been removed or blocked.

---

## Detection 4: GPU Miner Process with Stratum Protocol Connection - Cryptojacking Campaign Payload Execution

### Detection Opportunity

Miner process executing with stratum protocol command-line arguments and establishing outbound connections on common mining pool ports, consistent with the GPU mining payload deployed in the ScreenConnect cryptojacking campaign

### Intelligence Context

- Microsoft Security Blog: From poisoned search results to GPU mining: A cryptojacking campaign abusing ScreenConnect and Microsoft .NET utilities — [https://www.microsoft.com/en-us/security/blog/2026/05/26/poisoned-search-results-gpu-mining-cryptojacking-campaign-abusing-screenconnect-microsoft-net-utilities/](https://www.microsoft.com/en-us/security/blog/2026/05/26/poisoned-search-results-gpu-mining-cryptojacking-campaign-abusing-screenconnect-microsoft-net-utilities/)
  - Context: Microsoft reports that after gaining remote access via ScreenConnect, the campaign deploys GPU mining payloads on high-performance PCs. Miner processes use stratum protocol connections to mining pool infrastructure on characteristic ports.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1071.001, T1496
- Products: ScreenConnect
- Platforms: Windows, .NET
- Malware: Not specified
- Tools: ScreenConnect
- Search tags: ScreenConnect, Windows, .NET, T1071, T1071.001, T1496

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (low); Impact: T1496 Resource Hijacking (high)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let mining_ports = dynamic([3333, 4444, 5555, 14444, 45700]);
let miner_flags = dynamic(["--stratum", "stratum+tcp", "stratum+ssl", "xmrig", "--pool", "--coin", "--algo"]);
let miner_binary_names = dynamic(["xmrig.exe", "xmrig-cuda.exe", "xmrig-opencl.exe", "minerd.exe", "cgminer.exe", "nbminer.exe", "t-rex.exe", "gminer.exe", "lolminer.exe", "phoenixminer.exe"]);
let miner_procs = DeviceProcessEvents
| where Timestamp > ago(1d)
| where
    ProcessCommandLine has_any (miner_flags)
    or FileName in~ (miner_binary_names)
| extend DetectionBasis = case(
    FileName in~ (miner_binary_names) and ProcessCommandLine has_any (miner_flags), "BinaryName+CommandLine",
    FileName in~ (miner_binary_names), "BinaryName",
    "CommandLine"
)
| project
    MinerTime = Timestamp,
    DeviceName,
    AccountName,
    FileName,
    SHA256,
    ProcessId,
    ProcessCommandLine,
    InitiatingProcessFileName,
    DetectionBasis,
    ReportId;
let mining_conns = DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort in (mining_ports)
| project
    ConnTime = Timestamp,
    DeviceName,
    RemoteIP,
    RemotePort,
    RemoteUrl;
miner_procs
| join kind=leftouter mining_conns on DeviceName
| where isnull(ConnTime) or ConnTime between (MinerTime .. (MinerTime + 10m))
| summarize
    FirstSeen = min(MinerTime),
    Ports = make_set(RemotePort, 10),
    RemoteIPs = make_set(RemoteIP, 10),
    RemoteUrls = make_set(RemoteUrl, 10),
    HasNetworkCorrelation = max(iff(isnotempty(ConnTime), 1, 0))
    by DeviceName, AccountName, FileName, SHA256, ProcessCommandLine, InitiatingProcessFileName, DetectionBasis, ReportId
| where HasNetworkCorrelation == 1
| extend AlertDetail = strcat("Miner '", FileName, "' (", DetectionBasis, ") on ", DeviceName, " connected to mining ports: ", tostring(Ports))
| project FirstSeen, DeviceName, AccountName, FileName, SHA256, ProcessCommandLine, InitiatingProcessFileName, DetectionBasis, Ports, RemoteIPs, RemoteUrls, HasNetworkCorrelation, AlertDetail, ReportId
| sort by FirstSeen desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Game servers or development environments that use port 3333 or 4444 for non-mining purposes.
- Legitimate cryptocurrency mining operations in environments where this activity is authorized.
- Security research or malware analysis sandboxes that execute miner samples.

Tuning notes:
- Run the mining_conns subquery over 7 days and review RemoteIP and RemoteUrl values to identify any legitimate services using ports 3333, 4444, or 5555 before scheduling.
- Add lolminer.exe and phoenixminer.exe to the binary name list if GPU-specific miners are a concern in the environment; these are included in the improved query.
- Consider joining results against ScreenConnect process ancestry using a separate DeviceProcessEvents query on InitiatingProcessFileName to add campaign-specific context when ScreenConnect is in the process tree.
- If ProcessCommandLine is frequently truncated in the environment, supplement with a DeviceFileEvents query looking for miner binary names written to disk as a parallel detection.

Risks / caveats:
- ProcessCommandLine may be truncated for processes with very long argument strings in some Defender for Endpoint sensor configurations, potentially causing stratum flag matching to fail for miners with lengthy pool lists.
- The 10-minute join window between process creation and network connection may be too narrow if the miner takes longer to establish its first pool connection after launch. Extend to 20m if missed detections are observed.
- Port 3333 and 4444 are used by some legitimate game servers and development tools. Validate against DeviceNetworkEvents for these ports before scheduling to identify any environment-specific exclusions needed.
- The leftouter join followed by HasNetworkCorrelation filter is logically equivalent to an inner join in this query; it was structured this way for clarity but can be simplified to kind=inner if performance is a concern on large datasets.

### Triage Runbook

First 15 minutes:
- Identify the miner binary, command line, account, and device from the alert.
- Verify the outbound connection details, including remote IP, URL, and port, and whether they match known mining infrastructure.
- Check whether the host is a lab, research system, or approved cryptocurrency mining environment.
- Look for the process tree to see whether the miner was launched by ScreenConnect, a script, or another suspicious parent process.

Evidence to collect:
- DeviceProcessEvents for the miner process, including FileName, SHA256, ProcessCommandLine, ProcessId, and parent process.
- DeviceNetworkEvents showing the mining port connection, remote IPs, and any RemoteUrl values.
- Process ancestry and any preceding download, archive extraction, or script execution events.
- Host resource indicators if available, such as sustained CPU/GPU usage or thermal alerts.

Pivot points:
- DeviceProcessEvents for the miner SHA256 or FileName across the environment.
- DeviceNetworkEvents for the remote IPs, URLs, and ports associated with the miner.
- DeviceProcessEvents for the parent process and any ScreenConnect-related ancestry on the same device.
- Threat intelligence or blocklist lookups for the remote IPs and domains if available.

Benign explanations:
- Authorized cryptocurrency mining in a lab, research, or approved business environment.
- Security research or malware analysis activity in a sandbox.
- A legitimate application using one of the flagged ports in a non-mining context, though this should be validated carefully.
- A false positive from a renamed tool that matches miner-like flags but is not a miner.

Escalation criteria:
- Escalate if the host is not an approved mining system and the process is connecting to mining ports or pools.
- Escalate if the miner is launched by ScreenConnect, a browser download, or another suspicious parent process.
- Escalate if the same host also shows additional remote access, persistence, or credential abuse.
- Escalate if multiple hosts show the same miner hash or remote infrastructure.

Containment actions:
- Terminate the miner process and isolate the host if unauthorized mining is confirmed.
- Block the mining pool IPs/domains and the miner hash if validated as malicious.
- Remove any persistence mechanisms or remote access tools used to deploy the miner.
- Reset credentials if the miner was deployed through compromised remote access or stolen accounts.

Closure criteria:
- The miner is confirmed as authorized or is removed and blocked.
- No additional mining-related network traffic or processes remain on the host.
- The process tree and remote infrastructure were reviewed and no broader compromise was identified.
- Any malicious hashes, domains, or IPs have been added to blocking or hunting lists.

---

## Detection 5: Combined Miner and RAT C2 Behavior - High-Frequency Outbound Connections with CPU-Intensive Child Process

### Detection Opportunity

A process exhibiting both high-frequency outbound C2-pattern connections and spawning CPU-intensive child processes consistent with mining, reflecting the miner-plus-RAT module combination described in the piracy-themed malware campaign

### Intelligence Context

- Securelist: Pirates in the crosshairs: how one cybercrime gang has been infecting book, movie, and TV show fans for years — [https://securelist.com/video-books-pirates-miners-rat/119943/](https://securelist.com/video-books-pirates-miners-rat/119943/)
  - Context: Securelist reports a long-running campaign targeting consumers of pirated content where a miner payload was updated to include a RAT module. The combined behavior of mining activity and RAT C2 communication from the same process or process tree is the distinguishing characteristic of this threat.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1071.001, T1496
- Products: Not specified
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: T1071, T1071.001, T1496

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Command and Control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (low); Impact: T1496 Resource Hijacking (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let time_window = 30m;
let miner_flags = dynamic(["--stratum", "stratum+tcp", "--pool", "--algo", "xmrig", "--coin"]);
let excluded_procs = dynamic(["svchost.exe", "MsMpEng.exe", "OneDrive.exe", "Teams.exe", "msedge.exe", "chrome.exe", "firefox.exe", "SearchIndexer.exe", "WmiPrvSE.exe"]);
let excluded_ports = dynamic([80, 443, 53, 8080, 8443, 123, 67, 68, 5353]);
let high_freq_c2 = DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort !in (excluded_ports)
| where InitiatingProcessFileName !in~ (excluded_procs)
| where isnotempty(InitiatingProcessFileName)
| summarize
    RemoteCount = dcount(RemoteIP),
    FirstConn = min(Timestamp)
    by DeviceName, ParentProc = InitiatingProcessFileName, bin(Timestamp, time_window)
| where RemoteCount >= 10
| project DeviceName, ParentProc, FirstConn, RemoteCount;
let miner_children = DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (miner_flags)
| where isnotempty(InitiatingProcessFileName)
| project
    ChildTime = Timestamp,
    DeviceName,
    ChildFile = FileName,
    ParentProc = InitiatingProcessFileName,
    ProcessCommandLine,
    AccountName;
high_freq_c2
| join kind=inner miner_children on DeviceName, ParentProc
| where ChildTime between (FirstConn .. (FirstConn + time_window))
| summarize
    FirstSeen = min(FirstConn),
    MinerChildren = make_set(ChildFile, 5),
    CommandLineSamples = make_set(ProcessCommandLine, 3),
    AccountNames = make_set(AccountName, 5),
    RemoteCount = max(RemoteCount)
    by DeviceName, ParentProc
| extend AlertDetail = strcat(ParentProc, " on ", DeviceName, " shows high-frequency outbound connections (", RemoteCount, " IPs) and spawned miner-flagged children: ", tostring(MinerChildren))
| project FirstSeen, DeviceName, ParentProc, RemoteCount, MinerChildren, CommandLineSamples, AccountNames, AlertDetail
| sort by FirstSeen desc
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Software update agents (Windows Update, Chrome updater, software deployment tools) that contact many CDN endpoints and also spawn child processes.
- Development environments where build tools spawn child processes with flags that partially match miner_flags (e.g., --algo in build systems).
- Security tools that perform network scanning and also spawn analysis child processes.
- Browsers that maintain many simultaneous connections and spawn renderer child processes.

Tuning notes:
- Run the high_freq_c2 subquery over 48-72 hours and add any ParentProc values that consistently appear with high RemoteCount but are known-legitimate to the excluded_procs list.
- Review CommandLineSamples in hunting results to identify any build tools or legitimate software that matches miner_flags and add them to a ProcessCommandLine exclusion.
- Consider raising the RemoteCount threshold to 20 or 30 in environments with active telemetry agents or software distribution systems.
- This query is best used as a starting point for threat hunting sessions rather than as an unattended scheduled rule. Analyst review of ParentProc and CommandLineSamples is recommended before escalating results.

Risks / caveats:
- InitiatingProcessFileName must be consistently populated in both DeviceNetworkEvents and DeviceProcessEvents for the join on ParentProc to produce results. Sparse population of this field in DeviceNetworkEvents will cause the join to miss correlated events.
- The 10-distinct-IP threshold remains a heuristic that requires environment-specific baselining. Run the high_freq_c2 subquery alone over 48 hours and review ParentProc values before using results operationally.
- The miner_flags list includes '--algo' which is a common flag in many legitimate command-line tools beyond miners. Review CommandLineSamples in results to filter false matches.
- The bin(Timestamp, time_window) grouping may split events across bin boundaries, causing the RemoteCount to fall below threshold for activity that spans a 30-minute boundary.

### Triage Runbook

First 15 minutes:
- Identify the parent process, child miner process, and the account involved from the alert.
- Review the remote connection pattern to see whether the parent process is contacting many distinct IPs or unusual destinations.
- Check whether the parent process is a known legitimate updater, browser, or management tool before assuming compromise.
- Look for evidence of persistence, additional child processes, or recent file downloads associated with the same parent process.

Evidence to collect:
- DeviceNetworkEvents for the parent process showing remote IPs, ports, and connection frequency.
- DeviceProcessEvents for the child miner process, including command line, SHA256, and process ancestry.
- Command line samples and account names tied to the suspicious process tree.
- Any persistence artifacts or follow-on processes launched by the same parent on the same device.

Pivot points:
- DeviceNetworkEvents filtered on the parent process name and device to review the connection pattern.
- DeviceProcessEvents for the child process SHA256 and any sibling processes spawned by the same parent.
- DeviceProcessEvents for known legitimate updaters or browsers to compare against the alert pattern.
- If available, endpoint telemetry for file writes, scheduled tasks, services, or registry changes tied to the same process tree.

Benign explanations:
- Software update agents, browsers, or telemetry services that make many outbound connections and spawn child processes.
- Development or build tools that use command-line flags similar to miner flags.
- Security tools or scanners that generate high network activity and launch helper processes.
- Legitimate remote support or management software in an enterprise environment.

Escalation criteria:
- Escalate if the parent process is not a known legitimate service and the child process matches miner behavior.
- Escalate if the host is a user workstation or server with no approved mining or remote management use case.
- Escalate if the same process tree also shows persistence, credential theft, or additional suspicious network destinations.
- Escalate if multiple hosts exhibit the same parent process and command line pattern.

Containment actions:
- Isolate the host if the process tree is not clearly legitimate and the miner behavior is confirmed.
- Terminate the suspicious parent and child processes after preserving evidence if possible.
- Block the observed remote IPs/domains and hashes associated with the process tree.
- Disable or reset the account if the activity appears tied to compromised credentials or remote access.

Closure criteria:
- The parent process is confirmed as a legitimate updater, browser, or management tool with matching business justification.
- The child process is determined to be benign or the malicious components are removed.
- No persistence, additional malware, or suspicious remote destinations are found.
- The alert is documented with the validated explanation and any exclusions needed for future tuning.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Schema / correlation keys:
- Akira Intrusion - SMB or RDP Lateral Movement Spike Followed by Privileged Logon on Multiple Targets: Do not schedule yet; validate as an analyst-led hunt first.
- Akira Intrusion - SMB or RDP Lateral Movement Spike Followed by Privileged Logon on Multiple Targets: RemoteDeviceName in DeviceLogonEvents is frequently null or empty for network logon events in many Defender XDR environments. If this field is not populated, the join between lateral_sources and DeviceLogonEvents will return no results.
- Combined Miner and RAT C2 Behavior - High-Frequency Outbound Connections with CPU-Intensive Child Process: Do not schedule yet; validate as an analyst-led hunt first.

Shared-table notes:
- DeviceNetworkEvents: shared by Akira Intrusion - SMB or RDP Lateral Movement Spike Followed by Privileged Logon on Multiple Targets; GPU Miner Process with Stratum Protocol Connection - Cryptojacking Campaign Payload Execution; Combined Miner and RAT C2 Behavior - High-Frequency Outbound Connections with CPU-Intensive Child Process
- DeviceProcessEvents: shared by ScreenConnect Spawned by Browser or User Download Path - Cryptojacking Campaign Delivery; GPU Miner Process with Stratum Protocol Connection - Cryptojacking Campaign Payload Execution; Combined Miner and RAT C2 Behavior - High-Frequency Outbound Connections with CPU-Intensive Child Process

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Akira Intrusion - Domain Admin Group Membership Change Following Privileged Logon; ScreenConnect Spawned by Browser or User Download Path - Cryptojacking Campaign Delivery; GPU Miner Process with Stratum Protocol Connection - Cryptojacking Campaign Payload Execution.
2. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Akira Intrusion - SMB or RDP Lateral Movement Spike Followed by Privileged Logon on Multiple Targets; Combined Miner and RAT C2 Behavior - High-Frequency Outbound Connections with CPU-Intensive Child Process.

### Hunting Agenda and Promotion Criteria

- Akira Intrusion - SMB or RDP Lateral Movement Spike Followed by Privileged Logon on Multiple Targets: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Combined Miner and RAT C2 Behavior - High-Frequency Outbound Connections with CPU-Intensive Child Process: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
