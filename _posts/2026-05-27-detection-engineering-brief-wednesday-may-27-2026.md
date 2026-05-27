---
layout: post
title: "Detection Engineering Brief - Wednesday, May 27, 2026"
subtitle: "Machine-speed threat intelligence translated into detection engineering action."
date: 2026-05-27
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - MITRE ATT&CK
---

## Executive Signal

This brief produced 5 detection candidates.

2 production candidates, 1 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Deployment blockers or scheduling gates were identified for: Kerberos Relay Attempt from Linux Host to Internal Server; Linux Process Accessing Credential Store Paths Following Edge Appliance Pivot; Browser-Spawned Executable Accessing Credential Paths Followed by Outbound Network Connection.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

## Detection 1: Kerberos Relay Attempt from Linux Host to Internal Server

### Detection Opportunity

Linux-originated Kerberos TGS requests targeting internal enterprise servers following edge appliance compromise

### Intelligence Context

- Microsoft Security Blog: From edge appliance to enterprise compromise: Multi-stage Linux intrusion via F5 and Confluence — https://www.microsoft.com/en-us/security/blog/2026/05/22/from-edge-appliance-to-enterprise-compromise-multi-stage-linux-intrusion-via-f5-and-confluence/
  - Context: After pivoting from a compromised F5 edge appliance to an internal Confluence server, the attacker attempted Kerberos relay from a Linux host to authenticate against internal Windows services, a rare and high-fidelity indicator of post-exploitation lateral movement.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Lateral Movement: T1550 Use Alternate Authentication Material/ T1550.003 Pass the Ticket (high)

### Deployment Gates

- Syslog table must be populated by Linux host syslog forwarding via the Log Analytics agent or AMA Syslog connector. If Linux hosts do not forward syslog to Sentinel, the join will return no results.

Required telemetry:
- SecurityEvent, Syslog

### KQL

```kql
let lookback = 1h;
let kerberos_tgs = SecurityEvent
| where TimeGenerated >= ago(lookback)
| where EventID == 4769
| where AuthenticationPackageName == "Kerberos"
| where TargetServerName !endswith "$" and isnotempty(TargetServerName)
| where IpAddress !startswith "::" and IpAddress != "-" and isnotempty(IpAddress)
| where Status == "0x0"
| project TimeGenerated, AccountName, TargetServerName, IpAddress, Computer, TicketEncryptionType, TicketOptions;
let linux_kerberos_syslog = Syslog
| where TimeGenerated >= ago(lookback)
| where SyslogMessage has_any ("krb5", "kinit", "kvno", "impacket", "getTGT", "getST")
| project SyslogTime = TimeGenerated, SyslogHost = Computer, SyslogMessage;
kerberos_tgs
| join kind=inner linux_kerberos_syslog on $left.IpAddress == $right.SyslogHost
| where datetime_diff('minute', TimeGenerated, SyslogTime) between (-10 .. 10)
| project TimeGenerated, AccountName, TargetServerName, IpAddress, TicketEncryptionType, TicketOptions, SyslogMessage, DomainController = Computer
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Legitimate Linux hosts running Kerberos-integrated applications (e.g., SSSD, Samba, web servers with Kerberos auth) will generate 4769 events and may log krb5 messages. Analyst review of AccountName and TargetServerName is required.
- Automated service account renewals on Linux hosts may produce matching Syslog entries coinciding with 4769 events.

Tuning notes:
- To increase fidelity, restrict TargetServerName to a known list of high-value internal servers such as Confluence, domain controllers, or file servers.
- If the environment uses AES Kerberos exclusively, add a filter for TicketEncryptionType == '0x17' to flag RC4 downgrade attempts specifically associated with impacket relay.
- Consider adding a watchlist of known Linux host IPs to pre-filter IpAddress values to only Linux-origin requests rather than relying solely on Syslog correlation.

Risks / caveats:
- Syslog table must be populated by Linux host syslog forwarding via the Log Analytics agent or AMA Syslog connector. If Linux hosts do not forward syslog to Sentinel, the join will return no results.
- SecurityEvent 4769 IpAddress field contains the requesting client IP. The Syslog Computer field typically contains a hostname, not an IP. The join on IpAddress == HostName will fail unless the Syslog Computer field is configured to emit IP addresses, which is non-default. Environment-specific DNS resolution or an IP-to-hostname mapping table is required to make this join reliable.
- The 1-hour lookback is appropriate for near-real-time hunting but should be extended to 24 hours for scheduled execution to account for Syslog ingestion latency.
- The join time window of 10 minutes may need adjustment based on observed ingestion delay between Syslog and SecurityEvent in the specific workspace.

### Triage Runbook

First 15 minutes:
- Confirm the alert is tied to a real Linux source host and not a hostname/IP mapping issue in the environment.
- Review the target server and account to see whether the ticket request was for a high-value server or privileged account.
- Check whether the same source IP generated multiple 4769 events across different servers in a short window.
- Look for Linux syslog evidence of krb5, kinit, kvno, impacket, getTGT, or getST activity around the same time.

Evidence to collect:
- SecurityEvent 4769 details: AccountName, TargetServerName, IpAddress, TicketEncryptionType, TicketOptions, Status, TimeGenerated.
- Syslog entries from the suspected Linux host showing Kerberos tooling or relay-related commands.
- Any adjacent authentication events from the same source IP, especially repeated TGS requests or unusual service targets.
- Host inventory or CMDB data to determine whether the source IP belongs to a known Linux server, appliance, or jump host.

Pivot points:
- SecurityEvent for 4769, 4768, and 4771 events from the same IpAddress and AccountName.
- Syslog for the suspected Linux host around the alert time to identify the process or user invoking Kerberos tooling.
- Device or asset inventory to map IpAddress to hostname, owner, and expected function.
- If available, network or proxy logs for the source IP to identify lateral movement or remote administration activity.

Benign explanations:
- A legitimate Linux service using Kerberos-integrated authentication to access Windows services.
- Automated service account renewals or scheduled jobs on a joined Linux host.
- A misconfigured environment where the Syslog host field does not map cleanly to the source IP, causing an apparent correlation.

Escalation criteria:
- The source IP is an unapproved Linux host or edge appliance and the target is a domain controller, file server, or other high-value system.
- Multiple successful TGS requests are observed for different internal services from the same source in a short period.
- Syslog confirms use of impacket, getST, getTGT, or similar tooling on the source host.
- The account involved is privileged, unusual for Linux, or not expected to authenticate to the target server.

Containment actions:
- Isolate the suspected Linux source host if the activity is confirmed malicious or strongly suspicious.
- Disable or reset any account credentials that appear to be abused for relay or ticket requests.
- Block the source IP at network controls if the host cannot be immediately isolated and the activity is ongoing.
- Preserve volatile evidence on the Linux host before remediation if incident response support is available.

Closure criteria:
- The source host is confirmed as a legitimate Linux Kerberos client and the activity matches expected service behavior.
- The alert is attributable to a known admin action, scheduled task, or approved integration and no other suspicious authentication activity is present.
- No corroborating syslog, authentication, or network evidence supports relay tooling or lateral movement.
- Any false-positive mapping issue between Syslog and SecurityEvent has been validated and documented.

---

## Detection 2: Linux Process Accessing Credential Store Paths Following Edge Appliance Pivot

### Detection Opportunity

Credential theft via Linux process access to sensitive credential paths after lateral movement from a compromised edge appliance

### Intelligence Context

- Microsoft Security Blog: From edge appliance to enterprise compromise: Multi-stage Linux intrusion via F5 and Confluence — https://www.microsoft.com/en-us/security/blog/2026/05/22/from-edge-appliance-to-enterprise-compromise-multi-stage-linux-intrusion-via-f5-and-confluence/
  - Context: Following the pivot from the F5 appliance to the internal Confluence Linux server, the attacker performed credential theft targeting Linux credential stores, consistent with post-exploitation credential harvesting to enable further lateral movement.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1003 OS Credential Dumping/ T1003.008 /etc/passwd and /etc/shadow (high)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

Required telemetry:
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let lookback = 24h;
let cred_paths = dynamic(["/etc/shadow", "/etc/passwd", "/etc/gshadow", ".ssh/id_rsa", ".gnome2/keyrings", ".local/share/keyrings"]);
let suspicious_procs = dynamic(["cat", "cp", "base64", "xxd", "strings", "python", "python3", "perl", "ruby", "curl", "wget", "nc", "ncat"]);
let excluded_procs = dynamic(["apt", "dpkg", "rpm", "yum", "dnf", "passwd", "chage", "useradd", "usermod"]);
let proc_cred_access = DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where ProcessCommandLine has_any (cred_paths)
| where InitiatingProcessFileName !in~ (excluded_procs)
| where FileName in~ (suspicious_procs)
| project DeviceName, Timestamp, InitiatingProcessFileName, InitiatingProcessAccountName, FileName, ProcessCommandLine, SHA256;
let file_cred_events = DeviceFileEvents
| where Timestamp >= ago(lookback)
| where FolderPath has_any (cred_paths)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where InitiatingProcessFileName in~ (suspicious_procs)
| where InitiatingProcessFileName !in~ (excluded_procs)
| project DeviceName, FileTimestamp = Timestamp, FolderPath, FileName, ActionType, InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessCommandLine;
proc_cred_access
| join kind=leftouter file_cred_events on DeviceName
| where isnull(FileTimestamp) or datetime_diff('minute', Timestamp, FileTimestamp) between (-5 .. 5)
| project Timestamp, DeviceName, SuspiciousProcess = FileName, InitiatingProcessFileName, InitiatingProcessAccountName, ProcessCommandLine, SHA256, FolderPath, ActionType, InitiatingProcessCommandLine
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- System administrators running manual audits or backup scripts that read /etc/passwd or /etc/shadow.
- Configuration management tools (Ansible, Chef, Puppet) that read credential files as part of compliance checks.
- Password management utilities run by root during legitimate user provisioning.

Tuning notes:
- Scope DeviceName to known Linux servers reachable from edge appliances to reduce noise from developer workstations.
- Add InitiatingProcessAccountName exclusions for known service accounts that legitimately invoke Python or Perl scripts in the environment.
- If the environment confirms FileRead ActionType is available in DeviceFileEvents for Linux, add it back to the ActionType filter for higher-fidelity file access detection.

Risks / caveats:
- ActionType values 'FileRead' and 'FileAccessed' are not documented as standard Linux MDE telemetry ActionType values. On Linux, DeviceFileEvents primarily captures FileCreated, FileModified, FileDeleted, and FileRenamed. A query relying on FileRead or FileAccessed for Linux hosts may return zero results. This must be validated in the target environment before the query is meaningful.
- DeviceFileEvents file access telemetry for /etc/shadow and /etc/passwd requires that MDE on Linux is configured with sufficient audit policy or fanotify coverage for read events, which is not guaranteed by default deployment.
- The primary signal (ProcessCommandLine containing credential paths) will miss cases where the attacker uses a compiled binary that does not pass the path as a command-line argument.
- DeviceFileEvents ActionType coverage for read operations on Linux must be validated in the environment. If only FileCreated/FileModified/FileRenamed are available, the file event corroboration will only catch cases where the attacker copies or modifies credential files rather than reads them in place.

### Triage Runbook

First 15 minutes:
- Identify the exact process name, command line, and account that touched the credential path.
- Check whether the process is a known admin tool, backup utility, or configuration management agent.
- Review whether the host is a server expected to handle Linux credential files or whether the access is anomalous.
- Look for nearby signs of staging, compression, archiving, or outbound transfer from the same host.

Evidence to collect:
- DeviceProcessEvents for the suspicious process, including ProcessCommandLine, FileName, InitiatingProcessFileName, and InitiatingProcessAccountName.
- DeviceFileEvents for any related file creation, modification, or renaming in credential-related paths.
- Process tree context to determine whether the activity originated from a shell, script, remote session, or known admin tool.
- Host identity and role information to determine whether the system is a Linux server, jump host, or appliance pivot target.

Pivot points:
- DeviceProcessEvents for the same DeviceName and account to find preceding shell, archive, or transfer activity.
- DeviceFileEvents for access to /etc/shadow, /etc/passwd, /etc/gshadow, .ssh/id_rsa, and keyring paths.
- DeviceNetworkEvents for outbound connections from the same host shortly after the credential-path activity.
- If available, Linux audit or syslog data for commands such as cat, cp, tar, base64, scp, curl, wget, or nc.

Benign explanations:
- A system administrator performing a legitimate audit, backup, or recovery task.
- Configuration management or compliance tooling reading credential-related files as part of normal operations.
- Password or account provisioning workflows that temporarily access /etc/passwd or /etc/shadow.

Escalation criteria:
- The process is not a known administrative or automation tool and the command line suggests credential harvesting or staging.
- The host is a recently pivoted server or an internal system not normally used for credential administration.
- There is evidence of follow-on exfiltration, compression, or remote transfer after the file access.
- The initiating account is unexpected, non-interactive, or associated with a compromised service.

Containment actions:
- Isolate the host if credential theft is confirmed or strongly suspected.
- Disable or rotate credentials that may have been exposed, especially local admin, service, or SSH keys.
- Preserve process, file, and network evidence before rebooting or cleaning the system.
- Block known malicious outbound destinations if exfiltration is observed.

Closure criteria:
- The process is verified as a legitimate admin, backup, or configuration management action.
- The accessed paths and timing align with approved maintenance or provisioning activity.
- No evidence of staging, exfiltration, or unauthorized privilege escalation is found.
- Any telemetry limitations or missing read-event coverage have been documented and the alert is judged non-actionable.

---

## Detection 3: ScreenConnect Spawning GPU-Intensive or Mining-Related Child Processes

### Detection Opportunity

ScreenConnect remote access software used as execution vector to launch cryptomining payloads delivered via poisoned search results

### Intelligence Context

- Microsoft Security Blog: From poisoned search results to GPU mining: A cryptojacking campaign abusing ScreenConnect and Microsoft .NET utilities — https://www.microsoft.com/en-us/security/blog/2026/05/26/poisoned-search-results-gpu-mining-cryptojacking-campaign-abusing-screenconnect-microsoft-net-utilities/
  - Context: Victims were directed via SEO-poisoned search results to download ScreenConnect, which was then abused by the attacker to remotely deploy and execute GPU cryptomining payloads. The parent-child process chain from ScreenConnect to mining processes is the primary behavioral indicator.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1106 Native API (low); Impact: T1496 Resource Hijacking (high)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let lookback = 1d;
let mining_ports = dynamic([3333, 4444, 14444, 45700, 14433, 3334]);
let mining_keywords = dynamic(["stratum+tcp", "stratum+ssl", "--algo", "--pool", "xmrig", "nbminer", "t-rex", "lolminer", "gminer"]);
let screenconnect_children = DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where InitiatingProcessFileName has_any ("ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe", "screenconnect")
| where FileName !in~ ("ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe")
| project DeviceName, ChildProcessName = FileName, ProcessId, ProcessCommandLine, SHA256, InitiatingProcessAccountName, ChildTimestamp = Timestamp;
let mining_network = DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where ActionType == "ConnectionSuccess"
| where RemotePort in (mining_ports) or InitiatingProcessCommandLine has_any (mining_keywords)
| where not(ipv4_is_private(RemoteIP))
| project DeviceName, RemoteIP, RemotePort, NetProcessName = InitiatingProcessFileName, NetworkTimestamp = Timestamp;
screenconnect_children
| join kind=inner mining_network on DeviceName
| where datetime_diff('minute', ChildTimestamp, NetworkTimestamp) between (-15 .. 15)
| where NetProcessName =~ ChildProcessName or ProcessCommandLine has_any (mining_keywords)
| project ChildTimestamp, DeviceName, ChildProcessName, ProcessCommandLine, SHA256, InitiatingProcessAccountName, RemoteIP, RemotePort
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Environments where ScreenConnect is legitimately used by IT administrators may see false positives if admins run network diagnostic tools that connect on ports overlapping with mining_ports. Allowlisting by InitiatingProcessAccountName for known IT admin accounts mitigates this.
- Security testing or red team exercises using ScreenConnect as a C2 simulation may trigger this rule.

Tuning notes:
- If ScreenConnect is an approved tool, add an InitiatingProcessAccountName exclusion for known IT admin accounts to suppress legitimate remote sessions.
- Extend mining_keywords with additional miner binary names as new variants emerge.
- Consider adding a DeviceNetworkEvents filter for RemoteUrl containing known mining pool domain patterns as a complementary signal.

Risks / caveats:
- If ScreenConnect is legitimately deployed in the environment, the InitiatingProcessFileName filter will match all ScreenConnect-spawned processes. An allowlist of authorized ScreenConnect operator account names should be added to InitiatingProcessAccountName exclusions.
- Mining pool operators increasingly use ports 443 and 80 with TLS to evade port-based detection. The mining_keywords filter on ProcessCommandLine partially compensates but will miss pre-compiled miners without command-line arguments.
- The 15-minute join window may miss staged deployments where the miner is dropped and executed with a delay.

### Triage Runbook

First 15 minutes:
- Confirm whether ScreenConnect is approved on the host and whether the initiating account is a known IT support user.
- Inspect the child process name, command line, and hash for mining indicators such as xmrig, nbminer, t-rex, or stratum parameters.
- Check for outbound connections to unusual external IPs or ports commonly used by mining pools.
- Determine whether the child process is consuming high CPU or GPU resources and whether the user reported performance issues.

Evidence to collect:
- DeviceProcessEvents showing the ScreenConnect parent process and spawned child process details.
- DeviceNetworkEvents for the same host and process, including RemoteIP, RemotePort, and connection success status.
- Process hashes and command lines for the child process and any related loader or script.
- User and admin account context for the ScreenConnect session that initiated the process.

Pivot points:
- DeviceProcessEvents for the same DeviceName to reconstruct the process tree around the ScreenConnect session.
- DeviceNetworkEvents for the child process to identify mining pool destinations and connection patterns.
- DeviceLogonEvents or identity logs to identify who authenticated to ScreenConnect around the alert time.
- If available, endpoint performance telemetry or EDR alerts for CPU/GPU spikes on the same host.

Benign explanations:
- A legitimate ScreenConnect support session where an administrator launched a diagnostic or utility process.
- A security test or red team exercise using ScreenConnect as a remote execution path.
- A non-malicious process with a misleading name that happens to match mining keywords.

Escalation criteria:
- The child process is a known miner or has mining command-line indicators and connects to external mining infrastructure.
- The ScreenConnect session is not associated with an approved support account or change window.
- The host shows sustained resource abuse, user impact, or repeated process respawning.
- Multiple hosts show the same ScreenConnect-to-miner pattern, indicating broader compromise.

Containment actions:
- Terminate the mining process and isolate the host if malicious mining is confirmed.
- Disable or revoke the ScreenConnect account used in the session if unauthorized access is suspected.
- Block the mining pool IPs or domains observed in network telemetry.
- Remove or suspend ScreenConnect access on the affected host until the investigation is complete.

Closure criteria:
- The process is confirmed as an approved administrative or diagnostic action with no mining behavior.
- The child process hash, command line, and network activity are consistent with a known-good tool.
- No external mining destinations or resource-hijacking indicators are present.
- The ScreenConnect account and session are validated as authorized and documented.

---

## Detection 4: ScreenConnect Spawning .NET Utility Processes with Anomalous Command-Line Arguments

### Detection Opportunity

Malicious .NET utilities executed as child processes of ScreenConnect as part of post-access cryptojacking campaign payload staging

### Intelligence Context

- Microsoft Security Blog: From poisoned search results to GPU mining: A cryptojacking campaign abusing ScreenConnect and Microsoft .NET utilities — https://www.microsoft.com/en-us/security/blog/2026/05/26/poisoned-search-results-gpu-mining-cryptojacking-campaign-abusing-screenconnect-microsoft-net-utilities/
  - Context: The campaign used ScreenConnect as a remote execution bridge to run malicious .NET utilities that staged or executed the cryptomining payload. The combination of ScreenConnect as parent and .NET CLR hosting processes as children with unusual arguments is a specific behavioral pattern from this campaign.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Execution: T1127 Trusted Developer Utilities Proxy Execution/ T1127.001 MSBuild (medium); Defense Evasion: T1027 Obfuscated Files or Information/ T1027.010 Command Obfuscation (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

Required telemetry:
- DeviceProcessEvents

### KQL

```kql
let lookback = 7d;
let dotnet_lolbins = dynamic(["msbuild.exe", "csc.exe", "installutil.exe", "regsvcs.exe", "regasm.exe", "dotnet.exe", "ilasm.exe"]);
let suspicious_path_fragments = dynamic(["\\Temp\\", "\\AppData\\Local\\", "\\ProgramData\\", "\\Users\\Public\\"]);
let excluded_path_fragments = dynamic(["\\Program Files\\", "\\Program Files (x86)\\", "\\Windows\\Microsoft.NET\\"]);
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where InitiatingProcessFileName in~ ("ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe")
| where FileName in~ (dotnet_lolbins)
| where not(FolderPath has_any (excluded_path_fragments))
| where FolderPath has_any (suspicious_path_fragments)
    or ProcessCommandLine matches regex @"(?i)(-enc\s|-e\s|/b64|frombase64string|downloadstring|new-object\s+net\.webclient|iex\s|invoke-expression)"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessAccountName, ProcessId, InitiatingProcessId
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Developer workstations where ScreenConnect is used for IT support and developers legitimately run msbuild.exe or csc.exe from non-standard paths.
- CI/CD agents that use ScreenConnect for remote management and invoke .NET build tools from AppData or ProgramData staging directories.

Tuning notes:
- Scope DeviceName to non-developer workstations if .NET tooling is legitimately invoked by ScreenConnect in developer support scenarios.
- Add InitiatingProcessParentFileName filter to further restrict to cases where ScreenConnect was itself spawned by a browser or installer, indicating the initial access vector.
- If promoted to a scheduled rule, reduce lookback to 1d and add a summarize step to group by DeviceName and FileName to reduce alert volume.

Risks / caveats:
- The 7-day lookback is appropriate for hunting but will need to be reduced to 1 day if promoted to a scheduled rule to avoid query timeout on large environments.
- Attackers using pre-compiled binaries renamed to non-.NET names will evade the FileName filter. Combining with SHA256 threat intelligence lookups would improve coverage.
- The regex pattern does not cover all possible encoding or download techniques; it targets the most common patterns observed in this campaign.

### Triage Runbook

First 15 minutes:
- Review the parent-child relationship to confirm ScreenConnect launched the .NET utility.
- Inspect the command line for encoding, download, or obfuscation patterns such as -enc, frombase64string, downloadstring, or invoke-expression.
- Check the file path to see whether the utility was launched from Temp, AppData, ProgramData, or another non-standard location.
- Identify the initiating account and determine whether it is a known support or admin account.

Evidence to collect:
- DeviceProcessEvents for the suspicious .NET utility, including ProcessCommandLine, FolderPath, SHA256, ProcessId, and InitiatingProcessId.
- Process tree context showing the ScreenConnect parent and any subsequent child processes.
- File reputation or threat intelligence results for the SHA256 if available.
- User context and change records for the ScreenConnect session.

Pivot points:
- DeviceProcessEvents for the same DeviceName and InitiatingProcessId to reconstruct the full process chain.
- DeviceFileEvents for related file drops or modifications in Temp, AppData, or ProgramData.
- DeviceNetworkEvents for any outbound connections made by the same process after launch.
- Identity or remote access logs to determine who initiated the ScreenConnect session.

Benign explanations:
- Legitimate IT support using ScreenConnect to run .NET utilities for troubleshooting.
- Developer or CI/CD activity on a managed workstation where .NET tools are used from non-standard paths.
- A benign utility with command-line arguments that resemble obfuscation or download patterns.

Escalation criteria:
- The command line contains clear obfuscation, download, or execution chaining indicators and the file path is unusual.
- The utility is unsigned, unknown, or has a suspicious hash reputation.
- The ScreenConnect session is not authorized or the initiating account is unexpected.
- Follow-on activity includes network connections, file drops, or additional suspicious child processes.

Containment actions:
- Suspend the ScreenConnect session or disable the account if unauthorized remote execution is confirmed.
- Isolate the host if the .NET utility appears to be a loader, stager, or malware component.
- Preserve the process tree and file artifacts for analysis before remediation.
- Block any confirmed malicious hashes or destinations associated with the utility.

Closure criteria:
- The .NET utility is identified as a legitimate administrative or development tool.
- The command line and file path are consistent with approved software deployment or troubleshooting.
- No suspicious follow-on process, file, or network activity is observed.
- The ScreenConnect use case is validated against change records or support tickets.

---

## Detection 5: Browser-Spawned Executable Accessing Credential Paths Followed by Outbound Network Connection

### Detection Opportunity

ACR Stealer-style payload delivered via browser download executing from temp path, accessing credential stores, and exfiltrating data

### Intelligence Context

- SANS ISC: Possible ACR Stealer From Page Impersonating Claude, (Tue, May 26th) — https://isc.sans.edu/diary/rss/33018
  - Context: A page impersonating the Claude AI service delivered a suspected stealer payload via browser-driven download. Post-execution behavior consistent with ACR Stealer includes accessing browser credential stores and making outbound connections to attacker infrastructure, detectable via compound process and network telemetry even without confirmed payload hashes.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1204 User Execution/ T1204.002 Malicious File (medium); Credential Access: T1555 Credentials from Password Stores (high); Exfiltration: T1041 Exfiltration Over C2 Channel (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

Required telemetry:
- DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents

### KQL

```kql
let lookback = 24h;
let browser_procs = dynamic(["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe"]);
let temp_paths = dynamic(["\\Downloads\\", "\\AppData\\Local\\Temp\\", "\\Temp\\"]);
let cred_paths = dynamic(["Login Data", "Cookies", "Web Data", "wallet", "MetaMask", "\\Roaming\\Mozilla\\", "credential", "vault"]);
let browser_spawned = DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where InitiatingProcessFileName in~ (browser_procs)
| where FolderPath has_any (temp_paths)
| project DeviceName, SpawnedProcess = FileName, SpawnedPID = ProcessId, SHA256, SpawnTime = Timestamp, SpawnFolderPath = FolderPath, InitiatingProcessAccountName;
let cred_access = DeviceFileEvents
| where Timestamp >= ago(lookback)
| where FolderPath has_any (cred_paths) or FileName has_any (cred_paths)
| where ActionType in ("FileCreated", "FileCopied", "FileModified")
| project DeviceName, AccessingProcessName = InitiatingProcessFileName, AccessingPID = InitiatingProcessId, CredPath = FolderPath, CredFileName = FileName, CredActionType = ActionType, AccessTime = Timestamp;
let exfil_net = DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where ActionType == "ConnectionSuccess"
| where RemotePort in (80, 443, 8080, 8443)
| where not(ipv4_is_private(RemoteIP))
| project DeviceName, RemoteIP, RemotePort, NetPID = InitiatingProcessId, NetProcessName = InitiatingProcessFileName, NetTime = Timestamp;
browser_spawned
| join kind=inner cred_access on DeviceName
| where SpawnedPID == AccessingPID
| where AccessTime > SpawnTime and datetime_diff('minute', AccessTime, SpawnTime) <= 30
| join kind=inner exfil_net on DeviceName
| where NetPID == AccessingPID
| where NetTime > AccessTime and datetime_diff('minute', NetTime, AccessTime) <= 15
| project SpawnTime, DeviceName, SpawnedProcess, SHA256, SpawnFolderPath, CredPath, CredFileName, CredActionType, RemoteIP, RemotePort, InitiatingProcessAccountName
```

### False Positives / Tuning / Risks / Caveats

Expected false positives:
- Browser extension installers spawned by browsers that copy profile data as part of migration or backup.
- Password manager agents that are spawned by browsers and legitimately access credential store paths.
- Legitimate software updaters downloaded via browser that make outbound connections shortly after execution.

Tuning notes:
- If PID-based correlation produces zero results due to InitiatingProcessId not being populated in DeviceFileEvents for the environment, fall back to DeviceName plus SpawnedProcess == AccessingProcessName correlation with the time window constraints.
- Add a SHA256 allowlist for known-good browser helper executables that legitimately access credential paths such as password manager agents.
- Tighten the SpawnTime-to-AccessTime window from 30 minutes to 10 minutes if the environment shows high legitimate browser-spawned installer activity that accesses credential paths.

Risks / caveats:
- DeviceFileEvents ActionType 'FileRead' and 'FileAccessed' are not standard MDE Windows telemetry values for credential store access. MDE typically emits FileCreated or FileCopied when stealers copy SQLite credential databases. If the query relies on FileRead/FileAccessed, it will return no results for the credential access stage on Windows endpoints.
- ProcessId reuse within the lookback window could cause false correlations if a PID is recycled between the spawn event and the file/network events. This is unlikely within a 30-minute window but possible on high-churn systems.
- Stealers that use a loader/injector pattern where the credential access occurs in a different process than the one spawned by the browser will evade the PID-based join. A DeviceName-only join with broader time windows would catch these but at the cost of significantly higher noise.
- FileCreated and FileCopied ActionType coverage for browser credential database copies depends on MDE audit policy configuration. Some environments may not emit these events for reads of SQLite files that stealers open directly via file handle without copying.

### Triage Runbook

First 15 minutes:
- Identify the browser that spawned the executable and confirm the download source or user action if available.
- Review the spawned process name, hash, and folder path for temp or user-profile staging locations.
- Check whether the process accessed browser credential stores, cookies, wallet files, or keyring paths.
- Inspect the outbound connection for external IPs, ports, and timing immediately after credential access.

Evidence to collect:
- DeviceProcessEvents for the browser-spawned executable, including SHA256, ProcessCommandLine, FolderPath, and InitiatingProcessAccountName.
- DeviceFileEvents showing access or copying of credential-related files such as Login Data, Cookies, Web Data, or wallet artifacts.
- DeviceNetworkEvents for the same process or PID, including RemoteIP and RemotePort.
- User activity context such as browser history, download records, and any reported suspicious website interaction.

Pivot points:
- DeviceProcessEvents to reconstruct the full process tree from the browser to the spawned executable.
- DeviceFileEvents for the same DeviceName and InitiatingProcessId to identify additional credential or wallet access.
- DeviceNetworkEvents for the same process to identify exfiltration destinations and repeated connections.
- If available, browser telemetry or proxy logs to identify the original download URL and any redirect chain.

Benign explanations:
- A legitimate installer or updater downloaded through a browser and then accessing profile-related files.
- A password manager or browser helper process that legitimately interacts with credential stores.
- A user-initiated migration, backup, or sync tool that copies browser profile data.

Escalation criteria:
- The executable is unsigned, unknown, or launched from a temp path and accesses credential stores shortly after execution.
- The process makes external network connections after touching credential files, especially to unfamiliar IPs or ports.
- The browser download source is suspicious, impersonated, or associated with known malicious infrastructure.
- Multiple endpoints show the same browser-to-stealer pattern or the same hash appears across hosts.

Containment actions:
- Isolate the host if the executable is confirmed or strongly suspected to be a stealer.
- Reset affected browser, SSO, and local credentials that may have been exposed.
- Block the malicious hash, URL, and destination IPs/domains if identified.
- Preserve the executable, browser artifacts, and process tree for forensic analysis.

Closure criteria:
- The executable is verified as a legitimate installer, updater, or approved helper process.
- The credential-path access is explained by normal application behavior and no exfiltration is observed.
- The outbound connection is to a known-good service or update endpoint.
- Browser history, file reputation, and process lineage do not support malicious execution.

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

Telemetry availability:
- Kerberos Relay Attempt from Linux Host to Internal Server: Syslog table must be populated by Linux host syslog forwarding via the Log Analytics agent or AMA Syslog connector. If Linux hosts do not forward syslog to Sentinel, the join will return no results.

Other deployment dependency:
- Linux Process Accessing Credential Store Paths Following Edge Appliance Pivot: Defender for Endpoint file-event coverage must be confirmed on the target host population.

Schema / correlation keys:
- Browser-Spawned Executable Accessing Credential Paths Followed by Outbound Network Connection: Do not schedule yet; validate as an analyst-led hunt first.

Shared-table notes:
- DeviceFileEvents: shared by Linux Process Accessing Credential Store Paths Following Edge Appliance Pivot; Browser-Spawned Executable Accessing Credential Paths Followed by Outbound Network Connection
- DeviceProcessEvents: shared by Linux Process Accessing Credential Store Paths Following Edge Appliance Pivot; ScreenConnect Spawning GPU-Intensive or Mining-Related Child Processes; ScreenConnect Spawning .NET Utility Processes with Anomalous Command-Line Arguments; Browser-Spawned Executable Accessing Credential Paths Followed by Outbound Network Connection
- DeviceNetworkEvents: shared by ScreenConnect Spawning GPU-Intensive or Mining-Related Child Processes; Browser-Spawned Executable Accessing Credential Paths Followed by Outbound Network Connection

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: ScreenConnect Spawning GPU-Intensive or Mining-Related Child Processes; ScreenConnect Spawning .NET Utility Processes with Anomalous Command-Line Arguments.
2. Resolve environment-mapping detections next: Kerberos Relay Attempt from Linux Host to Internal Server; Linux Process Accessing Credential Store Paths Following Edge Appliance Pivot.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Browser-Spawned Executable Accessing Credential Paths Followed by Outbound Network Connection.

### Hunting Agenda and Promotion Criteria

- Browser-Spawned Executable Accessing Credential Paths Followed by Outbound Network Connection: Do not schedule yet; validate as an analyst-led hunt first.; confirm required file-access telemetry exists and produces representative events; prove correlation keys join correctly on real tenant telemetry.
- Kerberos Relay Attempt from Linux Host to Internal Server: Syslog table must be populated by Linux host syslog forwarding via the Log Analytics agent or AMA Syslog connector. If Linux hosts do not forward syslog to Sentinel, the join will return no results.; prove correlation keys join correctly on real tenant telemetry.
- Linux Process Accessing Credential Store Paths Following Edge Appliance Pivot: Defender for Endpoint file-event coverage must be confirmed on the target host population.; confirm required file-access telemetry exists and produces representative events; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

This run exposes a file-access telemetry blind spot: browser cookie theft and resource-file loader behaviors depend on file-read style events that may not be emitted in every Defender deployment. Validate that coverage before treating these as scheduled analytics.

---

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering automation. Validate all detections before production deployment. Stay dangerous._
