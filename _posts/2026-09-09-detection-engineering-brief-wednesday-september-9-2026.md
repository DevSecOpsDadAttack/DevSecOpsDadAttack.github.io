---
layout: post
title: "Detection Engineering Brief - Wednesday, September 9, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-09
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - MikroTik
  - T1136
  - crond
  - agetty
  - atd
  - sshd
  - polkitd
  - Linux
  - T1059
  - T1105
  - HAProxy
  - T1119
  - CVE-2026-86206
  - CVE-2026-86207
  - N-able N-central
  - Windows
  - T1204
  - T1566
  - T1204.002
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 2 hunting-only, 2 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: MikroTik, T1136, crond, agetty, atd, sshd, polkitd, Linux, T1059, T1105, HAProxy, T1119, CVE-2026-86206, CVE-2026-86207, N-able N-central, Windows, T1204, T1566, T1204.002.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: MikroTik Device Account Creation via Syslog; Trojanized HAProxy Spawning Shell or Making Unexpected Outbound Connection; New Privileged Account Created on N-able N-central Host Following Authentication Bypass; Executable Launched from User Download Directory Following Browser Activity.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: MikroTik Device Account Creation via Syslog

### Detection Opportunity

Attackers create new accounts on MikroTik devices post-exploitation to maintain persistence after patching.

### Intelligence Context

- SANS ISC: Critical MikroTik Vulnerability - Patch Now, (Sun, Sep 6th) — [https://isc.sans.edu/diary/rss/33314](https://isc.sans.edu/diary/rss/33314)
  - Context: Following active exploitation of an SSH authentication bypass on MikroTik devices, attackers were observed adding new user accounts to maintain persistent access even after patching was applied.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1136
- Products: MikroTik
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: MikroTik, T1136

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1136 Create Account (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.

**Required telemetry:**
- Syslog

### KQL

```kql
Syslog
| where TimeGenerated > ago(1d)
| where SyslogMessage has_any ("user add", "added user", "account created", "user created")
| where ProcessName has_any ("mikrotik", "routeros") or HostName has_any ("mikrotik", "routeros")
| project TimeGenerated, HostName, ProcessName, Facility, SeverityLevel, SyslogMessage
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrative account creation during maintenance windows.
- Non-MikroTik syslog sources that log user management events with overlapping keywords if HostName scoping is not applied.

**Tuning notes:**
- Replace the ProcessName/HostName has_any filter with a specific list of MikroTik device hostnames confirmed in the environment.
- Test by creating a non-production account on a MikroTik device and confirming the exact SyslogMessage string before finalizing keyword filters.
- Consider extending the lookback to ago(7d) for hunting use while baselining.

**Risks / caveats:**
- MikroTik syslog forwarding to the Sentinel Syslog table must be explicitly configured on each device; if not configured, the table will contain no MikroTik entries and the query will return no results.
- RouterOS account-creation syslog message format must be confirmed to contain the keyword strings used in has_any; if RouterOS uses different phrasing the query will silently miss events.
- HostName values for MikroTik devices in the environment must be confirmed and used to scope the query before scheduling to avoid false positives from other syslog sources.
- RouterOS syslog verbosity must be set to include account management events; default verbosity may not log these actions.

### Triage Runbook

**First 15 minutes:**
- Verify the HostName is a known MikroTik device and not a generic syslog source.
- Open the raw SyslogMessage and confirm it is an account-creation event, not a different user-management action.
- Check whether the event occurred during a planned maintenance window or change ticket.
- Identify the new account name and whether it matches any approved admin naming convention.

**Evidence to collect:**
- TimeGenerated, HostName, ProcessName, Facility, SeverityLevel, and full SyslogMessage.
- Any preceding or following MikroTik syslog entries showing login, configuration changes, or privilege changes.
- Device inventory record for the MikroTik host and its normal administrators.
- Change ticket or maintenance approval covering account creation on that device.

**Pivot points:**
- Syslog for the same HostName over the prior 24-72 hours to look for login attempts, config changes, and other admin actions.
- MikroTik management logs or AAA logs if available outside Sentinel.
- Network/security logs for the source IPs that accessed the device before the account was created.

**Benign explanations:**
- Legitimate account creation by a network administrator during maintenance.
- Account provisioning after a device rebuild or replacement.
- Log noise from a non-MikroTik syslog source if HostName scoping is incorrect.

**Escalation criteria:**
- The new account is unknown, not documented, or created outside an approved change window.
- Additional MikroTik logs show suspicious login activity, configuration tampering, or repeated admin actions from an unrecognized source.
- The device was recently exposed to known exploitation activity and the account appears to be attacker-controlled.

**Containment actions:**
- Disable or remove the newly created account if it is not confirmed legitimate.
- Rotate administrative credentials used on the MikroTik device.
- If compromise is likely, isolate the device from management access until configuration integrity is verified.

**Closure criteria:**
- The account creation is matched to a valid change request and approved administrator.
- No other suspicious MikroTik activity is present around the event window.
- The HostName scoping is validated and the event is confirmed benign or non-applicable.

<br/>
---
<br/>

## Detection 2: Trojanized Linux System Binary Spawning Anomalous Child Process

### Detection Opportunity

Trojanized versions of core Linux services (crond, sshd, polkitd, atd, agetty) spawn unexpected child processes as part of DPRK-linked campaign persistence.

### Intelligence Context

- Rapid7: DPRK APTs: Ted backdoor and curlRAT target South Korean media and automotive sectors — [https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors](https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors)
  - Context: A DPRK-linked campaign deployed trojanized versions of crond, agetty, atd, sshd, and polkitd on Linux servers. These modified binaries were used to blend into the environment while enabling remote command execution and persistence. Detection focuses on these processes spawning shell interpreters or other unexpected children.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1105
- Products: crond, agetty, atd, sshd, polkitd
- Platforms: Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: crond, agetty, atd, sshd, polkitd, Linux, T1059, T1105

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (high); Command and Control: T1105 Ingress Tool Transfer (medium)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where TimeGenerated > ago(1d)
| where InitiatingProcessFileName in~ ("crond", "sshd", "polkitd", "atd", "agetty")
| where FileName in~ ("bash", "sh", "dash", "zsh", "python", "python3", "perl", "ruby", "nc", "ncat", "curl", "wget")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, FileName, FolderPath, ProcessCommandLine, SHA256
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Scheduled cron jobs that legitimately invoke bash or python for automation tasks.
- SSH session management scripts that spawn shell children in some configurations.
- Configuration management agents that run via crond and invoke interpreters.

**Tuning notes:**
- After initial deployment, build an exclusion list of AccountName and ProcessCommandLine combinations observed in legitimate crond-spawned shell activity.
- Add a filter on InitiatingProcessFolderPath not in ('/usr/sbin', '/usr/bin', '/sbin', '/bin') to prioritize detections where the parent binary is running from a non-standard path, which is a stronger indicator of trojanization.
- Consider adding InitiatingProcessCommandLine to the projection to capture the full parent invocation context.

**Risks / caveats:**
- Microsoft Defender for Endpoint must be onboarded on Linux hosts and process telemetry collection must be enabled; without Linux MDE coverage DeviceProcessEvents will contain no Linux entries.
- Legitimate crond-invoked automation that spawns bash or python will generate false positives until an exclusion list is baselined.
- sshd spawning sh is expected in some SSH forced-command configurations; review sshd-related results separately.
- The 1-day lookback may miss low-frequency persistence activity; consider extending to 7 days for initial deployment.

### Triage Runbook

**First 15 minutes:**
- Confirm the parent process is one of crond, sshd, polkitd, atd, or agetty and inspect the child process name and command line.
- Check whether the parent binary path is standard (/usr/sbin, /usr/bin, /sbin, /bin) or a suspicious non-standard location.
- Review the account context and whether the child process is a shell, downloader, or scripting interpreter.
- Look for multiple hits on the same host or repeated spawning behavior from the same parent binary.

**Evidence to collect:**
- TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, FileName, FolderPath, ProcessCommandLine, and SHA256.
- Any related DeviceProcessEvents showing the same parent binary spawning other children.
- File reputation or hash results for the parent and child binaries.
- Host baseline showing whether this child process is normal for that service on this device.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and InitiatingProcessFileName over the last 7 days.
- DeviceNetworkEvents for the same DeviceName to see whether the child process made outbound connections.
- DeviceFileEvents or file inventory to determine whether the parent binary was replaced or modified recently.

**Benign explanations:**
- Legitimate automation or maintenance scripts launched by cron or SSH forced commands.
- Expected helper processes in a hardened environment that use service wrappers.
- Administrative troubleshooting that temporarily spawns a shell from a service account.

**Escalation criteria:**
- The parent binary runs from a non-standard path or has an unexpected hash.
- The child process is a shell, downloader, or remote access tool with no approved business purpose.
- Multiple Linux hosts show the same pattern, suggesting a broader campaign or shared trojanized package.

**Containment actions:**
- Isolate the affected Linux host if the parent binary appears replaced or malicious.
- Stop the suspicious service only if doing so will not cause unacceptable business impact and you have approval.
- Preserve the suspicious binary and collect hashes before remediation or reboot.

**Closure criteria:**
- The child process is explained by approved automation or documented service behavior.
- The parent binary path and hash match the known-good baseline.
- No additional suspicious process or network activity is found on the host.

<br/>
---
<br/>

## Detection 3: Trojanized HAProxy Spawning Shell or Making Unexpected Outbound Connection

### Detection Opportunity

A trojanized HAProxy instance named 'ted backdoor' executes remote commands by spawning shell interpreters or initiating outbound connections to attacker infrastructure.

### Intelligence Context

- Rapid7: DPRK APTs: Ted backdoor and curlRAT target South Korean media and automotive sectors — [https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors](https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors)
  - Context: The campaign deployed a trojanized HAProxy binary referred to as the 'ted backdoor' that enabled remote command execution on compromised Linux servers. The trojanized binary would spawn shell processes or make outbound network connections atypical of legitimate HAProxy behavior.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1105, T1119
- Products: HAProxy
- Platforms: Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: HAProxy, Linux, T1059, T1105, T1119

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (high); Command and Control: T1105 Ingress Tool Transfer (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceNetworkEvents

### KQL

```kql
let HaproxyShellSpawn = DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where InitiatingProcessFileName =~ "haproxy"
| where FileName in~ ("bash", "sh", "dash", "zsh", "python", "python3", "perl", "nc", "ncat")
| extend DetectionBranch = "ShellSpawn"
| project TimeGenerated, DetectionBranch, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, FileName, ProcessCommandLine, FolderPath, RemoteIP = "", RemotePort = int(null);
let HaproxyOutbound = DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where InitiatingProcessFileName =~ "haproxy"
| where ActionType == "ConnectionSuccess"
| where RemotePort !in (80, 443, 8080, 8443)
| extend DetectionBranch = "UnexpectedOutbound"
| project TimeGenerated, DetectionBranch, DeviceName, AccountName = InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, FileName = "", ProcessCommandLine = "", FolderPath = "", RemoteIP, RemotePort;
union HaproxyShellSpawn, HaproxyOutbound
| order by TimeGenerated desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- HAProxy health-check scripts or reload hooks that invoke shell commands in some configurations.
- HAProxy connecting to backend services on non-standard ports that are legitimate in the environment.
- Monitoring agents that attach to the haproxy process and spawn child processes.

**Tuning notes:**
- To convert the shell-spawn branch into a scheduled rule, extract it as a standalone query; it is high-fidelity and does not require environment-specific port knowledge.
- Extend the RemotePort exclusion list in the outbound branch with all confirmed legitimate HAProxy backend ports before using that branch for alerting.
- Add a FolderPath not in ('/usr/sbin', '/usr/bin', '/sbin', '/bin') filter to the shell-spawn branch to prioritize trojanized binaries running from non-standard paths.

**Risks / caveats:**
- Microsoft Defender for Endpoint must be onboarded on Linux hosts running HAProxy; without Linux MDE coverage neither DeviceProcessEvents nor DeviceNetworkEvents will contain HAProxy entries.
- ActionType value 'ConnectionSuccess' must be confirmed as a valid ActionType in DeviceNetworkEvents for the MDE Linux sensor; some Linux network event types use different ActionType strings.
- The outbound network branch port exclusion list covers only common HTTP/HTTPS ports; legitimate HAProxy backend ports in the environment must be added to the exclusion list before this query produces actionable results.
- InitiatingProcessAccountName may not be populated for all network events on Linux; AccountName in the network branch may be empty in some telemetry configurations.

### Triage Runbook

**First 15 minutes:**
- Prioritize any ShellSpawn result over the outbound-connection branch.
- Verify the HAProxy binary path and hash; compare them to the approved package or image baseline.
- Inspect the child process command line or remote destination for signs of remote command execution or attacker infrastructure.
- Check whether the outbound connection is to a known backend service or an unexpected external IP.

**Evidence to collect:**
- TimeGenerated, DetectionBranch, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, FileName, ProcessCommandLine, FolderPath, RemoteIP, and RemotePort.
- Package manager or deployment records showing when HAProxy was installed or updated.
- Host baseline for legitimate HAProxy backend ports and destinations.
- Any related process or network events before and after the alert window.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and InitiatingProcessFileName to find additional child processes.
- DeviceNetworkEvents for the same DeviceName to review all HAProxy connections and identify unusual RemoteIP/RemotePort pairs.
- Linux package integrity or configuration management records to confirm whether the binary or service was modified.

**Benign explanations:**
- HAProxy health checks, reload hooks, or monitoring integrations that legitimately invoke helper processes.
- Legitimate backend connections on non-standard ports that are normal in the environment.
- Administrative testing or troubleshooting on the proxy host.

**Escalation criteria:**
- HAProxy spawns a shell or scripting interpreter with no approved operational reason.
- The binary hash or path does not match the expected package and appears replaced.
- Outbound connections target unknown external infrastructure or coincide with other compromise indicators.

**Containment actions:**
- Isolate the host if the HAProxy binary is confirmed trojanized or is executing attacker commands.
- Block suspicious outbound destinations if they are clearly malicious and blocking will not disrupt critical services.
- Preserve the binary, service configuration, and relevant logs before remediation.

**Closure criteria:**
- The shell-spawn activity is tied to documented HAProxy operations or approved tooling.
- Outbound connections are matched to known backend infrastructure and approved ports.
- Binary integrity checks confirm the HAProxy executable is legitimate.

<br/>
---
<br/>

## Detection 4: New Privileged Account Created on N-able N-central Host Following Authentication Bypass

### Detection Opportunity

An unauthenticated attacker exploiting CVE-2026-86206 or CVE-2026-86207 creates a new system administrator account on N-able N-central to establish persistent privileged access.

### Intelligence Context

- Rapid7: CVE-2026-86206, CVE-2026-86207: N-able N-central Authentication Bypass (FIXED) — [https://www.rapid7.com/blog/post/ve-cve-2026-86206-cve-2026-86207-n-able-n-central-authentication-bypass-fixed](https://www.rapid7.com/blog/post/ve-cve-2026-86206-cve-2026-86207-n-able-n-central-authentication-bypass-fixed)
  - Context: CVE-2026-86206 and CVE-2026-86207 allow a remote unauthenticated attacker to bypass authentication on N-able N-central and subsequently create a new attacker-controlled system administrator account. Account creation is the primary persistence mechanism following the bypass.

### Search Metadata

- CVEs: CVE-2026-86206, CVE-2026-86207
- Threat actors: Not specified
- ATT&CK tags: T1136
- Products: N-able N-central
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: CVE-2026-86206, CVE-2026-86207, N-able N-central, T1136

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Persistence: T1136 Create Account (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.

**Required telemetry:**
- SecurityEvent

### KQL

```kql
let AccountCreation = SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4720
| project CreationTime = TimeGenerated, Computer, SubjectUserName, NewAccount = TargetUserName;
let PrivilegedGroupAdd = SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID in (4728, 4732, 4756)
| project GroupAddTime = TimeGenerated, Computer, GroupAddSubject = SubjectUserName, AddedAccount = TargetUserName, GroupEventID = EventID;
AccountCreation
| join kind=inner PrivilegedGroupAdd on $left.Computer == $right.Computer and $left.NewAccount == $right.AddedAccount
| where GroupAddTime between (CreationTime .. (CreationTime + 10m))
| project CreationTime, GroupAddTime, Computer, SubjectUserName, NewAccount, GroupAddSubject, GroupEventID
| order by CreationTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate administrator-initiated account creation followed by immediate group membership assignment during normal provisioning workflows.
- Automated provisioning scripts that create and elevate accounts within the correlation window.

**Tuning notes:**
- Add a where Computer == '<ncentral_hostname>' filter to both let blocks after confirming the N-central server hostname in the environment.
- If multiple N-central servers exist, use where Computer in ('host1', 'host2') to scope appropriately.
- Adjust the correlation window from 10m to a value that reflects observed legitimate provisioning timing to reduce false positives from automated workflows.

**Risks / caveats:**
- N-able N-central must be deployed on a Windows host with Windows Security Event auditing enabled and the Security Events connector forwarding to Sentinel; if N-central runs on Linux or uses a non-Windows authentication model, EventID 4720 will not be generated.
- EventID 4720 is only generated when account creation occurs at the Windows OS level; if N-central manages accounts internally without creating Windows OS accounts, this detection will not fire.
- The Computer field must be scoped to the confirmed N-central server hostname before scheduling; without scoping this query will alert on all Windows hosts in the environment.
- The 10-minute correlation window may need adjustment based on observed provisioning workflow timing in the environment.

### Triage Runbook

**First 15 minutes:**
- Verify the Computer value matches the known N-central server hostname.
- Check whether the account creation and group-add events occurred within the expected provisioning workflow.
- Identify the new account and the actor account in SubjectUserName/GroupAddSubject.
- Determine whether the event aligns with a change ticket or emergency admin action.

**Evidence to collect:**
- CreationTime, GroupAddTime, Computer, SubjectUserName, NewAccount, GroupAddSubject, and GroupEventID.
- Windows Security Event details for EventID 4720, 4728, 4732, and 4756 around the same time.
- N-central application or audit logs showing authentication bypass, admin creation, or configuration changes.
- Change management records and administrator roster for the N-central server.

**Pivot points:**
- SecurityEvent on the N-central host for the prior 24-72 hours to find logons, privilege changes, and other account events.
- Application and service logs from the N-central server for signs of exploitation or web access anomalies.
- Network logs for access to the N-central web interface from unusual source IPs.

**Benign explanations:**
- Legitimate administrator provisioning a new account and adding it to a privileged group.
- Automated onboarding or break-glass account creation during maintenance.
- A non-N-central Windows host matching the same event pattern if Computer scoping is missing or incorrect.

**Escalation criteria:**
- The new privileged account is unknown, unapproved, or created outside a change window.
- The actor account is unexpected or the creation is followed by other suspicious admin actions.
- There are signs of web authentication bypass, unusual source IPs, or additional N-central tampering.

**Containment actions:**
- Disable the new account and any related suspicious admin accounts if they are not approved.
- Restrict access to the N-central server to trusted admin sources while investigation is underway.
- If compromise is likely, preserve logs and consider isolating the N-central host from external access.

**Closure criteria:**
- The account creation is validated against a change request and approved provisioning workflow.
- The Computer field is confirmed to be the N-central server and the event is not from another Windows host.
- No additional suspicious N-central activity is observed in the surrounding time window.

<br/>
---
<br/>

## Detection 5: Executable Launched from User Download Directory Following Browser Activity

### Detection Opportunity

Users socially engineered via YouTube gaming lures execute malware downloaded through the browser, resulting in process execution from user-writable download directories.

### Intelligence Context

- Unit 42: Untracked Nightmares: The Threats Hiding Behind Commodity Infrastructure — [https://unit42.paloaltonetworks.com/ppi-network-malware-campaign-analysis/](https://unit42.paloaltonetworks.com/ppi-network-malware-campaign-analysis/)
  - Context: Cybercriminals used YouTube gaming lures and SEO poisoning to deliver multi-payload malware to enterprise Windows endpoints. Users were directed to download and execute files, with execution originating from browser download directories. The campaign delivered multiple payloads in sequence.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1204, T1566, T1204.002
- Products: Not specified
- Platforms: Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: Windows, T1204, T1566, T1204.002

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Execution: T1204 User Execution/ T1204.002 Malicious File (high); Initial Access: T1566 Phishing (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let BrowserSpawnedExec = DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where InitiatingProcessFileName in~ ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe")
| where FolderPath has_any ("\\Downloads\\", "\\AppData\\Local\\Temp\\", "\\Users\\Public\\")
| where FileName endswith ".exe" or FileName endswith ".msi" or FileName endswith ".bat" or FileName endswith ".ps1"
| project FirstExecTime = TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, FirstFileName = FileName, FirstFolderPath = FolderPath, FirstCommandLine = ProcessCommandLine, FirstSHA256 = SHA256, ProcessId;
let SecondStageExec = DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FolderPath has_any ("\\Downloads\\", "\\AppData\\Local\\Temp\\", "\\Users\\Public\\")
| where FileName endswith ".exe" or FileName endswith ".bat" or FileName endswith ".ps1"
| project SecondExecTime = TimeGenerated, DeviceName, AccountName, SecondFileName = FileName, SecondFolderPath = FolderPath, SecondCommandLine = ProcessCommandLine, SecondSHA256 = SHA256, InitiatingProcessId;
BrowserSpawnedExec
| join kind=inner SecondStageExec on $left.DeviceName == $right.DeviceName and $left.AccountName == $right.AccountName and $left.ProcessId == $right.InitiatingProcessId
| where SecondExecTime between (FirstExecTime .. (FirstExecTime + 5m))
| where SecondFileName != FirstFileName
| project FirstExecTime, SecondExecTime, DeviceName, AccountName, InitiatingProcessFileName, FirstFileName, FirstFolderPath, FirstCommandLine, FirstSHA256, SecondFileName, SecondFolderPath, SecondCommandLine, SecondSHA256
| order by FirstExecTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate software downloaded via browser and executed by the user, particularly games, utilities, and enterprise software installers that drop and launch secondary executables.
- Browser-initiated download managers that spawn installer processes.
- Security tools that self-update by downloading and executing new binaries from the Downloads directory.

**Tuning notes:**
- After initial hunting runs, build a SHA256 allowlist of known-good installer binaries observed in FirstSHA256 to suppress software deployment false positives.
- Consider adding a filter on FirstFileName not in ('setup.exe', 'install.exe', 'update.exe') to reduce installer-related noise during initial review.
- Extend the lookback to ago(14d) for broader historical hunting when investigating a specific campaign.

**Risks / caveats:**
- Microsoft Defender for Endpoint must be deployed on Windows endpoints and DeviceProcessEvents must be populated; without MDE coverage the query returns no results.
- The ProcessId to InitiatingProcessId join requires that both events are captured within the same MDE telemetry session; process ID reuse on long-running systems could theoretically produce false matches, though this is rare within a 5-minute window.
- The 5-minute correlation window may miss staged payload delivery with longer delays between first and second execution; adjust based on observed campaign timing.
- Legitimate software installers that spawn child executables from the same directory will generate false positives until an exclusion list is developed.

### Triage Runbook

**First 15 minutes:**
- Review the first and second execution records and confirm the second process is a direct child of the first where possible.
- Inspect the file names, command lines, and folder paths for signs of a downloaded installer, script, or payload chain.
- Check whether the user recently visited a suspicious site, search result, or YouTube lure related to the download.
- Determine whether the file was launched from Downloads, Temp, or Public and whether that is normal for the user.

**Evidence to collect:**
- FirstExecTime, SecondExecTime, DeviceName, AccountName, InitiatingProcessFileName, FirstFileName, FirstFolderPath, FirstCommandLine, FirstSHA256, SecondFileName, SecondFolderPath, SecondCommandLine, and SecondSHA256.
- Browser history or web proxy logs for the user around the execution time.
- Any file reputation, hash, or sandbox results for the downloaded binaries.
- Process tree details including ProcessId and InitiatingProcessId to validate the chain.

**Pivot points:**
- DeviceProcessEvents for the same DeviceName and AccountName to map the full process tree before and after the alert.
- DeviceNetworkEvents or web proxy logs to identify the download source and any follow-on connections.
- DeviceFileEvents or file inventory to see whether additional payloads were dropped in the same directory.

**Benign explanations:**
- Legitimate software installers or updates downloaded by the user and launched from Downloads or Temp.
- Enterprise tools or self-updaters that stage files in user-writable directories.
- User testing or personal software installation on a managed endpoint.

**Escalation criteria:**
- The file is unsigned, unknown, or has a malicious reputation.
- The process chain shows multiple staged payloads or follow-on execution not consistent with a normal installer.
- The user reports clicking a lure, fake update, or suspicious download source.

**Containment actions:**
- If the file is confirmed malicious, isolate the endpoint and stop the active process chain.
- Quarantine the downloaded file and any secondary payloads if supported by your tooling.
- Reset the user session or credentials if the execution led to credential theft indicators.

**Closure criteria:**
- The execution is tied to a known-good installer, updater, or approved software deployment.
- Hash, signer, and command-line review show no malicious behavior.
- No additional suspicious downloads, child processes, or network activity are present.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- MikroTik Device Account Creation via Syslog: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.
- New Privileged Account Created on N-able N-central Host Following Authentication Bypass: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.

**Other deployment dependency:**
- Trojanized Linux System Binary Spawning Anomalous Child Process: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Schema / correlation keys:**
- Trojanized HAProxy Spawning Shell or Making Unexpected Outbound Connection: Do not schedule yet; validate as an analyst-led hunt first.
- Executable Launched from User Download Directory Following Browser Activity: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- DeviceProcessEvents: shared by Trojanized Linux System Binary Spawning Anomalous Child Process; Trojanized HAProxy Spawning Shell or Making Unexpected Outbound Connection; Executable Launched from User Download Directory Following Browser Activity

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Trojanized Linux System Binary Spawning Anomalous Child Process.
2. Resolve environment-mapping detections next: MikroTik Device Account Creation via Syslog; New Privileged Account Created on N-able N-central Host Following Authentication Bypass.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Trojanized HAProxy Spawning Shell or Making Unexpected Outbound Connection; Executable Launched from User Download Directory Following Browser Activity.

### Hunting Agenda and Promotion Criteria

- Trojanized HAProxy Spawning Shell or Making Unexpected Outbound Connection: Do not schedule yet; validate as an analyst-led hunt first..
- Executable Launched from User Download Directory Following Browser Activity: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- MikroTik Device Account Creation via Syslog: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: Syslog before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- New Privileged Account Created on N-able N-central Host Following Authentication Bypass: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
