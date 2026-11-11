---
layout: post
title: "Detection Engineering Brief - Wednesday, November 11, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-11-11
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - N-able N-central
  - Windows
  - Linux
  - T1190
  - T1136
  - T1068
  - Citrus
  - Sn00py
  - VLESS
  - T1059
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 1 hunting-only, 3 require environment mapping, and 0 rejected.

5 detections include KQL. 3 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: N-able N-central, Windows, Linux, T1190, T1136, T1068, Citrus, Sn00py, VLESS, T1059.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: N-central Post-Exploitation: New Local Account Created Following Service Account Activity; N-central Post-Exploitation: Privilege Escalation via sudo or su Spawned from N-central Service Account; N-central Post-Exploitation: Unexpected Child Process Spawned by N-central Service Account (XXE/RCE Indicator); Citrus Ransomware: Anomalous Outbound TLS Connection from Non-Browser Process Consistent with VLESS C2 Tunneling.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: N-central Post-Exploitation: New Local Account Created Following Service Account Activity

### Detection Opportunity

Unauthorized local account creation following exploitation of N-able N-central, consistent with attacker persistence after RCE.

### Intelligence Context

- Rapid7: Critical vulnerabilities in N-able N-central prompt hosted shutdown — [https://www.rapid7.com/blog/post/etr-critical-vulnerabilities-in-n-able-n-central-prompt-hosted-shutdown](https://www.rapid7.com/blog/post/etr-critical-vulnerabilities-in-n-able-n-central-prompt-hosted-shutdown)
  - Context: Rapid7 reported that exploitation chains against N-able N-central include unauthenticated RCE followed by unauthorized account creation, enabling attacker persistence on compromised infrastructure.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190, T1136, T1059
- Products: N-able N-central
- Platforms: Windows, Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: N-able N-central, Windows, Linux, T1190, T1136, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (low)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.

**Required telemetry:**
- SecurityEvent

### KQL

```kql
let lookback = 1h;
let ncentral_hosts = SecurityEvent
| where TimeGenerated > ago(lookback)
| where EventID == 4624
| where LogonType in (2, 3, 10)
| where TargetUserName has_any ("nable", "ncentral", "n-central")
| summarize LogonCount = count(), RecentLogonAccount = any(TargetUserName) by Computer;
SecurityEvent
| where TimeGenerated > ago(lookback)
| where EventID == 4720
| where SubjectUserName != "SYSTEM"
| join kind=leftsemi ncentral_hosts on Computer
| lookup kind=leftouter ncentral_hosts on Computer
| project TimeGenerated, Computer, SubjectUserName, SubjectDomainName = column_ifexists("SubjectDomainName", ""), TargetUserName, LogonCount, RecentLogonAccount
| extend AlertDetail = strcat("New account '", TargetUserName, "' created by '", SubjectUserName, "' on host '", Computer, "' which had recent N-central service account logon activity (count: ", LogonCount, ")")
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate N-central upgrades or re-installations may trigger account creation events under the service account context.
- Other software using 'nable' or 'ncentral' in account names on the same hosts would match the logon baseline and trigger the join.

**Tuning notes:**
- Validate actual N-central service account names in SecurityEvent before deploying; replace has_any patterns with exact account names if possible.
- Add a Computer filter scoped to known N-central server hostnames using a Sentinel watchlist to reduce false positives from unrelated infrastructure.
- Adjust LogonType filter if N-central service accounts authenticate via service logon (LogonType 5) rather than interactive or network logons.

**Risks / caveats:**
- SecurityEvent table requires Microsoft Sentinel Windows Security Events connector (via AMA or legacy MMA) with audit policy enabling EventID 4720 (Account Management) and EventID 4624 (Logon) on N-central hosts. If these audit categories are not enabled, both event types will be absent.
- SubjectUserName in EventID 4720 may be empty or populated as SYSTEM in some configurations, which would prevent attribution of the creating account.
- The 1-hour lookback window may miss slow-burn post-exploitation scenarios where account creation occurs hours after initial access. Consider extending to 4-8 hours if alert volume permits.
- The service account name patterns 'nable', 'ncentral', 'n-central' must be validated against the actual deployment before scheduling.

### Triage Runbook

**First 15 minutes:**
- Confirm the affected host is a known N-able N-central server and identify whether the alert falls within a maintenance, upgrade, or reinstallation window.
- Review the creating account, target account, and host context to determine whether the creator is a known admin or service identity versus an unexpected interactive user.
- Check whether the new account was immediately used for logons, remote access, or privilege assignment after creation.
- Look for concurrent signs of post-exploitation on the same host, including suspicious process creation, script execution, or outbound connections.

**Evidence to collect:**
- EventID 4720 details: SubjectUserName, SubjectDomainName, TargetUserName, TargetDomainName, Computer, and TimeGenerated.
- Recent EventID 4624 logons on the same host, especially LogonType 2, 3, or 10, tied to N-central service account activity.
- Any subsequent account-management events for the new account, such as group membership changes or password resets.
- Host-level process telemetry around the same time to identify the process tree and any child processes spawned by the N-central service context.

**Pivot points:**
- SecurityEvent for EventID 4720, 4722, 4728, 4732, 4738, and 4624 on the affected Computer.
- SecurityEvent filtered to the suspected SubjectUserName to see whether that identity has a history of legitimate account creation.
- DeviceProcessEvents or equivalent endpoint process telemetry on the N-central host to identify suspicious child processes around the alert time.
- DeviceNetworkEvents or firewall logs from the host to check for outbound connections immediately before or after account creation.

**Benign explanations:**
- A planned N-central upgrade, reinstall, or administrative workflow created a local service account as part of normal setup.
- A known administrator used the N-central server to create a support or service account during maintenance.
- The alert matched a non-N-central account name that happens to contain the same substrings used by the detection logic.

**Escalation criteria:**
- The account was created outside a known maintenance window and the creator is not a recognized administrator or service identity.
- The new account is used for logon, remote access, or privilege changes shortly after creation.
- There are additional indicators of compromise on the N-central host, such as suspicious child processes, scripting activity, or unusual outbound traffic.
- The host is internet-facing or otherwise exposed and there is no clear business justification for the account creation.

**Containment actions:**
- Disable the newly created local account if it is not confirmed legitimate.
- Isolate the N-central server from the network if there are corroborating signs of active compromise.
- Preserve volatile and endpoint evidence before rebooting or making major changes to the host.
- Notify the N-central platform owner to validate whether any maintenance activity explains the event.

**Closure criteria:**
- The account creation is confirmed as part of a documented and approved N-central maintenance or installation activity.
- No suspicious follow-on logons, privilege changes, or process activity are found on the host.
- The creating identity and target account are validated as expected service or administrative accounts.
- Any false-positive pattern is documented for future tuning, including host scoping or exact account-name matching.

<br/>
---
<br/>

## Detection 2: N-central Post-Exploitation: Privilege Escalation via sudo or su Spawned from N-central Service Account

### Detection Opportunity

Privilege escalation to root on Linux hosts running N-central, initiated from the N-central service account process tree via sudo or su execution.

### Intelligence Context

- Rapid7: Critical vulnerabilities in N-able N-central prompt hosted shutdown — [https://www.rapid7.com/blog/post/etr-critical-vulnerabilities-in-n-able-n-central-prompt-hosted-shutdown](https://www.rapid7.com/blog/post/etr-critical-vulnerabilities-in-n-able-n-central-prompt-hosted-shutdown)
  - Context: Rapid7 reported that exploitation of N-central includes privilege escalation to root, with one chain executing code as the nable service account before escalating. Detection targets sudo or su execution spawned within the N-central service account process tree on Linux.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1068, T1190, T1059
- Products: N-able N-central
- Platforms: Linux
- Malware: Not specified
- Tools: Not specified
- Search tags: N-able N-central, Linux, T1068, T1190, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (low)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("sudo", "su")
| where InitiatingProcessAccountName has_any ("nable", "ncentral")
| where InitiatingProcessFileName has_any ("java", "ncentral", "nable", "tomcat")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| extend AlertDetail = strcat("Privilege escalation attempt via '", FileName, "' initiated by '", InitiatingProcessAccountName, "' under parent '", InitiatingProcessFileName, "' on '", DeviceName, "'")
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate N-central maintenance scripts or automated patching workflows may invoke sudo under the service account context.
- Other Java-based applications running under accounts with 'nable' or 'ncentral' substrings on the same hosts would match.

**Tuning notes:**
- Confirm the exact N-central service account name in the environment and replace has_any patterns with the precise account name.
- Confirm the N-central parent process name as it appears in InitiatingProcessFileName in DeviceProcessEvents on the target hosts before relying on the filter.
- Add a DeviceName filter scoped to known N-central Linux server hostnames to reduce noise from other Java applications.

**Risks / caveats:**
- Microsoft Defender for Endpoint must be deployed on Linux hosts running N-central and process telemetry must be flowing to Defender XDR. Without MDE Linux agent coverage on N-central hosts, DeviceProcessEvents will contain no relevant records.
- ParentProcessName is not a standard field in DeviceProcessEvents; the correct field is InitiatingProcessFileName. Using ParentProcessName will cause a query error or return no results.
- The 7-day lookback is appropriate for hunting but may generate high volume in active environments; reduce to 24-48 hours for initial triage runs.
- Service account name patterns must be validated against the actual N-central deployment before this query is meaningful.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is a Linux N-central server and verify the exact service account name involved.
- Inspect the sudo or su command line to see which user, command, and target shell were requested.
- Check whether the parent process is the expected N-central Java or Tomcat process and whether the timing aligns with approved maintenance.
- Look for immediate post-escalation activity such as root-owned process creation, file changes, or outbound connections.

**Evidence to collect:**
- DeviceProcessEvents for the sudo or su process, including InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, and ProcessCommandLine.
- Any process tree showing what sudo or su launched next, especially shells, scripts, package managers, or remote tools.
- Authentication and audit logs on the Linux host that show who invoked sudo, whether a password was supplied, and whether the command succeeded.
- Recent file, network, and service changes on the host that indicate root-level actions after the escalation attempt.

**Pivot points:**
- DeviceProcessEvents for all processes spawned by the same InitiatingProcessAccountName on the affected DeviceName.
- Linux auth logs or auditd logs for sudo, su, and root session activity around the alert timestamp.
- DeviceNetworkEvents for the same host to identify outbound connections from the escalated process tree.
- DeviceFileEvents or file integrity logs to identify configuration changes, new binaries, or dropped scripts.

**Benign explanations:**
- A legitimate N-central maintenance script used sudo or su to perform approved administrative tasks.
- An automated patching or configuration workflow ran under the N-central service account and required elevated privileges.
- The service account naming pattern matched the detection even though the process was unrelated to N-central.

**Escalation criteria:**
- sudo or su was used interactively or with an unexpected command, especially to spawn a shell or run a downloader.
- The parent process or command line is inconsistent with known N-central maintenance behavior.
- Root-level follow-on activity is observed, such as new services, modified cron jobs, dropped scripts, or outbound C2-like traffic.
- The host shows additional compromise indicators or the escalation occurred on an internet-facing N-central system.

**Containment actions:**
- Suspend or disable the affected service account if it is not required for ongoing operations.
- Isolate the Linux host if root compromise is suspected or confirmed.
- Preserve process, auth, and audit logs before remediation.
- Coordinate with the platform owner to stop any suspicious automation or scheduled jobs tied to the host.

**Closure criteria:**
- The sudo or su invocation is validated as a documented administrative or maintenance action.
- No suspicious child processes, root-owned persistence, or outbound connections are found.
- The service account and parent process are confirmed to be expected for this N-central deployment.
- Any legitimate automation is documented and, if needed, added to tuning or allowlists.

<br/>
---
<br/>

## Detection 3: N-central Post-Exploitation: Unexpected Child Process Spawned by N-central Service Account (XXE/RCE Indicator)

### Detection Opportunity

Unexpected child processes spawned under the N-central Java or web service process running as the nable service account, consistent with XXE-triggered remote code execution.

### Intelligence Context

- Rapid7: Critical vulnerabilities in N-able N-central prompt hosted shutdown — [https://www.rapid7.com/blog/post/etr-critical-vulnerabilities-in-n-able-n-central-prompt-hosted-shutdown](https://www.rapid7.com/blog/post/etr-critical-vulnerabilities-in-n-able-n-central-prompt-hosted-shutdown)
  - Context: Rapid7 described an exploitation chain combining XXE and session-handling weaknesses to execute code as the nable service account. Unexpected process spawning from the N-central service process is the primary observable post-exploitation artifact.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: N-able N-central
- Platforms: Linux, Windows
- Malware: Not specified
- Tools: Not specified
- Search tags: N-able N-central, Linux, Windows, T1190, T1059

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1059 Command and Scripting Interpreter (low)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.

**Required telemetry:**
- DeviceProcessEvents

### KQL

```kql
let suspicious_children = dynamic(["bash", "sh", "dash", "cmd.exe", "powershell.exe", "curl", "wget", "python", "python3", "perl", "nc", "ncat", "netcat"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName has_any ("nable", "ncentral")
| where InitiatingProcessFileName has_any ("java", "tomcat", "ncentral", "nable")
| where FileName in~ (suspicious_children)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| extend AlertDetail = strcat("Suspicious child process '", FileName, "' spawned under N-central service account '", InitiatingProcessAccountName, "' from parent '", InitiatingProcessFileName, "' on '", DeviceName, "'")
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate N-central maintenance or health-check scripts may invoke bash or python under the service account.
- Automated deployment or configuration management tools running under the N-central service account context may spawn scripting interpreters.
- Other Java-based applications on the same hosts running under similarly named accounts would match the account filter.

**Tuning notes:**
- Run the query without the FileName in~ filter first to enumerate all child processes of the N-central service account and establish a baseline of expected process names before applying the suspicious_children filter.
- Confirm the exact N-central service account name and parent process name as they appear in DeviceProcessEvents on the target hosts.
- Add a DeviceName filter scoped to known N-central server hostnames to reduce noise from other Java or Tomcat applications in the environment.

**Risks / caveats:**
- Microsoft Defender for Endpoint must be deployed on N-central hosts (both Linux and Windows) and process telemetry must be flowing to Defender XDR. Without MDE agent coverage on N-central hosts, DeviceProcessEvents will contain no relevant records.
- has_any against a dynamic array performs substring matching on FileName, which may match unintended process names. The suspicious_children list should use in~ for exact case-insensitive matching of process file names.
- Service account name patterns and parent process names must be validated against the actual N-central deployment before this query produces meaningful results.
- The suspicious_children list represents common attacker tools but is not exhaustive; legitimate N-central processes that invoke these binaries will generate false positives until a baseline is established.

### Triage Runbook

**First 15 minutes:**
- Identify the exact child process name, command line, and parent process on the affected host.
- Confirm whether the parent is the expected N-central Java or web service process and whether the host is a known N-central server.
- Check whether the child process is a common administrative tool or a suspicious interpreter, downloader, or shell.
- Look for nearby signs of exploitation such as account creation, privilege escalation, or unusual outbound connections.

**Evidence to collect:**
- DeviceProcessEvents for the child process and its full process tree, including parent and grandparent processes.
- Process command lines for both the parent N-central process and the spawned child process.
- DeviceNetworkEvents from the same host and time window to identify downloads, callbacks, or lateral movement.
- DeviceFileEvents to determine whether the child process wrote scripts, binaries, or configuration changes.

**Pivot points:**
- DeviceProcessEvents filtered to the same DeviceName and InitiatingProcessAccountName to enumerate all child processes spawned by the N-central service account.
- DeviceNetworkEvents for the same host to identify suspicious remote destinations or high-volume TLS traffic.
- DeviceFileEvents for the same host to identify dropped files or renamed artifacts around the alert time.
- SecurityEvent or Linux auth logs if the host also shows account creation or privilege escalation activity.

**Benign explanations:**
- A legitimate N-central maintenance task spawned a shell, script interpreter, or utility under the service account.
- An automated health check, backup, or deployment workflow used the N-central process tree to launch a helper process.
- The environment contains another Java or Tomcat application with a similar account name that matched the filter.

**Escalation criteria:**
- The child process is a shell, scripting interpreter, downloader, or remote access tool not expected for N-central operations.
- The command line indicates execution of attacker-controlled content, encoded commands, or staged payloads.
- The child process is followed by account creation, privilege escalation, persistence, or suspicious network activity.
- The host is externally exposed and there is no approved maintenance activity that explains the process spawn.

**Containment actions:**
- Isolate the host if the child process is clearly malicious or if multiple compromise indicators are present.
- Terminate the suspicious child process only if containment can be done safely and evidence has been preserved.
- Preserve the process tree and relevant logs before remediation.
- Coordinate with the N-central owner to stop any related scheduled jobs or services if they are implicated.

**Closure criteria:**
- The child process is confirmed as part of a legitimate and documented N-central workflow.
- No suspicious follow-on activity is observed in process, network, or file telemetry.
- The parent and child process names and command lines match an approved baseline for the environment.
- Any legitimate process pattern is documented for future tuning or allowlisting.

<br/>
---
<br/>

## Detection 4: Sn00py Ransomware: Mass File Rename or Extension Change by Single Process

### Detection Opportunity

Mass file modification consistent with Sn00py ransomware encryption activity, where a single process renames or changes the extension of a high volume of files within a short time window.

### Intelligence Context

- Securelist: Citrus Ransomware: VLESS for traffic, Sn00py for encryption, and LLMs lending a hand — [https://securelist.com/citrus-ransomware/121879/](https://securelist.com/citrus-ransomware/121879/)
  - Context: Securelist reported that the Citrus threat actor deploys Sn00py ransomware to encrypt victim files. No file hashes are available, so detection relies on behavioral volume-based indicators: mass file rename or extension modification by a single process in a compressed time window.

### Search Metadata

- CVEs: Not specified
- Threat actors: Citrus
- ATT&CK tags: Not specified
- Products: Not specified
- Platforms: Not specified
- Malware: Sn00py
- Tools: VLESS
- Search tags: Citrus, Sn00py, VLESS

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Not mapped

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
let time_window = 5m;
let rename_threshold = 100;
let excluded_processes = dynamic(["robocopy.exe", "backup.exe", "veeam", "acronis"]);
DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType == "FileRenamed"
| where not(InitiatingProcessFileName has_any (excluded_processes))
| extend FileExtension = extract(@"\.([^.]+)$", 1, FileName)
| summarize
    FileCount = count(),
    DistinctFolders = dcount(FolderPath),
    DistinctExtensions = dcount(FileExtension),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    InitiatingProcessFolderPath = any(InitiatingProcessFolderPath),
    InitiatingProcessSHA256 = any(InitiatingProcessSHA256)
    by InitiatingProcessFileName, DeviceName, bin(Timestamp, time_window)
| where FileCount >= rename_threshold
| extend DurationSeconds = datetime_diff('second', LastSeen, FirstSeen)
| project FirstSeen, LastSeen, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, FileCount, DistinctFolders, DistinctExtensions, DurationSeconds
| extend AlertDetail = strcat("Process '", InitiatingProcessFileName, "' renamed ", FileCount, " files across ", DistinctFolders, " folders (", DistinctExtensions, " distinct extensions) in ", DurationSeconds, " seconds on '", DeviceName, "'")
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Backup agents, file migration tools, or bulk file conversion utilities not in the excluded_processes list may exceed the threshold.
- Automated document processing pipelines that rename large batches of files in short windows will trigger the alert.

**Tuning notes:**
- Run the query with a threshold of 10 during a known-clean period to establish a baseline of legitimate high-volume file rename operations and identify processes to add to excluded_processes.
- Consider adding 'FileModified' back to ActionType as a secondary signal if the environment shows Sn00py modifying file content without renaming, but expect significantly higher false positive volume.
- Add DistinctExtensions >= 1 and DistinctFolders >= 3 as additional filters to reduce false positives from single-folder batch operations.

**Risks / caveats:**
- DeviceFileEvents ActionType values must include 'FileRenamed' in the environment. 'FileModified' is a valid ActionType but does not specifically indicate extension change; if Sn00py renames files with a new extension, 'FileRenamed' is the primary signal. Confirm ActionType population before relying on 'FileModified' as a ransomware indicator.
- TimeGenerated is not the primary time field in Defender XDR DeviceFileEvents; the correct field is Timestamp. Using TimeGenerated may cause the query to return no results or use ingestion time instead of event time.
- The rename_threshold of 100 files per 5-minute window is a starting baseline and must be adjusted based on observed legitimate file operation volumes in the environment before scheduling.
- The 1-hour lookback window means the scheduled rule must run at least every hour to avoid gaps; align the rule run frequency with the lookback period.

### Triage Runbook

**First 15 minutes:**
- Identify the initiating process, host, and time window to determine whether the activity is still ongoing.
- Check whether the renamed files are concentrated in user data, shared drives, or critical business folders.
- Look for signs of encryption impact such as unusual extensions, inaccessible files, ransom notes, or rapid file churn.
- Verify whether the initiating process is a known backup, migration, or document-processing tool before assuming malicious activity.

**Evidence to collect:**
- DeviceFileEvents showing the renamed files, affected folders, and the initiating process name and hash.
- A sample of original and renamed file names to determine whether extensions were changed consistently.
- DeviceProcessEvents for the initiating process to identify its parent, command line, and execution path.
- Any ransom note files, deleted shadow copies, or other post-encryption artifacts on the host or nearby shares.

**Pivot points:**
- DeviceFileEvents for the same DeviceName and InitiatingProcessFileName to map the full scope of renamed files.
- DeviceProcessEvents for the initiating process hash or path to determine whether it is a known tool or suspicious binary.
- DeviceFileEvents or file share logs on adjacent hosts to see whether the activity spread beyond one endpoint.
- DeviceNetworkEvents to check for outbound connections from the initiating process or related payloads.

**Benign explanations:**
- A backup, migration, or file synchronization tool renamed large numbers of files as part of a legitimate job.
- A document conversion or archival workflow performed bulk renaming in a short period.
- A software deployment or cleanup script changed file names across multiple folders.

**Escalation criteria:**
- The process is not a known administrative or backup tool and the rename pattern is broad, fast, and cross-folder.
- Files show consistent extension changes, inaccessible content, or ransom note artifacts.
- The activity is still in progress or has spread to other hosts or shares.
- The initiating process is unsigned, runs from an unusual path, or has a suspicious parent process.

**Containment actions:**
- Isolate the host immediately if ransomware behavior is confirmed or strongly suspected.
- Stop the initiating process if doing so will not destroy critical evidence and containment is not already achieved by isolation.
- Disable access to affected shares if encryption is spreading across network locations.
- Preserve samples of the process, renamed files, and relevant logs for incident response.

**Closure criteria:**
- The activity is confirmed as a legitimate bulk file operation by an approved tool or workflow.
- No encryption artifacts, ransom notes, or spread to other systems are found.
- The initiating process is validated as expected and the file rename pattern matches normal operational behavior.
- The event is documented and, if needed, the process is added to an allowlist or exclusion list.

<br/>
---
<br/>

## Detection 5: Citrus Ransomware: Anomalous Outbound TLS Connection from Non-Browser Process Consistent with VLESS C2 Tunneling

### Detection Opportunity

VLESS protocol used by Citrus threat actor for C2 traffic tunneling, observable as unusual outbound TLS connections from non-browser processes to uncategorized destinations.

### Intelligence Context

- Securelist: Citrus Ransomware: VLESS for traffic, Sn00py for encryption, and LLMs lending a hand — [https://securelist.com/citrus-ransomware/121879/](https://securelist.com/citrus-ransomware/121879/)
  - Context: Securelist reported that the Citrus group uses VLESS for traffic tunneling as part of their ransomware operation. VLESS operates over standard TLS ports, making detection reliant on behavioral patterns: non-browser processes making sustained outbound connections on port 443 or 8443 to destinations with no established categorization.

### Search Metadata

- CVEs: Not specified
- Threat actors: Citrus
- ATT&CK tags: Not specified
- Products: Not specified
- Platforms: Not specified
- Malware: Sn00py
- Tools: VLESS
- Search tags: Citrus, Sn00py, VLESS

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
- VLESS traffic is indistinguishable from legitimate HTTPS at the network event level without deep packet inspection or JA3/JA4 fingerprinting, which is not available in DeviceNetworkEvents.

**Required telemetry:**
- DeviceNetworkEvents

### KQL

```kql
let browser_processes = dynamic(["chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "safari", "opera.exe"]);
let excluded_processes = dynamic(["svchost.exe", "MsMpEng.exe", "WindowsUpdate", "teams.exe", "onedrive.exe"]);
let lookback = 24h;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where RemotePort in (443, 8443)
| where ActionType == "ConnectionSuccess"
| where not(InitiatingProcessFileName has_any (browser_processes))
| where not(InitiatingProcessFileName has_any (excluded_processes))
| summarize
    ConnectionCount = count(),
    DistinctRemoteIPs = dcount(RemoteIP),
    BytesSent = sum(SentBytes),
    BytesReceived = sum(ReceivedBytes),
    InitiatingProcessFolderPath = any(InitiatingProcessFolderPath),
    InitiatingProcessSHA256 = any(InitiatingProcessSHA256)
    by InitiatingProcessFileName, DeviceName, RemoteUrl, RemoteIP
| where ConnectionCount > 20 or BytesSent > 5000000
| project DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, RemoteIP, RemoteUrl, ConnectionCount, DistinctRemoteIPs, BytesSent, BytesReceived
| sort by BytesSent desc
| extend AlertDetail = strcat("Process '", InitiatingProcessFileName, "' made ", ConnectionCount, " outbound TLS connections to '", RemoteIP, "' with ", BytesSent, " bytes sent from '", DeviceName, "'")
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Enterprise software agents, EDR telemetry uploaders, cloud sync clients, and update services not in the excluded_processes list will generate high-volume matches.
- Custom line-of-business applications making frequent API calls over TLS will match the ConnectionCount threshold.
- Any process with 'svchost.exe' variants or service host wrappers not captured by the exclusion list will appear.

**Tuning notes:**
- Before using this query for triage, run it without the ConnectionCount and BytesSent filters to enumerate all non-browser TLS processes and build a comprehensive excluded_processes list for the environment.
- Validate SentBytes population by running: DeviceNetworkEvents → where Timestamp > ago(1h) → summarize NonNullBytes = countif(isnotnull(SentBytes) and SentBytes > 0) → project NonNullBytes before relying on the bytes threshold.
- Consider correlating results with DeviceProcessEvents to check whether the initiating process was spawned from an unusual parent or is running from a non-standard path, which would increase confidence in a VLESS match.
- Adjust ConnectionCount threshold based on observed baseline connection counts for non-browser processes in the environment over a 24-hour clean period.

**Risks / caveats:**
- SentBytes and ReceivedBytes are not guaranteed to be populated in DeviceNetworkEvents for all connection types or all MDE agent versions. If these fields are null or zero for most records, the BytesSent threshold will not function as intended.
- TimeGenerated is not the primary time field in Defender XDR DeviceNetworkEvents; the correct field is Timestamp. Using TimeGenerated may cause incorrect time filtering.
- No VLESS-specific protocol signatures or IOCs are available; all matches require analyst triage to distinguish VLESS tunneling from legitimate high-volume TLS traffic.
- SentBytes may be null or zero in many DeviceNetworkEvents records depending on MDE agent version and OS; validate field population before relying on the BytesSent threshold.

### Triage Runbook

**First 15 minutes:**
- Identify the initiating process, destination IP or URL, and whether the connection volume is unusual for that host.
- Check whether the process is a known browser, updater, agent, or line-of-business application that normally uses TLS.
- Review the process path and parent process to see whether the binary is running from an unusual location or was spawned by a suspicious parent.
- Look for corroborating signs of compromise such as file renames, scripting activity, or new persistence on the same host.

**Evidence to collect:**
- DeviceNetworkEvents showing the destination, port, connection count, and byte volume for the initiating process.
- DeviceProcessEvents for the initiating process, including parent process, command line, and file path.
- Any related DeviceFileEvents that indicate payload staging, script drops, or ransomware-like file activity.
- Proxy, firewall, or DNS logs to determine whether the destination is newly observed, uncategorized, or associated with other suspicious hosts.

**Pivot points:**
- DeviceNetworkEvents for the same DeviceName and InitiatingProcessFileName to see all remote destinations contacted.
- DeviceProcessEvents for the initiating process hash or path to determine whether it is signed and expected.
- DNS and proxy logs to identify whether the destination domain is newly registered, rare, or shared across multiple alerts.
- DeviceFileEvents and DeviceRegistryEvents to check for persistence or payload staging on the same host.

**Benign explanations:**
- A legitimate enterprise agent, updater, or sync client is making frequent TLS connections.
- A custom business application uses HTTPS for API calls and is not browser-based.
- The process is a service wrapper or helper binary that normally communicates over TLS.

**Escalation criteria:**
- The process is unknown, unsigned, or running from an unusual path and the destination is rare or uncategorized.
- The connection pattern is sustained, high-volume, and not consistent with the application’s normal behavior.
- There are additional compromise indicators on the host, especially file encryption, script execution, or persistence.
- Multiple hosts show the same destination or process pattern, suggesting coordinated malicious activity.

**Containment actions:**
- Isolate the host if the TLS activity is accompanied by other compromise indicators or the process is clearly malicious.
- Block the destination at the proxy or firewall if it is confirmed malicious and containment is needed.
- Preserve process and network evidence before terminating the process or reimaging the host.
- Coordinate with endpoint owners to verify whether the process is an approved application before taking disruptive action.

**Closure criteria:**
- The process and destination are confirmed as legitimate and consistent with normal application behavior.
- No supporting evidence of ransomware, persistence, or unauthorized execution is found.
- The destination is documented as an approved service or vendor endpoint.
- The process is added to tuning guidance or allowlists if it is a recurring benign source of alerts.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Telemetry availability:**
- N-central Post-Exploitation: New Local Account Created Following Service Account Activity: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.
- N-central Post-Exploitation: Privilege Escalation via sudo or su Spawned from N-central Service Account: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.
- N-central Post-Exploitation: Unexpected Child Process Spawned by N-central Service Account (XXE/RCE Indicator): Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.

**Schema / correlation keys:**
- Citrus Ransomware: Anomalous Outbound TLS Connection from Non-Browser Process Consistent with VLESS C2 Tunneling: Do not schedule yet; validate as an analyst-led hunt first.

**Other deployment dependency:**
- Citrus Ransomware: Anomalous Outbound TLS Connection from Non-Browser Process Consistent with VLESS C2 Tunneling: VLESS traffic is indistinguishable from legitimate HTTPS at the network event level without deep packet inspection or JA3/JA4 fingerprinting, which is not available in DeviceNetworkEvents.

**Shared-table notes:**
- DeviceProcessEvents: shared by N-central Post-Exploitation: Privilege Escalation via sudo or su Spawned from N-central Service Account; N-central Post-Exploitation: Unexpected Child Process Spawned by N-central Service Account (XXE/RCE Indicator)

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: Sn00py Ransomware: Mass File Rename or Extension Change by Single Process.
2. Resolve environment-mapping detections next: N-central Post-Exploitation: New Local Account Created Following Service Account Activity; N-central Post-Exploitation: Privilege Escalation via sudo or su Spawned from N-central Service Account; N-central Post-Exploitation: Unexpected Child Process Spawned by N-central Service Account (XXE/RCE Indicator).
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: Citrus Ransomware: Anomalous Outbound TLS Connection from Non-Browser Process Consistent with VLESS C2 Tunneling.

### Hunting Agenda and Promotion Criteria

- Citrus Ransomware: Anomalous Outbound TLS Connection from Non-Browser Process Consistent with VLESS C2 Tunneling: Do not schedule yet; validate as an analyst-led hunt first.; baseline expected benign activity and define an alert-volume threshold.
- N-central Post-Exploitation: New Local Account Created Following Service Account Activity: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: SecurityEvent before scheduling.; baseline expected benign activity and define an alert-volume threshold.
- N-central Post-Exploitation: Privilege Escalation via sudo or su Spawned from N-central Service Account: Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling..
- N-central Post-Exploitation: Unexpected Child Process Spawned by N-central Service Account (XXE/RCE Indicator): Environment-specific telemetry or field mapping must be resolved for Defender XDR: DeviceProcessEvents before scheduling.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
