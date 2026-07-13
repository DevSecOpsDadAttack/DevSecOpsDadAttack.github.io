---
layout: post
title: "Detection Engineering Brief - Monday, July 13, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-13
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-41264
  - T1190
  - Flowise
  - Metasploit
  - macOS
  - GigaWiper
  - email
  - MCP servers
  - AI assistant credentials
  - T1059
  - T1059.006
  - T1485
  - T1490
  - T1566
  - T1566.001
  - T1595
  - T1595.002
  - T1552
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

1 production candidate, 1 hunting-only, 3 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-41264, T1190, Flowise, Metasploit, macOS, GigaWiper, email, MCP servers, AI assistant credentials, T1059, T1059.006, T1485, T1490, T1566, T1566.001, T1595, T1595.002, T1552.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Flowise CSV Upload Triggering Python Child Process Execution; Flowise CSV Agent Endpoint POST Followed by Unexpected Child Process Spawn (CVE-2026-41264); HTML Attachment Delivered via External Email as Phishing Lure; High-Rate Inbound Connection Attempts to MCP Server Ports Followed by API Credential Access.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Flowise CSV Upload Triggering Python Child Process Execution

### Detection Opportunity

Unauthenticated CSV file upload to Flowise server triggers Python code execution as a child process of the web server process

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Exploits for FlowiseAI CSV Agent and MacOS Package Kit — [https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-exploits-for-flowiseai-csv-agent-and-macos-package-kit](https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-exploits-for-flowiseai-csv-agent-and-macos-package-kit)
  - Context: CVE-2026-41264 allows unauthenticated attackers to upload a malicious CSV file to the Flowise CSV Agent endpoint, causing the server to execute arbitrary Python code. A Metasploit module covering this exploit path has been released, indicating active weaponization.

### Search Metadata

- CVEs: CVE-2026-41264
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059, T1059.006
- Products: Flowise
- Platforms: macOS
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-41264, T1190, Flowise, Metasploit, macOS, T1059, T1059.006

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter/ T1059.006 Python (high)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let lookback = 15m;
let csvUploads = DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType == "FileCreated"
| where FileExtension =~ "csv"
| where FolderPath has_any ("tmp", "temp", "upload", "flowise")
| project DeviceId, UploadTime = Timestamp, UploadedFile = FileName, FolderPath;
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in~ ("python", "python3", "python3.11", "python3.12")
| where InitiatingProcessFileName in~ ("node", "flowise")
| join kind=inner (csvUploads) on DeviceId
| where Timestamp between (UploadTime .. (UploadTime + lookback))
| project
    Timestamp,
    DeviceId,
    DeviceName,
    AccountName,
    ParentProcess = InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    PythonProcess = FileName,
    CommandLine = ProcessCommandLine,
    UploadedFile,
    FolderPath,
    UploadTime
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate data science or automation workflows where a Node.js application intentionally spawns Python processes against CSV files.
- Scheduled ETL jobs that write CSV files to temp directories and then invoke Python for processing.

**Tuning notes:**
- Confirm the exact FolderPath prefix used by Flowise for uploaded CSV files on the target host and replace the has_any list with that specific path.
- Confirm the InitiatingProcessFileName value reported by MDE for the Flowise Node.js process on macOS before scheduling.
- Adjust the lookback window based on observed Flowise CSV processing latency in the environment.

**Risks / caveats:**
- DeviceFileEvents and DeviceProcessEvents telemetry from macOS endpoints requires Microsoft Defender for Endpoint macOS agent at a sufficient onboarding level; FileCreated ActionType availability on macOS should be confirmed.
- InitiatingProcessFileName for Node.js processes on macOS may be reported as 'node' without the '.js' extension; the exact value depends on the MDE sensor version and macOS packaging of Flowise.
- The 15-minute correlation window between CSV file creation and Python spawn may miss slow-processing Flowise deployments or generate false positives if the window is too wide.
- The FileEventCount threshold and FolderPath filter require baseline review against the specific Flowise deployment before the query reliably distinguishes exploit activity from normal operation.

### Triage Runbook

**First 15 minutes:**
- Confirm the Flowise host, timestamp, and user context in the alert; verify the Python process was spawned by the expected Flowise/Node parent and not by a known automation job.
- Check whether the CSV upload came from an unauthenticated or unexpected source and whether the upload path matches the deployment’s normal Flowise temp/upload directory.
- Review the Python command line and any child processes for signs of payload execution, shell invocation, network access, or file modification beyond normal CSV parsing.
- Look for additional process creation, new files, or outbound connections from the same host in the same time window to determine if the activity extended beyond a single execution event.

**Evidence to collect:**
- DeviceProcessEvents for the parent Node/Flowise process, Python child process, command lines, account name, and process lineage.
- DeviceFileEvents for the uploaded CSV file, its path, creation time, and any follow-on file writes or drops.
- Any web/proxy/WAF logs showing the CSV upload request, source IP, request path, and authentication state.
- Host telemetry for outbound connections, persistence artifacts, or additional suspicious child processes after the Python spawn.

**Pivot points:**
- DeviceProcessEvents filtered to the same DeviceId and a wider time window around the alert.
- DeviceFileEvents for the same DeviceId and FolderPath to identify other uploaded or dropped files.
- Web proxy/WAF or reverse proxy logs for Flowise CSV agent requests and source IPs.
- If available, endpoint network telemetry for outbound connections from the host after the alert time.

**Benign explanations:**
- A legitimate Flowise workflow may intentionally spawn Python to process uploaded CSV data.
- A data science or automation pipeline may use Node.js to invoke Python as part of normal ETL processing.
- A service account or scheduled job may create CSV files in temp/upload directories and trigger expected script execution.

**Escalation criteria:**
- The Python process is not associated with a known approved Flowise workflow or service account.
- The host shows additional suspicious activity such as shell spawning, persistence, credential access, or outbound connections to unknown destinations.
- The CSV upload originated from an unauthenticated or external source and the host behavior matches exploit execution.
- You cannot validate the upload path, parent process, or command line against the environment’s known-good Flowise deployment.

**Containment actions:**
- Isolate the Flowise host from the network if the Python execution is unexpected or there are signs of follow-on activity.
- Disable or restrict the exposed Flowise CSV endpoint until the vulnerable version is confirmed and patched.
- Preserve volatile evidence and collect process, file, and network telemetry before remediation if compromise is suspected.

**Closure criteria:**
- The Python spawn is confirmed to be part of an approved Flowise workflow or scheduled automation.
- No additional suspicious processes, files, or network activity are found on the host.
- The upload path and parent process match the documented deployment behavior and the source is trusted.
- The alert is attributable to a known benign test, integration, or maintenance activity with supporting evidence.

<br/>
---
<br/>

## Detection 2: Flowise CSV Agent Endpoint POST Followed by Unexpected Child Process Spawn (CVE-2026-41264)

### Detection Opportunity

HTTP POST requests to Flowise CSV Agent endpoints correlated with unexpected process spawning on the same host, consistent with prompt injection RCE exploitation

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Exploits for FlowiseAI CSV Agent and MacOS Package Kit — [https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-exploits-for-flowiseai-csv-agent-and-macos-package-kit](https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-exploits-for-flowiseai-csv-agent-and-macos-package-kit)
  - Context: CVE-2026-41264 is exploited via prompt injection through the Flowise CSV Agent endpoint. An unauthenticated POST request carrying a malicious CSV payload causes the server to execute arbitrary Python code. The exploit path is covered by a public Metasploit module.

### Search Metadata

- CVEs: CVE-2026-41264
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059, T1059.006
- Products: Flowise
- Platforms: macOS
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-41264, T1190, Flowise, Metasploit, macOS, T1059, T1059.006

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Initial Access: T1190 Exploit Public-Facing Application (high); Execution: T1059 Command and Scripting Interpreter/ T1059.006 Python (high)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.

**Required telemetry:**
- CommonSecurityLog, Syslog

### KQL

```kql
let lookback = 10m;
let flowisePosts = CommonSecurityLog
| where TimeGenerated > ago(1h)
| where RequestMethod == "POST"
| where RequestURL has_any ("csv", "agent", "flowise")
| project PostTime = TimeGenerated, DestHost = tolower(DestinationHostName), SourceIP;
Syslog
| where TimeGenerated > ago(1h)
| where SyslogMessage has_any ("python", "python3")
| where ProcessName in ("node", "flowise", "sh", "bash")
| project SpawnTime = TimeGenerated, SyslogHost = tolower(HostName), SyslogMessage, ProcessName
| join kind=inner (flowisePosts) on $left.SyslogHost == $right.DestHost
| where SpawnTime between (PostTime .. (PostTime + lookback))
| project
    PostTime,
    SpawnTime,
    SyslogHost,
    SourceIP,
    ProcessName,
    SyslogMessage
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate POST requests to Flowise CSV agent endpoints from authorized users followed by normal Python invocations.
- Monitoring or health-check systems that POST to Flowise endpoints and trigger benign Python execution.
- Syslog messages from unrelated processes whose names or messages contain 'python' as a substring.

**Tuning notes:**
- Replace the RequestURL has_any list with the exact Flowise CSV agent API path once confirmed in the deployment.
- Confirm the ProcessName values reported in Syslog for the Flowise Node.js process on the target macOS host.
- Consider adding a DestinationPort filter to CommonSecurityLog to restrict to the Flowise service port and reduce unrelated POST traffic matches.

**Risks / caveats:**
- CommonSecurityLog RequestURL and RequestMethod fields are only populated when the log source is a WAF, reverse proxy, or application-aware firewall forwarding HTTP metadata; a standard network firewall will not populate these fields.
- Syslog process execution visibility depends on the macOS host being configured to forward auditd or equivalent process execution messages; macOS does not emit process creation to syslog by default without additional endpoint tooling.
- The join on DestinationHostName == HostName requires both fields to use the same hostname format (FQDN vs short name); a mismatch will silently produce zero results.
- The 10-minute correlation window may produce false positives if Python is legitimately invoked by the Flowise host within that window for unrelated reasons.

### Triage Runbook

**First 15 minutes:**
- Confirm the POST request details: source IP, request URL, time, and whether the request was authenticated or came from an external host.
- Correlate the POST with the spawned process on the same host and verify the child process name, command line, and parent process are consistent with exploitation.
- Check for additional process spawns, shell usage, file writes, or outbound connections within the correlation window to assess impact.
- Determine whether the Flowise instance is internet-facing and whether the vulnerable version or exposed endpoint is still present.

**Evidence to collect:**
- CommonSecurityLog entries for the POST request, including source IP, destination host, URL, method, and any proxy/WAF metadata.
- Syslog or host process logs showing the spawned process, parent process, command line, and timestamp.
- Any authentication, application, or reverse proxy logs that show whether the request was unauthenticated or tied to a known user.
- Endpoint telemetry for subsequent child processes, file creation, and network connections from the Flowise host.

**Pivot points:**
- CommonSecurityLog for all requests to the Flowise host around the alert time, especially repeated POSTs from the same source IP.
- Syslog for the same HostName to identify other process execution events near the alert.
- DeviceProcessEvents or equivalent endpoint telemetry if available for the Flowise host to validate process lineage.
- Firewall or proxy logs to determine whether the source IP is external, internal, or a known scanner.

**Benign explanations:**
- Authorized users may legitimately POST to the CSV Agent endpoint during normal application use.
- Monitoring, health checks, or integration tests may generate POST traffic that coincides with benign Python execution.
- A local admin or automation job may trigger a Node.js application to spawn Python for normal processing.

**Escalation criteria:**
- The POST was unauthenticated, external, or from an unknown source and the spawned process is not expected.
- The child process launches a shell, downloads content, modifies system files, or creates persistence.
- Multiple POSTs or repeated process spawns occur from the same source or host.
- You cannot confirm the request was benign or the process lineage matches an approved workflow.

**Containment actions:**
- Block the source IP at the perimeter if it is clearly malicious and the request is part of active exploitation.
- Disable or restrict access to the Flowise CSV Agent endpoint until the host is patched and exposure is reviewed.
- Isolate the Flowise host if there are signs of post-exploitation activity or additional suspicious processes.
- Preserve logs and endpoint evidence before restarting services or applying fixes if compromise is suspected.

**Closure criteria:**
- The POST is confirmed to be from an approved user, test, or monitoring system and the spawned process is expected.
- No additional suspicious process activity or follow-on actions are observed on the host.
- The endpoint exposure is understood and the alert maps to documented application behavior rather than exploitation.
- The source IP and request pattern are validated as benign after review of proxy/WAF and host logs.

<br/>
---
<br/>

## Detection 3: GigaWiper Mass File Deletion with Shadow Copy Destruction

### Detection Opportunity

High-frequency file deletion or overwrite events combined with volume shadow copy or backup deletion commands, consistent with GigaWiper destructive wiper behavior

### Intelligence Context

- Microsoft Security Blog: GigaWiper: Anatomy of a destructive backdoor assembled from multiple malware — [https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/](https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/)
  - Context: GigaWiper combines destructive file wiping with ransomware-like capabilities in a single payload assembled from multiple malware families. Microsoft's analysis highlights mass file deletion and shadow copy destruction as key behavioral indicators for detection.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1485, T1490
- Products: Not specified
- Platforms: Not specified
- Malware: GigaWiper
- Tools: Not specified
- Search tags: GigaWiper, T1485, T1490

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: Impact: T1485 Data Destruction (high); Impact: T1490 Inhibit System Recovery (high)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let timeWindow = 10m;
let shadowCopyDeletion = DeviceProcessEvents
| where Timestamp > ago(1h)
| where ProcessCommandLine has_any (
    "delete shadows",
    "shadowcopy delete",
    "delete catalog",
    "recoveryenabled no",
    "wbadmin delete"
  )
| summarize ShadowDeleteTime = min(Timestamp), CommandLine = take_any(ProcessCommandLine), InitiatingProcess = take_any(InitiatingProcessFileName) by DeviceId;
let massFileDeletion = DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType in ("FileDeleted", "FileModified")
| summarize FileEventCount = count(), WipeWindowStart = min(Timestamp) by DeviceId, bin(Timestamp, timeWindow)
| where FileEventCount > 200
| project DeviceId, WipeWindowStart, FileEventCount;
shadowCopyDeletion
| join kind=inner (massFileDeletion) on DeviceId
| where ShadowDeleteTime between (WipeWindowStart .. (WipeWindowStart + timeWindow))
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(1h)
    | summarize AccountName = take_any(AccountName), DeviceName = take_any(DeviceName) by DeviceId
) on DeviceId
| project
    DeviceId,
    DeviceName,
    AccountName,
    ShadowDeleteTime,
    WipeWindowStart,
    FileEventCount,
    CommandLine,
    InitiatingProcess
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Backup software that deletes old shadow copies as part of a rotation policy and simultaneously modifies large numbers of backup files.
- Software deployment or imaging tools that overwrite many files and invoke bcdedit during OS provisioning.
- Disk cleanup utilities that delete large numbers of temp files while shadow copy management runs concurrently.

**Tuning notes:**
- Increase FileEventCount above 200 if backup or deployment processes on monitored hosts generate high file modification rates during maintenance windows.
- Reduce timeWindow from 10 minutes to 5 minutes to tighten the correlation if sequential but unrelated shadow copy and file deletion events produce false positives.
- Consider adding an InitiatingProcessFileName exclusion list for known backup agent executables that legitimately invoke vssadmin or wbadmin.

**Risks / caveats:**
- FileModified ActionType availability in DeviceFileEvents depends on MDE sensor version and OS; on some configurations only FileCreated and FileDeleted are reliably emitted. Confirm FileModified is present in the environment before relying on it as a wipe signal.
- The FileEventCount threshold of 200 within a 10-minute bin is a starting point; environments with active backup agents or software deployment pipelines may require a higher threshold to avoid false positives.
- The bin(Timestamp, timeWindow) grouping aligns to fixed 10-minute clock boundaries rather than a sliding window, so a wipe event that straddles two bins may be split and fall below the threshold in each bin individually.
- The summarize-based deduplication of shadow copy deletion events takes the earliest timestamp per device; if multiple shadow copy commands fire across the 1-hour lookback, only the first is correlated.

### Triage Runbook

**First 15 minutes:**
- Treat the alert as active destructive behavior until proven otherwise; confirm the affected host, account, and the exact command line used for shadow copy or backup deletion.
- Check whether file deletion or modification is still ongoing and whether the rate is consistent with mass wiping rather than maintenance.
- Identify the initiating process and parent process to determine whether the activity came from a known backup, deployment, or admin tool.
- Assess whether the host has already lost critical data or recovery points by checking for deleted shadow copies, backup catalog changes, or widespread file changes.

**Evidence to collect:**
- DeviceProcessEvents for the shadow copy deletion command line, initiating process, account name, and process tree.
- DeviceFileEvents showing the volume and timing of file deletions or modifications on the same host.
- Any backup, imaging, or admin tool logs that could explain the shadow copy deletion commands.
- Host and security logs for signs of lateral movement, privilege escalation, or additional destructive commands.

**Pivot points:**
- DeviceProcessEvents on the same DeviceId for commands such as vssadmin, wbadmin, bcdedit, or shadow copy deletion variants.
- DeviceFileEvents for the same DeviceId to measure the scope of file deletion/modification across the alert window.
- DeviceNetworkEvents or equivalent telemetry to look for remote command execution or exfiltration preceding the wipe.
- Identity logs for the AccountName to determine whether the account is privileged, service-based, or newly compromised.

**Benign explanations:**
- Backup software may delete old shadow copies as part of a normal retention policy.
- Imaging, deployment, or endpoint management tools may overwrite many files during provisioning or patching.
- Disk cleanup or maintenance tasks may generate high file modification rates and recovery-point changes during scheduled windows.

**Escalation criteria:**
- Shadow copy deletion is performed by an unexpected account or process and coincides with mass file deletion.
- The host shows ongoing destructive activity, multiple affected directories, or evidence of ransomware-like behavior.
- The activity occurs outside a known maintenance window or cannot be matched to a documented backup/deployment job.
- There are signs of lateral movement, privilege escalation, or coordinated activity across multiple hosts.

**Containment actions:**
- Isolate the host immediately if destructive activity is active or unapproved.
- Disable the suspected account or revoke its tokens if the account appears compromised.
- Stop or suspend any suspicious process tree if safe to do so and preserve evidence first when possible.
- Notify backup/recovery owners to verify whether clean backups and restore points remain available.

**Closure criteria:**
- The activity is confirmed to be from an approved backup, imaging, or maintenance process.
- No ongoing file deletion, shadow copy destruction, or related suspicious process activity is observed.
- The file event volume and command line match documented administrative behavior.
- Recovery points and backups are verified intact and the alert is attributable to benign operations.

<br/>
---
<br/>

## Detection 4: HTML Attachment Delivered via External Email as Phishing Lure

### Detection Opportunity

Inbound email from external sender carrying an HTML or HTM attachment, consistent with HTML phishing lure delivery using comment-stuffing evasion techniques

### Intelligence Context

- SANS ISC: "Comment stuffing" in an HTML phishing attachment as a mechanism for evading AI-based detection, (Fri, Jul 10th) — [https://isc.sans.edu/diary/rss/33144](https://isc.sans.edu/diary/rss/33144)
  - Context: Phishing campaigns are delivering HTML attachments padded with excessive HTML comment blocks to evade AI-based email security detection. The structural evasion technique is embedded in the attachment itself, making gateway-level content inspection the primary detection surface.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1566, T1566.001
- Products: Not specified
- Platforms: email
- Malware: Not specified
- Tools: Not specified
- Search tags: email, T1566, T1566.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: Initial Access: T1566 Phishing/ T1566.001 Spearphishing Attachment (medium)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- EmailAttachmentInfo, EmailEvents

### KQL

```kql
let internalDomains = dynamic([]);
EmailAttachmentInfo
| where TimeGenerated > ago(24h)
| where FileName has_any (".html", ".htm") or FileType =~ "html"
| join kind=inner (
    EmailEvents
    | where TimeGenerated > ago(24h)
    | where DeliveryAction == "Delivered"
    | project TimeGenerated, NetworkMessageId, SenderFromAddress, SenderFromDomain, RecipientEmailAddress, Subject, SenderIPv4, ThreatTypes
) on NetworkMessageId
| where array_length(internalDomains) == 0 or SenderFromDomain !in~ (internalDomains)
| project
    TimeGenerated,
    NetworkMessageId,
    SenderFromAddress,
    SenderFromDomain,
    RecipientEmailAddress,
    Subject,
    FileName,
    FileType,
    SenderIPv4,
    DeliveryAction,
    ThreatTypes
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- HTML newsletters, marketing emails, and automated reports from legitimate external senders.
- Business partner communications that include HTML-formatted reports as attachments.
- Internal forwarding scenarios where an external HTML attachment is re-delivered internally.

**Tuning notes:**
- Populate the internalDomains dynamic list with your organization's accepted sender domains to filter out internal mail flows.
- Add a SenderFromDomain exclusion list for known legitimate HTML-sending services such as marketing automation platforms.
- Consider adding a ThreatTypes != '' filter to surface only emails where Defender has already flagged a threat, reducing analyst burden during initial hunting.

**Risks / caveats:**
- OfficeActivity does not contain reliable attachment file name or extension metadata for inbound mail delivery; the original query's use of OfficeObjectId has_any('.html', '.htm') is not a supported pattern for attachment detection in this table.
- EmailAttachmentInfo and EmailEvents are Defender XDR tables; if the target platform is Microsoft Sentinel, these tables require the Microsoft Defender XDR connector with Advanced Hunting data forwarding enabled in Sentinel.
- The internalDomains dynamic list is empty by default; without populating it, the external-sender filter has no effect and all delivered HTML attachments will be returned regardless of sender origin.
- This detection identifies HTML attachment delivery but cannot inspect attachment content for comment-stuffing density; a high false-positive rate from legitimate HTML attachments is expected without additional triage.

### Triage Runbook

**First 15 minutes:**
- Review the sender domain, sender address, subject, recipient, and delivery action to determine whether the message is external and suspicious.
- Inspect the attachment name and file type to confirm it is an HTML/HTM lure and check whether Defender already assigned any threat verdicts.
- Identify whether the recipient opened the message or attachment, clicked links, or reported the email as suspicious.
- Check whether the same sender or subject has been delivered to other users in the tenant.

**Evidence to collect:**
- EmailEvents for sender, recipient, subject, delivery action, threat types, and message identifiers.
- EmailAttachmentInfo for attachment filename, file type, and any related metadata.
- Mailbox or user activity logs showing whether the recipient opened the message or interacted with the attachment.
- Any URL or web proxy logs if the attachment redirected the user to a website after opening.

**Pivot points:**
- EmailEvents for the same sender domain, subject, or NetworkMessageId across the tenant.
- EmailAttachmentInfo for other messages with HTML/HTM attachments from the same sender.
- User mailbox audit or endpoint browser telemetry to determine whether the recipient opened the attachment.
- Threat intelligence or mail gateway logs for the sender domain and any embedded URLs if available.

**Benign explanations:**
- Legitimate newsletters, marketing emails, or business communications may use HTML attachments.
- A trusted partner may send HTML-formatted reports or invoices as attachments.
- Internal forwarding can make an external HTML attachment appear in multiple mailboxes without malicious intent.

**Escalation criteria:**
- The sender is unknown, spoofed, or associated with a known phishing campaign.
- The recipient opened the attachment or clicked through to a credential-harvesting page.
- Multiple recipients received the same HTML attachment or the message contains other phishing indicators.
- Defender or the mail gateway flags the message as malicious or suspicious beyond simple delivery.

**Containment actions:**
- Quarantine or purge the message from other mailboxes if it is confirmed malicious.
- Block the sender domain or sender address if it is clearly abusive and not a legitimate business partner.
- Reset credentials and review sign-in activity if a user interacted with the lure and entered credentials.
- Isolate the endpoint only if there is evidence of malicious payload execution after opening the attachment.

**Closure criteria:**
- The sender and attachment are confirmed legitimate and expected for the business context.
- No user interaction, credential submission, or malicious follow-on activity is found.
- The message is part of a known campaign that was already blocked or remediated by mail controls.
- The alert is attributable to a benign HTML attachment from a trusted source.

<br/>
---
<br/>

## Detection 5: High-Rate Inbound Connection Attempts to MCP Server Ports Followed by API Credential Access

### Detection Opportunity

External scanning of exposed MCP server endpoints correlated with subsequent unusual API key or secret read operations in cloud audit logs, indicating credential harvesting against AI infrastructure

### Intelligence Context

- SANS ISC: Someone Is Scanning for Your MCP Servers and AI Assistant Credentials, (Mon, Jul 13th) — [https://isc.sans.edu/diary/rss/33150](https://isc.sans.edu/diary/rss/33150)
  - Context: Active internet scanning is targeting exposed MCP server endpoints with the goal of harvesting AI assistant API keys and credentials. The compound behavior of external scanning followed by credential access operations represents a higher-confidence signal than either indicator alone.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1595, T1595.002, T1552
- Products: MCP servers, AI assistant credentials
- Platforms: Not specified
- Malware: Not specified
- Tools: Not specified
- Search tags: MCP servers, AI assistant credentials, T1595, T1595.002, T1552

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Reconnaissance: T1595 Active Scanning/ T1595.002 Vulnerability Scanning (medium); Credential Access: T1552 Unsecured Credentials (low)

### Deployment Gates

- Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, AzureActivity before scheduling.

**Required telemetry:**
- CommonSecurityLog, AzureActivity

### KQL

```kql
let scanWindow = 30m;
let scanThreshold = 20;
let scanningIPs = CommonSecurityLog
| where TimeGenerated > ago(2h)
| where DeviceAction !in~ ("allow", "permit", "allowed", "accept", "accepted")
| where DestinationPort !in (80, 443, 22, 25, 53)
| summarize ConnectionCount = count(), FirstSeen = min(TimeGenerated), DestinationHostName = take_any(DestinationHostName) by SourceIP, DestinationPort
| where ConnectionCount >= scanThreshold
| project SourceIP, FirstSeen, DestinationPort, ConnectionCount, DestinationHostName;
let credentialAccess = AzureActivity
| where TimeGenerated > ago(2h)
| where OperationName has_any ("listKeys", "listSecrets", "getSecret", "regenerateKey", "credentials")
| project AccessTime = TimeGenerated, CallerIP = CallerIpAddress, OperationName, ResourceId, ResultType;
scanningIPs
| join kind=inner (credentialAccess) on $left.SourceIP == $right.CallerIP
| where AccessTime between (FirstSeen .. (FirstSeen + scanWindow))
| project
    FirstSeen,
    AccessTime,
    SourceIP,
    DestinationPort,
    DestinationHostName,
    ConnectionCount,
    OperationName,
    ResourceId,
    ResultType
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate penetration testing or vulnerability scanning from authorized external vendors targeting non-standard ports.
- Cloud management platforms or DevOps pipelines that perform key rotation operations from IPs that also appear in firewall logs as high-rate connection sources.
- Shared NAT egress IPs where multiple users generate both network scanning activity and legitimate key management operations.

**Tuning notes:**
- Replace the DestinationPort exclusion list with an explicit inclusion list of the ports on which MCP servers are exposed in the environment to reduce false positives from unrelated port scanning.
- Validate AzureActivity OperationName values against the specific Azure resource types (Key Vault, Azure OpenAI, Cognitive Services) hosting AI credentials before scheduling.
- Adjust scanThreshold based on the baseline connection rate from external IPs observed in CommonSecurityLog for the environment.
- If CallerIpAddress in AzureActivity reflects a shared egress IP, consider replacing the IP join with a time-proximity-only correlation or adding ResourceId filtering to scope to AI-specific resources.

**Risks / caveats:**
- CommonSecurityLog DeviceAction field values vary by log source vendor; the filter DeviceAction !in ('allow', 'permit') may not correctly identify denied or logged-only traffic for all firewall vendors. Confirm the DeviceAction values used by the specific log source before relying on this filter.
- AzureActivity CallerIpAddress may reflect a NAT gateway, VPN concentrator, or Azure service IP rather than the originating external scanner IP, making the IP-based join between CommonSecurityLog and AzureActivity unreliable in environments with shared egress.
- AzureActivity OperationName values for key and secret access vary by Azure service (Key Vault, Cognitive Services, OpenAI); the has_any filter must be validated against the specific resource types hosting AI credentials in the environment.
- The IP-based join between CommonSecurityLog SourceIP and AzureActivity CallerIpAddress is the weakest link in this detection; shared NAT, VPN, or proxy egress will produce false positives or miss true positives depending on the network architecture.

### Triage Runbook

**First 15 minutes:**
- Confirm the source IP, destination port, connection count, and whether the traffic was denied or merely logged by the perimeter device.
- Identify which host or service was targeted and whether it is an MCP server or another exposed non-standard service.
- Review the Azure activity event to see which resource was accessed, whether the operation succeeded, and whether it involved secrets or keys.
- Check whether the source IP is known internal scanning, a vulnerability scanner, or an external internet host.

**Evidence to collect:**
- CommonSecurityLog entries for the scan source, destination port, destination host, and device action.
- AzureActivity records for the credential access operation, including operation name, resource ID, result type, and caller IP.
- Asset inventory or service documentation showing which hosts expose MCP-related ports and which cloud resources store AI credentials.
- Any authentication or admin activity around the same time that could explain the key or secret access.

**Pivot points:**
- CommonSecurityLog for repeated attempts from the same source IP across other ports or hosts.
- AzureActivity for other key, secret, or credential operations on the same ResourceId or by the same CallerIpAddress.
- Firewall or proxy logs to determine whether the source IP is external, NATed, or part of an approved scanner.
- Cloud audit logs for role assignments, token use, or secret retrieval around the same time window.

**Benign explanations:**
- Authorized vulnerability scanning or penetration testing may generate high-rate connection attempts.
- Cloud automation or DevOps pipelines may legitimately access keys or secrets during rotation or deployment.
- Shared NAT or proxy egress can make unrelated internal activity appear correlated by IP.
- A monitoring system may probe exposed services while a separate admin task accesses credentials.

**Escalation criteria:**
- The scan source is external and not an approved scanner, and the cloud credential access is successful.
- The same source or related infrastructure is seen probing multiple hosts or ports.
- The accessed resource contains production AI credentials or secrets and the operation was not expected.
- There is evidence of follow-on abuse such as new token creation, secret export, or unauthorized access to AI services.

**Containment actions:**
- Block or rate-limit the scanning source at the perimeter if it is clearly malicious.
- Rotate or revoke exposed keys and secrets if the credential access is confirmed unauthorized.
- Review and restrict network exposure of MCP services and AI credential stores.
- Escalate to cloud and platform owners to validate whether any secrets were used elsewhere after access.

**Closure criteria:**
- The scan source is an approved internal scanner or authorized test activity.
- The Azure activity is confirmed to be a legitimate key rotation, deployment, or admin action.
- No unauthorized access, secret misuse, or additional suspicious activity is found.
- The correlation is explained by NAT/proxy behavior or unrelated benign operations.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Other deployment dependency:**
- Flowise CSV Upload Triggering Python Child Process Execution: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Telemetry availability:**
- Flowise CSV Agent Endpoint POST Followed by Unexpected Child Process Spawn (CVE-2026-41264): Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.
- High-Rate Inbound Connection Attempts to MCP Server Ports Followed by API Credential Access: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, AzureActivity before scheduling.

**Schema / correlation keys:**
- HTML Attachment Delivered via External Email as Phishing Lure: Do not schedule yet; validate as an analyst-led hunt first.

**Shared-table notes:**
- DeviceProcessEvents: shared by Flowise CSV Upload Triggering Python Child Process Execution; GigaWiper Mass File Deletion with Shadow Copy Destruction
- DeviceFileEvents: shared by Flowise CSV Upload Triggering Python Child Process Execution; GigaWiper Mass File Deletion with Shadow Copy Destruction
- CommonSecurityLog: shared by Flowise CSV Agent Endpoint POST Followed by Unexpected Child Process Spawn (CVE-2026-41264); High-Rate Inbound Connection Attempts to MCP Server Ports Followed by API Credential Access

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: GigaWiper Mass File Deletion with Shadow Copy Destruction.
2. Resolve environment-mapping detections next: Flowise CSV Upload Triggering Python Child Process Execution; Flowise CSV Agent Endpoint POST Followed by Unexpected Child Process Spawn (CVE-2026-41264); High-Rate Inbound Connection Attempts to MCP Server Ports Followed by API Credential Access.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: HTML Attachment Delivered via External Email as Phishing Lure.

### Hunting Agenda and Promotion Criteria

- HTML Attachment Delivered via External Email as Phishing Lure: Do not schedule yet; validate as an analyst-led hunt first..
- Flowise CSV Upload Triggering Python Child Process Execution: Defender for Endpoint file-event coverage must be confirmed on the target host population.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Flowise CSV Agent Endpoint POST Followed by Unexpected Child Process Spawn (CVE-2026-41264): Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, Syslog before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- High-Rate Inbound Connection Attempts to MCP Server Ports Followed by API Credential Access: Environment-specific telemetry or field mapping must be resolved for Microsoft Sentinel: CommonSecurityLog, AzureActivity before scheduling.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
