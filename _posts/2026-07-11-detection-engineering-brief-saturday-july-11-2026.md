---
layout: post
title: "Detection Engineering Brief - Saturday, July 11, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-07-11
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - CVE-2026-41264
  - Flowise
  - macOS
  - Metasploit
  - T1059
  - T1190
  - GigaWiper
  - email
  - T1485
  - T1486
  - T1566
  - T1566.001
---

## Detection Engineering Summary

This brief produced 4 detection candidates.

1 production candidate, 0 hunting-only, 3 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 4 include triage guidance.

Search metadata extracted for this run includes: CVE-2026-41264, Flowise, macOS, Metasploit, T1059, T1190, GigaWiper, email, T1485, T1486, T1566, T1566.001.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: Flowise CSV Agent - Python Execution Spawned by Node.js Web Process; Flowise CSV Agent - Unauthenticated CSV File Drop in Web Application Directory; HTML Phishing Attachment Delivery - External Sender with HTML or HTM File Attachment.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: Flowise CSV Agent - Python Execution Spawned by Node.js Web Process

### Detection Opportunity

Arbitrary Python code execution spawned from Flowise CSV_Agents process following unauthenticated CSV upload

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Exploits for FlowiseAI CSV Agent and MacOS Package Kit — [https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-exploits-for-flowiseai-csv-agent-and-macos-package-kit](https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-exploits-for-flowiseai-csv-agent-and-macos-package-kit)
  - Context: CVE-2026-41264 allows unauthenticated attackers to upload a CSV file containing arbitrary Python code to the Flowise CSV_Agents endpoint, resulting in server-side Python execution. A Metasploit module exists for this vulnerability.

### Search Metadata

- CVEs: CVE-2026-41264
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Flowise
- Platforms: macOS
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-41264, Flowise, macOS, Metasploit, T1059, T1190

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: initial-access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let lookback = 1h;
let csvUploads = DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType == "FileCreated"
| where FileName endswith ".csv"
| where FolderPath has_any ("flowise", "uploads", "tmp")
| project DeviceName, CSVCreatedTime = Timestamp, CSVFile = FileName, FolderPath;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ ("python", "python3", "python3.exe", "python.exe")
| where InitiatingProcessFileName has_any ("node", "flowise")
| project
    DeviceName,
    PythonSpawnTime = Timestamp,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    SHA256,
    InitiatingProcessSHA256
| join kind=leftouter csvUploads on DeviceName
| where isnull(CSVCreatedTime) or PythonSpawnTime between (CSVCreatedTime .. (CSVCreatedTime + 5min))
| project
    DeviceName,
    AccountName,
    PythonSpawnTime,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    SHA256,
    InitiatingProcessSHA256,
    CSVCreatedTime,
    CSVFile,
    FolderPath
| order by PythonSpawnTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate Node.js applications that invoke Python scripts as part of normal workflows on the same host.
- Development or CI/CD environments where Node.js and Python are co-located and interact routinely.
- Backup or data-processing pipelines that create CSV files in temp directories and subsequently invoke Python.

**Tuning notes:**
- Scope DeviceName to known Flowise server hostnames using a dynamic device group or a let-bound list to reduce false positives from other Node.js applications.
- Replace FolderPath has_any fragments with the exact absolute path of the Flowise upload directory in your deployment.
- Baseline Python-spawned-by-Node events in your environment before scheduling to establish a normal rate and identify exclusion candidates.

**Risks / caveats:**
- DeviceFileEvents and DeviceProcessEvents require Defender for Endpoint Plan 2 or Microsoft 365 Defender with endpoint telemetry enabled on macOS hosts running Flowise.
- macOS process telemetry in DeviceProcessEvents may not capture all parent-child relationships for Node.js-spawned processes depending on the MDE sensor version deployed.
- FolderPath fragments ('flowise', 'uploads', 'tmp') are broad and will match non-Flowise processes; replace with the exact Flowise upload directory path for your deployment before scheduling.
- The leftouter join will surface Python-spawns-from-Node events even without a correlated CSV drop, which increases sensitivity but also increases analyst review volume.

### Triage Runbook

**First 15 minutes:**
- Confirm the host is an approved Flowise server and that the alert time aligns with a recent CSV upload or user action.
- Review the Python process command line, parent process, and parent command line to verify the spawn came from Flowise/node rather than another application.
- Check whether the Python process created, modified, or executed additional files in the Flowise working or upload directories.
- Look for nearby authentication, web, or application logs showing an unauthenticated request to the CSV_Agents endpoint or unusual client IPs.
- If the process is unexpected, preserve volatile evidence and notify the incident lead immediately.

**Evidence to collect:**
- DeviceProcessEvents for the Python child process, parent node/flowise process, command lines, SHA256 values, and account context.
- DeviceFileEvents for the CSV creation event, file name, folder path, and timestamp correlation.
- Any Flowise application logs, reverse proxy logs, or web server access logs covering the same time window.
- Host inventory details confirming the device role, installed Flowise version, and whether the host is internet-facing.
- Any subsequent process tree activity from the same initiating process, including shell, script, or archive utilities.

**Pivot points:**
- DeviceProcessEvents filtered to the same DeviceName and InitiatingProcessFileName in the 30 minutes before and after the alert.
- DeviceFileEvents for CSV file creation, rename, or modification in the Flowise upload directory on the same host.
- DeviceNetworkEvents for inbound connections to the host around the alert time to identify the source IP and listener port.
- Flowise or web access logs to correlate request path, source IP, user agent, and response code.
- Threat intel or EDR enrichment on the Python SHA256 and initiating process SHA256.

**Benign explanations:**
- A legitimate Flowise workflow may invoke Python as part of normal data processing or agent execution.
- A developer, tester, or CI/CD job may be running Flowise locally on a macOS host with Node.js and Python co-located.
- The alert may be caused by another Node.js application on the same host that also spawns Python for routine tasks.
- File telemetry may correlate to a benign CSV upload if the host is not actually running Flowise or the path is a shared temp directory.

**Escalation criteria:**
- The host is a production or internet-facing Flowise server and the Python spawn is not tied to a known approved workflow.
- The CSV file or request appears to originate from an unauthenticated or external source, especially if followed by unexpected script execution.
- The Python process launches shells, downloads content, writes web-accessible files, or spawns additional suspicious children.
- The same host shows multiple exploit-like attempts, repeated CSV drops, or other signs of post-exploitation activity.

**Containment actions:**
- Isolate the host from the network if the Python execution is confirmed unexpected or if additional suspicious activity is observed.
- Disable or restrict external access to the Flowise endpoint until the host is validated and patched.
- Preserve relevant process, file, and web logs before remediation or reboot.
- Block the source IP or account only if corroborated by web logs and broader incident context.

**Closure criteria:**
- The host is confirmed to be a non-production or approved test system and the Python execution matches documented behavior.
- The correlated CSV upload and Python spawn are validated as part of a known Flowise workflow with no additional suspicious activity.
- No evidence of unauthenticated access, malicious command execution, or follow-on activity is found after review.
- Any false-positive source is documented and the host/path is added to the approved baseline or watchlist.

<br/>
---
<br/>

## Detection 2: Flowise CSV Agent - Unauthenticated CSV File Drop in Web Application Directory

### Detection Opportunity

Unauthenticated CSV file upload containing arbitrary Python code to Flowise endpoint, detected via file creation in application working directory

### Intelligence Context

- Rapid7: Weekly Metasploit Update: Exploits for FlowiseAI CSV Agent and MacOS Package Kit — [https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-exploits-for-flowiseai-csv-agent-and-macos-package-kit](https://www.rapid7.com/blog/post/pt-weekly-metasploit-update-exploits-for-flowiseai-csv-agent-and-macos-package-kit)
  - Context: The exploit for CVE-2026-41264 requires no authentication and delivers a CSV file with embedded Python code to the Flowise CSV_Agents run method. Detection of the file drop itself provides an earlier-stage signal before code execution occurs.

### Search Metadata

- CVEs: CVE-2026-41264
- Threat actors: Not specified
- ATT&CK tags: T1190, T1059
- Products: Flowise
- Platforms: macOS
- Malware: Not specified
- Tools: Metasploit
- Search tags: CVE-2026-41264, Flowise, macOS, Metasploit, T1059, T1190

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: initial-access: T1190 Exploit Public-Facing Application (high)

### Deployment Gates

- Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Required telemetry:**
- DeviceFileEvents, DeviceNetworkEvents

### KQL

```kql
let lookback = 1h;
let csvDrops = DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType == "FileCreated"
| where FileName endswith ".csv"
| where FolderPath has_any ("flowise", "uploads", "tmp")
| where InitiatingProcessFileName has_any ("node", "flowise")
| project DeviceName, FileDropTime = Timestamp, FileName, FolderPath, InitiatingProcessFileName;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType in ("InboundConnectionAccepted", "ConnectionSuccess")
| where InitiatingProcessFileName has_any ("node", "flowise")
| where RemotePort > 1024
| project
    DeviceName,
    NetworkTime = Timestamp,
    RemoteIP,
    RemotePort,
    LocalPort,
    InitiatingProcessFileName
| join kind=inner csvDrops on DeviceName
| where NetworkTime between ((FileDropTime - 2min) .. FileDropTime)
| project
    DeviceName,
    RemoteIP,
    RemotePort,
    LocalPort,
    FileDropTime,
    NetworkTime,
    FileName,
    FolderPath,
    InitiatingProcessFileName
| order by FileDropTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate CSV uploads to Flowise by authorized users will trigger this detection; the detection is intended as a hunting signal requiring analyst review.
- Other Node.js web applications on the same host that accept file uploads will generate matching events.
- Monitoring or health-check agents that connect to the Flowise port shortly before a scheduled file operation.

**Tuning notes:**
- Replace RemotePort > 1024 with the exact port Flowise listens on (default is 3000) to reduce noise from other inbound connections.
- Scope DeviceName to known Flowise server hostnames to prevent matching other Node.js applications.
- Validate that DeviceNetworkEvents captures inbound connections to the Flowise process on your macOS hosts before relying on this detection for alerting.

**Risks / caveats:**
- DeviceNetworkEvents on macOS via MDE may not reliably populate RemoteIP for inbound connections depending on sensor version; validate that inbound HTTP connections to the Flowise process are captured before relying on this table for correlation.
- DeviceNetworkEvents does not have a native 'inbound' direction field in all schema versions; the query relies on RemotePort as a proxy for inbound traffic, which is unreliable.
- RemotePort > 1024 is a broad filter; replace with the specific TCP port Flowise is configured to listen on in your environment to eliminate unrelated inbound connections.
- FolderPath fragments ('flowise', 'uploads', 'tmp') must be replaced with the exact Flowise upload directory path for reliable detection.

### Triage Runbook

**First 15 minutes:**
- Confirm the device is a Flowise server and identify the exact folder path where the CSV was created.
- Review the file name, timestamp, and initiating process to determine whether the upload came through the Flowise/node runtime or another process.
- Check web or reverse proxy logs for a matching request to the CSV_Agents endpoint, including source IP, user agent, and response code.
- Determine whether the uploaded CSV is new, unexpected, or associated with a known user workflow or scheduled job.
- If the file is suspicious or the host is internet-facing, escalate for containment and preserve the file for analysis.

**Evidence to collect:**
- DeviceFileEvents for the CSV creation event, folder path, and initiating process details.
- DeviceNetworkEvents around the same time to identify inbound connections and the source IP.
- Flowise application logs and any front-end proxy logs showing the upload request and endpoint used.
- A copy or hash of the uploaded CSV file for malware or content inspection.
- Host role and deployment details confirming whether the path is the actual Flowise upload directory.

**Pivot points:**
- DeviceFileEvents on the same host for other recent file creations in the Flowise upload or temp directories.
- DeviceNetworkEvents for inbound connections to the host in the 2 minutes before the file drop.
- Web server or reverse proxy logs for requests to Flowise upload endpoints and associated client IPs.
- DeviceProcessEvents for node, flowise, python, shell, or archive utilities spawned near the file creation time.
- Threat intel enrichment on the source IP if one is identified in network or web logs.

**Benign explanations:**
- A legitimate user may have uploaded a CSV to Flowise as part of normal application use.
- A developer or tester may be exercising the CSV_Agents feature in a lab or staging environment.
- Another Node.js application on the same host may create CSV files in a shared temp directory.
- The file may be a benign export or import artifact if the host is not actually running Flowise.

**Escalation criteria:**
- The host is a production or internet-facing Flowise server and the upload is not tied to an approved user or job.
- Web logs show an unauthenticated, external, or suspicious request to the CSV upload endpoint.
- The uploaded CSV is followed by Python execution, shell spawning, or other post-upload activity.
- Multiple suspicious uploads or repeated attempts are observed from the same source IP or account.

**Containment actions:**
- Restrict external access to the Flowise endpoint if the upload is confirmed suspicious or unauthenticated.
- Quarantine or preserve the uploaded CSV and related logs for forensic analysis.
- Isolate the host if there is evidence of follow-on execution or additional suspicious processes.
- Block the source IP at the web tier or perimeter only after confirming it is malicious and not a shared proxy.

**Closure criteria:**
- The file is confirmed to be a legitimate upload from an authorized user or approved automation.
- The device is not a Flowise server or the path is a known benign shared temp location.
- No corroborating web, process, or network evidence supports exploitation.
- The event is documented and the environment-specific path or host baseline is updated to reduce repeat noise.

<br/>
---
<br/>

## Detection 3: GigaWiper - Mass File Deletion and Rename Pattern Indicative of Wiper or Encryption Activity

### Detection Opportunity

Destructive wiper activity combining high-volume file deletion and rapid file rename patterns consistent with GigaWiper's combined wiping and ransomware-like capabilities

### Intelligence Context

- Microsoft Security Blog: GigaWiper: Anatomy of a destructive backdoor assembled from multiple malware — [https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/](https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/)
  - Context: GigaWiper is a destructive backdoor that combines wiping and ransomware-like capabilities assembled from multiple malware families. The behavioral signature is mass file deletion combined with rapid file rename events, which together indicate either data destruction or encryption-based extortion activity.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1485, T1486
- Products: Not specified
- Platforms: Not specified
- Malware: GigaWiper
- Tools: Not specified
- Search tags: GigaWiper, T1485, T1486

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: scheduled_rule
- Severity recommendation: high
- MITRE ATT&CK: impact: T1485 Data Destruction (high); impact: T1486 Data Encrypted for Impact (medium)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceFileEvents

### KQL

```kql
let timeWindow = 5m;
let deletionThreshold = 50;
let renameThreshold = 20;
DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType in ("FileDeleted", "FileRenamed")
| summarize
    Deletions = countif(ActionType == "FileDeleted"),
    Renames = countif(ActionType == "FileRenamed"),
    UniqueExtensions = dcount(tostring(split(FileName, ".")[-1])),
    SampleFiles = make_set(FileName, 5),
    SampleFolderPaths = make_set(FolderPath, 5),
    InitiatingProcessCommandLine = take_any(InitiatingProcessCommandLine),
    InitiatingProcessSHA256 = take_any(InitiatingProcessSHA256),
    InitiatingProcessAccountName = take_any(InitiatingProcessAccountName)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, timeWindow)
| where Deletions >= deletionThreshold and Renames >= renameThreshold
| extend RenameToDeleteRatio = round(todouble(Renames) / todouble(Deletions), 2)
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessSHA256,
    InitiatingProcessAccountName,
    Deletions,
    Renames,
    RenameToDeleteRatio,
    UniqueExtensions,
    SampleFiles,
    SampleFolderPaths
| order by Deletions desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Backup agents (e.g., Veeam, Windows Backup, rsync wrappers) that delete and recreate large file sets during backup jobs.
- File migration or archival tools that rename files as part of staging workflows.
- Antivirus or EDR remediation processes that bulk-delete quarantined files.
- Software deployment tools that replace large numbers of files during updates.

**Tuning notes:**
- Baseline the maximum Deletions and Renames counts per process per 5-minute window for known backup and file management tools in your environment, then add an InitiatingProcessFileName exclusion list for those processes.
- Consider lowering timeWindow to 2m for higher-sensitivity environments where faster wiper execution is expected.
- Add a FolderPath exclusion for known backup staging directories to reduce false positives from backup agents.

**Risks / caveats:**
- ActionType values 'FileDeleted' and 'FileRenamed' must be confirmed as populated in DeviceFileEvents for the OS types (Windows, Linux) enrolled in your Defender for Endpoint deployment; these values are not guaranteed on all sensor configurations.
- Thresholds of 50 deletions and 20 renames within 5 minutes are heuristic starting points; environments with active backup agents or file migration tools may require higher thresholds or process-level exclusions.
- The 1-hour lookback window means the scheduled rule should run at least every 30 minutes to avoid missing short-lived wiper activity that completes before the next execution.
- take_any() for CommandLine and SHA256 returns one sample value per group; if the initiating process changes command lines across events in the window, only one is captured.

### Triage Runbook

**First 15 minutes:**
- Identify the initiating process, command line, account, and host role to determine whether the activity is expected maintenance or malicious.
- Check whether deletions and renames are concentrated in user data, shared drives, backups, or critical application directories.
- Look for concurrent signs of encryption or wiping such as new extensions, ransom notes, shadow copy deletion, or service stoppage.
- Determine whether the process is a known backup, migration, deployment, or remediation tool before taking action.
- If the activity is unexpected or still active, escalate immediately and prepare containment.

**Evidence to collect:**
- DeviceFileEvents for the alert window, including sample files, sample folder paths, deletions, renames, and unique extensions.
- DeviceProcessEvents or process telemetry for the initiating process command line, SHA256, and account context.
- Any ransom notes, extension changes, or evidence of mass file overwrite in affected directories.
- Host inventory and scheduled task/job information to identify backup, migration, or deployment tooling.
- Recent authentication and remote access logs to determine whether the process was launched interactively or remotely.

**Pivot points:**
- DeviceFileEvents on the same host for FileCreated, FileDeleted, and FileRenamed activity in the preceding and following hour.
- DeviceProcessEvents for the initiating process SHA256 across other hosts to determine whether the binary is widespread or unique.
- DeviceFileEvents for known backup staging directories or application data paths to assess scope of impact.
- DeviceLogonEvents or equivalent authentication logs for suspicious logons before the destructive activity.
- Any available incident timeline or EDR process tree views to identify parent-child relationships and lateral movement.

**Benign explanations:**
- A backup agent, file migration tool, or deployment process may legitimately delete and rename large numbers of files.
- Endpoint protection remediation may bulk-delete quarantined files during cleanup.
- A software update or archival workflow may rename many files in a short period.
- A maintenance script may operate on a large dataset and trigger the thresholds without malicious intent.

**Escalation criteria:**
- The process is unknown, unsigned, or not associated with an approved maintenance window.
- The activity affects critical business data, backups, or multiple systems, or is still ongoing.
- There are additional signs of ransomware or wiper behavior such as encryption notes, extension changes, or shadow copy deletion.
- The same initiating process or hash appears on multiple hosts or is associated with remote execution.

**Containment actions:**
- Isolate the host immediately if destructive activity is active or confirmed malicious.
- Disable the initiating account and terminate the process if doing so will not destroy needed evidence.
- Block the hash or executable path across the environment after validation from incident response.
- Protect backups and snapshot infrastructure and verify recovery points are intact.

**Closure criteria:**
- The initiating process is confirmed as an approved backup, migration, or remediation tool and the activity matches a documented change window.
- No evidence of malicious encryption, wiping, or unauthorized execution is found after review.
- The affected directories and file counts are understood and the business owner confirms the activity was expected.
- Any false-positive process or path is baselined or excluded with documented approval.

<br/>
---
<br/>

## Detection 4: HTML Phishing Attachment Delivery - External Sender with HTML or HTM File Attachment

### Detection Opportunity

Phishing content delivered via HTML file attachment from external sender, a technique observed using comment stuffing to evade AI-based detection

### Intelligence Context

- SANS ISC: "Comment stuffing" in an HTML phishing attachment as a mechanism for evading AI-based detection — [https://isc.sans.edu/diary/rss/33144](https://isc.sans.edu/diary/rss/33144)
  - Context: Phishing actors are embedding credential-harvesting content in HTML file attachments and using HTML comment stuffing to evade AI-based email security scanning. The delivery mechanism is an HTML attachment from an external sender rather than inline email body content or a URL link.

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

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: initial-access: T1566 Phishing/ T1566.001 Spearphishing Attachment (high)

### Deployment Gates

- If AttachmentName or FileSize are not populated in OfficeActivity for the tenant, the query will return no results; validate field population before relying on this detection.
- The Operation value 'MessageReceived' must be confirmed as the correct audit event name for inbound mail in the specific Office 365 connector version deployed in the Sentinel workspace.

**Required telemetry:**
- OfficeActivity

### KQL

```kql
OfficeActivity
| where TimeGenerated > ago(24h)
| where Operation == "MessageReceived"
| where isnotempty(AttachmentName)
| where AttachmentName endswith ".html" or AttachmentName endswith ".htm"
| where isnotempty(SenderAddress)
| extend SenderDomain = tostring(split(SenderAddress, "@")[1])
| where isnotempty(SenderDomain)
| summarize
    AttachmentCount = count(),
    RecipientCount = dcount(RecipientAddress),
    Recipients = make_set(RecipientAddress, 10),
    Subjects = make_set(Subject, 5),
    MaxFileSize = max(FileSize)
    by SenderAddress, SenderDomain, AttachmentName, DeliveryAction
| where MaxFileSize > 10000
| project
    SenderAddress,
    SenderDomain,
    AttachmentName,
    DeliveryAction,
    AttachmentCount,
    RecipientCount,
    Recipients,
    Subjects,
    MaxFileSize
| order by MaxFileSize desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate HTML newsletters or marketing emails delivered as attachments from external senders.
- Automated report delivery systems that send HTML-formatted reports as file attachments.
- Vendor or partner communications that use HTML attachment templates for invoices or notifications.

**Tuning notes:**
- Add a SenderDomain exclusion filter for your organization's primary and secondary email domains to prevent internal senders from matching.
- Expand the Operation filter to include additional mail receipt event names if 'MessageReceived' is not populated in your OfficeActivity connector configuration.
- Validate that AttachmentName and FileSize fields are non-null for a sample of known inbound emails before scheduling this query.
- Consider adding a trusted partner domain exclusion list to reduce false positives from known HTML-attachment-sending vendors.

**Risks / caveats:**
- AttachmentName and FileSize are not guaranteed to be populated in OfficeActivity for all Exchange Online configurations; these fields depend on Exchange audit log verbosity settings and the Office 365 Management Activity API connector being configured to ingest mail submission events.
- The Operation value 'MessageReceived' may not exist in all Office 365 connector configurations; the correct operation name varies by connector version and may be 'MailItemsAccessed', 'Send', or absent entirely depending on audit plan.
- DeliveryAction is not a standard OfficeActivity field in all connector versions; availability depends on whether the Microsoft Defender for Office 365 connector supplements OfficeActivity with additional fields.
- OfficeActivity does not natively expose FileSize for email attachments in all tenant configurations; this field may be null or absent, causing the MaxFileSize filter to drop all results.

### Triage Runbook

**First 15 minutes:**
- Review the sender address, sender domain, subject, recipients, and delivery action to determine whether the message is external and suspicious.
- Inspect the attachment name and size to assess whether it resembles a lure, invoice, notification, or login page.
- Check whether the message was delivered to multiple recipients or targeted a small set of users.
- Search for any user interaction signals such as attachment opens, clicks, or related mailbox activity if available.
- If the message is clearly malicious or widely delivered, initiate email containment and user notification.

**Evidence to collect:**
- OfficeActivity details for sender, recipients, subject, attachment name, file size, and delivery action.
- Message trace or mail flow logs to confirm delivery path, timestamps, and whether the message was quarantined or delivered.
- A copy of the HTML attachment or its hash for content review and sandboxing.
- Recipient list and any reports from users who opened the attachment or entered credentials.
- Tenant or mail security verdicts associated with the message, sender, or attachment.

**Pivot points:**
- OfficeActivity for other messages from the same sender address or domain in the last 24 to 72 hours.
- Message trace or mail gateway logs for the same subject, attachment name, or sender domain.
- Mailbox audit or endpoint telemetry for attachment opens, browser launches, or credential submissions by recipients.
- Threat intel lookups for the sender domain, attachment hash, or any embedded URLs if extracted.
- User-reported phishing submissions or help desk tickets tied to the same message.

**Benign explanations:**
- A legitimate vendor, partner, or newsletter may send HTML attachments as part of normal business communication.
- Automated reporting systems may distribute HTML-formatted reports to users.
- A trusted external service may use HTML attachments for invoices, notifications, or dashboards.
- The message may be benign if the sender is known and the attachment content matches an expected workflow.

**Escalation criteria:**
- The sender is external and unknown, and the attachment is designed to mimic a login page, invoice, or urgent action request.
- Multiple recipients received the same message or users report opening the attachment and entering credentials.
- The attachment contains obfuscated scripts, redirects, or embedded credential-harvesting content.
- Mail security or threat intel confirms the sender, domain, or attachment is malicious.

**Containment actions:**
- Quarantine or purge the message from all mailboxes if it is confirmed malicious.
- Block the sender address and domain at the mail gateway if the source is not legitimate.
- Reset credentials and revoke sessions for any users who interacted with the attachment or entered credentials.
- Notify recipients to delete the message and report any suspicious prompts or browser activity.

**Closure criteria:**
- The sender and attachment are validated as legitimate business communication and no user interaction occurred.
- The message is quarantined or removed and no further malicious activity is observed.
- Any impacted users have been checked for credential exposure and no compromise is found.
- The sender domain or attachment pattern is documented for future allowlisting or detection tuning.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Other deployment dependency:**
- Flowise CSV Agent - Python Execution Spawned by Node.js Web Process: Defender for Endpoint file-event coverage must be confirmed on the target host population.
- Flowise CSV Agent - Unauthenticated CSV File Drop in Web Application Directory: Defender for Endpoint file-event coverage must be confirmed on the target host population.

**Schema / correlation keys:**
- HTML Phishing Attachment Delivery - External Sender with HTML or HTM File Attachment: If AttachmentName or FileSize are not populated in OfficeActivity for the tenant, the query will return no results; validate field population before relying on this detection.

**Telemetry availability:**
- HTML Phishing Attachment Delivery - External Sender with HTML or HTM File Attachment: The Operation value 'MessageReceived' must be confirmed as the correct audit event name for inbound mail in the specific Office 365 connector version deployed in the Sentinel workspace.

**Shared-table notes:**
- DeviceFileEvents: shared by Flowise CSV Agent - Python Execution Spawned by Node.js Web Process; Flowise CSV Agent - Unauthenticated CSV File Drop in Web Application Directory; GigaWiper - Mass File Deletion and Rename Pattern Indicative of Wiper or Encryption Activity

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: GigaWiper - Mass File Deletion and Rename Pattern Indicative of Wiper or Encryption Activity.
2. Resolve environment-mapping detections next: Flowise CSV Agent - Python Execution Spawned by Node.js Web Process; Flowise CSV Agent - Unauthenticated CSV File Drop in Web Application Directory; HTML Phishing Attachment Delivery - External Sender with HTML or HTM File Attachment.

### Hunting Agenda and Promotion Criteria

- Flowise CSV Agent - Python Execution Spawned by Node.js Web Process: Defender for Endpoint file-event coverage must be confirmed on the target host population.; baseline expected benign activity and define an alert-volume threshold; prove correlation keys join correctly on real tenant telemetry.
- Flowise CSV Agent - Unauthenticated CSV File Drop in Web Application Directory: Defender for Endpoint file-event coverage must be confirmed on the target host population..
- HTML Phishing Attachment Delivery - External Sender with HTML or HTM File Attachment: If AttachmentName or FileSize are not populated in OfficeActivity for the tenant, the query will return no results; validate field population before relying on this detection.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
