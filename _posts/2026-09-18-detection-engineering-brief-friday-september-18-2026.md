---
layout: post
title: "Detection Engineering Brief - Friday, September 18, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-18
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - AWS AgentCore Harness
  - AWS
  - MovieReaper
  - endpoint
  - LausivLoader
  - mail gateway
  - T1552
  - T1552.001
  - T1204
  - T1204.002
  - T1036
  - T1027
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

2 production candidates, 0 hunting-only, 3 require environment mapping, and 0 rejected.

5 detections include KQL. 5 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: AWS AgentCore Harness, AWS, MovieReaper, endpoint, LausivLoader, mail gateway, T1552, T1552.001, T1204, T1204.002, T1036, T1027.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: AWS AgentCore Harness - Anomalous Secret Retrieval by Agent Service Identity; LausivLoader - Malspam Document Attachment from Sender Domain Impersonating Internal Organization; AWS AgentCore Harness - Credential API Access from Agent Identity Outside Baseline Hours.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: AWS AgentCore Harness - Anomalous Secret Retrieval by Agent Service Identity

### Detection Opportunity

Unexpected secret retrieval from AWS AgentCore Harness agent workloads indicating potential prompt-injection-triggered credential exfiltration.

### Intelligence Context

- Unit 42: A Vault with a Heap-View: The Uncomfortable Space Between AgentCore Harness and Identity — [https://unit42.paloaltonetworks.com/securing-aws-agentcore-harness-credentials/](https://unit42.paloaltonetworks.com/securing-aws-agentcore-harness-credentials/)
  - Context: Unit 42 reported that default configurations in AWS AgentCore Harness allow prompt injection to trigger credential exfiltration. Hunting guidance explicitly called out abnormal credential access and unexpected secret retrieval from agent workloads as key detection signals.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1552, T1552.001
- Products: AWS AgentCore Harness
- Platforms: AWS
- Malware: Not specified
- Tools: Not specified
- Search tags: AWS AgentCore Harness, AWS, T1552, T1552.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1552 Unsecured Credentials/ T1552.001 Credentials In Files (medium)

### Deployment Gates

- AuditLogs caller identity format must be validated before relying on joins between sign-in identities and audit activity.

**Required telemetry:**
- AuditLogs

### KQL

```kql
let lookback = 7d;
let recentWindow = 1h;
let volumeMultiplier = 3;
let minBaselineCount = 3;
let baselineSecretOps =
    AuditLogs
    | where TimeGenerated between (ago(lookback) .. ago(recentWindow))
    | where OperationName has_any ("Get Secret", "GetSecretValue", "AccessSecret")
    | summarize BaselineCount = count(), BaselineResources = make_set(ResourceId) by Identity;
let recentSecretOps =
    AuditLogs
    | where TimeGenerated >= ago(recentWindow)
    | where OperationName has_any ("Get Secret", "GetSecretValue", "AccessSecret")
    | summarize
        RecentCount = count(),
        RecentResources = make_set(ResourceId),
        CallerIPs = make_set(CallerIpAddress),
        EarliestRecentOp = min(TimeGenerated),
        LatestRecentOp = max(TimeGenerated)
        by Identity;
recentSecretOps
| join kind=leftouter baselineSecretOps on Identity
| extend BaselineCount = coalesce(BaselineCount, 0)
| extend BaselineResources = coalesce(BaselineResources, dynamic([]))
| extend NewResources = set_difference(RecentResources, BaselineResources)
| where
    (BaselineCount >= minBaselineCount and RecentCount > (BaselineCount * volumeMultiplier))
    or array_length(NewResources) > 0
| project
    EarliestRecentOp,
    LatestRecentOp,
    Identity,
    RecentCount,
    BaselineCount,
    NewResources,
    RecentResources,
    CallerIPs
| order by RecentCount desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Agent identities accessing new secrets during legitimate configuration rollouts or secret rotation events.
- First-time agent deployments with no baseline history will appear as new-resource access for all secrets they touch.
- Automated remediation or compliance scanning tools running under agent service identities.

**Tuning notes:**
- Adjust volumeMultiplier from 3 to a value calibrated against the 95th percentile of legitimate agent secret access rates observed in the environment.
- Set minBaselineCount to a value that reflects the minimum meaningful baseline for volume comparison; identities below this threshold should only be evaluated on the new-resource branch.
- Scope the Identity filter to known agent service principal naming patterns (e.g., contains 'agent' or 'svc') to exclude human operator identities.
- Extend the OperationName list with the exact values observed in ingested CloudTrail events for the specific connector in use.

**Risks / caveats:**
- AuditLogs is a Microsoft Entra ID / Azure AD table; AWS CloudTrail events from AgentCore Harness are not ingested here by default. A configured AWS connector that maps CloudTrail events into AuditLogs with OperationName, Identity, ResourceId, and CallerIpAddress fields is required before this query produces any results.
- The OperationName values 'Get Secret', 'GetSecretValue', and 'AccessSecret' are AWS Secrets Manager CloudTrail event names. Their exact representation in the Sentinel table depends on the connector's normalization. If the connector uses ASIM or a custom table, the query will return zero results as written.
- The Identity field in AuditLogs is an Entra ID concept. AWS IAM role ARNs or service principal identifiers from CloudTrail may not populate this field; they may appear in a different column depending on the connector.
- The 7-day lookback baseline may be insufficient for agents with infrequent but legitimate secret access patterns; a 14-day or 30-day baseline may reduce false positives.

### Triage Runbook

**First 15 minutes:**
- Confirm the alerting identity is an agent service identity and not a human operator or automation account with an approved maintenance task.
- Review the time range, RecentCount, BaselineCount, NewResources, and CallerIPs to see whether this is a volume spike, first-time secret access, or both.
- Check whether the accessed secrets are production credentials, cross-account credentials, or secrets tied to privileged roles.
- Correlate the secret access time with recent agent prompt inputs, workflow changes, deployment events, or secret rotation activity.
- If the identity is new or recently modified, verify whether the behavior matches expected onboarding or configuration rollout.

**Evidence to collect:**
- CloudTrail or connector-normalized records for the exact secret retrieval operations and target ResourceId values.
- Caller IPs, source VPC/VPC endpoint details, and any unusual geolocation or network path associated with the access.
- Agent deployment history, prompt templates, tool configuration changes, and any recent policy or permission updates.
- List of secrets accessed, their sensitivity, and whether those secrets were subsequently used to call other AWS services.

**Pivot points:**
- Pivot on the Identity to all secret access events over the last 14-30 days to establish normal access patterns.
- Pivot on ResourceId to identify other identities that accessed the same secrets and whether access is shared or unique.
- Review AWS CloudTrail for AssumeRole, GetSessionToken, and downstream API calls made after the secret retrieval.
- Check agent orchestration logs or application logs for prompt injection indicators, unexpected tool calls, or abnormal user inputs.

**Benign explanations:**
- Legitimate onboarding of a new secret or a planned secret rotation causing first-time access.
- A newly deployed agent or service identity with no prior baseline history.
- Automated compliance scanning, remediation, or health-check tooling running under the same identity.
- A scheduled workflow that legitimately accesses secrets outside normal business hours.

**Escalation criteria:**
- The identity accessed high-value secrets it has never touched before and there is no approved change record.
- The access is followed by unusual downstream AWS activity such as role assumption, token generation, or data exfiltration patterns.
- Multiple secrets were retrieved in a short period from an agent identity that normally accesses few or none.
- Caller IPs, source accounts, or execution context do not match the expected agent runtime environment.

**Containment actions:**
- Temporarily disable or restrict the agent service identity if unauthorized access is likely.
- Revoke or rotate any secrets that were retrieved and are considered sensitive or exposed.
- Block the suspicious source IP or isolate the agent runtime environment if it is clearly compromised.
- Pause the affected agent workflow until prompt injection or configuration abuse is ruled out.

**Closure criteria:**
- The access is matched to an approved deployment, secret rotation, or documented maintenance activity.
- The accessed secrets are confirmed non-sensitive or already expected for that workflow.
- No suspicious downstream AWS activity or prompt-injection indicators are found.
- The identity is added to an allowlist or baseline after validation of normal behavior.

<br/>
---
<br/>

## Detection 2: MovieReaper - Executable Spawned from Torrent Client Writing to Temp or Download Directory

### Detection Opportunity

Trojan delivered via compromised movie torrent files executes on endpoint, spawning child processes or writing executables from a torrent client parent process.

### Intelligence Context

- Securelist: The Odyssey and trojans again: MovieReaper attacks users in multiple countries via compromised torrents — [https://securelist.com/moviereaper-malware-torrent-odyssey-solana/121344/](https://securelist.com/moviereaper-malware-torrent-odyssey-solana/121344/)
  - Context: Securelist reported that MovieReaper is a multi-stage Trojan distributed through compromised movie torrent files. The malware executes on the endpoint after the torrent payload is opened, making torrent client parent-child process chains a viable detection signal.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1204, T1204.002, T1036
- Products: Not specified
- Platforms: endpoint
- Malware: MovieReaper
- Tools: Not specified
- Search tags: MovieReaper, endpoint, T1204, T1204.002, T1036

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1204 User Execution/ T1204.002 Malicious File (medium); Defense Evasion: T1036 Masquerading (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let lookbackDays = 7d;
let writeExecWindowMin = 5m;
let torrentClients = dynamic(["bittorrent.exe", "utorrent.exe", "qbittorrent.exe", "transmission.exe", "deluge.exe", "vuze.exe", "tixati.exe"]);
let suspiciousPaths = dynamic(["\\temp\\", "\\tmp\\", "\\downloads\\", "\\appdata\\local\\temp\\"]);
let torrentSpawnedProcs =
    DeviceProcessEvents
    | where TimeGenerated >= ago(lookbackDays)
    | where tolower(InitiatingProcessFileName) in (torrentClients)
    | project
        DeviceName,
        DeviceId,
        SpawnedProcess = FileName,
        SpawnedProcessId = ProcessId,
        SpawnedCommandLine = ProcessCommandLine,
        SpawnTime = TimeGenerated,
        ParentProcess = InitiatingProcessFileName,
        ReportId;
let execWriteEvents =
    DeviceFileEvents
    | where TimeGenerated >= ago(lookbackDays)
    | where ActionType == "FileCreated"
    | where tolower(FolderPath) has_any (suspiciousPaths)
    | where FileName endswith ".exe"
        or FileName endswith ".dll"
        or FileName endswith ".bat"
        or FileName endswith ".ps1"
    | project
        DeviceName,
        DeviceId,
        WrittenFile = FileName,
        WritePath = FolderPath,
        WriteTime = TimeGenerated,
        SHA256;
torrentSpawnedProcs
| join kind=inner execWriteEvents on DeviceName, DeviceId
| where WriteTime between (SpawnTime .. (SpawnTime + writeExecWindowMin))
| project
    SpawnTime,
    WriteTime,
    DeviceName,
    DeviceId,
    ParentProcess,
    SpawnedProcess,
    SpawnedCommandLine,
    WrittenFile,
    WritePath,
    SHA256,
    ReportId
| order by SpawnTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate torrent clients that spawn helper processes (e.g., update checkers, media players) that write temporary files to temp directories.
- Software bundled with torrent clients (e.g., search bars, media codecs) that write executables during installation.
- Automated test environments where torrent clients are used for legitimate software distribution testing.

**Tuning notes:**
- Extend the torrentClients list with any additional torrent applications observed in the environment's software inventory.
- Adjust writeExecWindowMin if legitimate torrent client helper processes write files outside the 5-minute window.
- Add exclusions for known legitimate torrent client child processes (e.g., media players launched by the client) by filtering SpawnedProcess against an allowlist.
- Consider adding a SHA256 lookup against threat intelligence if available in the environment.

**Risks / caveats:**
- DeviceFileEvents.FolderPath uses backslash path separators on Windows; the has_any tolower comparison is case-insensitive but path separator consistency must be confirmed for non-Windows endpoints if any are in scope.
- The 5-minute join window may miss cases where the torrent client spawns a process that delays file writing beyond 5 minutes.
- Torrent clients not in the dynamic list will not be detected; the list should be reviewed against software inventory.
- The query does not confirm that the spawned process is the one writing the file; it correlates by device and time window, so coincidental writes by unrelated processes on the same device within 5 minutes of a torrent-spawned process will be surfaced.

### Triage Runbook

**First 15 minutes:**
- Identify the user, device, torrent client, spawned process, and written file from the alert details.
- Check whether the file was executed from a temp or downloads path and whether the SHA256 is known malicious.
- Review the process tree around the spawn time for additional child processes, script interpreters, or persistence activity.
- Determine whether the activity occurred on a user workstation, test system, or a managed software distribution environment.
- Look for signs of user interaction such as a recent download, archive extraction, or file open event.

**Evidence to collect:**
- DeviceProcessEvents for the full parent-child chain, command lines, and any subsequent suspicious processes.
- DeviceFileEvents for the written file path, file name, hash, and any follow-on file modifications.
- DeviceNetworkEvents for outbound connections from the spawned process or related children.
- User logon context, recent downloads, and any endpoint protection alerts on the same device.

**Pivot points:**
- Pivot on DeviceId to all process and file activity within several hours before and after the alert.
- Pivot on SHA256 to reputation, threat intelligence, and other devices with the same hash.
- Pivot on the torrent client process name to find other endpoints using the same application.
- Review DeviceNetworkEvents and DeviceRegistryEvents for persistence, C2, or defense evasion behavior.

**Benign explanations:**
- A legitimate torrent client helper process or media player launched during normal use.
- Software installation or update activity that stages files in temp or downloads directories.
- A test or lab environment where torrent clients are used intentionally.
- A benign file write by a related process that happened to occur within the correlation window.

**Escalation criteria:**
- The written file hash is malicious or the process tree shows additional suspicious execution.
- The endpoint shows persistence, credential theft, lateral movement, or outbound C2 traffic.
- The user did not intentionally use a torrent client or denies the activity.
- Multiple endpoints show the same hash or similar process chain.

**Containment actions:**
- Isolate the endpoint if the file executed and the process tree is suspicious.
- Quarantine or delete the malicious file if the endpoint protection platform supports it.
- Block the hash and any related network indicators if confirmed malicious.
- Reset credentials for the affected user if there are signs of credential theft or token abuse.

**Closure criteria:**
- The activity is confirmed as a legitimate torrent client helper or approved software distribution workflow.
- The file hash is benign and no suspicious follow-on behavior is present.
- No additional malicious processes, network activity, or persistence are found on the host.
- The event is documented and the torrent client or helper process is allowlisted if appropriate.

<br/>
---
<br/>

## Detection 3: LausivLoader - Malspam Document Attachment from Sender Domain Impersonating Internal Organization

### Detection Opportunity

Malspam with an attached requirements document impersonating a legitimate company employee delivers LausivLoader via email.

### Intelligence Context

- SANS ISC: LausivLoader analysis, or how to pass data between malware stages, (Thu, Sep 17th) — [https://isc.sans.edu/diary/rss/33348](https://isc.sans.edu/diary/rss/33348)
  - Context: SANS ISC reported that LausivLoader was delivered via a malspam message caught in a mail gateway quarantine. The message carried an attached requirements document and impersonated an employee of a legitimate company, making sender domain anomaly and document attachment type a viable compound detection signal.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1204, T1204.002, T1036, T1027
- Products: mail gateway
- Platforms: endpoint
- Malware: LausivLoader
- Tools: Not specified
- Search tags: LausivLoader, mail gateway, endpoint, T1204, T1204.002, T1036, T1027

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1204 User Execution/ T1204.002 Malicious File (medium); Defense Evasion: T1036 Masquerading (low); Defense Evasion: T1027 Obfuscated Files or Information (low)

### Deployment Gates

- OfficeActivity is populated by the Microsoft 365 connector. AttachmentName is not consistently populated for all mail operations; it is available for Exchange Online audit events but may be absent for some Operation types. The Operations 'MessageReceived' and 'Receive' are not standard Exchange Online audit operation names; the correct values are typically 'Send' for outbound and events captured via mail flow rules or Defender for Office 365 for inbound. Inbound mail attachment metadata may require the Defender for Office 365 connector or EmailAttachmentInfo table rather than OfficeActivity.

**Required telemetry:**
- OfficeActivity

### KQL

```kql
let lookbackDays = 14d;
let docExtensions = dynamic([".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".pdf", ".rtf", ".odt"]);
let trustedSenderDomains = dynamic(["microsoft.com"]);
let luреKeywords = dynamic(["requirement", "requirements", "document", "invoice", "request", "urgent", "attached"]);
OfficeActivity
| where TimeGenerated >= ago(lookbackDays)
| where Operation in ("Send", "MessageReceived", "Receive")
| where isnotempty(AttachmentName)
| extend AttachmentExt = tolower(tostring(split(AttachmentName, ".")[-1]))
| where strcat(".", AttachmentExt) in (docExtensions)
| extend SenderDomain = tolower(tostring(split(SenderMailFromAddress, "@")[1]))
| where isnotempty(SenderDomain)
| where not(SenderDomain has_any (trustedSenderDomains))
| extend SubjectLower = tolower(Subject)
| where SubjectLower has_any (luреKeywords)
| summarize
    AttachmentNames = make_set(AttachmentName),
    Recipients = make_set(RecipientEmailAddress),
    Subjects = make_set(Subject),
    SenderIPs = make_set(ClientIP),
    EventCount = count(),
    RecipientCount = dcount(RecipientEmailAddress),
    EarliestSeen = min(TimeGenerated),
    LatestSeen = max(TimeGenerated)
    by SenderMailFromAddress, SenderDomain
| order by LatestSeen desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate external vendors sending requirements documents, invoices, or RFP responses from external domains.
- Automated business process emails with document attachments from external SaaS platforms.
- Cold outreach and sales emails with attached documents from external senders.

**Tuning notes:**
- Populate trustedSenderDomains with all internal organizational domains and known trusted external partner domains before running.
- Validate that AttachmentName is populated for the Operation types in use by running a count of non-empty AttachmentName values per Operation in the tenant.
- Extend luреKeywords with industry-specific lure terms relevant to the organization's sector.
- Consider pivoting to EmailAttachmentInfo and EmailEvents tables in Defender XDR for more reliable inbound mail attachment telemetry if OfficeActivity attachment fields are sparse.

**Risks / caveats:**
- OfficeActivity is populated by the Microsoft 365 connector. AttachmentName is not consistently populated for all mail operations; it is available for Exchange Online audit events but may be absent for some Operation types. The Operations 'MessageReceived' and 'Receive' are not standard Exchange Online audit operation names; the correct values are typically 'Send' for outbound and events captured via mail flow rules or Defender for Office 365 for inbound. Inbound mail attachment metadata may require the Defender for Office 365 connector or EmailAttachmentInfo table rather than OfficeActivity.
- The Operation filter includes 'MessageReceived' and 'Receive' which are not documented standard OfficeActivity operation names for Exchange Online. If these values do not appear in the tenant's OfficeActivity, the inbound mail branch of the query will return no results.
- The trustedSenderDomains list contains only 'microsoft.com' as a placeholder example. All internal organizational domains and trusted external partner domains must be added before the query produces meaningful results.
- OfficeActivity may not populate AttachmentName for inbound mail depending on the Exchange Online audit configuration and connector version. The EmailAttachmentInfo table in Defender XDR may provide more reliable attachment metadata for inbound mail.

### Triage Runbook

**First 15 minutes:**
- Identify the sender address, sender domain, recipient list, subject, and attachment name from the alert.
- Verify whether the sender domain is truly external or a lookalike of an internal domain.
- Check whether the message was delivered, quarantined, or opened by any recipient.
- Assess whether the attachment type and subject match a known business process or a suspicious lure.
- Search for other messages from the same sender or similar domain sent to additional users.

**Evidence to collect:**
- Email headers, sender authentication results, and mail flow details for the message.
- Attachment metadata, file type, and any available hash or detonation result.
- Recipient actions such as open, click, download, or quarantine status.
- Any endpoint alerts or process activity on recipients who opened the attachment.

**Pivot points:**
- Pivot on SenderMailFromAddress and SenderDomain to identify related messages and campaigns.
- Pivot on AttachmentName and attachment hash to find other recipients or similar files.
- Review EmailEvents, EmailAttachmentInfo, and Defender for Office 365 quarantine data if available.
- Check DeviceProcessEvents on recipient endpoints for document-to-script or document-to-loader execution chains.

**Benign explanations:**
- A legitimate external vendor or partner sending a requirements document or business attachment.
- A routine business email that happens to use lure-like wording such as invoice or request.
- A misclassified internal or trusted partner domain not yet added to the allowlist.
- A quarantined message that never reached the user and was blocked before delivery.

**Escalation criteria:**
- The sender domain is a lookalike or spoofed internal domain and the message bypassed controls.
- Any recipient opened the attachment and endpoint telemetry shows execution or follow-on activity.
- The same sender or domain is sending similar attachments to multiple users.
- The attachment is malicious, weaponized, or linked to known malware behavior.

**Containment actions:**
- Purge the message from all mailboxes and quarantine if it is confirmed malicious.
- Block the sender domain, sender address, and any related attachment hashes.
- Isolate any endpoint that opened the attachment and shows suspicious activity.
- Reset credentials if the attachment led to credential theft or token capture.

**Closure criteria:**
- The sender is validated as legitimate and the attachment is business-approved.
- No recipients opened the attachment or no endpoint activity followed delivery.
- The message is fully contained in quarantine or removed from mailboxes.
- The sender domain is added to the trusted list only after validation.

<br/>
---
<br/>

## Detection 4: LausivLoader - Multi-Stage Loader Child Process Writing and Executing Files from Temp Directory

### Detection Opportunity

Multi-stage LausivLoader passes data between loader stages by writing files to temp directories and executing them via a different parent process chain on the endpoint.

### Intelligence Context

- SANS ISC: LausivLoader analysis, or how to pass data between malware stages, (Thu, Sep 17th) — [https://isc.sans.edu/diary/rss/33348](https://isc.sans.edu/diary/rss/33348)
  - Context: SANS ISC analysis of LausivLoader described a multi-stage loader architecture where data is passed between stages. This produces a detectable pattern of short-lived child processes writing files to temp directories that are subsequently executed by a different parent process, a behavioral chain observable via endpoint process and file telemetry.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1204, T1204.002, T1036, T1027
- Products: mail gateway
- Platforms: endpoint
- Malware: LausivLoader
- Tools: Not specified
- Search tags: LausivLoader, mail gateway, endpoint, T1204, T1204.002, T1036, T1027

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Execution: T1204 User Execution/ T1204.002 Malicious File (medium); Defense Evasion: T1036 Masquerading (low); Defense Evasion: T1027 Obfuscated Files or Information (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let lookbackDays = 7d;
let execWindowMin = 10m;
let tempPaths = dynamic(["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\windows\\temp\\"]);
let stagingExtensions = dynamic([".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".hta"]);
let fileWrites =
    DeviceFileEvents
    | where TimeGenerated >= ago(lookbackDays)
    | where ActionType == "FileCreated"
    | where tolower(FolderPath) has_any (tempPaths)
    | where FileName endswith ".exe"
        or FileName endswith ".dll"
        or FileName endswith ".bat"
        or FileName endswith ".ps1"
        or FileName endswith ".vbs"
        or FileName endswith ".js"
        or FileName endswith ".hta"
    | where isnotempty(FileName)
    | project
        DeviceName,
        DeviceId,
        WrittenFileName = FileName,
        WrittenFilePath = FolderPath,
        WriterProcess = InitiatingProcessFileName,
        WriteTime = TimeGenerated,
        SHA256;
let fileExecs =
    DeviceProcessEvents
    | where TimeGenerated >= ago(lookbackDays)
    | where isnotempty(FileName)
    | where tolower(FolderPath) has_any (tempPaths)
    | project
        DeviceName,
        DeviceId,
        ExecFileName = FileName,
        ExecPath = FolderPath,
        ExecParent = InitiatingProcessFileName,
        ExecCommandLine = ProcessCommandLine,
        ExecTime = TimeGenerated,
        ReportId;
fileWrites
| join kind=inner fileExecs on DeviceName, DeviceId
| where ExecFileName == WrittenFileName
| where ExecTime between (WriteTime .. (WriteTime + execWindowMin))
| where tolower(ExecParent) != tolower(WriterProcess)
| project
    WriteTime,
    ExecTime,
    DeviceName,
    DeviceId,
    WriterProcess,
    WrittenFileName,
    WrittenFilePath,
    ExecParent,
    ExecCommandLine,
    SHA256,
    ReportId
| order by WriteTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Software installers that extract components to temp directories and launch them via a different parent process (e.g., MSI installers, self-extracting archives).
- Software update mechanisms that write updated binaries to temp and execute them via a service or scheduler.
- Legitimate scripting frameworks that stage scripts in temp directories for execution by an interpreter spawned by a different parent.

**Tuning notes:**
- Adjust execWindowMin if additional LausivLoader reporting indicates longer inter-stage dwell times.
- Add an exclusion for known legitimate staged installer parent process names (e.g., msiexec.exe, setup.exe, installer.exe) to reduce false positives from software deployment.
- Consider adding a SHA256 lookup against threat intelligence if available to prioritize results with known-malicious hashes.
- Scope the query to specific device groups or OUs if the false positive volume from software deployment infrastructure is high.

**Risks / caveats:**
- DeviceFileEvents does not expose a FolderPath field for the executing process in DeviceProcessEvents; the FolderPath in DeviceProcessEvents refers to the process image path, not a temp directory filter. The query correctly uses FolderPath from DeviceFileEvents for write events and FolderPath from DeviceProcessEvents for execution path filtering, which is valid but requires that DeviceProcessEvents.FolderPath reflects the process image directory.
- The 10-minute execution window may miss LausivLoader stages with longer dwell times between write and execution.
- If the same process both writes and executes the file (e.g., a single-stage dropper), the ExecParent != WriterProcess filter will suppress those events by design.
- The query correlates by filename only within the device and time window; if two different files with the same name are written and executed in the same window, the join may produce spurious matches.

### Triage Runbook

**First 15 minutes:**
- Review the writer process, executing parent process, file name, temp path, and SHA256 from the alert.
- Confirm whether the same file was written and then executed by a different parent process within the expected window.
- Inspect the process tree for additional stages, script interpreters, or suspicious child processes.
- Check whether the activity aligns with a known installer, updater, or software deployment workflow.
- Look for any endpoint protection, network, or registry activity that indicates persistence or payload delivery.

**Evidence to collect:**
- DeviceProcessEvents showing the full parent-child chain and command lines.
- DeviceFileEvents for the temp file creation, hash, and any subsequent modifications.
- DeviceNetworkEvents for outbound connections from the executing process or its children.
- Any related alerts on the same device, especially persistence, credential access, or defense evasion.

**Pivot points:**
- Pivot on DeviceId to all process and file activity around the write and execution times.
- Pivot on SHA256 to identify other endpoints or detections with the same file.
- Review DeviceRegistryEvents for autoruns, services, scheduled tasks, or run keys.
- Search for the writer or executing parent process names across the environment to identify prevalence.

**Benign explanations:**
- A legitimate installer or self-extracting archive that stages components in temp before execution.
- A software update mechanism that writes a file and launches it via a different parent process.
- A scripting framework or admin tool that uses temp as a staging area.
- A false correlation where unrelated processes wrote and executed similarly named files in the same window.

**Escalation criteria:**
- The file hash is malicious or the process chain is not associated with approved software.
- The host shows persistence, suspicious network traffic, or additional malware stages.
- The same pattern appears on multiple endpoints or under multiple user sessions.
- The executing parent is unusual for the environment and not part of a known installer/update workflow.

**Containment actions:**
- Isolate the endpoint if the staged file executed and the chain is not clearly benign.
- Quarantine or remove the staged file and any related payloads.
- Block the hash and any related network indicators if confirmed malicious.
- Suspend the user session or service account if the execution was unauthorized.

**Closure criteria:**
- The chain is matched to a known installer, updater, or approved admin workflow.
- No malicious network, persistence, or follow-on execution is found.
- The file hash is benign and the process lineage is expected.
- The detection is documented and allowlisted only after validation.

<br/>
---
<br/>

## Detection 5: AWS AgentCore Harness - Credential API Access from Agent Identity Outside Baseline Hours

### Detection Opportunity

Prompt injection triggers credential exfiltration from AWS AgentCore Harness workloads, observable as anomalous credential or secret API calls from agent service identities at unusual times or volumes.

### Intelligence Context

- Unit 42: A Vault with a Heap-View: The Uncomfortable Space Between AgentCore Harness and Identity — [https://unit42.paloaltonetworks.com/securing-aws-agentcore-harness-credentials/](https://unit42.paloaltonetworks.com/securing-aws-agentcore-harness-credentials/)
  - Context: Unit 42 identified that default AWS AgentCore Harness configurations allow prompt injection to exfiltrate credentials. The recommended hunting approach includes detecting abnormal credential access patterns from agent identities, including access outside normal operational hours or from unexpected caller IP addresses.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1552, T1552.001
- Products: AWS AgentCore Harness
- Platforms: AWS
- Malware: Not specified
- Tools: Not specified
- Search tags: AWS AgentCore Harness, AWS, T1552, T1552.001

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: Credential Access: T1552 Unsecured Credentials/ T1552.001 Credentials In Files (medium)

### Deployment Gates

- AuditLogs caller identity format must be validated before relying on joins between sign-in identities and audit activity.

**Required telemetry:**
- AzureActivity

### KQL

```kql
let baselineDays = 14d;
let recentHours = 2h;
let credOps = dynamic(["GetSecretValue", "DescribeSecret", "GetCredentials", "AssumeRole", "GetSessionToken"]);
let baselineActivity =
    AzureActivity
    | where TimeGenerated between (ago(baselineDays) .. ago(recentHours))
    | where OperationName has_any (credOps)
    | where ResultType == "Success"
    | extend HourOfDay = hourofday(TimeGenerated)
    | summarize
        BaselineHours = make_set(HourOfDay),
        BaselineIPs = make_set(CallerIpAddress)
        by Identity;
let recentActivity =
    AzureActivity
    | where TimeGenerated >= ago(recentHours)
    | where OperationName has_any (credOps)
    | where ResultType == "Success"
    | extend HourOfDay = hourofday(TimeGenerated)
    | summarize
        RecentOps = count(),
        RecentHours = make_set(HourOfDay),
        RecentIPs = make_set(CallerIpAddress),
        Operations = make_set(OperationName),
        EarliestRecentOp = min(TimeGenerated),
        LatestRecentOp = max(TimeGenerated)
        by Identity;
recentActivity
| join kind=leftouter baselineActivity on Identity
| extend BaselineHours = coalesce(BaselineHours, dynamic([]))
| extend BaselineIPs = coalesce(BaselineIPs, dynamic([]))
| extend NewHours = set_difference(RecentHours, BaselineHours)
| extend NewIPs = set_difference(RecentIPs, BaselineIPs)
| where array_length(NewHours) > 0 or array_length(NewIPs) > 0
| project
    EarliestRecentOp,
    LatestRecentOp,
    Identity,
    RecentOps,
    Operations,
    NewHours,
    NewIPs,
    RecentIPs,
    RecentHours
| order by RecentOps desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Agent identities that operate on irregular schedules (e.g., event-driven agents) will frequently appear as off-hours access.
- Infrastructure changes such as IP address reassignment or load balancer rotation will produce new-IP alerts for legitimate agent activity.
- New agent deployments with no baseline history will trigger on all hours and IPs they access.

**Tuning notes:**
- Validate that OperationName values in AzureActivity for the specific AWS connector in use match the strings in the credOps list before scheduling.
- Validate that ResultType == 'Success' is the correct success indicator for the connector's normalization of AWS CloudTrail errorCode fields.
- Scope the Identity filter to known agent service principal naming conventions to exclude human operator identities.
- Extend the credOps list with additional AWS STS or Secrets Manager operation names observed in ingested CloudTrail events.

**Risks / caveats:**
- AzureActivity is an Azure Resource Manager audit table. AWS CloudTrail events from AgentCore Harness (GetSecretValue, DescribeSecret, AssumeRole, GetSessionToken) are not present in AzureActivity by default. A connector that ingests AWS CloudTrail into AzureActivity with these exact OperationName values and populates Identity with the AWS caller identity is required. Without this connector, the query returns zero results.
- ResultType == 'Success' is an AzureActivity field convention. AWS CloudTrail events ingested via custom connectors may use different success/failure field names or values depending on the connector's normalization logic.
- The Identity field in AzureActivity stores Azure AD UPNs or service principal display names. AWS IAM role ARNs or assumed-role session names from CloudTrail may not populate this field; they may appear in Caller, Properties, or a custom column depending on the connector.
- The 14-day baseline may be insufficient for agents with weekly or monthly operational cycles; a 30-day baseline may reduce false positives for infrequently active agents.

### Triage Runbook

**First 15 minutes:**
- Confirm the identity is an agent service identity and not a human or break-glass account.
- Review the alert for new hours, new IPs, recent operations, and the time span of the activity.
- Check whether the access pattern matches a scheduled job, deployment, or maintenance window.
- Identify which credential-related operations were called and whether they target privileged resources.
- Look for any immediate downstream AWS activity after the credential access.

**Evidence to collect:**
- CloudTrail or connector-normalized records for the exact operations, timestamps, and source IPs.
- Agent runtime logs, prompt history, and any recent configuration or policy changes.
- List of secrets, tokens, or roles accessed and whether they were used afterward.
- Any correlated AWS STS, IAM, Secrets Manager, or data-plane activity from the same identity.

**Pivot points:**
- Pivot on Identity to establish normal hours, IPs, and operation types over 14-30 days.
- Pivot on CallerIpAddress to find other identities or sessions using the same source.
- Review AWS CloudTrail for AssumeRole, GetSessionToken, and subsequent API calls.
- Search agent orchestration and application logs for prompt injection, unexpected tool use, or abnormal user input.

**Benign explanations:**
- An event-driven agent that legitimately runs outside business hours.
- Infrastructure changes such as IP reassignment, NAT changes, or load balancer rotation.
- A newly deployed agent with no baseline history.
- A scheduled maintenance or remediation task that uses credential APIs at unusual times.

**Escalation criteria:**
- The identity accessed sensitive credentials outside its normal schedule and there is no approved change.
- New IPs or new hours coincide with other suspicious AWS activity or prompt-injection indicators.
- The identity accessed multiple credential resources in a short period.
- The access is followed by role assumption, token generation, or unusual data access.

**Containment actions:**
- Disable or restrict the agent identity if unauthorized access is likely.
- Rotate any credentials or tokens that were accessed.
- Pause the affected agent workflow until the activity is explained.
- Block the source IP or isolate the runtime environment if it is clearly malicious.

**Closure criteria:**
- The activity is tied to an approved schedule, deployment, or infrastructure change.
- The new hour or IP is explained by a documented operational change.
- No suspicious downstream AWS activity is found.
- The identity is baselined or allowlisted after validation.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Schema / correlation keys:**
- AuditLogs caller identity format must be validated before relying on joins between sign-in identities and audit activity.

**Telemetry availability:**
- LausivLoader - Malspam Document Attachment from Sender Domain Impersonating Internal Organization: OfficeActivity is populated by the Microsoft 365 connector. AttachmentName is not consistently populated for all mail operations; it is available for Exchange Online audit events but may be absent for some Operation types. The Operations 'MessageReceived' and 'Receive' are not standard Exchange Online audit operation names; the correct values are typically 'Send' for outbound and events captured via mail flow rules or Defender for Office 365 for inbound. Inbound mail attachment metadata may require the Defender for Office 365 connector or EmailAttachmentInfo table rather than OfficeActivity.

**Shared-table notes:**
- DeviceProcessEvents: shared by MovieReaper - Executable Spawned from Torrent Client Writing to Temp or Download Directory; LausivLoader - Multi-Stage Loader Child Process Writing and Executing Files from Temp Directory
- DeviceFileEvents: shared by MovieReaper - Executable Spawned from Torrent Client Writing to Temp or Download Directory; LausivLoader - Multi-Stage Loader Child Process Writing and Executing Files from Temp Directory

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: MovieReaper - Executable Spawned from Torrent Client Writing to Temp or Download Directory; LausivLoader - Multi-Stage Loader Child Process Writing and Executing Files from Temp Directory.
2. Resolve environment-mapping detections next: AWS AgentCore Harness - Anomalous Secret Retrieval by Agent Service Identity; LausivLoader - Malspam Document Attachment from Sender Domain Impersonating Internal Organization; AWS AgentCore Harness - Credential API Access from Agent Identity Outside Baseline Hours.

### Hunting Agenda and Promotion Criteria

- AWS AgentCore Harness - Anomalous Secret Retrieval by Agent Service Identity: AuditLogs caller identity format must be validated before relying on joins between sign-in identities and audit activity.; baseline expected benign activity and define an alert-volume threshold.
- LausivLoader - Malspam Document Attachment from Sender Domain Impersonating Internal Organization: OfficeActivity is populated by the Microsoft 365 connector. AttachmentName is not consistently populated for all mail operations; it is available for Exchange Online audit events but may be absent for some Operation types. The Operations 'MessageReceived' and 'Receive' are not standard Exchange Online audit operation names; the correct values are typically 'Send' for outbound and events captured via mail flow rules or Defender for Office 365 for inbound. Inbound mail attachment metadata may require the Defender for Office 365 connector or EmailAttachmentInfo table rather than OfficeActivity..
- AWS AgentCore Harness - Credential API Access from Agent Identity Outside Baseline Hours: AuditLogs caller identity format must be validated before relying on joins between sign-in identities and audit activity.; baseline expected benign activity and define an alert-volume threshold.

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
