---
layout: post
title: "Detection Engineering Brief - Saturday, September 19, 2026"
subtitle: "Threat intelligence translated into detection engineering action."
date: 2026-09-19
author: DevSecOpsDad
tags:
  - detection-engineering
  - kql
  - LausivLoader
  - email_gateway
  - endpoint
  - AWS AgentCore Harness
  - AWS
  - MovieReaper
  - torrent_clients
  - T1059
  - T1547
  - T1071
  - T1071.001
  - T1090
---

## Detection Engineering Summary

This brief produced 5 detection candidates.

2 production candidates, 2 hunting-only, 1 require environment mapping, and 0 rejected.

4 detections include KQL. 4 include ATT&CK mappings. 5 include triage guidance.

Search metadata extracted for this run includes: LausivLoader, email_gateway, endpoint, AWS AgentCore Harness, AWS, MovieReaper, torrent_clients, T1059, T1547, T1071, T1071.001, T1090.

No explicit IOCs were preserved for this run.

Deployment blockers or scheduling gates were identified for: LausivLoader - Multi-Stage Malware Inter-Stage Data Passing on Endpoint; AWS AgentCore Harness - Default Configuration Credential Exposure Posture; MovieReaper - Non-Browser Process Connecting to Solana Blockchain RPC Endpoints.

Detection candidates were derived from recent cybersecurity reporting, operational threat research, RSS intelligence feeds, and related detection engineering sources.

<br/>
---
<br/>

## Detection 1: LausivLoader - Quarantined Email with Attachment Lure

### Detection Opportunity

Malspam with attachment lure delivered via mail gateway and quarantined, impersonating a company employee requesting document review

### Intelligence Context

- SANS ISC: LausivLoader analysis, or how to pass data between malware stages, (Thu, Sep 17th) — [https://isc.sans.edu/diary/rss/33348](https://isc.sans.edu/diary/rss/33348)
  - Context: A malspam message was caught in quarantine of a mail gateway. The email impersonated a company employee and asked the recipient to review attached requirements, delivering LausivLoader as a multi-stage malware payload.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1547
- Products: Not specified
- Platforms: email_gateway, endpoint
- Malware: LausivLoader
- Tools: Not specified
- Search tags: LausivLoader, email_gateway, endpoint, T1059, T1547

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: medium
- MITRE ATT&CK: execution: T1059 Command and Scripting Interpreter (low); persistence: T1547 Boot or Logon Autostart Execution (low)

### Deployment Gates

- EmailEvents and EmailAttachmentInfo require Microsoft Defender for Office 365 Plan 1 or Plan 2 licensing. Without this, both tables will be absent from the Advanced Hunting schema.

**Required telemetry:**
- EmailEvents, EmailAttachmentInfo

### KQL

```kql
let reviewKeywords = dynamic(["review", "requirements", "attached", "please find", "kindly review"]);
EmailEvents
| where DeliveryAction == "Quarantine"
| where AttachmentCount >= 1
| where Subject has_any (reviewKeywords)
| join kind=inner (
    EmailAttachmentInfo
    | project NetworkMessageId, FileName, FileType, SHA256
) on NetworkMessageId
| project
    Timestamp,
    SenderFromAddress,
    SenderDisplayName,
    RecipientEmailAddress,
    Subject,
    DeliveryAction,
    ThreatTypes,
    AttachmentCount,
    FileName,
    FileType,
    SHA256,
    NetworkMessageId
| order by Timestamp desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate internal emails requesting document review that were quarantined due to policy or reputation scoring rather than malicious content.
- Automated workflow emails with review-themed subjects and attachments caught by overly aggressive quarantine policies.

**Tuning notes:**
- Expand reviewKeywords with lure subjects observed in your environment to improve precision.
- Add a FileType filter such as FileType in ('exe', 'docm', 'xlsm', 'zip', 'iso', 'lnk') to narrow results to high-risk attachment types.
- Add a SenderDomain exclusion list for known-good internal domains if impersonation lures from external senders are the primary concern.

**Risks / caveats:**
- EmailEvents and EmailAttachmentInfo require Microsoft Defender for Office 365 Plan 1 or Plan 2 licensing. Without this, both tables will be absent from the Advanced Hunting schema.
- The reviewKeywords list is intentionally broad; environments with high volumes of legitimate quarantined review-themed emails should extend the filter with additional subject-line specificity or sender domain exclusions.
- ThreatTypes may be empty for emails quarantined by policy rather than threat detection; analysts should not rely solely on ThreatTypes to confirm malicious classification.
- SHA256 may be null for certain attachment types not fully inspected by Defender for Office 365.

### Triage Runbook

**First 15 minutes:**
- Confirm the message was actually quarantined and not delivered; note the recipient, sender address, sender display name, subject, and timestamp.
- Review the attachment name, file type, and SHA256 if present; treat executable, archive, macro-enabled, or script-like attachments as higher risk.
- Check whether the sender display name impersonates an internal employee or business function and whether the sender address domain is external or newly seen.
- Look for other recipients of the same subject, sender, or attachment hash in the same time window to determine if this is a broader campaign.
- If the message was delivered to any mailbox despite quarantine on the original event, immediately check for user interaction and downstream endpoint activity.

**Evidence to collect:**
- EmailEvents details: SenderFromAddress, SenderDisplayName, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes, Timestamp, NetworkMessageId.
- EmailAttachmentInfo details: FileName, FileType, SHA256, and whether the attachment record exists for the same NetworkMessageId.
- Any related mail trace or quarantine history showing additional recipients, retries, or policy actions.
- Endpoint evidence for the recipient device if the message was delivered or opened: process creation, file writes, and any child processes shortly after receipt.
- User-reported context: whether the recipient expected a document review request from that sender.

**Pivot points:**
- EmailEvents filtered by the same SenderFromAddress, Subject keywords, or NetworkMessageId to find related messages.
- EmailAttachmentInfo filtered by SHA256 or FileName to identify reuse across messages.
- DeviceProcessEvents and DeviceFileEvents for the recipient host around the email timestamp if delivery or interaction occurred.
- Threat intelligence or file reputation lookup for the attachment SHA256 if available.

**Benign explanations:**
- A legitimate internal review request that was quarantined by policy or reputation scoring.
- An automated workflow or document-routing email that uses review-themed language and attachments.
- A false positive caused by broad subject keyword matching on common business terms.

**Escalation criteria:**
- The attachment hash is known malicious, detonates as malware, or matches prior malicious activity.
- The same lure is sent to multiple users or multiple mailboxes show similar quarantine events from the same sender.
- Any recipient opened the message or attachment and endpoint telemetry shows child process creation, script execution, or suspicious file drops.
- The sender address or domain is newly registered, spoofed, or otherwise inconsistent with the claimed internal identity.

**Containment actions:**
- If any copy was delivered, remove the message from all mailboxes and quarantine any related messages with the same sender, subject, or hash.
- Block the sender address, sending domain, and attachment hash if confirmed malicious.
- If a recipient interacted with the attachment, isolate the endpoint and begin endpoint scoping for follow-on activity.

**Closure criteria:**
- The message is confirmed benign internal correspondence or an approved workflow email.
- No recipients interacted with the message and no related malicious messages or endpoint activity are found.
- Attachment reputation, sender validation, and mail trace review support a policy-only quarantine with no compromise indicators.

<br/>
---
<br/>

## Detection 2: LausivLoader - Multi-Stage Malware Inter-Stage Data Passing on Endpoint

### Detection Opportunity

Multi-stage malware passing data between stages via child process spawning and sequential file writes in temporary or download directories

### Intelligence Context

- SANS ISC: LausivLoader analysis, or how to pass data between malware stages, (Thu, Sep 17th) — [https://isc.sans.edu/diary/rss/33348](https://isc.sans.edu/diary/rss/33348)
  - Context: LausivLoader passes data between malware stages. This produces a detectable pattern of a parent process spawning child processes that write files to temporary paths, characteristic of staged loader execution chains.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1059, T1547
- Products: Not specified
- Platforms: email_gateway, endpoint
- Malware: LausivLoader
- Tools: Not specified
- Search tags: LausivLoader, email_gateway, endpoint, T1059, T1547

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: execution: T1059 Command and Scripting Interpreter (low); persistence: T1547 Boot or Logon Autostart Execution (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceProcessEvents, DeviceFileEvents

### KQL

```kql
let stagingPaths = dynamic(["\\Downloads\\", "\\Temp\\", "\\AppData\\Local\\Temp\\", "\\AppData\\Roaming\\"]);
let suspawnProcs = DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where FolderPath has_any (stagingPaths)
| project DeviceId, DeviceName, SpawnTime=Timestamp, SpawnedProcess=FileName, SpawnedPID=ProcessId, ParentProcess=InitiatingProcessFileName, SpawnCmdLine=ProcessCommandLine;
let stageWrites = DeviceFileEvents
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath has_any (stagingPaths)
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".bat" or FileName endswith ".ps1"
| project DeviceId, WriteTime=Timestamp, WrittenFile=FileName, WritePath=FolderPath, WritingProcess=InitiatingProcessFileName;
suspawnProcs
| join kind=inner stageWrites on DeviceId
| where WriteTime between (SpawnTime .. (SpawnTime + 2m))
| project
    DeviceId,
    DeviceName,
    SpawnTime,
    SpawnedProcess,
    ParentProcess,
    SpawnCmdLine,
    WriteTime,
    WrittenFile,
    WritePath,
    WritingProcess
| order by SpawnTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Software installers and update managers that extract executables to Temp directories after spawning a child process.
- Package managers such as npm, pip, or Chocolatey that write scripts to AppData paths during installation.
- Browser-based download helpers that spawn child processes and write executables to Downloads.

**Tuning notes:**
- Restrict ParentProcess to known email client or browser process names such as outlook.exe, winword.exe, chrome.exe, msedge.exe to anchor the chain to email-delivered payloads.
- Adjust the time window from 2 minutes based on observed loader dwell times in your environment.
- Add a SHA256 lookup against threat intelligence after the join to prioritize confirmed malicious file hashes.

**Risks / caveats:**
- DeviceProcessEvents and DeviceFileEvents require Microsoft Defender for Endpoint Plan 2 onboarding. Devices not onboarded to MDE will produce no results.
- The 2-minute correlation window is a heuristic and may miss loaders with longer dwell times between stages or generate FP from fast-executing legitimate installers.
- The join on DeviceId without a process ID linkage means the writing process may not be the same process that was spawned; the correlation is temporal and device-scoped, not process-lineage-scoped.
- Broad staging path coverage will match legitimate software deployment activity in managed environments.

### Triage Runbook

**First 15 minutes:**
- Identify the host, parent process, spawned process, and written file path from the alert and confirm the sequence occurred within the stated time window.
- Review the command line of the spawning process for archive extraction, script execution, PowerShell, cmd.exe, mshta, rundll32, or other loader-like behavior.
- Check whether the written file is executable, script-like, or located in a user-writable staging path such as Downloads, Temp, or AppData.
- Look for immediate follow-on process creation, network connections, or additional file writes from the same host around the same timestamp.
- Determine whether the parent process is an email client, browser, or document viewer, which would strengthen the likelihood of a user-delivered payload.

**Evidence to collect:**
- DeviceProcessEvents for the host: DeviceName, Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, ProcessId, and parent lineage.
- DeviceFileEvents for the same host: FolderPath, FileName, ActionType, InitiatingProcessFileName, and SHA256 if available.
- Any subsequent DeviceNetworkEvents from the same host within the next hour to identify beaconing or download activity.
- File reputation or sandbox results for the written file hash if available.
- User context indicating whether the activity followed opening an attachment or downloaded file.

**Pivot points:**
- DeviceProcessEvents filtered by the same DeviceId and parent process name to map the full process tree.
- DeviceFileEvents filtered by the same DeviceId and written file name or SHA256 to find repeated staging behavior.
- DeviceNetworkEvents for the same DeviceId and time window to identify outbound connections after staging.
- If available, email telemetry for the same user to correlate with a delivered attachment or lure.

**Benign explanations:**
- Legitimate software installers or updaters extracting files into Temp or Downloads.
- Package managers or developer tooling writing scripts or binaries during installation.
- Browser download helpers or archive utilities creating temporary executable files as part of normal use.

**Escalation criteria:**
- The process tree includes suspicious interpreters or LOLBins and the written file is executable or script content in a staging directory.
- The same host shows subsequent network connections, persistence attempts, or additional malicious file drops.
- The parent process is tied to a recent email attachment or downloaded file and the behavior is not consistent with approved software installation.
- Multiple hosts show the same staging pattern or the written file hash matches known malware.

**Containment actions:**
- If the chain is suspicious and not attributable to approved software, isolate the host from the network.
- Terminate the suspicious process tree only after preserving evidence if your response process allows it.
- Quarantine or remove the dropped file and block the hash if confirmed malicious.
- Scope for additional affected hosts using the same parent process, file hash, or command line.

**Closure criteria:**
- The activity is matched to a known installer, updater, or approved package manager and no other malicious indicators are present.
- No suspicious follow-on process, network, or persistence activity is found on the host.
- The file hash and command line are consistent with benign software deployment and the event is documented as expected staging behavior.

<br/>
---
<br/>

## Detection 3: AWS AgentCore Harness - Default Configuration Credential Exposure Posture

### Detection Opportunity

Default configuration in AWS AgentCore Harness left credentials exposed, enabling potential prompt injection-driven exfiltration

### Intelligence Context

- Unit 42: A Vault with a Heap-View: The Uncomfortable Space Between AgentCore Harness and Identity — [https://unit42.paloaltonetworks.com/securing-aws-agentcore-harness-credentials/](https://unit42.paloaltonetworks.com/securing-aws-agentcore-harness-credentials/)
  - Context: Unit 42 identified that default configurations in AWS AgentCore Harness allow prompt injection to exfiltrate credentials. The misconfiguration is the root enabler; detecting it via posture audit provides early warning before exploitation occurs.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: Not specified
- Products: AWS AgentCore Harness
- Platforms: AWS
- Malware: Not specified
- Tools: Not specified
- Search tags: AWS AgentCore Harness, AWS

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: requires environment mapping
- Platform: Microsoft Sentinel
- Analytic type: inventory
- Severity recommendation: medium
- MITRE ATT&CK: Not mapped

### Deployment Gates

- No usable KQL is available; treat this as intelligence context only.
- An AWS Security Hub Sentinel connector or a custom AWS Config data connector must be deployed and validated before any KQL can be written for this detection.

**Required telemetry:**
- Not specified

### KQL

```kql
// No KQL available.
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- None documented.

**Tuning notes:**
- After connector deployment, scope the query to AWS account IDs associated with AgentCore deployments.
- Filter on complianceType equal to NON_COMPLIANT to surface only actionable posture findings.
- Validate that the ingested schema includes a field identifying the AgentCore Harness resource type before writing filter logic.

**Risks / caveats:**
- No standard Microsoft Sentinel table contains AWS AgentCore Harness configuration state or AWS Config compliance findings. AzureActivity is scoped to Azure Resource Manager operations and does not ingest AWS telemetry.
- An AWS Security Hub Sentinel connector or a custom AWS Config data connector must be deployed and validated before any KQL can be written for this detection.
- Without confirmed ingestion of AWS Config or Security Hub findings, no responsible KQL can be generated.
- Detection cannot be operationalized until AWS Config or Security Hub telemetry is confirmed in Sentinel.

### Triage Runbook

**First 15 minutes:**
- Validate the finding source and confirm the resource is an AWS AgentCore Harness deployment, not a mislabeled or unrelated AWS asset.
- Identify the account, region, resource ID, and compliance status to determine whether the issue is isolated or widespread.
- Check whether the configuration is a default or non-compliant posture that could expose credentials to prompt injection or other abuse.
- Determine whether the resource is internet-facing, used in production, or connected to sensitive data or privileged roles.
- Notify the cloud platform owner if the finding appears to affect a live workload with credential exposure risk.

**Evidence to collect:**
- ResourceId, ResourceType, AccountId, Region, ComplianceType, FindingTitle, and Severity from the ingested AWS finding source.
- Any attached configuration details showing the specific default setting or exposed credential path.
- IAM role or identity context associated with the AgentCore Harness deployment.
- Change history or deployment records showing when the insecure configuration was introduced.
- Evidence of whether the resource has access to sensitive secrets, tokens, or production systems.

**Pivot points:**
- AWS Security Hub or AWS Config findings table used by your Sentinel connector for the same AccountId or ResourceId.
- Cloud inventory records for other AgentCore Harness resources in the same account or region.
- IAM and secrets-management records to determine what credentials or permissions the resource can access.
- Change-management or deployment logs to identify the owner and last configuration change.

**Benign explanations:**
- A lab, proof-of-concept, or development deployment intentionally using default settings.
- A stale or duplicate compliance finding for a resource that has already been remediated.
- A non-production environment with no sensitive credentials or external exposure.

**Escalation criteria:**
- The resource is production-facing or has access to privileged credentials, secrets, or sensitive data.
- The insecure default configuration is confirmed and has not been remediated.
- There is evidence the resource has been accessed unexpectedly or used in a way consistent with prompt injection or credential exfiltration risk.
- Multiple AgentCore Harness resources in the same account show the same non-compliant posture.

**Containment actions:**
- Disable or restrict the affected AgentCore Harness resource if it is exposed and cannot be quickly remediated.
- Rotate any credentials, tokens, or secrets that the resource could access if exposure is confirmed.
- Apply the secure configuration baseline and revalidate compliance after remediation.
- Limit network and IAM permissions until the posture is corrected.

**Closure criteria:**
- The resource is confirmed non-production, intentionally configured, and has no access to sensitive credentials.
- The insecure default setting has been remediated and the finding clears on recheck.
- The finding is determined to be stale, duplicate, or not applicable to the current deployment state.

<br/>
---
<br/>

## Detection 4: MovieReaper - Executable Dropped by Torrent Client Process

### Detection Opportunity

Trojan delivered via compromised torrent files, resulting in executable files created by torrent client processes in user download directories

### Intelligence Context

- Securelist: The Odyssey and trojans again: MovieReaper attacks users in multiple countries via compromised torrents — [https://securelist.com/moviereaper-malware-torrent-odyssey-solana/121344/](https://securelist.com/moviereaper-malware-torrent-odyssey-solana/121344/)
  - Context: MovieReaper is a multi-stage Trojan spread through compromised movie torrents. The initial infection vector produces executable files dropped into user download directories by torrent client processes, which then spawn child processes as part of the multi-stage execution chain.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1071.001, T1090
- Products: Not specified
- Platforms: endpoint, torrent_clients
- Malware: MovieReaper
- Tools: Not specified
- Search tags: MovieReaper, endpoint, torrent_clients, T1071, T1071.001, T1090

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: production candidate
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: command-and-control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium); command-and-control: T1090 Proxy (low)

### Deployment Gates

- No gate-level deployment blockers identified.

**Required telemetry:**
- DeviceFileEvents, DeviceProcessEvents

### KQL

```kql
let torrentClients = dynamic(["bittorrent.exe", "utorrent.exe", "qbittorrent.exe", "transmission.exe", "deluge.exe", "vuze.exe", "tixati.exe"]);
let downloadPaths = dynamic(["\\Downloads\\", "\\Temp\\"]);
let droppedFiles = DeviceFileEvents
| where ActionType == "FileCreated"
| where InitiatingProcessFileName has_any (torrentClients)
| where FolderPath has_any (downloadPaths)
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".bat" or FileName endswith ".ps1" or FileName endswith ".vbs"
| project DeviceId, DropTime=Timestamp, DroppedFile=FileName, DropPath=FolderPath, TorrentClient=InitiatingProcessFileName, SHA256;
DeviceProcessEvents
| where ActionType == "ProcessCreated"
| join kind=inner droppedFiles on DeviceId
| where FileName =~ DroppedFile or ProcessCommandLine has DroppedFile
| where Timestamp between (DropTime .. (DropTime + 10m))
| project
    DeviceId,
    DeviceName,
    DropTime,
    DroppedFile,
    DropPath,
    TorrentClient,
    SHA256,
    ExecTime=Timestamp,
    ExecutedProcess=FileName,
    ProcessCommandLine,
    ParentProcessName
| order by DropTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate torrent clients downloading software packages that include executable installers in the Downloads directory.
- Torrent clients configured to download to non-standard paths not covered by the downloadPaths list may be missed, while legitimate downloads to covered paths may match.

**Tuning notes:**
- Add environment-specific torrent client process names to the torrentClients list.
- Narrow DropPath to specific user profile download directories if FP volume from shared download locations is high.
- Submit SHA256 values from matched records to threat intelligence for automated triage.

**Risks / caveats:**
- DeviceFileEvents and DeviceProcessEvents require Microsoft Defender for Endpoint Plan 2 onboarding. Devices not onboarded will produce no results.
- The 10-minute drop-to-execution window is a heuristic; loaders with delayed execution or user-triggered execution may fall outside this window.
- The torrent client list covers common applications but will miss environment-specific or less common clients not in the list.
- SHA256 may be null for files not fully hashed by MDE at the time of the FileCreated event.

### Triage Runbook

**First 15 minutes:**
- Confirm the torrent client process name, dropped file name, file type, and download path from the alert.
- Check whether the dropped file is executable or script-like and whether it was created in a user download directory.
- Review the process command line and parent process to determine whether the file was part of a normal download or a suspicious payload drop.
- Look for a matching process execution event for the dropped file within the 10-minute window or shortly after user interaction.
- Check whether the same torrent client or download path has produced other suspicious files on the host.

**Evidence to collect:**
- DeviceFileEvents for the host: DropTime, DroppedFile, DropPath, TorrentClient, SHA256, and any repeated file creation events.
- DeviceProcessEvents for the same host: ExecTime, ExecutedProcess, ProcessCommandLine, ParentProcessName, and DeviceName.
- File reputation or sandbox results for the dropped file hash.
- User activity context showing whether the file was opened manually after download.
- Any related network activity from the host after execution, especially to unusual domains or blockchain-related endpoints.

**Pivot points:**
- DeviceFileEvents filtered by the same SHA256, DroppedFile, or TorrentClient to find other affected hosts.
- DeviceProcessEvents filtered by the same DeviceId and ExecutedProcess name to identify follow-on execution.
- DeviceNetworkEvents for the same host after the drop to identify outbound connections or beaconing.
- If available, email or browser download telemetry to determine whether the torrent file was user-initiated.

**Benign explanations:**
- A legitimate torrent download that included a software installer or utility.
- A user intentionally downloading executable content from a torrent source.
- A false positive from a torrent client extracting bundled files into the Downloads directory.

**Escalation criteria:**
- The dropped file executes and is followed by suspicious child processes, persistence, or network activity.
- The file hash is malicious or the file name and command line match known MovieReaper behavior.
- Multiple executables are dropped by the same torrent client or the same host shows repeated suspicious downloads.
- The user did not expect executable content from the torrent and the file is not associated with approved software.

**Containment actions:**
- If the file is suspicious or executed, isolate the host from the network.
- Quarantine or delete the dropped file and block the hash if confirmed malicious.
- Stop the torrent client process if it is actively dropping additional suspicious files and this will not disrupt critical operations.
- Scope for other hosts downloading the same torrent or sharing the same file hash.

**Closure criteria:**
- The dropped file is a known benign installer or utility and execution is consistent with user intent.
- No suspicious follow-on execution or network activity is found.
- The torrent client activity is attributable to approved software distribution or a sanctioned download workflow.

<br/>
---
<br/>

## Detection 5: MovieReaper - Non-Browser Process Connecting to Solana Blockchain RPC Endpoints

### Detection Opportunity

Multi-stage malware using Solana blockchain as hidden C2 infrastructure, with non-browser processes making outbound connections to Solana RPC nodes

### Intelligence Context

- Securelist: The Odyssey and trojans again: MovieReaper attacks users in multiple countries via compromised torrents — [https://securelist.com/moviereaper-malware-torrent-odyssey-solana/121344/](https://securelist.com/moviereaper-malware-torrent-odyssey-solana/121344/)
  - Context: MovieReaper uses the Solana blockchain to hide its C2 infrastructure. Non-browser or non-crypto-wallet processes making outbound connections to Solana RPC endpoints is anomalous and indicative of blockchain-based C2 beaconing.

### Search Metadata

- CVEs: Not specified
- Threat actors: Not specified
- ATT&CK tags: T1071, T1071.001, T1090
- Products: Not specified
- Platforms: endpoint, torrent_clients
- Malware: MovieReaper
- Tools: Not specified
- Search tags: MovieReaper, endpoint, torrent_clients, T1071, T1071.001, T1090

### Relevant IOCs

No explicit IOCs were preserved for this detection.

### Metadata

- Readiness: hunting-only
- Platform: Defender XDR
- Analytic type: hunting
- Severity recommendation: high
- MITRE ATT&CK: command-and-control: T1071 Application Layer Protocol/ T1071.001 Web Protocols (medium); command-and-control: T1090 Proxy (low)

### Deployment Gates

- Do not schedule yet; validate as an analyst-led hunt first.

**Required telemetry:**
- DeviceNetworkEvents, DeviceFileEvents

### KQL

```kql
let solanaRpcDomains = dynamic(["api.mainnet-beta.solana.com", "api.devnet.solana.com", "api.testnet.solana.com", "rpc.ankr.com", "solana-api.projectserum.com"]);
let legitimateClients = dynamic(["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "phantom.exe", "solflare.exe", "exodus.exe"]);
let solanaConns = DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has_any (solanaRpcDomains)
    or (RemotePort == 8899 and isnotempty(RemoteUrl))
| where not (InitiatingProcessFileName has_any (legitimateClients))
| project DeviceId, DeviceName, ConnTime=Timestamp, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine;
let recentDrops = DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath has_any (["\\Downloads\\", "\\Temp\\", "\\AppData\\"])
| where FileName endswith ".exe" or FileName endswith ".dll"
| project DeviceId, DropTime=Timestamp, DroppedFile=FileName;
solanaConns
| join kind=leftouter (
    recentDrops
) on DeviceId
| where isempty(DropTime) or ConnTime between (DropTime .. (DropTime + 30m))
| project
    DeviceId,
    DeviceName,
    ConnTime,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteUrl,
    RemoteIP,
    RemotePort,
    DroppedFile,
    DropTime
| order by ConnTime desc
```

### False Positives / Tuning / Risks / Caveats

**Expected false positives:**
- Legitimate Solana blockchain development tools, CLI utilities, or dApps running as non-browser processes on developer workstations.
- Crypto trading bots or automation scripts connecting to Solana RPC endpoints that are not in the legitimateClients exclusion list.
- Port 8899 matches from local Solana validator nodes in developer or research environments.

**Tuning notes:**
- Expand the legitimateClients exclusion list with any Solana development tools, CLI utilities, or blockchain applications present in your environment.
- Tighten the 30-minute drop-to-connection window if FP volume from legitimate post-install network activity is high.
- Consider adding a RemoteIP-based filter using known Solana RPC IP ranges as a secondary signal for connections where RemoteUrl is not populated.
- To convert to a higher-confidence scheduled rule, require the DroppedFile correlation to be non-null by changing the join to kind=inner.

**Risks / caveats:**
- DeviceNetworkEvents and DeviceFileEvents require Microsoft Defender for Endpoint Plan 2 onboarding. Devices not onboarded will produce no results.
- RemoteUrl population in DeviceNetworkEvents depends on DNS resolution and URL inspection being available for the connection; connections to IP addresses without domain resolution will not match domain-based filters.
- The Solana RPC domain list covers primary public endpoints only; MovieReaper may use additional third-party or private RPC providers not in this list.
- The leftouter join means all Solana connections from non-excluded processes are surfaced regardless of file drop correlation; DroppedFile will be null for connections without a correlated drop event, requiring analyst review to distinguish.

### Triage Runbook

**First 15 minutes:**
- Identify the initiating process, command line, remote URL, remote IP, and remote port from the alert and confirm the process is not a browser or approved Solana tool.
- Check whether the connection is to a known Solana RPC endpoint or a suspicious third-party RPC provider and whether the process is expected in the environment.
- Look for a recent file drop or execution event on the same host that could explain the network activity as part of a malware chain.
- Review the frequency and timing of the connections to see whether they are periodic or beacon-like.
- Determine whether the host is a developer workstation, crypto-related system, or a normal user endpoint, since legitimate Solana tooling is more likely in those environments.

**Evidence to collect:**
- DeviceNetworkEvents for the host: ConnTime, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, and DeviceName.
- DeviceFileEvents for the same host to identify recent executable drops or staging activity.
- Process lineage from DeviceProcessEvents to determine how the initiating process started.
- Any DNS or proxy logs that show repeated access to the same RPC endpoint or related infrastructure.
- File hash and reputation for the initiating process if it is not a standard application.

**Pivot points:**
- DeviceNetworkEvents filtered by the same RemoteUrl, RemoteIP, or RemotePort to find other hosts contacting the same infrastructure.
- DeviceProcessEvents filtered by the same InitiatingProcessFileName or command line to identify related executions.
- DeviceFileEvents filtered by the same DeviceId and recent drop paths to correlate with a payload drop.
- Proxy, DNS, or firewall logs to validate whether the traffic is periodic and whether the destination is expected.

**Benign explanations:**
- Legitimate Solana development tools, CLI utilities, or wallet applications running on a developer workstation.
- A crypto trading bot or automation script that legitimately uses Solana RPC endpoints.
- Local validator or research activity in a lab environment, especially on port 8899.

**Escalation criteria:**
- The process is not an approved browser, wallet, or development tool and the connection is to a Solana RPC endpoint.
- The host also shows recent suspicious file drops, execution chains, or other malware indicators.
- The traffic is periodic or beacon-like and there is no business justification for Solana connectivity.
- Multiple non-browser processes or multiple hosts show the same unusual RPC access pattern.

**Containment actions:**
- If the connection is suspicious and not attributable to approved software, isolate the host from the network.
- Block the process or executable if it is confirmed malicious and preserve the file for analysis.
- Restrict outbound access to the suspicious RPC destination if your environment allows targeted blocking.
- Scope for additional hosts with the same process name, command line, or destination.

**Closure criteria:**
- The process is confirmed as approved Solana-related software or a sanctioned developer tool.
- The connection pattern is consistent with expected business use and no other compromise indicators are present.
- Any correlated file-drop or execution activity is explained by legitimate software installation or development activity.

<br/>
---
<br/>

## Recommended Next Actions

### Pre-Deployment Checklist by Dependency Type

**Licensing / identity risk fields:**
- LausivLoader - Quarantined Email with Attachment Lure: EmailEvents and EmailAttachmentInfo require Microsoft Defender for Office 365 Plan 1 or Plan 2 licensing. Without this, both tables will be absent from the Advanced Hunting schema.

**Schema / correlation keys:**
- LausivLoader - Multi-Stage Malware Inter-Stage Data Passing on Endpoint: Do not schedule yet; validate as an analyst-led hunt first.
- MovieReaper - Non-Browser Process Connecting to Solana Blockchain RPC Endpoints: Do not schedule yet; validate as an analyst-led hunt first.

**Other deployment dependency:**
- AWS AgentCore Harness - Default Configuration Credential Exposure Posture: No usable KQL is available; treat this as intelligence context only.

**Telemetry availability:**
- AWS AgentCore Harness - Default Configuration Credential Exposure Posture: An AWS Security Hub Sentinel connector or a custom AWS Config data connector must be deployed and validated before any KQL can be written for this detection.

**Shared-table notes:**
- DeviceProcessEvents: shared by LausivLoader - Multi-Stage Malware Inter-Stage Data Passing on Endpoint; MovieReaper - Executable Dropped by Torrent Client Process
- DeviceFileEvents: shared by LausivLoader - Multi-Stage Malware Inter-Stage Data Passing on Endpoint; MovieReaper - Executable Dropped by Torrent Client Process; MovieReaper - Non-Browser Process Connecting to Solana Blockchain RPC Endpoints

### Sequenced Deployment Plan

1. Start with production candidates that have no gate-level blockers: LausivLoader - Quarantined Email with Attachment Lure; MovieReaper - Executable Dropped by Torrent Client Process.
2. Resolve environment-mapping detections next: AWS AgentCore Harness - Default Configuration Credential Exposure Posture.
3. Keep hunting-only detections in analyst-led mode until their promotion criteria are met: LausivLoader - Multi-Stage Malware Inter-Stage Data Passing on Endpoint; MovieReaper - Non-Browser Process Connecting to Solana Blockchain RPC Endpoints.

### Hunting Agenda and Promotion Criteria

- LausivLoader - Multi-Stage Malware Inter-Stage Data Passing on Endpoint: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- MovieReaper - Non-Browser Process Connecting to Solana Blockchain RPC Endpoints: Do not schedule yet; validate as an analyst-led hunt first.; prove correlation keys join correctly on real tenant telemetry.
- AWS AgentCore Harness - Default Configuration Credential Exposure Posture: No usable KQL is available; treat this as intelligence context only..

### Unique Blind Spot Callout

No unique blind spot was isolated beyond the detection-specific gates above.

<br/>
---
<br/>

_Generated by DevSecOpsDadAttack threat intelligence and detection engineering. Validate detections before deployment._
